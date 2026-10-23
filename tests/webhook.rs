//! Webhook receiver tests (WH receiver): signature verification against an
//! independent RFC 2104 construction, and boot-time self-registration
//! (`ensure_subscription`) against a wiremock ledger.
//!
//! The route-level integration tests live in `tests/http.rs`; this file
//! covers the two functions the route and the boot task call directly.

#[path = "support/hmac.rs"]
mod hmac;

use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::state::Store;
use dump_analyzer::types::AnalyzerError;
use dump_analyzer::webhook::{ensure_subscription, stored_secret, verify_signature};

const ADMIN_TOKEN: &str = "webhook-admin-token-0123456789abcdef";
const ANALYZER_TOKEN: &str = "analyzer-token-0123456789abcdef";
const WEBHOOK_URL: &str = "https://da.example:4180/webhooks";
const SECRET: &str = "whsec_0123456789abcdef";

fn test_config(server: &MockServer) -> Config {
    Config {
        base_url: Url::parse(&server.uri()).expect("mock server URI is absolute"),
        token: Some(SecretToken::new(ANALYZER_TOKEN)),
        state_dir: PathBuf::from("./unused-in-webhook-tests"),
        name: "dump-analyzer".to_owned(),
        version: "0.9.9-test".to_owned(),
        poll_interval: Duration::from_millis(10_000),
        run_wall_timeout: Duration::from_millis(600_000),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes: 10 * 1024 * 1024 * 1024,
        ssh_target: None,
        symbol_cache_dir: None,
        http_addr: None,
        runner: dump_analyzer::types::RunnerKind::CdbSsh,
        claude_bin: "claude".to_string(),
        claude_model: None,
        dsh_base_url: None,
        dsh_token: None,
        dsh_model: None,
        dsh_preset: "analyzer-triage".to_owned(),
        tls_ca_cert: None,
        webhook_enabled: true,
        webhook_admin_token: Some(SecretToken::new(ADMIN_TOKEN)),
        webhook_url: Some(WEBHOOK_URL.to_owned()),
        webhook_actions: vec!["AcceptDump".to_owned(), "SealUpload".to_owned()],
        scheduler_enabled: true,
        writeback_enabled: true,
    }
}

fn open_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    (dir, store)
}

fn subscription_json(id: &str, url: &str) -> Value {
    json!({
        "id": id,
        "url": url,
        "actions": ["AcceptDump", "SealUpload"],
        "caseId": null,
        "cursor": "0000000000000001",
        "createdAt": "2026-10-20T02:00:00.000Z"
    })
}

fn error_envelope(code: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": "Synthetic failure for the webhook test",
            "retryable": false
        }
    })
}

async fn requests(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("mock server records requests by default")
}

/// Asserts the exact admin bearer header and that the analyzer token never
/// rides the same calls.
fn assert_admin_authorized(request: &Request) {
    let authorization = request
        .headers
        .get("authorization")
        .expect("Authorization header");
    let authorization = authorization.to_str().expect("ASCII header value");
    assert_eq!(authorization, format!("Bearer {ADMIN_TOKEN}"));
    assert_ne!(
        authorization,
        format!("Bearer {ANALYZER_TOKEN}"),
        "webhook-admin calls must never use the analyzer token"
    );
}

/// Mounts `GET /api/v1/webhooks` (admin bearer) returning `subscriptions`.
async fn mount_list(server: &MockServer, subscriptions: Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/webhooks"))
        .and(header("authorization", format!("Bearer {ADMIN_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subscriptions": subscriptions,
        })))
        .expect(1)
        .mount(server)
        .await;
}

/// Mounts `POST /api/v1/webhooks` (admin bearer, exact url/actions body)
/// answering `201` with `id`/`secret`.
async fn mount_create(server: &MockServer, id: &str, secret: &str) {
    Mock::given(method("POST"))
        .and(path("/api/v1/webhooks"))
        .and(header("authorization", format!("Bearer {ADMIN_TOKEN}")))
        .and(body_json(json!({
            "url": WEBHOOK_URL,
            "actions": ["AcceptDump", "SealUpload"],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "subscription": subscription_json(id, WEBHOOK_URL),
            "secret": secret,
        })))
        .expect(1)
        .mount(server)
        .await;
}

/// Mounts `DELETE /api/v1/webhooks/:id` (admin bearer) answering `204`.
async fn mount_delete(server: &MockServer, id: &str) {
    Mock::given(method("DELETE"))
        .and(path(format!("/api/v1/webhooks/{id}")))
        .and(header("authorization", format!("Bearer {ADMIN_TOKEN}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// verify_signature
// ---------------------------------------------------------------------------

#[test]
fn verify_signature_matches_the_rfc4231_vector() {
    // RFC 4231, test case 2: key "Jefe", data "what do ya want for nothing?".
    let digest = hmac::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex::encode(digest),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "the test-side HMAC is anchored to the RFC vector"
    );
    assert!(verify_signature(
        "Jefe",
        b"what do ya want for nothing?",
        "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    ));
}

#[test]
fn verify_signature_rejects_wrong_keys_tampering_and_malformed_headers() {
    let body = br#"{"cursor":"0000000000000001"}"#;
    let good = hmac::signature_header(SECRET.as_bytes(), body);
    assert!(verify_signature(SECRET, body, &good));

    // A different key over the same body must not verify.
    let wrong_key = hmac::signature_header(b"whsec_other_key", body);
    assert!(!verify_signature(SECRET, body, &wrong_key));

    // A tampered body must not verify against the original signature.
    let tampered = br#"{"cursor":"0000000000000002"}"#;
    assert!(!verify_signature(SECRET, tampered, &good));

    // Malformed headers: no prefix, empty digest, wrong length, non-hex.
    for header in [
        "",
        "deadbeef",
        "sha256=",
        "sha256=zzzz",
        "sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        // 63 hex characters.
        "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec384",
        // 65 hex characters.
        "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec38433",
    ] {
        assert!(
            !verify_signature(SECRET, body, header),
            "malformed header must be rejected: {header:?}"
        );
    }
}

#[test]
fn verify_signature_hashes_overlong_keys_before_padding() {
    // 100 ASCII bytes > the 64-byte HMAC block.
    let secret = "k".repeat(100);
    let body = br#"{"action":"AcceptDump"}"#;
    let good = hmac::signature_header(secret.as_bytes(), body);
    assert!(verify_signature(&secret, body, &good));

    // The naive construction that truncates the key to the first block
    // instead of hashing it must NOT verify: RFC 2104 hashes long keys.
    let naive = naive_truncating_hmac(secret.as_bytes(), body);
    assert!(
        !verify_signature(&secret, body, &format!("sha256={}", hex::encode(naive))),
        "an overlong key must be hashed, not truncated"
    );
}

#[test]
fn verify_signature_covers_empty_and_multibyte_bodies() {
    let secret = "whsec_ünïcøde-секрет";
    let empty = b"";
    assert!(verify_signature(
        secret,
        empty,
        &hmac::signature_header(secret.as_bytes(), empty)
    ));

    let body = "{\"detail\":{\"note\":\"崩溃转储\"}}".as_bytes();
    assert!(verify_signature(
        secret,
        body,
        &hmac::signature_header(secret.as_bytes(), body)
    ));
}

/// A deliberately wrong HMAC that truncates overlong keys instead of hashing
/// them; proves the long-key test discriminates the two constructions.
fn naive_truncating_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    key_block.copy_from_slice(&key[..64]);
    let ipad: Vec<u8> = key_block.iter().map(|byte| byte ^ 0x36).collect();
    let opad: Vec<u8> = key_block.iter().map(|byte| byte ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize()
        .into()
}

// ---------------------------------------------------------------------------
// ensure_subscription
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ensure_subscription_creates_when_absent_and_persists_the_secret() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();
    mount_list(&server, json!([])).await;
    mount_create(&server, "wh_new", "whsec_fresh_0123456789abcdef").await;

    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");
    let subscription = ensure_subscription(&client, &store, &config)
        .await
        .expect("ensure subscription");

    assert_eq!(subscription.id, "wh_new");
    assert_eq!(subscription.url, WEBHOOK_URL);
    assert_eq!(
        stored_secret(&store).expect("stored secret"),
        Some("whsec_fresh_0123456789abcdef".to_owned())
    );
    assert_eq!(
        store
            .secrets()
            .get("webhook.subscription_id")
            .expect("subscription id"),
        Some("wh_new".to_owned())
    );

    let recorded = requests(&server).await;
    assert_eq!(recorded.len(), 2, "list, then create");
    assert_eq!(recorded[0].method.as_str(), "GET");
    assert_eq!(recorded[1].method.as_str(), "POST");
    for request in &recorded {
        assert_admin_authorized(request);
    }
}

#[tokio::test]
async fn ensure_subscription_reuses_an_existing_matching_subscription() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();
    store
        .secrets()
        .set("webhook.secret", "whsec_existing")
        .expect("set secret");
    store
        .secrets()
        .set("webhook.subscription_id", "wh_old")
        .expect("set id");
    mount_list(
        &server,
        json!([
            subscription_json("wh_other", "https://other.example/webhooks"),
            subscription_json("wh_old", WEBHOOK_URL),
        ]),
    )
    .await;

    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");
    let subscription = ensure_subscription(&client, &store, &config)
        .await
        .expect("ensure subscription");

    assert_eq!(subscription.id, "wh_old", "our URL is reused");
    let recorded = requests(&server).await;
    assert_eq!(recorded.len(), 1, "reuse must not create or delete");
    assert_admin_authorized(&recorded[0]);
    assert_eq!(
        stored_secret(&store).expect("stored secret").as_deref(),
        Some("whsec_existing"),
        "the stored secret is left untouched"
    );
}

#[tokio::test]
async fn ensure_subscription_rotates_when_the_secret_is_missing() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();
    mount_list(&server, json!([subscription_json("wh_old", WEBHOOK_URL)])).await;
    mount_delete(&server, "wh_old").await;
    mount_create(&server, "wh_new", "whsec_rotated_0123456789abcdef").await;

    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");
    let subscription = ensure_subscription(&client, &store, &config)
        .await
        .expect("ensure subscription");

    assert_eq!(subscription.id, "wh_new");
    assert_eq!(
        stored_secret(&store).expect("stored secret"),
        Some("whsec_rotated_0123456789abcdef".to_owned())
    );
    assert_eq!(
        store
            .secrets()
            .get("webhook.subscription_id")
            .expect("subscription id"),
        Some("wh_new".to_owned())
    );

    let recorded = requests(&server).await;
    assert_eq!(recorded.len(), 3, "list, delete, then create");
    assert_eq!(recorded[0].method.as_str(), "GET");
    assert_eq!(recorded[1].method.as_str(), "DELETE");
    assert_eq!(recorded[2].method.as_str(), "POST");
    for request in &recorded {
        assert_admin_authorized(request);
    }
}

#[tokio::test]
async fn ensure_subscription_creates_when_only_other_urls_are_registered() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();
    mount_list(
        &server,
        json!([subscription_json(
            "wh_other",
            "https://other.example/webhooks"
        )]),
    )
    .await;
    mount_create(&server, "wh_new", "whsec_new_0123456789abcdef").await;

    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");
    let subscription = ensure_subscription(&client, &store, &config)
        .await
        .expect("ensure subscription");

    assert_eq!(subscription.id, "wh_new");
    let recorded = requests(&server).await;
    assert_eq!(recorded.len(), 2, "no delete for a foreign URL");
    assert_eq!(recorded[0].method.as_str(), "GET");
    assert_eq!(recorded[1].method.as_str(), "POST");
}

#[tokio::test]
async fn ensure_subscription_requires_url_and_admin_token_config() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();

    let mut config = test_config(&server);
    config.webhook_url = None;
    let client = LedgerClient::new(&config).expect("client");
    let err = ensure_subscription(&client, &store, &config)
        .await
        .expect_err("missing URL must fail");
    match &err {
        AnalyzerError::Config(message) => assert!(
            message.contains("DUMP_ANALYZER_WEBHOOK_URL"),
            "names the variable: {message}"
        ),
        other => panic!("expected Config, got {other:?}"),
    }

    let mut config = test_config(&server);
    config.webhook_admin_token = None;
    let err = ensure_subscription(&client, &store, &config)
        .await
        .expect_err("missing admin token must fail");
    match &err {
        AnalyzerError::Config(message) => assert!(
            message.contains("DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN"),
            "names the variable: {message}"
        ),
        other => panic!("expected Config, got {other:?}"),
    }

    assert!(
        requests(&server).await.is_empty(),
        "config validation happens before any ledger call"
    );
}

#[tokio::test]
async fn ensure_subscription_surfaces_a_ledger_401_without_persisting() {
    let server = MockServer::start().await;
    let (_dir, store) = open_store();
    Mock::given(method("GET"))
        .and(path("/api/v1/webhooks"))
        .respond_with(ResponseTemplate::new(401).set_body_json(error_envelope("unauthenticated")))
        .expect(1)
        .mount(&server)
        .await;

    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");
    let err = ensure_subscription(&client, &store, &config)
        .await
        .expect_err("401 must fail");

    match &err {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 401);
            assert_eq!(code.as_deref(), Some("unauthenticated"));
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(!err.is_transient(), "401 must never be retried");
    assert_eq!(stored_secret(&store).expect("stored secret"), None);
    assert_eq!(
        store
            .secrets()
            .get("webhook.subscription_id")
            .expect("subscription id"),
        None
    );
}
