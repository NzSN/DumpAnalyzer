//! `LedgerClient` tests (task B1): exact request assertions against a
//! wiremock DumpLedger, status mapping, strict response decoding, and
//! credential hygiene — the analyzer token must never reach URLs, error
//! text, or `Debug` output.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use reqwest::Url;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use dump_analyzer::client::{ContentResult, DEFAULT_API_TIMEOUT, LedgerClient, PostAnalysisResult};
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::types::{AnalyzerError, ReportOutcome};
use dump_analyzer::wire::{
    AnalysisReportSubmission, Analyzer, DumpCatalogQuery, DumpPhase, ValidationState,
};

/// Analyzer bearer token used by every test; assertions prove it appears
/// exactly as `Authorization: Bearer <token>` and nowhere else.
const TOKEN: &str = "analyzer-token-0123456789abcdef";

/// Canonical valid sha256 (64 lowercase hex characters).
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Strong content validator as the server emits it: quoted digest.
const ETAG: &str = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

const DUMP_ID: &str = "dump_01JABCXYZ";

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

fn test_config(base_url: Url) -> Config {
    test_config_with_token(base_url, TOKEN)
}

fn test_config_with_token(base_url: Url, token: &str) -> Config {
    Config {
        base_url,
        token: Some(SecretToken::new(token)),
        state_dir: PathBuf::from("./unused-in-client-tests"),
        name: "dump-analyzer".to_owned(),
        version: "0.1.0".to_owned(),
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
        tls_ca_cert: None,
        scheduler_enabled: true,
        writeback_enabled: true,
    }
}

fn config_for(server: &MockServer) -> Config {
    test_config(Url::parse(&server.uri()).expect("mock server URI is absolute"))
}

async fn client_for(server: &MockServer) -> LedgerClient {
    LedgerClient::new(&config_for(server)).expect("client construction")
}

/// The single request the mock server recorded.
async fn single_request(server: &MockServer) -> Request {
    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests by default");
    assert_eq!(requests.len(), 1, "expected exactly one request");
    requests.into_iter().next().expect("one request")
}

/// Asserts the exact bearer header and that the token never rides in the URL.
fn assert_authorized(request: &Request) {
    let authorization = request
        .headers
        .get("authorization")
        .expect("Authorization header");
    assert_eq!(
        authorization.to_str().expect("ASCII header value"),
        format!("Bearer {TOKEN}")
    );
    assert!(
        !request.url.as_str().contains(TOKEN),
        "the token must never appear in request URLs: {}",
        request.url
    );
}

/// Decoded query pairs in wire order (order is part of the assertion).
fn query_pairs(request: &Request) -> Vec<(String, String)> {
    request
        .url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures (strict wire shapes)
// ---------------------------------------------------------------------------

fn catalog_entry(dump_id: &str) -> Value {
    json!({
        "dumpId": dump_id,
        "caseId": "case_01JAB0XYZ",
        "customerId": "customer_01JAA0XYZ",
        "phase": "available",
        "validation": "valid",
        "originalName": "renderer-crash.dmp",
        "byteSize": "1073741824",
        "sha256": SHA256,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "architecture": "x64",
        "exceptionCode": 3221225477u32,
        "exceptionAddress": "140698920429645",
        "symbolCoverage": { "present": 12, "missing": 3, "unidentified": 1 }
    })
}

fn dump_detail() -> Value {
    json!({
        "dumpId": DUMP_ID,
        "case": { "caseId": "case_01JAB0XYZ", "title": "Renderer crash loop" },
        "phase": "available",
        "originalName": "renderer-crash.dmp",
        "byteSize": "1073741824",
        "sha256": SHA256,
        "validation": "valid",
        "coverage": "full-memory-declared",
        "downloadable": true,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": "2026-11-12T02:00:00.000Z",
        "purgedAt": null,
        "inspectionError": null,
        "symbolCoverage": [
            {
                "name": "C:\\Windows\\System32\\ntdll.dll",
                "debugFile": "ntdll.pdb",
                "debugId": "6A0F3E1B2C3D4E5F60718293A4B5C6D71",
                "status": "present",
                "artifactId": "sym_01JABC999",
                "system": true
            }
        ],
        "activity": [
            { "occurredAt": "2026-10-13T02:05:30.250Z", "action": "SealUpload", "outcome": "sealed" }
        ]
    })
}

fn analysis_report() -> Value {
    json!({
        "analysisId": "analysis_01JABC001",
        "dumpId": DUMP_ID,
        "analyzer": { "name": "dump-analyzer", "version": "0.1.0" },
        "kind": "triage",
        "inputSha256": SHA256,
        "createdAt": "2026-10-13T03:30:00.000Z",
        "outcome": "completed",
        "summary": "Access violation writing location 0x0000000000000000",
        "facts": { "exceptionCode": 3221225477u32, "faultingModule": "renderer.dll" },
        "duplicateOf": null
    })
}

fn event_feed() -> Value {
    json!({
        "events": [
            {
                "cursor": "0000000000000043",
                "eventId": "event_01JABC001",
                "occurredAt": "2026-10-13T02:05:30.250Z",
                "action": "SealUpload",
                "customerId": "customer_01JAA0XYZ",
                "caseId": "case_01JAB0XYZ",
                "dumpId": DUMP_ID,
                "detail": { "byteSize": "1073741824", "outcome": "sealed" }
            }
        ],
        "nextCursor": "0000000000000043"
    })
}

fn submission() -> AnalysisReportSubmission {
    AnalysisReportSubmission::new(
        Analyzer {
            name: "dump-analyzer".to_owned(),
            version: "0.1.0".to_owned(),
        },
        "triage".to_owned(),
        SHA256.to_owned(),
        ReportOutcome::Completed,
        "Access violation writing location 0x0000000000000000".to_owned(),
        Some(json!({ "exceptionCode": 3221225477u32, "faultingModule": "renderer.dll" })),
        None,
    )
    .expect("fixture submission is valid")
}

fn error_envelope(code: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": "Synthetic failure for the client test",
            "retryable": false
        }
    })
}

/// A loopback URL whose listener is already closed, so connects are refused.
fn refused_local_url() -> Url {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    Url::parse(&format!("http://127.0.0.1:{port}")).expect("URL")
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_get_dumps_sends_exact_authenticated_catalog_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("phase", "available"))
        .and(query_param("cursor", "cursor_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dumps": [catalog_entry(DUMP_ID)],
            "nextCursor": "cursor_42_next"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let params = DumpCatalogQuery {
        case_id: Some("case_01JAB0XYZ".to_owned()),
        phase: Some(DumpPhase::Available),
        validation: Some(ValidationState::Valid),
        received_after: Some("2026-10-13T00:00:00.000Z".to_owned()),
        architecture: Some("x64".to_owned()),
        exception_code: Some(3_221_225_477),
        sha256: Some(SHA256.to_owned()),
        ..DumpCatalogQuery::default()
    };
    let page = client
        .get_dumps(&params, Some("cursor_42"))
        .await
        .expect("catalog page");

    assert_eq!(page.dumps.len(), 1);
    assert_eq!(page.dumps[0].dump_id, DUMP_ID);
    assert_eq!(page.dumps[0].sha256.as_deref(), Some(SHA256));
    assert_eq!(page.dumps[0].exception_code, Some(3_221_225_477));
    assert_eq!(page.next_cursor.as_deref(), Some("cursor_42_next"));

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "GET");
    assert_eq!(request.url.path(), "/api/v1/dumps");
    assert_authorized(&request);
    assert!(request.body.is_empty());
    assert_eq!(
        query_pairs(&request),
        vec![
            ("caseId".to_owned(), "case_01JAB0XYZ".to_owned()),
            ("phase".to_owned(), "available".to_owned()),
            ("validation".to_owned(), "valid".to_owned()),
            (
                "receivedAfter".to_owned(),
                "2026-10-13T00:00:00.000Z".to_owned()
            ),
            ("architecture".to_owned(), "x64".to_owned()),
            ("exceptionCode".to_owned(), "3221225477".to_owned()),
            ("sha256".to_owned(), SHA256.to_owned()),
            ("cursor".to_owned(), "cursor_42".to_owned()),
        ]
    );
}

#[tokio::test]
async fn client_get_dumps_without_filters_sends_bare_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "dumps": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let page = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect("empty page");

    assert!(page.dumps.is_empty());
    assert_eq!(page.next_cursor, None);
    let request = single_request(&server).await;
    assert_eq!(request.url.query(), None);
}

#[tokio::test]
async fn client_get_dumps_cursor_argument_overrides_params_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "dumps": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let params = DumpCatalogQuery {
        cursor: Some("stale_cursor".to_owned()),
        ..DumpCatalogQuery::default()
    };
    client
        .get_dumps(&params, Some("fresh_cursor"))
        .await
        .expect("catalog page");

    let request = single_request(&server).await;
    assert_eq!(
        query_pairs(&request),
        vec![("cursor".to_owned(), "fresh_cursor".to_owned())]
    );
}

#[tokio::test]
async fn client_get_dump_by_sha256_returns_matching_entries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/by-sha256/{SHA256}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "dumps": [catalog_entry(DUMP_ID)] })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let entries = client
        .get_dump_by_sha256(SHA256)
        .await
        .expect("hash lookup");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].dump_id, DUMP_ID);
    assert_eq!(entries[0].sha256.as_deref(), Some(SHA256));

    let request = single_request(&server).await;
    assert_eq!(
        request.url.path(),
        format!("/api/v1/dumps/by-sha256/{SHA256}")
    );
    assert_authorized(&request);
}

#[tokio::test]
async fn client_get_dump_returns_detail_with_symbol_coverage() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(dump_detail()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let detail = client.get_dump(DUMP_ID).await.expect("dump detail");

    assert_eq!(detail.dump_id, DUMP_ID);
    assert_eq!(detail.phase, DumpPhase::Available);
    assert_eq!(detail.validation, ValidationState::Valid);
    assert!(detail.downloadable);
    assert_eq!(detail.symbol_coverage.len(), 1);
    assert!(detail.symbol_coverage[0].system);
    assert_eq!(detail.activity.len(), 1);

    let request = single_request(&server).await;
    assert_eq!(request.url.path(), format!("/api/v1/dumps/{DUMP_ID}"));
    assert_authorized(&request);
}

// ---------------------------------------------------------------------------
// Content and ETag conditional requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_get_content_returns_bytes_and_etag_without_validator() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", ETAG)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(b"\x01\x02\x03".to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let result = client
        .get_content(DUMP_ID, None)
        .await
        .expect("content bytes");

    match result {
        ContentResult::Bytes { bytes, etag } => {
            assert_eq!(bytes, b"\x01\x02\x03");
            assert_eq!(etag, ETAG);
        }
        ContentResult::NotModified => panic!("expected fresh bytes"),
    }

    let request = single_request(&server).await;
    assert!(request.headers.get("if-none-match").is_none());
    assert_authorized(&request);
}

#[tokio::test]
async fn client_get_content_sends_if_none_match_and_maps_304() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .and(header("if-none-match", ETAG))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", ETAG))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let result = client
        .get_content(DUMP_ID, Some(ETAG))
        .await
        .expect("conditional fetch");

    assert_eq!(result, ContentResult::NotModified);

    let request = single_request(&server).await;
    assert_eq!(
        request
            .headers
            .get("if-none-match")
            .expect("If-None-Match header")
            .to_str()
            .expect("ASCII"),
        ETAG
    );
    assert_authorized(&request);
}

// ---------------------------------------------------------------------------
// Event feed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_get_events_sends_filtered_cursor_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(query_param("since", "0000000000000043"))
        .and(query_param("actions", "SealUpload,RejectDump"))
        .and(query_param("caseId", "case_01JAB0XYZ"))
        .and(query_param("limit", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(event_feed()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let response = client
        .get_events(
            Some("0000000000000043"),
            Some(&["SealUpload", "RejectDump"]),
            Some("case_01JAB0XYZ"),
            Some(100),
        )
        .await
        .expect("event page");

    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].dump_id.as_deref(), Some(DUMP_ID));
    assert_eq!(response.next_cursor, "0000000000000043");

    let request = single_request(&server).await;
    assert_eq!(request.url.path(), "/api/v1/events");
    assert_authorized(&request);
    assert_eq!(
        query_pairs(&request),
        vec![
            ("since".to_owned(), "0000000000000043".to_owned()),
            ("actions".to_owned(), "SealUpload,RejectDump".to_owned()),
            ("caseId".to_owned(), "case_01JAB0XYZ".to_owned()),
            ("limit".to_owned(), "100".to_owned()),
        ]
    );
}

#[tokio::test]
async fn client_get_events_without_filters_sends_bare_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events": [],
            "nextCursor": "0000000000000000"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let response = client
        .get_events(None, None, None, None)
        .await
        .expect("empty page");

    assert!(response.events.is_empty());
    assert_eq!(response.next_cursor, "0000000000000000");
    let request = single_request(&server).await;
    assert_eq!(request.url.query(), None);
}

// ---------------------------------------------------------------------------
// Analysis write-back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_post_analysis_created_on_201() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/analyses")))
        .and(header("content-type", "application/json"))
        .and(body_json(
            serde_json::to_value(submission()).expect("submission is serializable"),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let result = client
        .post_analysis(DUMP_ID, &submission())
        .await
        .expect("created report");

    match result {
        PostAnalysisResult::Created(report) => {
            assert_eq!(report.analysis_id, "analysis_01JABC001");
            assert_eq!(report.input_sha256, SHA256);
            assert_eq!(report.outcome, ReportOutcome::Completed);
        }
        other => panic!("expected Created, got {other:?}"),
    }

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(
        request.url.path(),
        format!("/api/v1/dumps/{DUMP_ID}/analyses")
    );
    assert_authorized(&request);
}

#[tokio::test]
async fn client_post_analysis_replayed_on_200() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/analyses")))
        .respond_with(ResponseTemplate::new(200).set_body_json(analysis_report()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let result = client
        .post_analysis(DUMP_ID, &submission())
        .await
        .expect("replayed report");

    assert!(result.is_replay());
    match result {
        PostAnalysisResult::Replayed(report) => {
            assert_eq!(report.analysis_id, "analysis_01JABC001");
        }
        other => panic!("expected Replayed, got {other:?}"),
    }
    assert_authorized(&single_request(&server).await);
}

#[tokio::test]
async fn client_get_analyses_returns_reports() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/analyses")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "analyses": [analysis_report()]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let reports = client.get_analyses(DUMP_ID).await.expect("analyses list");

    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].dump_id, DUMP_ID);
    assert_eq!(reports[0].input_sha256, SHA256);

    let request = single_request(&server).await;
    assert_eq!(
        request.url.path(),
        format!("/api/v1/dumps/{DUMP_ID}/analyses")
    );
    assert_authorized(&request);
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_maps_401_envelope_to_terminal_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(401).set_body_json(error_envelope("unauthenticated")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("401 must fail");

    match &error {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 401);
            assert_eq!(code.as_deref(), Some("unauthenticated"));
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(!error.is_transient(), "401 must never be retried");
}

#[tokio::test]
async fn client_maps_403_envelope_to_terminal_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(error_envelope("forbidden")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client.get_dump(DUMP_ID).await.expect_err("403 must fail");

    match &error {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 403);
            assert_eq!(code.as_deref(), Some("forbidden"));
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(!error.is_transient(), "403 must never be retried");
}

#[tokio::test]
async fn client_maps_404_envelope_to_terminal_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_envelope("not_found")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client.get_dump(DUMP_ID).await.expect_err("404 must fail");

    match &error {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 404);
            assert_eq!(code.as_deref(), Some("not_found"));
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(!error.is_transient(), "404 must never be retried");
}

#[tokio::test]
async fn client_non_envelope_error_bodies_keep_a_null_code() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Route GET:/api/v1/dumps/dump_01JABCXYZ not found",
            "error": "Not Found",
            "statusCode": 404
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client.get_dump(DUMP_ID).await.expect_err("404 must fail");

    match &error {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 404);
            assert_eq!(*code, None, "framework responses carry no envelope code");
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(!error.is_transient());
}

#[tokio::test]
async fn client_malformed_success_body_maps_to_decode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_bytes(b"{ not json".to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("malformed body must fail");

    assert!(matches!(error, AnalyzerError::Decode(_)), "got {error:?}");
    assert!(!error.is_transient());
}

#[tokio::test]
async fn client_unexpected_success_status_maps_to_decode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({ "dumps": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("202 is not a catalog success status");

    match &error {
        AnalyzerError::Decode(message) => {
            assert!(message.contains("unexpected success status"), "{message}");
        }
        other => panic!("expected Decode, got {other:?}"),
    }
    assert!(!error.is_transient());
}

#[tokio::test]
async fn client_server_failure_maps_to_transient_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(500).set_body_bytes(b"boom".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("500 must fail");

    match &error {
        AnalyzerError::Server { status, code } => {
            assert_eq!(*status, 500);
            assert_eq!(*code, None);
        }
        other => panic!("expected Server, got {other:?}"),
    }
    assert!(
        error.is_transient(),
        "5xx is retryable infrastructure failure"
    );
}

#[tokio::test]
async fn client_transport_failure_maps_to_transient_transport_error() {
    let client = LedgerClient::new(&test_config(refused_local_url())).expect("client construction");
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("closed port must fail");

    match &error {
        AnalyzerError::Transport(message) => {
            assert!(!message.contains(TOKEN), "token leaked into: {message}");
        }
        other => panic!("expected Transport, got {other:?}"),
    }
    assert!(error.is_transient());
    assert!(!format!("{error:?}").contains(TOKEN));
}

// ---------------------------------------------------------------------------
// Request deadlines
// ---------------------------------------------------------------------------

#[test]
fn client_default_api_timeout_is_thirty_seconds() {
    assert_eq!(DEFAULT_API_TIMEOUT, Duration::from_secs(30));
}

#[tokio::test]
async fn client_api_timeout_fires_early_and_is_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server)
        .await
        .with_api_timeout(Duration::from_millis(100));

    let started = Instant::now();
    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("a never-responding route must hit the request deadline");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "the 100 ms request deadline must fire long before the 5 s response delay: {elapsed:?}"
    );
    match &error {
        AnalyzerError::Transport(message) => {
            assert!(
                message.starts_with("timeout"),
                "request deadlines must classify as timeout: {message}"
            );
            assert!(!message.contains(TOKEN), "token leaked into: {message}");
        }
        other => panic!("expected Transport, got {other:?}"),
    }
    assert!(
        error.is_transient(),
        "request deadlines are retryable transport failures"
    );
}

#[tokio::test]
async fn client_content_route_is_exempt_from_the_api_total_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", ETAG)
                .set_body_bytes(b"\x01".to_vec())
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;

    // 50 ms API deadline, 300 ms response delay: the content route must not
    // inherit the JSON/API total deadline (only the client-level 30 s read
    // stall bound applies, which is far above this delay).
    let client = client_for(&server)
        .await
        .with_api_timeout(Duration::from_millis(50));

    let result = client
        .get_content(DUMP_ID, None)
        .await
        .expect("content must not inherit the API total deadline");
    match result {
        ContentResult::Bytes { bytes, etag } => {
            assert_eq!(bytes, b"\x01");
            assert_eq!(etag, ETAG);
        }
        ContentResult::NotModified => panic!("expected fresh bytes"),
    }
}

// ---------------------------------------------------------------------------
// Argument validation (client-side, before any request)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_argument_validation_rejects_before_sending() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;

    let client = client_for(&server).await;

    let cases: Vec<AnalyzerError> = vec![
        client.get_dump_by_sha256("XYZ").await.expect_err("bad sha"),
        client.get_dump("dump id").await.expect_err("bad id"),
        client
            .get_dumps(&DumpCatalogQuery::default(), Some("bad cursor"))
            .await
            .expect_err("bad cursor"),
        client
            .get_events(Some("has space"), None, None, None)
            .await
            .expect_err("bad since"),
        client
            .get_events(None, Some(&["Seal,Upload"]), None, None)
            .await
            .expect_err("comma in action"),
        client
            .get_events(None, None, None, Some(0))
            .await
            .expect_err("zero limit"),
        client
            .get_events(None, None, None, Some(501))
            .await
            .expect_err("oversized limit"),
        client
            .get_content(DUMP_ID, Some("bad\netag"))
            .await
            .expect_err("bad etag"),
    ];
    for error in cases {
        assert!(
            matches!(error, AnalyzerError::Decode(_)),
            "expected Decode, got {error:?}"
        );
        assert!(!error.is_transient());
    }

    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    assert!(
        requests.is_empty(),
        "invalid arguments must never reach the network: {requests:?}"
    );
}

// ---------------------------------------------------------------------------
// URL construction and credential hygiene
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_base_url_path_prefix_is_preserved() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/base/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "dumps": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let base = Url::parse(&format!("{}/base/", server.uri())).expect("prefixed base URL");
    let client = LedgerClient::new(&test_config(base)).expect("client construction");
    client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect("catalog page");

    let request = single_request(&server).await;
    assert_eq!(request.url.path(), "/base/api/v1/dumps");
}

#[tokio::test]
async fn client_token_never_appears_in_debug_errors_or_urls() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(401).set_body_json(error_envelope("unauthenticated")))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server).await;

    let debug = format!("{client:?}");
    assert!(
        !debug.contains(TOKEN),
        "client Debug leaked the token: {debug}"
    );

    let error = client
        .get_dumps(&DumpCatalogQuery::default(), None)
        .await
        .expect_err("401 must fail");
    assert!(!format!("{error}").contains(TOKEN));
    assert!(!format!("{error:?}").contains(TOKEN));

    let request = single_request(&server).await;
    assert!(!request.url.as_str().contains(TOKEN));
    // The credential is present exactly as the bearer header, nowhere else.
    assert_authorized(&request);
}

#[test]
fn client_new_rejects_header_hostile_token_without_echoing_it() {
    let config = test_config_with_token(refused_local_url(), "tökén-nön-ascii");
    let error = LedgerClient::new(&config).expect_err("non-ASCII tokens cannot form a header");

    match &error {
        AnalyzerError::Config(message) => {
            assert!(message.contains("DUMP_ANALYZER_TOKEN"), "{message}");
            assert!(!message.contains("tökén"), "config error echoed the token");
        }
        other => panic!("expected Config, got {other:?}"),
    }
    assert!(!error.is_transient());
}

#[test]
fn client_ledger_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LedgerClient>();
}

#[test]
fn client_tls_ca_cert_missing_file_and_garbage_pem_fail_fast() {
    let mut config = test_config(Url::parse("https://ledger.example.test").expect("url"));
    config.tls_ca_cert = Some(std::path::PathBuf::from("/nonexistent/ledger.pem"));
    let err = LedgerClient::new(&config).expect_err("missing file must fail");
    assert!(
        err.to_string().contains("DUMP_ANALYZER_TLS_CA_CERT"),
        "{err}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let pem = dir.path().join("bad.pem");
    std::fs::write(&pem, b"not a certificate").expect("write");
    config.tls_ca_cert = Some(pem);
    let err = LedgerClient::new(&config).expect_err("garbage PEM must fail");
    assert!(
        err.to_string().contains("DUMP_ANALYZER_TLS_CA_CERT"),
        "{err}"
    );
}
