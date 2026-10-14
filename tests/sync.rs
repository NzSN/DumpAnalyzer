//! Catalog sync and event-follower tests (task B2).
//!
//! `wiremock` stands in for the DumpLedger read surface and a real
//! `tempfile` SQLite store is the local state, so the tested seams are
//! exactly the ones the daemon will wire together: keyset catalog scan,
//! feed application (intake/purge classification, catalog-gated scheduling),
//! cursor monotonicity, replay idempotency, and prompt shutdown.

use std::path::PathBuf;
use std::time::Duration;

use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::state::Store;
use dump_analyzer::sync::{CancellationToken, EVENT_CURSOR, follow_feed, initial_scan};
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase, Result as AnalyzerResult};
use reqwest::Url;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TOKEN: &str = "analyzer-token-0123456789abcdef";

/// Exact server-side `actions` filter pinned by R3 (analyzer guide, "Follow
/// changes"): the spelling, the comma joining, and the order are part of the
/// request contract. Spelled out here rather than imported from the module
/// so the pin cannot drift with the implementation.
const FEED_ACTIONS: &str =
    "AcceptDump,RejectDump,BeginPurge,FinishPurge,SealUpload,PromoteObject,MarkQuarantined";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// 64-lowercase-hex content hash, deterministic per label.
fn sha256(label: u8) -> String {
    format!("{label:02x}").repeat(32)
}

fn test_config(server: &MockServer) -> Config {
    Config {
        base_url: Url::parse(&server.uri()).expect("mock server URI is absolute"),
        token: Some(SecretToken::new(TOKEN)),
        state_dir: PathBuf::from("./unused-in-sync-tests"),
        name: "dump-analyzer".to_owned(),
        version: "0.9.9-test".to_owned(),
        poll_interval: Duration::from_millis(20),
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
    }
}

fn open_store(dir: &TempDir) -> Store {
    Store::open(dir.path().join("analyzer.sqlite")).expect("open store")
}

fn query_param_value(request: &Request, name: &str) -> Option<String> {
    request
        .url
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn discovered_jobs(store: &Store) -> Vec<JobIdentity> {
    store
        .jobs()
        .jobs_in_phase(JobPhase::Discovered)
        .expect("jobs_in_phase")
        .into_iter()
        .map(|(identity, _attempts)| identity)
        .collect()
}

/// Waits (bounded) until the persisted event cursor equals `expected`.
async fn await_cursor(store: &Store, expected: &str) {
    for _ in 0..500 {
        if store
            .cursors()
            .get(EVENT_CURSOR)
            .expect("cursor read")
            .as_deref()
            == Some(expected)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("event cursor never reached {expected}");
}

/// Waits (bounded) until `path` received at least `at_least` requests.
async fn await_requests(server: &MockServer, path: &str, at_least: usize) {
    for _ in 0..500 {
        let count = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count();
        if count >= at_least {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("fewer than {at_least} requests seen for {path}");
}

/// Runs [`follow_feed`] until the persisted cursor reaches `stop_at`, then
/// cancels the token and returns the follower's result.
async fn follow_until_cursor(store: &Store, config: &Config, stop_at: &str) -> AnalyzerResult<()> {
    let client = LedgerClient::new(config).expect("client");
    let token = CancellationToken::new();
    let follower = follow_feed(&client, store, config, &token);
    let driver = async {
        await_cursor(store, stop_at).await;
        token.cancel();
    };
    let (result, ()) = tokio::join!(follower, driver);
    result
}

// ---------------------------------------------------------------------------
// Fixtures (strict wire shapes)
// ---------------------------------------------------------------------------

fn catalog_entry(dump_id: &str, phase: &str, sha256: Option<&str>) -> Value {
    json!({
        "dumpId": dump_id,
        "caseId": "case_01JAB0XYZ",
        "customerId": "customer_01JAA0XYZ",
        "phase": phase,
        "validation": "valid",
        "originalName": "renderer-crash.dmp",
        "byteSize": "1073741824",
        "sha256": sha256,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "symbolCoverage": { "present": 12, "missing": 3, "unidentified": 1 }
    })
}

fn dump_detail(dump_id: &str, phase: &str, sha256: Option<&str>) -> Value {
    json!({
        "dumpId": dump_id,
        "case": { "caseId": "case_01JAB0XYZ", "title": "Renderer crash loop" },
        "phase": phase,
        "originalName": "renderer-crash.dmp",
        "byteSize": "1073741824",
        "sha256": sha256,
        "validation": "valid",
        "coverage": "full-memory-declared",
        "downloadable": true,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "purgedAt": null,
        "inspectionError": null,
        "symbolCoverage": [],
        "activity": []
    })
}

fn event(cursor: &str, action: &str, dump_id: Option<&str>) -> Value {
    json!({
        "cursor": cursor,
        "eventId": "event_01JABC001",
        "occurredAt": "2026-10-13T03:00:00.000Z",
        "action": action,
        "customerId": null,
        "caseId": "case_01JAB0XYZ",
        "dumpId": dump_id,
        "detail": { "outcome": "recorded" }
    })
}

/// Mounts one `GET /api/v1/dumps` page: `cursor = None` matches the first
/// request (no `cursor` parameter), `Some` matches that exact cursor.
async fn mount_catalog_page(server: &MockServer, cursor: Option<&str>, body: Value) {
    let given = Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(query_param("phase", "available"))
        .and(header("authorization", format!("Bearer {TOKEN}")));
    let given = match cursor {
        Some(cursor) => given.and(query_param("cursor", cursor)),
        None => given.and(query_param_is_missing("cursor")),
    };
    given
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Mounts `GET /api/v1/events` returning the same body for every request.
///
/// The mock only matches requests carrying the exact pinned `actions` query,
/// so every feed test doubles as a filter assertion: a missing or different
/// filter would leave the request unmatched and fail the follower.
async fn mount_events(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(query_param("actions", FEED_ACTIONS))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_dump_detail(server: &MockServer, dump_id: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{dump_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_initial_scan_walks_every_page_and_schedules_available_dumps() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    let sha_a = sha256(0xa1);
    let sha_b = sha256(0xb2);

    mount_catalog_page(
        &server,
        None,
        json!({
            "dumps": [
                catalog_entry("dump_A", "available", Some(&sha_a)),
                catalog_entry("dump_Q", "sealed", Some(&sha256(0xc3))),
            ],
            "nextCursor": "0000000000000010"
        }),
    )
    .await;
    mount_catalog_page(
        &server,
        Some("0000000000000010"),
        json!({
            "dumps": [
                catalog_entry("dump_Y", "available", None),
                catalog_entry("dump_B", "available", Some(&sha_b)),
            ],
            "nextCursor": "0000000000000020"
        }),
    )
    .await;
    mount_catalog_page(&server, Some("0000000000000020"), json!({ "dumps": [] })).await;

    let inserted = initial_scan(&client, &store, &config).await.expect("scan");
    assert_eq!(
        inserted, 2,
        "only available dumps with a hash are scheduled"
    );

    let jobs = discovered_jobs(&store);
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().any(|job| {
        job.dump_id == "dump_A"
            && job.input_sha256 == sha_a
            && job.kind == "triage"
            && job.analyzer_version == "0.9.9-test"
    }));
    assert!(
        jobs.iter()
            .any(|job| job.dump_id == "dump_B" && job.input_sha256 == sha_b)
    );

    // The keyset walk visited every page, in cursor order, with the filter.
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 3, "three catalog pages were fetched");
    let cursors: Vec<Option<String>> = requests
        .iter()
        .map(|request| query_param_value(request, "cursor"))
        .collect();
    assert_eq!(
        cursors,
        [
            None,
            Some("0000000000000010".to_owned()),
            Some("0000000000000020".to_owned()),
        ]
    );
    for request in &requests {
        assert_eq!(
            query_param_value(request, "phase").as_deref(),
            Some("available")
        );
    }
}

#[tokio::test]
async fn sync_interleaved_insert_between_pages_is_not_double_scheduled() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    let sha_a = sha256(0xa1);
    let sha_b = sha256(0xb2);

    // Page 1 is served; then `dump_B` lands. Keyset ordering means B can only
    // appear on page 2, and it must not be lost by the walk.
    mount_catalog_page(
        &server,
        None,
        json!({
            "dumps": [catalog_entry("dump_A", "available", Some(&sha_a))],
            "nextCursor": "0000000000000010"
        }),
    )
    .await;
    mount_catalog_page(
        &server,
        Some("0000000000000010"),
        json!({ "dumps": [catalog_entry("dump_B", "available", Some(&sha_b))] }),
    )
    .await;

    let inserted = initial_scan(&client, &store, &config).await.expect("scan");
    assert_eq!(
        inserted, 2,
        "the interleaved insert is discovered by page 2"
    );

    // The feed also reports B's intake (as it would for any new dump); the
    // replay must not schedule a second job or resurrect the first.
    mount_events(
        &server,
        json!({
            "events": [event("0000000000000020", "AcceptDump", Some("dump_B"))],
            "nextCursor": "0000000000000020"
        }),
    )
    .await;
    mount_dump_detail(
        &server,
        "dump_B",
        dump_detail("dump_B", "available", Some(&sha_b)),
    )
    .await;

    follow_until_cursor(&store, &config, "0000000000000020")
        .await
        .expect("follower");

    // Exactly the two scan-discovered jobs; the feed event for B was applied
    // against the existing identity.
    let jobs = discovered_jobs(&store);
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs.iter().filter(|job| job.dump_id == "dump_B").count(), 1);
    let requests = server.received_requests().await.expect("recorded requests");
    assert!(
        requests
            .iter()
            .any(|request| request.url.path() == "/api/v1/dumps/dump_B"),
        "the intake event re-read B's catalog entry"
    );

    // A restart rescan of the same catalog inserts nothing.
    let rescanned = initial_scan(&client, &store, &config)
        .await
        .expect("rescan");
    assert_eq!(rescanned, 0);
    assert_eq!(discovered_jobs(&store).len(), 2);
}

#[tokio::test]
async fn sync_purge_event_drops_the_job_of_any_phase_and_ignores_unknown_dumps() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    let sha_a = sha256(0xa1);
    mount_catalog_page(
        &server,
        None,
        json!({ "dumps": [catalog_entry("dump_A", "available", Some(&sha_a))] }),
    )
    .await;
    assert_eq!(
        initial_scan(&client, &store, &config).await.expect("scan"),
        1
    );

    // Move A past `discovered` so the purge has to reach a live phase.
    let claimed = store.jobs().claim_next().expect("claim").expect("one job");
    assert_eq!(claimed.0.dump_id, "dump_A");

    mount_events(
        &server,
        json!({
            "events": [
                event("0000000000000001", "BeginPurge", Some("dump_A")),
                event("0000000000000002", "FinishPurge", Some("dump_GHOST")),
            ],
            "nextCursor": "0000000000000002"
        }),
    )
    .await;

    follow_until_cursor(&store, &config, "0000000000000002")
        .await
        .expect("follower");

    let dropped = store
        .jobs()
        .jobs_in_phase(JobPhase::Dropped)
        .expect("dropped");
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].0.dump_id, "dump_A");
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("claimed")
            .is_empty()
    );
    assert!(discovered_jobs(&store).is_empty());
}

#[tokio::test]
async fn sync_cursor_regression_from_the_server_is_rejected() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    store
        .cursors()
        .set_monotonic(EVENT_CURSOR, "0000000000000050")
        .expect("seed cursor");
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000001" }),
    )
    .await;

    let error = follow_feed(&client, &store, &config, &CancellationToken::new())
        .await
        .expect_err("a regressing cursor must fail the follower");
    let AnalyzerError::State(message) = &error else {
        panic!("expected AnalyzerError::State, got {error:?}");
    };
    assert!(message.contains("backward"), "message: {message}");
    assert_eq!(
        store
            .cursors()
            .get(EVENT_CURSOR)
            .expect("cursor read")
            .as_deref(),
        Some("0000000000000050"),
        "the rejected cursor must not be persisted"
    );
}

#[tokio::test]
async fn sync_duplicate_event_replay_is_idempotent() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    let sha_c = sha256(0xc3);
    // The server keeps echoing the same page (a crash between apply and
    // cursor persist replays it the same way): the intake event is applied
    // on every poll and must converge on one job row.
    mount_events(
        &server,
        json!({
            "events": [event("0000000000000010", "AcceptDump", Some("dump_C"))],
            "nextCursor": "0000000000000010"
        }),
    )
    .await;
    mount_dump_detail(
        &server,
        "dump_C",
        dump_detail("dump_C", "available", Some(&sha_c)),
    )
    .await;

    let token = CancellationToken::new();
    let follower = follow_feed(&client, &store, &config, &token);
    let driver = async {
        await_requests(&server, "/api/v1/events", 2).await;
        token.cancel();
    };
    let (result, ()) = tokio::join!(follower, driver);
    result.expect("follower");

    let jobs = discovered_jobs(&store);
    assert_eq!(
        jobs.len(),
        1,
        "the replayed event must not add a second job"
    );
    assert_eq!(jobs[0].dump_id, "dump_C");
    assert_eq!(jobs[0].input_sha256, sha_c);
    assert_eq!(
        store
            .cursors()
            .get(EVENT_CURSOR)
            .expect("cursor read")
            .as_deref(),
        Some("0000000000000010")
    );
}

#[tokio::test]
async fn sync_cancellation_stops_an_idle_follower_promptly() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let mut config = test_config(&server);
    // A long poll interval makes the promptness meaningful: without
    // cancellation the follower would sleep out this interval.
    config.poll_interval = Duration::from_secs(60);
    let client = LedgerClient::new(&config).expect("client");

    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000000" }),
    )
    .await;

    let token = CancellationToken::new();
    let follower = follow_feed(&client, &store, &config, &token);
    let driver = async {
        await_cursor(&store, "0000000000000000").await;
        token.cancel();
    };
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(follower, driver)
    })
    .await
    .expect("the follower did not stop within 5 s of cancellation");
    outcome.0.expect("clean shutdown result");
}

#[tokio::test]
async fn sync_feed_requests_carry_the_pinned_action_filter() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir);
    let config = test_config(&server);
    let client = LedgerClient::new(&config).expect("client");

    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000000" }),
    )
    .await;

    let token = CancellationToken::new();
    let follower = follow_feed(&client, &store, &config, &token);
    let driver = async {
        await_cursor(&store, "0000000000000000").await;
        token.cancel();
    };
    let (result, ()) = tokio::join!(follower, driver);
    result.expect("follower");

    let requests = server.received_requests().await.expect("recorded requests");
    assert!(
        !requests.is_empty(),
        "the follower must have polled the feed"
    );
    for request in &requests {
        assert_eq!(request.url.path(), "/api/v1/events");
        assert_eq!(
            query_param_value(request, "actions").as_deref(),
            Some(FEED_ACTIONS),
            "the actions filter must be sent verbatim, in the pinned order"
        );
    }
    // The first poll has no persisted cursor yet, so the filter is the only
    // query parameter: nothing else may be smuggled in beside it.
    let first = &requests[0];
    let pairs: Vec<(String, String)> = first
        .url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(pairs, vec![("actions".to_owned(), FEED_ACTIONS.to_owned())]);
}
