//! The explorer browses the catalog independently of the local work queue.

use std::sync::Arc;

use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::Config;
use dump_analyzer::explorer::DumpsExplorer;
use dump_analyzer::state::Store;
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase};
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn setup(server: &MockServer) -> (TempDir, Store, DumpsExplorer) {
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let mut config = Config::from_env(
        [
            (
                "DUMP_ANALYZER_BASE_URL".to_owned(),
                "https://ledger.example.test".to_owned(),
            ),
            ("DUMP_ANALYZER_TOKEN".to_owned(), "test-token".to_owned()),
        ]
        .into_iter(),
    )
    .expect("config");
    config.base_url = reqwest::Url::parse(&server.uri()).expect("mock URL");
    let client = Arc::new(LedgerClient::new(&config).expect("client"));
    let explorer = DumpsExplorer::new(client, store.clone(), "0.1.0".to_owned());
    (dir, store, explorer)
}

fn identity(dump_id: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump_id.to_owned(),
        input_sha256: SHA256.to_owned(),
        kind: "triage".to_owned(),
        analyzer_version: "0.1.0".to_owned(),
    }
}

fn entry(dump_id: &str, customer_id: &str, case_id: &str) -> Value {
    json!({
        "dumpId": dump_id,
        "caseId": case_id,
        "customerId": customer_id,
        "phase": "available",
        "validation": "valid",
        "originalName": format!("{dump_id}.dmp"),
        "byteSize": "9007199254740993",
        "sha256": SHA256,
        "receivedAt": "2026-10-15T00:00:00.000Z",
        "availableAt": "2026-10-15T00:01:00.000Z",
        "purgeAt": null,
        "symbolCoverage": { "present": 0, "missing": 0, "unidentified": 0 }
    })
}

async fn page(server: &MockServer, cursor: Option<&str>, dumps: Vec<Value>, next: Option<&str>) {
    let expected_cursor = cursor.map(str::to_owned);
    let mut body = json!({ "dumps": dumps });
    if let Some(next) = next {
        body["nextCursor"] = json!(next);
    }
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(query_param("phase", "available"))
        .and(move |request: &Request| {
            request
                .url
                .query_pairs()
                .find(|(key, _)| key == "cursor")
                .map(|(_, value)| value.into_owned())
                == expected_cursor
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(server)
        .await;
}

async fn details(server: &MockServer, dump_id: &str, case_id: &str, title: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{dump_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dumpId": dump_id,
            "case": { "caseId": case_id, "title": title },
            "phase": "available",
            "originalName": format!("{dump_id}.dmp"),
            "byteSize": "9007199254740993",
            "sha256": SHA256,
            "validation": "valid",
            "downloadable": true,
            "receivedAt": "2026-10-15T00:00:00.000Z",
            "symbolCoverage": [],
            "activity": []
        })))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn explorer_follows_pages_groups_by_ids_and_retains_completed_dumps() {
    let server = MockServer::start().await;
    let (_dir, store, explorer) = setup(&server);
    let completed = identity("dump_a");
    store
        .jobs()
        .upsert_discovered(&completed)
        .expect("discover");
    store
        .jobs()
        .set_phase(&completed, JobPhase::Done)
        .expect("settle");
    assert!(store.jobs().list().expect("queue").is_empty());

    page(
        &server,
        None,
        vec![
            entry("dump_a", "customer_a", "case_a"),
            entry("dump_b", "customer_a", "case_a"),
        ],
        Some("page_2"),
    )
    .await;
    page(
        &server,
        Some("page_2"),
        vec![
            entry("dump_b", "customer_a", "case_a"),
            entry("dump_c", "customer_a", "case_b"),
            entry("dump_d", "customer_b", "case_c"),
        ],
        None,
    )
    .await;
    Mock::given(path("/api/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "customers": [
                {"customerId": "customer_b", "displayName": "Same name"},
                {"customerId": "customer_a", "displayName": "Same name"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    details(&server, "dump_b", "case_a", "Same title").await;
    details(&server, "dump_c", "case_b", "Same title").await;
    details(&server, "dump_d", "case_c", "Same title").await;

    let snapshot = explorer.snapshot().await.expect("snapshot");
    let value = serde_json::to_value(snapshot).expect("json");
    assert_eq!(value["total"], 4);
    let customers = value["customers"].as_array().expect("customers");
    assert_eq!(customers.len(), 2);
    assert_eq!(customers[0]["customerId"], "customer_a");
    assert_eq!(customers[0]["displayName"], "Same name");
    assert_eq!(customers[0]["dumpCount"], 3);
    assert_eq!(customers[0]["cases"].as_array().expect("cases").len(), 2);
    assert_eq!(customers[1]["customerId"], "customer_b");
    assert_eq!(customers[1]["dumpCount"], 1);
    let case = &customers[0]["cases"][0];
    assert_eq!(case["caseId"], "case_a");
    assert_eq!(case["title"], "Same title");
    assert_eq!(case["dumpCount"], 2);
    assert_eq!(
        case["dumps"][0],
        json!({
            "dumpId": "dump_a",
            "originalName": "dump_a.dmp",
            "byteSize": "9007199254740993",
            "sha256": SHA256,
            "receivedAt": "2026-10-15T00:00:00.000Z",
            "analysisPhase": "done"
        })
    );
    assert!(case["dumps"][1]["analysisPhase"].is_null());
}

#[tokio::test]
async fn explorer_caches_remote_catalog_but_reads_current_analysis_phase() {
    let server = MockServer::start().await;
    let (_dir, store, explorer) = setup(&server);
    let job = identity("dump_a");
    store.jobs().upsert_discovered(&job).expect("discover");
    page(
        &server,
        None,
        vec![entry("dump_a", "customer_a", "case_a")],
        None,
    )
    .await;
    Mock::given(path("/api/v1/customers"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/dumps/dump_a"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    // Concurrent first requests share the same remote refresh.
    let (first, concurrent) = tokio::join!(explorer.snapshot(), explorer.snapshot());
    for snapshot in [first.expect("first"), concurrent.expect("concurrent")] {
        assert_eq!(snapshot.customers[0].display_name, "customer_a");
        assert_eq!(snapshot.customers[0].cases[0].title, "case_a");
        assert_eq!(
            snapshot.customers[0].cases[0].dumps[0].analysis_phase,
            Some(JobPhase::Discovered)
        );
    }
    store
        .jobs()
        .set_phase(&job, JobPhase::Analyzing)
        .expect("start analysis");
    let updated = explorer.snapshot().await.expect("updated");
    assert_eq!(
        updated.customers[0].cases[0].dumps[0].analysis_phase,
        Some(JobPhase::Analyzing)
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 3);
}

#[tokio::test]
async fn explorer_empty_catalog_is_an_empty_explorer() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    page(&server, None, Vec::new(), None).await;
    let snapshot = explorer.snapshot().await.expect("empty catalog");
    assert_eq!(
        serde_json::to_value(snapshot).expect("json"),
        json!({
            "total": 0,
            "customers": []
        })
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn explorer_catalog_failures_remain_errors() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    Mock::given(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        explorer.snapshot().await,
        Err(AnalyzerError::Server { status: 503, .. })
    ));
}

#[tokio::test]
async fn explorer_repeated_cursor_is_an_error_instead_of_partial_results() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    page(
        &server,
        None,
        vec![entry("dump_a", "customer_a", "case_a")],
        Some("repeated"),
    )
    .await;
    page(&server, Some("repeated"), Vec::new(), Some("repeated")).await;
    match explorer.snapshot().await {
        Err(AnalyzerError::Decode(message)) => assert!(message.contains("repeated")),
        result => panic!("expected cursor error, got {result:?}"),
    }
}
