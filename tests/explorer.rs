//! The explorer browses the catalog independently of the local work queue.

use std::sync::Arc;

use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::Config;
use dump_analyzer::explorer::{BrowseQuery, DumpsExplorer};
use dump_analyzer::state::Store;
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase};
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path, path_regex, query_param};
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

async fn unnamed_metadata(server: &MockServer) {
    Mock::given(path("/api/v1/customers"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(path_regex("^/api/v1/dumps/[^/]+$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

#[tokio::test]
async fn browse_large_catalog_returns_only_bounded_rows_at_each_level() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    let mut dumps = Vec::new();
    for customer in 0..40 {
        for case in 0..5 {
            for dump in 0..50 {
                dumps.push(entry(
                    &format!("dump_{customer:02}_{case}_{dump:02}"),
                    &format!("customer_{customer:02}"),
                    &format!("case_{customer:02}_{case}"),
                ));
            }
        }
    }
    // Respect the ledger protocol's 4096-row page bound while exercising a
    // catalog substantially larger than a single upstream page.
    for (index, chunk) in dumps.chunks(2500).enumerate() {
        let cursor = (index > 0).then(|| format!("page_{index}"));
        let next = (index < 3).then(|| format!("page_{}", index + 1));
        page(&server, cursor.as_deref(), chunk.to_vec(), next.as_deref()).await;
    }
    unnamed_metadata(&server).await;

    let root = explorer
        .browse(&BrowseQuery::default())
        .await
        .expect("root");
    assert_eq!(
        (root.total, root.scope_dump_count, root.matching),
        (10_000, 10_000, 40)
    );
    assert_eq!((root.page, root.page_size, root.total_pages), (1, 25, 2));
    assert_eq!(root.customers.len(), 25);
    assert_eq!(
        (root.customers[0].case_count, root.customers[0].dump_count),
        (5, 250)
    );
    assert!(root.cases.is_empty() && root.dumps.is_empty());
    let wire = serde_json::to_value(&root).expect("wire");
    assert!(wire["customers"][0].get("cases").is_none());
    assert!(wire["customer"].is_null() && wire["case"].is_null());
    let last = explorer
        .browse(&BrowseQuery {
            page: usize::MAX,
            ..BrowseQuery::default()
        })
        .await
        .expect("last root");
    assert_eq!(last.page, 2);
    assert_eq!(last.customers.len(), 15);
    assert_eq!(last.customers[0].customer_id, "customer_25");

    let cases = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_00".to_owned()),
            page: 2,
            page_size: 2,
            ..BrowseQuery::default()
        })
        .await
        .expect("cases");
    assert_eq!(cases.level, "cases");
    assert_eq!(
        (cases.scope_dump_count, cases.matching, cases.total_pages),
        (250, 5, 3)
    );
    assert_eq!(cases.cases.len(), 2);
    assert_eq!(cases.cases[0].case_id, "case_00_2");
    assert!(cases.customers.is_empty() && cases.dumps.is_empty());
    assert!(
        serde_json::to_value(&cases).expect("wire")["cases"][0]
            .get("dumps")
            .is_none()
    );

    let dumps = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_00".to_owned()),
            case_id: Some("case_00_0".to_owned()),
            page: 2,
            ..BrowseQuery::default()
        })
        .await
        .expect("dumps");
    assert_eq!(dumps.level, "dumps");
    assert_eq!(
        (dumps.total, dumps.scope_dump_count, dumps.matching),
        (10_000, 50, 50)
    );
    assert_eq!(dumps.dumps.len(), 25);
    assert_eq!(dumps.dumps[0].dump_id, "dump_00_0_25");
    assert!(dumps.customers.is_empty() && dumps.cases.is_empty());
    assert_eq!(
        serde_json::to_value(&dumps).expect("wire")["case"]["caseId"],
        "case_00_0"
    );
}

#[tokio::test]
async fn browse_search_preserves_parent_matches_and_full_scope_counts() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    page(
        &server,
        None,
        vec![
            entry("dump_alpha", "customer_a", "case_a"),
            entry("dump_beta", "customer_a", "case_a"),
            entry("dump_gamma", "customer_a", "case_b"),
            entry("dump_delta", "customer_b", "case_c"),
        ],
        None,
    )
    .await;
    Mock::given(path("/api/v1/customers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"customers": [
                {"customerId":"customer_a", "displayName":"Acme"},
                {"customerId":"customer_b", "displayName":"Beta"}
            ]})),
        )
        .mount(&server)
        .await;
    details(&server, "dump_beta", "case_a", "Renderer crashes").await;
    details(&server, "dump_gamma", "case_b", "GPU crashes").await;
    details(&server, "dump_delta", "case_c", "Other").await;

    let root = explorer
        .browse(&BrowseQuery {
            q: "  ALPHA.DMP ".to_owned(),
            ..BrowseQuery::default()
        })
        .await
        .expect("root search");
    assert_eq!(
        (root.total, root.scope_dump_count, root.matching),
        (4, 4, 1)
    );
    assert_eq!(root.customers[0].customer_id, "customer_a");
    assert_eq!(root.customers[0].dump_count, 3);
    let cases = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_a".to_owned()),
            q: "AcME".to_owned(),
            ..BrowseQuery::default()
        })
        .await
        .expect("inherited customer");
    assert_eq!((cases.scope_dump_count, cases.matching), (3, 2));
    let dumps = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_a".to_owned()),
            case_id: Some("case_a".to_owned()),
            q: " RENDERER ".to_owned(),
            ..BrowseQuery::default()
        })
        .await
        .expect("inherited case");
    assert_eq!((dumps.scope_dump_count, dumps.matching), (2, 2));
    let filtered = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_a".to_owned()),
            case_id: Some("case_a".to_owned()),
            q: "dump_alpha".to_owned(),
            ..BrowseQuery::default()
        })
        .await
        .expect("dump search");
    assert_eq!(
        (filtered.total, filtered.scope_dump_count, filtered.matching),
        (4, 2, 1)
    );
    assert_eq!(filtered.dumps[0].dump_id, "dump_alpha");
    let empty = explorer
        .browse(&BrowseQuery {
            customer_id: Some("customer_a".to_owned()),
            q: "no matching dump".to_owned(),
            page: 99,
            ..BrowseQuery::default()
        })
        .await
        .expect("empty search");
    assert_eq!((empty.scope_dump_count, empty.matching), (3, 0));
    assert_eq!((empty.page, empty.total_pages), (1, 0));
    assert!(empty.cases.is_empty());
}

#[tokio::test]
async fn browse_validates_queries_and_handles_empty_or_unknown_scopes() {
    let server = MockServer::start().await;
    let (_dir, _store, explorer) = setup(&server);
    for query in [
        BrowseQuery {
            page: 0,
            ..BrowseQuery::default()
        },
        BrowseQuery {
            page_size: 0,
            ..BrowseQuery::default()
        },
        BrowseQuery {
            page_size: 101,
            ..BrowseQuery::default()
        },
        BrowseQuery {
            case_id: Some("case_a".to_owned()),
            ..BrowseQuery::default()
        },
    ] {
        assert!(matches!(
            explorer.browse(&query).await,
            Err(AnalyzerError::Server { status: 400, .. })
        ));
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
    page(&server, None, Vec::new(), None).await;
    let empty = explorer
        .browse(&BrowseQuery {
            page: usize::MAX,
            page_size: 100,
            ..BrowseQuery::default()
        })
        .await
        .expect("empty");
    assert_eq!((empty.page, empty.total_pages, empty.matching), (1, 0, 0));
    assert!(empty.customers.is_empty() && empty.cases.is_empty() && empty.dumps.is_empty());
    assert!(
        matches!(explorer.browse(&BrowseQuery { customer_id: Some("unknown".to_owned()), ..BrowseQuery::default() }).await,
        Err(AnalyzerError::Server { status: 404, code: Some(code) }) if code == "scope_not_found")
    );
}

#[tokio::test]
async fn browse_phase_is_current_and_only_page_dumps_are_enriched() {
    let server = MockServer::start().await;
    let (dir, store, explorer) = setup(&server);
    let job = identity("dump_a");
    let other = identity("dump_b");
    store.jobs().upsert_discovered(&job).expect("job");
    store.jobs().upsert_discovered(&other).expect("other");
    page(
        &server,
        None,
        vec![
            entry("dump_a", "customer_a", "case_a"),
            entry("dump_b", "customer_a", "case_a"),
        ],
        None,
    )
    .await;
    unnamed_metadata(&server).await;
    let query = BrowseQuery {
        customer_id: Some("customer_a".to_owned()),
        case_id: Some("case_a".to_owned()),
        page_size: 1,
        ..BrowseQuery::default()
    };
    assert_eq!(
        explorer.browse(&query).await.expect("first").dumps[0].analysis_phase,
        Some(JobPhase::Discovered)
    );
    store
        .jobs()
        .set_phase(&job, JobPhase::Analyzing)
        .expect("analyzing");
    // An invalid phase outside the current page proves browsing does not query
    // every dump's phase before applying the page limit.
    let connection =
        rusqlite::Connection::open(dir.path().join("analyzer.sqlite")).expect("connection");
    connection
        .execute(
            "UPDATE jobs SET phase = 'invalid' WHERE dump_id = 'dump_b'",
            [],
        )
        .expect("corrupt off-page phase");
    assert_eq!(
        explorer.browse(&query).await.expect("updated").dumps[0].analysis_phase,
        Some(JobPhase::Analyzing)
    );
    assert!(
        explorer
            .browse(&BrowseQuery {
                page: 2,
                ..query.clone()
            })
            .await
            .is_err()
    );
    assert!(explorer.browse(&BrowseQuery::default()).await.is_ok());
    assert!(
        matches!(explorer.browse(&BrowseQuery { case_id: Some("unknown".to_owned()), ..query }).await,
        Err(AnalyzerError::Server { status: 404, code: Some(code) }) if code == "scope_not_found")
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 3);
}
