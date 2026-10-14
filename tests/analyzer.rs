//! On-demand component tests (`f : DumpId -> IO Report`): the real pipeline
//! (client → fetch/verify → runner) against a wiremock ledger and a fake
//! tool runner. No SSH, no CDB.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dump_analyzer::analyzer::{AnalyzeError, Analyzer, PipelineAnalyzer};
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::state::Store;
use dump_analyzer::types::{ReportOutcome, RunOutput, RunRequest, RunnerKind, ToolRunner};
use sha2::Digest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DUMP_ID: &str = "dump_01JONDEMAND";
const CONTENT: &[u8] = b"on-demand dump bytes";

fn config_for(server: &MockServer) -> Config {
    Config {
        base_url: reqwest::Url::parse(&server.uri()).expect("url"),
        token: Some(SecretToken::new("test-token")),
        state_dir: {
            // A fresh tempdir per call (leaked for the process): the pipeline
            // writes the byte cache under state_dir, and a fixed relative path
            // would leak artifacts into the repository root.
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().to_path_buf();
            std::mem::forget(dir);
            path
        },
        name: "dump-analyzer".to_string(),
        version: "0.1.0".to_string(),
        poll_interval: Duration::from_millis(10_000),
        run_wall_timeout: Duration::from_millis(600_000),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes: 10 * 1024 * 1024 * 1024,
        ssh_target: None,
        symbol_cache_dir: None,
        http_addr: None,
        runner: RunnerKind::CdbSsh,
        claude_bin: "claude".to_string(),
        claude_model: None,
        tls_ca_cert: None,
        scheduler_enabled: true,
    }
}

fn detail_json(phase: &str, sha256: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "dumpId": DUMP_ID,
        "case": { "caseId": "case_01", "title": "On demand" },
        "phase": phase,
        "originalName": "crash.dmp",
        "byteSize": format!("{}", CONTENT.len()),
        "sha256": sha256,
        "validation": "valid",
        "coverage": "partial",
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

fn content_sha() -> String {
    hex::encode(sha2::Sha256::digest(CONTENT))
}

/// Scripted runner: pops queued outcomes in order.
struct FakeRunner {
    queue: Mutex<Vec<Result<RunOutput, String>>>,
}

#[async_trait::async_trait]
impl ToolRunner for FakeRunner {
    async fn run(&self, _request: RunRequest) -> dump_analyzer::types::Result<RunOutput> {
        let next = self.queue.lock().expect("lock").remove(0);
        match next {
            Ok(output) => Ok(output),
            Err(message) => Err(dump_analyzer::types::AnalyzerError::Runner(message)),
        }
    }
}

fn good_output() -> RunOutput {
    RunOutput {
        outcome: ReportOutcome::Completed,
        summary: "access violation in app".to_string(),
        facts: serde_json::json!({ "exceptionCode": "0xc0000005" }),
    }
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    (dir, store)
}

async fn mount_detail(server: &MockServer, detail: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(server)
        .await;
}

async fn mount_content(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(CONTENT)
                .insert_header("etag", format!("\"{}\"", content_sha())),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn analyze_happy_path_returns_the_report() {
    let server = MockServer::start().await;
    mount_detail(&server, detail_json("available", Some(&content_sha()))).await;
    mount_content(&server).await;

    let config = config_for(&server);
    let (_dir, store) = store();
    let store_check = store.clone();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let runner = Arc::new(FakeRunner {
        queue: Mutex::new(vec![Ok(good_output())]),
    });
    let analyzer = PipelineAnalyzer::new(client, store, config, runner);

    let report = analyzer.analyze(DUMP_ID).await.expect("report");
    assert_eq!(report.outcome, ReportOutcome::Completed);
    assert_eq!(report.identity.dump_id, DUMP_ID);
    assert_eq!(report.identity.input_sha256, content_sha());
    assert!(report.summary.contains("access violation"));

    // The on-demand run is recorded as a pending local report (dashboard
    // visibility; the replay path posts it lazily).
    let pending = store_check.local_reports().pending().expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].dump_id, DUMP_ID);
    assert!(!pending[0].posted);
}

#[tokio::test]
async fn analyze_unknown_dump_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![]),
        }),
    );
    let err = analyzer.analyze(DUMP_ID).await.expect_err("404");
    assert!(matches!(err, AnalyzeError::NotFound(_)), "{err}");
}

#[tokio::test]
async fn analyze_rejects_unavailable_phases_and_unsealed() {
    let (_dir, store) = store();

    for detail in [
        detail_json("sealed", Some(&content_sha())),
        detail_json("available", None),
    ] {
        let server2 = MockServer::start().await;
        mount_detail(&server2, detail).await;
        let config = config_for(&server2);
        let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
        let analyzer = PipelineAnalyzer::new(
            client,
            store.clone(),
            config,
            Arc::new(FakeRunner {
                queue: Mutex::new(vec![]),
            }),
        );
        let err = analyzer.analyze(DUMP_ID).await.expect_err("not available");
        assert!(matches!(err, AnalyzeError::NotAvailable { .. }), "{err}");
    }
}

#[tokio::test]
async fn analyze_transient_runner_failures_retry_then_exhaust() {
    let server = MockServer::start().await;
    mount_detail(&server, detail_json("available", Some(&content_sha()))).await;
    mount_content(&server).await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let runner = Arc::new(FakeRunner {
        queue: Mutex::new(vec![
            Err("ssh down".to_string()),
            Err("cdb crashed".to_string()),
        ]),
    });
    let analyzer = PipelineAnalyzer::new(client, store, config, runner);
    let err = analyzer.analyze(DUMP_ID).await.expect_err("exhausted");
    assert!(matches!(err, AnalyzeError::Transient(_)), "{err}");
}

#[tokio::test]
async fn analyze_retries_once_and_succeeds() {
    let server = MockServer::start().await;
    mount_detail(&server, detail_json("available", Some(&content_sha()))).await;
    mount_content(&server).await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let runner = Arc::new(FakeRunner {
        queue: Mutex::new(vec![Err("transient".to_string()), Ok(good_output())]),
    });
    let analyzer = PipelineAnalyzer::new(client, store, config, runner);
    let report = analyzer.analyze(DUMP_ID).await.expect("recovered");
    assert_eq!(report.outcome, ReportOutcome::Completed);
}

#[tokio::test]
async fn analyze_purge_mid_run_is_not_found() {
    let server = MockServer::start().await;
    mount_detail(&server, detail_json("available", Some(&content_sha()))).await;
    // Content 404 with an envelope: purged between detail and fetch.
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            serde_json::json!({ "error": { "code": "not_found", "message": "purged" } }),
        ))
        .mount(&server)
        .await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![]),
        }),
    );
    let err = analyzer.analyze(DUMP_ID).await.expect_err("purged");
    assert!(matches!(err, AnalyzeError::NotFound(_)), "{err}");
}

// ---------------------------------------------------------------------------
// Scope analysis (case / customer)
// ---------------------------------------------------------------------------

use wiremock::matchers::{path as mock_path, query_param};

const DUMP_B: &str = "dump_01JONDEMANDB";
const CONTENT_B: &[u8] = b"on-demand dump bytes B";

fn content_sha_b() -> String {
    hex::encode(sha2::Sha256::digest(CONTENT_B))
}

fn detail_json_for(dump_id: &str, phase: &str, sha256: Option<&str>) -> serde_json::Value {
    let mut v = detail_json(phase, sha256);
    v["dumpId"] = serde_json::Value::String(dump_id.to_string());
    v
}

fn catalog_entry_for(dump_id: &str, sha256: &str) -> serde_json::Value {
    serde_json::json!({
        "dumpId": dump_id,
        "caseId": "case_01",
        "customerId": "customer_01",
        "phase": "available",
        "validation": "valid",
        "originalName": "crash.dmp",
        "byteSize": "1048576",
        "sha256": sha256,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "symbolCoverage": { "present": 1, "missing": 2, "unidentified": 0 }
    })
}

async fn mount_dump(server: &MockServer, dump_id: &str, content: &'static [u8]) {
    let sha = hex::encode(sha2::Sha256::digest(content));
    Mock::given(method("GET"))
        .and(mock_path(format!("/api/v1/dumps/{dump_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail_json_for(
            dump_id,
            "available",
            Some(&sha),
        )))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(mock_path(format!("/api/v1/dumps/{dump_id}/content")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(content)
                .insert_header("etag", format!("\"{sha}\"")),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn analyze_case_runs_every_available_dump() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(mock_path("/api/v1/dumps"))
        .and(query_param("caseId", "case_01"))
        .and(query_param("phase", "available"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": [
                catalog_entry_for(DUMP_ID, &content_sha()),
                catalog_entry_for(DUMP_B, &content_sha_b()),
            ]
        })))
        .mount(&server)
        .await;
    mount_dump(&server, DUMP_ID, CONTENT).await;
    mount_dump(&server, DUMP_B, CONTENT_B).await;

    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let runner = Arc::new(FakeRunner {
        queue: Mutex::new(vec![Ok(good_output()), Ok(good_output())]),
    });
    let analyzer = PipelineAnalyzer::new(client, store, config, runner);

    let report = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Case(
            "case_01".to_string(),
        ))
        .await
        .expect("scope report");
    assert_eq!(report.scope, "case case_01");
    assert_eq!(report.considered, 2);
    assert_eq!(report.reports.len(), 2);
    assert!(report.skipped.is_empty());
    assert_eq!(report.reports[0].identity.dump_id, DUMP_ID);
    assert_eq!(report.reports[1].identity.dump_id, DUMP_B);
}

#[tokio::test]
async fn analyze_scope_isolates_a_per_dump_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(mock_path("/api/v1/dumps"))
        .and(query_param("customerId", "customer_01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": [
                catalog_entry_for(DUMP_ID, &content_sha()),
                catalog_entry_for(DUMP_B, &content_sha_b()),
            ]
        })))
        .mount(&server)
        .await;
    // First dump's content 404s (purged), second is fine.
    Mock::given(method("GET"))
        .and(mock_path(format!("/api/v1/dumps/{DUMP_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail_json_for(
            DUMP_ID,
            "available",
            Some(&content_sha()),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(mock_path(format!("/api/v1/dumps/{DUMP_ID}/content")))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            serde_json::json!({ "error": { "code": "not_found", "message": "purged" } }),
        ))
        .mount(&server)
        .await;
    mount_dump(&server, DUMP_B, CONTENT_B).await;

    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let runner = Arc::new(FakeRunner {
        queue: Mutex::new(vec![Ok(good_output())]),
    });
    let analyzer = PipelineAnalyzer::new(client, store, config, runner);

    let report = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Customer(
            "customer_01".to_string(),
        ))
        .await
        .expect("scope report");
    assert_eq!(report.considered, 2);
    assert_eq!(report.reports.len(), 1);
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].dump_id, DUMP_ID);
}

#[tokio::test]
async fn analyze_scope_empty_case_is_an_empty_batch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(mock_path("/api/v1/dumps"))
        .and(query_param("caseId", "case_empty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "dumps": [] })))
        .mount(&server)
        .await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![]),
        }),
    );
    let report = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Case(
            "case_empty".to_string(),
        ))
        .await
        .expect("empty batch");
    assert_eq!(report.considered, 0);
    assert!(report.reports.is_empty());
    assert!(report.skipped.is_empty());
}

// ---------------------------------------------------------------------------
// Customer name resolution (display name → id)
// ---------------------------------------------------------------------------

async fn mount_customers(server: &MockServer, customers: serde_json::Value) {
    Mock::given(method("GET"))
        .and(mock_path("/api/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "customers": customers
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn analyze_scope_resolves_a_customer_display_name() {
    let server = MockServer::start().await;
    mount_customers(
        &server,
        serde_json::json!([
            { "customerId": "customer_real-id-1", "displayName": "Acme Corp" }
        ]),
    )
    .await;
    Mock::given(method("GET"))
        .and(mock_path("/api/v1/dumps"))
        .and(query_param("customerId", "customer_real-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": [catalog_entry_for(DUMP_ID, &content_sha())]
        })))
        .mount(&server)
        .await;
    mount_dump(&server, DUMP_ID, CONTENT).await;

    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![Ok(good_output())]),
        }),
    );
    let report = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Customer(
            "Acme Corp".to_string(),
        ))
        .await
        .expect("resolved by name");
    assert_eq!(report.considered, 1);
    assert_eq!(report.reports.len(), 1);
}

#[tokio::test]
async fn analyze_scope_unknown_customer_name_is_not_found() {
    let server = MockServer::start().await;
    mount_customers(
        &server,
        serde_json::json!([
            { "customerId": "customer_real-id-1", "displayName": "Acme Corp" }
        ]),
    )
    .await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![]),
        }),
    );
    let err = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Customer(
            "No Such Corp".to_string(),
        ))
        .await
        .expect_err("unknown name");
    assert!(matches!(err, AnalyzeError::NotFound(_)), "{err}");
}

#[tokio::test]
async fn analyze_scope_ambiguous_customer_name_is_terminal() {
    let server = MockServer::start().await;
    mount_customers(
        &server,
        serde_json::json!([
            { "customerId": "customer_a", "displayName": "Acme" },
            { "customerId": "customer_b", "displayName": "Acme" }
        ]),
    )
    .await;
    let config = config_for(&server);
    let (_dir, store) = store();
    let client = dump_analyzer::client::LedgerClient::new(&config).expect("client");
    let analyzer = PipelineAnalyzer::new(
        client,
        store,
        config,
        Arc::new(FakeRunner {
            queue: Mutex::new(vec![]),
        }),
    );
    let err = analyzer
        .analyze_scope(&dump_analyzer::analyzer::AnalysisScope::Customer(
            "Acme".to_string(),
        ))
        .await
        .expect_err("ambiguous");
    assert!(matches!(err, AnalyzeError::Terminal(_)), "{err}");
}
