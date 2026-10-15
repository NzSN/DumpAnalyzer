//! Status-UI integration tests: a real loopback listener over a seeded
//! state store, exercised with a real HTTP client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dump_analyzer::http;
use dump_analyzer::state::Store;
use dump_analyzer::sync::CancellationToken;
use dump_analyzer::types::{JobIdentity, JobPhase, ReportOutcome};
use reqwest::Url;
use tokio::net::TcpListener;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA256_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn identity(dump: &str, sha: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump.to_string(),
        input_sha256: sha.to_string(),
        kind: "triage".to_string(),
        analyzer_version: "0.1.0".to_string(),
    }
}

fn test_config() -> dump_analyzer::config::Config {
    dump_analyzer::config::Config {
        base_url: Url::parse("https://ledger.example.test").expect("url"),
        token: Some(dump_analyzer::config::SecretToken::new(
            "never-me-in-output",
        )),
        state_dir: std::path::PathBuf::from("./unused-in-http-tests"),
        name: "dump-analyzer".to_string(),
        version: "0.1.0".to_string(),
        poll_interval: Duration::from_millis(10_000),
        run_wall_timeout: Duration::from_millis(600_000),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes: 10 * 1024 * 1024 * 1024,
        ssh_target: Some("windows-dev".to_string()),
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

struct RunningUi {
    addr: SocketAddr,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<dump_analyzer::types::Result<()>>,
}

async fn start(store: Store) -> RunningUi {
    let config = test_config();
    let context = http::UiContext::new(&config, store);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

fn seed(store: &Store) {
    let jobs = store.jobs();
    let job_a = identity("dump_01AAA", SHA256_A);
    let job_b = identity("dump_01BBB", SHA256_B);
    jobs.upsert_discovered(&job_a).expect("upsert a");
    jobs.upsert_discovered(&job_b).expect("upsert b");
    jobs.set_phase(&job_a, JobPhase::Done).expect("done a");
    jobs.set_phase(&job_b, JobPhase::Analyzing)
        .expect("analyzing b");
    jobs.record_attempt(&job_b).expect("attempt b");
    store
        .cursors()
        .set_monotonic("event_cursor", "00000000000000000042")
        .expect("cursor");
    store
        .local_reports()
        .insert(
            &job_a,
            ReportOutcome::Completed,
            "triage complete <ok>",
            "{}",
        )
        .expect("insert report");
}

#[tokio::test]
async fn http_dashboard_and_json_api() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    seed(&store);
    let ui = start(store).await;
    let base = format!("http://{}", ui.addr);
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("reqwest client");

    // The dashboard is a static shell; all data flows through /api/*.
    let html = client
        .get(format!("{base}/"))
        .send()
        .await
        .expect("GET /")
        .text()
        .await
        .expect("body");
    assert!(html.contains("<title>DumpAnalyzer</title>"), "shell title");
    assert!(html.contains(r#"id="jobs""#), "jobs container");
    assert!(html.contains("Work queue"), "queue heading");
    for panel in ["queue", "dumps", "reports", "settings"] {
        assert!(
            html.contains(&format!("id=\"panel-{panel}\"")),
            "separate {panel} panel"
        );
        assert!(
            html.contains(&format!("href=\"#{panel}\"")),
            "{panel} navigation"
        );
    }
    assert!(html.contains("No active jobs."), "queue empty state");
    assert!(html.contains("/api/capabilities"), "capabilities probe");

    assert!(
        !html.contains("never-me-in-output"),
        "the token is never embedded in the shell"
    );
    assert!(
        !html.contains("dump_01AAA"),
        "no server data is embedded in the static shell"
    );

    // JSON status.
    let status = client
        .get(format!("{base}/api/status"))
        .send()
        .await
        .expect("GET /api/status")
        .bytes()
        .await
        .expect("body");
    let status: serde_json::Value = serde_json::from_slice(&status).expect("json");
    assert_eq!(status["jobs"]["total"], 1);
    assert!(status["jobs"]["byPhase"].get("done").is_none());
    assert_eq!(status["jobs"]["byPhase"]["analyzing"], 1);
    assert_eq!(status["reports"]["pending"], 1);
    assert_eq!(status["eventCursor"], "00000000000000000042");
    assert!(status["sshConfigured"].as_bool().expect("bool"));

    // JSON jobs.
    let jobs = client
        .get(format!("{base}/api/jobs"))
        .send()
        .await
        .expect("GET /api/jobs")
        .bytes()
        .await
        .expect("body");
    let jobs: serde_json::Value = serde_json::from_slice(&jobs).expect("json");
    let list = jobs["jobs"].as_array().expect("jobs array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["dumpId"], "dump_01BBB");
    assert_eq!(list[0]["phase"], "analyzing");
    assert_eq!(list[0]["attempts"], 1);

    // JSON reports.
    let reports = client
        .get(format!("{base}/api/reports"))
        .send()
        .await
        .expect("GET /api/reports")
        .bytes()
        .await
        .expect("body");
    let reports: serde_json::Value = serde_json::from_slice(&reports).expect("json");
    let list = reports["reports"].as_array().expect("reports array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["outcome"], "completed");
    assert_eq!(list[0]["posted"], false);

    // Method and unknown routes.
    let post = client
        .post(format!("{base}/api/status"))
        .send()
        .await
        .expect("POST");
    assert_eq!(post.status(), 405);
    let missing = client
        .get(format!("{base}/nope"))
        .send()
        .await
        .expect("GET /nope");
    assert_eq!(missing.status(), 404);

    // Clean shutdown: cancel the token and the accept loop returns.
    ui.shutdown.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), ui.task)
        .await
        .expect("server stops on shutdown")
        .expect("join");
    assert!(result.is_ok(), "clean stop: {result:?}");
}

#[tokio::test]
async fn terminal_jobs_leave_the_work_queue_and_keep_reports() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let completed = identity("dump_01DONE", SHA256_A);
    let failed = identity("dump_01FAILED", SHA256_B);
    let dropped = identity("dump_01DROPPED", SHA256_A);
    for job in [&completed, &failed, &dropped] {
        store.jobs().upsert_discovered(job).expect("discover job");
        store
            .jobs()
            .set_phase(job, JobPhase::Analyzing)
            .expect("start job");
    }
    let ui = start(store.clone()).await;
    let base = format!("http://{}", ui.addr);
    let client = test_client();

    let fetch = |path: &str| client.get(format!("{base}{path}"));
    let response = fetch("/api/jobs").send().await.expect("GET jobs");
    let jobs: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(jobs["jobs"].as_array().expect("jobs array").len(), 3);
    let response = fetch("/api/status").send().await.expect("GET status");
    let status: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(status["jobs"]["total"], 3);

    store
        .local_reports()
        .insert(
            &completed,
            ReportOutcome::Completed,
            "finished analysis",
            "{}",
        )
        .expect("save report");
    for (job, phase) in [
        (&completed, JobPhase::Done),
        (&failed, JobPhase::Failed),
        (&dropped, JobPhase::Dropped),
    ] {
        store.jobs().set_phase(job, phase).expect("settle job");
    }

    let response = fetch("/api/jobs").send().await.expect("GET settled jobs");
    let jobs: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert!(jobs["jobs"].as_array().expect("jobs array").is_empty());
    let response = fetch("/api/status")
        .send()
        .await
        .expect("GET settled status");
    let status: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(status["jobs"]["total"], 0);
    assert!(
        status["jobs"]["byPhase"]
            .as_object()
            .expect("phase counts")
            .is_empty()
    );
    assert_eq!(status["reports"]["pending"], 1);
    let response = fetch("/api/reports").send().await.expect("GET reports");
    let reports: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    let reports = reports["reports"].as_array().expect("reports array");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["dumpId"], "dump_01DONE");
    assert_eq!(reports[0]["outcome"], "completed");
    assert_eq!(reports[0]["summary"], "finished analysis");

    ui.shutdown.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), ui.task)
        .await
        .expect("server stops on shutdown")
        .expect("join");
    assert!(result.is_ok(), "clean stop: {result:?}");
}

#[tokio::test]
async fn http_empty_state_renders() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start(store).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("reqwest client");
    let jobs = client
        .get(format!("http://{}/api/jobs", ui.addr))
        .send()
        .await
        .expect("GET /api/jobs")
        .bytes()
        .await
        .expect("body");
    let jobs: serde_json::Value = serde_json::from_slice(&jobs).expect("json");
    assert_eq!(jobs["jobs"].as_array().expect("array").len(), 0);
    let reports = client
        .get(format!("http://{}/api/reports", ui.addr))
        .send()
        .await
        .expect("GET /api/reports")
        .bytes()
        .await
        .expect("body");
    let reports: serde_json::Value = serde_json::from_slice(&reports).expect("json");
    assert_eq!(reports["reports"].as_array().expect("array").len(), 0);
    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

// ---------------------------------------------------------------------------
// POST /-/analyze — the on-demand component endpoint
// ---------------------------------------------------------------------------

struct FakeAnalyzer {
    outcome: Result<dump_analyzer::analyzer::Report, dump_analyzer::analyzer::AnalyzeError>,
}

#[async_trait::async_trait]
impl dump_analyzer::analyzer::Analyzer for FakeAnalyzer {
    async fn analyze(
        &self,
        dump_id: &str,
    ) -> Result<dump_analyzer::analyzer::Report, dump_analyzer::analyzer::AnalyzeError> {
        match &self.outcome {
            Ok(report) => Ok(dump_analyzer::analyzer::Report {
                identity: JobIdentity {
                    dump_id: dump_id.to_string(),
                    ..report.identity.clone()
                },
                ..report.clone()
            }),
            Err(_) => match &self.outcome {
                Err(dump_analyzer::analyzer::AnalyzeError::NotFound(_)) => Err(
                    dump_analyzer::analyzer::AnalyzeError::NotFound(dump_id.to_string()),
                ),
                Err(dump_analyzer::analyzer::AnalyzeError::NotAvailable { .. }) => {
                    Err(dump_analyzer::analyzer::AnalyzeError::NotAvailable {
                        dump_id: dump_id.to_string(),
                        reason: "phase is sealed".to_string(),
                    })
                }
                Err(dump_analyzer::analyzer::AnalyzeError::Transient(_)) => {
                    Err(dump_analyzer::analyzer::AnalyzeError::Transient(
                        dump_analyzer::types::AnalyzerError::Transport("down".to_string()),
                    ))
                }
                _ => unreachable!(),
            },
        }
    }

    async fn analyze_scope(
        &self,
        _scope: &dump_analyzer::analyzer::AnalysisScope,
    ) -> Result<dump_analyzer::analyzer::ScopeReport, dump_analyzer::analyzer::AnalyzeError> {
        unreachable!("single-dump tests never call analyze_scope")
    }
}

fn canned_report() -> dump_analyzer::analyzer::Report {
    dump_analyzer::analyzer::Report {
        identity: JobIdentity {
            dump_id: "dump_x".to_string(),
            input_sha256: SHA256_A.to_string(),
            kind: "triage".to_string(),
            analyzer_version: "0.1.0".to_string(),
        },
        outcome: ReportOutcome::Completed,
        summary: "access violation in app.exe".to_string(),
        facts: Some(serde_json::json!({ "exceptionCode": "0xc0000005" })),
    }
}

async fn start_with_analyzer(
    store: Store,
    outcome: Result<dump_analyzer::analyzer::Report, dump_analyzer::analyzer::AnalyzeError>,
) -> RunningUi {
    let config = test_config();
    let context = http::UiContext::new(&config, store)
        .with_analyzer(std::sync::Arc::new(FakeAnalyzer { outcome }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        std::sync::Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn analyze_requires_the_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer(store, Ok(canned_report())).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    let url = format!("http://{}/-/analyze", ui.addr);
    let body = r#"{"dumpId":"dump_01AAA"}"#;

    // No Authorization header = "use the daemon's stored token" (200 here);
    // a WRONG presented token is still 401.
    let no_auth = client.post(&url).body(body).send().await.expect("post");
    assert_eq!(no_auth.status(), 200, "no header uses the stored token");
    let wrong = client
        .post(&url)
        .header("authorization", "Bearer wrong-token")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(wrong.status(), 401);
    let wrong_scheme = client
        .post(&url)
        .header("authorization", "Basic never-me-in-output")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(wrong_scheme.status(), 401);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn analyze_happy_path_returns_the_report_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer(store, Ok(canned_report())).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");

    let response = client
        .post(format!("http://{}/-/analyze", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .header("content-type", "application/json")
        .body(r#"{"dumpId":"dump_01AAA"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body["report"]["dumpId"], "dump_01AAA");
    assert_eq!(body["report"]["outcome"], "completed");
    assert_eq!(body["report"]["inputSha256"], SHA256_A);
    assert_eq!(body["report"]["facts"]["exceptionCode"], "0xc0000005");

    // Malformed bodies are 400.
    let bad = client
        .post(format!("http://{}/-/analyze", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .body(r#"{"nope":1}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(bad.status(), 400);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn analyze_error_mapping() {
    for (outcome, want) in [
        (
            Err(dump_analyzer::analyzer::AnalyzeError::NotFound(
                "x".to_string(),
            )),
            404,
        ),
        (
            Err(dump_analyzer::analyzer::AnalyzeError::NotAvailable {
                dump_id: "x".to_string(),
                reason: "sealed".to_string(),
            }),
            409,
        ),
        (
            Err(dump_analyzer::analyzer::AnalyzeError::Transient(
                dump_analyzer::types::AnalyzerError::Transport("down".to_string()),
            )),
            503,
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
        let ui = start_with_analyzer(store, outcome).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client");
        let response = client
            .post(format!("http://{}/-/analyze", ui.addr))
            .header("authorization", "Bearer never-me-in-output")
            .body(r#"{"dumpId":"dump_01AAA"}"#)
            .send()
            .await
            .expect("post");
        assert_eq!(response.status(), want);
        ui.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
    }
}

#[tokio::test]
async fn analyze_form_renders_a_result_page() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer(store, Ok(canned_report())).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");

    let response = client
        .post(format!("http://{}/-/analyze-form", ui.addr))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("dumpId=dump_01AAA&token=never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let html = response.text().await.expect("body");
    assert!(html.contains("On-demand analysis"));
    assert!(html.contains("access violation in app.exe"));
    assert!(html.contains("dump_01AAA"));
    assert!(!html.contains("never-me-in-output"), "token never rendered");

    // Wrong form token → 401.
    let denied = client
        .post(format!("http://{}/-/analyze-form", ui.addr))
        .body("dumpId=dump_01AAA&token=nope")
        .send()
        .await
        .expect("post");
    assert_eq!(denied.status(), 401);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

// ---------------------------------------------------------------------------
// Contextual actions on the dashboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dashboard_capabilities_reflect_wiring() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer(store, Ok(canned_report())).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");

    // The shell always carries the actions card; the client enables per wiring.
    let html = client
        .get(format!("http://{}/", ui.addr))
        .send()
        .await
        .expect("GET /")
        .text()
        .await
        .expect("body");
    assert!(
        html.contains(r#"id="actions-card""#),
        "actions card in shell"
    );
    assert!(html.contains(r#"data-act="dump""#), "dump action form");
    assert!(html.contains(r#"data-act="case""#), "case action form");
    assert!(
        html.contains(r#"data-act="customer""#),
        "customer action form"
    );

    let caps = client
        .get(format!("http://{}/api/capabilities", ui.addr))
        .send()
        .await
        .expect("GET /api/capabilities")
        .bytes()
        .await
        .expect("body");
    let caps: serde_json::Value = serde_json::from_slice(&caps).expect("json");
    assert_eq!(caps["analyzer"], true);
    assert_eq!(caps["rescan"], false);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn dashboard_without_analyzer_reports_no_capability() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start(store).await; // no analyzer wired
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");

    let caps = client
        .get(format!("http://{}/api/capabilities", ui.addr))
        .send()
        .await
        .expect("GET /api/capabilities")
        .bytes()
        .await
        .expect("body");
    let caps: serde_json::Value = serde_json::from_slice(&caps).expect("json");
    assert_eq!(caps["analyzer"], false);
    assert_eq!(caps["rescan"], false);

    // The mutation endpoint still reports 500 (not wired) rather than pretending.
    let response = client
        .post(format!("http://{}/-/analyze", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .body(r#"{"dumpId":"dump_01AAA"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 500);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

/// One available catalog row (strict wire shape; mirrors tests/sync.rs).
fn catalog_entry(dump_id: &str) -> serde_json::Value {
    serde_json::json!({
        "dumpId": dump_id,
        "caseId": "case_01JAB0XYZ",
        "customerId": "customer_01JAA0XYZ",
        "phase": "available",
        "validation": "valid",
        "originalName": "crash.dmp",
        "byteSize": "1048576",
        "sha256": SHA256_A,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "symbolCoverage": { "present": 1, "missing": 2, "unidentified": 0 }
    })
}

/// Starts the UI with BOTH the analyzer and rescan deps wired (the rescan
/// ledger URL may be unreachable; nothing calls it in these tests).
async fn start_with_analyzer_and_rescan(store: Store, server_url: &str) -> RunningUi {
    let mut config = test_config();
    config.base_url = reqwest::Url::parse(server_url).expect("url");
    let client =
        std::sync::Arc::new(dump_analyzer::client::LedgerClient::new(&config).expect("client"));
    let context = http::UiContext::new(&config, store.clone())
        .with_analyzer(std::sync::Arc::new(FakeAnalyzer {
            outcome: Ok(canned_report()),
        }))
        .with_rescan(http::RescanDeps::new(client, store, config.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        std::sync::Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
}

/// Starts the UI with rescan deps pointing at the given ledger (wiremock).
async fn start_with_rescan(store: Store, server_url: &str) -> RunningUi {
    let mut config = test_config();
    config.base_url = reqwest::Url::parse(server_url).expect("mock server URI");
    let client =
        std::sync::Arc::new(dump_analyzer::client::LedgerClient::new(&config).expect("client"));
    let context = http::UiContext::new(&config, store.clone()).with_rescan(http::RescanDeps::new(
        client,
        store,
        config.clone(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        std::sync::Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn http_rescan_requires_the_token() {
    let server = MockServer::start().await;
    // Exactly one request may reach the ledger: the stored-token scan. The
    // rejected (wrong-token) attempts must never touch it.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, &server.uri()).await;
    let client = test_client();
    let url = format!("http://{}/-/rescan", ui.addr);

    // No header = stored token: the rescan RUNS (and touches the ledger).
    let no_auth = client.post(&url).send().await.expect("post");
    assert_eq!(no_auth.status(), 200, "no header uses the stored token");
    let wrong = client
        .post(&url)
        .header("authorization", "Bearer wrong-token")
        .send()
        .await
        .expect("post");
    assert_eq!(wrong.status(), 401);
    let wrong_scheme = client
        .post(&url)
        .header("authorization", "Basic never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(wrong_scheme.status(), 401);

    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    // The no-header call ran one catalog scan; the 401s touched nothing.
    assert_eq!(requests.len(), 1, "exactly the stored-token scan ran");

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_get_is_method_not_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    // GET must be answered before any dependency/auth handling.
    let ui = start(store).await;
    let client = test_client();

    let response = client
        .get(format!("http://{}/-/rescan", ui.addr))
        .send()
        .await
        .expect("GET");
    assert_eq!(response.status(), 405);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body["error"], "method_not_allowed");

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_empty_catalog_reports_zero_and_sends_exact_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(query_param("phase", "available"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, &server.uri()).await;
    let client = test_client();

    let response = client
        .post(format!("http://{}/-/rescan", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body["inserted"], 0);

    // Exact request the route produced: one page fetch, phase-filtered.
    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    assert_eq!(requests.len(), 1, "one catalog page fetch");
    assert_eq!(requests[0].url.path(), "/api/v1/dumps");
    let pairs: Vec<(String, String)> = requests[0]
        .url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        pairs,
        vec![("phase".to_string(), "available".to_string())],
        "the scan must filter server-side by phase=available"
    );
    assert_eq!(
        requests[0]
            .headers
            .get("authorization")
            .expect("bearer header")
            .to_str()
            .expect("ascii"),
        "Bearer never-me-in-output"
    );

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_inserts_one_available_dump_and_is_idempotent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": [catalog_entry("dump_01RESCAN")]
        })))
        .expect(2)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store.clone(), &server.uri()).await;
    let client = test_client();
    let url = format!("http://{}/-/rescan", ui.addr);

    let first: serde_json::Value = serde_json::from_slice(
        &client
            .post(&url)
            .header("authorization", "Bearer never-me-in-output")
            .send()
            .await
            .expect("post")
            .bytes()
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(first["inserted"], 1);

    let jobs = store.jobs().list().expect("jobs");
    assert_eq!(jobs.len(), 1, "exactly one job scheduled");
    assert_eq!(jobs[0].identity.dump_id, "dump_01RESCAN");
    assert_eq!(jobs[0].identity.input_sha256, SHA256_A);
    assert_eq!(jobs[0].identity.kind, "triage");
    assert_eq!(jobs[0].phase, JobPhase::Discovered);

    // Replaying the same catalogue is a no-op (upsert dedup), not an error.
    let second: serde_json::Value = serde_json::from_slice(
        &client
            .post(&url)
            .header("authorization", "Bearer never-me-in-output")
            .send()
            .await
            .expect("post")
            .bytes()
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(second["inserted"], 0);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_maps_transient_failure_to_503() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_bytes(b"boom".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, &server.uri()).await;
    let client = test_client();

    let response = client
        .post(format!("http://{}/-/rescan", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 503);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body, serde_json::json!({ "error": "transient" }));

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_terminal_failure_is_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_bytes(b"{ not json".to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, &server.uri()).await;
    let client = test_client();

    let response = client
        .post(format!("http://{}/-/rescan", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 500);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body["error"], "terminal");

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_unwired_is_500() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start(store).await; // no rescan deps
    let client = test_client();

    let response = client
        .post(format!("http://{}/-/rescan", ui.addr))
        .header("authorization", "Bearer never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 500);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("body")).expect("json");
    assert_eq!(body["error"], "terminal");
    assert!(
        body["message"]
            .as_str()
            .expect("message")
            .contains("not wired"),
        "unwired rescan must say so: {body}"
    );

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_rescan_form_runs_and_renders_count() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, &server.uri()).await;
    let client = test_client();

    let response = client
        .post(format!("http://{}/-/rescan-form", ui.addr))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    let html = response.text().await.expect("body");
    assert!(html.contains("Catalog rescan"));
    assert!(html.contains("inserted: 0"), "count rendered: {html}");
    assert!(!html.contains("never-me-in-output"), "token never rendered");

    // Wrong form token → 401, and the ledger is not touched again.
    let denied = client
        .post(format!("http://{}/-/rescan-form", ui.addr))
        .body("token=nope")
        .send()
        .await
        .expect("post");
    assert_eq!(denied.status(), 401);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_dashboard_rescan_capability_follows_wiring() {
    let client = test_client();

    // Unwired: capabilities say rescan is off (the client hides the form).
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start(store).await;
    let caps = client
        .get(format!("http://{}/api/capabilities", ui.addr))
        .send()
        .await
        .expect("GET /api/capabilities")
        .bytes()
        .await
        .expect("body");
    let caps: serde_json::Value = serde_json::from_slice(&caps).expect("json");
    assert_eq!(caps["rescan"], false, "unwired");
    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;

    // Rescan-only: capability on, analyzer off. The ledger URL is never
    // contacted while serving these reads.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_rescan(store, "http://127.0.0.1:1").await;
    let caps = client
        .get(format!("http://{}/api/capabilities", ui.addr))
        .send()
        .await
        .expect("GET /api/capabilities")
        .bytes()
        .await
        .expect("body");
    let caps: serde_json::Value = serde_json::from_slice(&caps).expect("json");
    assert_eq!(caps["rescan"], true, "wired");
    assert_eq!(caps["analyzer"], false, "analyzer stays off");

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn http_dashboard_shares_one_actions_card() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer_and_rescan(store, "http://127.0.0.1:1").await;
    let client = test_client();

    // The static shell carries one actions card with all four action forms;
    // the client enables them per /api/capabilities.
    let html = client
        .get(format!("http://{}/", ui.addr))
        .send()
        .await
        .expect("GET /")
        .text()
        .await
        .expect("body");
    assert_eq!(html.matches(r#"id="actions-card""#).count(), 1);
    assert_eq!(html.matches(r#"data-act="dump""#).count(), 1);
    assert_eq!(html.matches(r#"data-act="case""#).count(), 1);
    assert_eq!(html.matches(r#"data-act="customer""#).count(), 1);
    assert_eq!(html.matches(r#"data-act="rescan""#).count(), 1);

    let caps = client
        .get(format!("http://{}/api/capabilities", ui.addr))
        .send()
        .await
        .expect("GET /api/capabilities")
        .bytes()
        .await
        .expect("body");
    let caps: serde_json::Value = serde_json::from_slice(&caps).expect("json");
    assert_eq!(caps["analyzer"], true);
    assert_eq!(caps["rescan"], true);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

// ---------------------------------------------------------------------------
// POST /-/analyze-case and /-/analyze-customer
// ---------------------------------------------------------------------------

struct FakeScopeAnalyzer;

#[async_trait::async_trait]
impl dump_analyzer::analyzer::Analyzer for FakeScopeAnalyzer {
    async fn analyze(
        &self,
        dump_id: &str,
    ) -> Result<dump_analyzer::analyzer::Report, dump_analyzer::analyzer::AnalyzeError> {
        let _ = dump_id;
        unreachable!("scope tests never call single-dump analyze")
    }

    async fn analyze_scope(
        &self,
        scope: &dump_analyzer::analyzer::AnalysisScope,
    ) -> Result<dump_analyzer::analyzer::ScopeReport, dump_analyzer::analyzer::AnalyzeError> {
        Ok(dump_analyzer::analyzer::ScopeReport {
            scope: scope.describe(),
            considered: 2,
            reports: vec![canned_report()],
            skipped: vec![dump_analyzer::analyzer::SkippedDump {
                dump_id: "dump_gone".to_string(),
                reason: "dump not found".to_string(),
            }],
        })
    }
}

async fn start_with_scope_analyzer(store: Store) -> RunningUi {
    let config = test_config();
    let context =
        http::UiContext::new(&config, store).with_analyzer(std::sync::Arc::new(FakeScopeAnalyzer));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        std::sync::Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn analyze_case_and_customer_json_routes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_scope_analyzer(store).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");

    for (route, key) in [
        ("/-/analyze-case", "caseId"),
        ("/-/analyze-customer", "customerId"),
    ] {
        // No header = stored token → 200; the batch runs.
        let no_auth = client
            .post(format!("http://{}{}", ui.addr, route))
            .body(format!(r#"{{"{key}":"x"}}"#))
            .send()
            .await
            .expect("post");
        assert_eq!(
            no_auth.status(),
            200,
            "{route} without header uses the stored token"
        );

        // 200 with the batch report.
        let ok = client
            .post(format!("http://{}{}", ui.addr, route))
            .header("authorization", "Bearer never-me-in-output")
            .body(format!(r#"{{"{key}":"case_01"}}"#))
            .send()
            .await
            .expect("post");
        assert_eq!(ok.status(), 200, "{route}");
        let body: serde_json::Value =
            serde_json::from_slice(&ok.bytes().await.expect("body")).expect("json");
        assert_eq!(body["considered"], 2);
        assert_eq!(body["reports"].as_array().expect("reports").len(), 1);
        assert_eq!(body["skipped"].as_array().expect("skipped").len(), 1);

        // 400 on a malformed body.
        let bad = client
            .post(format!("http://{}{}", ui.addr, route))
            .header("authorization", "Bearer never-me-in-output")
            .body(r#"{"nope":1}"#)
            .send()
            .await
            .expect("post");
        assert_eq!(bad.status(), 400, "{route} malformed");
    }

    // The form route renders the result page.
    let form = client
        .post(format!("http://{}/-/analyze-case-form", ui.addr))
        .body("caseId=case_01&token=never-me-in-output")
        .send()
        .await
        .expect("post");
    assert_eq!(form.status(), 200);
    let html = form.text().await.expect("body");
    assert!(html.contains("case case_01"));
    assert!(html.contains("2 considered, 1 reported, 1 skipped"));

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn empty_token_uses_the_stored_token_and_none_configured_denies() {
    let client = test_client();

    // With a configured token, an empty form token uses the daemon's token.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_with_analyzer(store, Ok(canned_report())).await;
    let response = client
        .post(format!("http://{}/-/analyze-form", ui.addr))
        .body("dumpId=dump_01AAA&token=")
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200, "empty token uses the stored one");
    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;

    // With NO token configured anywhere, nothing can authenticate.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let mut config = test_config();
    config.token = None;
    let context = http::UiContext::new(&config, store);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        std::sync::Arc::new(context),
        shutdown.clone(),
    ));
    let response = client
        .post(format!("http://{addr}/-/analyze"))
        .header("authorization", "Bearer never-me-in-output")
        .body(r#"{"dumpId":"dump_01AAA"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 401, "no configured token denies all");
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// ---------------------------------------------------------------------------
// POST /-/store-token (+ form)
// ---------------------------------------------------------------------------

/// Starts the UI with rescan deps pointing at the given ledger (needed so the
/// context can probe); analyzer stays unwired.
async fn start_for_token_store(store: Store, server_url: &str) -> RunningUi {
    start_with_rescan(store, server_url).await
}

#[tokio::test]
async fn store_token_probes_the_ledger_and_updates_live_auth() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [], "nextCursor": "00000000000000000001"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_for_token_store(store.clone(), &server.uri()).await;
    let client = test_client();

    // Whitespace is malformed.
    let bad = client
        .post(format!("http://{}/-/store-token", ui.addr))
        .body(r#"{"token":"two words"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(bad.status(), 400);

    // A token the ledger accepts is stored and immediately usable.
    let ok = client
        .post(format!("http://{}/-/store-token", ui.addr))
        .body(r#"{"token":"fresh-token"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(ok.status(), 200);
    assert_eq!(
        store.secrets().get("analyzer_token").expect("get"),
        Some("fresh-token".to_string())
    );

    // The probe carried the candidate as the bearer credential.
    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.iter().any(
        |r| r.headers.get("authorization").and_then(|v| v.to_str().ok())
            == Some("Bearer fresh-token")
    ));

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn store_token_ledger_rejection_stores_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "unauthenticated", "message": "no", "retryable": false }
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_for_token_store(store.clone(), &server.uri()).await;
    let client = test_client();

    let rejected = client
        .post(format!("http://{}/-/store-token", ui.addr))
        .body(r#"{"token":"bad-token"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(rejected.status(), 401);
    assert_eq!(store.secrets().get("analyzer_token").expect("get"), None);

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn store_token_form_renders_a_result_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [], "nextCursor": "00000000000000000001"
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("analyzer.sqlite")).expect("store");
    let ui = start_for_token_store(store, &server.uri()).await;
    let client = test_client();

    let form = client
        .post(format!("http://{}/-/store-token-form", ui.addr))
        .body("token=form-token")
        .send()
        .await
        .expect("post");
    assert_eq!(form.status(), 200);
    let html = form.text().await.expect("body");
    assert!(html.contains("stored"));
    assert!(!html.contains("form-token"), "token never rendered");

    ui.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), ui.task).await;
}

#[tokio::test]
async fn discovered_dumps_do_not_appear_in_jobs_or_queue_counts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("analyzer.sqlite")).unwrap();
    let idle = identity("dump_DISCOVERED", SHA256_A);
    let claimed = identity("dump_CLAIMED", SHA256_A);
    let reporting = identity("dump_REPORTING", SHA256_B);
    for job in [&idle, &claimed, &reporting] {
        store.jobs().upsert_discovered(job).unwrap();
    }
    store.jobs().set_phase(&claimed, JobPhase::Claimed).unwrap();
    store
        .jobs()
        .set_phase(&reporting, JobPhase::Reporting)
        .unwrap();
    let ui = start(store.clone()).await;
    let client = test_client();
    let body = client
        .get(format!("http://{}/api/jobs", ui.addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let jobs = body["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().all(|row| row["phase"] != "discovered"));
    let status = client
        .get(format!("http://{}/api/status", ui.addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let status: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status["jobs"]["total"], 2);
    assert!(status["jobs"]["byPhase"].get("discovered").is_none());
    assert_eq!(
        store.jobs().phase_of(&idle).unwrap(),
        Some(JobPhase::Discovered),
        "Discovery remains available to the scheduler"
    );
    ui.shutdown.cancel();
    ui.task.await.unwrap().unwrap();
}

async fn start_with_explorer(store: Store, server_url: &str) -> RunningUi {
    let mut config = test_config();
    config.base_url = Url::parse(server_url).unwrap();
    let client = Arc::new(dump_analyzer::client::LedgerClient::new(&config).unwrap());
    let explorer = Arc::new(dump_analyzer::explorer::DumpsExplorer::new(
        client,
        store.clone(),
        config.version.clone(),
    ));
    let context = http::UiContext::new(&config, store).with_explorer(explorer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        Arc::new(context),
        shutdown.clone(),
    ));
    RunningUi {
        addr,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn http_explorer_groups_catalog_dumps_independently_of_jobs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(query_param("phase", "available"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dumps":[catalog_entry("dump_READY"),catalog_entry("dump_DONE")]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "customers":[{"customerId":"customer_01JAA0XYZ", "displayName":"Customer <one>"}]
        })))
        .mount(&server)
        .await;
    // Detail metadata is absent on this server; grouping falls back to case ID.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("analyzer.sqlite")).unwrap();
    let ready = identity("dump_READY", SHA256_A);
    let done = identity("dump_DONE", SHA256_A);
    store.jobs().upsert_discovered(&ready).unwrap();
    store.jobs().upsert_discovered(&done).unwrap();
    store.jobs().set_phase(&done, JobPhase::Done).unwrap();
    let ui = start_with_explorer(store.clone(), &server.uri()).await;
    let client = test_client();
    let base = format!("http://{}", ui.addr);
    let response = client
        .get(format!("{base}/api/dumps"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(!text.contains("never-me-in-output"));
    let data: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(data["total"], 2);
    let customer = &data["customers"][0];
    assert_eq!(customer["displayName"], "Customer <one>");
    assert_eq!(customer["dumpCount"], 2);
    let case = &customer["cases"][0];
    assert_eq!(case["caseId"], "case_01JAB0XYZ");
    assert_eq!(case["title"], "case_01JAB0XYZ");
    let dumps = case["dumps"].as_array().unwrap();
    assert!(
        dumps
            .iter()
            .any(|d| d["dumpId"] == "dump_READY" && d["analysisPhase"] == "discovered")
    );
    assert!(
        dumps
            .iter()
            .any(|d| d["dumpId"] == "dump_DONE" && d["analysisPhase"] == "done")
    );
    let jobs: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/jobs"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(jobs["jobs"].as_array().unwrap().is_empty());
    let caps: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/api/capabilities"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(caps["explorer"], true);
    assert_eq!(
        store.jobs().phase_of(&ready).unwrap(),
        Some(JobPhase::Discovered)
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );
    ui.shutdown.cancel();
    ui.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_catalog_failure_does_not_break_the_jobs_api() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("analyzer.sqlite")).unwrap();
    let job = identity("dump_RUNNING", SHA256_A);
    store.jobs().upsert_discovered(&job).unwrap();
    store.jobs().set_phase(&job, JobPhase::Analyzing).unwrap();
    let ui = start_with_explorer(store, &server.uri()).await;
    let client = test_client();
    let response = client
        .get(format!("http://{}/api/dumps", ui.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let response = client
        .get(format!("http://{}/api/jobs", ui.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(data["jobs"][0]["dumpId"], "dump_RUNNING");
    ui.shutdown.cancel();
    ui.task.await.unwrap().unwrap();
}

struct BlockingUiAnalyzer {
    running: std::sync::atomic::AtomicBool,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl dump_analyzer::analyzer::Analyzer for BlockingUiAnalyzer {
    async fn analyze(
        &self,
        _dump_id: &str,
    ) -> std::result::Result<dump_analyzer::analyzer::Report, dump_analyzer::analyzer::AnalyzeError>
    {
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.release.notified().await;
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(canned_report())
    }
    async fn analyze_scope(
        &self,
        _scope: &dump_analyzer::analyzer::AnalysisScope,
    ) -> std::result::Result<
        dump_analyzer::analyzer::ScopeReport,
        dump_analyzer::analyzer::AnalyzeError,
    > {
        unreachable!("scope analysis is not used in this test")
    }
    fn active_jobs(&self) -> dump_analyzer::types::Result<Vec<dump_analyzer::state::JobRow>> {
        Ok(if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            vec![dump_analyzer::state::JobRow {
                identity: identity("dump_01AAA", SHA256_A),
                phase: JobPhase::Claimed,
                attempts: 0,
                created_at: "2026-10-15T00:00:00Z".into(),
                updated_at: "2026-10-15T00:00:00Z".into(),
            }]
        } else {
            vec![]
        })
    }
}

#[tokio::test]
async fn manual_execution_is_visible_in_jobs_and_explorer_until_completion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"dumps":[catalog_entry("dump_01AAA")]})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.sqlite")).unwrap();
    store
        .jobs()
        .upsert_discovered(&identity("dump_01AAA", SHA256_A))
        .unwrap();
    let mut config = test_config();
    config.base_url = server.uri().parse().unwrap();
    let ledger = Arc::new(dump_analyzer::client::LedgerClient::new(&config).unwrap());
    let analyzer = Arc::new(BlockingUiAnalyzer {
        running: std::sync::atomic::AtomicBool::new(false),
        release: tokio::sync::Notify::new(),
    });
    let context = http::UiContext::new(&config, store.clone())
        .with_analyzer(analyzer.clone())
        .with_explorer(Arc::new(dump_analyzer::explorer::DumpsExplorer::new(
            ledger,
            store,
            config.version.clone(),
        )));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(http::serve_listener(
        listener,
        Arc::new(context),
        shutdown.clone(),
    ));
    let client = test_client();
    let request = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .post(format!("http://{addr}/-/analyze"))
                .body(r#"{"dumpId":"dump_01AAA"}"#)
                .send()
                .await
                .unwrap()
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !analyzer.running.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let read = |path: &str| client.get(format!("http://{addr}{path}"));
    let jobs: serde_json::Value = serde_json::from_str(
        &read("/api/jobs")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(jobs["jobs"][0]["phase"], "claimed");
    let status: serde_json::Value = serde_json::from_str(
        &read("/api/status")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status["jobs"]["total"], 1);
    let dumps: serde_json::Value = serde_json::from_str(
        &read("/api/dumps")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        dumps["customers"][0]["cases"][0]["dumps"][0]["analysisPhase"],
        "claimed"
    );
    let page: serde_json::Value = serde_json::from_str(
        &read("/api/dumps/browse?customerId=customer_01JAA0XYZ&caseId=case_01JAB0XYZ")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(page["dumps"][0]["analysisPhase"], "claimed");
    analyzer.release.notify_one();
    assert_eq!(request.await.unwrap().status(), 200);
    let jobs: serde_json::Value = serde_json::from_str(
        &read("/api/jobs")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(jobs["jobs"].as_array().unwrap().is_empty());
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_reports_are_bounded_and_status_counts_cover_the_complete_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("reports.sqlite")).unwrap();
    for n in 0..257 {
        let id = identity(&format!("dump_REPORT{n:04}"), SHA256_A);
        store
            .local_reports()
            .insert(
                &id,
                if n % 2 == 0 {
                    ReportOutcome::Completed
                } else {
                    ReportOutcome::Failed
                },
                "searchable report",
                "{}",
            )
            .unwrap();
        if n % 2 == 0 {
            store.local_reports().mark_posted(&id).unwrap();
        }
    }
    let ui = start(store).await;
    let client = test_client();
    let base = format!("http://{}", ui.addr);
    let get = |path: &str| client.get(format!("{base}{path}"));
    let result: serde_json::Value = serde_json::from_str(
        &get("/api/reports")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["total"], 257);
    assert_eq!(result["matching"], 257);
    assert_eq!(result["reports"].as_array().unwrap().len(), 25);
    assert_eq!(result["pageSize"], 25);
    assert_eq!(result["totalPages"], 11);
    let result: serde_json::Value = serde_json::from_str(
        &get("/api/reports?page=2&pageSize=10&outcome=failed&delivery=pending&q=searchable")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["page"], 2);
    assert_eq!(result["matching"], 128);
    assert_eq!(result["reports"].as_array().unwrap().len(), 10);
    assert!(
        result["reports"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["outcome"] == "failed" && r["posted"] == false)
    );
    let status: serde_json::Value = serde_json::from_str(
        &get("/api/status")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status["reports"]["total"], 257);
    assert_eq!(status["reports"]["pending"], 128);
    for query in [
        "page=0",
        "pageSize=101",
        "pageSize=0",
        "page=wat",
        "page=1&page=2",
        "outcome=unknown",
        "delivery=unknown",
        "unknown=1",
    ] {
        let response = get(&format!("/api/reports?{query}")).send().await.unwrap();
        assert_eq!(response.status(), 400, "{query}");
    }
    ui.shutdown.cancel();
    ui.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_dump_browse_returns_one_level_and_one_page() {
    let server = MockServer::start().await;
    let dumps: Vec<_> = (0..60)
        .map(|n| catalog_entry(&format!("dump_PAGE{n:03}")))
        .collect();
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"dumps":dumps})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("browse.sqlite")).unwrap();
    let ui = start_with_explorer(store, &server.uri()).await;
    let client = test_client();
    let base = format!("http://{}", ui.addr);
    let get = |path: &str| client.get(format!("{base}{path}"));
    let root: serde_json::Value = serde_json::from_str(
        &get("/api/dumps/browse")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(root["level"], "customers");
    assert_eq!(root["total"], 60);
    assert_eq!(root["customers"].as_array().unwrap().len(), 1);
    assert!(root["customers"][0].get("cases").is_none());
    assert!(root["dumps"].as_array().unwrap().is_empty());
    let cases: serde_json::Value = serde_json::from_str(
        &get("/api/dumps/browse?customerId=customer_01JAA0XYZ")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cases["level"], "cases");
    assert_eq!(cases["cases"][0]["dumpCount"], 60);
    assert!(cases["dumps"].as_array().unwrap().is_empty());
    let result:serde_json::Value=serde_json::from_str(&get("/api/dumps/browse?customerId=customer_01JAA0XYZ&caseId=case_01JAB0XYZ&page=2&pageSize=25").send().await.unwrap().text().await.unwrap()).unwrap();
    assert_eq!(result["level"], "dumps");
    assert_eq!(result["scopeDumpCount"], 60);
    assert_eq!(result["matching"], 60);
    assert_eq!(result["dumps"].as_array().unwrap().len(), 25);
    assert_eq!(result["page"], 2);
    assert_eq!(result["totalPages"], 3);
    for query in [
        "caseId=case_01JAB0XYZ",
        "page=0",
        "pageSize=101",
        "customerId=",
        "page=1&page=2",
        "other=1",
    ] {
        assert_eq!(
            get(&format!("/api/dumps/browse?{query}"))
                .send()
                .await
                .unwrap()
                .status(),
            400,
            "{query}"
        );
    }
    assert_eq!(
        get("/api/dumps/browse?customerId=customer_UNKNOWN")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    ui.shutdown.cancel();
    ui.task.await.unwrap().unwrap();
}
