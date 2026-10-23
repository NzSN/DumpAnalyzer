//! Tool-enabled DSH orchestration through the real local MCP endpoint and
//! controlled debugger/model doubles. No live model or Windows host is used.
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::dsh_runner::{
    DshAnalysisMcp, DshApi, DshCdbRunner, DshRoute, DshTurn, HttpDshApi, TrajectoryDigest,
};
use dump_analyzer::report::{CauseStatus, CrashReportV2};
use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::state::{ReportHandoff, Store};
use dump_analyzer::types::{AnalyzerError, JobIdentity, Result, RunBounds, RunRequest, ToolRunner};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LOG: &str = include_str!("fixtures/report-v2/marked-av.log");

#[derive(Clone, Default)]
struct Debugger {
    cleaned: Arc<AtomicBool>,
    queries: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ExecTransport for Debugger {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        _: Duration,
    ) -> Result<TransportOutput> {
        let text = if program == "rm" {
            self.cleaned.store(true, Ordering::SeqCst);
            String::new()
        } else if program != "cdb" {
            String::new()
        } else if let Some(script) = stdin {
            assert!(
                !self.cleaned.load(Ordering::SeqCst),
                "dump must survive until investigation ends"
            );
            assert_eq!(args[0], "-z");
            self.queries.fetch_add(1, Ordering::SeqCst);
            let script = std::str::from_utf8(script).unwrap();
            assert!(script.contains("db 0x1000 L0n8"));
            let begin = script
                .lines()
                .find(|l| l.starts_with(".echo DA_QUERY_BEGIN:"))
                .unwrap()
                .trim_start_matches(".echo ");
            let end = script
                .lines()
                .find(|l| l.starts_with(".echo DA_QUERY_END:"))
                .unwrap()
                .trim_start_matches(".echo ");
            format!("{begin}\n00000000`00001000  de ad be ef 00 00 00 00\n{end}\n")
        } else {
            LOG.to_owned()
        };
        Ok(TransportOutput {
            status: Some(0),
            stdout: text.into_bytes(),
            stderr: vec![],
        })
    }
    async fn put_file(&self, _: &Path, _: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Valid,
    Forensicator,
    ForensicatorUnavailable,
    BadReference,
    InvalidHypothesis,
    Confirmed,
    NoDiscovery,
    FailsAfterQuery,
    TimesOut,
}

struct Reasoner {
    mcp: Mutex<Option<DshAnalysisMcp>>,
    mode: Mode,
    closes: AtomicUsize,
    queried: tokio::sync::Notify,
}
impl Reasoner {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mcp: Mutex::new(None),
            mode,
            closes: AtomicUsize::new(0),
            queried: tokio::sync::Notify::new(),
        })
    }
    async fn rpc(mcp: &DshAnalysisMcp, id: u64, method: &str, params: Value) -> Value {
        let response = reqwest::Client::new()
            .post(&mcp.url)
            .bearer_auth(mcp.token.expose())
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }
}

#[async_trait::async_trait]
impl DshApi for Reasoner {
    async fn create_session(&self, _: &str, _: &DshRoute, _: Option<&str>) -> Result<String> {
        panic!("tool mode must use capability handoff")
    }
    async fn create_session_with_tools(
        &self,
        _: &str,
        _: &DshRoute,
        mcp: &DshAnalysisMcp,
    ) -> Result<String> {
        assert!(!format!("{mcp:?}").contains(mcp.token.expose()));
        *self.mcp.lock().unwrap() = Some(mcp.clone());
        Ok("controlled-tools-session".into())
    }
    async fn send_message(&self, _: &str, prompt: &str) -> Result<DshTurn> {
        let mcp = self.mcp.lock().unwrap().clone().unwrap();
        assert!(!prompt.contains(mcp.token.expose()));
        assert!(!prompt.contains(&mcp.url));
        assert!(prompt.contains("dump_analysis MCP tools"));
        let mut evidence_id = "exception".to_owned();
        if !matches!(self.mode, Mode::NoDiscovery) {
            let init = Self::rpc(
                &mcp,
                1,
                "initialize",
                json!({
                    "protocolVersion":"2026-07-28", "capabilities":{},
                    "clientInfo":{"name":"controlled-reasoner","version":"1"}
                }),
            )
            .await;
            assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
            let tools = Self::rpc(&mcp, 2, "tools/list", json!({})).await;
            let forensicator = matches!(
                self.mode,
                Mode::Forensicator | Mode::ForensicatorUnavailable
            );
            assert_eq!(
                tools["result"]["tools"].as_array().unwrap().len(),
                if forensicator { 10 } else { 6 }
            );
            let query = if forensicator {
                assert!(prompt.contains("Forensicator"));
                json!({"name":"forensicator_inspect", "arguments":{}})
            } else {
                json!({"name":"read_memory", "arguments":{"address":"0x1000","length":8}})
            };
            let result = Self::rpc(&mcp, 3, "tools/call", query).await;
            assert!(result["error"].is_null(), "{result}");
            let evidence: Value =
                serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            if matches!(self.mode, Mode::ForensicatorUnavailable) {
                assert_eq!(result["result"]["isError"], true);
                return Err(AnalyzerError::Runner(
                    "Forensicator unavailable in controlled test".into(),
                ));
            }
            if forensicator {
                assert_eq!(result["result"]["isError"], false);
                assert!(
                    evidence["command"]
                        .as_str()
                        .unwrap()
                        .contains("Forensicator MCP inspect")
                );
            } else {
                assert!(evidence["text"].as_str().unwrap().contains("de ad be ef"));
            }
            evidence_id = evidence["id"].as_str().unwrap().to_owned();
            self.queried.notify_one();
        }
        if matches!(self.mode, Mode::FailsAfterQuery) {
            return Err(AnalyzerError::Runner("controlled reasoning failure".into()));
        }
        if matches!(self.mode, Mode::TimesOut) {
            std::future::pending::<()>().await;
        }
        if matches!(self.mode, Mode::BadReference) {
            evidence_id = "invented-query".into();
        }
        let missing = if matches!(self.mode, Mode::InvalidHypothesis) {
            vec![]
        } else {
            vec!["Allocation history"]
        };
        Ok(DshTurn {
            model: Some("controlled-reasoner".into()),
            response: json!({
                "status":if matches!(self.mode, Mode::Confirmed) { "confirmed" } else { "hypothesis" },
                "mechanism":{"status":"unknown","description":"","evidenceRefs":[]},
                "conclusion":"The inspected bytes support a stale-state hypothesis, but do not prove its origin.",
                "evidenceRefs":[evidence_id],
                "hypotheses":[{"explanation":"The inspected object may contain stale state","evidenceRefs":[evidence_id],"missingEvidence":missing,"nextChecks":["Trace object lifetime"]}],
                "missingEvidence":["Allocation history"],"nextChecks":["Trace object lifetime"],"ruleId":null
            }),
        })
    }
    async fn trajectory_digest(&self, _: &str) -> Result<TrajectoryDigest> {
        Ok(TrajectoryDigest {
            events: 4,
            sha256: "0".repeat(64),
        })
    }
    async fn close_session(&self, _: &str) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn reasoner_can_discover_call_cite_and_persist_forensicator_evidence() {
    use std::os::unix::fs::PermissionsExt;
    for available in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("forensicator");
        if available {
            std::fs::write(&executable, include_str!("fixtures/forensicator-mcp.py")).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let debugger = Debugger::default();
        let reasoner = Reasoner::new(if available {
            Mode::Forensicator
        } else {
            Mode::ForensicatorUnavailable
        });
        let run = request(temp.path(), Duration::from_secs(5));
        let baseline = SshCdbRunner::new(Debugger::default())
            .run(run.clone())
            .await
            .unwrap()
            .capture
            .unwrap();
        let output = DshCdbRunner::new(debugger.clone(), reasoner.clone(), "analyzer-triage")
            .with_analysis_tools(true)
            .with_forensicator(Some(executable))
            .run(run)
            .await
            .unwrap();
        let capture = output.capture.as_ref().unwrap();
        assert_eq!(capture.exception, baseline.exception);
        assert_eq!(capture.symbols, baseline.symbols);
        assert_eq!(capture.root_cause.mechanism, baseline.root_cause.mechanism);
        assert!(
            capture
                .provenance
                .analysis_revision
                .contains("forensicator=mcp-stdio-v1")
        );
        let evidence = capture.evidence.iter().find(|e| e.id == "query-1").unwrap();
        assert!(evidence.command.contains("Forensicator MCP inspect"));
        if available {
            assert_eq!(capture.root_cause.evidence_refs, vec!["query-1"]);
            assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
        } else {
            assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
            assert_eq!(
                evidence.status,
                dump_analyzer::report::CaptureStatus::Failed
            );
            assert!(!capture.completeness.omissions.is_empty());
        }
        assert_eq!(debugger.queries.load(Ordering::SeqCst), 0);
        assert!(debugger.cleaned.load(Ordering::SeqCst));
        assert_eq!(reasoner.closes.load(Ordering::SeqCst), 1);
        let config = Config::from_env(
            [
                (
                    "DUMP_ANALYZER_BASE_URL".into(),
                    "https://ledger.example.test".into(),
                ),
                (
                    "DUMP_ANALYZER_VERSION".into(),
                    "0.2.0-forensicator-test".into(),
                ),
                ("DUMP_ANALYZER_WRITE_BACK".into(), "off".into()),
            ]
            .into_iter(),
        )
        .unwrap();
        let identity = JobIdentity {
            dump_id: "forensicator-fixture".into(),
            input_sha256: "0".repeat(64),
            kind: "triage".into(),
            analyzer_version: config.version.clone(),
        };
        let db = temp.path().join("state.sqlite");
        let store = Store::open(&db).unwrap();
        let (stored, _) = dump_analyzer::verdict::prepare_report(
            &store,
            &identity,
            &output,
            &config,
            ReportHandoff::None,
        )
        .unwrap();
        let mcp = reasoner.mcp.lock().unwrap().clone().unwrap();
        assert!(!stored.report_json.contains(mcp.token.expose()));
        drop(store);
        let restored = Store::open(db)
            .unwrap()
            .local_reports()
            .get_rich(&identity)
            .unwrap()
            .unwrap();
        assert_eq!(
            restored
                .report
                .capture
                .evidence
                .iter()
                .find(|e| e.id == "query-1"),
            Some(evidence)
        );
        assert!(reqwest::Client::new().post(&mcp.url).send().await.is_err());
    }
}

fn request(root: &Path, wall: Duration) -> RunRequest {
    let dump_path = root.join("verified.dmp");
    std::fs::write(&dump_path, b"controlled dump bytes").unwrap();
    RunRequest {
        dump_path,
        work_dir: root.join("work"),
        symbol_path: "C:/symbols".into(),
        bounds: RunBounds {
            wall_timeout: wall,
            max_output_bytes: 1024 * 1024,
            max_workspace_bytes: 2 * 1024 * 1024,
        },
    }
}

#[tokio::test]
async fn investigation_retains_citable_evidence_through_cleanup_and_store_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let request = request(temp.path(), Duration::from_secs(5));
    let baseline = SshCdbRunner::new(Debugger::default())
        .run(request.clone())
        .await
        .unwrap()
        .capture
        .unwrap();
    let debugger = Debugger::default();
    let reasoner = Reasoner::new(Mode::Valid);
    let output = DshCdbRunner::new(debugger.clone(), reasoner.clone(), "analyzer-triage")
        .with_analysis_tools(true)
        .run(request)
        .await
        .unwrap();
    let capture = output.capture.as_ref().unwrap();
    assert_eq!(capture.exception, baseline.exception);
    assert_eq!(capture.context, baseline.context);
    assert_eq!(capture.stack, baseline.stack);
    assert_eq!(capture.symbols, baseline.symbols);
    assert_eq!(
        capture.evidence[..baseline.evidence.len()],
        baseline.evidence
    );
    assert_eq!(capture.root_cause.mechanism, baseline.root_cause.mechanism);
    assert_eq!(capture.root_cause.evidence_refs, vec!["query-1"]);
    assert_eq!(debugger.queries.load(Ordering::SeqCst), 1);
    assert!(debugger.cleaned.load(Ordering::SeqCst));
    assert_eq!(reasoner.closes.load(Ordering::SeqCst), 1);
    let mcp = reasoner.mcp.lock().unwrap().clone().unwrap();
    assert!(
        reqwest::Client::new().post(&mcp.url).send().await.is_err(),
        "run capability must be gone"
    );
    let config = Config::from_env(
        [
            (
                "DUMP_ANALYZER_BASE_URL".into(),
                "https://ledger.example.test".into(),
            ),
            ("DUMP_ANALYZER_VERSION".into(), "0.2.0-mcp-test".into()),
            ("DUMP_ANALYZER_WRITE_BACK".into(), "off".into()),
        ]
        .into_iter(),
    )
    .unwrap();
    let identity = JobIdentity {
        dump_id: "dump_controlled".into(),
        input_sha256: "0".repeat(64),
        kind: "triage".into(),
        analyzer_version: config.version.clone(),
    };
    let db = temp.path().join("state.sqlite");
    let store = Store::open(&db).unwrap();
    let (stored, _) = dump_analyzer::verdict::prepare_report(
        &store,
        &identity,
        &output,
        &config,
        ReportHandoff::None,
    )
    .unwrap();
    assert!(!stored.report_json.contains(mcp.token.expose()));
    assert!(!stored.report_json.contains(&mcp.url));
    let digest = stored.digest;
    drop(store);
    let restored = Store::open(db)
        .unwrap()
        .local_reports()
        .get_rich(&identity)
        .unwrap()
        .unwrap();
    assert_eq!(restored.digest, digest);
    assert!(
        restored
            .report
            .capture
            .evidence
            .iter()
            .any(|e| e.id == "query-1" && e.text.contains("de ad be ef"))
    );
}

#[tokio::test]
async fn bad_reasoning_preserves_baseline_and_successful_tool_evidence() {
    for mode in [
        Mode::BadReference,
        Mode::InvalidHypothesis,
        Mode::Confirmed,
        Mode::FailsAfterQuery,
        Mode::NoDiscovery,
        Mode::TimesOut,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let debugger = Debugger::default();
        let reasoner = Reasoner::new(mode);
        let wall = if matches!(mode, Mode::TimesOut) {
            Duration::from_millis(150)
        } else {
            Duration::from_secs(5)
        };
        let output = DshCdbRunner::new(debugger.clone(), reasoner.clone(), "analyzer-triage")
            .with_analysis_tools(true)
            .run(request(temp.path(), wall))
            .await
            .unwrap();
        let capture = output.capture.as_ref().unwrap();
        assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
        assert!(!capture.evidence.iter().any(|e| e.id == "assessment-model"));
        assert!(
            capture
                .completeness
                .omissions
                .iter()
                .any(|o| o.contains("Optional causal reasoning unavailable"))
        );
        if !matches!(mode, Mode::NoDiscovery) {
            assert!(capture.evidence.iter().any(|e| e.id == "query-1"));
        }
        assert!(debugger.cleaned.load(Ordering::SeqCst));
        assert_eq!(reasoner.closes.load(Ordering::SeqCst), 1);
        let identity = JobIdentity {
            dump_id: "dump_controlled".into(),
            input_sha256: "0".repeat(64),
            kind: "triage".into(),
            analyzer_version: "test-mcp".into(),
        };
        CrashReportV2::from_output(&identity, "test", &output).unwrap();
    }
}

#[tokio::test]
async fn cancelled_investigation_revokes_mcp_and_prunes_both_sessions() {
    let temp = tempfile::tempdir().unwrap();
    let debugger = Debugger::default();
    let reasoner = Reasoner::new(Mode::TimesOut);
    let runner = DshCdbRunner::new(debugger.clone(), reasoner.clone(), "analyzer-triage")
        .with_analysis_tools(true);
    let request = request(temp.path(), Duration::from_secs(30));
    let task = tokio::spawn(async move { runner.run(request).await });
    tokio::time::timeout(Duration::from_secs(5), reasoner.queried.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !debugger.cleaned.load(Ordering::SeqCst)
            || reasoner.closes.load(Ordering::SeqCst) == 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mcp = reasoner.mcp.lock().unwrap().clone().unwrap();
    assert!(reqwest::Client::new().post(&mcp.url).send().await.is_err());
}

#[tokio::test]
async fn http_contract_requires_tool_capability_acknowledgement() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/analyzer-sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sessionId":"old-adapter"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/analyzer-sessions/old-adapter"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let api = HttpDshApi::new(
        server.uri().parse().unwrap(),
        Some(&SecretToken::new("adapter-token")),
        None,
    )
    .unwrap();
    let mcp = DshAnalysisMcp {
        url: "http://127.0.0.1:12345/mcp".into(),
        token: SecretToken::new("test-run-token"),
    };
    let error = api
        .create_session_with_tools("analyzer-triage", &DshRoute::default(), &mcp)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("did not acknowledge"));
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["analysisMcp"]["url"], mcp.url);
    assert_eq!(body["analysisMcp"]["token"], "test-run-token");
}

#[tokio::test]
async fn session_redirect_never_forwards_run_or_model_credentials() {
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&destination)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", destination.uri()))
        .mount(&source)
        .await;
    let api = HttpDshApi::new_with_api_key(
        source.uri().parse().unwrap(),
        Some(&SecretToken::new("adapter-token")),
        Some(&SecretToken::new("model-token")),
        None,
    )
    .unwrap();
    let mcp = DshAnalysisMcp {
        url: "http://127.0.0.1:12345/mcp".into(),
        token: SecretToken::new("run-token"),
    };
    let error = api
        .create_session_with_tools("analyzer-triage", &DshRoute::default(), &mcp)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("run-token"));
    assert!(destination.received_requests().await.unwrap().is_empty());
}
