//! Wiremock DSH adapter doubles qualify contract, confinement, deadline, and
//! fallback behavior without a live DeepSeek Harness service. These tests
//! qualify the provider against the documented adapter contract only; they
//! are not live-DSH qualification.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dump_analyzer::config::SecretToken;
use dump_analyzer::dsh_runner::{DshCdbRunner, HttpDshApi};
use dump_analyzer::report::CauseStatus;
use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::types::{AnalyzerError, RunBounds, RunRequest, ToolRunner};
use reqwest::Url;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const LOG: &str = include_str!("fixtures/report-v2/marked-av.log");
const BOUNDS: RunBounds = RunBounds {
    wall_timeout: Duration::from_secs(3),
    max_output_bytes: 1 << 20,
    max_workspace_bytes: 1 << 21,
};

#[derive(Clone, Default)]
struct FakeTransport {
    puts: Arc<Mutex<Vec<(PathBuf, String)>>>,
}

#[async_trait::async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        _args: &[&str],
        _stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> dump_analyzer::types::Result<TransportOutput> {
        Ok(TransportOutput {
            status: Some(0),
            stdout: if program == "cdb" {
                LOG.as_bytes().to_vec()
            } else {
                vec![]
            },
            stderr: vec![],
        })
    }
    async fn put_file(&self, local: &Path, remote: &str) -> dump_analyzer::types::Result<()> {
        self.puts
            .lock()
            .expect("lock")
            .push((local.to_owned(), remote.to_owned()));
        Ok(())
    }
}

fn request(dir: &Path, bounds: RunBounds) -> RunRequest {
    let dump = dir.join("dump.dmp");
    std::fs::write(&dump, b"authored dummy dump; no RSDS module identity").expect("dump");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).expect("work");
    RunRequest {
        dump_path: dump,
        symbol_path: "SRV*C:/symcache*https://ledger.example.test/symbols".into(),
        work_dir: work,
        bounds,
    }
}

/// The bounded hypothesis the fake service returns; cites only evidence the
/// fixture capture actually retains.
fn candidate() -> Value {
    json!({
        "status":"hypothesis",
        "mechanism":{"status":"unknown","description":"Preserve deterministic mechanism","evidenceRefs":[]},
        "conclusion":"A caller supplied an invalid pointer; its origin remains a hypothesis.",
        "evidenceRefs":["exception"],
        "hypotheses":[{"explanation":"Invalid state may have reached the call site","evidenceRefs":["exception"],"missingEvidence":["State origin"],"nextChecks":["Trace pointer lifetime"]}],
        "missingEvidence":["State origin"],"nextChecks":["Trace pointer lifetime"],"ruleId":null
    })
}

/// A responder that serves each mounted body in order, repeating the last.
struct Seq {
    bodies: Vec<Value>,
    next: AtomicUsize,
}

impl Respond for Seq {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let index = self
            .next
            .fetch_add(1, Ordering::SeqCst)
            .min(self.bodies.len() - 1);
        ResponseTemplate::new(200).set_body_json(self.bodies[index].clone())
    }
}

fn turn(body: Value) -> Value {
    json!({"status":"completed","response":body,"model":"dsh-fixture-model"})
}

fn runner(server: &MockServer, token: Option<SecretToken>) -> DshCdbRunner<FakeTransport> {
    let api = HttpDshApi::new(
        Url::parse(&server.uri()).expect("wiremock URL"),
        token.as_ref(),
        None,
    )
    .expect("DSH API client");
    DshCdbRunner::new(FakeTransport::default(), Arc::new(api), "analyzer-triage")
        .with_remote_base("C:/da/test")
}

async fn mount_lifecycle(server: &MockServer, message: impl Respond + 'static) {
    Mock::given(method("POST"))
        .and(path("/v1/analyzer-sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sessionId":"s-1"})))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/analyzer-sessions/s-1/messages"))
        .respond_with(message)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/analyzer-sessions/s-1/events"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"events":[{"type":"user"},{"type":"assistant"}]})),
        )
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/analyzer-sessions/s-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

async fn reference_capture(request: &RunRequest) -> dump_analyzer::report::ReportCapture {
    SshCdbRunner::new(FakeTransport::default())
        .run(request.clone())
        .await
        .expect("reference report")
        .capture
        .expect("reference capture")
}

#[tokio::test]
async fn happy_path_adopts_bounded_assessment_and_prunes_session() {
    let server = MockServer::start().await;
    mount_lifecycle(
        &server,
        ResponseTemplate::new(200).set_body_json(turn(candidate())),
    )
    .await;
    let dir = tempfile::tempdir().expect("directory");
    let request = request(dir.path(), BOUNDS);
    let expected = reference_capture(&request).await;
    let output = runner(&server, Some(SecretToken::new("dsh-test-token")))
        .with_model(Some("configured-model".into()))
        .run(request)
        .await
        .expect("report");
    let capture = output.capture.expect("owned capture");
    assert_eq!(capture.exception, expected.exception);
    assert_eq!(capture.context, expected.context);
    assert_eq!(capture.stack, expected.stack);
    assert_eq!(capture.symbols, expected.symbols);
    // The deterministic immediate mechanism survives; the model owns only
    // the bounded hypothesis layer.
    assert_eq!(capture.root_cause.mechanism, expected.root_cause.mechanism);
    assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
    assert_eq!(capture.provenance.provider, "dsh-http");
    assert_eq!(
        capture.provenance.model.as_deref(),
        Some("dsh-fixture-model")
    );
    assert!(
        capture
            .provenance
            .analysis_revision
            .contains("reasoner=dsh-http-v1")
    );
    let assessment = capture
        .evidence
        .iter()
        .find(|item| item.id == "assessment-model")
        .expect("assessment evidence");
    assert!(assessment.command.contains("zero-tool session s-1"));
    assert!(assessment.command.contains("trajectory 2 events sha256:"));
    assert_eq!(
        capture.evidence[..expected.evidence.len()],
        expected.evidence
    );
    assert_eq!(
        output.outcome,
        dump_analyzer::types::ReportOutcome::Completed
    );
    dump_analyzer::assessment::validate(&capture).expect("accepted assessment proof gate");

    let requests = server.received_requests().await.expect("requests");
    let methods: Vec<(String, String)> = requests
        .iter()
        .map(|r| (r.method.to_string(), r.url.path().to_owned()))
        .collect();
    assert_eq!(
        methods,
        vec![
            ("POST".into(), "/v1/analyzer-sessions".into()),
            ("POST".into(), "/v1/analyzer-sessions/s-1/messages".into()),
            ("GET".into(), "/v1/analyzer-sessions/s-1/events".into()),
            ("DELETE".into(), "/v1/analyzer-sessions/s-1".into()),
        ],
        "create -> message -> export -> prune, nothing else"
    );
    for request in &requests {
        assert_eq!(
            request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer dsh-test-token"),
            "every call carries the scoped token"
        );
    }
    let create = requests[0].body_json::<Value>().expect("create body");
    assert_eq!(create["preset"], "analyzer-triage");
    assert_eq!(create["model"], "configured-model");
    let message = requests[1].body_json::<Value>().expect("message body");
    let prompt = message["prompt"].as_str().expect("prompt");
    assert!(prompt.contains("untrusted data"));
    assert!(prompt.contains("OUTPUT_SCHEMA_JSON"));
}

#[tokio::test]
async fn one_formatting_correction_accepts_valid_response() {
    let server = MockServer::start().await;
    let invalid = turn(json!("{\"status\" \"do-not-echo-rejected\"}"));
    mount_lifecycle(
        &server,
        Seq {
            bodies: vec![invalid, turn(candidate())],
            next: AtomicUsize::new(0),
        },
    )
    .await;
    let dir = tempfile::tempdir().expect("directory");
    let request = request(dir.path(), BOUNDS);
    let capture = runner(&server, None)
        .run(request)
        .await
        .expect("corrected report")
        .capture
        .expect("capture");
    assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
    dump_analyzer::assessment::validate(&capture).expect("corrected assessment proof gate");
    let requests = server.received_requests().await.expect("requests");
    let messages: Vec<&Request> = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/analyzer-sessions/s-1/messages")
        .collect();
    assert_eq!(messages.len(), 2, "initial turn plus one correction");
    let correction = messages[1].body_json::<Value>().expect("correction body");
    let prompt = correction["prompt"].as_str().expect("correction prompt");
    assert!(prompt.contains("only formatting correction turn"));
    assert!(
        !prompt.contains("do-not-echo-rejected"),
        "rejected model text is never echoed"
    );
}

#[tokio::test]
async fn repeated_invalid_responses_fall_back_and_prune() {
    let server = MockServer::start().await;
    mount_lifecycle(
        &server,
        Seq {
            bodies: vec![turn(json!("{invalid JSON}"))],
            next: AtomicUsize::new(0),
        },
    )
    .await;
    let dir = tempfile::tempdir().expect("directory");
    let request = request(dir.path(), BOUNDS);
    let expected = reference_capture(&request).await;
    let capture = runner(&server, None)
        .run(request)
        .await
        .expect("fallback report")
        .capture
        .expect("capture");
    // Deterministic evidence and assessment are retained verbatim.
    assert_eq!(capture.root_cause, expected.root_cause);
    assert_eq!(capture.evidence, expected.evidence);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("Optional causal reasoning unavailable"))
    );
    let requests = server.received_requests().await.expect("requests");
    let messages = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/analyzer-sessions/s-1/messages")
        .count();
    assert_eq!(messages, 2, "exactly one correction turn was spent");
    assert!(
        requests
            .iter()
            .any(|r| r.method == "DELETE" && r.url.path() == "/v1/analyzer-sessions/s-1"),
        "the session is pruned even on reasoning failure"
    );
}

#[tokio::test]
async fn http_failure_falls_back_and_prunes() {
    let server = MockServer::start().await;
    mount_lifecycle(&server, ResponseTemplate::new(500)).await;
    let dir = tempfile::tempdir().expect("directory");
    let request = request(dir.path(), BOUNDS);
    let expected = reference_capture(&request).await;
    let capture = runner(&server, None)
        .run(request)
        .await
        .expect("fallback report")
        .capture
        .expect("capture");
    assert_eq!(capture.root_cause, expected.root_cause);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("HTTP 500"))
    );
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests.iter().any(|r| r.method == "DELETE"),
        "the session is pruned even on transport failure"
    );
}

#[tokio::test]
async fn reasoning_deadline_falls_back_and_prunes() {
    let server = MockServer::start().await;
    let slow = ResponseTemplate::new(200)
        .set_body_json(turn(candidate()))
        .set_delay(Duration::from_secs(30));
    mount_lifecycle(&server, slow).await;
    let dir = tempfile::tempdir().expect("directory");
    let bounds = RunBounds {
        wall_timeout: Duration::from_secs(2),
        ..BOUNDS
    };
    let request = request(dir.path(), bounds);
    let expected = reference_capture(&request).await;
    let started = Instant::now();
    let capture = runner(&server, None)
        .run(request)
        .await
        .expect("fallback report")
        .capture
        .expect("capture");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the run deadline bounds the stalled turn"
    );
    assert_eq!(capture.root_cause, expected.root_cause);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("exceeded shared run wall timeout"))
    );
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests.iter().any(|r| r.method == "DELETE"),
        "the session is pruned even after the deadline fires"
    );
}

#[tokio::test]
async fn collection_failure_never_touches_the_service() {
    let server = MockServer::start().await;
    // No mocks: any request fails the test via unmatched-request 404s.
    let dir = tempfile::tempdir().expect("directory");
    let dump = dir.path().join("dump.dmp");
    std::fs::write(&dump, b"authored dummy dump").expect("dump");
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).expect("work");
    struct FailingTransport;
    #[async_trait::async_trait]
    impl ExecTransport for FailingTransport {
        async fn exec(
            &self,
            _program: &str,
            _args: &[&str],
            _stdin: Option<&[u8]>,
            _timeout: Duration,
        ) -> dump_analyzer::types::Result<TransportOutput> {
            Err(AnalyzerError::Transport("CDB unavailable".into()))
        }
        async fn put_file(&self, _local: &Path, _remote: &str) -> dump_analyzer::types::Result<()> {
            Ok(())
        }
    }
    let api = HttpDshApi::new(Url::parse(&server.uri()).expect("URL"), None, None).expect("api");
    let runner = DshCdbRunner::new(FailingTransport, Arc::new(api), "analyzer-triage");
    let err = runner
        .run(RunRequest {
            dump_path: dump,
            symbol_path: "SRV*C:/symcache*https://ledger.example.test/symbols".into(),
            work_dir: work,
            bounds: BOUNDS,
        })
        .await
        .expect_err("collection failure propagates");
    assert!(matches!(err, AnalyzerError::Runner(_)));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "no DSH session is created when deterministic collection fails"
    );
}

/// Live qualification against a real confined DSH analyzer service
/// (deploy/dsh-adapter). Ignored by default; run explicitly:
///
/// ```sh
/// DUMP_ANALYZER_DSH_LIVE_BASE_URL=http://127.0.0.1:4181 \
/// DUMP_ANALYZER_DSH_LIVE_TOKEN=<token> \
/// cargo test --offline --test dsh_runner live_dsh -- --ignored --nocapture
/// ```
///
/// Asserts the contract and proof gates; the model's assessment quality is
/// printed for the qualification receipt, not asserted (nondeterministic).
#[tokio::test]
#[ignore = "requires a live confined DSH analyzer service"]
async fn live_dsh_http_provider_qualification() {
    let base =
        std::env::var("DUMP_ANALYZER_DSH_LIVE_BASE_URL").expect("DUMP_ANALYZER_DSH_LIVE_BASE_URL");
    let token = std::env::var("DUMP_ANALYZER_DSH_LIVE_TOKEN")
        .ok()
        .map(SecretToken::new);
    let dir = tempfile::tempdir().expect("directory");
    let bounds = RunBounds {
        wall_timeout: Duration::from_secs(170),
        ..BOUNDS
    };
    let request = request(dir.path(), bounds);
    let expected = reference_capture(&request).await;
    let api = HttpDshApi::new(
        Url::parse(&base).expect("live base URL"),
        token.as_ref(),
        None,
    )
    .expect("DSH API client");
    let output = DshCdbRunner::new(FakeTransport::default(), Arc::new(api), "analyzer-triage")
        .run(request)
        .await
        .expect("live report");
    let capture = output.capture.expect("capture");
    // Receipt evidence (printed under --nocapture).
    println!("LIVE-QUAL provider={}", capture.provenance.provider);
    println!("LIVE-QUAL model={:?}", capture.provenance.model);
    println!(
        "LIVE-QUAL revision={}",
        capture.provenance.analysis_revision
    );
    println!(
        "LIVE-QUAL root_cause.status={:?}",
        capture.root_cause.status
    );
    println!("LIVE-QUAL outcome={:?}", output.outcome);
    if let Some(entry) = capture.evidence.iter().find(|e| e.id == "assessment-model") {
        println!("LIVE-QUAL assessment.command={}", entry.command);
        println!("LIVE-QUAL assessment.bytes={}", entry.text.len());
    }
    for omission in &capture.completeness.omissions {
        println!("LIVE-QUAL omission={omission}");
    }
    // Contract gates: deterministic evidence survives verbatim; an adopted
    // assessment passes the same proof gate as every provider.
    assert_eq!(capture.exception, expected.exception);
    assert_eq!(capture.context, expected.context);
    assert_eq!(capture.stack, expected.stack);
    assert_eq!(capture.symbols, expected.symbols);
    assert_eq!(capture.provenance.provider, "dsh-http");
    assert!(
        capture
            .provenance
            .analysis_revision
            .contains("reasoner=dsh-http-v1")
    );
    if capture
        .evidence
        .iter()
        .any(|item| item.id == "assessment-model")
    {
        dump_analyzer::assessment::validate(&capture).expect("live assessment proof gate");
        assert_ne!(
            capture.root_cause, expected.root_cause,
            "an adopted live assessment extends the deterministic one"
        );
    } else {
        assert_eq!(capture.root_cause, expected.root_cause);
        assert!(
            !capture.completeness.omissions.is_empty(),
            "reasoning failure records an explicit omission"
        );
    }
}
