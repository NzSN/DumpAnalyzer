//! `Agent` pipeline tests (task C1): the spec's stage machine driven
//! against a wiremock DumpLedger, an in-memory `ToolRunner` fake, and a
//! fake [`VerdictSink`]. Covers the happy path (cache miss + ETag `304`
//! revalidation), pinned-hash refetch, purge drop, bounded tool-runner
//! retries, write-back outcomes, workspace wiping, and crash recovery.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use dump_analyzer::agent::{Agent, MAX_ATTEMPTS, VerdictSink};
use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::state::Store;
use dump_analyzer::types::{
    AnalyzerError, JobIdentity, JobPhase, ReportOutcome, RunOutput, RunRequest, ToolRunner,
};

type TyResult<T> = dump_analyzer::types::Result<T>;

const TOKEN: &str = "analyzer-token-0123456789abcdef";
/// Strong content validator, quoted, as the server emits it.
const ETAG: &str = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";
const KIND: &str = "triage";
const VERSION: &str = "0.1.0";

/// Byte-cache cap used by every test that does not exercise eviction.
const DEFAULT_BYTE_CACHE_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixtures and fakes
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn job(dump_id: &str, sha256: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump_id.to_owned(),
        input_sha256: sha256.to_owned(),
        kind: KIND.to_owned(),
        analyzer_version: VERSION.to_owned(),
    }
}

fn sample_output() -> RunOutput {
    RunOutput {
        outcome: ReportOutcome::Completed,
        summary: "triage completed: access violation in electron".to_owned(),
        facts: json!({"exception": {"code": "0xc0000005"}}),
    }
}

/// One `ToolRunner::run` call, captured with the preconditions the agent
/// must have established (workspace present, verified dump bytes staged).
#[derive(Clone)]
struct RecordedCall {
    request: RunRequest,
    dump_bytes: Vec<u8>,
    work_dir_existed: bool,
}

struct FakeRunner {
    responses: Mutex<VecDeque<TyResult<RunOutput>>>,
    calls: Mutex<Vec<RecordedCall>>,
}

impl FakeRunner {
    fn new(responses: Vec<TyResult<RunOutput>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("runner calls lock").clone()
    }
}

#[async_trait]
impl ToolRunner for FakeRunner {
    async fn run(&self, request: RunRequest) -> TyResult<RunOutput> {
        let work_dir_existed = request.work_dir.is_dir();
        let dump_bytes = std::fs::read(&request.dump_path).unwrap_or_default();
        // Per-run artifacts the agent must wipe along with the workspace.
        std::fs::write(request.work_dir.join("triage.cdb"), b".ecxr\nq\n")
            .expect("fake runner writes into its workspace");
        self.calls
            .lock()
            .expect("runner calls lock")
            .push(RecordedCall {
                request: request.clone(),
                dump_bytes,
                work_dir_existed,
            });
        self.responses
            .lock()
            .expect("runner responses lock")
            .pop_front()
            .unwrap_or_else(|| Ok(sample_output()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkBehavior {
    Accept,
    Transient,
    Purged,
    InvalidRequest,
}

struct FakeSink {
    behavior: SinkBehavior,
    submissions: Mutex<Vec<(JobIdentity, RunOutput)>>,
}

impl FakeSink {
    fn new(behavior: SinkBehavior) -> Self {
        Self {
            behavior,
            submissions: Mutex::new(Vec::new()),
        }
    }

    fn submissions(&self) -> Vec<(JobIdentity, RunOutput)> {
        self.submissions
            .lock()
            .expect("sink submissions lock")
            .clone()
    }
}

#[async_trait]
impl VerdictSink for FakeSink {
    async fn submit(&self, identity: &JobIdentity, output: RunOutput) -> TyResult<()> {
        self.submissions
            .lock()
            .expect("sink submissions lock")
            .push((identity.clone(), output));
        match self.behavior {
            SinkBehavior::Accept => Ok(()),
            SinkBehavior::Transient => Err(AnalyzerError::Transport(
                "mock write-back transport failure".to_owned(),
            )),
            SinkBehavior::Purged => Err(AnalyzerError::Server {
                status: 404,
                code: Some("not_found".to_owned()),
            }),
            SinkBehavior::InvalidRequest => Err(AnalyzerError::Server {
                status: 400,
                code: Some("invalid_request".to_owned()),
            }),
        }
    }
}

/// Plays a fixed script of responses, one per content request.
struct ScriptResponder {
    responses: Mutex<VecDeque<ResponseTemplate>>,
}

impl ScriptResponder {
    fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
        }
    }
}

impl Respond for ScriptResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.responses
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("content script exhausted")
    }
}

fn bytes_200(body: &[u8], etag: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("ETag", etag)
        .insert_header("Content-Type", "application/octet-stream")
        .set_body_bytes(body.to_vec())
}

fn not_modified() -> ResponseTemplate {
    ResponseTemplate::new(304)
}

fn gone_404() -> ResponseTemplate {
    ResponseTemplate::new(404)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    server: MockServer,
    state: TempDir,
    store: Store,
    runner: Arc<FakeRunner>,
    sink: Arc<FakeSink>,
    agent: Agent,
}

impl Harness {
    async fn new(sink_behavior: SinkBehavior, runner_responses: Vec<TyResult<RunOutput>>) -> Self {
        Self::with_byte_cache_cap(
            sink_behavior,
            runner_responses,
            DEFAULT_BYTE_CACHE_MAX_BYTES,
        )
        .await
    }

    async fn with_byte_cache_cap(
        sink_behavior: SinkBehavior,
        runner_responses: Vec<TyResult<RunOutput>>,
        byte_cache_max_bytes: u64,
    ) -> Self {
        let server = MockServer::start().await;
        let state = tempfile::tempdir().expect("state dir");
        let store = Store::open(state.path().join("analyzer.sqlite")).expect("open store");
        let config = test_config(&server, state.path(), byte_cache_max_bytes);
        let client = LedgerClient::new(&config).expect("client construction");
        let runner = Arc::new(FakeRunner::new(runner_responses));
        let sink = Arc::new(FakeSink::new(sink_behavior));
        let runner_seam: Arc<dyn ToolRunner> = runner.clone();
        let sink_seam: Arc<dyn VerdictSink> = sink.clone();
        let agent = Agent::new(client, store.clone(), config, runner_seam, sink_seam);
        Self {
            server,
            state,
            store,
            runner,
            sink,
            agent,
        }
    }

    fn cache_path(&self, sha256: &str) -> std::path::PathBuf {
        self.state.path().join("bytes").join(sha256)
    }
}

fn test_config(server: &MockServer, state_dir: &Path, byte_cache_max_bytes: u64) -> Config {
    Config {
        base_url: server.uri().parse().expect("mock server URI is absolute"),
        token: Some(SecretToken::new(TOKEN)),
        state_dir: state_dir.to_path_buf(),
        name: "dump-analyzer".to_owned(),
        version: VERSION.to_owned(),
        poll_interval: Duration::from_millis(10_000),
        run_wall_timeout: Duration::from_secs(600),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes,
        ssh_target: Some("windows-dev".to_owned()),
        symbol_cache_dir: Some(r"C:\symcache".to_owned()),
        http_addr: None,
        runner: dump_analyzer::types::RunnerKind::CdbSsh,
        claude_bin: "claude".to_string(),
        claude_model: None,
        tls_ca_cert: None,
        scheduler_enabled: true,
        writeback_enabled: true,
    }
}

async fn mount_content(server: &MockServer, dump_id: &str, responses: Vec<ResponseTemplate>) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{dump_id}/content")))
        .respond_with(ScriptResponder::new(responses))
        .mount(server)
        .await;
}

async fn content_requests(server: &MockServer, dump_id: &str) -> Vec<Request> {
    let route = format!("/api/v1/dumps/{dump_id}/content");
    server
        .received_requests()
        .await
        .expect("mock server records requests")
        .into_iter()
        .filter(|request| request.url.path() == route)
        .collect()
}

/// Names of the files currently present in the content-addressed cache
/// directory (sorted for deterministic comparison).
fn cache_files(harness: &Harness) -> Vec<String> {
    let dir = harness.state.path().join("bytes");
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                files.push(name);
            }
        }
    }
    files.sort();
    files
}

fn claim(store: &Store, identity: &JobIdentity) {
    assert!(
        store
            .jobs()
            .upsert_discovered(identity)
            .expect("upsert discovered"),
        "job row inserted"
    );
    let (claimed, attempts) = store
        .jobs()
        .claim_next()
        .expect("claim query")
        .expect("job claimed");
    assert_eq!(&claimed, identity);
    assert_eq!(attempts, 0);
}

fn phase_of(store: &Store, identity: &JobIdentity) -> JobPhase {
    for phase in [
        JobPhase::Discovered,
        JobPhase::Claimed,
        JobPhase::Fetching,
        JobPhase::Staged,
        JobPhase::Analyzing,
        JobPhase::Reporting,
        JobPhase::Done,
        JobPhase::Dropped,
        JobPhase::Failed,
    ] {
        let found = store
            .jobs()
            .jobs_in_phase(phase)
            .expect("phase query")
            .into_iter()
            .any(|(job, _)| &job == identity);
        if found {
            return phase;
        }
    }
    panic!("job {} not found in any phase", identity.dump_id);
}

fn attempts_of(store: &Store, identity: &JobIdentity) -> u32 {
    for phase in [
        JobPhase::Discovered,
        JobPhase::Claimed,
        JobPhase::Fetching,
        JobPhase::Staged,
        JobPhase::Analyzing,
        JobPhase::Reporting,
        JobPhase::Done,
        JobPhase::Dropped,
        JobPhase::Failed,
    ] {
        for (job, attempts) in store.jobs().jobs_in_phase(phase).expect("phase query") {
            if &job == identity {
                return attempts;
            }
        }
    }
    panic!("job {} not found in any phase", identity.dump_id);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn budget_matches_the_spec_and_agent_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Agent>();
    assert_eq!(MAX_ATTEMPTS, 2, "specs/DumpAnalyzer.tla: MaxAttempts == 2");
}

#[tokio::test]
async fn happy_path_fetches_caches_and_reuses_via_etag() {
    let harness = Harness::new(SinkBehavior::Accept, Vec::new()).await;
    let payload = b"minidump payload shared by dump_01 and dump_02".to_vec();
    let pin = sha256_hex(&payload);
    let first = job("dump_01", &pin);
    let second = job("dump_02", &pin);

    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;
    mount_content(&harness.server, "dump_02", vec![not_modified()]).await;

    claim(&harness.store, &first);
    harness.agent.run_job(&first).await.expect("run first job");
    claim(&harness.store, &second);
    harness
        .agent
        .run_job(&second)
        .await
        .expect("run second job");

    // Both jobs settled `done`, without burning any retry budget.
    assert_eq!(phase_of(&harness.store, &first), JobPhase::Done);
    assert_eq!(phase_of(&harness.store, &second), JobPhase::Done);
    assert_eq!(attempts_of(&harness.store, &first), 0);
    assert_eq!(attempts_of(&harness.store, &second), 0);

    // The byte cache holds the content-addressed file and its ETag.
    assert_eq!(std::fs::read(harness.cache_path(&pin)).unwrap(), payload);
    let entry = harness
        .store
        .cache_index()
        .lookup(&pin)
        .unwrap()
        .expect("cache entry indexed");
    assert_eq!(entry.etag.as_deref(), Some(ETAG));
    assert_eq!(entry.byte_size, payload.len() as u64);

    // First fetch unconditional; the second revalidated with the ETag.
    let first_requests = content_requests(&harness.server, "dump_01").await;
    assert_eq!(first_requests.len(), 1);
    assert!(first_requests[0].headers.get("if-none-match").is_none());
    let second_requests = content_requests(&harness.server, "dump_02").await;
    assert_eq!(second_requests.len(), 1);
    assert_eq!(
        second_requests[0]
            .headers
            .get("if-none-match")
            .expect("conditional request carries If-None-Match")
            .to_str()
            .unwrap(),
        ETAG
    );

    // The runner saw the verified bytes in a fresh per-run workspace, under
    // the configured bounds and symbol path; the workspace is wiped after.
    let calls = harness.runner.calls();
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert!(
            call.work_dir_existed,
            "workspace exists when the run starts"
        );
        assert_eq!(call.dump_bytes, payload, "runner received the pinned bytes");
        assert!(
            !call.request.work_dir.exists(),
            "workspace wiped after the run"
        );
        assert_eq!(call.request.bounds.wall_timeout, Duration::from_secs(600));
        assert_eq!(call.request.bounds.max_output_bytes, 1024 * 1024);
        assert_eq!(
            call.request.symbol_path,
            format!("SRV*C:\\symcache*{}/symbols", harness.server.uri())
        );
    }

    // The verdicts went through the seam with the parsed output.
    let submissions = harness.sink.submissions();
    assert_eq!(submissions.len(), 2);
    assert_eq!(submissions[0].0, first);
    assert_eq!(submissions[0].1.outcome, ReportOutcome::Completed);
    assert_eq!(submissions[0].1.summary, sample_output().summary);
    assert_eq!(submissions[1].0, second);
}

#[tokio::test]
async fn sha256_mismatch_refetches_bounded_then_fails() {
    let harness = Harness::new(SinkBehavior::Accept, Vec::new()).await;
    let pin = sha256_hex(b"canonical bytes the server no longer serves");
    let identity = job("dump_01", &pin);
    let tampered = b"tampered payload".to_vec();
    mount_content(
        &harness.server,
        "dump_01",
        vec![bytes_200(&tampered, ETAG), bytes_200(&tampered, ETAG)],
    )
    .await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Failed);
    assert_eq!(attempts_of(&harness.store, &identity), MAX_ATTEMPTS);
    assert!(
        harness.runner.calls().is_empty(),
        "the toolchain never runs on unverified bytes"
    );
    assert!(
        harness.sink.submissions().is_empty(),
        "no report for a job with no verdict"
    );

    let requests = content_requests(&harness.server, "dump_01").await;
    assert_eq!(requests.len(), 2, "one refetch inside the attempt budget");
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("if-none-match").is_none()),
        "a discarded staging has no validator to revalidate with"
    );
    assert!(
        !harness.cache_path(&pin).exists(),
        "mismatched staging is discarded, never left in the cache"
    );
}

#[tokio::test]
async fn content_404_drops_the_job_without_retry() {
    let harness = Harness::new(SinkBehavior::Accept, Vec::new()).await;
    let identity = job("dump_01", &sha256_hex(b"payload"));
    mount_content(&harness.server, "dump_01", vec![gone_404()]).await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Dropped);
    assert_eq!(
        attempts_of(&harness.store, &identity),
        0,
        "a purge is not a transient failure"
    );
    assert_eq!(content_requests(&harness.server, "dump_01").await.len(), 1);
    assert!(harness.runner.calls().is_empty());
    assert!(harness.sink.submissions().is_empty());
}

#[tokio::test]
async fn runner_failure_retries_with_reverification_then_fails() {
    let harness = Harness::new(
        SinkBehavior::Accept,
        vec![
            Err(AnalyzerError::Runner("cdb crashed".to_owned())),
            Err(AnalyzerError::Runner("ssh dropped".to_owned())),
        ],
    )
    .await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(
        &harness.server,
        "dump_01",
        vec![bytes_200(&payload, ETAG), not_modified()],
    )
    .await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Failed);
    assert_eq!(attempts_of(&harness.store, &identity), MAX_ATTEMPTS);

    let calls = harness.runner.calls();
    assert_eq!(calls.len(), MAX_ATTEMPTS as usize);
    for call in &calls {
        assert!(call.work_dir_existed);
        assert!(
            !call.request.work_dir.exists(),
            "every attempt's workspace is wiped"
        );
        assert_eq!(call.dump_bytes, payload);
    }

    // The retry re-entered at fetch and revalidated the pinned bytes.
    let requests = content_requests(&harness.server, "dump_01").await;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].headers.get("if-none-match").is_none());
    assert_eq!(
        requests[1]
            .headers
            .get("if-none-match")
            .expect("retry revalidates with the ETag")
            .to_str()
            .unwrap(),
        ETAG
    );
    assert!(
        harness.sink.submissions().is_empty(),
        "no report, no verdict"
    );
}

#[tokio::test]
async fn runner_failure_then_success_retries_once_and_completes() {
    let harness = Harness::new(
        SinkBehavior::Accept,
        vec![
            Err(AnalyzerError::Runner("cdb crashed".to_owned())),
            Ok(sample_output()),
        ],
    )
    .await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(
        &harness.server,
        "dump_01",
        vec![bytes_200(&payload, ETAG), not_modified()],
    )
    .await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);
    assert_eq!(attempts_of(&harness.store, &identity), 1);
    assert_eq!(harness.runner.calls().len(), 2);
    let submissions = harness.sink.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].0, identity);
    assert_eq!(submissions[0].1.outcome, ReportOutcome::Completed);
}

#[tokio::test]
async fn failed_verdict_is_reported_not_retried() {
    let verdict = RunOutput {
        outcome: ReportOutcome::Failed,
        summary: "triage failed: could not open the dump".to_owned(),
        facts: json!({"failure": {"reason": "dump_corrupt"}}),
    };
    let harness = Harness::new(SinkBehavior::Accept, vec![Ok(verdict)]).await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);
    assert_eq!(attempts_of(&harness.store, &identity), 0);
    assert_eq!(harness.runner.calls().len(), 1);
    let submissions = harness.sink.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].1.outcome, ReportOutcome::Failed);
}

#[tokio::test]
async fn write_back_404_drops_the_job() {
    let harness = Harness::new(SinkBehavior::Purged, Vec::new()).await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Dropped);
    assert_eq!(attempts_of(&harness.store, &identity), 0);
    assert_eq!(
        harness.runner.calls().len(),
        1,
        "a purge at write-back does not re-run the analysis"
    );
    assert_eq!(harness.sink.submissions().len(), 1);
}

#[tokio::test]
async fn transient_write_back_failure_keeps_the_job_reporting() {
    let harness = Harness::new(SinkBehavior::Transient, Vec::new()).await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;

    claim(&harness.store, &identity);
    let error = harness
        .agent
        .run_job(&identity)
        .await
        .expect_err("a transient write-back failure yields an error");
    assert!(error.is_transient());
    assert_eq!(
        phase_of(&harness.store, &identity),
        JobPhase::Reporting,
        "reporting is the durable hand-off state reconciliation owns"
    );
    assert_eq!(attempts_of(&harness.store, &identity), 0);
    assert_eq!(harness.sink.submissions().len(), 1);
}

#[tokio::test]
async fn terminal_write_back_failure_settles_failed() {
    let harness = Harness::new(SinkBehavior::InvalidRequest, Vec::new()).await;
    let payload = b"payload".to_vec();
    let pin = sha256_hex(&payload);
    let identity = job("dump_01", &pin);
    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;

    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");

    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Failed);
    assert_eq!(attempts_of(&harness.store, &identity), 0);
}

#[tokio::test]
async fn recovery_resets_volatile_phases_and_leaves_reporting() {
    let harness = Harness::new(SinkBehavior::Accept, Vec::new()).await;
    let sha = sha256_hex(b"payload");
    let fetching = job("dump_fetching", &sha);
    let staged = job("dump_staged", &sha);
    let analyzing = job("dump_analyzing", &sha);
    let reporting = job("dump_reporting", &sha);
    let claimed = job("dump_claimed", &sha);
    let done = job("dump_done", &sha);
    let dropped = job("dump_dropped", &sha);
    let failed = job("dump_failed", &sha);
    let discovered = job("dump_discovered", &sha);
    let jobs = harness.store.jobs();
    for identity in [
        &fetching,
        &staged,
        &analyzing,
        &reporting,
        &claimed,
        &done,
        &dropped,
        &failed,
        &discovered,
    ] {
        assert!(jobs.upsert_discovered(identity).unwrap());
    }
    jobs.set_phase(&fetching, JobPhase::Fetching).unwrap();
    jobs.set_phase(&staged, JobPhase::Staged).unwrap();
    jobs.set_phase(&analyzing, JobPhase::Analyzing).unwrap();
    jobs.set_phase(&reporting, JobPhase::Reporting).unwrap();
    jobs.set_phase(&claimed, JobPhase::Claimed).unwrap();
    jobs.set_phase(&done, JobPhase::Done).unwrap();
    jobs.set_phase(&dropped, JobPhase::Dropped).unwrap();
    jobs.set_phase(&failed, JobPhase::Failed).unwrap();
    jobs.record_attempt(&fetching).unwrap();
    jobs.record_attempt(&fetching).unwrap();
    jobs.record_attempt(&reporting).unwrap();

    let report = Agent::recover(&harness.store).expect("recover");
    let mut reset: Vec<String> = report
        .reset_to_claimed
        .iter()
        .map(|job| job.dump_id.clone())
        .collect();
    reset.sort();
    assert_eq!(
        reset,
        vec!["dump_analyzing", "dump_fetching", "dump_staged"],
        "exactly the volatile phases reset"
    );

    assert_eq!(phase_of(&harness.store, &fetching), JobPhase::Claimed);
    assert_eq!(phase_of(&harness.store, &staged), JobPhase::Claimed);
    assert_eq!(phase_of(&harness.store, &analyzing), JobPhase::Claimed);
    assert_eq!(
        phase_of(&harness.store, &reporting),
        JobPhase::Reporting,
        "verdict reconciliation owns reporting jobs"
    );
    assert_eq!(phase_of(&harness.store, &claimed), JobPhase::Claimed);
    assert_eq!(phase_of(&harness.store, &done), JobPhase::Done);
    assert_eq!(phase_of(&harness.store, &dropped), JobPhase::Dropped);
    assert_eq!(phase_of(&harness.store, &failed), JobPhase::Failed);
    assert_eq!(phase_of(&harness.store, &discovered), JobPhase::Discovered);

    assert_eq!(
        attempts_of(&harness.store, &fetching),
        2,
        "the retry budget is durable across the crash (spec CrashReset)"
    );
    assert_eq!(attempts_of(&harness.store, &reporting), 1);

    // Re-running recovery changes nothing and still leaves `reporting`.
    let second = Agent::recover(&harness.store).expect("second recover");
    assert!(second.reset_to_claimed.is_empty());
    assert_eq!(phase_of(&harness.store, &reporting), JobPhase::Reporting);
}

#[tokio::test]
async fn run_job_requires_a_claimed_job() {
    let harness = Harness::new(SinkBehavior::Accept, Vec::new()).await;
    let identity = job("dump_01", &sha256_hex(b"payload"));
    assert!(harness.store.jobs().upsert_discovered(&identity).unwrap());

    let error = harness
        .agent
        .run_job(&identity)
        .await
        .expect_err("a discovered job must be rejected");
    assert!(matches!(error, AnalyzerError::State(_)));
    assert_eq!(
        phase_of(&harness.store, &identity),
        JobPhase::Discovered,
        "no stage side effects before the precondition holds"
    );
    assert!(harness.runner.calls().is_empty());
}

// ---------------------------------------------------------------------------
// Byte-cache cap enforcement (task R4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_byte_cache_cap_evicts_oldest_after_third_write() {
    let harness = Harness::with_byte_cache_cap(SinkBehavior::Accept, Vec::new(), 200).await;
    let payloads = [vec![b'1'; 80], vec![b'2'; 80], vec![b'3'; 80]];
    let shas: Vec<String> = payloads.iter().map(|payload| sha256_hex(payload)).collect();

    for (index, dump) in ["dump_01", "dump_02", "dump_03"].into_iter().enumerate() {
        mount_content(
            &harness.server,
            dump,
            vec![bytes_200(&payloads[index], ETAG)],
        )
        .await;
        let identity = job(dump, &shas[index]);
        claim(&harness.store, &identity);
        harness.agent.run_job(&identity).await.expect("run_job");
        assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);
        if index < 2 {
            assert_eq!(
                harness.store.cache_index().total_bytes().unwrap(),
                80 * (index as u64 + 1),
                "the first two entries fit under the cap"
            );
        }
    }

    // The third 80-byte write exceeded the 200-byte cap by 40; the oldest
    // entry was evicted (its 80 bytes) and the two newest survive.
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 160);
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&shas[0])
            .unwrap()
            .is_none(),
        "oldest entry evicted from the index"
    );
    assert!(
        !harness.cache_path(&shas[0]).exists(),
        "evicted file deleted"
    );
    for sha in &shas[1..] {
        assert!(
            harness.store.cache_index().lookup(sha).unwrap().is_some(),
            "survivor indexed"
        );
        assert!(harness.cache_path(sha).is_file(), "survivor file present");
    }

    // Index/file consistency: every file on disk has an index row, and no
    // known entry's row points at a missing file.
    let mut expected_files = shas[1..].to_vec();
    expected_files.sort();
    assert_eq!(cache_files(&harness), expected_files);
    for file in cache_files(&harness) {
        assert!(
            harness.store.cache_index().lookup(&file).unwrap().is_some(),
            "no cache file without an index row"
        );
    }
}

#[tokio::test]
async fn agent_byte_cache_fresh_entry_stays_when_over_cap() {
    let harness = Harness::with_byte_cache_cap(SinkBehavior::Accept, Vec::new(), 100).await;
    let small = vec![b's'; 64];
    let big = vec![b'b'; 128];
    let sha_small = sha256_hex(&small);
    let sha_big = sha256_hex(&big);

    mount_content(&harness.server, "dump_01", vec![bytes_200(&small, ETAG)]).await;
    let first = job("dump_01", &sha_small);
    claim(&harness.store, &first);
    harness.agent.run_job(&first).await.expect("run_job");
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 64);

    mount_content(&harness.server, "dump_02", vec![bytes_200(&big, ETAG)]).await;
    let second = job("dump_02", &sha_big);
    claim(&harness.store, &second);
    harness.agent.run_job(&second).await.expect("run_job");
    assert_eq!(phase_of(&harness.store, &second), JobPhase::Done);

    // The fresh 128-byte entry exceeds the 100-byte cap: the older entry is
    // evicted, the fresh entry stays (the cache stays over cap, warned not
    // looped), and the staged input is still on disk for the verify step.
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&sha_big)
            .unwrap()
            .is_some(),
        "the just-written entry survives its own eviction pass"
    );
    assert!(
        harness.cache_path(&sha_big).is_file(),
        "the fresh file is the in-flight fetch's staged input"
    );
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&sha_small)
            .unwrap()
            .is_none()
    );
    assert!(!harness.cache_path(&sha_small).exists());
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 128);
}

#[tokio::test]
async fn agent_byte_cache_single_entry_over_cap_stays_alone() {
    let harness = Harness::with_byte_cache_cap(SinkBehavior::Accept, Vec::new(), 64).await;
    let payload = vec![b'x'; 128];
    let sha = sha256_hex(&payload);

    mount_content(&harness.server, "dump_01", vec![bytes_200(&payload, ETAG)]).await;
    let identity = job("dump_01", &sha);
    claim(&harness.store, &identity);
    harness.agent.run_job(&identity).await.expect("run_job");
    assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);

    // Nothing else to evict: the oversized entry stays put.
    assert!(harness.store.cache_index().lookup(&sha).unwrap().is_some());
    assert!(harness.cache_path(&sha).is_file());
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 128);
}

#[tokio::test]
async fn agent_byte_cache_evicted_entry_refetches_with_fresh_etag() {
    const ETAG_A1: &str = "\"etag-first-generation\"";
    const ETAG_A2: &str = "\"etag-second-generation\"";

    let harness = Harness::with_byte_cache_cap(SinkBehavior::Accept, Vec::new(), 150).await;
    let a = vec![b'A'; 60];
    let b = vec![b'B'; 60];
    let c = vec![b'C'; 60];
    let sha_a = sha256_hex(&a);
    let sha_b = sha256_hex(&b);
    let sha_c = sha256_hex(&c);

    mount_content(&harness.server, "dump_01", vec![bytes_200(&a, ETAG_A1)]).await;
    mount_content(&harness.server, "dump_02", vec![bytes_200(&b, ETAG)]).await;
    mount_content(&harness.server, "dump_03", vec![bytes_200(&c, ETAG)]).await;
    for (dump, sha) in [
        ("dump_01", sha_a.as_str()),
        ("dump_02", sha_b.as_str()),
        ("dump_03", sha_c.as_str()),
    ] {
        let identity = job(dump, sha);
        claim(&harness.store, &identity);
        harness.agent.run_job(&identity).await.expect("run_job");
        assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);
    }

    // Writing the third 60-byte entry evicted the first.
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&sha_a)
            .unwrap()
            .is_none()
    );
    assert!(!harness.cache_path(&sha_a).exists());
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 120);

    // Refetching the evicted content is a cache miss → unconditional 200,
    // and the fresh validator replaces the evicted entry.
    mount_content(&harness.server, "dump_04", vec![bytes_200(&a, ETAG_A2)]).await;
    let refetch = job("dump_04", &sha_a);
    claim(&harness.store, &refetch);
    harness.agent.run_job(&refetch).await.expect("run_job");
    assert_eq!(phase_of(&harness.store, &refetch), JobPhase::Done);
    let entry = harness
        .store
        .cache_index()
        .lookup(&sha_a)
        .unwrap()
        .expect("refetched entry indexed");
    assert_eq!(entry.etag.as_deref(), Some(ETAG_A2));
    assert_eq!(std::fs::read(harness.cache_path(&sha_a)).unwrap(), a);
    // The refetch write pushed the cache over cap again: the next oldest
    // entry went out, not the fresh one.
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&sha_b)
            .unwrap()
            .is_none()
    );
    assert!(!harness.cache_path(&sha_b).exists());
    assert!(
        harness
            .store
            .cache_index()
            .lookup(&sha_c)
            .unwrap()
            .is_some()
    );
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 120);

    // The re-indexed entry now revalidates with the fresh ETag.
    mount_content(&harness.server, "dump_05", vec![not_modified()]).await;
    let revalidate = job("dump_05", &sha_a);
    claim(&harness.store, &revalidate);
    harness.agent.run_job(&revalidate).await.expect("run_job");
    assert_eq!(phase_of(&harness.store, &revalidate), JobPhase::Done);
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 120);

    let refetch_requests = content_requests(&harness.server, "dump_04").await;
    assert_eq!(refetch_requests.len(), 1);
    assert!(
        refetch_requests[0].headers.get("if-none-match").is_none(),
        "an evicted entry is a cache miss: no validator to present"
    );
    let revalidate_requests = content_requests(&harness.server, "dump_05").await;
    assert_eq!(revalidate_requests.len(), 1);
    assert_eq!(
        revalidate_requests[0]
            .headers
            .get("if-none-match")
            .expect("revalidation carries the fresh ETag")
            .to_str()
            .unwrap(),
        ETAG_A2
    );
}

#[tokio::test]
async fn agent_byte_cache_stays_consistent_across_evictions() {
    let harness = Harness::with_byte_cache_cap(SinkBehavior::Accept, Vec::new(), 150).await;
    let mut shas: Vec<String> = Vec::new();

    for (index, letter) in [b'a', b'b', b'c', b'd', b'e'].into_iter().enumerate() {
        let payload = vec![letter; 60];
        let sha = sha256_hex(&payload);
        let dump = format!("dump_{index:02}");
        mount_content(&harness.server, &dump, vec![bytes_200(&payload, ETAG)]).await;
        let identity = job(&dump, &sha);
        claim(&harness.store, &identity);
        harness.agent.run_job(&identity).await.expect("run_job");
        assert_eq!(phase_of(&harness.store, &identity), JobPhase::Done);
        shas.push(sha);

        // Invariants after every write: under cap, the fresh entry present,
        // and index rows and files agree for every entry written so far.
        let total = harness.store.cache_index().total_bytes().unwrap();
        assert!(total <= 150, "cap holds after write {index}: {total}");
        assert!(
            harness
                .store
                .cache_index()
                .lookup(shas.last().expect("fresh sha"))
                .unwrap()
                .is_some(),
            "the just-written entry survives"
        );
        for sha in &shas {
            let indexed = harness.store.cache_index().lookup(sha).unwrap().is_some();
            assert_eq!(
                indexed,
                harness.cache_path(sha).is_file(),
                "index row and file agree for {sha}"
            );
        }
        for file in cache_files(&harness) {
            assert!(
                harness.store.cache_index().lookup(&file).unwrap().is_some(),
                "no cache file without an index row"
            );
        }
    }

    // Two 60-byte entries fit under the 150-byte cap; the rest cycled out.
    assert_eq!(harness.store.cache_index().total_bytes().unwrap(), 120);
}
