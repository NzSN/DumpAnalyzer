//! Daemon end-to-end tests (task D2).
//!
//! Two layers:
//!
//! * In-process: [`scheduler::run`] drives a wiremock DumpLedger with a fake
//!   [`ToolRunner`] — two dumps through fetch/analyze/write-back, and a purge
//!   event that drops a queued job while another is mid-run. These exercise
//!   the real `Agent`, the real `VerdictWriter` adapter, and the real
//!   `Store`.
//! * Process-level: the built `dump-analyzer` binary is spawned against an
//!   unreachable (closed-port) HTTPS base URL, which is enough to prove the
//!   single-instance lock (second start fails fast naming the lock path) and
//!   SIGTERM handling (graceful exit 0, lock removed) without needing a live
//!   server.

use std::collections::VecDeque;
use std::path::Path;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::sync::Notify;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::scheduler::{self, STATE_DB_FILE, STATE_LOCK_FILE};
use dump_analyzer::state::Store;
use dump_analyzer::sync::CancellationToken;
use dump_analyzer::types::{
    JobIdentity, JobPhase, ReportOutcome, RunOutput, RunRequest, ToolRunner,
};

type TyResult<T> = dump_analyzer::types::Result<T>;

const TOKEN: &str = "analyzer-token-0123456789abcdef";
const NAME: &str = "dump-analyzer";
const VERSION: &str = "0.9.9-test";

// ---------------------------------------------------------------------------
// Fixtures and fakes
// ---------------------------------------------------------------------------

fn sha256_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn test_config(server: &MockServer, state_dir: &Path) -> Config {
    Config {
        base_url: server.uri().parse().expect("mock server URI is absolute"),
        token: Some(SecretToken::new(TOKEN)),
        state_dir: state_dir.to_path_buf(),
        name: NAME.to_owned(),
        version: VERSION.to_owned(),
        poll_interval: Duration::from_millis(25),
        run_wall_timeout: Duration::from_secs(600),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes: 10 * 1024 * 1024 * 1024,
        ssh_target: Some("windows-dev".to_owned()),
        symbol_cache_dir: Some(r"C:\symcache".to_owned()),
        http_addr: None,
        runner: dump_analyzer::types::RunnerKind::CdbSsh,
        claude_bin: "claude".to_string(),
        claude_model: None,
        dsh_base_url: None,
        dsh_token: None,
        dsh_model: None,
        dsh_api_key: None,
        dsh_preset: "analyzer-triage".to_owned(),
        tls_ca_cert: None,
        webhook_enabled: false,
        webhook_admin_token: None,
        webhook_url: None,
        webhook_actions: Vec::new(),
        scheduler_enabled: true,
        writeback_enabled: true,
    }
}

/// Catalog row fixture (strict wire shape; mirrors tests/sync.rs).
fn catalog_entry(dump_id: &str, sha: &str) -> Value {
    json!({
        "dumpId": dump_id,
        "caseId": "case_01JAB0XYZ",
        "customerId": "customer_01JAA0XYZ",
        "phase": "available",
        "validation": "valid",
        "originalName": "renderer-crash.dmp",
        "byteSize": "1048576",
        "sha256": sha,
        "receivedAt": "2026-10-13T02:00:00.000Z",
        "availableAt": "2026-10-13T02:05:30.250Z",
        "purgeAt": null,
        "symbolCoverage": { "present": 12, "missing": 3, "unidentified": 1 }
    })
}

/// Event row fixture (strict wire shape; mirrors tests/sync.rs).
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

/// Server-side analysis report fixture (decoded by the client after POST).
fn analysis_report(dump_id: &str, sha: &str) -> Value {
    json!({
        "analysisId": format!("analysis_{dump_id}"),
        "dumpId": dump_id,
        "analyzer": { "name": NAME, "version": VERSION },
        "kind": "triage",
        "inputSha256": sha,
        "createdAt": "2026-10-13T03:00:00.000Z",
        "outcome": "completed",
        "summary": "triage completed"
    })
}

fn completed_output(label: &str) -> RunOutput {
    RunOutput {
        capture: None,
        outcome: ReportOutcome::Completed,
        summary: format!("triage completed for {label}"),
        facts: json!({ "exception": { "code": "0xc0000005" } }),
    }
}

/// One `ToolRunner::run` call, with the bytes it found at the staged path
/// (the agent must only hand it sha256-verified bytes).
#[derive(Clone)]
struct RecordedCall {
    request: RunRequest,
    dump_bytes: Vec<u8>,
    work_dir_existed: bool,
}

/// Gate used by the mid-run purge test: the first run blocks until the test
/// releases it.
#[derive(Default)]
struct RunnerGate {
    release: Notify,
}

struct FakeRunner {
    responses: Mutex<VecDeque<TyResult<RunOutput>>>,
    calls: Mutex<Vec<RecordedCall>>,
    gate_first: Option<Arc<RunnerGate>>,
}

impl FakeRunner {
    fn new(responses: Vec<TyResult<RunOutput>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
            gate_first: None,
        }
    }

    fn gated_first(response: TyResult<RunOutput>) -> (Self, Arc<RunnerGate>) {
        let gate = Arc::new(RunnerGate::default());
        let runner = Self {
            responses: Mutex::new(vec![response].into()),
            calls: Mutex::new(Vec::new()),
            gate_first: Some(Arc::clone(&gate)),
        };
        (runner, gate)
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
        let index = {
            let mut calls = self.calls.lock().expect("runner calls lock");
            let index = calls.len();
            calls.push(RecordedCall {
                request: request.clone(),
                dump_bytes,
                work_dir_existed,
            });
            index
        };
        if index == 0 {
            if let Some(gate) = &self.gate_first {
                gate.release.notified().await;
            }
        }
        self.responses
            .lock()
            .expect("runner responses lock")
            .pop_front()
            .unwrap_or_else(|| Ok(completed_output("default")))
    }
}

// ---------------------------------------------------------------------------
// Wiremock surface
// ---------------------------------------------------------------------------

/// Mounts the two catalog pages a scan of `dumps` performs: the page itself
/// and the empty page that terminates the keyset walk.
async fn mount_catalog(server: &MockServer, dumps: Vec<Value>, next_cursor: &str) {
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("phase", "available"))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dumps": dumps,
            "nextCursor": next_cursor,
        })))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/dumps"))
        .and(query_param("cursor", next_cursor))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "dumps": [] })))
        .expect(1)
        .mount(server)
        .await;
}

/// Mounts the content route. `expect` pins the exact hit count (checked by
/// wiremock's automatic verification on drop); `None` leaves it open, for
/// routes the test expects never to be hit at all.
async fn mount_content(
    server: &MockServer,
    dump_id: &str,
    body: &[u8],
    etag: &str,
    expect: Option<u64>,
) {
    let mock = Mock::given(method("GET"))
        .and(path(format!("/api/v1/dumps/{dump_id}/content")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("ETag", etag)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(body.to_vec()),
        );
    let mock = match expect {
        Some(times) => mock.expect(times),
        None => mock,
    };
    mock.mount(server).await;
}

/// Mounts the write-back route; see [`mount_content`] for `expect`.
async fn mount_analysis_post(server: &MockServer, dump_id: &str, sha: &str, expect: Option<u64>) {
    let mock = Mock::given(method("POST"))
        .and(path(format!("/api/v1/dumps/{dump_id}/analyses")))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report(dump_id, sha)));
    let mock = match expect {
        Some(times) => mock.expect(times),
        None => mock,
    };
    mock.mount(server).await;
}

/// Serves a scripted first events page; afterwards every poll echoes its
/// request cursor with an empty page (the follower's sleep signal), so a
/// delivered event is never redelivered.
struct EventsResponder {
    first_page: Value,
}

impl Respond for EventsResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let since = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "since")
            .map(|(_, value)| value.into_owned());
        match since {
            None => ResponseTemplate::new(200).set_body_json(self.first_page.clone()),
            Some(cursor) => ResponseTemplate::new(200).set_body_json(json!({
                "events": [],
                "nextCursor": cursor,
            })),
        }
    }
}

async fn mount_events(server: &MockServer, first_page: Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(EventsResponder { first_page })
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Polls `check` (bounded) until it returns true.
async fn await_condition(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn open_store(state_dir: &Path) -> Store {
    Store::open(state_dir.join(STATE_DB_FILE)).expect("open store")
}

fn phases(store: &Store, phase: JobPhase) -> Vec<JobIdentity> {
    store
        .jobs()
        .jobs_in_phase(phase)
        .expect("phase query")
        .into_iter()
        .map(|(identity, _attempts)| identity)
        .collect()
}

fn triage_job(dump_id: &str, sha: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump_id.to_owned(),
        input_sha256: sha.to_owned(),
        kind: "triage".to_owned(),
        analyzer_version: VERSION.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// In-process end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn daemon_analyzes_two_dumps_end_to_end() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");
    // An orphaned workspace from a killed previous run must be swept at
    // boot; unrelated state-directory entries must survive.
    let orphan = state_dir.join("run-orphaned01");
    std::fs::create_dir_all(orphan.join("deep")).expect("orphan workspace");
    std::fs::write(orphan.join("deep/triage.cdb"), b".ecxr\n").expect("orphan file");
    std::fs::create_dir_all(state_dir.join("keep")).expect("unrelated dir");

    let payload_a = b"dump-A-bytes-0123456789".as_slice();
    let payload_b = b"dump-B-bytes-0123456789".as_slice();
    let sha_a = sha256_of(payload_a);
    let sha_b = sha256_of(payload_b);

    mount_catalog(
        &server,
        vec![
            catalog_entry("dump_A", &sha_a),
            catalog_entry("dump_B", &sha_b),
        ],
        "0000000000000010",
    )
    .await;
    mount_content(&server, "dump_A", payload_a, "\"etag-a\"", Some(1)).await;
    mount_content(&server, "dump_B", payload_b, "\"etag-b\"", Some(1)).await;
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000000" }),
    )
    .await;
    mount_analysis_post(&server, "dump_A", &sha_a, Some(1)).await;
    mount_analysis_post(&server, "dump_B", &sha_b, Some(1)).await;

    let config = test_config(&server, &state_dir);
    let runner = Arc::new(FakeRunner::new(vec![
        Ok(completed_output("dump_A")),
        Ok(completed_output("dump_B")),
    ]));
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let runner = runner.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });

    let store = open_store(&state_dir);
    await_condition("both jobs to reach done", || {
        phases(&store, JobPhase::Done).len() == 2
    })
    .await;

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon must stop after cancellation")
        .expect("daemon task")
        .expect("clean shutdown");

    // Exactly the expected server surface was consumed (content and POST
    // mocks carry `.expect(1)`).
    // `verify` panics when a mock with an expectation was not satisfied
    // exactly (running the daemon against an extra copy of the server
    // surface fails here).
    server.verify().await;

    // Both jobs settled done with the right pins; nothing else remains.
    let done = phases(&store, JobPhase::Done);
    assert_eq!(done.len(), 2, "two jobs done: {done:?}");
    assert!(done.contains(&triage_job("dump_A", &sha_a)));
    assert!(done.contains(&triage_job("dump_B", &sha_b)));

    // The runner saw each verified dump exactly once, in claim order.
    let calls = runner.calls();
    assert_eq!(calls.len(), 2, "one tool run per dump");
    assert!(calls[0].request.dump_path.ends_with(&sha_a));
    assert_eq!(calls[0].dump_bytes, payload_a);
    assert!(calls[1].request.dump_path.ends_with(&sha_b));
    assert_eq!(calls[1].dump_bytes, payload_b);
    assert!(calls[0].request.symbol_path.contains("/symbols"));
    assert!(calls[0].work_dir_existed && calls[1].work_dir_existed);
    // The agent wipes each per-run workspace once the run finishes.
    assert!(!calls[0].request.work_dir.exists());
    assert!(!calls[1].request.work_dir.exists());

    // Byte cache holds both verified payloads.
    assert!(state_dir.join("bytes").join(&sha_a).is_file());
    assert!(state_dir.join("bytes").join(&sha_b).is_file());

    // Both verdicts were POSTed with the pinned identity and marked posted in
    // local-verdict bookkeeping.
    let requests = server.received_requests().await.expect("recorded requests");
    let posts: Vec<&Request> = requests
        .iter()
        .filter(|request| {
            request.url.path().starts_with("/api/v1/") && request.url.path().ends_with("/analyses")
        })
        .collect();
    assert_eq!(posts.len(), 2, "one analysis report per dump");
    for request in posts {
        // The dump id rides in the route; the body carries the writable
        // subset (analyzer, kind, pinned inputSha256, outcome, summary).
        let body: Value = request.body_json().expect("POST body is JSON");
        let path = request.url.path();
        let (expected_dump, expected_sha) = if path.contains("dump_A") {
            ("dump_A", &sha_a)
        } else {
            ("dump_B", &sha_b)
        };
        assert!(path.contains(expected_dump));
        assert_eq!(body["inputSha256"], json!(expected_sha));
        assert_eq!(body["analyzer"]["name"], json!(NAME));
        assert_eq!(body["analyzer"]["version"], json!(VERSION));
        assert_eq!(body["kind"], json!("triage"));
        assert_eq!(body["outcome"], json!("completed"));
    }
    for (dump_id, sha) in [("dump_A", &sha_a), ("dump_B", &sha_b)] {
        let row = store
            .local_reports()
            .get(&triage_job(dump_id, sha))
            .expect("local report query")
            .expect("local report exists");
        assert!(row.posted, "server accepted {dump_id}'s verdict");
    }
    assert!(
        store.local_reports().pending().expect("pending").is_empty(),
        "no verdict left pending"
    );

    // Boot hygiene: the orphan workspace was swept, unrelated entries and
    // the lock file handling are correct.
    assert!(!orphan.exists(), "orphaned run workspace was swept");
    assert!(state_dir.join("keep").is_dir(), "unrelated dirs survive");
    assert!(
        !state_dir.join(STATE_LOCK_FILE).exists(),
        "lock file removed on exit"
    );
}

#[tokio::test]
async fn purge_event_mid_run_drops_the_queued_job() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");

    let payload_a = b"dump-A-mid-run-purge-test".as_slice();
    let payload_b = b"dump-B-mid-run-purge-test".as_slice();
    let sha_a = sha256_of(payload_a);
    let sha_b = sha256_of(payload_b);

    mount_catalog(
        &server,
        vec![
            catalog_entry("dump_A", &sha_a),
            catalog_entry("dump_B", &sha_b),
        ],
        "0000000000000010",
    )
    .await;
    mount_content(&server, "dump_A", payload_a, "\"etag-a\"", Some(1)).await;
    // dump_B must never be fetched or POSTed (asserted after the run); the
    // route stays mounted without an expectation so a violation surfaces as
    // an explicit assertion rather than a wiremock drop panic.
    mount_content(&server, "dump_B", payload_b, "\"etag-b\"", None).await;
    // The first poll delivers the purge of the *queued* dump_B while dump_A
    // is still being analyzed.
    mount_events(
        &server,
        json!({
            "events": [event("0000000000000001", "FinishPurge", Some("dump_B"))],
            "nextCursor": "0000000000000002",
        }),
    )
    .await;
    mount_analysis_post(&server, "dump_A", &sha_a, Some(1)).await;
    mount_analysis_post(&server, "dump_B", &sha_b, None).await;

    let config = test_config(&server, &state_dir);
    let (runner, gate) = FakeRunner::gated_first(Ok(completed_output("dump_A")));
    let runner = Arc::new(runner);
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let runner = runner.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });

    let store = open_store(&state_dir);
    await_condition("dump_A's tool run to start", || !runner.calls().is_empty()).await;

    // While dump_A is blocked inside the runner (phase `analyzing`), the
    // purge event for dump_B lands and drops it before it is ever claimed.
    await_condition("dump_B to be dropped mid-run", || {
        phases(&store, JobPhase::Dropped).contains(&triage_job("dump_B", &sha_b))
    })
    .await;
    let mid_run = phases(&store, JobPhase::Analyzing);
    assert_eq!(
        mid_run,
        vec![triage_job("dump_A", &sha_a)],
        "dump_A is mid-run while dump_B is purged"
    );

    gate.release.notify_one();
    await_condition("dump_A to reach done", || {
        phases(&store, JobPhase::Done).contains(&triage_job("dump_A", &sha_a))
    })
    .await;
    // Give the scheduler a chance to claim anything it wrongly still sees.
    tokio::time::sleep(Duration::from_millis(150)).await;

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon must stop after cancellation")
        .expect("daemon task")
        .expect("clean shutdown");

    // dump_B was never analyzed and never POSTed; dump_A completed exactly
    // once.
    assert_eq!(runner.calls().len(), 1, "purged dump_B was never analyzed");
    assert!(phases(&store, JobPhase::Done).contains(&triage_job("dump_A", &sha_a)));
    assert!(phases(&store, JobPhase::Dropped).contains(&triage_job("dump_B", &sha_b)));
    let posts: Vec<String> = server
        .received_requests()
        .await
        .expect("recorded requests")
        .into_iter()
        .filter(|request| {
            request.url.path().starts_with("/api/v1/") && request.url.path().ends_with("/analyses")
        })
        .map(|request| request.url.path().to_owned())
        .collect();
    assert_eq!(
        posts.len(),
        1,
        "only dump_A's verdict was POSTed: {posts:?}"
    );
    assert!(posts[0].contains("dump_A"));
}

// ---------------------------------------------------------------------------
// Process-level: the real binary
// ---------------------------------------------------------------------------

/// A spawned `dump-analyzer` child, killed on drop if it outlives the test.
struct DaemonChild {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl DaemonChild {
    /// Spawns the built binary against an unreachable HTTPS base URL (a
    /// closed loopback port): the daemon locks the state dir, then retries
    /// the initial scan behind its backoff — enough to exercise the lock and
    /// signal paths without a live server.
    fn spawn(state_dir: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dump-analyzer"));
        command
            .env_clear()
            .env("DUMP_ANALYZER_BASE_URL", "https://127.0.0.1:1")
            .env("DUMP_ANALYZER_TOKEN", TOKEN)
            .env("DUMP_ANALYZER_STATE_DIR", state_dir)
            .env("DUMP_ANALYZER_SSH_TARGET", "windows-dev")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn dump-analyzer");
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id().expect("child pid")
    }

    /// Waits (bounded) for exit; `None` on timeout.
    async fn exited(&mut self, timeout: Duration) -> Option<ExitStatus> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(result) => Some(result.expect("wait on the dump-analyzer child")),
            Err(_) => None,
        }
    }

    /// Reads both captured streams to EOF (call after exit).
    async fn output(&mut self) -> (String, String) {
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout).await;
        }
        if let Some(mut pipe) = self.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr).await;
        }
        (stdout, stderr)
    }

    /// Waits until the state lock file exists (the daemon's readiness
    /// point: config, tracing, the signal handlers, and the lock are all
    /// established), failing loudly if the child exits first.
    async fn await_lock(&mut self, lock_path: &Path) {
        for _ in 0..500 {
            if lock_path.is_file() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                let (stdout, stderr) = self.output().await;
                panic!(
                    "daemon exited early with {status:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("daemon never created the lock file {}", lock_path.display());
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Sends SIGTERM to `pid` through a POSIX shell (no extra crate).
fn send_sigterm(pid: u32) {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {pid}"))
        .status()
        .expect("run kill -TERM");
    assert!(status.success(), "kill -TERM {pid} failed");
}

#[tokio::test]
async fn second_daemon_fails_fast_while_the_lock_is_held() {
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");
    let lock_path = state_dir.join(STATE_LOCK_FILE);

    let mut first = DaemonChild::spawn(&state_dir);
    first.await_lock(&lock_path).await;

    let mut second = DaemonChild::spawn(&state_dir);
    let status = second
        .exited(Duration::from_secs(10))
        .await
        .expect("the second instance must fail fast, not hang");
    assert_eq!(
        status.code(),
        Some(1),
        "a held lock is a runtime failure, got {status:?}"
    );
    let (stdout, stderr) = second.output().await;
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("analyzer.lock"),
        "the failure names the lock file:\n{combined}"
    );
    assert!(
        combined.contains("another dump-analyzer instance"),
        "the failure explains the conflict:\n{combined}"
    );

    // The lock holder shuts down cleanly on SIGTERM and releases the file.
    send_sigterm(first.pid());
    let status = first
        .exited(Duration::from_secs(10))
        .await
        .expect("the lock holder must exit after SIGTERM");
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM is a clean shutdown, got {status:?}"
    );
    assert!(!lock_path.exists(), "the lock file is removed on exit");
    let (stdout, _) = first.output().await;
    assert!(
        stdout.contains("SIGTERM received"),
        "the journal records the signal:\n{stdout}"
    );
}

#[tokio::test]
async fn sigterm_shuts_the_daemon_down_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");
    let lock_path = state_dir.join(STATE_LOCK_FILE);

    let mut daemon = DaemonChild::spawn(&state_dir);
    daemon.await_lock(&lock_path).await;

    send_sigterm(daemon.pid());
    let status = daemon
        .exited(Duration::from_secs(10))
        .await
        .expect("SIGTERM must stop the daemon promptly");
    assert_eq!(status.code(), Some(0), "clean exit code, got {status:?}");

    let (stdout, stderr) = daemon.output().await;
    assert!(
        stdout.contains("SIGTERM received"),
        "the journal records the signal:\n{stdout}\n{stderr}"
    );
    assert!(
        !lock_path.exists(),
        "the lock file is removed on a clean exit"
    );
}

#[tokio::test]
async fn daemon_scheduler_off_discovers_but_never_claims() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");

    let payload = b"dump-off-bytes".as_slice();
    let sha = sha256_of(payload);
    mount_catalog(
        &server,
        vec![catalog_entry("dump_OFF", &sha)],
        "0000000000000005",
    )
    .await;
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000005" }),
    )
    .await;

    let mut config = test_config(&server, &state_dir);
    config.scheduler_enabled = false;
    let runner = Arc::new(FakeRunner::new(vec![]));
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });

    let store = open_store(&state_dir);
    await_condition("the catalog row to be discovered", || {
        !store
            .jobs()
            .jobs_in_phase(JobPhase::Discovered)
            .expect("list")
            .is_empty()
    })
    .await;

    // With the scheduler off, the job must stay discovered — never claimed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("list")
            .is_empty(),
        "no job may be claimed while the scheduler is off"
    );
    assert!(
        !store
            .jobs()
            .jobs_in_phase(JobPhase::Discovered)
            .expect("list")
            .is_empty()
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon stops")
        .expect("join")
        .expect("clean shutdown");
}

#[tokio::test]
async fn daemon_persists_the_env_token_and_boots_from_it_later() {
    let server = MockServer::start().await;
    mount_catalog(&server, vec![], "0000000000000000").await;
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000000" }),
    )
    .await;
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");

    // Boot 1: token from the environment; it must be persisted.
    let config = test_config(&server, &state_dir);
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, Arc::new(FakeRunner::new(vec![])), &shutdown).await }
    });
    await_condition("boot to finish the initial scan", || {
        open_store(&state_dir)
            .secrets()
            .get("analyzer_token")
            .expect("get")
            .is_some()
    })
    .await;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("stop")
        .expect("join")
        .expect("clean");
    assert_eq!(
        open_store(&state_dir)
            .secrets()
            .get("analyzer_token")
            .expect("get")
            .as_deref(),
        Some(TOKEN)
    );

    // Boot 2: no env token — the stored latest-used token takes over, and the
    // ledger sees it as the bearer credential. (reset clears the mocks, so
    // they are re-mounted.)
    server.reset().await;
    mount_catalog(&server, vec![], "0000000000000000").await;
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000000" }),
    )
    .await;
    let mut config = test_config(&server, &state_dir);
    config.token = None;
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, Arc::new(FakeRunner::new(vec![])), &shutdown).await }
    });
    // Poll the ledger for the boot scan request (received_requests is async,
    // so this cannot use await_condition).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if server
            .received_requests()
            .await
            .map(|r| !r.is_empty())
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "ledger never saw a request"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("stop")
        .expect("join")
        .expect("clean boot from the stored token");
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.iter().any(
            |r| r.headers.get("authorization").and_then(|v| v.to_str().ok())
                == Some(format!("Bearer {TOKEN}").as_str())
        ),
        "the stored token is presented as bearer"
    );
}

#[tokio::test]
async fn daemon_writeback_off_settles_done_without_any_post() {
    let server = MockServer::start().await;
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().join("state");

    let payload = b"dump-offline-bytes".as_slice();
    let sha = sha256_of(payload);
    mount_catalog(
        &server,
        vec![catalog_entry("dump_OFF", &sha)],
        "0000000000000005",
    )
    .await;
    mount_content(&server, "dump_OFF", payload, "\"etag-off\"", None).await;
    mount_events(
        &server,
        json!({ "events": [], "nextCursor": "0000000000000005" }),
    )
    .await;
    // Any POST to the analyses route must never happen.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let mut config = test_config(&server, &state_dir);
    config.writeback_enabled = false;
    let runner = Arc::new(FakeRunner::new(vec![Ok(completed_output("dump_OFF"))]));
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let config = config.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });

    let store = open_store(&state_dir);
    await_condition("the job to settle done", || {
        !store
            .jobs()
            .jobs_in_phase(JobPhase::Done)
            .expect("list")
            .is_empty()
    })
    .await;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon stops")
        .expect("join")
        .expect("clean shutdown");

    // The verdict is the local record; the ledger saw no write.
    let local = store.local_reports().pending().expect("pending");
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].dump_id, "dump_OFF");
}

#[tokio::test]
async fn daemon_resumes_interrupted_queue_entries_and_drains_them() {
    let server = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    let state_dir = dir.path().join("state");
    let store = open_store(&state_dir);
    let payload = b"recovered-dump";
    let sha = sha256_of(payload);
    let mut identities = Vec::new();
    for (index, phase) in [
        JobPhase::Claimed,
        JobPhase::Fetching,
        JobPhase::Staged,
        JobPhase::Analyzing,
        JobPhase::Reporting,
    ]
    .into_iter()
    .enumerate()
    {
        let id = triage_job(&format!("dump_RECOVER{index}"), &sha);
        store.jobs().upsert_discovered(&id).unwrap();
        store.jobs().set_phase(&id, phase).unwrap();
        store.jobs().record_attempt(&id).unwrap();
        mount_content(&server, &id.dump_id, payload, "\"recover\"", None).await;
        identities.push(id);
    }
    // Empty discovery proves that persisted work itself is resumed.
    mount_catalog(&server, vec![], "0000000000000005").await;
    mount_events(
        &server,
        json!({"events":[], "nextCursor":"0000000000000005"}),
    )
    .await;
    let mut config = test_config(&server, &state_dir);
    config.writeback_enabled = false;
    let runner = Arc::new(FakeRunner::new(
        (0..5).map(|_| Ok(completed_output("recovered"))).collect(),
    ));
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });
    await_condition("recovered work to leave the queue", || {
        phases(&store, JobPhase::Done).len() == identities.len()
    })
    .await;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(store.jobs().list().unwrap().is_empty());
    assert_eq!(
        store.local_reports().list_recent(10).unwrap().len(),
        identities.len()
    );
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Done)
            .unwrap()
            .iter()
            .all(|(_, attempts)| *attempts == 1)
    );
}

#[tokio::test]
async fn daemon_survives_a_purge_of_the_executing_job() {
    let server = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    let state_dir = dir.path().join("state");
    let payload = b"purge-while-executing";
    let sha = sha256_of(payload);
    mount_catalog(
        &server,
        vec![catalog_entry("dump_A", &sha), catalog_entry("dump_B", &sha)],
        "0000000000000010",
    )
    .await;
    mount_content(&server, "dump_A", payload, "\"purge\"", Some(1)).await;
    mount_content(&server, "dump_B", payload, "\"purge\"", None).await;
    mount_events(
        &server,
        json!({"events":[], "nextCursor":"0000000000000000"}),
    )
    .await;
    let mut config = test_config(&server, &state_dir);
    config.writeback_enabled = false;
    let (runner, gate) = FakeRunner::gated_first(Ok(completed_output("purged")));
    let runner = Arc::new(runner);
    let shutdown = CancellationToken::new();
    let daemon = tokio::spawn({
        let runner = runner.clone();
        let shutdown = shutdown.clone();
        async move { scheduler::run(config, runner, &shutdown).await }
    });
    let store = open_store(&state_dir);
    await_condition("first job inside runner", || !runner.calls().is_empty()).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(query_param("since", "0000000000000000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events":[event("0000000000000001", "FinishPurge", Some("dump_A"))],
            "nextCursor":"0000000000000002"
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    await_condition("executing job archived as dropped", || {
        store.jobs().phase_of(&triage_job("dump_A", &sha)).unwrap() == Some(JobPhase::Dropped)
    })
    .await;
    gate.release.notify_one();
    await_condition("next job completes after purge", || {
        store.jobs().phase_of(&triage_job("dump_B", &sha)).unwrap() == Some(JobPhase::Done)
    })
    .await;
    assert!(!daemon.is_finished(), "a purge must not stop the daemon");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(store.jobs().list().unwrap().is_empty());
    assert_eq!(
        store.jobs().phase_of(&triage_job("dump_A", &sha)).unwrap(),
        Some(JobPhase::Dropped)
    );
}
