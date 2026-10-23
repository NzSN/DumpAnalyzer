//! Controlled transport fixtures; no debugger, model, or network is required.
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dump_analyzer::analysis_tools::{AnalysisTools, CdbSession, tool_definitions};
use dump_analyzer::report::CaptureStatus;
use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::types::{AnalyzerError, Result, RunBounds, RunRequest};
use serde_json::json;

const CLEAN: &str = include_str!("fixtures/cdb/clean.log");

#[derive(Clone, Default)]
struct FakeTransport(Arc<Mutex<Calls>>);
#[derive(Default)]
struct Calls {
    executions: Vec<(String, Vec<String>, Option<String>, usize)>,
    uploads: Vec<String>,
    mode: QueryMode,
    baseline_wait: bool,
}
#[derive(Default, Clone, Copy)]
enum QueryMode {
    #[default]
    Good,
    Error,
    Huge,
    Wait,
    MissingMemory,
}
impl FakeTransport {
    fn cleanups(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .executions
            .iter()
            .filter(|(name, ..)| name == "rm")
            .count()
    }
    fn queries(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .executions
            .iter()
            .filter(|(_, _, script, _)| script.is_some())
            .count()
    }
}
#[async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput> {
        self.exec_bounded(program, args, stdin, timeout, usize::MAX)
            .await
    }
    async fn exec_bounded(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        _: Duration,
        output_cap: usize,
    ) -> Result<TransportOutput> {
        let (mode, baseline_wait) = {
            let mut state = self.0.lock().unwrap();
            state.executions.push((
                program.into(),
                args.iter().map(|s| s.to_string()).collect(),
                stdin.map(|s| String::from_utf8_lossy(s).to_string()),
                output_cap,
            ));
            (state.mode, state.baseline_wait)
        };
        let body = if program != "cdb" {
            String::new()
        } else if let Some(script) = stdin {
            match mode {
                QueryMode::Error => {
                    return Err(AnalyzerError::Transport("secret=DO_NOT_RETAIN".into()));
                }
                QueryMode::Wait => {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
                _ => {}
            }
            let script = String::from_utf8_lossy(script);
            let begin = script
                .lines()
                .find(|line| line.starts_with(".echo DA_QUERY_BEGIN:"))
                .unwrap()
                .trim_start_matches(".echo ");
            let end = script
                .lines()
                .find(|line| line.starts_with(".echo DA_QUERY_END:"))
                .unwrap()
                .trim_start_matches(".echo ");
            let content = match mode {
                QueryMode::Huge => "x".repeat(output_cap + 1000),
                QueryMode::MissingMemory => "00000000`00000000  ?? ?? ?? ?? ????????????????".into(),
                _ if script.contains("\n~\n") => ". 0 Id: abcd.1234 Suspend: 0 Teb: 00000100\n  7 Id: abcd.9876 Suspend: 0 Teb: 00000200".into(),
                _ => "controlled debugger evidence".into(),
            };
            format!("{begin}\n{content}\n{end}\n")
        } else {
            if baseline_wait {
                std::future::pending::<()>().await;
            }
            format!("{CLEAN}\n. 0 Id: abcd.1234 Suspend: 0 Teb: 00000100\n")
        };
        Ok(TransportOutput {
            status: Some(0),
            stdout: body.into_bytes(),
            stderr: Vec::new(),
        })
    }
    async fn put_file(&self, _: &Path, remote: &str) -> Result<()> {
        self.0.lock().unwrap().uploads.push(remote.into());
        Ok(())
    }
}

fn request(temp: &tempfile::TempDir, max_output: usize) -> RunRequest {
    let dump = temp.path().join("verified.dmp");
    std::fs::write(&dump, b"MDMP controlled test").unwrap();
    RunRequest {
        dump_path: dump,
        work_dir: temp.path().into(),
        symbol_path: "C:/symbols".into(),
        bounds: RunBounds {
            wall_timeout: Duration::from_secs(1),
            max_output_bytes: max_output,
            max_workspace_bytes: 1_000_000,
        },
    }
}
async fn session(
    fake: FakeTransport,
    temp: &tempfile::TempDir,
    max_output: usize,
) -> Arc<CdbSession<FakeTransport>> {
    SshCdbRunner::new(fake)
        .begin_session(
            request(temp, max_output),
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
        .unwrap()
        .1
}

#[tokio::test]
async fn six_tools_use_pinned_dump_and_leave_baseline_intact_until_close() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let runner = SshCdbRunner::new(fake.clone());
    let (baseline, session) = runner
        .begin_session(
            request(&temp, 1024 * 1024),
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
        .unwrap();
    let original = baseline.capture.unwrap();
    assert_eq!(fake.cleanups(), 0);
    assert_eq!(tool_definitions().as_array().unwrap().len(), 6);
    for (name, args) in [
        ("list_threads", json!({})),
        ("get_stack", json!({"thread_id":7,"frames":64})),
        ("get_registers", json!({"thread_id":0})),
        (
            "read_memory",
            json!({"address":"0xFEDCBA9876543210","length":256}),
        ),
        (
            "disassemble",
            json!({"address":"0x7ff6e2d02a41","count":64}),
        ),
        ("get_module_symbols", json!({"module_id":"electron"})),
    ] {
        let evidence = session.call(name, args).await.unwrap();
        assert_eq!(
            evidence.status,
            CaptureStatus::Present,
            "{name}: {evidence:?}"
        );
        assert!(session.evidence().await.contains(&evidence));
        assert!(!original.evidence.iter().any(|e| e.id == evidence.id));
    }
    {
        let state = fake.0.lock().unwrap();
        let dump_paths: Vec<_> = state
            .executions
            .iter()
            .filter(|(p, ..)| p == "cdb")
            .map(|(_, args, ..)| &args[1])
            .collect();
        assert!(dump_paths.iter().all(|p| *p == dump_paths[0]));
        assert_eq!(
            state
                .uploads
                .iter()
                .filter(|p| p.ends_with("/dump.dmp"))
                .count(),
            1
        );
        assert!(
            state
                .executions
                .iter()
                .filter(|(_, _, s, _)| s.is_some())
                .all(|(_, _, _, cap)| *cap <= 8192)
        );
        assert!(state.executions.iter().any(|(_, _, script, _)| {
            script
                .as_ref()
                .is_some_and(|s| s.contains("db 0xfedcba9876543210 L0n256"))
        }));
    }
    session.close().await;
    session.close().await;
    assert_eq!(fake.cleanups(), 1);
    assert!(session.call("list_threads", json!({})).await.is_err());
    drop(session);
    tokio::task::yield_now().await;
    assert_eq!(fake.cleanups(), 1);
}

#[tokio::test]
async fn rejects_injection_unknown_inputs_and_overflow_without_execution() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    for (name, args) in [
        ("shell", json!({"command":"whoami"})),
        ("list_threads", json!({"command":".shell cmd"})),
        ("list_threads", json!([])),
        (
            "read_memory",
            json!({"address":"0x1; .shell whoami","length":1}),
        ),
        ("read_memory", json!({"address":"@$ip","length":1})),
        ("read_memory", json!({"address":1234,"length":1})),
        ("read_memory", json!({"address":"0x1","length":257})),
        (
            "read_memory",
            json!({"address":"0xffffffffffffffff","length":2}),
        ),
        ("disassemble", json!({"address":"0x1","count":65})),
        ("get_stack", json!({"thread_id":"0; .shell cmd"})),
        ("get_stack", json!({"thread_id":0,"frames":0})),
        ("get_stack", json!({"thread_id":5})),
        ("get_registers", json!({"thread_id":-1})),
        (
            "get_module_symbols",
            json!({"module_id":"electron; .shell cmd"}),
        ),
        ("get_module_symbols", json!({"module_id":"*"})),
        (
            "get_module_symbols",
            json!({"module_id":"electron","path":"C:/secret"}),
        ),
    ] {
        let session = session(fake.clone(), &temp, 1024 * 1024).await;
        assert!(session.call(name, args).await.is_err(), "{name}");
        assert!(session.evidence().await.is_empty());
        session.close().await;
    }
    assert_eq!(fake.queries(), 0);
}

#[tokio::test]
async fn rejected_arguments_consume_attempt_budget() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let session = session(fake.clone(), &temp, 1024 * 1024).await;
    for _ in 0..7 {
        assert!(
            session
                .call("list_threads", json!({"extra":true}))
                .await
                .is_err()
        );
    }
    assert!(session.call("list_threads", json!({})).await.is_ok());
    assert!(session.call("list_threads", json!({})).await.is_err());
    assert_eq!(fake.queries(), 1);
    assert_eq!(session.evidence().await.len(), 1);
    session.close().await;
}

#[tokio::test]
async fn failures_and_caps_are_retained_and_attempts_are_charged() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let session = session(fake.clone(), &temp, 1024 * 1024).await;
    fake.0.lock().unwrap().mode = QueryMode::Error;
    let failed = session.call("list_threads", json!({})).await.unwrap();
    assert_eq!(failed.status, CaptureStatus::Failed);
    assert!(
        !serde_json::to_string(&failed)
            .unwrap()
            .contains("DO_NOT_RETAIN")
    );
    fake.0.lock().unwrap().mode = QueryMode::MissingMemory;
    let missing = session
        .call("read_memory", json!({"address":"0x0","length":16}))
        .await
        .unwrap();
    assert_eq!(missing.status, CaptureStatus::Failed);
    fake.0.lock().unwrap().mode = QueryMode::Huge;
    for _ in 2..8 {
        let capped = session.call("list_threads", json!({})).await.unwrap();
        assert_eq!(capped.status, CaptureStatus::Truncated);
        assert!(capped.truncated);
        assert!(capped.text.len() <= 8192);
    }
    assert!(session.call("list_threads", json!({})).await.is_err());
    assert_eq!(session.evidence().await.len(), 8);
    session.close().await;
}

#[tokio::test]
async fn output_reservation_is_shared_across_queries_and_baseline() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    // A quarter of this budget is exactly one full query section.
    let session = session(fake.clone(), &temp, 32 * 1024).await;
    fake.0.lock().unwrap().mode = QueryMode::Huge;
    let evidence = session.call("list_threads", json!({})).await.unwrap();
    assert_eq!(evidence.status, CaptureStatus::Truncated);
    assert!(session.call("list_threads", json!({})).await.is_err());
    let caps: Vec<_> = fake
        .0
        .lock()
        .unwrap()
        .executions
        .iter()
        .filter(|(p, ..)| p == "cdb")
        .map(|(_, _, _, cap)| *cap)
        .collect();
    assert_eq!(caps, vec![24 * 1024, 8 * 1024]);
    session.close().await;
}

#[tokio::test]
async fn close_cancels_active_query_and_records_failure_before_cleanup() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let session = session(fake.clone(), &temp, 1024 * 1024).await;
    fake.0.lock().unwrap().mode = QueryMode::Wait;
    let query_session = Arc::clone(&session);
    let query = tokio::spawn(async move { query_session.call("list_threads", json!({})).await });
    while fake.queries() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(1), session.close())
        .await
        .unwrap();
    let evidence = query.await.unwrap().unwrap();
    assert_eq!(evidence.status, CaptureStatus::Failed);
    assert_eq!(session.evidence().await, vec![evidence]);
    assert_eq!(fake.cleanups(), 1);
}

#[tokio::test]
async fn dropping_session_and_cancelling_initial_collection_schedule_cleanup() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let session = session(fake.clone(), &temp, 1024 * 1024).await;
    drop(session);
    tokio::time::timeout(Duration::from_secs(1), async {
        while fake.cleanups() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fake.cleanups(), 1);

    let fake = FakeTransport::default();
    fake.0.lock().unwrap().baseline_wait = true;
    let runner = SshCdbRunner::new(fake.clone());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            runner.begin_session(
                request(&temp, 1024 * 1024),
                tokio::time::Instant::now() + Duration::from_secs(60)
            )
        )
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while fake.cleanups() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn whole_run_deadline_bounds_query_and_rejects_late_calls() {
    let fake = FakeTransport::default();
    let temp = tempfile::tempdir().unwrap();
    let runner = SshCdbRunner::new(fake.clone());
    let (_, session) = runner
        .begin_session(
            request(&temp, 1024 * 1024),
            tokio::time::Instant::now() + Duration::from_millis(100),
        )
        .await
        .unwrap();
    fake.0.lock().unwrap().mode = QueryMode::Wait;
    let evidence = session.call("list_threads", json!({})).await.unwrap();
    assert_eq!(evidence.status, CaptureStatus::TimedOut);
    assert!(session.call("list_threads", json!({})).await.is_err());
    session.close().await;
}
