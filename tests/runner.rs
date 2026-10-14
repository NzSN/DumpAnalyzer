//! Tool runner tests (task C2).
//!
//! CDB log parsing is exercised against the authored fixtures under
//! `tests/fixtures/cdb/` (clean analysis, missing symbols, corrupt dump); the
//! SSH/scp transport is exercised only through the in-memory
//! `FakeTransport` — no live SSH anywhere in this suite.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dump_analyzer::runner::{
    ExecTransport, MAX_FRAMES, SshCdbRunner, TransportOutput, parse_triage,
};
use dump_analyzer::types::{
    AnalyzerError, ReportOutcome, RunBounds, RunOutput, RunRequest, ToolRunner,
};

const CLEAN: &str = include_str!("fixtures/cdb/clean.log");
const SYMBOLS: &str = include_str!("fixtures/cdb/symbols.log");
const CORRUPT: &str = include_str!("fixtures/cdb/corrupt.log");

const SYMBOL_PATH: &str = "SRV*c:\\symcache*https://192.168.150.219:4080/symbols";

fn default_bounds() -> RunBounds {
    RunBounds {
        wall_timeout: Duration::from_secs(600),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 64 * 1024 * 1024,
    }
}

fn make_request(work_dir: PathBuf, bounds: RunBounds) -> RunRequest {
    std::fs::create_dir_all(&work_dir).expect("work dir");
    let dump_path = work_dir.join("dump.dmp");
    std::fs::write(&dump_path, b"MDMP pretend dump bytes").expect("write staged dump");
    RunRequest {
        dump_path,
        symbol_path: SYMBOL_PATH.to_string(),
        work_dir,
        bounds,
    }
}

// ---------------------------------------------------------------------------
// Parser tests (fixtures)
// ---------------------------------------------------------------------------

#[test]
fn runner_clean_fixture_yields_completed_triage() {
    let output = parse_triage(CLEAN).expect("clean fixture parses");

    assert_eq!(output.outcome, ReportOutcome::Completed);
    assert!(output.summary.contains("Access violation"));
    assert!(output.summary.contains("in electron"));
    assert!(output.summary.chars().count() <= 2000);

    let facts = &output.facts;
    assert_eq!(facts["exception"]["code"], "0xc0000005");
    assert_eq!(facts["exception"]["name"], "Access violation");
    assert_eq!(facts["exception"]["address"], "0x00007ff6e2d02a41");
    assert_eq!(facts["faulting_module"], "electron");

    let frames = facts["frames"].as_array().expect("frames array");
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0], "electron!CrashHandler");
    assert_eq!(frames[1], "electron!RenderFrame");
    assert_eq!(frames[3], "ntdll!RtlUserThreadStart");
    assert_eq!(facts["frames_total"], 4);

    assert_eq!(facts["symbols"]["pdb"], 3);
    assert_eq!(facts["symbols"]["deferred"], 1);
    assert_eq!(facts["symbols"]["missing"].as_array().unwrap().len(), 0);
    assert_eq!(facts["symbols"]["modules"]["electron"], "pdb");
    assert_eq!(facts["symbols"]["modules"]["KERNEL32"], "pdb");
    assert_eq!(facts["symbols"]["modules"]["USER32"], "deferred");

    assert_eq!(facts["process"]["id"], "2bc4");
    assert!(facts.get("failure").is_none());
}

#[test]
fn runner_symbols_fixture_fails_for_missing_critical_symbols() {
    let output = parse_triage(SYMBOLS).expect("symbols fixture parses");

    assert_eq!(output.outcome, ReportOutcome::Failed);
    assert_eq!(output.facts["failure"]["reason"], "symbols_missing");
    assert_eq!(output.facts["faulting_module"], "electron");
    assert_eq!(output.facts["symbols"]["modules"]["electron"], "none");
    assert_eq!(output.facts["symbols"]["no_symbols"], 1);
    assert_eq!(output.facts["symbols"]["missing"][0], "electron");

    let frames = output.facts["frames"].as_array().expect("frames array");
    assert_eq!(frames[0], "electron+0x1f2a41");
    assert_eq!(frames[2], "KERNEL32!BaseThreadInitThunk");

    assert!(output.summary.contains("no symbols"));
    assert!(output.summary.contains("electron"));
    assert!(output.summary.contains("triage failed"));
}

#[test]
fn runner_corrupt_fixture_fails_as_dump_corrupt() {
    let output = parse_triage(CORRUPT).expect("corrupt fixture parses");

    assert_eq!(output.outcome, ReportOutcome::Failed);
    assert_eq!(output.facts["failure"]["reason"], "dump_corrupt");
    assert!(output.summary.contains("could not open the dump"));
    assert!(output.summary.contains("Win32 error 0n38"));
    assert!(output.summary.contains("Reached the end of the file"));
    assert!(output.facts.get("frames").is_none());
}

#[test]
fn runner_unparseable_logs_are_runner_errors() {
    for log in [
        "",
        "hello world\nthis is not a debugger log\n",
        "\u{0}\u{1}\u{2}",
    ] {
        let error = parse_triage(log).expect_err("garbage must not parse");
        assert!(
            matches!(error, AnalyzerError::Runner(_)),
            "expected runner error for {log:?}, got {error:?}"
        );
    }
}

#[test]
fn runner_truncated_log_without_quit_marker_is_a_runner_error() {
    // The dump loaded, but the output ends before any triage facts and the
    // script never reached `q`: that is a run failure (crash/truncation),
    // never a "failed dump" verdict.
    let log = "\
Loading Dump File [C:\\dumps\\cut.dmp]
User Mini Dump File: Only registers, stack and portions of memory are available
0:000> .ecxr
";
    let error = parse_triage(log).expect_err("truncated log must not parse");
    assert!(matches!(error, AnalyzerError::Runner(_)));
}

#[test]
fn runner_log_with_quit_marker_but_no_facts_is_a_failed_verdict() {
    let log = "\
Loading Dump File [C:\\dumps\\empty.dmp]
User Mini Dump File: Only registers, stack and portions of memory are available
0:000> .ecxr
*** ERROR: Unable to get exception context for this dump
0:000> kc
Call Site
0:000> q
";
    let output = parse_triage(log).expect("script completed");
    assert_eq!(output.outcome, ReportOutcome::Failed);
    assert_eq!(output.facts["failure"]["reason"], "no_analysis_output");
}

#[test]
fn runner_tabular_frames_are_understood() {
    // Shape of `k`/`kv` console output (cf. real CDB logs): two address
    // columns followed by the call site.
    let log = "\
Loading Dump File [C:\\dumps\\case.dmp]
User Mini Dump File: Only registers, stack and portions of memory are available
0:047> k
 # Child-SP          RetAddr               Call Site
00 00000041`161fa8b0 0000227c`0d56f9c0     lceda_pro+0x475bc4b
01 00000041`161fa8b8 00007ffb`f6c9e8d7     KERNEL32!BaseThreadInitThunk+0x17
02 00000041`161fa8c0 00007ffb`f6e67624     ntdll!RtlUserThreadStart+0x21
";
    let output = parse_triage(log).expect("tabular frames parse");
    assert_eq!(output.outcome, ReportOutcome::Completed);
    let frames = output.facts["frames"].as_array().expect("frames array");
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0], "lceda_pro+0x475bc4b");
    assert_eq!(frames[1], "KERNEL32!BaseThreadInitThunk+0x17");
}

#[test]
fn runner_kv_frames_with_argument_columns_are_understood() {
    let log = "\
Loading Dump File [C:\\dumps\\case.dmp]
User Mini Dump File: Only registers, stack and portions of memory are available
0:047> kv
Child-SP          RetAddr               : Args to Child                                                           : Call Site
00000041`161fa8b0 0000227c`0d56f9c0     : 00000041`161fba10 0000227c`08ed1fa8 00000000`00008c36 00000000`ffffff04 : lceda_pro+0x475bc4b
00000041`161fa8b8 00007ffb`f6c9e8d7     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x17
";
    let output = parse_triage(log).expect("kv frames parse");
    let frames = output.facts["frames"].as_array().expect("frames array");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], "lceda_pro+0x475bc4b");
    assert_eq!(frames[1], "KERNEL32!BaseThreadInitThunk+0x17");
}

#[test]
fn runner_frames_are_capped_and_facts_stay_bounded() {
    let mut log = String::from(
        "Loading Dump File [C:\\dumps\\many.dmp]\n\
         User Mini Dump File: Only registers, stack and portions of memory are available\n\
         (2bc4.5f18): Access violation - code c0000005 (first/second chance not available)\n\
         0:000> .ecxr\n\
         rip=00007ff6e2d02a41 rsp=000000d1f27fe6b8\n\
         electron!CrashHandler+0x1f2a41:\n\
         00007ff6`e2d02a41 488b01          mov     rax,qword ptr [rcx]\n\
         0:000> kc\n\
         Call Site\n",
    );
    for index in 0..100 {
        log.push_str(&format!("electron!Frame{index}\n"));
    }
    log.push_str(
        "0:000> lm\n\
         start             end                 module name\n\
         00007ff6`e2b10000 00007ff6`ecc00000   electron   (private pdb symbols)  C:\\symcache\\electron.pdb\n",
    );

    let output = parse_triage(&log).expect("long stack parses");
    assert_eq!(output.outcome, ReportOutcome::Completed);
    let frames = output.facts["frames"].as_array().expect("frames array");
    assert_eq!(frames.len(), MAX_FRAMES);
    assert_eq!(output.facts["frames_total"], 100);
    assert_eq!(output.facts["frames_truncated"], true);

    let encoded = serde_json::to_string(&output.facts).expect("facts serialize");
    assert!(
        encoded.len() < 16 * 1024,
        "facts must fit the server envelope, got {} bytes",
        encoded.len()
    );
}

#[test]
fn runner_missing_caller_symbols_alone_stay_completed() {
    // Only the *faulting* module's missing symbols are critical; a caller
    // module with export-only symbols is recorded, not failed.
    let log = "\
Loading Dump File [C:\\dumps\\ok.dmp]
User Mini Dump File: Only registers, stack and portions of memory are available
(2bc4.5f18): Access violation - code c0000005 (first/second chance not available)
0:000> .ecxr
rip=00007ff6e2d02a41 rsp=000000d1f27fe6b8
electron!CrashHandler+0x1f2a41:
00007ff6`e2d02a41 488b01          mov     rax,qword ptr [rcx]
0:000> kc
Call Site
electron!CrashHandler
USER32+0x1234
0:000> lm
start             end                 module name
00007ff6`e2b10000 00007ff6`ecc00000   electron   (private pdb symbols)  C:\\symcache\\electron.pdb
00007ffb`c2a00000 00007ffb`c2bd0000   USER32     (export symbols)       C:\\WINDOWS\\system32\\USER32.dll
0:000> q
";
    let output = parse_triage(log).expect("log parses");
    assert_eq!(output.outcome, ReportOutcome::Completed);
    assert_eq!(output.facts["symbols"]["export_only"], 1);
    assert_eq!(output.facts["symbols"]["missing"][0], "USER32");
    assert!(output.facts.get("failure").is_none());
}

// ---------------------------------------------------------------------------
// SshCdbRunner tests (fake transport)
// ---------------------------------------------------------------------------

type Reply = std::result::Result<TransportOutput, AnalyzerError>;
type Handler = dyn Fn(&str, &[&str]) -> Option<Reply> + Send + Sync;

#[derive(Debug)]
struct Call {
    program: String,
    args: Vec<String>,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct Put {
    local: PathBuf,
    remote: String,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct FakeInner {
    handler: Option<Box<Handler>>,
    calls: Mutex<Vec<Call>>,
    puts: Mutex<Vec<Put>>,
    fail_put_suffix: Mutex<Option<(String, String)>>,
}

#[derive(Clone)]
struct FakeTransport {
    inner: Arc<FakeInner>,
}

impl FakeTransport {
    fn new(handler: impl Fn(&str, &[&str]) -> Option<Reply> + Send + Sync + 'static) -> Self {
        Self {
            inner: Arc::new(FakeInner {
                handler: Some(Box::new(handler)),
                ..FakeInner::default()
            }),
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.inner
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .map(|call| (call.program.clone(), call.args.clone()))
            .collect()
    }

    fn cdb_call(&self) -> Option<(Vec<String>, Duration)> {
        self.inner
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .find(|call| call.program == "cdb")
            .map(|call| (call.args.clone(), call.timeout))
    }

    fn puts(&self) -> Vec<Put> {
        self.inner.puts.lock().expect("puts lock").clone()
    }

    fn fail_put(&self, suffix: &str, message: &str) {
        *self.inner.fail_put_suffix.lock().expect("lock") =
            Some((suffix.to_string(), message.to_string()));
    }
}

#[async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        _stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput, AnalyzerError> {
        self.inner.calls.lock().expect("calls lock").push(Call {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            timeout,
        });
        let handler = self.inner.handler.as_ref().expect("handler");
        match handler(program, args) {
            Some(reply) => reply,
            None => Ok(TransportOutput {
                status: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        }
    }

    async fn put_file(&self, local: &Path, remote: &str) -> Result<(), AnalyzerError> {
        if let Some((suffix, message)) = self.inner.fail_put_suffix.lock().expect("lock").clone() {
            if remote.ends_with(&suffix) {
                return Err(AnalyzerError::Transport(message));
            }
        }
        let bytes = std::fs::read(local)
            .map_err(|err| AnalyzerError::Transport(format!("fake read: {err}")))?;
        self.inner.puts.lock().expect("puts lock").push(Put {
            local: local.to_path_buf(),
            remote: remote.to_string(),
            bytes,
        });
        Ok(())
    }
}

/// A transport whose `cdb` call returns `stdout`/`status` as given.
fn cdb_transport(stdout: &str, status: Option<i32>) -> FakeTransport {
    let stdout = stdout.as_bytes().to_vec();
    FakeTransport::new(move |program, _args| {
        if program == "cdb" {
            Some(Ok(TransportOutput {
                status,
                stdout: stdout.clone(),
                stderr: Vec::new(),
            }))
        } else {
            None
        }
    })
}

fn expected_script() -> String {
    format!(
        "$$ DumpAnalyzer CDB triage script (v1)\n.sympath {SYMBOL_PATH}\n.reload\n.ecxr\nkc\nlm\n|\nq\n"
    )
}

#[tokio::test]
async fn runner_run_stages_script_and_dump_then_parses_cdb() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work_dir = tmp.path().join("run-2bc4");
    let dump_bytes = b"MDMP pretend dump bytes".to_vec();

    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(work_dir.clone(), default_bounds());
    let output = runner.run(request).await.expect("clean run succeeds");

    assert_eq!(output.outcome, ReportOutcome::Completed);
    assert_eq!(output.facts["log"]["truncated"], false);
    assert_eq!(output.facts["log"]["bytes"], CLEAN.len());
    assert!(output.facts.get("failure").is_none());

    // Staging: the bounded script and the dump, in that order.
    let puts = fake.puts();
    assert_eq!(puts.len(), 2);
    assert!(puts[0].remote.ends_with("/triage.cdb"), "{:?}", puts[0]);
    assert!(puts[1].remote.ends_with("/dump.dmp"), "{:?}", puts[1]);
    assert!(puts[1].remote.starts_with("C:/da/work/"), "{:?}", puts[1]);
    assert_eq!(
        String::from_utf8(puts[0].bytes.clone()).unwrap(),
        expected_script()
    );
    assert_eq!(puts[1].bytes, dump_bytes);
    assert_eq!(puts[1].local, work_dir.join("dump.dmp"));

    // Script is also written into the local run workspace.
    let local_script = std::fs::read(work_dir.join("triage.cdb")).expect("local script");
    assert_eq!(String::from_utf8(local_script).unwrap(), expected_script());

    // Command order: mkdir, cdb, cleanup.
    let calls = fake.calls();
    let remote_dir = puts[0]
        .remote
        .strip_suffix("/triage.cdb")
        .expect("remote dir")
        .to_string();
    assert_eq!(calls.len(), 3, "{calls:?}");
    let bash_dir = remote_dir.replacen("C:", "/c", 1);
    assert_eq!(
        calls[0],
        (
            "mkdir".to_string(),
            vec!["-p".to_string(), bash_dir.clone()]
        )
    );
    assert_eq!(
        calls[2],
        ("rm".to_string(), vec!["-rf".to_string(), bash_dir.clone()])
    );

    let (args, timeout) = fake.cdb_call().expect("cdb invoked");
    assert_eq!(args[0], "-z");
    assert_eq!(args[1], format!("{remote_dir}/dump.dmp"));
    assert_eq!(args[2], "-cf");
    assert_eq!(args[3], format!("{remote_dir}/triage.cdb"));
    assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(600));
}

#[tokio::test]
async fn runner_dump_staging_failure_is_a_runner_error_and_cdb_never_runs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    fake.fail_put("dump.dmp", "scp: connection refused");
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(tmp.path().join("run-stage"), default_bounds());

    let error = runner.run(request).await.expect_err("staging must fail");
    let message = error.to_string();
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(message.contains("staging"), "{message}");
    assert!(message.contains("dump.dmp"), "{message}");
    assert!(fake.cdb_call().is_none(), "cdb must not run");
    // The remote workspace is still cleaned up on failure.
    assert!(fake.calls().iter().any(|(program, _)| program == "rm"));
}

#[tokio::test]
async fn runner_cdb_timeout_is_a_runner_error_never_a_verdict() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = FakeTransport::new(|program, _args| {
        if program == "cdb" {
            Some(Err(AnalyzerError::Transport(
                "ssh: cdb timed out after 600s".to_string(),
            )))
        } else {
            None
        }
    });
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(tmp.path().join("run-timeout"), default_bounds());

    let error = runner.run(request).await.expect_err("timeout must fail");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(error.to_string().contains("timed out"), "{error}");
    assert!(fake.calls().iter().any(|(program, _)| program == "rm"));
}

#[tokio::test]
async fn runner_corrupt_dump_is_a_failed_verdict_even_with_nonzero_exit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CORRUPT, Some(1));
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(tmp.path().join("run-corrupt"), default_bounds());

    let output = runner
        .run(request)
        .await
        .expect("corrupt dump is a verdict");
    assert_eq!(output.outcome, ReportOutcome::Failed);
    assert_eq!(output.facts["failure"]["reason"], "dump_corrupt");
}

#[tokio::test]
async fn runner_unparsed_cdb_output_is_a_runner_error_not_a_verdict() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = FakeTransport::new(|program, _args| {
        if program == "cdb" {
            Some(Ok(TransportOutput {
                status: Some(-1073741819),
                stdout: b"\x00\x01 not a cdb log at all".to_vec(),
                stderr: Vec::new(),
            }))
        } else {
            None
        }
    });
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(tmp.path().join("run-crash"), default_bounds());

    let error = runner
        .run(request)
        .await
        .expect_err("crash must not be a verdict");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(
        error.to_string().contains("no usable CDB verdict"),
        "{error}"
    );
}

#[tokio::test]
async fn runner_clean_log_with_nonzero_exit_is_a_runner_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(1));
    let runner = SshCdbRunner::new(fake.clone());
    let request = make_request(tmp.path().join("run-exit"), default_bounds());

    let error = runner
        .run(request)
        .await
        .expect_err("non-zero exit must fail");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(
        error.to_string().contains("without a failed verdict"),
        "{error}"
    );
}

#[tokio::test]
async fn runner_output_cap_truncates_and_marks_the_log() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let mut bounds = default_bounds();
    bounds.max_output_bytes = CLEAN.len() - 40;
    let request = make_request(tmp.path().join("run-cap"), bounds);

    let output = runner
        .run(request)
        .await
        .expect("truncated tail still parses");
    assert_eq!(output.outcome, ReportOutcome::Completed);
    assert_eq!(output.facts["log"]["truncated"], true);
    assert_eq!(output.facts["log"]["bytes"], CLEAN.len());
    assert!(
        output.summary.contains("truncated to"),
        "{}",
        output.summary
    );
}

#[tokio::test]
async fn runner_output_cap_hit_before_any_facts_is_a_runner_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let mut bounds = default_bounds();
    bounds.max_output_bytes = 200;
    let request = make_request(tmp.path().join("run-cap2"), bounds);

    let error = runner.run(request).await.expect_err("unclassifiable cap");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("no usable CDB verdict"), "{message}");
    assert!(message.contains("truncated to 200 bytes"), "{message}");
}

#[tokio::test]
async fn runner_workspace_over_cap_fails_before_any_transport_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let mut bounds = default_bounds();
    bounds.max_workspace_bytes = 8;
    let request = make_request(tmp.path().join("run-ws"), bounds);

    let error = runner.run(request).await.expect_err("workspace cap");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(error.to_string().contains("cap"), "{error}");
    assert!(fake.calls().is_empty(), "no transport call expected");
}

#[tokio::test]
async fn runner_zero_wall_timeout_fails_before_any_transport_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let mut bounds = default_bounds();
    bounds.wall_timeout = Duration::ZERO;
    let request = make_request(tmp.path().join("run-deadline"), bounds);

    let error = runner.run(request).await.expect_err("deadline exceeded");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(error.to_string().contains("wall-time budget"), "{error}");
    assert!(fake.calls().is_empty(), "no transport call expected");
}

#[tokio::test]
async fn runner_symbol_path_injection_is_rejected_before_staging() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let mut request = make_request(tmp.path().join("run-inject"), default_bounds());
    request.symbol_path = "SRV*c:\\symcache\n.echo pwned".to_string();

    let error = runner.run(request).await.expect_err("injection rejected");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(error.to_string().contains("symbol path"), "{error}");
    assert!(fake.calls().is_empty(), "no transport call expected");

    // A whitespace path would split the `.sympath` line: reject loudly
    // instead of silently staging a wrong symbol path.
    let mut request = make_request(tmp.path().join("run-space"), default_bounds());
    request.symbol_path = SYMBOL_PATH.replace("c:\\symcache", "c:\\my cache");
    let error = runner.run(request).await.expect_err("whitespace rejected");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(fake.calls().is_empty(), "no transport call expected");
}

#[tokio::test]
async fn runner_missing_staged_dump_is_rejected_before_staging() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake = cdb_transport(CLEAN, Some(0));
    let runner = SshCdbRunner::new(fake.clone());
    let work_dir = tmp.path().join("run-missing");
    std::fs::create_dir_all(&work_dir).expect("work dir");
    let request = RunRequest {
        dump_path: work_dir.join("absent.dmp"),
        symbol_path: SYMBOL_PATH.to_string(),
        work_dir,
        bounds: default_bounds(),
    };

    let error = runner
        .run(request)
        .await
        .expect_err("missing dump rejected");
    assert!(matches!(error, AnalyzerError::Runner(_)), "{error:?}");
    assert!(error.to_string().contains("staged dump"), "{error}");
    assert!(fake.calls().is_empty(), "no transport call expected");
}

// Keep `RunOutput` referenced so the payload type is checked here too.
fn _assert_run_output(_: &RunOutput) {}
