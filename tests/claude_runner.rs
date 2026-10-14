//! `claude-cdb` provider tests: a fake `claude` executable (shell script
//! emitting canned envelopes) and a fake staging transport — no SSH, no real
//! claude, no network.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use dump_analyzer::claude_runner::ClaudeCdbRunner;
use dump_analyzer::runner::{ExecTransport, TransportOutput};
use dump_analyzer::types::{AnalyzerError, ReportOutcome, RunBounds, RunRequest, ToolRunner};

const BOUNDS: RunBounds = RunBounds {
    wall_timeout: Duration::from_secs(30),
    max_output_bytes: 1 << 20,
    max_workspace_bytes: 1 << 21,
};

#[derive(Clone, Default)]
struct FakeTransport {
    puts: std::sync::Arc<Mutex<Vec<(PathBuf, String)>>>,
    execs: std::sync::Arc<Mutex<Vec<Vec<String>>>>,
}

#[async_trait::async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        _stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> dump_analyzer::types::Result<TransportOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|a| a.to_string()));
        self.execs.lock().expect("lock").push(call);
        Ok(TransportOutput {
            status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    async fn put_file(&self, local: &Path, remote: &str) -> dump_analyzer::types::Result<()> {
        self.puts
            .lock()
            .expect("lock")
            .push((local.to_path_buf(), remote.to_string()));
        Ok(())
    }
}

/// Writes an executable fake `claude` whose stdout is `body`; the script also
/// records its argv into `$PWD/argv.txt` (cwd is the run workspace).
fn fake_claude(dir: &Path, body: &str) -> PathBuf {
    let script = dir.join("fake-claude.sh");
    let content = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PWD/argv.txt\"\nprintf '%s' '{}' \n",
        body.replace('\'', "'\\''")
    );
    std::fs::write(&script, content).expect("write fake claude");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod");
    }
    script
}

fn envelope(result: &str) -> String {
    let escaped = result
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!(
        "{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"{escaped}\"}}"
    )
}

fn request(dir: &Path) -> (RunRequest, PathBuf) {
    let dump = dir.join("dump.dmp");
    std::fs::write(&dump, b"fake-dump-bytes").expect("dump");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).expect("workdir");
    (
        RunRequest {
            dump_path: dump,
            symbol_path: "SRV*C:/symcache*https://ledger.example.test/symbols".to_string(),
            work_dir: work.clone(),
            bounds: BOUNDS,
        },
        work,
    )
}

#[tokio::test]
async fn claude_runner_completed_verdict() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = r#"{"outcome":"completed","summary":"access violation in app","facts":{"exceptionCode":"0xc0000005","faultingModule":"app.exe","topFrames":["app!main+0x12"]}}"#;
    let bin = fake_claude(dir.path(), &envelope(report));
    let seen = FakeTransport::default();
    let runner = ClaudeCdbRunner::new(
        seen.clone(),
        "windows-dev",
        bin.to_string_lossy().into_owned(),
    )
    .with_remote_base("C:/da/test");
    let (req, work) = request(dir.path());

    let out = runner.run(req).await.expect("run");
    assert_eq!(out.outcome, ReportOutcome::Completed);
    assert!(out.summary.contains("access violation"));
    assert_eq!(out.facts["exceptionCode"], "0xc0000005");

    // Staging happened: put_file plus remote mkdir and cleanup.
    assert_eq!(seen.puts.lock().expect("lock").len(), 1);
    let execs: Vec<Vec<String>> = seen.execs.lock().expect("lock").clone();
    assert!(
        execs.iter().any(|c| c.iter().any(|a| a == "mkdir")),
        "{execs:?}"
    );
    assert!(
        execs.iter().any(|c| c.iter().any(|a| a == "rm")),
        "{execs:?}"
    );

    // The claude invocation is contained: restricted, Bash-only, ssh/scp only.
    let argv = std::fs::read_to_string(work.join("argv.txt")).expect("argv recorded");
    assert!(argv.contains("--restricted"));
    assert!(argv.contains("--json-schema"));
    assert!(argv.contains("Bash(ssh:*) Bash(scp:*)"), "{argv}");
    assert!(argv.contains("--no-session-persistence"));
    assert!(argv.contains("windows-dev"));
}

#[tokio::test]
async fn claude_runner_failed_verdict_is_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report =
        r#"{"outcome":"failed","summary":"dump is corrupt","facts":{"reason":"bad header"}}"#;
    let bin = fake_claude(dir.path(), &envelope(report));
    let runner = ClaudeCdbRunner::new(
        FakeTransport::default(),
        "windows-dev",
        bin.to_string_lossy().into_owned(),
    );
    let (req, _work) = request(dir.path());
    let out = runner.run(req).await.expect("verdict");
    assert_eq!(out.outcome, ReportOutcome::Failed);
    assert!(out.summary.contains("corrupt"));
}

#[tokio::test]
async fn claude_runner_error_envelope_is_runner_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = fake_claude(
        dir.path(),
        "{\"type\":\"result\",\"subtype\":\"error\",\"is_error\":true}",
    );
    let runner = ClaudeCdbRunner::new(
        FakeTransport::default(),
        "windows-dev",
        bin.to_string_lossy().into_owned(),
    );
    let (req, _work) = request(dir.path());
    let err = runner.run(req).await.expect_err("must fail");
    assert!(matches!(err, AnalyzerError::Runner(_)), "{err}");
    assert!(err.is_transient(), "runner failures are transient");
}

#[tokio::test]
async fn claude_runner_malformed_result_is_runner_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = fake_claude(dir.path(), &envelope("not json at all"));
    let runner = ClaudeCdbRunner::new(
        FakeTransport::default(),
        "windows-dev",
        bin.to_string_lossy().into_owned(),
    );
    let (req, _work) = request(dir.path());
    let err = runner.run(req).await.expect_err("must fail");
    assert!(matches!(err, AnalyzerError::Runner(_)), "{err}");
}

#[tokio::test]
async fn claude_runner_timeout_kills() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A sleeping script (separate path: rewriting the same path races exec
    // with ETXTBSY on Linux).
    let bin = dir.path().join("sleep-claude.sh");
    std::fs::write(&bin, "#!/bin/sh\nsleep 30\n").expect("sleep script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&bin).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).expect("chmod");
    }
    let runner = ClaudeCdbRunner::new(
        FakeTransport::default(),
        "windows-dev",
        bin.to_string_lossy().into_owned(),
    );
    let (mut req, _work) = request(dir.path());
    req.bounds.wall_timeout = Duration::from_millis(200);
    let err = runner.run(req).await.expect_err("must time out");
    assert!(matches!(err, AnalyzerError::Runner(_)), "{err}");
    assert!(err.to_string().contains("wall timeout"), "{err}");
}

#[tokio::test]
async fn claude_runner_missing_binary_names_the_bin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let runner = ClaudeCdbRunner::new(
        FakeTransport::default(),
        "windows-dev",
        "/nonexistent/claude-bin",
    );
    let (req, _work) = request(dir.path());
    let err = runner.run(req).await.expect_err("must fail");
    assert!(matches!(err, AnalyzerError::Runner(_)), "{err}");
    assert!(err.to_string().contains("/nonexistent/claude-bin"), "{err}");
}
