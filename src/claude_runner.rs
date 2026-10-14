//! The `claude-cdb` tool-runner provider (decision 2026-10-13): the `claude`
//! CLI agent drives CDB on the analysis box, replacing the deterministic
//! script of [`crate::runner::SshCdbRunner`].
//!
//! Containment, per the project's Claude-usage discipline:
//!
//! * claude runs in `--restricted` mode with only `Bash` re-enabled, and only
//!   `ssh`/`scp` commands are pre-approved (`--allowedTools`) — the agent can
//!   reach the analysis box and nothing else;
//! * its working directory is the per-run workspace, wiped by the agent after
//!   the run; sessions are not persisted (`--no-session-persistence`);
//! * the run is bounded by [`RunBounds::wall_timeout`] (process kill) and
//!   [`RunBounds::max_output_bytes`] (captured-output cap), exactly like the
//!   script runner;
//! * output is forced through `--json-schema` into the report contract;
//!   anything unparseable is a runner error (transient, retry-budgeted),
//!   never a verdict.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::runner::{ExecTransport, bash_path};
use crate::types::{AnalyzerError, ReportOutcome, Result, RunOutput, RunRequest, ToolRunner};

/// Remote staging root on the analysis box (matches the script runner).
const DEFAULT_REMOTE_BASE: &str = "C:/da/work";

/// The output contract forced via `--json-schema`.
const OUTPUT_SCHEMA: &str = r#"{
  "type": "object",
  "required": ["outcome", "summary", "facts"],
  "additionalProperties": false,
  "properties": {
    "outcome": { "type": "string", "enum": ["completed", "failed"] },
    "summary": { "type": "string", "maxLength": 2000 },
    "facts": { "type": "object" }
  }
}"#;

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A [`ToolRunner`] that lets `claude` drive CDB over SSH. Generic over the
/// staging transport so tests never touch SSH.
pub struct ClaudeCdbRunner<T: ExecTransport> {
    transport: T,
    ssh_target: String,
    remote_base: String,
    claude_bin: String,
    model: Option<String>,
}

impl<T: ExecTransport> ClaudeCdbRunner<T> {
    pub fn new(transport: T, ssh_target: impl Into<String>, claude_bin: impl Into<String>) -> Self {
        Self {
            transport,
            ssh_target: ssh_target.into(),
            remote_base: DEFAULT_REMOTE_BASE.to_string(),
            claude_bin: claude_bin.into(),
            model: None,
        }
    }

    pub fn with_remote_base(mut self, base: impl Into<String>) -> Self {
        self.remote_base = base.into();
        self
    }

    pub fn with_model(mut self, model: Option<String>) -> Self {
        self.model = model;
        self
    }

    fn prompt(&self, remote_dump: &str, symbol_path: &str) -> String {
        format!(
            "You are a Windows crash-dump triage agent. A minidump is staged on the \
             Windows analysis box.\n\n\
             Environment:\n\
             - SSH target: {target} (run every box command as `ssh {target} ...`; BatchMode \
               is on, so interactive auth will fail)\n\
             - Dump path on the box: {remote_dump}\n\
             - Symbol store for .sympath: {symbol_path}\n\n\
             Task: analyze the dump with CDB over SSH (at minimum `.sympath`, `.reload`, \
             `.ecxr`, a stack walk, and a module list), identify the exception, faulting \
             module, and top frames, and judge symbol coverage. Do not modify anything on \
             the box outside a scratch directory you create and remove. Do not run local \
             commands other than ssh/scp.\n\n\
             Output contract: your final message is a single JSON object matching the \
             provided schema — outcome \"completed\" when a verdict was reached, \
             \"failed\" when the dump is unanalyzable (corrupt, unloadable, unusable); \
             summary is plain text for an operator; facts is a structured object with at \
             least exceptionCode, exceptionAddress, faultingModule, topFrames, and \
             symbolStatus. Never embed raw dump memory or credentials.",
            target = self.ssh_target,
            remote_dump = remote_dump,
            symbol_path = symbol_path,
        )
    }

    async fn run_claude(
        &self,
        work_dir: &std::path::Path,
        remote_dump: &str,
        symbol_path: &str,
        bounds: crate::types::RunBounds,
    ) -> Result<Vec<u8>> {
        let mut args: Vec<String> = vec![
            "-p".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
            "--json-schema".to_string(),
            OUTPUT_SCHEMA.to_string(),
            "--restricted".to_string(),
            "--tools".to_string(),
            "Bash".to_string(),
            "--allowedTools".to_string(),
            format!("Bash(ssh:*) Bash(scp:*)"),
            "--no-session-persistence".to_string(),
        ];
        if let Some(model) = &self.model {
            args.push("--model".to_string());
            args.push(model.clone());
        }
        args.push(self.prompt(remote_dump, symbol_path));

        let mut child = Command::new(&self.claude_bin)
            .args(&args)
            .current_dir(work_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| {
                AnalyzerError::Runner(format!(
                    "spawn {} (PATH lookup or DUMP_ANALYZER_CLAUDE_BIN): {err}",
                    self.claude_bin
                ))
            })?;

        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let deadline = tokio::time::Instant::now() + bounds.wall_timeout;
        let mut out: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        let status = loop {
            let read = tokio::time::timeout_at(deadline, stdout.read(&mut chunk));
            match read.await {
                Err(_) => {
                    let _ = child.kill().await;
                    return Err(AnalyzerError::Runner(format!(
                        "claude exceeded the run wall timeout of {:?}",
                        bounds.wall_timeout
                    )));
                }
                Ok(Err(err)) => {
                    let _ = child.kill().await;
                    return Err(AnalyzerError::Runner(format!("read claude output: {err}")));
                }
                Ok(Ok(0)) => break child.wait().await,
                Ok(Ok(n)) => {
                    if out.len() < bounds.max_output_bytes {
                        let keep = (bounds.max_output_bytes - out.len()).min(n);
                        out.extend_from_slice(&chunk[..keep]);
                    }
                }
            }
        };
        // Best-effort drain of stderr for diagnostics.
        let mut err_tail = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), stderr.read_to_end(&mut err_tail)).await;
        let status = status.map_err(|err| AnalyzerError::Runner(format!("wait claude: {err}")))?;
        if !status.success() {
            let tail = String::from_utf8_lossy(&err_tail);
            let tail = tail
                .chars()
                .rev()
                .take(500)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            return Err(AnalyzerError::Runner(format!(
                "claude exited {status}: {tail}"
            )));
        }
        Ok(out)
    }
}

/// The `claude --output-format json` envelope (only the fields we read).
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    subtype: String,
    result: Option<String>,
}

/// The schema-shaped final message.
#[derive(Deserialize)]
struct ClaudeReport {
    outcome: String,
    summary: String,
    #[serde(default)]
    facts: serde_json::Value,
}

fn parse_output(bytes: &[u8]) -> Result<RunOutput> {
    let envelope: Envelope = serde_json::from_slice(bytes)
        .map_err(|err| AnalyzerError::Runner(format!("claude envelope is not JSON: {err}")))?;
    if envelope.is_error {
        return Err(AnalyzerError::Runner(format!(
            "claude reported an error (subtype {})",
            envelope.subtype
        )));
    }
    let text = envelope
        .result
        .ok_or_else(|| AnalyzerError::Runner("claude envelope has no result".to_string()))?;
    let report: ClaudeReport = serde_json::from_str(&text).map_err(|err| {
        AnalyzerError::Runner(format!(
            "claude result does not match the report schema: {err}"
        ))
    })?;
    let outcome = match report.outcome.as_str() {
        "completed" => ReportOutcome::Completed,
        "failed" => ReportOutcome::Failed,
        other => {
            return Err(AnalyzerError::Runner(format!(
                "claude outcome must be completed|failed (got {other:?})"
            )));
        }
    };
    if !report.facts.is_object() {
        return Err(AnalyzerError::Runner(
            "claude facts must be a JSON object".to_string(),
        ));
    }
    // Defensive bound; verdict::assemble enforces the contract limits too.
    let summary: String = report.summary.chars().take(2000).collect();
    Ok(RunOutput {
        outcome,
        summary,
        facts: report.facts,
    })
}

#[async_trait::async_trait]
impl<T: ExecTransport> ToolRunner for ClaudeCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        // Stage the dump on the analysis box (same discipline as the script
        // runner: per-run remote directory under the base).
        let run_id = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let remote_dir: PathBuf = PathBuf::from(&self.remote_base).join(format!("claude-{run_id}"));
        let remote_dir_s = remote_dir.to_string_lossy().replace('\\', "/");
        self.transport
            .exec(
                "mkdir",
                &["-p", &bash_path(&remote_dir_s)],
                None,
                Duration::from_secs(30),
            )
            .await?;
        let remote_dump = format!("{remote_dir_s}/dump.dmp");
        self.transport
            .put_file(&request.dump_path, &remote_dump)
            .await?;
        let out = self
            .run_claude(
                &request.work_dir,
                &remote_dump,
                &request.symbol_path,
                request.bounds,
            )
            .await;
        // Best-effort remote cleanup regardless of the claude outcome.
        let _ = self
            .transport
            .exec(
                "rm",
                &["-rf", &bash_path(&remote_dir_s)],
                None,
                Duration::from_secs(60),
            )
            .await;
        let bytes = out?;
        parse_output(&bytes)
    }
}
