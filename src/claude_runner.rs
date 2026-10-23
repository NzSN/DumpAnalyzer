//! Deterministic CDB evidence followed by an optional evidence-only reasoner.
//! The persistent duplex NDJSON host denies every tool request. Reasoning
//! failure preserves the owned debugger evidence and deterministic assessment.
//!
//! The shared prompt/schema/validation contract lives in [`crate::reason`].

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};
use tokio::time::Instant;

use crate::reason::{FORMAT_CORRECTION_PROMPT, adopt_assessment, apply_outcome, runner_error};
use crate::report::{ReportCapture, RootCause};
use crate::runner::{ExecTransport, SshCdbRunner};
use crate::types::{Result, RunOutput, RunRequest, ToolRunner};

pub struct ClaudeCdbRunner<T: ExecTransport> {
    collector: SshCdbRunner<T>,
    claude_bin: String,
    model: Option<String>,
}

impl<T: ExecTransport> ClaudeCdbRunner<T> {
    /// The supplied transport owns the SSH target; keep the argument for
    /// configuration compatibility with the previous provider constructor.
    pub fn new(
        transport: T,
        _ssh_target: impl Into<String>,
        claude_bin: impl Into<String>,
    ) -> Self {
        Self {
            collector: SshCdbRunner::new(transport),
            claude_bin: claude_bin.into(),
            model: None,
        }
    }
    pub fn with_remote_base(mut self, base: impl Into<String>) -> Self {
        self.collector = self.collector.with_remote_base(base);
        self
    }
    pub fn with_model(mut self, model: Option<String>) -> Self {
        self.model = model;
        self
    }

    async fn reason(
        &self,
        work_dir: &Path,
        capture: &ReportCapture,
        deadline: Instant,
        cap: usize,
        observed_model: &mut Option<String>,
    ) -> Result<RootCause> {
        let prompt = crate::reason::assessment_prompt(capture)?;
        let isolated = tempfile::Builder::new()
            .prefix("reasoner-")
            .tempdir_in(work_dir)
            .map_err(|err| runner_error(format!("create reasoner workspace: {err}")))?;
        let mut command = Command::new(&self.claude_bin);
        command.args([
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-prompt-tool",
            "stdio",
            "--permission-mode",
            "default",
            "--tools",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--settings",
            "{\"disableAllHooks\":true}",
            "--setting-sources",
            "",
            "--no-session-persistence",
        ]);
        if let Some(model) = &self.model {
            command.args(["--model", model]);
        }
        let mut child = command
            .current_dir(isolated.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| runner_error(format!("spawn {}: {err}", self.claude_bin)))?;
        let mut input = child.stdin.take().expect("piped stdin");
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let mut state = HostState::default();
        let exchange = async {
            write_message(&mut input, &json!({"type":"user","message":{"role":"user","content":[{"type":"text","text":prompt}]}})).await?;
            let mut out_chunk = [0_u8; 8192];
            let mut err_chunk = [0_u8; 8192];
            let mut stdout_closed = false;
            let mut stderr_closed = false;
            loop {
                if stdout_closed && stderr_closed {
                    // The encompassing deadline covers EOF followed by a child
                    // that remains alive; never wait without that deadline.
                    let status = child
                        .wait()
                        .await
                        .map_err(|err| runner_error(format!("wait reasoner: {err}")))?;
                    return Err(runner_error(format!(
                        "reasoner exited {status} before a result; {}",
                        state.stderr_tail
                    )));
                }
                tokio::select! {
                    read = stdout.read(&mut out_chunk), if !stdout_closed => {
                        let n = read.map_err(|err| runner_error(format!("read reasoner stdout: {err}")))?;
                        if n == 0 {
                            stdout_closed = true;
                            if !state.line.is_empty() {
                                let line = std::mem::take(&mut state.line);
                                if let Some(cause) = state.event(&line, &mut input).await? { return Ok(cause); }
                            }
                        } else {
                            state.charge(n, cap)?;
                            for byte in &out_chunk[..n] {
                                if *byte == b'\n' {
                                    let line = std::mem::take(&mut state.line);
                                    if !line.is_empty() {
                                        if let Some(cause) = state.event(&line, &mut input).await? { return Ok(cause); }
                                    }
                                } else { state.line.push(*byte); }
                            }
                        }
                    }
                    read = stderr.read(&mut err_chunk), if !stderr_closed => {
                        let n = read.map_err(|err| runner_error(format!("read reasoner stderr: {err}")))?;
                        if n == 0 { stderr_closed = true; }
                        else {
                            state.charge(n, cap)?;
                            state.stderr_tail.push_str(&String::from_utf8_lossy(&err_chunk[..n]));
                            state.stderr_tail = state.stderr_tail.chars().rev().take(500).collect::<String>().chars().rev().collect();
                        }
                    }
                }
            }
        };
        let result = tokio::time::timeout_at(deadline, exchange)
            .await
            .unwrap_or_else(|_| Err(runner_error("reasoner exceeded shared run wall timeout")));
        // Persistent stdin stays open until the result. End this private host
        // session explicitly, since a successful turn does not exit Claude.
        drop(input);
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_millis(250), child.wait()).await;
        // Provenance survives malformed output, EOF, and a reasoning timeout,
        // just as the deterministic evidence survives those optional failures.
        *observed_model = state.model;
        result
    }
}

#[derive(Default)]
struct HostState {
    bytes: usize,
    line: Vec<u8>,
    stderr_tail: String,
    model: Option<String>,
    formatting_correction_requested: bool,
}

impl HostState {
    fn charge(&mut self, bytes: usize, cap: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > cap {
            return Err(runner_error(
                "reasoner exceeded bounded stdout/stderr budget",
            ));
        }
        Ok(())
    }
    async fn event(&mut self, line: &[u8], input: &mut ChildStdin) -> Result<Option<RootCause>> {
        let event: Value = serde_json::from_slice(line).map_err(|err| {
            runner_error(format!("reasoner emitted malformed stream JSON: {err}"))
        })?;
        match event.get("type").and_then(Value::as_str) {
            Some("system") if event.get("subtype").and_then(Value::as_str) == Some("init") => {
                if let Some(model) = event.get("model").and_then(Value::as_str).filter(|model| {
                    !model.is_empty() && model.len() <= 256 && !model.chars().any(char::is_control)
                }) {
                    self.model = Some(model.to_owned());
                }
                Ok(None)
            }
            Some("control_request") => {
                let id = event
                    .get("request_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or_else(|| runner_error("invalid reasoner control request_id"))?;
                write_message(input, &json!({"type":"control_response","response":{
                    "subtype":"success","request_id":id,"response":{
                        "behavior":"deny","message":"Evidence-only assessment denies all tools and external probes"}}})).await?;
                Ok(None)
            }
            Some("result") => {
                if event.get("is_error").and_then(Value::as_bool) == Some(true) {
                    return Err(runner_error(result_error_diagnostic(&event)));
                }
                match decode_assessment(&event) {
                    Ok(cause) => Ok(Some(cause)),
                    Err(_) if !self.formatting_correction_requested => {
                        // Correct only the inner response format once. This
                        // remains inside the original deadline and cumulative
                        // output budget; no rejected model text is echoed.
                        self.formatting_correction_requested = true;
                        write_message(input, &json!({"type":"user","message":{"role":"user","content":[{"type":"text","text":FORMAT_CORRECTION_PROMPT}]}})).await?;
                        Ok(None)
                    }
                    Err(err) => Err(err),
                }
            }
            Some("user")
                if event
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|part| {
                            part.get("type").and_then(Value::as_str) == Some("tool_result")
                        })
                    }) =>
            {
                Err(runner_error(
                    "unexpected tool result under deny-all assessment policy",
                ))
            }
            Some(
                "system" | "assistant" | "user" | "stream_event" | "rate_limit_event"
                | "control_response",
            ) => Ok(None),
            _ => Err(runner_error("unknown reasoner stream event type")),
        }
    }
}

fn decode_assessment(event: &Value) -> Result<RootCause> {
    let payload = if let Some(value) = event.get("structured_output") {
        value.clone()
    } else {
        serde_json::from_str(
            event
                .get("result")
                .and_then(Value::as_str)
                .ok_or_else(|| runner_error("reasoner result has no structured assessment"))?,
        )
        .map_err(|err| runner_error(format!("reasoner assessment is not JSON: {err}")))?
    };
    crate::reason::decode_root_cause(payload)
}

/// Keep actionable provider failures without retaining an unbounded event or
/// printing its transcript, usage, session credentials, or other metadata.
fn result_error_diagnostic(event: &Value) -> String {
    fn bounded(value: Option<&str>, limit: usize) -> String {
        value
            .unwrap_or("unavailable")
            .chars()
            .take(limit)
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect()
    }
    let subtype = bounded(event.get("subtype").and_then(Value::as_str), 80);
    let errors = event
        .get("errors")
        .and_then(Value::as_array)
        .map(|errors| {
            errors
                .iter()
                .take(2)
                .map(|error| bounded(error.as_str(), 120))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_else(|| "unavailable".into());
    let result = bounded(event.get("result").and_then(Value::as_str), 120);
    format!("reasoner error result: subtype={subtype}; errors={errors}; result={result}")
}

async fn write_message(input: &mut ChildStdin, message: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(|err| runner_error(err.to_string()))?;
    bytes.push(b'\n');
    input
        .write_all(&bytes)
        .await
        .map_err(|err| runner_error(format!("write reasoner host message: {err}")))?;
    input
        .flush()
        .await
        .map_err(|err| runner_error(format!("flush reasoner host message: {err}")))
}
#[async_trait::async_trait]
impl<T: ExecTransport> ToolRunner for ClaudeCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        let deadline = Instant::now() + request.bounds.wall_timeout;
        let mut collection = request.clone();
        // Reserve part of the shared budget for collector cleanup and optional
        // reasoning, rather than granting a second full run timeout.
        collection.bounds.wall_timeout = request.bounds.wall_timeout.mul_f64(0.8);
        let mut output = tokio::time::timeout_at(deadline, self.collector.run(collection))
            .await
            .map_err(|_| {
                runner_error("deterministic collection exceeded shared run wall timeout")
            })??;
        let capture = output.capture.get_or_insert_with(ReportCapture::default);
        capture.provenance.provider = "claude-cdb".into();
        capture.provenance.model = self.model.clone();
        if !capture.provenance.analysis_revision.is_empty() {
            capture.provenance.analysis_revision.push(';');
        }
        capture
            .provenance
            .analysis_revision
            .push_str("reasoner=claude-host-v2.3");
        let mut observed_model = None;
        let assessment = self
            .reason(
                &request.work_dir,
                capture,
                deadline,
                request.bounds.max_output_bytes,
                &mut observed_model,
            )
            .await;
        if let Some(actual_model) = observed_model {
            capture.provenance.model = Some(actual_model);
        }
        let assessment = assessment.and_then(|cause| adopt_assessment(capture, cause));
        apply_outcome(
            capture,
            assessment,
            "bounded evidence-only Claude host assessment (all tools denied)",
        )?;
        Ok(output)
    }
}
