//! Run-scoped Forensicator tools, bridged from Streamable HTTP to native MCP
//! stdio. The reasoner selects queries, never a dump path or executable.
//!
//! A fresh `forensicator mcp` child performs initialization, discovery and one
//! call. Dropping a cancelled exchange kills the child. Both backends share
//! the debugger session's evidence inventory and investigation budget.

use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Take};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Instant, timeout_at};

use crate::analysis_tools::{
    AnalysisTools, CdbSession, MAX_QUERY_OUTPUT_BYTES, QUERY_TIMEOUT, QueryBudget,
};
use crate::report::{CaptureStatus, Evidence, MAX_SECTION_BYTES};
use crate::runner::ExecTransport;
use crate::types::{AnalyzerError, Result, RunRequest};

const PROTOCOLS: [&str; 3] = ["2025-11-25", "2025-06-18", "2024-11-05"];
const TOOLS: [&str; 4] = ["inspect", "analyze", "match", "list_plugins"];

pub struct ForensicatorTools {
    debugger: Arc<dyn AnalysisTools>,
    budget: Arc<QueryBudget>,
    executable: PathBuf,
    dump: PathBuf,
    workspace: PathBuf,
    deadline: Instant,
}

impl ForensicatorTools {
    pub fn new<T: ExecTransport + 'static>(
        debugger: Arc<CdbSession<T>>,
        executable: PathBuf,
        request: &RunRequest,
        deadline: Instant,
    ) -> Self {
        Self {
            budget: debugger.query_budget(),
            debugger,
            executable,
            dump: request.dump_path.clone(),
            workspace: request.work_dir.clone(),
            deadline,
        }
    }

    async fn invoke(
        &self,
        query: Query,
        wire_cap: usize,
    ) -> std::result::Result<ToolResult, McpFailure> {
        if !self.executable.is_absolute() {
            return Err(McpFailure::Spawn);
        }
        let workspace = tokio::fs::canonicalize(&self.workspace)
            .await
            .map_err(|_| McpFailure::Paths)?;
        let mut arguments = json!({});
        if !matches!(query, Query::ListPlugins) {
            let dump = tokio::fs::canonicalize(&self.dump)
                .await
                .map_err(|_| McpFailure::Paths)?;
            arguments["path"] = json!(dump.to_str().ok_or(McpFailure::Paths)?);
        }
        match &query {
            Query::Analyze(args) => {
                arguments["plugins"] = json!(args.plugins);
                if let Some(symbols) = &args.symbols {
                    arguments["symbols"] = json!(relative_path(&workspace, symbols, true).await?);
                }
            }
            Query::Match(args) => {
                for (field, files) in [("exes", &args.exes), ("pdbs", &args.pdbs)] {
                    if !files.is_empty() {
                        let mut paths = Vec::new();
                        for file in files {
                            paths.push(relative_path(&workspace, file, false).await?);
                        }
                        arguments[field] = json!(paths);
                    }
                }
            }
            _ => {}
        }
        // Direct exec with a fixed argument, no shell or inherited credentials.
        let child = Command::new(&self.executable)
            .arg("mcp")
            .current_dir(&workspace)
            .env_clear()
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| McpFailure::Spawn)?;
        let mut child = McpChild(Some(child));
        let process = child.0.as_mut().ok_or(McpFailure::Transport)?;
        let mut client = StdioClient {
            stdin: process.stdin.take().ok_or(McpFailure::Transport)?,
            stdout: BufReader::new(
                process
                    .stdout
                    .take()
                    .ok_or(McpFailure::Transport)?
                    .take(wire_cap as u64),
            ),
            remaining: wire_cap,
        };
        let result = client
            .call(query.name(), arguments)
            .await
            .map(|mut result| {
                // Include any bytes prefetched beyond the final response too.
                result.wire_bytes = wire_cap - client.stdout.get_ref().limit() as usize;
                result
            });
        drop(client);
        // Forensicator normally exits at EOF. Reap even a misbehaving server;
        // the surrounding per-query deadline also bounds this cleanup.
        child.close().await;
        result
    }
}

/// Tokio's kill-on-drop is a last resort; explicitly reap on cancellation too
/// so a quiet runtime does not retain a zombie until its next process spawn.
struct McpChild(Option<Child>);

impl McpChild {
    async fn close(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.start_kill();
            if matches!(
                tokio::time::timeout(Duration::from_secs(1), child.wait()).await,
                Ok(Ok(_))
            ) {
                self.0.take();
            }
        }
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                });
            }
        }
    }
}

#[async_trait]
impl AnalysisTools for ForensicatorTools {
    fn definitions(&self) -> Value {
        let mut definitions = self.debugger.definitions();
        definitions
            .as_array_mut()
            .expect("tool definitions are an array")
            .extend(tool_definitions());
        definitions
    }

    async fn call(&self, name: &str, arguments: Value) -> Result<Evidence> {
        if !name.starts_with("forensicator_") {
            return self.debugger.call(name, arguments).await;
        }
        let _serial = self.budget.serial.lock().await;
        if Instant::now() >= self.deadline {
            return Err(invalid("Forensicator investigation has expired"));
        }
        self.budget.attempt()?;
        let query = Query::parse(name, arguments.clone())?;
        // Reserve the remaining acquisition budget, including protocol
        // envelopes and duplicated text/structuredContent. Refund observed
        // unused bytes only after the full response, never on cancellation.
        let (index, mut evidence, cap) = self.budget.reserve(
            format!(
                "Forensicator MCP {}; {arguments}; dump=current verified dump",
                query.name()
            ),
            MAX_QUERY_OUTPUT_BYTES,
        );
        let deadline = self.deadline.min(Instant::now() + QUERY_TIMEOUT);
        let mut unused_bytes = 0;
        let response = tokio::select! {
            biased;
            _ = self.budget.cancel.notified() => None,
            result = timeout_at(deadline, self.invoke(query, cap)) => Some(result),
        };
        match response {
            None => {}
            Some(Err(_)) => {
                evidence.status = CaptureStatus::TimedOut;
                evidence.error = Some("Forensicator MCP query exceeded its deadline".into());
            }
            Some(Ok(Err(error))) => {
                evidence.truncated = matches!(error, McpFailure::OutputLimit);
                evidence.status = if evidence.truncated {
                    CaptureStatus::Truncated
                } else {
                    CaptureStatus::Failed
                };
                evidence.error = Some(error.message().into());
            }
            Some(Ok(Ok(result))) => {
                evidence.text = result.text;
                unused_bytes = cap.saturating_sub(result.wire_bytes);
                let retained_cap = cap.min(MAX_SECTION_BYTES);
                evidence.truncated = evidence.text.len() > retained_cap;
                let mut end = retained_cap.min(evidence.text.len());
                while !evidence.text.is_char_boundary(end) {
                    end -= 1;
                }
                evidence.text.truncate(end);
                (evidence.status, evidence.error) = if result.is_error {
                    (
                        CaptureStatus::Failed,
                        Some("Forensicator reported a tool error".into()),
                    )
                } else if evidence.truncated {
                    (
                        CaptureStatus::Truncated,
                        Some("Forensicator evidence exceeded the retained-output limit".into()),
                    )
                } else {
                    (CaptureStatus::Present, None)
                };
            }
        }
        self.budget.finish(index, evidence.clone(), unused_bytes);
        Ok(evidence)
    }

    async fn evidence(&self) -> Vec<Evidence> {
        self.budget.evidence()
    }
}

fn tool_definitions() -> Vec<Value> {
    let file = json!({"type":"string", "minLength":1, "maxLength":256,
        "description":"Existing path relative to this run's workspace; absolute paths and traversal are forbidden"});
    let files = json!({"type":"array", "maxItems":16, "items":file});
    [
        ("inspect", "Inspect the current verified minidump with Forensicator: modules, system, annotations and crash diagnosis.", json!({}), vec![]),
        ("analyze", "Run selected Forensicator analyzers on the current dump. Discover names with forensicator_list_plugins. Confidence and unknown results are evidence, not a confirmed root cause. Large analyses may exceed the shared deadline.",
            json!({"plugins":{"type":"array", "minItems":1, "maxItems":8, "items":{"type":"string", "minLength":1, "maxLength":64}}, "symbols":file}), vec!["plugins"]),
        ("match", "Compare this dump's module identities with PE/PDB files already staged in this run's workspace. Requires at least one artifact. Mismatch and unknown are successful forensic results; this does not upgrade the host's symbol status.",
            json!({"exes":files,"pdbs":files}), vec![]),
        ("list_plugins", "List Forensicator analyzer names and descriptions before selecting a focused analysis.", json!({}), vec![]),
    ].into_iter().map(|(name, description, properties, required)| json!({
        "name":format!("forensicator_{name}"),"description":description,
        "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}
    })).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Analyze {
    plugins: Vec<String>,
    symbols: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Match {
    #[serde(default)]
    exes: Vec<String>,
    #[serde(default)]
    pdbs: Vec<String>,
}

enum Query {
    Inspect,
    Analyze(Analyze),
    Match(Match),
    ListPlugins,
}

fn invalid(message: &str) -> AnalyzerError {
    AnalyzerError::Runner(message.into())
}

fn decode<T: serde::de::DeserializeOwned>(args: Value) -> Result<T> {
    if !args.is_object() {
        return Err(invalid("Invalid Forensicator arguments"));
    }
    serde_json::from_value(args).map_err(|_| invalid("Invalid Forensicator arguments"))
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

impl Query {
    fn name(&self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Analyze(_) => "analyze",
            Self::Match(_) => "match",
            Self::ListPlugins => "list_plugins",
        }
    }

    fn parse(name: &str, args: Value) -> Result<Self> {
        match name {
            "forensicator_inspect" | "forensicator_list_plugins" => {
                let _: Empty = decode(args)?;
                Ok(if name.ends_with("inspect") {
                    Self::Inspect
                } else {
                    Self::ListPlugins
                })
            }
            "forensicator_analyze" => {
                let args: Analyze = decode(args)?;
                if args.plugins.is_empty()
                    || args.plugins.len() > 8
                    || args.plugins.iter().any(|name| {
                        name.is_empty()
                            || name.len() > 64
                            || !name
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    })
                    || args
                        .symbols
                        .as_deref()
                        .is_some_and(|path| !valid_relative_path(path))
                {
                    return Err(invalid(
                        "Select one to eight Forensicator plugins and workspace-relative symbols",
                    ));
                }
                Ok(Self::Analyze(args))
            }
            "forensicator_match" => {
                let args: Match = decode(args)?;
                if !(1..=16).contains(&(args.exes.len() + args.pdbs.len()))
                    || args
                        .exes
                        .iter()
                        .chain(&args.pdbs)
                        .any(|path| !valid_relative_path(path))
                {
                    return Err(invalid(
                        "Select one to sixteen workspace-relative Forensicator artifacts",
                    ));
                }
                Ok(Self::Match(args))
            }
            _ => Err(invalid("Unknown Forensicator tool")),
        }
    }
}

async fn relative_path(
    root: &Path,
    path: &str,
    directory: bool,
) -> std::result::Result<String, McpFailure> {
    let resolved = tokio::fs::canonicalize(root.join(path))
        .await
        .map_err(|_| McpFailure::Paths)?;
    let metadata = tokio::fs::metadata(&resolved)
        .await
        .map_err(|_| McpFailure::Paths)?;
    if !resolved.starts_with(root)
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(McpFailure::Paths);
    }
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or(McpFailure::Paths)
}

enum McpFailure {
    Paths,
    Spawn,
    Transport,
    Protocol,
    OutputLimit,
}

impl McpFailure {
    fn message(&self) -> &'static str {
        match self {
            Self::Paths => "Forensicator input is unavailable or outside the run workspace",
            Self::Spawn => "Forensicator MCP executable could not be started",
            Self::Transport => "Forensicator MCP transport failed",
            Self::Protocol => "Forensicator MCP initialization, discovery or response was invalid",
            Self::OutputLimit => "Forensicator MCP response exceeded the bounded wire-output limit",
        }
    }
}

struct ToolResult {
    text: String,
    is_error: bool,
    wire_bytes: usize,
}

struct StdioClient {
    stdin: ChildStdin,
    stdout: BufReader<Take<ChildStdout>>,
    remaining: usize,
}

impl StdioClient {
    async fn send(&mut self, message: Value) -> std::result::Result<(), McpFailure> {
        let mut bytes = serde_json::to_vec(&message).map_err(|_| McpFailure::Protocol)?;
        bytes.push(b'\n');
        self.stdin
            .write_all(&bytes)
            .await
            .map_err(|_| McpFailure::Transport)?;
        self.stdin.flush().await.map_err(|_| McpFailure::Transport)
    }

    async fn rpc(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
    ) -> std::result::Result<Value, McpFailure> {
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .await?;
        let mut frame = Vec::new();
        loop {
            if self.remaining == 0 {
                return Err(McpFailure::OutputLimit);
            }
            let buffer = self
                .stdout
                .fill_buf()
                .await
                .map_err(|_| McpFailure::Transport)?;
            if buffer.is_empty() {
                return Err(McpFailure::Transport);
            }
            let end = buffer.iter().position(|byte| *byte == b'\n');
            let count = end.map_or(buffer.len(), |end| end + 1);
            if count > self.remaining {
                return Err(McpFailure::OutputLimit);
            }
            self.remaining -= count;
            frame.extend_from_slice(&buffer[..count]);
            self.stdout.consume(count);
            if end.is_some() {
                break;
            }
        }
        let response: Value = serde_json::from_slice(&frame).map_err(|_| McpFailure::Protocol)?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || response.get("id") != Some(&json!(id))
            || response.get("error").is_some()
            || response.get("method").is_some()
        {
            return Err(McpFailure::Protocol);
        }
        response
            .get("result")
            .cloned()
            .filter(Value::is_object)
            .ok_or(McpFailure::Protocol)
    }

    async fn call(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> std::result::Result<ToolResult, McpFailure> {
        let init = self
            .rpc(
                1,
                "initialize",
                json!({
                    "protocolVersion":PROTOCOLS[0], "capabilities":{},
                    "clientInfo":{"name":"dump-analyzer", "version":env!("CARGO_PKG_VERSION")}
                }),
            )
            .await?;
        if !init
            .get("protocolVersion")
            .and_then(Value::as_str)
            .is_some_and(|v| PROTOCOLS.contains(&v))
            || !init
                .pointer("/capabilities/tools")
                .is_some_and(Value::is_object)
        {
            return Err(McpFailure::Protocol);
        }
        self.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized", "params":{}}))
            .await?;
        let list = self.rpc(2, "tools/list", json!({})).await?;
        if list.get("nextCursor").is_some_and(|v| !v.is_null())
            || !list
                .get("tools")
                .and_then(Value::as_array)
                .is_some_and(|tools| {
                    TOOLS
                        .iter()
                        .all(|name| tools.iter().any(|tool| tool["name"].as_str() == Some(name)))
                })
        {
            return Err(McpFailure::Protocol);
        }
        let result = self
            .rpc(3, "tools/call", json!({"name":name,"arguments":arguments}))
            .await?;
        let is_error = match result.get("isError") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err(McpFailure::Protocol),
        };
        let text = if !is_error
            && result
                .get("structuredContent")
                .is_some_and(Value::is_object)
        {
            serde_json::to_string(&result["structuredContent"]).map_err(|_| McpFailure::Protocol)?
        } else {
            let blocks = result
                .get("content")
                .and_then(Value::as_array)
                .ok_or(McpFailure::Protocol)?;
            let texts: Option<Vec<&str>> = blocks
                .iter()
                .map(|block| {
                    (block["type"] == "text")
                        .then(|| block["text"].as_str())
                        .flatten()
                })
                .collect();
            let text = texts.ok_or(McpFailure::Protocol)?.join("\n");
            if text.is_empty() {
                return Err(McpFailure::Protocol);
            }
            if !is_error
                && !serde_json::from_str::<Value>(&text).is_ok_and(|value| value.is_object())
            {
                return Err(McpFailure::Protocol);
            }
            text
        };
        Ok(ToolResult {
            text,
            is_error,
            wire_bytes: 0,
        })
    }
}
