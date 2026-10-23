//! Read-only, typed debugger investigations on one retained verified dump.
//!
//! Addresses use hexadecimal strings to preserve all 64 bits through MCP/JS.
//! Thread IDs are CDB's decimal thread indexes, not operating-system TIDs.
//! Queries never accept debugger expressions, commands, paths, or extensions.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, Notify};

use crate::report::{CaptureStatus, Evidence, MAX_EVIDENCE, MAX_SECTION_BYTES, ReportCapture};
use crate::runner::{ExecTransport, bash_path};
use crate::types::{AnalyzerError, Result};

pub const MAX_QUERY_CALLS: usize = 8;
pub const MAX_QUERY_OUTPUT_BYTES: usize = 64 * 1024;
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
pub trait AnalysisTools: Send + Sync {
    /// Only capabilities actually configured for this run are advertised.
    fn definitions(&self) -> Value {
        tool_definitions()
    }
    /// Execute and retain an accepted query before exposing its result.
    async fn call(&self, name: &str, arguments: Value) -> Result<Evidence>;
    /// Snapshot only the additional evidence; baseline entries are unchanged.
    async fn evidence(&self) -> Vec<Evidence>;
}

pub fn tool_definitions() -> Value {
    let thread = json!({"type":"integer","minimum":0,"maximum":65535,
        "description":"CDB decimal thread index shown in target evidence or list_threads; not the OS TID"});
    let address = json!({"type":"string","pattern":"^0x[0-9a-fA-F]{1,16}$",
        "description":"Literal 64-bit virtual address in hexadecimal; expressions are forbidden"});
    let definitions = [
        (
            "list_threads",
            "List threads in this dump, including their CDB indexes.",
            json!({}),
            vec![],
        ),
        (
            "get_stack",
            "Read the selected thread's stack (initial saved thread context; baseline exception context remains separate).",
            json!({"thread_id":thread,"frames":{"type":"integer","minimum":1,"maximum":64,"default":32}}),
            vec!["thread_id"],
        ),
        (
            "get_registers",
            "Read the selected thread's initial saved registers; use baseline evidence for the exception context.",
            json!({"thread_id":thread}),
            vec!["thread_id"],
        ),
        (
            "read_memory",
            "Read at most 256 bytes of virtual memory available in this dump.",
            json!({"address":address,"length":{"type":"integer","minimum":1,"maximum":256}}),
            vec!["address", "length"],
        ),
        (
            "disassemble",
            "Disassemble at most 64 instructions from a literal address in this dump.",
            json!({"address":address,"count":{"type":"integer","minimum":1,"maximum":64}}),
            vec!["address", "count"],
        ),
        (
            "get_module_symbols",
            "Read symbol details for an exact module name in baseline symbol evidence. Debugger labels do not establish PDB identity.",
            json!({"module_id":{"type":"string","minLength":1,"maxLength":256}}),
            vec!["module_id"],
        ),
    ];
    Value::Array(definitions.into_iter().map(|(name, description, properties, required)| json!({
        "name":name,"description":description,
        "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}
    })).collect())
}

#[derive(Default)]
struct SessionState {
    threads: BTreeSet<u16>,
    modules: BTreeMap<String, u64>,
}

#[derive(Default)]
struct BudgetState {
    evidence: Vec<Evidence>,
    attempts: usize,
    available_slots: usize,
    output_remaining: usize,
}

/// Shared by debugger and Forensicator queries: adding a backend must not
/// multiply the run's call, retained-output, or evidence-slot allowance.
pub(crate) struct QueryBudget {
    state: Mutex<BudgetState>,
    pub(crate) serial: AsyncMutex<()>,
    pub(crate) cancel: Notify,
    closed: AtomicBool,
}

impl QueryBudget {
    fn new(output_budget: usize) -> Self {
        Self {
            state: Mutex::new(BudgetState {
                output_remaining: output_budget,
                ..Default::default()
            }),
            serial: AsyncMutex::new(()),
            cancel: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn initialize(&self, capture: &ReportCapture) {
        self.state.lock().expect("query budget").available_slots = MAX_EVIDENCE
            .saturating_sub(capture.evidence.len() + 1)
            .min(MAX_QUERY_CALLS);
    }

    /// Invalid arguments consume an attempt too. Call while holding serial.
    pub(crate) fn attempt(&self) -> Result<()> {
        let mut state = self.state.lock().expect("query budget");
        if self.closed.load(Ordering::Acquire)
            || state.attempts >= MAX_QUERY_CALLS
            || state.evidence.len() >= state.available_slots
            || state.output_remaining == 0
        {
            return Err(AnalyzerError::Runner(
                "Investigation budget exhausted".into(),
            ));
        }
        state.attempts += 1;
        Ok(())
    }

    /// Reserve before awaiting so cancellation retains a failed receipt.
    pub(crate) fn reserve(&self, command: String, max_bytes: usize) -> (usize, Evidence, usize) {
        let mut state = self.state.lock().expect("query budget");
        let index = state.evidence.len();
        let output_cap = state.output_remaining.min(max_bytes);
        state.output_remaining -= output_cap;
        let evidence = Evidence {
            id: format!("query-{}", index + 1),
            command,
            status: CaptureStatus::Failed,
            error: Some("Analysis query cancelled before completion".into()),
            ..Evidence::default()
        };
        state.evidence.push(evidence.clone());
        (index, evidence, output_cap)
    }

    pub(crate) fn finish(&self, index: usize, evidence: Evidence, unused_bytes: usize) {
        let mut state = self.state.lock().expect("query budget");
        state.output_remaining += unused_bytes;
        state.evidence[index] = evidence;
    }

    pub(crate) fn evidence(&self) -> Vec<Evidence> {
        self.state.lock().expect("query budget").evidence.clone()
    }
}

/// One dump's capability; the transport and pinned path are never model input.
pub struct CdbSession<T: ExecTransport + 'static> {
    transport: Arc<T>,
    remote_dir: String,
    remote_dump: String,
    cdb_program: String,
    symbol_path: String,
    deadline: tokio::time::Instant,
    state: Mutex<SessionState>,
    budget: Arc<QueryBudget>,
    cleaned: AtomicBool,
}

impl<T: ExecTransport + 'static> CdbSession<T> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transport: Arc<T>,
        remote_dir: String,
        remote_dump: String,
        cdb_program: String,
        symbol_path: String,
        deadline: tokio::time::Instant,
        output_budget: usize,
    ) -> Self {
        Self {
            transport,
            remote_dir,
            remote_dump,
            cdb_program,
            symbol_path,
            deadline,
            state: Mutex::new(SessionState::default()),
            budget: Arc::new(QueryBudget::new(output_budget)),
            cleaned: AtomicBool::new(false),
        }
    }

    pub(crate) fn initialize(&self, capture: Option<&ReportCapture>) {
        let mut state = self.state.lock().expect("session state");
        if let Some(capture) = capture {
            self.budget.initialize(capture);
            for evidence in &capture.evidence {
                if matches!(
                    evidence.id.as_str(),
                    "target" | "context" | "legacy-transcript"
                ) {
                    state.threads.extend(thread_indexes(&evidence.text));
                }
            }
            for module in &capture.symbols.modules {
                if let Some(base) = module.image_base.as_deref().and_then(parse_address) {
                    state.modules.insert(module.module.clone(), base);
                }
            }
        }
    }

    pub(crate) fn query_budget(&self) -> Arc<QueryBudget> {
        Arc::clone(&self.budget)
    }

    /// Revoke immediately, cancel the active query, and remove remote artifacts.
    /// Idempotent; dropping a cancelled close future retries cleanup via Drop.
    pub async fn close(&self) {
        self.budget.closed.store(true, Ordering::Release);
        self.budget.cancel.notify_one();
        let _serial = self.budget.serial.lock().await;
        if !self.cleaned.load(Ordering::Acquire) {
            cleanup(Arc::clone(&self.transport), self.remote_dir.clone()).await;
            self.cleaned.store(true, Ordering::Release);
        }
    }
}

impl<T: ExecTransport + 'static> Drop for CdbSession<T> {
    fn drop(&mut self) {
        if !self.cleaned.load(Ordering::Acquire) {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(cleanup(
                    Arc::clone(&self.transport),
                    self.remote_dir.clone(),
                ));
            } else {
                tracing::warn!("CDB session dropped without a runtime; remote cleanup unavailable");
            }
        }
    }
}

async fn cleanup<T: ExecTransport>(transport: Arc<T>, remote_dir: String) {
    let remote = bash_path(&remote_dir);
    let result = tokio::time::timeout(
        CLEANUP_TIMEOUT,
        transport.exec("rm", &["-rf", &remote], None, CLEANUP_TIMEOUT),
    )
    .await;
    if !matches!(result, Ok(Ok(ref output)) if output.success()) {
        tracing::warn!("CDB investigation workspace cleanup failed or timed out");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Thread {
    thread_id: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stack {
    thread_id: u16,
    #[serde(default = "default_frames")]
    frames: u8,
}
fn default_frames() -> u8 {
    32
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Memory {
    address: String,
    length: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disassemble {
    address: String,
    count: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Module {
    module_id: String,
}

enum Query {
    Threads,
    Stack(Stack),
    Registers(Thread),
    Memory { address: u64, length: u16 },
    Disassemble { address: u64, count: u8 },
    Module(Module),
}

fn invalid() -> AnalyzerError {
    AnalyzerError::Runner("Unknown debugger tool or invalid arguments".into())
}
fn parse_address(address: &str) -> Option<u64> {
    let hex = address.strip_prefix("0x")?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}
fn decode<T: serde::de::DeserializeOwned>(args: Value) -> Result<T> {
    if !args.is_object() {
        return Err(invalid());
    }
    serde_json::from_value(args).map_err(|_| invalid())
}
impl Query {
    fn parse(name: &str, args: Value) -> Result<Self> {
        Ok(match name {
            "list_threads" => {
                let _: Empty = decode(args)?;
                Self::Threads
            }
            "get_stack" => {
                let args: Stack = decode(args)?;
                if !(1..=64).contains(&args.frames) {
                    return Err(invalid());
                }
                Self::Stack(args)
            }
            "get_registers" => Self::Registers(decode(args)?),
            "read_memory" => {
                let args: Memory = decode(args)?;
                let address = parse_address(&args.address).ok_or_else(invalid)?;
                if !(1..=256).contains(&args.length)
                    || address.checked_add(u64::from(args.length) - 1).is_none()
                {
                    return Err(invalid());
                }
                Self::Memory {
                    address,
                    length: args.length,
                }
            }
            "disassemble" => {
                let args: Disassemble = decode(args)?;
                let address = parse_address(&args.address).ok_or_else(invalid)?;
                if !(1..=64).contains(&args.count)
                    || address
                        .checked_add(u64::from(args.count) * 15 - 1)
                        .is_none()
                {
                    return Err(invalid());
                }
                Self::Disassemble {
                    address,
                    count: args.count,
                }
            }
            "get_module_symbols" => {
                let args: Module = decode(args)?;
                if args.module_id.is_empty() || args.module_id.len() > 256 {
                    return Err(invalid());
                }
                Self::Module(args)
            }
            _ => return Err(invalid()),
        })
    }
    fn command(&self, state: &SessionState) -> Result<(String, Value)> {
        let check_thread = |index: u16| {
            if state.threads.contains(&index) {
                Ok(())
            } else {
                Err(AnalyzerError::Runner(
                    "Thread index was not observed in this dump; call list_threads first".into(),
                ))
            }
        };
        Ok(match self {
            Self::Threads => ("~".into(), json!({})),
            Self::Stack(args) => {
                check_thread(args.thread_id)?;
                (
                    format!("~{}s; kn 0n{}", args.thread_id, args.frames),
                    json!({"thread_id":args.thread_id,"frames":args.frames}),
                )
            }
            Self::Registers(args) => {
                check_thread(args.thread_id)?;
                (
                    format!("~{}s; r", args.thread_id),
                    json!({"thread_id":args.thread_id}),
                )
            }
            Self::Memory { address, length } => (
                format!("db 0x{address:x} L0n{length}"),
                json!({"address":format!("0x{address:x}"),"length":length}),
            ),
            Self::Disassemble { address, count } => (
                format!("u 0x{address:x} L0n{count}"),
                json!({"address":format!("0x{address:x}"),"count":count}),
            ),
            Self::Module(args) => {
                let base = state.modules.get(&args.module_id).ok_or_else(|| {
                    AnalyzerError::Runner(
                        "Module identity was not observed in baseline evidence".into(),
                    )
                })?;
                (
                    format!("lmv a 0x{base:x}"),
                    json!({"module_id":args.module_id}),
                )
            }
        })
    }
}

#[async_trait]
impl<T: ExecTransport + 'static> AnalysisTools for CdbSession<T> {
    async fn call(&self, name: &str, arguments: Value) -> Result<Evidence> {
        let _serial = self.budget.serial.lock().await;
        if tokio::time::Instant::now() >= self.deadline {
            return Err(AnalyzerError::Runner(
                "Debugger investigation is closed or expired".into(),
            ));
        }
        self.budget.attempt()?;
        let query = Query::parse(name, arguments)?;
        let (command, normalized) = query.command(&self.state.lock().expect("session state"))?;
        let (index, mut evidence, output_cap) = self.budget.reserve(
            format!("{name} {normalized}; CDB: {command}"),
            MAX_SECTION_BYTES,
        );
        let id = &evidence.id;
        let script = format!(
            ".sympath {}\n.echo DA_QUERY_BEGIN:{id}\n{command}\n.echo DA_QUERY_END:{id}\nq\n",
            self.symbol_path
        );
        let query_deadline = self
            .deadline
            .min(tokio::time::Instant::now() + QUERY_TIMEOUT);
        let timeout = query_deadline.saturating_duration_since(tokio::time::Instant::now());
        let args = ["-z", &self.remote_dump, "-y", &self.remote_dir];
        let execution = tokio::time::timeout_at(
            query_deadline,
            self.transport.exec_bounded(
                &self.cdb_program,
                &args,
                Some(script.as_bytes()),
                timeout,
                output_cap,
            ),
        );
        let response = tokio::select! {
            biased;
            _ = self.budget.cancel.notified() => None,
            result = execution => Some(result),
        };
        let mut unused_bytes = 0;
        match response {
            None => {}
            Some(Err(_)) => {
                evidence.status = CaptureStatus::TimedOut;
                evidence.error = Some("Debugger query exceeded its deadline".into());
            }
            Some(Ok(Err(_))) => {
                evidence.error = Some("Debugger query transport failed".into());
            }
            Some(Ok(Ok(output))) => {
                let actual = output.stdout.len().saturating_add(output.stderr.len());
                unused_bytes = output_cap.saturating_sub(actual);
                let mut bytes = output.stdout;
                bytes.truncate(output_cap);
                let remaining = output_cap - bytes.len();
                bytes.extend(output.stderr.into_iter().take(remaining));
                let raw = String::from_utf8_lossy(&bytes);
                let begin = format!("DA_QUERY_BEGIN:{id}");
                let end = format!("DA_QUERY_END:{id}");
                let mut inside = false;
                let mut ended = false;
                let mut lines = Vec::new();
                for line in raw.lines() {
                    if line.trim() == begin {
                        inside = true;
                    } else if line.trim() == end {
                        ended = true;
                        break;
                    } else if inside {
                        lines.push(line);
                    }
                }
                evidence.text = lines.join("\n");
                let capped = actual >= output_cap || evidence.text.len() > MAX_SECTION_BYTES;
                truncate_utf8(&mut evidence.text, MAX_SECTION_BYTES);
                evidence.truncated = capped || !ended;
                let lower = evidence.text.to_ascii_lowercase();
                let failed = output.status != Some(0)
                    || lower.contains("unable to")
                    || lower.contains("could not")
                    || lower.contains("memory access error")
                    || lower.contains("syntax error")
                    || lower.contains("invalid thread")
                    || lower.contains("??");
                if capped || !ended {
                    evidence.status = CaptureStatus::Truncated;
                    evidence.error =
                        Some("Debugger output limit reached or query end marker missing".into());
                } else if failed {
                    evidence.status = CaptureStatus::Failed;
                    evidence.error =
                        Some("Debugger could not acquire the requested evidence".into());
                } else if evidence.text.trim().is_empty() {
                    evidence.status = CaptureStatus::Absent;
                    evidence.error = Some("Debugger returned no requested evidence".into());
                } else {
                    evidence.status = CaptureStatus::Present;
                    evidence.error = None;
                }
                if matches!(query, Query::Threads) {
                    self.state
                        .lock()
                        .expect("session state")
                        .threads
                        .extend(thread_indexes(&evidence.text));
                }
            }
        }
        self.budget.finish(index, evidence.clone(), unused_bytes);
        Ok(evidence)
    }

    async fn evidence(&self) -> Vec<Evidence> {
        self.budget.evidence()
    }
}

fn thread_indexes(text: &str) -> BTreeSet<u16> {
    text.lines()
        .filter_map(|line| {
            let (index, _) = line.split_once("Id:").or_else(|| line.split_once("id:"))?;
            let index = index.trim().trim_start_matches(['.', '#']).trim();
            if index.bytes().all(|b| b.is_ascii_digit()) {
                index.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

fn truncate_utf8(text: &mut String, limit: usize) {
    let mut end = limit.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::TransportOutput;
    use std::path::Path;

    struct NeverExecute;
    #[async_trait]
    impl ExecTransport for NeverExecute {
        async fn exec(
            &self,
            _: &str,
            _: &[&str],
            _: Option<&[u8]>,
            _: Duration,
        ) -> Result<TransportOutput> {
            panic!("exhausted report evidence budget must not execute a query")
        }
        async fn put_file(&self, _: &Path, _: &str) -> Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn reserves_one_report_slot_for_model_assessment() {
        let session = CdbSession::new(
            Arc::new(NeverExecute),
            "unused".into(),
            "unused".into(),
            "unused".into(),
            "unused".into(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            MAX_QUERY_OUTPUT_BYTES,
        );
        let mut capture = ReportCapture::default();
        capture
            .evidence
            .resize(MAX_EVIDENCE - 1, Evidence::default());
        session.initialize(Some(&capture));
        assert!(session.call("list_threads", json!({})).await.is_err());
        assert!(session.evidence().await.is_empty());
        // No workspace was created by this constructed capability.
        session.cleaned.store(true, Ordering::Release);
    }
}
