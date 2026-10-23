//! Tool runner: bounded CDB execution over an SSH transport, and CDB output
//! parsing (task C2).
//!
//! [`SshCdbRunner`] stages a dump to the remote Windows analysis box, writes
//! a fixed, bounded CDB triage script, executes CDB under [`RunBounds`] hard
//! caps, and parses the bounded console log into a [`RunOutput`]. CDB never
//! runs on the configured Windows analysis host. DumpLedger and CDB are
//! separate processes; they may share a physical host.
//!
//! Two invariants drive the split between verdicts and errors
//! (docs/analyzer-design.md, "Agent pipeline"):
//!
//! * **Verdicts are not errors.** A dump CDB cannot analyze — unreadable,
//!   corrupt/truncated, or missing critical symbols for the faulting module
//!   — is `Ok(RunOutput { outcome: Failed, .. })`: a reportable verdict.
//! * **Run failures are errors.** Transport, timeout, and CDB-crash
//!   failures of the run itself leave `run` as `Err(AnalyzerError::Runner(_))`
//!   so the agent applies its bounded retry budget and eventually settles the
//!   job as `failed` with no report (task C1). The two paths are never
//!   conflated: only a parsed, bounded log can produce a verdict.
//!
//! Everything is bounded: wall time (per-run deadline, the transport kills
//! the child), captured output (truncated at
//! [`RunBounds::max_output_bytes`]), and workspace size (checked before
//! staging). The generated script is fixed (`triage.cdb`: `.sympath` with the
//! SymSrv store, `.reload`, `.ecxr`, `kc`, `lm`, `|`, `q`); `!analyze -v` is
//! deliberately out of scope for v1.
//!
//! Parsing targets CDB console text as produced through `cdb -cf`, where each
//! script line is echoed with its prompt (`0:000> kc`). The parser is also
//! tolerant of un-prompted output and of the tabular `k`/`kv` frame layout, so
//! a bounded log stays classifiable even when the transport or CDB version
//! varies. Marker strings (`Loading Dump File [`, `Could not open dump file
//! [...], Win32 error 0n38`, `"Reached the end of the file."`, `(no symbols)`,
//! `Call Site`) follow observed CDB 10.x output.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::report::{
    self, AccessViolation, CaptureStatus, ContextSource, Evidence, ExceptionRecord,
    FaultInstruction, ModuleSymbols, ReportCapture, StackFrame, SymbolQuality, UnwindStatus,
};
use crate::types::{
    AnalyzerError, ReportOutcome, Result, RunBounds, RunOutput, RunRequest, ToolRunner,
};

/// Maximum number of stack frames kept in `facts` ("bounded top frames").
pub const MAX_FRAMES: usize = 32;
/// Maximum number of modules kept in the per-module symbol status map.
pub const MAX_MODULES: usize = 64;
/// Maximum summary length; matches the server's `summary` bound (chars).
pub const MAX_SUMMARY_CHARS: usize = 2000;
/// Maximum length of one call-site string kept in `facts`.
const MAX_CALL_SITE_CHARS: usize = 160;
/// Maximum accepted `RunRequest::symbol_path` length (script injection guard).
pub const MAX_SYMBOL_PATH_CHARS: usize = 1024;
/// Upper bound for the generated triage script body.
pub const MAX_SCRIPT_BYTES: usize = 4096;
/// Default stdout/stderr read cap for the SSH transport, in bytes.
const DEFAULT_OUTPUT_CAP: usize = 8 * 1024 * 1024;
/// Small independent cap for metadata-only PDB probe output.
const PDB_METADATA_OUTPUT_CAP: usize = 32 * 1024;
/// Default `scp` transfer timeout for the SSH transport.
const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(900);
/// Wall-time budget for the best-effort remote workspace cleanup.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Default remote workspace root on the analysis box.
pub const DEFAULT_REMOTE_BASE: &str = "C:/da/work";
/// Local file name of the generated triage script inside the run workspace.
pub const TRIAGE_SCRIPT_NAME: &str = "triage.cdb";
/// Remote file name of the staged dump inside the remote run workspace.
const REMOTE_DUMP_NAME: &str = "dump.dmp";

/// Exit status and captured bytes from one transport execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportOutput {
    /// Process exit code; `None` when the child was terminated by a signal.
    pub status: Option<i32>,
    /// Captured standard output (possibly capped by the transport).
    pub stdout: Vec<u8>,
    /// Captured standard error (possibly capped by the transport).
    pub stderr: Vec<u8>,
}

impl TransportOutput {
    /// `true` when the command exited with status 0.
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

/// git-bash form of a Windows path (`C:/da/...` → `/c/da/...`). The analysis
/// box's SSH default shell is git-bash, where POSIX built-ins are the
/// reliable remote tools; `cmd.exe /c` mangles `/c` into a drive path.
pub(crate) fn bash_path(remote: &str) -> String {
    let bytes = remote.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = &remote[2..];
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        return format!("/{drive}/{rest}");
    }
    remote.to_string()
}

/// Transport seam owned by the tool runner: how commands and files reach the
/// Windows analysis box. Production is [`SshTransport`]; tests use an
/// in-memory fake. Implementations never run the toolchain locally, and never
/// carry credentials on their command lines.
#[async_trait]
pub trait ExecTransport: Send + Sync {
    /// Run `program` with `args` on the analysis box. `stdin` is closed
    /// immediately when `None`; the local transport child is killed after
    /// `timeout` (the returned error is `AnalyzerError::Transport`). Killing
    /// SSH is not a guarantee that a remote debugger process has terminated.
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput>;

    /// Execute with a per-request stdout/stderr acquisition cap. Production
    /// transports enforce it while reading, before parsing or retaining logs.
    /// In-memory adapters may delegate to `exec`; their fixture output is
    /// subsequently bounded by the runner's combined transcript projection.
    async fn exec_bounded(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
        _output_cap: usize,
    ) -> Result<TransportOutput> {
        self.exec(program, args, stdin, timeout).await
    }

    /// Copy `local` to `remote` (an analysis-box path).
    async fn put_file(&self, local: &Path, remote: &str) -> Result<()>;
}

#[async_trait]
impl<T: ExecTransport + ?Sized> ExecTransport for Box<T> {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput> {
        (**self).exec(program, args, stdin, timeout).await
    }

    async fn exec_bounded(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
        output_cap: usize,
    ) -> Result<TransportOutput> {
        (**self)
            .exec_bounded(program, args, stdin, timeout, output_cap)
            .await
    }

    async fn put_file(&self, local: &Path, remote: &str) -> Result<()> {
        (**self).put_file(local, remote).await
    }
}

/// SSH/scp implementation of [`ExecTransport`].
///
/// Commands run as `ssh -o BatchMode=yes <target> <program> <args...>`, so
/// program and arguments must survive the remote login shell: the runner only
/// uses shell-safe tokens and forward-slash Windows paths. Batch mode makes a
/// missing key or host entry fail fast instead of prompting a daemon.
#[derive(Debug)]
pub struct SshTransport {
    target: String,
    output_cap: usize,
    transfer_timeout: Duration,
}

impl SshTransport {
    /// Create a transport for an SSH target such as `windows-dev`.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            output_cap: DEFAULT_OUTPUT_CAP,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
        }
    }

    /// Override the stdout/stderr read cap (the child is killed when a
    /// combined stream output reaches it).
    pub fn with_output_cap(mut self, bytes: usize) -> Self {
        self.output_cap = bytes.max(1);
        self
    }

    /// Override the `scp` transfer timeout.
    pub fn with_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.transfer_timeout = timeout;
        self
    }
    fn for_output_cap(&self, cap: usize) -> Result<Self> {
        if cap == 0 {
            return Err(AnalyzerError::Transport(
                "raw output budget exhausted".into(),
            ));
        }
        Ok(Self {
            target: self.target.clone(),
            output_cap: self.output_cap.min(cap),
            transfer_timeout: self.transfer_timeout,
        })
    }
}

#[async_trait]
impl ExecTransport for SshTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput> {
        let mut command = Command::new("ssh");
        command
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(&self.target)
            .arg(program)
            .args(args);
        command.kill_on_drop(true);
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| AnalyzerError::Transport(format!("spawn ssh {}: {err}", self.target)))?;

        let cap = self.output_cap;
        let operation = async {
            if let Some(input) = stdin {
                if let Some(mut pipe) = child.stdin.take() {
                    pipe.write_all(input).await?;
                    drop(pipe);
                }
            }
            pump_child(&mut child, cap).await
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(Ok((stdout, stderr, status, _capped))) => Ok(TransportOutput {
                status: status.code(),
                stdout,
                stderr,
            }),
            Ok(Err(err)) => {
                let _ = child.kill().await;
                Err(AnalyzerError::Transport(format!(
                    "ssh {}: {err}",
                    self.target
                )))
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(AnalyzerError::Transport(format!(
                    "{program} on {} timed out after {timeout:?}",
                    self.target
                )))
            }
        }
    }

    async fn exec_bounded(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
        output_cap: usize,
    ) -> Result<TransportOutput> {
        self.for_output_cap(output_cap)?
            .exec(program, args, stdin, timeout)
            .await
    }

    async fn put_file(&self, local: &Path, remote: &str) -> Result<()> {
        let mut command = Command::new("scp");
        command
            .arg("-q")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(local)
            .arg(format!("{}:{remote}", self.target));
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| AnalyzerError::Transport(format!("spawn scp: {err}")))?;

        match tokio::time::timeout(self.transfer_timeout, pump_child(&mut child, 64 * 1024)).await {
            Ok(Ok((_stdout, _stderr, status, _capped))) if status.success() => Ok(()),
            Ok(Ok((stdout, stderr, status, _capped))) => Err(AnalyzerError::Transport(format!(
                "scp {} -> {}:{} failed (status {:?}): {}",
                local.display(),
                self.target,
                remote,
                status.code(),
                output_tail(&stderr, &stdout)
            ))),
            Ok(Err(err)) => {
                let _ = child.kill().await;
                Err(AnalyzerError::Transport(format!(
                    "scp {} -> {}:{}: {err}",
                    local.display(),
                    self.target,
                    remote
                )))
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(AnalyzerError::Transport(format!(
                    "scp {} -> {}:{} timed out after {:?}",
                    local.display(),
                    self.target,
                    remote,
                    self.transfer_timeout
                )))
            }
        }
    }
}

/// Read stdout and stderr concurrently under one shared acquisition cap, then
/// reap the child. Reads themselves are limited to the remaining budget; two
/// individually short streams cannot together acquire more than `cap` bytes.
async fn pump_child(
    child: &mut tokio::process::Child,
    cap: usize,
) -> io::Result<(Vec<u8>, Vec<u8>, ExitStatus, bool)> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe missing"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;

    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_open = true;
    let mut err_open = true;
    let mut out_buf = [0u8; 4096];
    let mut err_buf = [0u8; 4096];
    while out_open || err_open {
        let remaining = cap.saturating_sub(out.len() + err.len());
        if remaining == 0 {
            // Do not wait for EOF from a process which may be waiting for input.
            let _ = child.kill().await;
            return Ok((out, err, child.wait().await?, true));
        }
        let length = remaining.min(out_buf.len());
        tokio::select! {
            read = stdout.read(&mut out_buf[..length]), if out_open => {
                let read = read?;
                out_open = read != 0;
                out.extend_from_slice(&out_buf[..read]);
            }
            read = stderr.read(&mut err_buf[..length]), if err_open => {
                let read = read?;
                err_open = read != 0;
                err.extend_from_slice(&err_buf[..read]);
            }
        }
    }
    let status = child.wait().await?;
    Ok((out, err, status, false))
}

/// First non-empty line of `stderr` (else `stdout`), bounded for error text.
fn output_tail(stderr: &[u8], stdout: &[u8]) -> String {
    let text = if stderr.iter().any(|b| !b.is_ascii_whitespace()) {
        String::from_utf8_lossy(stderr).into_owned()
    } else {
        String::from_utf8_lossy(stdout).into_owned()
    };
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    bounded(line.to_string(), 200)
}

// ---------------------------------------------------------------------------
// CDB console log parsing
// ---------------------------------------------------------------------------

/// Failure reasons that make a failed triage a *verdict* rather than a runner
/// error (docs/analyzer-design.md: corrupt minidump, missing critical
/// symbols, CDB cannot load).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureReason {
    DumpCorrupt,
    DumpUnreadable,
    SymbolsMissing,
    NoAnalysisOutput,
}

impl FailureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::DumpCorrupt => "dump_corrupt",
            Self::DumpUnreadable => "dump_unreadable",
            Self::SymbolsMissing => "symbols_missing",
            Self::NoAnalysisOutput => "no_analysis_output",
        }
    }
}

/// Per-module symbol state as reported by `lm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymStatus {
    Pdb,
    Export,
    NoSymbols,
    Deferred,
    Unknown,
}

impl SymStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pdb => "pdb",
            Self::Export => "export",
            Self::NoSymbols => "none",
            Self::Deferred => "deferred",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    start: u64,
    end: u64,
    status: SymStatus,
}

#[derive(Debug)]
struct FrameInfo {
    call_site: String,
    module: Option<String>,
    resolved: bool,
}

#[derive(Debug)]
struct CandidateFrame {
    info: FrameInfo,
    /// The frame line was seen inside a `k*` command section.
    in_call_section: bool,
}

#[derive(Debug, Default)]
struct ParsedLog {
    loaded_dump: bool,
    open_failure: Option<String>,
    corruption: Option<String>,
    corruption_lines: Vec<String>,
    exception_code: Option<String>,
    exception_name: Option<String>,
    exception_address: Option<String>,
    context_call_site: Option<String>,
    candidates: Vec<CandidateFrame>,
    frames: Vec<FrameInfo>,
    frames_total: usize,
    modules: Vec<ModuleInfo>,
    process_id: Option<String>,
    quit_seen: bool,
}

#[derive(Debug)]
struct Verdict {
    outcome: ReportOutcome,
    reason: Option<FailureReason>,
    detail: Option<String>,
    faulting: Option<String>,
    critical_frames: usize,
}

/// Parse one bounded CDB triage console log into a [`RunOutput`].
///
/// An unclassifiable log (no dump-load evidence, or a log that ends before
/// any triage facts) is `Err(AnalyzerError::Runner(_))`: the run failed, it
/// did not produce a verdict.
pub fn parse_triage(log: &str) -> Result<RunOutput> {
    parse_triage_inner(log).map_err(AnalyzerError::Runner)
}

fn parse_triage_inner(log: &str) -> std::result::Result<RunOutput, String> {
    let mut parsed = scan_log(log);
    let (frames, total) = select_frames(&parsed.candidates, &parsed.modules);
    parsed.frames = frames;
    parsed.frames_total = total;

    let verdict = classify(&parsed, log.len())?;
    let summary = bounded(summarize(&parsed, &verdict), MAX_SUMMARY_CHARS);
    let facts = build_facts(&parsed, &verdict);
    Ok(RunOutput {
        outcome: verdict.outcome,
        summary,
        facts,
        capture: Some(capture_triage(log)),
    })
}

/// CDB phrasings for "the dump file could not be opened at all".
const OPEN_FAILURE_MARKERS: &[&str] = &[
    "could not open dump file",
    "unable to open dump file",
    "failed to open dump file",
    "cannot open dump file",
];

/// Evidence that the dump bytes are corrupt or truncated. Deliberately
/// specific: a bare "corrupt" appears in module and symbol names often
/// enough that it is not evidence on its own.
const CORRUPTION_MARKERS: &[&str] = &[
    "the file is corrupt",
    "is corrupted",
    "dump is corrupt",
    "dumpfile is corrupt",
    "corrupt or truncated",
    "reached the end of the file",
    "win32 error 0n38",
    "invalid file format",
    "could not match dump file signature",
];

fn scan_log(log: &str) -> ParsedLog {
    let mut parsed = ParsedLog::default();
    let mut current_command: Option<String> = None;
    let mut prompts_seen = false;
    let mut in_unloaded_section = false;

    for raw in log.lines() {
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        let trimmed = line.trim();

        if let Some(command) = prompt_command(line) {
            let name = command
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            prompts_seen = true;
            in_unloaded_section = false;
            if name == "q" || name == "qq" {
                parsed.quit_seen = true;
            }
            current_command = Some(name);
            continue;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("loading dump file [") {
            parsed.loaded_dump = true;
        }
        if parsed.open_failure.is_none() && OPEN_FAILURE_MARKERS.iter().any(|m| lower.contains(m)) {
            parsed.open_failure = Some(trimmed.to_string());
        }
        if parsed.corruption_lines.len() < 4
            && CORRUPTION_MARKERS.iter().any(|m| lower.contains(m))
            && !parsed.corruption_lines.iter().any(|line| line == trimmed)
        {
            parsed.corruption_lines.push(trimmed.to_string());
        }
        if parsed.exception_code.is_none()
            && let Some((code, name)) = parse_exception_field(trimmed, &lower)
        {
            parsed.exception_code = Some(code);
            parsed.exception_name = name;
        }
        if parsed.exception_address.is_none()
            && let Some(address) = parse_exception_address(trimmed, &lower)
        {
            parsed.exception_address = Some(address);
        }
        if parsed.context_call_site.is_none()
            && let Some(site) = parse_context_call_site(trimmed)
        {
            parsed.context_call_site = Some(site);
        }
        if lower.contains("unloaded modules:") {
            in_unloaded_section = true;
            continue;
        }

        // Modules: only inside an `lm` section, or shape-based when the log
        // carries no prompt echoes at all.
        let in_lm_section = current_command
            .as_deref()
            .is_some_and(|command| command.starts_with("lm"));
        if !in_unloaded_section
            && (!prompts_seen || in_lm_section)
            && let Some(module) = parse_module_line(trimmed)
        {
            parsed.modules.push(module);
        }

        if parsed.process_id.is_none()
            && let Some(pid) = parse_process_id(trimmed)
        {
            parsed.process_id = Some(pid);
        }

        let in_call_section = current_command.as_deref().is_some_and(is_k_command);
        if let Some(info) = parse_clean_frame(trimmed).or_else(|| parse_tabular_frame(trimmed)) {
            parsed.candidates.push(CandidateFrame {
                info,
                in_call_section,
            });
        }
    }

    // Prefer corruption evidence distinct from the open-failure line (CDB
    // often flags the truncation on the same line as the open error, then
    // quotes the OS message on the next).
    parsed.corruption = parsed
        .corruption_lines
        .iter()
        .find(|line| parsed.open_failure.as_deref() != Some(line.as_str()))
        .cloned()
        .or_else(|| parsed.corruption_lines.first().cloned());
    parsed
}

/// Detect a `0:000> command` (or `0:000:x86> command`) prompt echo.
fn prompt_command(line: &str) -> Option<String> {
    let index = line.find("> ")?;
    if index == 0 || index > 12 {
        return None;
    }
    let prefix = &line[..index];
    if !prefix.contains(':')
        || !prefix
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == 'x' || c == 'X')
    {
        return None;
    }
    let command = line[index + 2..].trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_string())
    }
}

fn is_k_command(command: &str) -> bool {
    command.starts_with('k') && command.len() <= 3
}

fn parse_exception_field(line: &str, lower: &str) -> Option<(String, Option<String>)> {
    if let Some(pos) = lower.find(" - code ") {
        let token = line[pos + " - code ".len()..].split_whitespace().next()?;
        if is_hex_code(token) {
            let name = line[..pos]
                .rsplit("): ")
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty() && name.len() < 80)
                .map(str::to_string);
            return Some((normalize_code(token), name));
        }
    }
    if let Some(pos) = lower.find("exceptioncode:") {
        let rest = line[pos + "exceptioncode:".len()..].trim();
        let token = rest.split_whitespace().next()?;
        if !is_hex_code(token) {
            return None;
        }
        let name = rest
            .find('(')
            .and_then(|open| {
                rest[open + 1..]
                    .find(')')
                    .map(|close| rest[open + 1..open + 1 + close].trim().to_string())
            })
            .filter(|name| !name.is_empty() && name.len() < 80);
        return Some((normalize_code(token), name));
    }
    None
}

fn is_hex_code(token: &str) -> bool {
    !token.is_empty() && token.len() <= 8 && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn normalize_code(token: &str) -> String {
    format!("0x{}", token.to_ascii_lowercase())
}

fn parse_exception_address(line: &str, lower: &str) -> Option<String> {
    if let Some(pos) = lower.find("exceptionaddress:") {
        let token = line[pos + "exceptionaddress:".len()..]
            .split_whitespace()
            .next()?;
        let hex = token.replace('`', "");
        if is_hex_digits(&hex) {
            return Some(format!("0x{}", hex.to_ascii_lowercase()));
        }
    }
    for register in ["rip=", "eip="] {
        if let Some(pos) = lower.find(register)
            && (pos == 0 || line.as_bytes()[pos - 1].is_ascii_whitespace())
        {
            let token = line[pos + register.len()..].split_whitespace().next()?;
            if is_hex_digits(token) {
                return Some(format!("0x{}", token.to_ascii_lowercase()));
            }
        }
    }
    None
}

fn is_hex_digits(text: &str) -> bool {
    !text.is_empty() && text.len() <= 16 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The faulting instruction line `module!symbol+0xoffset:` (or, without
/// symbols, `module+0xoffset:`) that `.ecxr` prints before the disassembly.
fn parse_context_call_site(line: &str) -> Option<String> {
    let candidate = line.strip_suffix(':')?;
    if candidate.len() < 3 || candidate.len() > 300 || candidate.contains(char::is_whitespace) {
        return None;
    }
    if !(candidate.contains('!') || candidate.contains("+0x")) {
        return None;
    }
    let module_end = candidate.find(['!', '+'])?;
    let module = &candidate[..module_end];
    if module.is_empty() || !module.chars().all(is_module_name_char) {
        return None;
    }
    Some(candidate.to_string())
}

fn is_module_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// `module!symbol[+0xoffset]` / `module+0xoffset` / `0x...` clean frames as
/// printed by `kc` ("clean" mode: module and function name only), plus their
/// un-prompted-format tolerance is handled by [`select_frames`].
fn parse_clean_frame(line: &str) -> Option<FrameInfo> {
    if line.len() < 3 || line.len() > 300 {
        return None;
    }
    if line.contains(char::is_whitespace) || line.ends_with(':') || line.starts_with('#') {
        return None;
    }
    if let Some(hex) = line.strip_prefix("0x")
        && is_hex_digits(&hex.replace('`', ""))
    {
        return Some(FrameInfo {
            call_site: line.to_string(),
            module: None,
            resolved: false,
        });
    }
    let module_end = line.find(['!', '+'])?;
    let module = &line[..module_end];
    if module.is_empty() || !module.chars().all(is_module_name_char) {
        return None;
    }
    let rest = &line[module_end + 1..];
    if line.as_bytes()[module_end] == b'!' {
        if rest.is_empty() {
            return None;
        }
        return Some(FrameInfo {
            call_site: line.to_string(),
            module: Some(module.to_string()),
            resolved: true,
        });
    }
    if !rest.starts_with("0x") || rest.len() < 4 || !is_hex_digits(&rest[2..]) {
        return None;
    }
    Some(FrameInfo {
        call_site: line.to_string(),
        module: Some(module.to_string()),
        resolved: false,
    })
}

/// Tabular frames (`k`, `kb`, `kp`, `kv`): two address columns followed by
/// the call site (kv/kb rows carry argument columns before it).
fn parse_tabular_frame(line: &str) -> Option<FrameInfo> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let start = if fields.len() >= 4
        && fields[0].len() <= 2
        && fields[0].chars().all(|c| c.is_ascii_digit())
    {
        1
    } else {
        0
    };
    if fields.len() < start + 3 {
        return None;
    }
    if !is_frame_address(fields[start]) || !is_frame_address(fields[start + 1]) {
        return None;
    }
    let mut call_tokens = fields[start + 2..].to_vec();
    if let Some(colon) = fields.iter().rposition(|token| *token == ":") {
        if colon >= start + 2 {
            call_tokens = fields[colon + 1..].to_vec();
        }
    }
    let call_site = call_tokens.join(" ");
    if !is_call_site_like(&call_site) {
        return None;
    }
    let module = module_of_call_site(&call_site);
    let resolved = call_site.contains('!');
    Some(FrameInfo {
        call_site,
        module,
        resolved,
    })
}

fn is_frame_address(token: &str) -> bool {
    let stripped = token.replace('`', "");
    if stripped.is_empty() || stripped.len() > 16 || !is_hex_digits(&stripped) {
        return false;
    }
    if token.contains('`') {
        stripped.len() > 8
    } else {
        (8..=16).contains(&stripped.len())
    }
}

fn is_call_site_like(call_site: &str) -> bool {
    !call_site.is_empty()
        && !call_site.contains(char::is_whitespace)
        && (call_site.contains('!')
            || call_site.contains("+0x")
            || call_site.starts_with("0x")
            || is_frame_address(call_site))
}

fn module_of_call_site(call_site: &str) -> Option<String> {
    let end = call_site.find(['!', '+'])?;
    let module = &call_site[..end];
    if module.is_empty() || module.len() > 256 || !module.chars().all(is_module_name_char) {
        return None;
    }
    Some(module.to_string())
}

/// One `lm` module line: `start end name [flags] (status) [path]`.
fn parse_module_line(line: &str) -> Option<ModuleInfo> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    let start = parse_module_range(fields[0])?;
    let end = parse_module_range(fields[1])?;
    if end <= start {
        return None;
    }
    let name = fields[2];
    if name.is_empty() || name.len() > 256 || !name.chars().all(is_module_name_char) {
        return None;
    }
    let rest = fields[3..].join(" ");
    let open = rest.find('(')?;
    if open > 4 {
        return None;
    }
    let close = rest[open..].find(')')?;
    let status_text = rest[open + 1..open + close].to_ascii_lowercase();
    Some(ModuleInfo {
        name: name.to_string(),
        start,
        end,
        status: classify_symbol_status(&status_text),
    })
}

fn parse_module_range(token: &str) -> Option<u64> {
    let stripped = token.replace('`', "");
    if !is_hex_digits(&stripped) {
        return None;
    }
    let backticked = token.contains('`');
    if (backticked && stripped.len() < 9) || (!backticked && stripped.len() != 8) {
        return None;
    }
    u64::from_str_radix(&stripped, 16).ok()
}

fn classify_symbol_status(text: &str) -> SymStatus {
    if text.contains("pdb") || text.contains("private symbols") || text.contains("public symbols") {
        SymStatus::Pdb
    } else if text.contains("export") {
        SymStatus::Export
    } else if text.contains("no symbols") || text == "none" {
        SymStatus::NoSymbols
    } else if text.contains("deferred") {
        SymStatus::Deferred
    } else {
        SymStatus::Unknown
    }
}

/// `|` (process status) rows: `0  id: 2bc4  create ...`.
fn parse_process_id(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        let Some(rest) = token.strip_prefix("id:") else {
            continue;
        };
        let pid = if rest.is_empty() {
            tokens.get(index + 1).copied()?
        } else {
            rest
        };
        if !pid.is_empty() && pid.len() <= 16 && pid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(pid.to_string());
        }
    }
    None
}

/// Keep the candidate frames that are actually stack frames, then apply the
/// [`MAX_FRAMES`] cap. Returns the kept frames and the total seen.
fn select_frames(candidates: &[CandidateFrame], modules: &[ModuleInfo]) -> (Vec<FrameInfo>, usize) {
    let known: HashSet<String> = modules
        .iter()
        .map(|module| normalize_module(&module.name))
        .collect();
    let mut frames = Vec::new();
    for candidate in candidates {
        let info = &candidate.info;
        let keep = info.resolved
            || info
                .module
                .as_deref()
                .is_some_and(|module| known.contains(&normalize_module(module)))
            || candidate.in_call_section;
        if !keep {
            continue;
        }
        frames.push(FrameInfo {
            call_site: info.call_site.clone(),
            module: info.module.clone(),
            resolved: info.resolved,
        });
    }
    let total = frames.len();
    frames.truncate(MAX_FRAMES);
    (frames, total)
}

fn normalize_module(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_suffix(".dll")
        .or_else(|| lower.strip_suffix(".exe"))
        .unwrap_or(&lower)
        .to_string()
}

fn modules_eq(left: &str, right: &str) -> bool {
    normalize_module(left) == normalize_module(right)
}

fn classify(parsed: &ParsedLog, log_len: usize) -> std::result::Result<Verdict, String> {
    let failure = |reason: FailureReason, detail: Option<String>| Verdict {
        outcome: ReportOutcome::Failed,
        reason: Some(reason),
        detail,
        faulting: faulting_module(parsed),
        critical_frames: 0,
    };

    if let Some(line) = &parsed.open_failure {
        let reason = if parsed.corruption.is_some() {
            FailureReason::DumpCorrupt
        } else {
            FailureReason::DumpUnreadable
        };
        return Ok(failure(reason, Some(line.clone())));
    }
    if !parsed.loaded_dump {
        return Err(format!(
            "no dump-load evidence in {log_len} bytes of CDB output"
        ));
    }
    if let Some(line) = &parsed.corruption {
        return Ok(failure(FailureReason::DumpCorrupt, Some(line.clone())));
    }

    let faulting = faulting_module(parsed);
    let empty =
        parsed.exception_code.is_none() && parsed.frames.is_empty() && parsed.modules.is_empty();
    if empty {
        if parsed.quit_seen {
            return Ok(failure(FailureReason::NoAnalysisOutput, None));
        }
        return Err(format!(
            "CDB output ends before any triage facts and before the script's quit command \
             ({log_len} bytes)"
        ));
    }

    let critical_frames = faulting
        .as_deref()
        .map(|name| unresolved_faulting_frames(parsed, name))
        .unwrap_or(0);
    if critical_frames > 0
        && faulting
            .as_deref()
            .is_some_and(|name| symbols_missing(parsed, name))
    {
        return Ok(Verdict {
            outcome: ReportOutcome::Failed,
            reason: Some(FailureReason::SymbolsMissing),
            detail: None,
            faulting,
            critical_frames,
        });
    }
    Ok(Verdict {
        outcome: ReportOutcome::Completed,
        reason: None,
        detail: None,
        faulting,
        critical_frames: 0,
    })
}

/// The module the fault was attributed to: the module range containing the
/// exception address, else the `.ecxr` context line, else the top frame.
fn faulting_module(parsed: &ParsedLog) -> Option<String> {
    if let Some(address) = parsed.exception_address.as_deref().and_then(parse_addr)
        && let Some(module) = parsed
            .modules
            .iter()
            .find(|module| address >= module.start && address < module.end)
    {
        return Some(module.name.clone());
    }
    let raw = parsed
        .context_call_site
        .as_deref()
        .and_then(module_of_call_site)
        .or_else(|| parsed.frames.first().and_then(|frame| frame.module.clone()))?;
    match parsed
        .modules
        .iter()
        .find(|module| modules_eq(&module.name, &raw))
    {
        Some(module) => Some(module.name.clone()),
        None => Some(raw),
    }
}

fn parse_addr(text: &str) -> Option<u64> {
    let stripped = text.strip_prefix("0x").unwrap_or(text).replace('`', "");
    if stripped.is_empty() || stripped.len() > 16 || !is_hex_digits(&stripped) {
        return None;
    }
    u64::from_str_radix(&stripped, 16).ok()
}

/// `true` only with evidence: the faulting module is listed by `lm` and its
/// symbols are not loaded from a PDB. A module absent from the module list is
/// not evidence of missing symbols.
fn symbols_missing(parsed: &ParsedLog, faulting: &str) -> bool {
    parsed
        .modules
        .iter()
        .find(|module| modules_eq(&module.name, faulting))
        .is_some_and(|module| module.status != SymStatus::Pdb)
}

fn unresolved_faulting_frames(parsed: &ParsedLog, faulting: &str) -> usize {
    parsed
        .frames
        .iter()
        .filter(|frame| {
            !frame.resolved
                && frame
                    .module
                    .as_deref()
                    .is_some_and(|module| modules_eq(module, faulting))
        })
        .count()
}

fn summarize(parsed: &ParsedLog, verdict: &Verdict) -> String {
    match verdict.reason {
        None => completed_summary(parsed, verdict),
        Some(FailureReason::DumpCorrupt) => match (&parsed.open_failure, &parsed.corruption) {
            (Some(open), Some(corruption)) if open != corruption => format!(
                "triage failed: CDB could not open the dump; the file is corrupt or \
                 truncated: {open}; {corruption}"
            ),
            (Some(open), _) => format!(
                "triage failed: CDB could not open the dump; the file is corrupt or \
                 truncated: {open}"
            ),
            (None, Some(corruption)) => {
                format!("triage failed: the dump is corrupt or truncated: {corruption}")
            }
            (None, None) => "triage failed: the dump is corrupt or truncated".to_string(),
        },
        Some(FailureReason::DumpUnreadable) => format!(
            "triage failed: CDB could not open the dump: {}",
            verdict.detail.clone().unwrap_or_default()
        ),
        Some(FailureReason::SymbolsMissing) => format!(
            "triage failed: no symbols for the faulting module {} ({} unresolved frame(s))",
            verdict.faulting.clone().unwrap_or_default(),
            verdict.critical_frames
        ),
        Some(FailureReason::NoAnalysisOutput) => {
            "triage failed: CDB produced no exception, stack, or module output for this dump"
                .to_string()
        }
    }
}

fn completed_summary(parsed: &ParsedLog, verdict: &Verdict) -> String {
    let mut text = String::new();
    match (&parsed.exception_name, &parsed.exception_code) {
        (Some(name), Some(code)) => {
            let _ = write!(text, "{name} ({code})");
        }
        (None, Some(code)) => {
            let _ = write!(text, "exception {code}");
        }
        _ => text.push_str("no stored exception record"),
    }
    if let Some(address) = &parsed.exception_address {
        let _ = write!(text, " at {address}");
    }
    if let Some(module) = &verdict.faulting {
        let _ = write!(text, " in {module}");
    }
    let _ = write!(text, "; {} frame(s)", parsed.frames.len());
    if !parsed.modules.is_empty() {
        let pdb = parsed
            .modules
            .iter()
            .filter(|module| module.status == SymStatus::Pdb)
            .count();
        let _ = write!(text, "; {} module(s): {pdb} with pdb", parsed.modules.len());
        let missing: Vec<String> = parsed
            .modules
            .iter()
            .filter(|module| matches!(module.status, SymStatus::Export | SymStatus::NoSymbols))
            .map(|module| module.name.clone())
            .collect();
        if !missing.is_empty() {
            let shown: Vec<String> = missing.iter().take(8).cloned().collect();
            let _ = write!(text, ", missing symbols for {}", shown.join(", "));
            if missing.len() > shown.len() {
                let _ = write!(text, " (+{} more)", missing.len() - shown.len());
            }
        }
    }
    text
}

fn build_facts(parsed: &ParsedLog, verdict: &Verdict) -> Value {
    let mut facts = Map::new();
    if let Some(code) = &parsed.exception_code {
        let mut exception = Map::new();
        exception.insert("code".to_string(), json!(code));
        if let Some(name) = &parsed.exception_name {
            exception.insert("name".to_string(), json!(name));
        }
        if let Some(address) = &parsed.exception_address {
            exception.insert("address".to_string(), json!(address));
        }
        facts.insert("exception".to_string(), Value::Object(exception));
    }
    if let Some(module) = &verdict.faulting {
        facts.insert("faulting_module".to_string(), json!(module));
    }
    if !parsed.frames.is_empty() {
        let frames: Vec<Value> = parsed
            .frames
            .iter()
            .map(|frame| json!(bounded(frame.call_site.clone(), MAX_CALL_SITE_CHARS)))
            .collect();
        facts.insert("frames".to_string(), Value::Array(frames));
        facts.insert("frames_total".to_string(), json!(parsed.frames_total));
        if parsed.frames_total > parsed.frames.len() {
            facts.insert("frames_truncated".to_string(), json!(true));
        }
    }
    if !parsed.modules.is_empty() {
        facts.insert("symbols".to_string(), symbols_facts(parsed));
    }
    if let Some(pid) = &parsed.process_id {
        facts.insert("process".to_string(), json!({ "id": pid }));
    }
    if let Some(reason) = verdict.reason {
        let mut failure = Map::new();
        failure.insert("reason".to_string(), json!(reason.as_str()));
        if let Some(detail) = &verdict.detail {
            failure.insert("detail".to_string(), json!(bounded(detail.clone(), 300)));
        }
        facts.insert("failure".to_string(), Value::Object(failure));
    }
    Value::Object(facts)
}

fn symbols_facts(parsed: &ParsedLog) -> Value {
    let mut pdb = 0usize;
    let mut export_only = 0usize;
    let mut no_symbols = 0usize;
    let mut deferred = 0usize;
    let mut unknown = 0usize;
    let mut missing = Vec::new();
    let mut modules = Map::new();
    let mut modules_truncated = false;

    for (index, module) in parsed.modules.iter().enumerate() {
        match module.status {
            SymStatus::Pdb => pdb += 1,
            SymStatus::Export => {
                export_only += 1;
                missing.push(module.name.clone());
            }
            SymStatus::NoSymbols => {
                no_symbols += 1;
                missing.push(module.name.clone());
            }
            SymStatus::Deferred => deferred += 1,
            SymStatus::Unknown => unknown += 1,
        }
        if index < MAX_MODULES {
            modules.insert(module.name.clone(), json!(module.status.as_str()));
        } else {
            modules_truncated = true;
        }
    }

    json!({
        "pdb": pdb,
        "export_only": export_only,
        "no_symbols": no_symbols,
        "deferred": deferred,
        "unknown": unknown,
        "missing": missing,
        "modules": Value::Object(modules),
        "modules_truncated": modules_truncated,
    })
}

// ---------------------------------------------------------------------------
// Bounded SSH/CDB runner
// ---------------------------------------------------------------------------

/// Bounded two-phase CDB acquisition over an [`ExecTransport`].
#[derive(Debug)]
pub struct SshCdbRunner<T: ExecTransport> {
    transport: Arc<T>,
    remote_base: String,
    cdb_program: String,
}

impl<T: ExecTransport> SshCdbRunner<T> {
    /// Create a runner over `transport`, using [`DEFAULT_REMOTE_BASE`] as the
    /// remote workspace root and `cdb` as the debugger program.
    pub fn new(transport: T) -> Self {
        Self {
            transport: Arc::new(transport),
            remote_base: DEFAULT_REMOTE_BASE.to_string(),
            cdb_program: "cdb".to_string(),
        }
    }

    /// Override the remote workspace root (forward-slash Windows path; it
    /// must exist on the analysis box).
    pub fn with_remote_base(mut self, base: impl Into<String>) -> Self {
        self.remote_base = base.into();
        self
    }

    /// Override the CDB executable name or path on the analysis box.
    pub fn with_cdb_program(mut self, program: impl Into<String>) -> Self {
        self.cdb_program = program.into();
        self
    }

    /// Collect baseline evidence and retain the verified remote dump for a
    /// bounded investigation. The caller must close the returned session after
    /// reasoning; dropping it also schedules best-effort remote cleanup.
    /// `request.bounds.wall_timeout` bounds baseline collection, while `deadline`
    /// covers the complete analysis including follow-up queries.
    pub async fn begin_session(
        &self,
        request: RunRequest,
        deadline: tokio::time::Instant,
    ) -> Result<(RunOutput, Arc<crate::analysis_tools::CdbSession<T>>)>
    where
        T: 'static,
    {
        self.begin_session_with_query_limit(
            request,
            deadline,
            crate::analysis_tools::MAX_QUERY_OUTPUT_BYTES,
        )
        .await
    }

    /// The DSH Forensicator bridge needs room for all-thread V8/JIT envelopes
    /// before it can project a bounded evidence excerpt. Reserve that room
    /// from the original output cap, never from a second independent budget.
    pub(crate) async fn begin_session_with_query_limit(
        &self,
        mut request: RunRequest,
        deadline: tokio::time::Instant,
        query_limit: usize,
    ) -> Result<(RunOutput, Arc<crate::analysis_tools::CdbSession<T>>)>
    where
        T: 'static,
    {
        let query_budget = query_limit.min(request.bounds.max_output_bytes / 4);
        request.bounds.max_output_bytes -= query_budget;
        let plan = self.plan(&request)?;
        let session = Arc::new(crate::analysis_tools::CdbSession::new(
            Arc::clone(&self.transport),
            plan.remote_dir.clone(),
            plan.remote_dump.clone(),
            self.cdb_program.clone(),
            request.symbol_path.clone(),
            deadline,
            query_budget,
        ));
        let collection_deadline =
            (tokio::time::Instant::now() + request.bounds.wall_timeout).min(deadline);
        let result = tokio::time::timeout_at(collection_deadline, async {
            let std_deadline = collection_deadline.into_std();
            self.ensure_remote_dir(
                &plan.remote_dir,
                remaining_budget("create remote workspace", std_deadline)?,
            )
            .await?;
            self.analyze(&request, &plan, std_deadline).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(AnalyzerError::Runner(
                "run wall-time budget exhausted during staging or execution".into(),
            ))
        });
        match result {
            Ok(output) => {
                session.initialize(output.capture.as_ref());
                Ok((output, session))
            }
            Err(error) => {
                session.close().await;
                Err(error)
            }
        }
    }

    /// Validate the request, size-check the workspace, and plan remote paths.
    fn plan(&self, request: &RunRequest) -> Result<RemotePlan> {
        validate_symbol_path(&request.symbol_path)?;
        if !request.dump_path.is_file() {
            return Err(AnalyzerError::Runner(format!(
                "staged dump {} is not a readable file",
                request.dump_path.display()
            )));
        }
        std::fs::create_dir_all(&request.work_dir).map_err(|err| {
            AnalyzerError::Runner(format!(
                "creating workspace {}: {err}",
                request.work_dir.display()
            ))
        })?;
        let size = workspace_size(&request.work_dir).map_err(|err| {
            AnalyzerError::Runner(format!(
                "measuring workspace {}: {err}",
                request.work_dir.display()
            ))
        })?;
        if size > request.bounds.max_workspace_bytes {
            return Err(AnalyzerError::Runner(format!(
                "workspace {} holds {size} bytes, over the {} byte cap",
                request.work_dir.display(),
                request.bounds.max_workspace_bytes
            )));
        }

        let script = essential_script();
        if script.len() > MAX_SCRIPT_BYTES {
            return Err(AnalyzerError::Runner(format!(
                "generated triage script is {} bytes, over the {MAX_SCRIPT_BYTES} byte cap",
                script.len()
            )));
        }

        let run_id = sanitize_run_id(&request.work_dir);
        let remote_dir = format!("{}/{}", self.remote_base.trim_end_matches('/'), run_id);
        Ok(RemotePlan {
            remote_dump: format!("{remote_dir}/{REMOTE_DUMP_NAME}"),
            remote_script: format!("{remote_dir}/{TRIAGE_SCRIPT_NAME}"),
            remote_symbols_script: format!("{remote_dir}/symbols.cdb"),
            remote_dir,
            local_symbols_script: request.work_dir.join("symbols.cdb"),
            local_script: request.work_dir.join(TRIAGE_SCRIPT_NAME),
            script,
        })
    }

    /// Ensure the remote run directory exists (idempotent; a failure here is
    /// reported by the subsequent `scp`, so only transport errors abort).
    async fn ensure_remote_dir(&self, remote_dir: &str, budget: Duration) -> Result<()> {
        let response = self
            .transport
            .exec("mkdir", &["-p", &bash_path(remote_dir)], None, budget)
            .await;
        match response {
            Ok(output) if output.success() => Ok(()),
            Ok(output) => {
                tracing::debug!(
                    remote_dir,
                    status = ?output.status,
                    "remote workspace mkdir did not succeed; continuing (idempotent)"
                );
                Ok(())
            }
            Err(err) => Err(AnalyzerError::Runner(format!(
                "creating remote workspace {remote_dir}: {err}"
            ))),
        }
    }

    /// Stage the script and dump, run CDB, and classify the bounded log.
    async fn analyze(
        &self,
        request: &RunRequest,
        plan: &RemotePlan,
        deadline: Instant,
    ) -> Result<RunOutput> {
        tokio::fs::write(&plan.local_script, plan.script.as_bytes())
            .await
            .map_err(|err| {
                AnalyzerError::Runner(format!(
                    "writing triage script {}: {err}",
                    plan.local_script.display()
                ))
            })?;
        self.transport
            .put_file(&plan.local_script, &plan.remote_script)
            .await
            .map_err(|err| {
                AnalyzerError::Runner(format!("staging {}: {err}", plan.remote_script))
            })?;
        self.transport
            .put_file(&request.dump_path, &plan.remote_dump)
            .await
            .map_err(|err| AnalyzerError::Runner(format!("staging {}: {err}", plan.remote_dump)))?;

        let budget = remaining_budget("execute cdb", deadline)?;
        let args = [
            "-z",
            plan.remote_dump.as_str(),
            "-cf",
            plan.remote_script.as_str(),
            "-y",
            plan.remote_dir.as_str(),
        ];
        let output = self
            .transport
            .exec_bounded(
                &self.cdb_program,
                &args,
                None,
                budget,
                request
                    .bounds
                    .max_output_bytes
                    .min(report::MAX_TRANSCRIPT_BYTES),
            )
            .await
            .map_err(|err| AnalyzerError::Runner(format!("cdb execution failed: {err}")))?;

        let mut output = classify_output(&request.bounds, output)?;
        // Mandatory evidence is now owned. Network symbol loading runs in a
        // second CDB process, so its timeout cannot erase the saved baseline.
        if output
            .capture
            .as_ref()
            .is_some_and(|capture| !capture.evidence.iter().any(|e| e.id == "legacy-transcript"))
        {
            self.refine_symbols(request, plan, deadline, &mut output)
                .await;
        }
        if let Some(capture) = &mut output.capture {
            attach_dump_modules(capture, &request.dump_path);
            self.qualify_pdbs(capture, deadline).await;
            apply_symbol_quality(capture);
            capture.root_cause = crate::assessment::assess(capture);
        }
        Ok(output)
    }

    /// Best-effort removal of the remote run directory (a wiped workspace is
    /// part of the security model); failures are logged, never propagated.
    async fn cleanup_remote(&self, remote_dir: &str) {
        let remote_path = bash_path(remote_dir);
        let response = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            self.transport
                .exec("rm", &["-rf", &remote_path], None, CLEANUP_TIMEOUT),
        )
        .await;
        match response {
            Err(_) => tracing::warn!(remote_dir, "remote workspace cleanup deadline expired"),
            Ok(response) => match response {
                Ok(output) if output.success() => {}
                Ok(output) => {
                    tracing::warn!(
                        remote_dir,
                        status = ?output.status,
                        "remote workspace cleanup failed"
                    );
                }
                Err(err) => {
                    tracing::warn!(remote_dir, error = %err, "remote workspace cleanup failed");
                }
            },
        }
    }
}

#[async_trait]
impl<T: ExecTransport> ToolRunner for SshCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        let deadline = Instant::now() + request.bounds.wall_timeout;
        let plan = self.plan(&request)?;
        let budget = remaining_budget("create remote workspace", deadline)?;
        // The outer deadline also bounds put_file implementations, including
        // their independently configured transfer timeout.
        let result = tokio::time::timeout(budget, async {
            self.ensure_remote_dir(
                &plan.remote_dir,
                remaining_budget("create remote workspace", deadline)?,
            )
            .await?;
            self.analyze(&request, &plan, deadline).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(AnalyzerError::Runner(
                "run wall-time budget exhausted during staging or execution".into(),
            ))
        });
        self.cleanup_remote(&plan.remote_dir).await;
        result
    }
}

/// Remote artifact paths for one run.
#[derive(Debug)]
struct RemotePlan {
    remote_dir: String,
    remote_dump: String,
    remote_script: String,
    remote_symbols_script: String,
    local_script: PathBuf,
    local_symbols_script: PathBuf,
    script: String,
}

/// Remaining wall-time budget, or a runner error once the deadline passed.
fn remaining_budget(stage: &str, deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            AnalyzerError::Runner(format!("run wall-time budget exhausted before {stage}"))
        })
}

/// Combined named script useful for authored fixtures and manual inspection.
/// Production executes essential acquisition and optional symbol refinement in
/// separate processes so symbol-loading failure preserves the baseline.
pub fn triage_script(symbol_path: &str) -> String {
    let mut script = String::from("$$ DumpAnalyzer CDB evidence script (v2)\n");
    let _ = writeln!(script, ".sympath {symbol_path}");
    // Every command has explicit markers; command echoes cannot become facts.
    for (id, command) in [
        ("target", "version; vertarget; ~; |"),
        ("exception", ".exr -1"),
        ("context", ".ecxr; ~.; r"),
        ("instruction", "u @$ip L0n16"),
        ("stack-before-symbols", "kn 0n128"),
        ("symbols-load", ".lines -e; .reload /f"),
        ("modules", "lmv"),
        ("stack", ".lines -e; .ecxr; ~.; kn 0n128"),
    ] {
        let _ = writeln!(script, ".echo DA_BEGIN:{id}\n{command}\n.echo DA_END:{id}");
    }
    script.push_str("q\n");
    script
}

/// The symbol path is embedded verbatim in the generated `.sympath` line, so
/// it must be a single token: bound it and reject whitespace, quotes, and
/// command separators. A path that needs quoting would otherwise split into
/// multiple `.sympath` words and silently lose symbol coverage.
fn validate_symbol_path(symbol_path: &str) -> Result<()> {
    let invalid = symbol_path.is_empty()
        || symbol_path.len() > MAX_SYMBOL_PATH_CHARS
        || symbol_path.chars().any(char::is_whitespace)
        || symbol_path.contains([';', '"']);
    if invalid {
        return Err(AnalyzerError::Runner(format!(
            "invalid symbol path ({} bytes; must be non-empty, at most \
             {MAX_SYMBOL_PATH_CHARS} bytes, without whitespace, quotes, or semicolons)",
            symbol_path.len()
        )));
    }
    Ok(())
}

/// Remote run id derived from the local workspace name; unique per run
/// because the agent gives every run its own workspace directory.
fn sanitize_run_id(work_dir: &Path) -> String {
    let raw = work_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("run");
    let mut run_id: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    run_id.truncate(64);
    if run_id.is_empty() || run_id.chars().all(|c| c == '.') {
        run_id = "run".to_string();
    }
    run_id
}

/// Recursive workspace size (symlinks are measured as entries, never
/// followed).
fn workspace_size(dir: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total += metadata.len();
            }
        }
    }
    Ok(total)
}

/// Reconcile the bounded CDB output with the run's exit status and build the
/// verdict: a parsed verdict wins even on a non-zero exit (a dump CDB cannot
/// load exits non-zero), but an unparsed log or a "clean" log with a non-zero
/// exit is a run failure, never a verdict.
fn classify_output(bounds: &RunBounds, output: TransportOutput) -> Result<RunOutput> {
    let mut raw = output.stdout;
    if !output.stderr.is_empty() {
        raw.push(b'\n');
        raw.extend_from_slice(&output.stderr);
    }
    let total = raw.len();
    let (log, truncated) = truncate_utf8(
        raw,
        bounds.max_output_bytes.min(report::MAX_TRANSCRIPT_BYTES),
    );

    match parse_triage_inner(&log) {
        Ok(mut run_output) => {
            if run_output.outcome == ReportOutcome::Completed && output.status != Some(0) {
                return Err(AnalyzerError::Runner(format!(
                    "cdb exited with status {:?} without a failed verdict",
                    output.status
                )));
            }
            if let Value::Object(facts) = &mut run_output.facts {
                facts.insert(
                    "log".to_string(),
                    json!({
                        "bytes": total,
                        "truncated": truncated,
                        "cap": bounds.max_output_bytes,
                    }),
                );
            }
            if truncated {
                if let Some(capture) = &mut run_output.capture {
                    capture.completeness.truncated = true;
                    capture.completeness.omissions.push(
                        "Combined debugger transcript exceeded the configured output budget".into(),
                    );
                }
                run_output.summary = bounded(
                    format!(
                        "{} (CDB output truncated to {} bytes)",
                        run_output.summary, bounds.max_output_bytes
                    ),
                    MAX_SUMMARY_CHARS,
                );
            }
            Ok(run_output)
        }
        Err(message) => {
            let cap_note = if truncated {
                format!(", truncated to {} bytes", bounds.max_output_bytes)
            } else {
                String::new()
            };
            Err(AnalyzerError::Runner(format!(
                "no usable CDB verdict (status {:?}, {total} bytes{cap_note}): {message}",
                output.status
            )))
        }
    }
}

/// Truncate raw output at `cap` bytes without splitting a UTF-8 codepoint.
fn truncate_utf8(mut bytes: Vec<u8>, cap: usize) -> (String, bool) {
    let truncated = bytes.len() > cap;
    if truncated {
        bytes.truncate(cap);
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text.to_string(),
        Err(err) => String::from_utf8_lossy(&bytes[..err.valid_up_to()]).into_owned(),
    };
    (text, truncated)
}

/// Truncate `text` to at most `max_chars` characters (codepoint-safe).
fn bounded(text: String, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text;
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Named, owned forensic evidence (v2)
// ---------------------------------------------------------------------------

fn canonical_address(text: &str) -> Option<String> {
    let token = text
        .trim()
        .trim_end_matches([',', ':', ';'])
        .trim_start_matches("0x");
    let digits = token.replace('`', "");
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", digits.to_ascii_lowercase()))
}

fn section_command(id: &str) -> &str {
    match id {
        "target" => "version; vertarget; ~; |",
        "exception" => ".exr -1",
        "context" => ".ecxr; ~.; r",
        "instruction" => "u @$ip L0n16",
        "stack-before-symbols" => "kn 0n128",
        "symbols-load" => ".lines -e; .reload /f",
        "modules" => "lmv",
        "modules-initial" => "lm",
        "stack" => ".lines -e; .ecxr; ~.; kn 0n128",
        _ => "legacy debugger transcript",
    }
}

fn bounded_bytes(text: &str, cap: usize) -> String {
    let mut end = text.len().min(cap);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn evidence_text(text: &str) -> (String, bool) {
    let mut end = text.len().min(report::MAX_SECTION_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), end < text.len())
}

fn capture_sections(log: &str) -> (BTreeMap<String, String>, Vec<Evidence>, bool) {
    let mut sections = BTreeMap::new();
    let mut evidence = Vec::new();
    let mut current: Option<(String, String)> = None;
    let mut truncated = false;
    for line in log.lines() {
        let line = line.trim_end();
        if let Some(id) = line.strip_prefix("DA_BEGIN:") {
            if let Some((id, body)) = current.take() {
                let (text, _) = evidence_text(&body);
                evidence.push(Evidence {
                    id: id.clone(),
                    command: section_command(&id).into(),
                    status: CaptureStatus::Truncated,
                    text,
                    truncated: true,
                    error: Some("Missing section end marker".into()),
                });
                sections.insert(id, body);
                truncated = true;
            }
            if evidence.len() >= report::MAX_EVIDENCE || sections.contains_key(id) {
                truncated = true;
                continue;
            }
            if [
                "target",
                "exception",
                "context",
                "instruction",
                "stack-before-symbols",
                "symbols-load",
                "modules",
                "modules-initial",
                "stack",
            ]
            .contains(&id)
            {
                current = Some((id.into(), String::new()));
            }
        } else if let Some(id) = line.strip_prefix("DA_END:") {
            if current.as_ref().is_some_and(|(name, _)| name == id) {
                let (id, body) = current.take().expect("checked section");
                let (text, capped) = evidence_text(&body);
                let lower = body.to_ascii_lowercase();
                let failed = [
                    "unable to get exception",
                    "no exception record",
                    "unable to read",
                    "could not read",
                    "memory access error",
                    "couldn't resolve error",
                ]
                .iter()
                .any(|m| lower.contains(m));
                evidence.push(Evidence {
                    id: id.clone(),
                    command: section_command(&id).into(),
                    status: if failed {
                        CaptureStatus::Failed
                    } else if capped {
                        CaptureStatus::Truncated
                    } else if body.trim().is_empty() {
                        CaptureStatus::Absent
                    } else {
                        CaptureStatus::Present
                    },
                    text,
                    truncated: capped,
                    error: failed
                        .then(|| "Debugger reported unavailable or unreadable evidence".into()),
                });
                sections.insert(id, body);
                truncated |= capped;
            }
        } else if let Some((_, body)) = &mut current {
            // Command echoes are metadata, not part of the acquired value.
            if prompt_command(line).is_none() {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    if let Some((id, body)) = current {
        let (text, _) = evidence_text(&body);
        evidence.push(Evidence {
            id: id.clone(),
            command: section_command(&id).into(),
            status: CaptureStatus::Truncated,
            text,
            truncated: true,
            error: Some("Missing section end marker".into()),
        });
        sections.insert(id, body);
        truncated = true;
    }
    (sections, evidence, truncated)
}

/// Parse rich evidence without making debugger symbol labels into independent
/// identity proofs. Old logs remain readable, with their missing fields marked.
pub fn capture_triage(log: &str) -> ReportCapture {
    let (mut sections, mut evidence, truncated) = capture_sections(log);
    let named = !sections.is_empty();
    let mut capture = ReportCapture::default();
    capture.provenance.provider = "cdb-ssh".into();
    capture.provenance.analysis_revision = "deterministic-cdb-v2.1".into();
    capture.completeness.truncated = truncated;
    if !named {
        let (text, capped) = evidence_text(log);
        evidence.push(Evidence {
            id: "legacy-transcript".into(),
            command: "legacy debugger transcript".into(),
            status: CaptureStatus::Partial,
            text,
            truncated: capped,
            error: None,
        });
        sections.insert("legacy-transcript".into(), log.into());
        capture.completeness.omissions.push("Legacy unmarked transcript: complete exception record and section provenance were not captured".into());
        capture.completeness.truncated |= capped;
    }
    capture.evidence = evidence;
    if truncated {
        capture
            .completeness
            .omissions
            .push("One or more evidence excerpts or command sections were truncated".into());
    }
    let target = sections.get("target").map(String::as_str).unwrap_or(log);
    for line in target.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("windows debugger version") {
            capture.provenance.debugger_version = Some(line.trim().chars().take(256).collect());
        }
        if lower.contains("amd64") || lower.contains(" free x64") {
            capture.provenance.architecture = Some("amd64".into());
            capture.provenance.pointer_width = Some(64);
        } else if lower.contains("arm64") {
            capture.provenance.architecture = Some("arm64".into());
            capture.provenance.pointer_width = Some(64);
        } else if lower.contains(" free x86") || lower.contains(" x86") {
            capture.provenance.architecture = Some("x86".into());
            capture.provenance.pointer_width = Some(32);
        }
        if let Some(pid) = parse_process_id(line) {
            capture.provenance.process_id = canonical_address(&pid);
        }
        if line.trim_start().starts_with('.')
            && let Some((_, ids)) = line.split_once("Id:").or_else(|| line.split_once("id:"))
        {
            if let Some((_, tid)) = ids
                .split_whitespace()
                .next()
                .and_then(|s| s.split_once('.'))
            {
                capture.context.thread_id = canonical_address(tid);
            }
        }
    }
    let fallback_id = "legacy-transcript";
    let exr = sections.get("exception");
    capture.exception = parse_exception_record(exr.map(String::as_str).unwrap_or(""), "exception");
    if !named {
        let parsed = scan_log(log);
        capture.exception.code = parsed.exception_code;
        capture.exception.address = parsed.exception_address;
        capture.exception.status = CaptureStatus::Unavailable;
        capture.exception.evidence_refs = vec![fallback_id.into()];
    }
    let context = sections
        .get("context")
        .map(String::as_str)
        .unwrap_or(if named { "" } else { log });
    let context_id = if named { "context" } else { fallback_id };
    let context_failed = context
        .to_ascii_lowercase()
        .contains("unable to get exception")
        || context
            .to_ascii_lowercase()
            .contains("no exception context");
    // Capture the current OS thread identity alongside the saved context,
    // rather than inferring it from a numbered stack-frame index.
    for line in context.lines() {
        if let Some((_, ids)) = line.split_once("Id:").or_else(|| line.split_once("id:")) {
            if let Some((_, tid)) = ids
                .split_whitespace()
                .next()
                .and_then(|s| s.split_once('.'))
            {
                capture.context.thread_id = canonical_address(tid);
            }
        }
    }
    capture.context.registers = parse_registers(context);
    if !capture.context.registers.is_empty() {
        capture.context.source = if named && !context_failed {
            ContextSource::Exception
        } else {
            ContextSource::Initial
        };
        capture.context.evidence_refs = vec![context_id.into()];
    }
    let instruction = sections
        .get("instruction")
        .map(String::as_str)
        .unwrap_or(if named { "" } else { log });
    let instruction_id = if named { "instruction" } else { fallback_id };
    capture.context.fault_instruction = parse_instruction(
        instruction,
        instruction_id,
        capture.exception.address.as_deref(),
    );
    if let Some(instruction) = &mut capture.context.fault_instruction {
        instruction.effective_address =
            simple_effective_address(&instruction.disassembly, &capture.context.registers);
    }
    let module_section = if sections.contains_key("modules") {
        "modules"
    } else {
        "modules-initial"
    };
    let modules = sections
        .get(module_section)
        .map(String::as_str)
        .unwrap_or(if named { "" } else { log });
    let module_id = if named { module_section } else { fallback_id };
    let preliminary_text = sections
        .get("stack")
        .or_else(|| sections.get("stack-before-symbols"))
        .map(String::as_str)
        .unwrap_or(if named { "" } else { log });
    let (referenced_frames, _, _) = parse_rich_frames(
        preliminary_text,
        "stack",
        capture.provenance.architecture.as_deref(),
        &[],
        None,
    );
    let mut relevant: HashSet<String> = referenced_frames
        .iter()
        .filter_map(|f| f.module.as_deref())
        .map(normalize_module)
        .collect();
    if let Some(address) = capture.exception.address.as_deref().and_then(parse_addr) {
        for module in modules
            .lines()
            .filter_map(|line| parse_module_line(line.trim()))
        {
            if address >= module.start && address < module.end {
                relevant.insert(normalize_module(&module.name));
            }
        }
    }
    let mut details = parse_detailed_modules(modules, module_id);
    details.sort_by_key(|m| !relevant.contains(&normalize_module(&m.module)));
    details.truncate(report::MAX_MODULES);
    capture.symbols.modules = details;
    let module_total = modules
        .lines()
        .filter_map(|line| parse_module_line(line.trim()))
        .count();
    if module_total > report::MAX_MODULES {
        let omitted = module_total - report::MAX_MODULES;
        capture.symbols.limitations.push(format!(
            "{omitted} detailed module records omitted at the 64-module limit"
        ));
        capture
            .completeness
            .omissions
            .push(format!("{omitted} module records omitted"));
        capture.completeness.truncated = true;
    }
    capture.symbols.limitations.push("Debugger PDB labels alone are unverified; matching requires the dump RSDS identity and the loaded PDB Info stream identity".into());
    let stack_id = if sections.contains_key("stack") {
        "stack"
    } else if sections.contains_key("stack-before-symbols") {
        "stack-before-symbols"
    } else {
        fallback_id
    };
    let stack = sections.get(stack_id).map(String::as_str).unwrap_or("");
    capture.stack.thread_id = capture.context.thread_id.clone();
    let (frames, total, field_truncated) = parse_rich_frames(
        stack,
        stack_id,
        capture.provenance.architecture.as_deref(),
        &capture.symbols.modules,
        if capture.context.source == ContextSource::Exception {
            capture.exception.address.as_deref()
        } else {
            None
        },
    );
    capture.stack.frames = frames;
    if field_truncated {
        capture.completeness.truncated = true;
        capture.stack.limitations.push(
            "Function/source labels exceeded their per-field bounds and were shortened".into(),
        );
    }
    capture.stack.status = if total == 0 {
        CaptureStatus::Unavailable
    } else if total > report::MAX_FRAMES {
        CaptureStatus::Truncated
    } else {
        CaptureStatus::Present
    };
    if total > report::MAX_FRAMES {
        capture.stack.limitations.push(format!(
            "{} additional frames omitted",
            total - report::MAX_FRAMES
        ));
        capture.completeness.truncated = true;
    } else if total == report::MAX_FRAMES {
        capture
            .stack
            .limitations
            .push("The debugger requested 128 frames; deeper frames were not requested".into());
        capture.completeness.truncated = true;
    }
    if capture.context.source != ContextSource::Exception && total > 0 {
        capture.stack.limitations.push("Stack belongs to the initial/fallback context because the saved exception context was unavailable".into());
    }
    if stack
        .to_ascii_lowercase()
        .contains("following frames may be wrong")
        || stack
            .to_ascii_lowercase()
            .contains("stack unwind information not available")
    {
        capture.stack.status = CaptureStatus::Partial;
        capture
            .stack
            .limitations
            .push("Debugger reported unreliable or missing unwind information".into());
        for frame in &mut capture.stack.frames {
            frame.unwind = UnwindStatus::Unreliable;
        }
    }
    if !named {
        capture
            .stack
            .limitations
            .push("Legacy stack may omit addresses and source locations".into());
    }
    for id in ["exception", "context", "instruction", "modules", "stack"] {
        let available = sections.contains_key(id)
            || (id == "modules" && sections.contains_key("modules-initial"))
            || (id == "stack" && sections.contains_key("stack-before-symbols"));
        if named && !available {
            capture.completeness.omissions.push(format!(
                "Required acquisition section {id} did not complete"
            ));
        }
    }
    apply_symbol_quality(&mut capture);
    capture.root_cause = crate::assessment::assess(&capture);
    capture
}

fn parse_exception_record(text: &str, id: &str) -> ExceptionRecord {
    let mut record = ExceptionRecord {
        status: CaptureStatus::Absent,
        ..ExceptionRecord::default()
    };
    if text.is_empty() {
        record.status = CaptureStatus::Unavailable;
        return record;
    }
    record.evidence_refs.push(id.into());
    let mut parameters = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let token = value.split_whitespace().next().unwrap_or_default();
        match key.as_str() {
            "exceptioncode" => record.code = canonical_address(token),
            "exceptionflags" => record.flags = canonical_address(token),
            "exceptionaddress" => record.address = canonical_address(token),
            "exceptionrecord" => record.record_pointer = canonical_address(token),
            "numberparameters" => {
                record.parameter_count = token.parse::<u32>().ok().filter(|n| *n <= 15)
            }
            _ if key.starts_with("parameter[") => {
                if let Some(index) = key
                    .strip_prefix("parameter[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .filter(|i| *i < 15)
                    && let Some(value) = canonical_address(token)
                {
                    parameters.insert(index, value);
                }
            }
            _ => (),
        }
    }
    // Preserve order and refuse to shift later parameters into a missing slot.
    for i in 0..record
        .parameter_count
        .unwrap_or(parameters.len() as u32)
        .min(15) as usize
    {
        let Some(value) = parameters.get(&i) else {
            break;
        };
        record.parameters.push(value.clone());
    }
    if record.code.is_some() {
        record.status = if record.flags.is_some()
            && record.address.is_some()
            && record
                .parameter_count
                .is_some_and(|n| n as usize == record.parameters.len())
        {
            CaptureStatus::Present
        } else {
            CaptureStatus::Partial
        };
    } else if text.to_ascii_lowercase().contains("unable")
        || text.to_ascii_lowercase().contains("error")
    {
        record.status = CaptureStatus::Failed;
    }
    if matches!(record.code.as_deref(), Some("0xc0000005" | "0xc0000006"))
        && record.parameters.len() >= 2
    {
        let operation = match parse_addr(&record.parameters[0]) {
            Some(0) => "read",
            Some(1) => "write",
            Some(8) => "execute",
            _ => "unknown",
        };
        record.access = Some(AccessViolation {
            operation: operation.into(),
            address: record.parameters[1].clone(),
            underlying_status: (record.code.as_deref() == Some("0xc0000006"))
                .then(|| record.parameters.get(2).cloned())
                .flatten(),
        });
    }
    record
}

fn parse_registers(text: &str) -> BTreeMap<String, String> {
    let mut registers = BTreeMap::new();
    for token in text.split_whitespace() {
        if let Some((name, value)) = token.split_once('=') {
            let name = name.to_ascii_lowercase();
            let known = [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10",
                "r11", "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                "esp", "eip", "cs", "ss", "ds", "es", "fs", "gs", "efl", "eflags", "rflags", "sp",
                "pc", "lr", "fp", "cpsr",
            ]
            .contains(&name.as_str())
                || name
                    .strip_prefix('x')
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some_and(|n| n <= 30);
            if known
                && registers.len() < 80
                && let Some(value) = canonical_address(value)
            {
                registers.insert(name, value);
            }
        }
    }
    registers
}

fn parse_instruction(text: &str, id: &str, wanted: Option<&str>) -> Option<FaultInstruction> {
    let mut first = None;
    for line in text.lines() {
        let mut parts = line.trim().splitn(3, char::is_whitespace);
        let Some(address) = parts.next().and_then(canonical_address) else {
            continue;
        };
        let Some(rest) = parts.next().map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        let remaining = parts.next().unwrap_or_default().trim();
        let (bytes, disassembly) =
            if rest.len() % 2 == 0 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
                (Some(rest.to_ascii_lowercase()), remaining)
            } else {
                (None, remaining)
            };
        if disassembly.is_empty() {
            continue;
        }
        let disassembly = disassembly.split(" ds:").next().unwrap_or(disassembly);
        let instruction = FaultInstruction {
            address: address.clone(),
            bytes,
            disassembly: disassembly.chars().take(1024).collect(),
            effective_address: None,
            evidence_refs: vec![id.into()],
        };
        if wanted.and_then(parse_addr) == parse_addr(&address) {
            return Some(instruction);
        }
        if first.is_none() {
            first = Some(instruction);
        }
    }
    first
}

fn simple_effective_address(
    disassembly: &str,
    registers: &BTreeMap<String, String>,
) -> Option<String> {
    let start = disassembly.find('[')?;
    let end = disassembly[start + 1..].find(']')? + start + 1;
    registers
        .get(&disassembly[start + 1..end].trim().to_ascii_lowercase())
        .cloned()
}

fn parse_detailed_modules(text: &str, id: &str) -> Vec<ModuleSymbols> {
    let mut modules: Vec<ModuleSymbols> = Vec::new();
    for line in text.lines() {
        if let Some(module) = parse_module_line(line.trim()) {
            if modules.len() >= 8192 {
                break;
            }
            let pdb_path = line
                .rsplit_once(')')
                .map(|(_, p)| p.trim())
                .filter(|p| p.to_ascii_lowercase().ends_with(".pdb") && p.len() <= 2048)
                .map(str::to_owned);
            modules.push(ModuleSymbols {
                module: module.name,
                image_base: Some(format!("0x{:x}", module.start)),
                image_size: Some(format!("0x{:x}", module.end - module.start)),
                quality: match module.status {
                    SymStatus::Export => SymbolQuality::ExportsOnly,
                    SymStatus::NoSymbols => SymbolQuality::Missing,
                    _ => SymbolQuality::Unverified,
                },
                pdb_path,
                evidence_refs: vec![id.into()],
                ..ModuleSymbols::default()
            });
        } else if let Some(module) = modules.last_mut() {
            if let Some((key, value)) = line.trim().split_once(':') {
                match key.trim().to_ascii_lowercase().as_str() {
                    "timestamp" => {
                        if let Some(value) = value
                            .rsplit_once('(')
                            .and_then(|(_, s)| s.strip_suffix(')'))
                            .and_then(canonical_address)
                        {
                            module.timestamp = Some(value);
                        }
                    }
                    "image size" | "imagesize" => {
                        module.image_size = canonical_address(value.trim())
                    }
                    "loaded pdb file" | "pdb file" => {
                        module.pdb_path = Some(bounded_bytes(value.trim(), 2048))
                    }
                    _ => (),
                }
            }
        }
    }
    modules
}

fn parse_rich_frames(
    text: &str,
    id: &str,
    architecture: Option<&str>,
    modules: &[ModuleSymbols],
    fault_address: Option<&str>,
) -> (Vec<StackFrame>, usize, bool) {
    let mut frames = Vec::new();
    let mut total = 0;
    let mut field_truncated = false;
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let mut frame = StackFrame {
            index: total as u32,
            unwind: UnwindStatus::Reported,
            evidence_refs: vec![id.into()],
            ..StackFrame::default()
        };
        let callsite;
        if words.len() >= 4
            && words[0].len() <= 3
            && words[0].bytes().all(|b| b.is_ascii_hexdigit())
            && is_frame_address(words[1])
            && is_frame_address(words[2])
        {
            frame.index = u32::from_str_radix(words[0], 16).unwrap_or(total as u32);
            if architecture == Some("x86") {
                frame.frame_pointer = canonical_address(words[1]);
            } else {
                frame.stack_pointer = canonical_address(words[1]);
            }
            frame.return_address = canonical_address(words[2]);
            let start = words
                .iter()
                .rposition(|s| *s == ":")
                .map(|i| i + 1)
                .unwrap_or(3);
            let Some(site) = words.get(start) else {
                continue;
            };
            callsite = *site;
            if let Some(source) = line
                .split_once('[')
                .and_then(|(_, s)| s.rsplit_once(']').map(|(v, _)| v))
            {
                if let Some((file, number)) = source
                    .rsplit_once(" @ ")
                    .or_else(|| source.rsplit_once(':'))
                {
                    frame.source_line = number.trim().parse().ok();
                    field_truncated |= file.trim().len() > 512;
                    frame.source_file = Some(bounded_bytes(file.trim(), 512));
                }
            }
        } else if words.len() == 1 && parse_clean_frame(words[0]).is_some() {
            callsite = words[0];
        } else {
            continue;
        }
        if !is_call_site_like(callsite) {
            continue;
        }
        frame.module = module_of_call_site(callsite);
        if let Some((_, symbol)) = callsite.split_once('!') {
            let (function, offset) = symbol
                .rsplit_once("+0x")
                .map(|(f, o)| (f, canonical_address(o)))
                .unwrap_or((symbol, None));
            field_truncated |= function.len() > 256;
            frame.function = Some(bounded_bytes(function, 256));
            frame.displacement = offset;
        } else if let Some((_, offset)) = callsite.split_once("+0x") {
            frame.module_rva = canonical_address(offset);
        } else {
            frame.instruction_pointer = canonical_address(callsite);
        }
        if total == 0 && frame.instruction_pointer.is_none() {
            frame.instruction_pointer = fault_address.map(str::to_owned);
        }
        if let Some(module) = frame
            .module
            .as_deref()
            .and_then(|name| modules.iter().find(|m| modules_eq(&m.module, name)))
        {
            frame.resolution = module.quality;
        }
        total += 1;
        if frames.len() < report::MAX_FRAMES {
            frames.push(frame);
        }
    }
    (frames, total, field_truncated)
}

fn attach_dump_modules(capture: &mut ReportCapture, path: &Path) {
    match crate::symbols::read_minidump_modules(path) {
        Ok(modules) => {
            for symbol in &mut capture.symbols.modules {
                if let Some(module) = modules.iter().find(|module| {
                    module.base
                        == symbol
                            .image_base
                            .as_deref()
                            .and_then(parse_addr)
                            .unwrap_or(u64::MAX)
                }) {
                    symbol.expected_pdb = module.pdb.clone();
                    symbol.evidence_refs.push("dump-module-identities".into());
                    if symbol
                        .timestamp
                        .as_deref()
                        .and_then(parse_addr)
                        .is_some_and(|stamp| stamp != u64::from(module.timestamp))
                        || symbol
                            .image_size
                            .as_deref()
                            .and_then(parse_addr)
                            .is_some_and(|size| size != u64::from(module.size))
                    {
                        symbol.quality = SymbolQuality::Mismatched;
                        capture.symbols.limitations.push(format!(
                            "{} image metadata differs from the minidump module identity",
                            symbol.module
                        ));
                    }
                }
            }
            let inventory: Vec<Value> = capture
                .symbols
                .modules
                .iter()
                .map(
                    |m| json!({"module":m.module,"base":m.image_base,"expectedPdb":m.expected_pdb}),
                )
                .collect();
            let raw = serde_json::to_string(
                &json!({"dumpModuleCount":modules.len(),"selected":inventory}),
            )
            .unwrap_or_default();
            let (text, truncated) = evidence_text(&raw);
            capture.evidence.push(Evidence { id:"dump-module-identities".into(),command:"Read minidump ModuleList and RSDS CodeView identities from the SHA-256-verified pipeline input".into(),status:if truncated {CaptureStatus::Truncated}else{CaptureStatus::Present},text,truncated,error:None });
            capture.completeness.truncated |= truncated;
        }
        Err(error) => {
            capture
                .symbols
                .limitations
                .push(format!("Expected PDB identity unavailable: {error}"));
            capture.evidence.push(Evidence {
                id: "dump-module-identities".into(),
                command: "Read minidump ModuleList and RSDS CodeView identities".into(),
                status: if error.contains("no module-list") {
                    CaptureStatus::Absent
                } else {
                    CaptureStatus::Failed
                },
                text: String::new(),
                truncated: false,
                error: Some(bounded_bytes(&error, 1024)),
            });
        }
    }
}

fn apply_symbol_quality(capture: &mut ReportCapture) {
    for frame in &mut capture.stack.frames {
        if let Some(module) = frame.module.as_deref().and_then(|name| {
            capture
                .symbols
                .modules
                .iter()
                .find(|m| modules_eq(&m.module, name))
        }) {
            frame.resolution = module.quality;
            if frame.index == 0 {
                if let (Some(ip), Some(base), Some(size)) = (
                    frame.instruction_pointer.as_deref().and_then(parse_addr),
                    module.image_base.as_deref().and_then(parse_addr),
                    module.image_size.as_deref().and_then(parse_addr),
                ) {
                    if let Some(rva) = ip.checked_sub(base).filter(|rva| *rva < size) {
                        frame.module_rva = Some(format!("0x{rva:x}"));
                    }
                }
            }
            if module.quality == SymbolQuality::Mismatched {
                frame.function = None;
                frame.source_file = None;
                frame.source_line = None;
                frame.displacement = None;
            }
        }
    }
}

fn local_pdb_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 7
        && bytes.len() <= 2048
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
        && !path[2..].contains([':', '\0', '\r', '\n'])
        && path.to_ascii_lowercase().ends_with(".pdb")
}

fn base64_utf16(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for part in bytes.chunks(3) {
        let bits = (u32::from(part[0]) << 16)
            | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
            | u32::from(*part.get(2).unwrap_or(&0));
        result.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
        result.push(if part.len() > 1 {
            ALPHABET[((bits >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if part.len() > 2 {
            ALPHABET[(bits & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

// Read only MSF header, bounded stream directory and 28 Info-stream bytes.
// Paths arrive as escaped PowerShell literals inside EncodedCommand, never as
// remote-shell syntax. The probe has no write operations and no shell tools.
const PDB_METADATA_PROBE: &str = r#"
$ErrorActionPreference='Stop'
function U32($b,$n) { [BitConverter]::ToUInt32($b,$n) }
function ReadAt($s,[long]$o,[int]$n) {
 if($o -lt 0 -or $n -lt 0 -or $n -gt 8388608 -or $o+$n -gt $s.Length){throw 'PDB offset/budget'}
 [void]$s.Seek($o,[IO.SeekOrigin]::Begin)
 $b=New-Object byte[] $n; $read=0
 while($read -lt $n){$got=$s.Read($b,$read,$n-$read);if($got -eq 0){throw 'short PDB'};$read+=$got}
 return ,$b
}
function PdbIdentity($path) {
 $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($path))
 if($drive.DriveType -eq [IO.DriveType]::Network){throw 'Network PDB paths are disabled'}
 $s=[IO.File]::OpenRead($path)
 try {
  $h=ReadAt $s 0 56
  if([Text.Encoding]::ASCII.GetString($h,0,24) -ne 'Microsoft C/C++ MSF 7.00'){throw 'unsupported PDB'}
  $page=[long](U32 $h 32);$length=[long](U32 $h 44);$map=[long](U32 $h 52)
  if($page -lt 512 -or $page -gt 65536 -or ($page -band ($page-1)) -ne 0 -or $length -gt 8388608){throw 'PDB budget'}
  $blocks=[int][Math]::Ceiling($length/$page)
  if($blocks -gt $page/4){throw 'PDB directory map budget'}
  $indices=ReadAt $s ($map*$page) ($blocks*4)
  $directory=New-Object byte[] ([int]$length)
  for($i=0;$i -lt $blocks;$i++){
   $n=[int][Math]::Min($page,$length-$i*$page)
   $part=ReadAt $s (([long](U32 $indices ($i*4)))*$page) $n
   [Array]::Copy($part,0,$directory,[int]($i*$page),$n)
  }
  $count=[long](U32 $directory 0);$zero=[long](U32 $directory 4);$size=[long](U32 $directory 8)
  if($count -lt 2 -or $count -gt 1000000 -or $size -lt 28 -or $size -eq 4294967295){throw 'PDB Info missing'}
  $skip=0;if($zero -ne 4294967295){$skip=[long][Math]::Ceiling($zero/$page)}
  $at=4+$count*4+$skip*4
  if($at+4 -gt $directory.Length){throw 'PDB Info map missing'}
  $info=ReadAt $s (([long](U32 $directory ([int]$at)))*$page) 28
  $g=[guid]::new([byte[]]($info[12..27]))
  return @{guid=$g.ToString('D');age=(U32 $info 8)}
 } finally { $s.Dispose() }
}
"#;

impl<T: ExecTransport> SshCdbRunner<T> {
    async fn qualify_pdbs(&self, capture: &mut ReportCapture, deadline: Instant) {
        let mut rejected_paths = 0;
        let mut paths: Vec<(String, String)> = capture
            .symbols
            .modules
            .iter()
            .filter(|m| m.expected_pdb.is_some())
            .filter_map(|m| {
                let path = m.pdb_path.as_ref()?;
                if !local_pdb_path(path) {
                    rejected_paths += 1;
                    return None;
                }
                Some((m.module.clone(), path.clone()))
            })
            .collect();
        if rejected_paths > 0 {
            capture.symbols.limitations.push(format!("{rejected_paths} PDB metadata path(s) rejected: only local absolute drive paths are permitted"));
        }
        if paths.is_empty() {
            return;
        }
        let relevant: HashSet<String> = capture
            .stack
            .frames
            .iter()
            .filter_map(|f| f.module.as_deref())
            .map(normalize_module)
            .collect();
        paths.sort_by_key(|(name, _)| !relevant.contains(&normalize_module(name)));
        let Ok(remaining) = remaining_budget("PDB metadata probe", deadline) else {
            capture
                .symbols
                .limitations
                .push("PDB identity probe omitted: run deadline exhausted".into());
            return;
        };
        let Some(budget) = remaining
            .checked_sub(Duration::from_millis(50))
            .filter(|b| *b > Duration::from_millis(50))
        else {
            capture.symbols.limitations.push(
                "PDB identity probe omitted to preserve the acquired report at the run deadline"
                    .into(),
            );
            return;
        };
        let budget = budget.min(Duration::from_secs(15));
        let mut script = PDB_METADATA_PROBE.to_owned();
        let mut omitted = 0;
        for (module, path) in &paths {
            let module = module.replace('\'', "''");
            let path = path.replace('\'', "''");
            // EncodedCommand must also fit Windows' command-line bound.
            if script.len() + module.len() + path.len() + 300 > 8192 {
                omitted += 1;
                continue;
            }
            let _ = writeln!(
                script,
                "try {{$r=PdbIdentity '{path}';@{{module='{module}';guid=$r.guid;age=$r.age}}|ConvertTo-Json -Compress}} catch {{@{{module='{module}';error='PDB Info stream unavailable'}}|ConvertTo-Json -Compress}}"
            );
        }
        if omitted > 0 {
            capture.symbols.limitations.push(format!("{omitted} loaded-PDB probes omitted to fit the bounded remote command; stack-referenced modules are prioritized"));
        }
        let encoded = base64_utf16(&script);
        let result = tokio::time::timeout(
            budget,
            self.transport.exec_bounded(
                "powershell.exe",
                &[
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    &encoded,
                ],
                None,
                budget,
                PDB_METADATA_OUTPUT_CAP,
            ),
        )
        .await;
        let output = match result {
            Ok(Ok(output)) if output.success() => output,
            _ => {
                capture.symbols.limitations.push("Independent loaded-PDB identity acquisition failed or timed out; debugger labels remain unverified".into());
                return;
            }
        };
        let raw = String::from_utf8_lossy(&output.stdout);
        let (text, capped) = evidence_text(&raw);
        let id = "pdb-info";
        capture.evidence.push(Evidence { id:id.into(), command:"Read loaded PDB MSF7 Info stream 1 (GUID and age), read-only bounded metadata probe".into(),status:if capped {CaptureStatus::Truncated}else{CaptureStatus::Present},text,truncated:capped,error:None });
        capture.completeness.truncated |= capped;
        let mut verified_files = 0;
        let mut failed_files = 0;
        for line in raw.lines().take(report::MAX_MODULES) {
            let Ok(value) =
                serde_json::from_str::<Value>(line.trim().trim_start_matches('\u{feff}'))
            else {
                continue;
            };
            let Some(name) = value["module"].as_str() else {
                continue;
            };
            if value["error"].is_string() {
                failed_files += 1;
            }
            let Some(module) = capture
                .symbols
                .modules
                .iter_mut()
                .find(|m| m.module == name)
            else {
                continue;
            };
            let Some(guid) = value["guid"].as_str().filter(|s| {
                s.len() == 36
                    && s.bytes()
                        .filter(|b| *b != b'-')
                        .all(|b| b.is_ascii_hexdigit())
            }) else {
                continue;
            };
            let Some(age) = value["age"].as_u64().and_then(|n| u32::try_from(n).ok()) else {
                continue;
            };
            verified_files += 1;
            module.loaded_pdb = Some(report::PdbIdentity {
                guid: guid.to_ascii_lowercase(),
                age,
            });
            if module.quality != SymbolQuality::Mismatched {
                module.quality = crate::symbols::qualify(
                    module.expected_pdb.as_ref(),
                    module.loaded_pdb.as_ref(),
                    module.quality,
                );
            }
            module.evidence_refs.push(id.into());
        }
        if failed_files > 0 || verified_files == 0 {
            if let Some(evidence) = capture.evidence.iter_mut().find(|e| e.id == id) {
                evidence.status = if verified_files == 0 {
                    CaptureStatus::Failed
                } else {
                    CaptureStatus::Partial
                };
                evidence.error = Some(format!(
                    "{failed_files} loaded-PDB metadata read(s) failed; {verified_files} identity record(s) acquired"
                ));
            }
        }
        for frame in &mut capture.stack.frames {
            if let Some(module) = frame.module.as_deref().and_then(|name| {
                capture
                    .symbols
                    .modules
                    .iter()
                    .find(|m| modules_eq(&m.module, name))
            }) {
                frame.resolution = module.quality;
                // A mismatching PDB cannot supply qualified function/source
                // attribution. Addresses and the command transcript survive.
                if module.quality == SymbolQuality::Mismatched {
                    frame.function = None;
                    frame.source_file = None;
                    frame.source_line = None;
                    frame.displacement = None;
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod process_tests {
    use super::*;
    #[test]
    fn pdb_probe_accepts_local_drive_paths_and_rejects_remote_or_device_paths() {
        assert!(local_pdb_path("D:/safe/symbols/app.pdb"));
        assert!(local_pdb_path("C:\\symbols\\O'Brien.pdb"));
        for path in [
            "\\\\server\\share\\app.pdb",
            "https://server/app.pdb",
            "\\\\?\\D:\\app.pdb",
            "D:/app:secret.pdb",
            "D:/app\n.pdb",
        ] {
            assert!(!local_pdb_path(path), "{path}");
        }
    }
    #[tokio::test]
    async fn request_cap_limits_production_transport_configuration_and_actual_read() {
        for (transport_cap, request_cap, expected) in [(32, 4, 4), (2, 4, 2)] {
            let transport = SshTransport::new("unused-test-host")
                .with_output_cap(transport_cap)
                .for_output_cap(request_cap)
                .unwrap();
            let mut child = Command::new("sh")
                .args(["-c", "printf '123456789'; exec sleep 30"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let (stdout, stderr, _, capped) = tokio::time::timeout(
                Duration::from_secs(1),
                pump_child(&mut child, transport.output_cap),
            )
            .await
            .expect("raw cap must kill promptly")
            .unwrap();
            assert_eq!(stdout.len(), expected);
            assert!(stderr.is_empty());
            assert!(capped);
        }
        assert!(
            SshTransport::new("unused-test-host")
                .for_output_cap(0)
                .is_err()
        );
    }
    #[tokio::test]
    async fn capped_stdout_does_not_wait_for_stderr_eof() {
        let mut child = Command::new("sh")
            .args(["-c", "printf '123456789'; exec sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (_, _, _, capped) =
            tokio::time::timeout(Duration::from_secs(1), pump_child(&mut child, 4))
                .await
                .expect("cap must terminate promptly")
                .unwrap();
        assert!(capped);
    }
    #[tokio::test]
    async fn capped_stderr_does_not_wait_for_stdout_eof() {
        let mut child = Command::new("sh")
            .args(["-c", "printf '123456789' >&2; exec sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (_, _, _, capped) =
            tokio::time::timeout(Duration::from_secs(1), pump_child(&mut child, 4))
                .await
                .expect("cap must terminate promptly")
                .unwrap();
        assert!(capped);
    }
    #[tokio::test]
    async fn simultaneous_short_streams_share_one_acquisition_budget() {
        let mut child = Command::new("sh")
            .args(["-c", "printf '123456'; printf 'abcdef' >&2; exec sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (stdout, stderr, _, capped) =
            tokio::time::timeout(Duration::from_secs(1), pump_child(&mut child, 8))
                .await
                .expect(
                    "combined cap must terminate promptly even though neither stream reached it",
                )
                .unwrap();
        assert_eq!(stdout.len() + stderr.len(), 8);
        assert!(!stdout.is_empty() && !stderr.is_empty());
        assert!(capped);
    }
    #[tokio::test]
    async fn child_wait_after_stdout_eof_stays_inside_caller_deadline() {
        let mut child = Command::new("sh")
            .args(["-c", "exec 1>&-; exec 2>&-; exec sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), pump_child(&mut child, 1024))
                .await
                .is_err()
        );
        let _ = child.kill().await;
    }
}

/// Essential acquisition deliberately has no HTTP symbol path. `-y` points at
/// the per-run workspace, which contains only the staged dump and scripts.
/// Symbol refinement runs separately after this process has returned evidence.
pub fn essential_script() -> String {
    let mut script = String::from("$$ DumpAnalyzer essential evidence (v2)\n");
    for (id, command) in [
        ("target", "version; vertarget; ~; |"),
        ("exception", ".exr -1"),
        ("context", ".ecxr; ~.; r"),
        ("instruction", "u @$ip L0n16"),
        ("stack-before-symbols", "kn 0n128"),
        ("modules-initial", "lm"),
    ] {
        let _ = writeln!(script, ".echo DA_BEGIN:{id}\n{command}\n.echo DA_END:{id}");
    }
    script.push_str("q\n");
    script
}
fn symbols_script(path: &str) -> String {
    let mut script = String::from("$$ DumpAnalyzer optional symbol refinement (v2)\n");
    let _ = writeln!(script, ".sympath {path}");
    for (id, command) in [
        ("symbols-load", ".lines -e; .reload /f"),
        ("modules", "lmv"),
        ("stack", ".lines -e; .ecxr; ~.; kn 0n128"),
    ] {
        let _ = writeln!(script, ".echo DA_BEGIN:{id}\n{command}\n.echo DA_END:{id}");
    }
    script.push_str("q\n");
    script
}
impl<T: ExecTransport> SshCdbRunner<T> {
    async fn refine_symbols(
        &self,
        request: &RunRequest,
        plan: &RemotePlan,
        deadline: Instant,
        baseline: &mut RunOutput,
    ) {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        let Some(budget) = remaining
            .checked_sub(Duration::from_millis(100))
            .filter(|b| !b.is_zero())
        else {
            mark_refinement_failure(
                baseline,
                CaptureStatus::TimedOut,
                "Optional symbol refinement omitted: acquisition consumed the run budget",
            );
            return;
        };
        let transcript_limit = request
            .bounds
            .max_output_bytes
            .min(report::MAX_TRANSCRIPT_BYTES);
        let baseline_bytes = baseline.facts["log"]["bytes"]
            .as_u64()
            .unwrap_or(0)
            .min(usize::MAX as u64) as usize;
        let mut optional_bounds = request.bounds;
        optional_bounds.max_output_bytes = transcript_limit.saturating_sub(baseline_bytes);
        if optional_bounds.max_output_bytes == 0 {
            mark_refinement_failure(
                baseline,
                CaptureStatus::Truncated,
                "Optional symbol refinement omitted: essential output exhausted the shared transcript budget",
            );
            return;
        }
        let result = tokio::time::timeout(budget, async {
            tokio::fs::write(
                &plan.local_symbols_script,
                symbols_script(&request.symbol_path),
            )
            .await
            .map_err(|e| AnalyzerError::Runner(format!("writing optional symbol script: {e}")))?;
            self.transport
                .put_file(&plan.local_symbols_script, &plan.remote_symbols_script)
                .await?;
            let output = self
                .transport
                .exec_bounded(
                    &self.cdb_program,
                    &[
                        "-z",
                        &plan.remote_dump,
                        "-cf",
                        &plan.remote_symbols_script,
                        "-y",
                        &plan.remote_dir,
                    ],
                    None,
                    budget,
                    optional_bounds.max_output_bytes,
                )
                .await?;
            classify_output(&optional_bounds, output)
        })
        .await;
        let optional = match result {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                mark_refinement_failure(
                    baseline,
                    CaptureStatus::Failed,
                    &format!("Optional symbol refinement failed: {error}"),
                );
                return;
            }
            Err(_) => {
                mark_refinement_failure(
                    baseline,
                    CaptureStatus::TimedOut,
                    "Optional symbol refinement timed out; essential exception/context/stack evidence is retained",
                );
                return;
            }
        };
        // Essential acquisition is deliberately offline (essential_script
        // carries no store), so a baseline symbols-missing verdict reflects
        // acquisition order, not evidence. When refinement parses the same
        // dump as Completed, it is the qualified result: upgrade. The refined
        // log still contains open-failure or corruption markers when the dump
        // itself is at fault, so those baselines stay failed. Refinement
        // failures returned earlier and never touch the baseline outcome.
        let refined_outcome = optional.outcome;
        let Some(mut extra) = optional.capture else {
            mark_refinement_failure(
                baseline,
                CaptureStatus::Failed,
                "Optional symbol refinement produced no structured evidence",
            );
            return;
        };
        let Some(capture) = &mut baseline.capture else {
            return;
        };
        if !extra.symbols.modules.is_empty() {
            capture.symbols = extra.symbols;
        }
        if !extra.stack.frames.is_empty() {
            extra.stack.thread_id = capture.context.thread_id.clone();
            if capture.context.source == ContextSource::Exception {
                extra
                    .stack
                    .limitations
                    .retain(|s| !s.starts_with("Stack belongs to the initial/fallback context"));
            }
            if let Some(frame) = extra.stack.frames.first_mut() {
                frame.instruction_pointer = if capture.context.source == ContextSource::Exception {
                    capture.exception.address.clone()
                } else {
                    None
                };
            }
            capture.stack = extra.stack;
        } else {
            capture.stack.limitations.push(
                "Symbol refinement produced no final stack; preliminary addresses retained".into(),
            );
        }
        for evidence in extra
            .evidence
            .into_iter()
            .filter(|e| ["symbols-load", "modules", "stack"].contains(&e.id.as_str()))
        {
            capture.evidence.retain(|e| e.id != evidence.id);
            capture.evidence.push(evidence);
        }
        capture.completeness.truncated |= extra.completeness.truncated;
        if extra.completeness.truncated {
            capture
                .completeness
                .omissions
                .push("Optional symbol-refinement output was truncated".into());
        }
        if baseline.outcome == ReportOutcome::Failed && refined_outcome == ReportOutcome::Completed
        {
            baseline.outcome = ReportOutcome::Completed;
        }
        baseline.summary = optional.summary;
        baseline.facts = optional.facts;
    }
}
fn mark_refinement_failure(baseline: &mut RunOutput, status: CaptureStatus, message: &str) {
    if let Some(capture) = &mut baseline.capture {
        capture
            .completeness
            .omissions
            .push(bounded_bytes(message, 1024));
        capture
            .stack
            .limitations
            .push("Final symbol-resolved stack unavailable; preliminary stack retained".into());
        capture.evidence.retain(|e| e.id != "symbols-load");
        capture.evidence.push(Evidence {
            id: "symbols-load".into(),
            command: "Optional .reload /f, lmv, and final numbered stack in a separate CDB process"
                .into(),
            status,
            text: String::new(),
            truncated: false,
            error: Some(bounded_bytes(message, 1024)),
        });
    }
}
