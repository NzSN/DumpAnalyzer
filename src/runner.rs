//! Tool runner: bounded CDB execution over an SSH transport, and CDB output
//! parsing (task C2).
//!
//! [`SshCdbRunner`] stages a dump to the remote Windows analysis box, writes
//! a fixed, bounded CDB triage script, executes CDB under [`RunBounds`] hard
//! caps, and parses the bounded console log into a [`RunOutput`]. CDB never
//! runs on the DumpLedger host (docs/analyzer-design.md, "Security
//! considerations").
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

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

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
/// Default `scp` transfer timeout for the SSH transport.
const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(900);
/// Wall-time budget for the best-effort remote workspace cleanup.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
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
    /// immediately when `None`; the child is killed after `timeout` (the
    /// returned error is then `AnalyzerError::Transport`).
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<TransportOutput>;

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
    /// stream reaches it).
    pub fn with_output_cap(mut self, bytes: usize) -> Self {
        self.output_cap = bytes.max(1);
        self
    }

    /// Override the `scp` transfer timeout.
    pub fn with_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.transfer_timeout = timeout;
        self
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

        if let Some(input) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                pipe.write_all(input).await.map_err(|err| {
                    AnalyzerError::Transport(format!("ssh {}: writing stdin: {err}", self.target))
                })?;
                drop(pipe);
            }
        }

        let cap = self.output_cap;
        match tokio::time::timeout(timeout, pump_child(&mut child, cap)).await {
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

/// Read the child's stdout and stderr concurrently, each capped, then reap
/// it (killing first when a stream hit the cap).
async fn pump_child(
    child: &mut tokio::process::Child,
    cap: usize,
) -> io::Result<(Vec<u8>, Vec<u8>, ExitStatus, bool)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;

    let (stdout, stderr) = tokio::join!(read_capped(stdout, cap), read_capped(stderr, cap));
    let (stdout, stdout_capped) = stdout?;
    let (stderr, stderr_capped) = stderr?;
    let capped = stdout_capped || stderr_capped;
    if capped {
        let _ = child.kill().await;
    }
    let status = child.wait().await?;
    Ok((stdout, stderr, status, capped))
}

/// Read at most `cap` bytes from a stream.
async fn read_capped<R: AsyncRead + Unpin>(reader: R, cap: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    reader.take(cap as u64).read_to_end(&mut buf).await?;
    let capped = buf.len() >= cap;
    Ok((buf, capped))
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
    if module.is_empty() || !module.chars().all(is_module_name_char) {
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
    if name.is_empty() || !name.chars().all(is_module_name_char) {
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

/// The v1 tool runner: CDB over an [`ExecTransport`] against the analysis box.
#[derive(Debug)]
pub struct SshCdbRunner<T: ExecTransport> {
    transport: T,
    remote_base: String,
    cdb_program: String,
}

impl<T: ExecTransport> SshCdbRunner<T> {
    /// Create a runner over `transport`, using [`DEFAULT_REMOTE_BASE`] as the
    /// remote workspace root and `cdb` as the debugger program.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
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

        let script = triage_script(&request.symbol_path);
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
            remote_dir,
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
        ];
        let output = self
            .transport
            .exec(&self.cdb_program, &args, None, budget)
            .await
            .map_err(|err| AnalyzerError::Runner(format!("cdb execution failed: {err}")))?;

        classify_output(&request.bounds, output)
    }

    /// Best-effort removal of the remote run directory (a wiped workspace is
    /// part of the security model); failures are logged, never propagated.
    async fn cleanup_remote(&self, remote_dir: &str) {
        let response = self
            .transport
            .exec(
                "rm",
                &["-rf", &bash_path(remote_dir)],
                None,
                CLEANUP_TIMEOUT,
            )
            .await;
        match response {
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
        }
    }
}

#[async_trait]
impl<T: ExecTransport> ToolRunner for SshCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        let plan = self.plan(&request)?;
        let deadline = Instant::now() + request.bounds.wall_timeout;

        let budget = match remaining_budget("create remote workspace", deadline) {
            Ok(budget) => budget,
            Err(err) => return Err(err),
        };
        self.ensure_remote_dir(&plan.remote_dir, budget).await?;

        let result = self.analyze(&request, &plan, deadline).await;
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
    local_script: PathBuf,
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

/// The fixed, bounded v1 triage script (`.sympath`, `.reload`, `.ecxr`,
/// `kc`, `lm`, `|`, `q`).
fn triage_script(symbol_path: &str) -> String {
    let mut script = String::new();
    script.push_str("$$ DumpAnalyzer CDB triage script (v1)\n");
    let _ = writeln!(script, ".sympath {symbol_path}");
    script.push_str(".reload\n");
    script.push_str(".ecxr\n");
    script.push_str("kc\n");
    script.push_str("lm\n");
    script.push_str("|\n");
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
    let (log, truncated) = truncate_utf8(raw, bounds.max_output_bytes);

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
