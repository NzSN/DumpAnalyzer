//! Shared kernel types (integrator-owned; task R0).
//!
//! Every module codes against these. They pin the cross-module contracts so
//! parallel tasks never redefine shared vocabulary. Wire-facing shapes live
//! in `wire`; these are the in-process domain types.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, AnalyzerError>;

/// Process-wide error taxonomy. `is_transient` is the retry classifier:
/// transient errors consume the job's bounded retry budget; everything else
/// is terminal for the job (docs/analyzer-design.md, "Outcome vs.
/// infrastructure failure" — a *toolchain* verdict of "failed" is a report,
/// not an error, and never passes through this type).
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("server status {status}: {code:?}")]
    Server { status: u16, code: Option<String> },
    #[error("decode: {0}")]
    Decode(String),
    #[error("state: {0}")]
    State(String),
    #[error("runner: {0}")]
    Runner(String),
    #[error("integrity: {0}")]
    Integrity(String),
}

impl AnalyzerError {
    /// Retry classification. Transport failures, runner (toolchain
    /// infrastructure) failures, and server 5xx/408/429 are transient;
    /// 4xx (401/404/invalid_request), decode, state, integrity, and config
    /// errors are terminal for the job.
    pub fn is_transient(&self) -> bool {
        match self {
            AnalyzerError::Transport(_) | AnalyzerError::Runner(_) => true,
            AnalyzerError::Server { status, .. } => {
                *status == 408 || *status == 429 || *status >= 500
            }
            _ => false,
        }
    }
}

/// Job lifecycle phases, mirroring `JobStates` in specs/DumpAnalyzer.tla
/// (the spec's "none" is the absence of a job row). Stored in SQLite as the
/// kebab-case serde spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobPhase {
    Discovered,
    Claimed,
    Fetching,
    Staged,
    Analyzing,
    Reporting,
    Done,
    Dropped,
    Failed,
}

impl JobPhase {
    /// Phases whose staging is volatile: a crash resets them to `Claimed`
    /// (spec: CrashReset). `Reporting` persists its pin and re-submits.
    pub fn is_volatile(self) -> bool {
        matches!(
            self,
            JobPhase::Fetching | JobPhase::Staged | JobPhase::Analyzing
        )
    }
}

/// Job identity, mirroring the server-side analysis-report identity
/// (dumpId, analyzer.name, analyzer.version, kind, inputSha256) with the
/// analyzer name carried by configuration. Local dedup and server idempotent
/// replay align on this tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobIdentity {
    pub dump_id: String,
    pub input_sha256: String,
    pub kind: String,
    pub analyzer_version: String,
}

/// Which tool-runner provider the daemon wires at boot
/// (`DUMP_ANALYZER_RUNNER`). `CdbSsh` is the deterministic CDB script runner;
/// `ClaudeCdb` drives CDB through the `claude` CLI agent (decision
/// 2026-10-13). Both execute CDB on the analysis box over SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerKind {
    CdbSsh,
    ClaudeCdb,
}

/// Verdict outcome; wire spelling matches the server's AnalysisReport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportOutcome {
    Completed,
    Failed,
}

/// One bounded tool-runner execution request.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// Staged, sha256-verified dump bytes (read-only for the runner).
    pub dump_path: PathBuf,
    /// SymSrv path expression for the toolchain, e.g.
    /// `SRV*<cache>*https://<host>/symbols`. Contains no credentials.
    pub symbol_path: String,
    /// Per-run workspace, wiped by the agent after the run.
    pub work_dir: PathBuf,
    pub bounds: RunBounds,
}

/// Hard caps for one run; exceeding any cap fails the run, never hangs it.
#[derive(Debug, Clone, Copy)]
pub struct RunBounds {
    pub wall_timeout: Duration,
    pub max_output_bytes: usize,
    pub max_workspace_bytes: u64,
}

/// What the tool runner produced. `outcome: Failed` here is a *verdict*
/// (the dump could not be analyzed), which becomes a report; runner
/// infrastructure failures are `Err(AnalyzerError::Runner(_))` instead.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub outcome: ReportOutcome,
    /// Plain text, bounded, no raw dump memory (design: Security).
    pub summary: String,
    /// Structured facts, bounded; must fit the server's 16 KiB body envelope
    /// together with the rest of the report.
    pub facts: serde_json::Value,
}

/// The tool-runner seam (docs/analyzer-design.md, "Tool runner"). The agent
/// talks only to this trait; v1's implementation is the SSH/CDB runner
/// (task C2). Test doubles implement it in-memory.
#[async_trait::async_trait]
pub trait ToolRunner: Send + Sync {
    async fn run(&self, request: RunRequest) -> Result<RunOutput>;
}
