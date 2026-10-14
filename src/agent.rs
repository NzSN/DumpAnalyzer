//! The internal analysis agent: the per-job pipeline driver (task C1).
//!
//! One [`Agent`] runs one [`JobIdentity`] at a time through the stage
//! machine of `specs/DumpAnalyzer.tla` and docs/analyzer-design.md
//! ("Agent pipeline"):
//!
//! ```text
//! claimed → fetching → staged → analyzing → reporting → done
//!              ↑           ↑          ↑                  ↓
//!              └───────────┴──────────┘            dropped / failed
//! ```
//!
//! Every stage boundary is persisted in the job table *before* the stage's
//! side effects begin, so a crash recovers from the boundary rather than
//! from a guess (spec: `BeginFetch`/`Stage`/`VerifyOk`/`AnalyzeCompletes`/
//! `SubmitAccept` are all durable transitions):
//!
//! * **Fetch + verify.** Dump bytes are content-addressed by the pinned
//!   `inputSha256` under `<state>/bytes/` and revalidated with an
//!   `If-None-Match` conditional GET (`304` reuses the cached bytes). The
//!   staged file is re-hashed and compared to the job pin before any
//!   toolchain runs ("a cache hit skips the download, never the sha256
//!   verification"); a mismatch discards the bytes and refetches.
//! * **Bounded cache.** Every cache write trims the content-addressed byte
//!   cache back to `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES` by evicting
//!   least-recently-used entries (index row first, then file); the entry
//!   just written always survives the trimming call because it is the bytes
//!   the in-flight fetch is about to hand to the toolchain.
//! * **Analyze.** The verified dump path, the SymSrv symbol path, and a
//!   per-run `tempfile` workspace under the state dir are handed to the
//!   [`ToolRunner`] seam. The workspace is wiped as soon as the run
//!   finishes, fails, or unwinds.
//! * **Report.** A parsed [`RunOutput`] — including `outcome: Failed`,
//!   which is a *verdict*, not an error — is handed to the [`VerdictSink`]
//!   seam after the job is persisted as `reporting`.
//! * **Bounded attempts.** Transient failures (tool-runner infrastructure,
//!   fetch transport/5xx) are charged against the job's persistent attempt
//!   counter; when the counter reaches [`MAX_ATTEMPTS`] the job settles
//!   `failed` with no report (spec: `RunnerFailed`/`VerifyCorrupt` bounded
//!   by `MaxAttempts`, `JobFailed` at the bound). The counter is durable
//!   across crashes — `CrashReset` deliberately preserves it.
//! * **Purges.** A `404`/`410` at any server touch settles the job
//!   `dropped`, never retried (spec: `FetchPurged`/`SubmitPurged`).
//!
//! [`Agent::recover`] implements the spec's `Crash`/`CrashReset`: jobs left
//! in volatile phases (`fetching`/`staged`/`analyzing`) go back to `claimed`
//! for a re-fetch with byte re-verification; `reporting` jobs are left
//! untouched for the verdict writer's reconciliation.
//!
//! The agent never touches `src/runner.rs` or `src/verdict.rs` internals:
//! both are behind the [`ToolRunner`] and [`VerdictSink`] seams.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::client::{ContentResult, LedgerClient};
use crate::config::Config;
use crate::state::Store;
use crate::types::{
    AnalyzerError, JobIdentity, JobPhase, Result, RunOutput, RunRequest, ToolRunner,
};

/// Transient-failure budget per job; mirrors `MaxAttempts == 2` in
/// `specs/DumpAnalyzer.tla`.
///
/// The counter lives in the job row and increments on every failed attempt.
/// When it reaches this bound the attempt that would exceed the budget
/// settles the job `failed` instead (spec: `JobFailed` at `attempts =
/// MaxAttempts`), so a job performs at most `MAX_ATTEMPTS` attempts.
pub const MAX_ATTEMPTS: u32 = 2;

/// Sub-directory of the state dir holding content-addressed dump bytes.
const BYTE_CACHE_DIR: &str = "bytes";

/// Read buffer for streaming file hashing.
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

/// Write-back seam between the agent pipeline and the verdict writer
/// (task D1; wired by the integrator in D2).
///
/// The agent persists `reporting` and then calls [`VerdictSink::submit`]
/// exactly once per successful analysis with the pinned [`JobIdentity`] and
/// the parsed [`RunOutput`] (a `Failed` *outcome* is still a verdict to
/// report). The sink owns the write-back semantics and, normally, the
/// settle transition:
///
/// * `Ok(())` — the verdict is durably recorded (created, replayed, or
///   stored in local-verdict mode). The agent settles `done` if the sink
///   left the job in `reporting`.
/// * `Err(404/410)` — the dump was purged between analysis and write-back;
///   the agent settles `dropped` (spec: `SubmitPurged`).
/// * `Err(transient)` — the job stays `reporting` (durable; the writer's
///   reconciliation and post-boot replay own re-submission) and the error
///   propagates to the caller to trigger backoff.
/// * `Err(other)` — terminal local write-back failure; the agent settles
///   `failed` (no report) after logging it.
#[async_trait]
pub trait VerdictSink: Send + Sync {
    /// Submit the verdict for one completed analysis and settle the job.
    async fn submit(&self, identity: &JobIdentity, output: RunOutput) -> Result<()>;
}

/// What [`Agent::recover`] found and reset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Jobs reset from a volatile phase (`fetching`/`staged`/`analyzing`)
    /// back to `claimed` (spec: `CrashReset`), oldest first. Their attempt
    /// counters are preserved.
    pub reset_to_claimed: Vec<JobIdentity>,
}

/// Outcome of one direct pipeline attempt ([`Agent::attempt`]); the caller
/// owns retry policy. `Completed` includes `outcome: Failed` verdicts — a
/// dump that cannot be analyzed is a report, not an error.
#[derive(Debug)]
pub enum Attempt {
    Completed(RunOutput),
    Purged,
    Transient(AnalyzerError),
    Terminal(AnalyzerError),
}

/// Pipeline driver for one analyzer process; owns workspace lifecycle.
pub struct Agent {
    client: LedgerClient,
    store: Store,
    config: Config,
    runner: Arc<dyn ToolRunner>,
    verdicts: Arc<dyn VerdictSink>,
}

impl Agent {
    /// Builds an agent over the shared local state and the two seams.
    pub fn new(
        client: LedgerClient,
        store: Store,
        config: Config,
        runner: Arc<dyn ToolRunner>,
        verdicts: Arc<dyn VerdictSink>,
    ) -> Self {
        Self {
            client,
            store,
            config,
            runner,
            verdicts,
        }
    }

    /// The ledger client (read routes) for the on-demand component's
    /// detail lookup. Write-back still goes through the verdict sink only.
    pub fn client(&self) -> &LedgerClient {
        &self.client
    }

    /// Crash recovery (spec: `Crash`/`CrashReset`), run once at boot.
    ///
    /// Volatile phases (`fetching`/`staged`/`analyzing`) lose their staging
    /// on a crash: they are reset to `claimed` for a re-fetch with byte
    /// re-verification. `reporting` jobs keep their pinned identity and are
    /// left untouched for the verdict writer's reconciliation; terminal
    /// phases are untouched. The attempt counter is never reset.
    pub fn recover(store: &Store) -> Result<RecoveryReport> {
        let jobs = store.jobs();
        let mut report = RecoveryReport::default();
        for phase in [JobPhase::Fetching, JobPhase::Staged, JobPhase::Analyzing] {
            debug_assert!(phase.is_volatile());
            for (job, _) in jobs.jobs_in_phase(phase)? {
                if Self::recover_job(store, &job, phase)? {
                    report.reset_to_claimed.push(job);
                }
            }
        }
        if !report.reset_to_claimed.is_empty() {
            tracing::info!(
                count = report.reset_to_claimed.len(),
                "crash recovery reset volatile jobs to claimed"
            );
        }
        Ok(report)
    }

    /// Resets one volatile job (`fetching`/`staged`/`analyzing`) back to
    /// `claimed` (spec: `CrashReset`); returns whether a reset happened.
    /// [`Agent::recover`] applies this to every volatile job; the MBT harness
    /// drives it per job to replay the spec's per-dump reset actions.
    pub fn recover_job(store: &Store, job: &JobIdentity, phase: JobPhase) -> Result<bool> {
        if phase.is_volatile() {
            store.jobs().set_phase(job, JobPhase::Claimed)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Runs one claimed job to a terminal phase: `done`, `dropped`, or
    /// `failed`.
    ///
    /// The caller must have claimed the job first ([`crate::state::JobStore::claim_next`],
    /// or [`Agent::recover`] for jobs reset from volatile phases); anything
    /// else is a state error. Transient failures are retried inside the
    /// returned future, bounded by [`MAX_ATTEMPTS`].
    ///
    /// # Errors
    ///
    /// `Ok(())` means the job reached a terminal phase. `Err(_)` means it
    /// did not: a transient write-back failure leaves the job in `reporting`
    /// (the caller backs off, reconciliation re-submits) and store/state
    /// errors are internal failures.
    pub async fn run_job(&self, identity: &JobIdentity) -> Result<()> {
        let mut attempts = self.claimed_attempts(identity)?;

        loop {
            // --- Stage 2: fetch (spec BeginFetch/Stage/FetchPurged). ---
            self.store.jobs().set_phase(identity, JobPhase::Fetching)?;
            let staged = match self.fetch_stage(identity).await {
                Ok(path) => path,
                Err(err) if is_purge(&err) => {
                    tracing::info!(dump_id = %identity.dump_id, "dump purged at fetch; dropping job");
                    self.store.jobs().drop_job(identity)?;
                    return Ok(());
                }
                Err(err) if err.is_transient() => {
                    if !self.charge_failure(identity, &mut attempts)? {
                        tracing::warn!(
                            dump_id = %identity.dump_id,
                            error = %err,
                            attempts,
                            "fetch retries exhausted; failing job"
                        );
                        self.store.jobs().set_phase(identity, JobPhase::Failed)?;
                        return Ok(());
                    }
                    tracing::warn!(
                        dump_id = %identity.dump_id,
                        error = %err,
                        attempts,
                        "transient fetch failure; retrying"
                    );
                    self.store.jobs().set_phase(identity, JobPhase::Claimed)?;
                    continue;
                }
                Err(err) => {
                    tracing::error!(
                        dump_id = %identity.dump_id,
                        error = %err,
                        "fetch failed terminally; failing job"
                    );
                    self.store.jobs().set_phase(identity, JobPhase::Failed)?;
                    return Ok(());
                }
            };

            // --- Stage 3: verify (spec VerifyOk/VerifyCorrupt). ---
            self.store.jobs().set_phase(identity, JobPhase::Staged)?;
            let verified = match hash_file(&staged).await {
                Ok(actual) => actual == identity.input_sha256,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => return Err(state_io("hash staged dump", err)),
            };
            if !verified {
                // Local staging corruption: discard the bytes; never run the
                // toolchain on unverified input (spec VerifyCorrupt).
                let _ = tokio::fs::remove_file(&staged).await;
                if !self.charge_failure(identity, &mut attempts)? {
                    tracing::warn!(
                        dump_id = %identity.dump_id,
                        attempts,
                        "sha256 verification retries exhausted; failing job"
                    );
                    self.store.jobs().set_phase(identity, JobPhase::Failed)?;
                    return Ok(());
                }
                continue;
            }

            // --- Stage 5: execute (spec AnalyzeCompletes/RunnerFailed). ---
            self.store.jobs().set_phase(identity, JobPhase::Analyzing)?;
            let workspace = tempfile::Builder::new()
                .prefix("run-")
                .tempdir_in(&self.config.state_dir)
                .map_err(|err| {
                    AnalyzerError::State(format!(
                        "create run workspace under {}: {err}",
                        self.config.state_dir.display()
                    ))
                })?;
            let request = RunRequest {
                dump_path: staged.clone(),
                symbol_path: self.symbol_path(),
                work_dir: workspace.path().to_path_buf(),
                bounds: self.config.run_bounds(),
            };
            let outcome = self.runner.run(request).await;
            // The per-run workspace is wiped after every attempt, including
            // failed ones and early returns.
            drop(workspace);
            let output = match outcome {
                Ok(output) => output,
                Err(err) if err.is_transient() => {
                    if !self.charge_failure(identity, &mut attempts)? {
                        tracing::warn!(
                            dump_id = %identity.dump_id,
                            error = %err,
                            attempts,
                            "tool-runner retries exhausted; failing job"
                        );
                        self.store.jobs().set_phase(identity, JobPhase::Failed)?;
                        return Ok(());
                    }
                    tracing::warn!(
                        dump_id = %identity.dump_id,
                        error = %err,
                        attempts,
                        "transient tool-runner failure; re-entering claimed"
                    );
                    self.store.jobs().set_phase(identity, JobPhase::Claimed)?;
                    continue;
                }
                Err(err) => {
                    tracing::error!(
                        dump_id = %identity.dump_id,
                        error = %err,
                        "tool runner failed terminally; failing job"
                    );
                    self.store.jobs().set_phase(identity, JobPhase::Failed)?;
                    return Ok(());
                }
            };

            // --- Stage 7: report (spec SubmitAccept/Replay/Purged). ---
            self.store.jobs().set_phase(identity, JobPhase::Reporting)?;
            return self.report(identity, output).await;
        }
    }

    /// One pipeline attempt without job-table bookkeeping: fetch (byte cache
    /// plus ETag revalidation), sha256 verify against the pin, toolchain run
    /// in a per-run workspace that is always wiped. Nothing is persisted
    /// except the content-addressed byte cache; the caller owns retry
    /// policy.
    ///
    /// This is the direct-analysis building block used by the on-demand
    /// [`crate::analyzer::Analyzer`] component. [`Agent::run_job`] keeps its
    /// own phase-persisting loop for scheduled work; both share
    /// `fetch_stage`, verification, and the runner bounds.
    pub async fn attempt(&self, identity: &JobIdentity) -> Result<Attempt> {
        let staged = match self.fetch_stage(identity).await {
            Ok(path) => path,
            Err(err) if is_purge(&err) => return Ok(Attempt::Purged),
            Err(err) if err.is_transient() => return Ok(Attempt::Transient(err)),
            Err(err) => return Ok(Attempt::Terminal(err)),
        };
        let verified = match hash_file(&staged).await {
            Ok(actual) => actual == identity.input_sha256,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => return Err(state_io("hash staged dump", err)),
        };
        if !verified {
            // Local staging corruption: discard the bytes; never run the
            // toolchain on unverified input.
            let _ = tokio::fs::remove_file(&staged).await;
            return Ok(Attempt::Transient(AnalyzerError::Integrity(format!(
                "staged bytes do not match the pinned sha256 {}",
                identity.input_sha256
            ))));
        }
        let workspace = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(&self.config.state_dir)
            .map_err(|err| {
                AnalyzerError::State(format!(
                    "create run workspace under {}: {err}",
                    self.config.state_dir.display()
                ))
            })?;
        let request = RunRequest {
            dump_path: staged,
            symbol_path: self.symbol_path(),
            work_dir: workspace.path().to_path_buf(),
            bounds: self.config.run_bounds(),
        };
        let outcome = self.runner.run(request).await;
        // The per-run workspace is wiped after every attempt.
        drop(workspace);
        match outcome {
            Ok(output) => Ok(Attempt::Completed(output)),
            Err(err) if err.is_transient() => Ok(Attempt::Transient(err)),
            Err(err) => Ok(Attempt::Terminal(err)),
        }
    }

    /// Fetches the pinned bytes, preferring the byte cache and revalidating
    /// it with the cached `ETag`.
    ///
    /// A cache entry whose file is present yields a conditional GET: a `304`
    /// reuses the cached bytes, a `200` refreshes them. Without a usable
    /// cached file the GET is unconditional (there is no validator to
    /// present, and a `304` could not be honored).
    async fn fetch_stage(&self, identity: &JobIdentity) -> Result<PathBuf> {
        let sha = identity.input_sha256.as_str();
        // The pin names the cache file, so it must be a canonical sha256.
        if !is_canonical_sha256(sha) {
            return Err(AnalyzerError::Integrity(format!(
                "job pin is not 64 lowercase hex characters: {sha:?}"
            )));
        }
        let dump_id = identity.dump_id.as_str();

        if let Some(entry) = self.store.cache_index().lookup(sha)? {
            let path = PathBuf::from(&entry.path);
            let present = tokio::fs::metadata(&path)
                .await
                .map(|meta| meta.is_file())
                .unwrap_or(false);
            if present {
                let _ = self.store.cache_index().touch(sha);
                match self
                    .client
                    .get_content(dump_id, entry.etag.as_deref())
                    .await?
                {
                    ContentResult::NotModified => {
                        tracing::debug!(dump_id, "content 304; reusing cached bytes");
                        return Ok(path);
                    }
                    ContentResult::Bytes { bytes, etag } => {
                        tracing::debug!(dump_id, "content changed; refreshing byte cache");
                        return self.write_cache(sha, &bytes, &etag).await;
                    }
                }
            }
        }

        match self.client.get_content(dump_id, None).await? {
            ContentResult::NotModified => Err(AnalyzerError::Decode(
                "content GET returned 304 without a conditional request".to_owned(),
            )),
            ContentResult::Bytes { bytes, etag } => self.write_cache(sha, &bytes, &etag).await,
        }
    }

    /// Writes fetched bytes to the content-addressed cache file and indexes
    /// them under the pinned sha256, then trims the cache back to
    /// [`Config::byte_cache_max_bytes`].
    async fn write_cache(&self, sha: &str, bytes: &[u8], etag: &str) -> Result<PathBuf> {
        let dir = self.config.state_dir.join(BYTE_CACHE_DIR);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| state_io("create byte cache directory", err))?;
        let path = dir.join(sha);
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|err| state_io("write cached dump bytes", err))?;
        let byte_size = bytes.len() as u64;
        self.store
            .cache_index()
            .upsert(sha, &path.to_string_lossy(), byte_size, Some(etag))?;
        self.enforce_byte_cache_cap(sha, &path, byte_size, etag)
            .await?;
        Ok(path)
    }

    /// Enforces the byte-cache cap after a successful write.
    ///
    /// Evicts least-recently-used entries (oldest `last_used_at` first) until
    /// the indexed total fits the cap: [`CacheIndex::evict_lru`] removes the
    /// index rows in one transaction and the returned files are deleted here.
    /// Index row first, file second, means a crash in between leaves an
    /// unreferenced orphan file — recoverable by a later fetch or sweep —
    /// never an index row pointing at a missing file.
    ///
    /// The entry just written always survives the call: it is the staged
    /// input the in-flight fetch is about to verify and hand to the
    /// toolchain, so deleting it would break the run. The eviction target
    /// never exceeds the other entries' accounted bytes, and if recency ties
    /// (second-resolution `last_used_at` stamps) still put the fresh row in
    /// the oldest-first order, its file is kept and its index row restored.
    /// A single entry larger than the cap simply stays (with a warning);
    /// eviction never loops.
    async fn enforce_byte_cache_cap(
        &self,
        fresh_sha: &str,
        fresh_path: &Path,
        fresh_size: u64,
        fresh_etag: &str,
    ) -> Result<()> {
        let cache = self.store.cache_index();
        let cap = self.config.byte_cache_max_bytes;
        let total = cache.total_bytes()?;
        if total <= cap {
            return Ok(());
        }
        let excess = total - cap;
        // Never ask to free more than the other entries hold.
        let target = excess.min(total.saturating_sub(fresh_size));
        let evicted = if target == 0 {
            Vec::new()
        } else {
            cache.evict_lru(target)?
        };
        let mut fresh_evicted = false;
        for (sha256, path) in &evicted {
            if sha256.as_str() == fresh_sha {
                fresh_evicted = true;
                continue;
            }
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        path = %path,
                        error = %err,
                        "failed to delete evicted byte-cache file"
                    );
                }
            }
        }
        if fresh_evicted {
            cache.upsert(
                fresh_sha,
                &fresh_path.to_string_lossy(),
                fresh_size,
                Some(fresh_etag),
            )?;
        }

        let remaining = cache.total_bytes()?;
        if remaining > cap {
            tracing::warn!(
                cap,
                remaining,
                "byte cache remains above DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES: a single entry can exceed the cap"
            );
        }
        Ok(())
    }

    /// Submits one verdict through the [`VerdictSink`] seam and settles the
    /// job as documented on the trait.
    async fn report(&self, identity: &JobIdentity, output: RunOutput) -> Result<()> {
        match self.verdicts.submit(identity, output).await {
            Ok(()) => {
                // Settle unless the sink already did (both are `done`).
                self.settle_if_reporting(identity, JobPhase::Done)
            }
            Err(err) if is_purge(&err) => {
                tracing::info!(dump_id = %identity.dump_id, "dump purged at write-back; dropping job");
                self.store.jobs().drop_job(identity)
            }
            Err(err) if err.is_transient() => {
                tracing::warn!(
                    dump_id = %identity.dump_id,
                    error = %err,
                    "transient write-back failure; job stays reporting"
                );
                Err(err)
            }
            Err(err) => {
                tracing::error!(
                    dump_id = %identity.dump_id,
                    error = %err,
                    "write-back failed terminally; no report"
                );
                self.settle_if_reporting(identity, JobPhase::Failed)?;
                Ok(())
            }
        }
    }

    /// The SymSrv path expression for the toolchain:
    /// `SRV*<symbol cache on the analysis box>*<base>/symbols`. An unset
    /// cache directory yields the empty-cache form `SRV**<base>/symbols`.
    /// No credentials are embedded.
    fn symbol_path(&self) -> String {
        let base = self.config.base_url.as_str().trim_end_matches('/');
        let cache = self.config.symbol_cache_dir.as_deref().unwrap_or("");
        format!("SRV*{cache}*{base}/symbols")
    }

    /// Reads the persisted attempt count for a job the caller first claimed.
    fn claimed_attempts(&self, identity: &JobIdentity) -> Result<u32> {
        for (job, attempts) in self.store.jobs().jobs_in_phase(JobPhase::Claimed)? {
            if &job == identity {
                return Ok(attempts);
            }
        }
        Err(AnalyzerError::State(format!(
            "run_job requires a claimed job ({}/{}); {}/{} is not claimed",
            identity.kind, identity.analyzer_version, identity.dump_id, identity.input_sha256
        )))
    }

    /// Charges one transient failure against the bounded retry budget.
    /// Returns `false` when the budget is exhausted (the caller settles
    /// `failed` with no report).
    fn charge_failure(&self, identity: &JobIdentity, attempts: &mut u32) -> Result<bool> {
        self.store.jobs().record_attempt(identity)?;
        *attempts += 1;
        Ok(*attempts < MAX_ATTEMPTS)
    }

    /// Settles a job that is still in `reporting` (a sink may have settled
    /// it already; both paths are idempotent).
    fn settle_if_reporting(&self, identity: &JobIdentity, target: JobPhase) -> Result<()> {
        debug_assert!(matches!(target, JobPhase::Done | JobPhase::Failed));
        let jobs = self.store.jobs();
        let still_reporting = jobs
            .jobs_in_phase(JobPhase::Reporting)?
            .into_iter()
            .any(|(job, _)| &job == identity);
        if still_reporting {
            jobs.set_phase(identity, target)?;
        }
        Ok(())
    }
}

/// Streams a file through SHA-256, bounding memory regardless of dump size.
async fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// `404`/`410` at any server touch means the dump was purged (design:
/// "a `404`/`410` at any later touch means the dump was purged: the job is
/// `dropped`, never retried").
fn is_purge(err: &AnalyzerError) -> bool {
    matches!(err, AnalyzerError::Server { status, .. } if *status == 404 || *status == 410)
}

/// Canonical content pin: 64 lowercase hex characters (`wire` enforces the
/// same shape on every server-provided sha256).
fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn state_io(what: &str, err: std::io::Error) -> AnalyzerError {
    AnalyzerError::State(format!("{what}: {err}"))
}
