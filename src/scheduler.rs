//! Job scheduling and the daemon loop (task D2): the final wiring that makes
//! one `dump-analyzer` process out of every module.
//!
//! [`run`] is the daemon body and the testable entry point:
//!
//! 1. **Lock.** A single-instance lock file (`create_new`) under the state
//!    directory guards the whole lifetime (design: "Single-writer
//!    discipline"); a second process fails fast naming the lock path.
//! 2. **Boot.** [`Agent::recover`] resets volatile phases to `claimed`
//!    (spec: `CrashReset`), [`verdict::reconcile_on_boot`] settles
//!    `reporting` jobs and replays pending local verdicts, and orphaned
//!    `run-*` workspaces left by a killed run are swept. `Agent::recover`
//!    has no state-dir handle, so the sweep lives here: at boot, before
//!    scheduling, while the single-instance lock guarantees no other
//!    process's workspaces are live.
//! 3. **Scan.** `initial_scan` seeds the job table; a transient failure is
//!    retried with the capped backoff instead of killing the daemon.
//! 4. **Run.** The event-feed follower and the scheduler run under
//!    `tokio::select!`, sharing a [`CancellationToken`]. The scheduler keeps
//!    run concurrency at 1 (design v1) and never busy-spins: a transient
//!    failure backs off 1 s → 30 s and an empty job table sleeps
//!    `config.poll_interval`. The feed is supervised: a transient poll
//!    failure restarts it behind the same backoff (the sync module leaves
//!    retrying to its caller).
//! 5. **Shutdown.** SIGTERM/SIGINT ([`run_until_signal`]) cancels the token:
//!    the feed returns promptly (its half-page is replayed next boot), the
//!    scheduler finishes its in-flight job — bounded by the runner's own
//!    hard caps — and the daemon exits `Ok(())` (process exit code 0). A
//!    job interrupted by a crash instead is recovered by step 2 on the next
//!    start.
//!
//! The toolchain/verdict seams are wired here: [`VerdictWriter`] implements
//! the agent's [`VerdictSink`] with the verdict writer's
//! [`assemble`](verdict::assemble) + [`submit`](verdict::submit) pair.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::agent::{Agent, VerdictSink};
use crate::client::LedgerClient;
use crate::config::Config;
use crate::state::Store;
use crate::sync::{self, CancellationToken};
use crate::types::{AnalyzerError, JobIdentity, Result, RunOutput, ToolRunner};
use crate::verdict;

/// File name of the local state database under the state directory.
pub const STATE_DB_FILE: &str = "analyzer.sqlite";

/// File name of the single-instance lock under the state directory.
pub const STATE_LOCK_FILE: &str = "analyzer.lock";

/// Prefix of the per-run workspace directories the agent creates under the
/// state directory (`tempfile` builder prefix, `src/agent.rs`).
const WORKSPACE_PREFIX: &str = "run-";

/// The production [`VerdictSink`]: assemble the bounded submission from the
/// completed run ([`verdict::assemble`]), then write it back
/// ([`verdict::submit`]) and let the verdict writer settle the job.
///
/// The writer owns the whole write-back contract documented in
/// `src/verdict.rs`: `created`/`replayed`/local-verdict mode → `done`, a
/// purge 404 → `dropped`, `invalid_request` → `failed`, transient errors
/// propagate so the job stays `reporting` for the next reconciliation.
pub struct VerdictWriter {
    client: Arc<LedgerClient>,
    store: Store,
    config: Config,
}

impl VerdictWriter {
    /// Builds the adapter over the shared client, state store, and config.
    pub fn new(client: Arc<LedgerClient>, store: Store, config: Config) -> Self {
        Self {
            client,
            store,
            config,
        }
    }
}

#[async_trait]
impl VerdictSink for VerdictWriter {
    async fn submit(&self, identity: &JobIdentity, output: RunOutput) -> Result<()> {
        let submission = verdict::assemble(identity, output, &self.config)?;
        verdict::submit(&self.client, &self.store, identity, &submission).await
    }
}

/// Runs the daemon until `shutdown` is cancelled (or a fatal error).
///
/// See the module docs for the boot order. `runner` is the
/// [`ToolRunner`] seam; `main` passes the SSH/CDB runner, tests pass a fake.
///
/// # Errors
///
/// A held state lock, local-state failures, boot-write failures that are not
/// transient, and non-transient scan/feed errors are fatal and returned; the
/// process then exits non-zero. A clean shutdown returns `Ok(())` even when
/// it arrives mid-boot.
pub async fn run(
    mut config: Config,
    runner: Arc<dyn ToolRunner>,
    shutdown: &CancellationToken,
) -> Result<()> {
    let _lock = StateLock::acquire(&config.state_dir)?;
    tracing::info!(state_dir = %config.state_dir.display(), "state directory locked");

    let store = Store::open(config.state_dir.join(STATE_DB_FILE))?;
    resolve_token(&mut config, &store)?;
    let client = Arc::new(LedgerClient::new(&config)?);

    // --- Boot (design: "Restart reconciliation"). ---
    let recovery = Agent::recover(&store)?;
    tracing::info!(
        reset = recovery.reset_to_claimed.len(),
        "crash recovery complete"
    );
    let reconcile = verdict::reconcile_on_boot(&client, &store, &config).await?;
    tracing::info!(
        confirmed = reconcile.confirmed,
        reposted = reconcile.reposted,
        dropped = reconcile.dropped,
        local_mode = reconcile.local_mode,
        replayed = reconcile.replayed,
        abandoned = reconcile.abandoned,
        unresolved = reconcile.unresolved.len(),
        route_absent = reconcile.route_absent,
        errors = reconcile.errors.len(),
        "boot reconciliation complete"
    );
    let swept = sweep_orphaned_workspaces(&config.state_dir)?;
    if swept > 0 {
        tracing::info!(swept, "swept orphaned run workspaces");
    }
    if shutdown.is_cancelled() {
        tracing::info!("shutdown requested during boot; exiting");
        return Ok(());
    }

    scan_with_retry(&client, &store, &config, shutdown).await?;
    if shutdown.is_cancelled() {
        tracing::info!("shutdown requested during boot; exiting");
        return Ok(());
    }

    let sink = Arc::new(VerdictWriter::new(
        Arc::clone(&client),
        store.clone(),
        config.clone(),
    ));
    // `LedgerClient` is not `Clone` (module ownership), so the agent gets its
    // own instance built from the same validated config; both speak to the
    // same base URL with the same credentials.
    let agent = Agent::new(
        LedgerClient::new(&config)?,
        store.clone(),
        config.clone(),
        runner.clone(),
        sink,
    );

    tracing::info!(
        name = %config.name,
        version = %config.version,
        poll_interval_ms = config.poll_interval.as_millis() as u64,
        "dump-analyzer started"
    );

    // Read-only status UI (DUMP_ANALYZER_HTTP_ADDR; loopback by default).
    // Failure to serve is logged, not fatal: the pipeline is the product.
    if let Some(addr) = config.http_addr {
        // The on-demand component (f : DumpId -> IO Report) backs the UI's
        // POST /-/analyze; it shares the runner and store with the agent.
        let on_demand = std::sync::Arc::new(crate::analyzer::PipelineAnalyzer::new(
            LedgerClient::new(&config)?,
            store.clone(),
            config.clone(),
            runner.clone(),
        ));
        let context = crate::http::UiContext::new(&config, store.clone())
            .with_analyzer(on_demand)
            .with_rescan(crate::http::RescanDeps::new(
                std::sync::Arc::clone(&client),
                store.clone(),
                config.clone(),
            ));
        let ui_shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(err) = crate::http::serve(addr, context, ui_shutdown).await {
                tracing::error!(%err, addr = %addr, "status UI stopped with an error");
            }
        });
    }

    // The feed stops on shutdown; the scheduler then drains its in-flight
    // job before returning. A fatal error in either stops the daemon
    // immediately (a job dropped by that path is recovered at the next
    // boot, when its volatile phase is reset to `claimed`).
    let feed = supervise_feed(&client, &store, &config, shutdown);
    // DUMP_ANALYZER_SCHEDULER=off: manual operation — feed, status UI, and
    // on-demand analysis run; no job is ever claimed.
    let scheduler = scheduler_loop(&agent, &client, &store, &config, shutdown);
    tokio::pin!(feed);
    tokio::pin!(scheduler);
    let mut feed_done = false;
    let mut scheduler_done = false;
    while !(feed_done && scheduler_done) {
        tokio::select! {
            biased;
            result = &mut feed, if !feed_done => {
                feed_done = true;
                tracing::debug!("event feed stopped");
                result?;
            }
            result = &mut scheduler, if !scheduler_done => {
                scheduler_done = true;
                tracing::debug!("scheduler stopped");
                result?;
            }
        }
    }
    tracing::info!("daemon stopped cleanly");
    Ok(())
}

/// Installs SIGTERM/SIGINT handling and runs [`run`] until either arrives.
///
/// The signal streams are created (and the OS handlers installed)
/// synchronously before the first await point, so from the moment this
/// function is called the process will not die on SIGTERM/SIGINT: the signal
/// cancels the token and the daemon shuts down gracefully with exit code 0.
pub async fn run_until_signal(config: Config, runner: Arc<dyn ToolRunner>) -> Result<()> {
    let shutdown = CancellationToken::new();
    spawn_signal_watcher(&shutdown)?;
    run(config, runner, &shutdown).await
}

/// Registers the termination signals and spawns the watcher that cancels
/// `shutdown`. Unix: SIGTERM and SIGINT; elsewhere: Ctrl-C.
#[cfg(unix)]
fn spawn_signal_watcher(shutdown: &CancellationToken) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|err| AnalyzerError::State(format!("install the SIGTERM handler: {err}")))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|err| AnalyzerError::State(format!("install the SIGINT handler: {err}")))?;
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => tracing::info!("SIGTERM received; shutting down"),
            _ = interrupt.recv() => tracing::info!("SIGINT received; shutting down"),
        }
        shutdown.cancel();
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_signal_watcher(shutdown: &CancellationToken) -> Result<()> {
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for Ctrl-C");
            return;
        }
        tracing::info!("Ctrl-C received; shutting down");
        shutdown.cancel();
    });
    Ok(())
}

/// One keyset scan, retried on transient failures with the capped backoff.
///
/// A non-transient failure (401, decode, state) is returned and stops the
/// daemon: retrying a credential or contract error would only spin.
async fn scan_with_retry(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    shutdown: &CancellationToken,
) -> Result<()> {
    let mut backoff = Backoff::new();
    loop {
        match sync::initial_scan(client, store, config).await {
            Ok(inserted) => {
                tracing::info!(inserted, "initial catalog scan completed");
                return Ok(());
            }
            Err(err) if err.is_transient() => {
                let delay = backoff.next_delay();
                tracing::warn!(
                    error = %err,
                    delay_ms = delay.as_millis() as u64,
                    "initial catalog scan failed transiently; retrying"
                );
                if sleep_or_shutdown(delay, shutdown).await {
                    return Ok(());
                }
            }
            Err(err) => return Err(err),
        }
    }
}

/// The event-feed follower, restarted behind a capped backoff after
/// transient failures (the sync module documents that retrying its failing
/// page is the caller's job; the page is re-fetched and re-applied
/// idempotently).
async fn supervise_feed(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    shutdown: &CancellationToken,
) -> Result<()> {
    let mut backoff = Backoff::new();
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        match sync::follow_feed(client, store, config, shutdown).await {
            // `follow_feed` returns `Ok` only on shutdown.
            Ok(()) => return Ok(()),
            Err(err) if err.is_transient() => {
                let delay = backoff.next_delay();
                tracing::warn!(
                    error = %err,
                    delay_ms = delay.as_millis() as u64,
                    "event feed failed transiently; restarting after backoff"
                );
                if sleep_or_shutdown(delay, shutdown).await {
                    return Ok(());
                }
            }
            Err(err) => return Err(err),
        }
    }
}

/// The scheduler loop: claim → run → settle, one job at a time.
///
/// `Agent::run_job` runs the persisted stage machine to a terminal phase
/// (`done`/`dropped`/`failed`). The only `Err` it returns is a transient
/// write-back failure with the job left durable in `reporting`; the loop
/// backs off and moves on (boot reconciliation owns re-submission). An empty
/// job table sleeps for `config.poll_interval`, so the loop never busy-spins.
/// Shutdown is observed between jobs: an in-flight job always finishes first.
/// Resolves the analyzer token at boot: the environment wins (and is
/// persisted as the latest-used token); otherwise the state store's stored
/// token; otherwise boot fails fast naming both sources. The source is
/// logged, never the value.
fn resolve_token(config: &mut Config, store: &Store) -> Result<()> {
    if let Some(token) = &config.token {
        store
            .secrets()
            .set("analyzer_token", token.expose())
            .map_err(|err| {
                AnalyzerError::State(format!("persist the latest-used analyzer token: {err}"))
            })?;
        tracing::info!("analyzer token source: environment (stored for the next boot)");
        return Ok(());
    }
    match store.secrets().get("analyzer_token")? {
        Some(stored) => {
            config.token = Some(crate::config::SecretToken::new(stored));
            tracing::info!("analyzer token source: state store (latest-used)");
            Ok(())
        }
        None => Err(AnalyzerError::Config(
            "no analyzer token: set DUMP_ANALYZER_TOKEN once (it is stored for later boots)"
                .to_owned(),
        )),
    }
}

/// Cadence of the pending-local-verdict replay sweep while the daemon idles
/// (boot reconciliation covers restarts; this covers the route appearing
/// mid-run). Cheap: one local query and zero requests when nothing pends.
const REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

async fn scheduler_loop(
    agent: &Agent,
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    shutdown: &CancellationToken,
) -> Result<()> {
    if !config.scheduler_enabled {
        tracing::info!("scheduler disabled (DUMP_ANALYZER_SCHEDULER=off); manual operation only");
        shutdown.cancelled().await;
        return Ok(());
    }
    let mut backoff = Backoff::new();
    let mut last_sweep = std::time::Instant::now();
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        match store.jobs().claim_next() {
            Ok(Some((identity, attempts))) => {
                tracing::info!(
                    dump_id = %identity.dump_id,
                    sha256 = %identity.input_sha256,
                    attempts,
                    "claimed job"
                );
                match agent.run_job(&identity).await {
                    Ok(()) => backoff.reset(),
                    Err(err) => {
                        let delay = backoff.next_delay();
                        tracing::warn!(
                            dump_id = %identity.dump_id,
                            error = %err,
                            delay_ms = delay.as_millis() as u64,
                            "job attempt failed; backing off"
                        );
                        if sleep_or_shutdown(delay, shutdown).await {
                            return Ok(());
                        }
                    }
                }
            }
            Ok(None) => {
                if last_sweep.elapsed() >= REPLAY_SWEEP_INTERVAL {
                    match verdict::replay_pending(client, store, config).await {
                        Ok(report) if report.replayed > 0 || report.abandoned > 0 => {
                            tracing::info!(
                                replayed = report.replayed,
                                abandoned = report.abandoned,
                                "periodic verdict replay sweep settled pending reports"
                            );
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::warn!(error = %err, "verdict replay sweep failed")
                        }
                    }
                    last_sweep = std::time::Instant::now();
                }
                if sleep_or_shutdown(config.poll_interval, shutdown).await {
                    return Ok(());
                }
            }
            Err(err) => {
                let delay = backoff.next_delay();
                tracing::warn!(
                    error = %err,
                    delay_ms = delay.as_millis() as u64,
                    "job claim failed; backing off"
                );
                if sleep_or_shutdown(delay, shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

/// Sleeps `delay`, or returns `true` early when `shutdown` is cancelled.
async fn sleep_or_shutdown(delay: Duration, shutdown: &CancellationToken) -> bool {
    if shutdown.is_cancelled() {
        return true;
    }
    tokio::select! {
        biased;
        () = shutdown.cancelled() => true,
        () = tokio::time::sleep(delay) => shutdown.is_cancelled(),
    }
}

/// Capped exponential backoff for transient failures: 1 s, 2 s, 4 s, …,
/// 30 s, 30 s, … (design: "bounded ... backoff"). [`Backoff::reset`] returns
/// the schedule to its base after a successful step.
#[derive(Debug)]
struct Backoff {
    next: Duration,
    cap: Duration,
}

impl Backoff {
    const BASE: Duration = Duration::from_secs(1);
    const CAP: Duration = Duration::from_secs(30);

    fn new() -> Self {
        Self {
            next: Self::BASE,
            cap: Self::CAP,
        }
    }

    /// Returns the current delay and advances the schedule.
    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.cap);
        delay
    }

    /// Returns the schedule to its base delay.
    fn reset(&mut self) {
        self.next = Self::BASE;
    }
}

/// Single-instance guard: a lock file under the state directory, created
/// exclusively (`create_new`) and removed on drop.
///
/// One DumpAnalyzer process per configured `(analyzer.name, analyzer.version)`
/// is a correctness requirement (design: "Single-writer discipline"): the
/// analyzer token has no per-client identity, so two concurrent writers
/// would share one attribution. The file is also the operator's evidence of
/// which PID holds the state directory; a stale file left by a SIGKILL is
/// removed manually after the stale process is confirmed gone.
#[derive(Debug)]
struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(|err| {
            AnalyzerError::State(format!(
                "create state directory {}: {err}",
                state_dir.display()
            ))
        })?;
        let path = state_dir.join(STATE_LOCK_FILE);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                let _ = writeln!(file, "pid={}", std::process::id());
                Ok(Self { path })
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(AnalyzerError::State(format!(
                    "another dump-analyzer instance holds the lock file {}; stop it, or remove \
                     the file if it is stale",
                    path.display()
                )))
            }
            Err(err) => Err(AnalyzerError::State(format!(
                "create lock file {}: {err}",
                path.display()
            ))),
        }
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            tracing::warn!(path = %self.path.display(), %err, "failed to remove the state lock");
        }
    }
}

/// Removes `run-*` directories under the state directory: per-run workspaces
/// orphaned by a crash (the agent wipes them on every normal path, including
/// failures, but a killed process cannot). Runs before scheduling, so it can
/// never race a live run in this process.
///
/// Symlinks and non-directories named `run-*` are left alone. Returns the
/// number of workspaces removed.
fn sweep_orphaned_workspaces(state_dir: &Path) -> Result<usize> {
    let entries = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => {
            return Err(AnalyzerError::State(format!(
                "scan state directory {}: {err}",
                state_dir.display()
            )));
        }
    };
    let mut swept = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|err| {
            AnalyzerError::State(format!(
                "scan state directory {}: {err}",
                state_dir.display()
            ))
        })?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(WORKSPACE_PREFIX)
        {
            continue;
        }
        let file_type = entry.file_type().map_err(|err| {
            AnalyzerError::State(format!(
                "inspect state directory entry {}: {err}",
                entry.path().display()
            ))
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        std::fs::remove_dir_all(&path).map_err(|err| {
            AnalyzerError::State(format!(
                "sweep orphaned workspace {}: {err}",
                path.display()
            ))
        })?;
        swept += 1;
    }
    Ok(swept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap_and_resets() {
        let mut backoff = Backoff::new();
        let delays: Vec<u64> = (0..8)
            .map(|_| backoff.next_delay().as_millis() as u64)
            .collect();
        assert_eq!(
            delays,
            [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn state_lock_is_exclusive_and_removed_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(STATE_LOCK_FILE);

        let lock = StateLock::acquire(dir.path()).expect("first acquire");
        assert!(lock_path.is_file(), "the lock file is created");

        let err = StateLock::acquire(dir.path()).expect_err("second acquire must fail");
        let message = err.to_string();
        assert!(
            message.contains("analyzer.lock"),
            "the error names the lock file: {message}"
        );
        assert!(
            message.contains("another dump-analyzer instance"),
            "the error explains the conflict: {message}"
        );

        drop(lock);
        assert!(!lock_path.exists(), "the lock file is removed on drop");
        StateLock::acquire(dir.path()).expect("reacquire after release");
    }

    #[test]
    fn workspace_sweep_removes_only_orphaned_run_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orphan_a = dir.path().join("run-abc123");
        std::fs::create_dir_all(orphan_a.join("deep")).expect("orphan dir");
        std::fs::write(orphan_a.join("deep/triage.cdb"), b".ecxr").expect("orphan file");
        let orphan_b = dir.path().join("run-old");
        std::fs::create_dir(&orphan_b).expect("orphan dir");
        let kept = dir.path().join("bytes");
        std::fs::create_dir(&kept).expect("unrelated dir");
        std::fs::write(dir.path().join("run-file"), b"not a directory").expect("file");

        let swept = sweep_orphaned_workspaces(dir.path()).expect("sweep");
        assert_eq!(swept, 2, "both run-* directories are swept");
        assert!(!orphan_a.exists());
        assert!(!orphan_b.exists());
        assert!(kept.is_dir(), "unrelated directories are untouched");
        assert!(
            dir.path().join("run-file").is_file(),
            "non-directories named run-* are left alone"
        );

        // Missing state dir is a no-op, not an error.
        assert_eq!(
            sweep_orphaned_workspaces(&dir.path().join("absent")).expect("missing dir sweep"),
            0
        );
    }
}
