//! Verdict writer: report assembly, idempotent write-back, local-verdict
//! mode, and restart reconciliation (task D1).
//!
//! One run's [`RunOutput`] becomes a bounded [`AnalysisReportSubmission`]
//! ([`assemble`]); [`submit`] persists that verdict locally *before* the
//! first network call and then POSTs it to
//! `POST /api/v1/dumps/:dumpId/analyses`. The local copy is the
//! crash-recovery source: reconciliation never needs the run output, only
//! the persisted verdict and the pinned identity.
//!
//! Settling rules (docs/analyzer-design.md, "Agent pipeline" and
//! "Correctness and idempotency"; DumpLedger
//! `docs/analyzer-integration-design.md`, "Analysis write-back"):
//!
//! | Server response | Meaning | Local effect |
//! |---|---|---|
//! | `201` created / `200` replay | verdict accepted; the identity tuple makes a repeat a no-op | copy marked posted, job `done` |
//! | `404` with an error envelope, or `410` | the dump was purged; the report can never attach | copy dequeued, job `dropped` |
//! | `404` without an error envelope | the analyses route does not exist (pre-AI3 server): **local-verdict mode** | copy kept pending (`posted = 0`), job `done`; replayed when the route appears |
//! | `400` `invalid_request` | pinned `inputSha256` mismatch — an analyzer bug signal, loudly logged | copy dequeued, job `failed` |
//! | `409` `invalid_transition` | dump left `available` (purging), or the 64-reports-per-dump cap | terminal: loud error, job `failed` (the local copy stays `posted = 0` for diagnosis) |
//! | transient (`Transport`, `408`/`429`/5xx) | infrastructure failure | error returned to the caller's retry budget; copy stays pending, job stays `reporting` |
//!
//! The two `404` meanings are distinguished by the consumed contract: a
//! handled DumpLedger route answers with the
//! `{error: {code, message, retryable}}` envelope (client
//! `Server { code: Some(_) }`), while an unregistered route answers Fastify's
//! default JSON 404 body, which does not decode as that envelope (client
//! `Server { code: None }`). `410` is the alternate spelling of a purged
//! dump.
//!
//! [`reconcile_on_boot`] repairs the two crash windows: jobs left in
//! `reporting` (the server either already has the identity — settle `done` —
//! or the stored copy is re-POSTed), and local verdicts still `posted = 0`
//! (the replay sweep that delivers them once the analyses route exists).
//! [`replay_pending`] is that sweep on its own: a long-running daemon calls
//! it periodically so a verdict recorded in local-verdict mode is delivered
//! when the route appears, without waiting for a restart.

use serde_json::{Map, Value};
use tracing::{debug, error, warn};

use crate::client::{LedgerClient, PostAnalysisResult};
use crate::config::Config;
use crate::state::{LocalReport, Store};
use crate::types::{AnalyzerError, JobIdentity, JobPhase, Result, RunOutput};
use crate::wire::{AnalysisReportSubmission, Analyzer, MAX_SUMMARY_CHARS};

/// Server-side JSON body limit for one analysis report (16 KiB), matching
/// DumpLedger's Fastify `bodyLimit`.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Server-side per-field bound: `facts` must serialize to at most 4096
/// compact UTF-8 bytes (`analyses.ts` `MAX_ANALYSIS_FACTS_BYTES`), applied
/// before the whole-body [`MAX_BODY_BYTES`] shrink.
pub const MAX_FACTS_BYTES: usize = 4096;

/// Appended when a summary is truncated to [`MAX_SUMMARY_CHARS`] characters.
pub const SUMMARY_TRUNCATION_MARKER: &str = "… [truncated]";

/// `facts` keys by ascending triage value: the first entries are dropped
/// first when a report must shrink to fit [`MAX_BODY_BYTES`]. Keys outside
/// this list have no demonstrated value and are dropped before any listed
/// key; new fact vocabulary should be ranked here when its producer adds it.
/// The list covers the v1 CDB runner's vocabulary, biased to keep the small
/// high-signal keys (`exception`, `failure`) longest.
const FACT_VALUE_LOWEST_FIRST: &[&str] = &[
    "frames_total",
    "frames_truncated",
    "process",
    "symbols",
    "frames",
    "faulting_module",
    "exception",
    "failure",
];

/// Outcome of one boot reconciliation, for the caller's journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Reporting jobs the server already has (identity match); settled `done`.
    pub confirmed: usize,
    /// Reporting jobs re-POSTed successfully from the local copy; `done`.
    pub reposted: usize,
    /// Reporting jobs whose dump is gone (`404`/`410`); settled `dropped`.
    pub dropped: usize,
    /// Reporting jobs settled `done` because the analyses route is still
    /// absent (local-verdict mode continues); the copy stays pending.
    pub local_mode: usize,
    /// Reporting jobs whose local copy is missing; requeued for analysis
    /// without resetting their attempt counts or waiting for the server.
    pub unresolved: Vec<JobIdentity>,
    /// Pending local verdicts accepted by the server this pass (the replay
    /// sweep: [`ReplayReport::replayed`]).
    pub replayed: usize,
    /// Pending local verdicts dequeued because they can never be accepted
    /// (dump purged, permanent `invalid_request`, or unusable stored copy)
    /// ([`ReplayReport::abandoned`]).
    pub abandoned: usize,
    /// The replay sweep stopped early because the analyses route is still
    /// absent (pre-AI3 server) ([`ReplayReport::route_absent`]).
    pub route_absent: bool,
    /// Per-item failures that did not stop reconciliation (also logged).
    pub errors: Vec<String>,
}

/// Outcome of one replay sweep ([`replay_pending`]), for the caller's
/// journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Pending local verdicts accepted by the server this pass.
    pub replayed: usize,
    /// Pending local verdicts dequeued because they can never be accepted
    /// (dump purged, permanent `invalid_request`, or unusable stored copy).
    pub abandoned: usize,
    /// The sweep stopped early because the analyses route is still absent
    /// (pre-AI3 server); the remaining rows stay pending.
    pub route_absent: bool,
    /// Per-item failures that did not stop the sweep (also logged).
    pub errors: Vec<String>,
}

/// Assembles one bounded submission from a completed run.
///
/// The `summary` is truncated (with [`SUMMARY_TRUNCATION_MARKER`], never mid
/// codepoint) to [`MAX_SUMMARY_CHARS`]; when the encoded body would exceed
/// [`MAX_BODY_BYTES`], `facts` keys are dropped lowest-value-first until it
/// fits. A body that still does not fit — or a `facts` value that is not a
/// JSON object — is [`AnalyzerError::Integrity`].
///
/// The analyzer attribution is `config.name` plus the job's pinned
/// `analyzer_version` (the version the bytes were analyzed under, so the
/// server identity tuple matches the job row).
pub fn assemble(
    identity: &JobIdentity,
    output: RunOutput,
    config: &Config,
) -> Result<AnalysisReportSubmission> {
    let RunOutput {
        outcome,
        summary,
        facts,
        ..
    } = output;
    let mut submission = AnalysisReportSubmission::new(
        Analyzer {
            name: config.name.clone(),
            version: identity.analyzer_version.clone(),
        },
        identity.kind.clone(),
        identity.input_sha256.clone(),
        outcome,
        bounded_summary(&summary),
        normalized_facts(facts)?,
        None,
    )?;
    shrink_facts_to_budget(&mut submission);
    if body_len(&submission)? <= MAX_BODY_BYTES {
        return Ok(submission);
    }
    shrink_to_fit(&mut submission)?;
    submission.validate()?;
    Ok(submission)
}

/// Persists the verdict locally, then POSTs it, then settles the job.
///
/// The local insert happens **before** any network call: a crash after the
/// server accepts but before the local bookkeeping must not lose the report
/// (the replay of the same identity is a `200` success). See the module docs
/// for the settling table.
///
/// # Errors
///
/// Returns `Err` for transient write-back failures (the caller's bounded
/// retry budget; the job stays `reporting`) and for local-state failures. A
/// terminal rejection settles the job (`failed`/`dropped`) and returns
/// `Ok(())`; `invalid_request` is additionally logged loudly as a bug signal.
/// The pin guard plus the local record: every accepted-to-be-reported
/// verdict lands in `local_reports` before anything else (crash-safe).
pub fn record_local(
    store: &Store,
    identity: &JobIdentity,
    submission: &AnalysisReportSubmission,
) -> Result<()> {
    if !submission_matches(identity, submission) {
        return Err(AnalyzerError::Integrity(format!(
            "report kind/sha256/analyzer version do not match the pinned job {}",
            job_key(identity)
        )));
    }
    let facts_json = facts_json_for_submission(submission);
    store.local_reports().insert(
        identity,
        submission.outcome,
        &submission.summary,
        &facts_json,
    )?;
    Ok(())
}

/// Save the authoritative document and reporting handoff before projection/delivery.
/// Retries reuse the immutable stored document rather than re-drafting evidence.
pub fn prepare_report(
    store: &Store,
    identity: &JobIdentity,
    output: &RunOutput,
    config: &Config,
    handoff: crate::state::ReportHandoff,
) -> Result<(crate::state::StoredReport, AnalysisReportSubmission)> {
    let report = crate::report::CrashReportV2::from_output(identity, &config.name, output)?;
    // Only this deliberately small projection passes through the v1 envelope.
    let submission = assemble(identity, report.compact_output()?, config)?;
    let stored =
        store
            .local_reports()
            .save_rich(&report, &submission, handoff, config.writeback_enabled)?;
    Ok((stored, submission))
}

/// Write-back off (`DUMP_ANALYZER_WRITE_BACK=off`): the ledger is a read-only
/// dump source. A verdict is assembled and recorded locally, and the job
/// settles `done` immediately — nothing is ever POSTed, and no job waits for
/// ledger acceptance.
pub struct LocalVerdictSink {
    store: Store,
    config: Config,
}

impl LocalVerdictSink {
    /// Builds the sink over the shared store and config.
    pub fn new(store: Store, config: Config) -> Self {
        Self { store, config }
    }
}

#[async_trait::async_trait]
impl crate::agent::VerdictSink for LocalVerdictSink {
    async fn submit(&self, identity: &JobIdentity, output: RunOutput) -> Result<()> {
        prepare_report(
            &self.store,
            identity,
            &output,
            &self.config,
            crate::state::ReportHandoff::None,
        )?;
        self.store
            .jobs()
            .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
        Ok(())
    }
}

/// With write-back off, a `reporting` job has nothing to wait for: its
/// analysis completed and its verdict is the local record. Settles every
/// stale `reporting` row with a durable report to `done`; reportless rows
/// return to discovery for another run. Boot-only: a live run may still be
/// between entering `reporting` and saving its report. Returns how many
/// completed jobs left the queue.
pub fn settle_reporting_locally(store: &Store) -> Result<usize> {
    let jobs = store.jobs();
    let mut settled = 0;
    for (identity, _attempts) in jobs.jobs_in_phase(JobPhase::Reporting)? {
        if store.local_reports().get(&identity)?.is_some() {
            jobs.set_phase(&identity, JobPhase::Done)?;
            settled += 1;
        } else {
            jobs.set_phase(&identity, JobPhase::Discovered)?;
        }
    }
    Ok(settled)
}

pub async fn submit(
    client: &LedgerClient,
    store: &Store,
    identity: &JobIdentity,
    submission: &AnalysisReportSubmission,
) -> Result<()> {
    record_local(store, identity, submission)?;
    match publish(client, store, identity, submission).await {
        Ok(PostAnalysisResult::Created(_) | PostAnalysisResult::Replayed(_)) => {
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
            Ok(())
        }
        Err(AnalyzerError::Server { status, code }) if route_missing(status, code.as_deref()) => {
            debug!(
                job = %job_key(identity),
                "analyses route absent (pre-AI3 server): keeping the verdict in local-verdict mode"
            );
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
            Ok(())
        }
        Err(AnalyzerError::Server { status, code }) if dump_gone(status, code.as_deref()) => {
            debug!(
                job = %job_key(identity),
                "dump purged before the verdict was accepted; dropping the job"
            );
            store.local_reports().mark_posted(identity)?;
            store.jobs().drop_job(identity)?;
            Ok(())
        }
        Err(err) if is_invalid_request(&err) => {
            error!(
                job = %job_key(identity),
                %err,
                "the server rejected the pinned report as invalid_request: an inputSha256 mismatch \
                 against the dump is a bug signal; dequeuing the verdict and failing the job"
            );
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
            Ok(())
        }
        Err(err) if err.is_transient() => Err(err),
        Err(err) => {
            error!(
                job = %job_key(identity),
                %err,
                "terminal analysis write-back error; failing the job"
            );
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
            Ok(())
        }
    }
}

/// Full delivery is independent of the legacy posted bit. An old server can
/// accept a digest-bound summary without pretending to have the full evidence.
async fn publish(
    client: &LedgerClient,
    store: &Store,
    identity: &JobIdentity,
    submission: &AnalysisReportSubmission,
) -> Result<PostAnalysisResult> {
    use crate::state::FullDelivery;
    let Some(stored) = store.local_reports().get_rich(identity)? else {
        return client.post_analysis(&identity.dump_id, submission).await;
    };
    let mut compact = submission.clone();
    compact.analyzer.name = stored.report.identity.analyzer_name.clone();
    compact.analyzer.version = stored.report.identity.analyzer_version.clone();
    match client.post_rich_analysis(&stored, &compact).await {
        Ok(result) => {
            store
                .local_reports()
                .set_full_delivery(identity, FullDelivery::FullyDelivered)?;
            Ok(result)
        }
        Err(AnalyzerError::Server { status, code })
            if route_missing(status, code.as_deref()) || matches!(status, 405 | 501) =>
        {
            let result = client.post_analysis(&identity.dump_id, &compact).await;
            if result.is_ok() {
                store
                    .local_reports()
                    .set_full_delivery(identity, FullDelivery::SummaryOnly)?;
            } else if result.as_ref().is_err_and(|err| is_invalid_request(err) || matches!(err, AnalyzerError::Server{status,code} if dump_gone(*status,code.as_deref()) || *status == 409)) {
                store.local_reports().set_full_delivery(identity,FullDelivery::Abandoned)?;
                if matches!(&result, Err(AnalyzerError::Server{status:409,..})) {
                    store.local_reports().mark_posted(identity)?;
                    store.jobs().set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
                }
            }
            result
        }
        Err(err @ AnalyzerError::Server { status: 409, .. }) => {
            store
                .local_reports()
                .set_full_delivery(identity, FullDelivery::Abandoned)?;
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
            Err(err)
        }
        Err(err) => {
            if is_invalid_request(&err)
                || matches!(&err, AnalyzerError::Server{status,code} if dump_gone(*status,code.as_deref()))
            {
                store
                    .local_reports()
                    .set_full_delivery(identity, FullDelivery::Abandoned)?;
            }
            Err(err)
        }
    }
}

/// Boot reconciliation: settle `reporting` jobs against the server, then
/// deliver pending local verdicts through [`replay_pending`] (one replay
/// implementation, shared with a running daemon's periodic sweep).
///
/// The analyzer name for server-identity matching and rebuilt submissions
/// comes from `config` (the process-global attribution); versions come from
/// each job's pin, so the server identity tuple is preserved across restarts.
///
/// # Errors
///
/// Local-state failures (the job/verdict tables) are fatal. Per-item server
/// failures are recorded in [`ReconcileReport::errors`] and logged; work
/// that can be retried is left for the next pass.
pub async fn reconcile_on_boot(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
) -> Result<ReconcileReport> {
    let mut report = ReconcileReport::default();

    for (identity, _attempts) in store.jobs().jobs_in_phase(JobPhase::Reporting)? {
        match reconcile_reporting(client, store, config, &identity).await {
            Ok(ReportingOutcome::Confirmed) => report.confirmed += 1,
            Ok(ReportingOutcome::Reposted) => report.reposted += 1,
            Ok(ReportingOutcome::Dropped) => report.dropped += 1,
            Ok(ReportingOutcome::LocalMode) => report.local_mode += 1,
            Ok(ReportingOutcome::Unresolved) => {
                warn!(
                    job = %job_key(&identity),
                    "reporting job has no local verdict copy; requeued for analysis"
                );
                report.unresolved.push(identity);
            }
            Err(AnalyzerError::State(message)) => {
                return Err(AnalyzerError::State(message));
            }
            Err(err) => {
                warn!(
                    job = %job_key(&identity),
                    %err,
                    "reconciliation of a reporting job failed; leaving it for the next pass"
                );
                report
                    .errors
                    .push(format!("reporting {}: {err}", job_key(&identity)));
            }
        }
    }

    let replay = replay_pending(client, store, config).await?;
    report.replayed = replay.replayed;
    report.abandoned = replay.abandoned;
    report.route_absent = replay.route_absent;
    report.errors.extend(replay.errors);

    Ok(report)
}

/// One replay sweep: POSTs every pending local verdict (`posted = 0`) until
/// the queue is drained, a verdict is permanently rejected, a transient
/// failure stops the pass, or the analyses route is absent (pre-AI3 server:
/// local-verdict mode continues and the rest of the queue stays pending).
///
/// [`reconcile_on_boot`] calls this for its boot sweep; a long-running
/// daemon calls it periodically so a verdict recorded in local-verdict mode
/// is delivered when the route appears, without waiting for a restart.
///
/// # Errors
///
/// Local-state failures (the verdict table) are fatal. Per-item server
/// failures are recorded in [`ReplayReport::errors`] and logged; a transient
/// failure stops the sweep and leaves the remaining rows pending.
pub async fn replay_pending(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
) -> Result<ReplayReport> {
    let mut report = ReplayReport::default();
    // Delivery can finish before a concurrent manual completion creates its
    // queue row. Such reports no longer appear in pending(), so settle their
    // late reporting rows explicitly without sending another request.
    for (identity, _) in store.jobs().jobs_in_phase(JobPhase::Reporting)? {
        if store
            .local_reports()
            .get(&identity)?
            .is_some_and(|row| row.posted)
        {
            store
                .jobs()
                .set_phase_if(&identity, JobPhase::Reporting, JobPhase::Done)?;
        }
    }
    let pending = store.local_reports().pending()?;
    let attempted: std::collections::HashSet<_> =
        pending.iter().map(LocalReport::identity).collect();
    for row in pending {
        let identity = row.identity();
        match replay_row(client, store, config, &row).await {
            Ok(ReplayOutcome::Replayed) => {
                report.replayed += 1;
                // A `reporting` job whose verdict just posted is done.
                if store.jobs().phase_of(&identity)? == Some(JobPhase::Reporting) {
                    store
                        .jobs()
                        .set_phase_if(&identity, JobPhase::Reporting, JobPhase::Done)?;
                }
            }
            Ok(ReplayOutcome::Abandoned(reason)) => {
                report.abandoned += 1;
                // The verdict can never be accepted; settle the job honestly.
                if store.jobs().phase_of(&identity)? == Some(JobPhase::Reporting) {
                    let phase = match reason {
                        AbandonReason::DumpGone => JobPhase::Dropped,
                        AbandonReason::Rejected => JobPhase::Failed,
                    };
                    store.jobs().set_phase(&identity, phase)?;
                }
            }
            Ok(ReplayOutcome::RouteAbsent) => {
                // The ledger cannot accept reports yet. Durable local
                // verdicts have finished their analysis work, just as in
                // submit's local-verdict mode. Keep the reports pending
                // for later delivery and remove their jobs from the queue.
                for (job, _) in store.jobs().jobs_in_phase(JobPhase::Reporting)? {
                    if store.local_reports().get(&job)?.is_some() {
                        store
                            .jobs()
                            .set_phase_if(&job, JobPhase::Reporting, JobPhase::Done)?;
                    }
                }
                debug!(
                    "analyses route still absent; local-verdict mode continues and the replay sweep stops"
                );
                report.route_absent = true;
                break;
            }
            Err(AnalyzerError::State(message)) => {
                return Err(AnalyzerError::State(message));
            }
            Err(err) if err.is_transient() => {
                warn!(%err, "replay sweep stopped by a transient error; the queue stays pending");
                report
                    .errors
                    .push(format!("replay {}: {err}", job_key(&identity)));
                break;
            }
            Err(err) => {
                error!(
                    row = %job_key(&identity),
                    %err,
                    "replay of a stored verdict failed permanently; the queue keeps the row for the next pass"
                );
                report
                    .errors
                    .push(format!("replay {}: {err}", job_key(&identity)));
            }
        }
    }
    // Summary-only acceptance must never suppress a later v2 promotion.
    if config.writeback_enabled {
        for identity in store.local_reports().pending_full_identities()? {
            if attempted.contains(&identity) {
                continue;
            }
            let Some(row) = store.local_reports().get(&identity)? else {
                continue;
            };
            let submission = submission_from_row(&row, config)?;
            match publish(client, store, &identity, &submission).await {
                Ok(_) => {
                    store.local_reports().mark_posted(&identity)?;
                    store
                        .jobs()
                        .set_phase_if(&identity, JobPhase::Reporting, JobPhase::Done)?;
                }
                Err(AnalyzerError::State(message)) => return Err(AnalyzerError::State(message)),
                Err(err) => {
                    report
                        .errors
                        .push(format!("full delivery {}: {err}", job_key(&identity)));
                    if err.is_transient() {
                        break;
                    }
                }
            }
        }
    }
    Ok(report)
}

/// What happened to one `reporting` job.
enum ReportingOutcome {
    /// The server already holds the identity; settled `done`.
    Confirmed,
    /// The stored copy was re-POSTed (or local mode resumed); settled `done`.
    Reposted,
    /// The dump is gone; settled `dropped`.
    Dropped,
    /// The route is absent and the copy stays pending; settled `done`.
    LocalMode,
    /// Nothing to re-POST; requeued for analysis at boot.
    Unresolved,
}

/// What happened to one pending local verdict during the replay sweep.
enum ReplayOutcome {
    /// Accepted (`201`/`200`); marked posted.
    Replayed,
    /// Dequeued without acceptance, with the reason (dump gone or permanent
    /// rejection) so the owning job can settle accordingly.
    Abandoned(AbandonReason),
    /// The analyses route is still absent.
    RouteAbsent,
}

/// Why a stored verdict was dequeued without acceptance.
enum AbandonReason {
    /// The dump is gone (`dropped` settles the job).
    DumpGone,
    /// The server rejected the pinned identity permanently (`failed`).
    Rejected,
}

async fn reconcile_reporting(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    identity: &JobIdentity,
) -> Result<ReportingOutcome> {
    let Some(local) = store.local_reports().get(identity)? else {
        // Boot runs before live agents start. Requeue this interrupted report
        // handoff even if the ledger is unavailable; otherwise no durable
        // report exists for periodic delivery to visit.
        store.jobs().set_phase(identity, JobPhase::Discovered)?;
        return Ok(ReportingOutcome::Unresolved);
    };

    match client.get_analyses(&identity.dump_id).await {
        Ok(reports) => {
            if reports
                .iter()
                .any(|report| report_matches(report, identity, config))
            {
                store.local_reports().mark_posted(identity)?;
                store
                    .jobs()
                    .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
                return Ok(ReportingOutcome::Confirmed);
            }
        }
        Err(AnalyzerError::Server { status, code }) if route_missing(status, code.as_deref()) => {
            // The GET route is absent too (pre-AI3); the re-POST below
            // observes the same absence and resumes local-verdict mode.
        }
        Err(AnalyzerError::Server { status, code }) if dump_gone(status, code.as_deref()) => {
            // Purged while reporting: the job is invalidated at this touch.
            store.local_reports().mark_posted(identity)?;
            store.jobs().drop_job(identity)?;
            return Ok(ReportingOutcome::Dropped);
        }
        Err(err) => return Err(err),
    }

    let submission = match submission_from_row(&local, config) {
        Ok(submission) => submission,
        Err(err) => {
            error!(
                job = %job_key(identity),
                %err,
                "stored verdict copy is unusable; the report cannot be re-posted, failing the job"
            );
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
            return Err(err);
        }
    };
    match publish(client, store, identity, &submission).await {
        Ok(_) => {
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
            Ok(ReportingOutcome::Reposted)
        }
        Err(AnalyzerError::Server { status, code }) if route_missing(status, code.as_deref()) => {
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Done)?;
            Ok(ReportingOutcome::LocalMode)
        }
        Err(AnalyzerError::Server { status, code }) if dump_gone(status, code.as_deref()) => {
            store.local_reports().mark_posted(identity)?;
            store.jobs().drop_job(identity)?;
            Ok(ReportingOutcome::Dropped)
        }
        Err(err) if is_invalid_request(&err) => {
            error!(
                job = %job_key(identity),
                %err,
                "re-posted verdict rejected as invalid_request (sha mismatch); failing the job"
            );
            store.local_reports().mark_posted(identity)?;
            store
                .jobs()
                .set_phase_if(identity, JobPhase::Reporting, JobPhase::Failed)?;
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// POSTs one stored verdict. The sweep wrapper ([`replay_pending`]) owns the
/// queue policy; this function owns the per-row outcome.
async fn replay_row(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    row: &LocalReport,
) -> Result<ReplayOutcome> {
    let identity = row.identity();
    let submission = match submission_from_row(row, config) {
        Ok(submission) => submission,
        Err(err) => {
            error!(
                row = %job_key(&identity),
                %err,
                "stored verdict is unusable; dequeuing it"
            );
            store.local_reports().mark_posted(&identity)?;
            return Ok(ReplayOutcome::Abandoned(AbandonReason::Rejected));
        }
    };
    match publish(client, store, &identity, &submission).await {
        Ok(PostAnalysisResult::Created(_) | PostAnalysisResult::Replayed(_)) => {
            store.local_reports().mark_posted(&identity)?;
            Ok(ReplayOutcome::Replayed)
        }
        Err(AnalyzerError::Server { status, code }) if route_missing(status, code.as_deref()) => {
            Ok(ReplayOutcome::RouteAbsent)
        }
        Err(AnalyzerError::Server { status, code }) if dump_gone(status, code.as_deref()) => {
            debug!(
                row = %job_key(&identity),
                "dump purged; the stored verdict can never be accepted, dequeuing it"
            );
            store.local_reports().mark_posted(&identity)?;
            Ok(ReplayOutcome::Abandoned(AbandonReason::DumpGone))
        }
        Err(err) if is_invalid_request(&err) => {
            error!(
                row = %job_key(&identity),
                %err,
                "stored verdict rejected as invalid_request (sha mismatch); dequeuing it"
            );
            store.local_reports().mark_posted(&identity)?;
            Ok(ReplayOutcome::Abandoned(AbandonReason::Rejected))
        }
        Err(err) => Err(err),
    }
}

/// Rebuilds the submission body for a stored verdict. The analyzer name is
/// the current process attribution; the version is the row's pin.
fn submission_from_row(row: &LocalReport, config: &Config) -> Result<AnalysisReportSubmission> {
    let facts = match serde_json::from_str::<Value>(&row.facts_json) {
        Ok(Value::Null) => None,
        Ok(Value::Object(map)) if map.is_empty() => None,
        Ok(facts @ Value::Object(_)) => Some(facts),
        Ok(other) => {
            return Err(AnalyzerError::Integrity(format!(
                "stored facts for {} are {}, not a JSON object",
                job_key(&row.identity()),
                value_kind(&other)
            )));
        }
        Err(err) => {
            return Err(AnalyzerError::Integrity(format!(
                "stored facts for {} are not valid JSON: {err}",
                job_key(&row.identity())
            )));
        }
    };
    AnalysisReportSubmission::new(
        Analyzer {
            name: config.name.clone(),
            version: row.analyzer_version.clone(),
        },
        row.kind.clone(),
        row.input_sha256.clone(),
        row.outcome,
        row.summary.clone(),
        facts,
        None,
    )
    .map_err(|err| {
        AnalyzerError::Integrity(format!(
            "stored verdict for {} does not re-validate: {err}",
            job_key(&row.identity())
        ))
    })
}

/// Whether a server report carries the job's identity tuple
/// `(dumpId, analyzer.name, analyzer.version, kind, inputSha256)`; the dump
/// id is implied by the route.
fn report_matches(
    report: &crate::wire::AnalysisReport,
    identity: &JobIdentity,
    config: &Config,
) -> bool {
    report.input_sha256 == identity.input_sha256
        && report.kind == identity.kind
        && report.analyzer.version == identity.analyzer_version
        && report.analyzer.name == config.name
}

fn submission_matches(identity: &JobIdentity, submission: &AnalysisReportSubmission) -> bool {
    submission.kind == identity.kind
        && submission.input_sha256 == identity.input_sha256
        && submission.analyzer.version == identity.analyzer_version
}

/// `404` without a decodable error envelope: the route itself does not exist
/// (Fastify's default JSON 404). A handled `not_found` for a dump carries the
/// envelope and is therefore [`dump_gone`].
fn route_missing(status: u16, code: Option<&str>) -> bool {
    status == 404 && code.is_none()
}

/// `404` with an error envelope, or `410`: the dump was purged.
fn dump_gone(status: u16, code: Option<&str>) -> bool {
    (status == 404 && code.is_some()) || status == 410
}

/// The server rejected the pinned identity as `invalid_request` — with an
/// otherwise valid body this means the dump's sealed sha256 moved, i.e. a bug.
fn is_invalid_request(err: &AnalyzerError) -> bool {
    matches!(
        err,
        AnalyzerError::Server { status: 400, code: Some(code) } if code == "invalid_request"
    )
}

/// Truncates to [`MAX_SUMMARY_CHARS`] by characters, never splitting a UTF-8
/// codepoint, and marks the truncation.
fn bounded_summary(summary: &str) -> String {
    if summary.chars().count() <= MAX_SUMMARY_CHARS {
        return summary.to_owned();
    }
    let keep = MAX_SUMMARY_CHARS.saturating_sub(SUMMARY_TRUNCATION_MARKER.chars().count());
    let end = summary
        .char_indices()
        .nth(keep)
        .map_or(summary.len(), |(index, _)| index);
    let mut bounded = String::with_capacity(end + SUMMARY_TRUNCATION_MARKER.len());
    bounded.push_str(&summary[..end]);
    bounded.push_str(SUMMARY_TRUNCATION_MARKER);
    bounded
}

/// Normalizes run facts: absent (`null`) or empty facts become `None`; a
/// non-object value is an integrity failure (the wire contract requires an
/// object).
fn normalized_facts(facts: Value) -> Result<Option<Value>> {
    match facts {
        Value::Null => Ok(None),
        Value::Object(map) if map.is_empty() => Ok(None),
        facts @ Value::Object(_) => Ok(Some(facts)),
        other => Err(AnalyzerError::Integrity(format!(
            "facts: expected a JSON object, found {}",
            value_kind(&other)
        ))),
    }
}

/// Drops lowest-value `facts` keys until the compact `facts` payload fits
/// the server's per-field [`MAX_FACTS_BYTES`] budget. An empty object becomes
/// absent (`None`), which always fits; this step never fails.
fn shrink_facts_to_budget(submission: &mut AnalysisReportSubmission) {
    loop {
        let over = match &submission.facts {
            Some(facts) => facts.to_string().len() > MAX_FACTS_BYTES,
            None => false,
        };
        let Some(Value::Object(map)) = submission.facts.as_mut() else {
            break;
        };
        if !over || map.is_empty() {
            break;
        }
        let victim = lowest_value_key(map);
        map.remove(&victim);
        debug!(
            key = %victim,
            "dropping a lowest-value facts key to fit the 4 KiB facts budget"
        );
    }
    // An emptied object normalizes to absent, which always fits.
    if matches!(&submission.facts, Some(Value::Object(map)) if map.is_empty()) {
        submission.facts = None;
    }
}

/// Drops the lowest-value `facts` keys, one at a time, until the encoded
/// body fits [`MAX_BODY_BYTES`]; a body that still does not fit afterwards is
/// an integrity failure.
fn shrink_to_fit(submission: &mut AnalysisReportSubmission) -> Result<()> {
    let mut facts = submission.facts.take();
    while let Some(Value::Object(map)) = facts.as_mut() {
        if map.is_empty() {
            break;
        }
        let victim = lowest_value_key(map);
        map.remove(&victim);
        debug!(
            key = %victim,
            "dropping a lowest-value facts key to fit the 16 KiB report envelope"
        );
        submission.facts = if map.is_empty() { None } else { facts.clone() };
        if body_len(submission)? <= MAX_BODY_BYTES {
            return Ok(());
        }
    }
    Err(AnalyzerError::Integrity(format!(
        "report body still exceeds {MAX_BODY_BYTES} bytes after dropping every facts key"
    )))
}

/// The key to drop next: lowest value tier first; ties break on the largest
/// encoded contribution (freeing the most envelope space), then on the key
/// name for determinism.
fn lowest_value_key(map: &Map<String, Value>) -> String {
    map.iter()
        .min_by(|(a, av), (b, bv)| drop_rank(a, av).cmp(&drop_rank(b, bv)))
        .map(|(key, _)| key.clone())
        .expect("caller checked the facts object is non-empty")
}

fn drop_rank<'a>(key: &'a str, value: &'a Value) -> (u32, std::cmp::Reverse<usize>, &'a str) {
    let tier = FACT_VALUE_LOWEST_FIRST
        .iter()
        .position(|candidate| *candidate == key)
        .map_or(0, |index| {
            u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1)
        });
    (tier, std::cmp::Reverse(encoded_len(value)), key)
}

/// Compact JSON length of a value (the wire body is compact-encoded).
fn encoded_len(value: &Value) -> usize {
    value.to_string().len()
}

fn body_len(submission: &AnalysisReportSubmission) -> Result<usize> {
    serde_json::to_vec(submission)
        .map(|bytes| bytes.len())
        .map_err(|err| AnalyzerError::Integrity(format!("report encoding failed: {err}")))
}

/// The local `facts_json` spelling: `"null"` for absent facts, otherwise the
/// compact object encoding [`submission_from_row`] reverses.
fn facts_json_for_submission(submission: &AnalysisReportSubmission) -> String {
    match &submission.facts {
        None => "null".to_owned(),
        Some(facts) => facts.to_string(),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Stable job rendering for logs: `dumpId@sha256:kind#analyzerVersion`.
fn job_key(job: &JobIdentity) -> String {
    format!(
        "{}@{}:{}#{}",
        job.dump_id, job.input_sha256, job.kind, job.analyzer_version
    )
}
