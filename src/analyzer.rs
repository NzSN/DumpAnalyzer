//! The on-demand analysis component: `f : DumpId -> IO Report`.
//!
//! Given a dump identifier from DumpLedger, `analyze` performs the whole
//! effectful pipeline — detail lookup, byte fetch with cache/ETag, sha256
//! verification, bounded toolchain run — and returns the verdict as a
//! [`Report`]. Successful reports are retained locally for the dashboard.
//! With write-back enabled, an unposted report creates or advances an idle
//! job to `reporting` for reconciliation to deliver it to the ledger. With
//! write-back disabled, the analysis settles immediately and leaves the
//! work queue. An already-posted report also settles immediately. Manual
//! reruns preserve settled identities and any scheduled execution in progress;
//! they do not persist their own attempt counters or intermediate phases.
//! Active manual executions appear in [`Analyzer::active_jobs`] until their
//! request completes, fails, or is cancelled.
//!
//! `Analyzer` here is the effectful component trait; `wire::Analyzer` (the
//! name/version attribution struct inside a report) is a different, purely
//! descriptive type.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use crate::agent::{Agent, Attempt, MAX_ATTEMPTS};
use crate::client::LedgerClient;
use crate::config::Config;
use crate::state::{JobRow, Store, now_utc};
use crate::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome, Result, ToolRunner};
use crate::verdict;
use crate::wire::{DumpCatalogQuery, DumpPhase};

/// A completed on-demand analysis: the verdict for one pinned dump content.
#[derive(Debug, Clone)]
pub struct Report {
    pub identity: JobIdentity,
    pub outcome: ReportOutcome,
    pub summary: String,
    pub facts: Option<serde_json::Value>,
}

/// Failure taxonomy for on-demand analysis. Maps directly onto HTTP statuses
/// in the status UI (`/-/analyze`).
#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    /// The ledger has no such dump (or it was purged mid-analysis).
    #[error("dump not found: {0}")]
    NotFound(String),
    /// The dump is unavailable, unsealed, or already being analyzed manually.
    #[error("dump {dump_id} is not analyzable: {reason}")]
    NotAvailable { dump_id: String, reason: String },
    /// Transient failure after the bounded retry budget (transport, 5xx,
    /// runner crashes, staging corruption).
    #[error("transient failure after the attempt budget: {0}")]
    Transient(#[source] AnalyzerError),
    /// Terminal failure (decode, integrity, config).
    #[error("terminal failure: {0}")]
    Terminal(#[source] AnalyzerError),
}

/// Hard cap on one scope batch (a case or a customer): scope analysis is
/// synchronous within the request, so the batch must stay operator-sized.
pub const MAX_SCOPE_DUMPS: u32 = 64;

/// A bulk analysis scope: every `available` dump of one case or one customer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisScope {
    Case(String),
    Customer(String),
}

impl AnalysisScope {
    /// The scope as it prints in logs and result pages.
    pub fn describe(&self) -> String {
        match self {
            AnalysisScope::Case(id) => format!("case {id}"),
            AnalysisScope::Customer(id) => format!("customer {id}"),
        }
    }
}

/// One dump skipped by a scope analysis, with the reason.
#[derive(Debug, Clone)]
pub struct SkippedDump {
    pub dump_id: String,
    pub reason: String,
}

/// The result of `f(scope)`: per-dump reports plus skips. A single dump's
/// failure never aborts the batch; it lands in `skipped`.
#[derive(Debug)]
pub struct ScopeReport {
    pub scope: String,
    pub considered: usize,
    pub reports: Vec<Report>,
    pub skipped: Vec<SkippedDump>,
}

/// The component contract: `DumpId -> IO Report`.
#[async_trait::async_trait]
pub trait Analyzer: Send + Sync {
    async fn analyze(&self, dump_id: &str) -> std::result::Result<Report, AnalyzeError>;

    /// Current on-demand executions, independent of the durable scheduled queue.
    fn active_jobs(&self) -> Result<Vec<JobRow>> {
        Ok(Vec::new())
    }

    /// `f : (CaseId | CustomerId) -> IO ScopeReport` — every `available`
    /// dump of the case/customer, analyzed sequentially through the same
    /// pipeline. Per-dump failures land in `skipped`, never abort the batch.
    async fn analyze_scope(
        &self,
        scope: &AnalysisScope,
    ) -> std::result::Result<ScopeReport, AnalyzeError>;
}

/// Verdict sink that must never receive a report: the on-demand path returns
/// reports to its caller instead of submitting them.
struct NoSink;

#[async_trait::async_trait]
impl crate::agent::VerdictSink for NoSink {
    async fn submit(
        &self,
        _identity: &JobIdentity,
        _output: crate::types::RunOutput,
    ) -> Result<()> {
        Err(AnalyzerError::State(
            "the on-demand analyzer never submits through the job path".to_owned(),
        ))
    }
}

/// The production [`Analyzer`]: the real pipeline over client, store,
/// config, and the configured tool runner.
pub struct PipelineAnalyzer {
    agent: Agent,
    config: Config,
    store: Store,
    active: Arc<Mutex<HashMap<JobIdentity, JobRow>>>,
}

/// Owns one live manual execution; cancellation drops the guard with its future.
struct ActiveManualJob {
    identity: JobIdentity,
    active: Arc<Mutex<HashMap<JobIdentity, JobRow>>>,
}

impl Drop for ActiveManualJob {
    fn drop(&mut self) {
        // Cleanup must also run while unwinding; recover the map if a prior
        // panic poisoned its mutex rather than leaving an orphan active row.
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.identity);
    }
}

impl PipelineAnalyzer {
    /// Builds the component. Shares the runner with the scheduled agent;
    /// uses its own client instance (the client is not `Clone`) against the
    /// same validated config.
    pub fn new(
        client: LedgerClient,
        store: Store,
        config: Config,
        runner: Arc<dyn ToolRunner>,
    ) -> Self {
        let agent = Agent::new(
            client,
            store.clone(),
            config.clone(),
            runner,
            Arc::new(NoSink),
        );
        Self {
            agent,
            config,
            store,
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register_active_job(
        &self,
        identity: &JobIdentity,
    ) -> std::result::Result<ActiveManualJob, AnalyzeError> {
        let mut active = self.active.lock().map_err(|_| {
            AnalyzeError::Terminal(AnalyzerError::State(
                "active analysis registry mutex poisoned".to_owned(),
            ))
        })?;
        match active.entry(identity.clone()) {
            Entry::Occupied(_) => {
                return Err(AnalyzeError::NotAvailable {
                    dump_id: identity.dump_id.clone(),
                    reason: "analysis already running".to_owned(),
                });
            }
            Entry::Vacant(entry) => {
                let now = now_utc();
                entry.insert(JobRow {
                    identity: identity.clone(),
                    phase: JobPhase::Claimed,
                    attempts: 0,
                    created_at: now.clone(),
                    updated_at: now,
                });
            }
        }
        Ok(ActiveManualJob {
            identity: identity.clone(),
            active: self.active.clone(),
        })
    }

    async fn resolve_customer(&self, input: &str) -> std::result::Result<String, AnalyzeError> {
        // IDs are used directly; anything else is tried as an exact display
        // name against the customers list. A 404 on the list route means the
        // server predates it: fall back to treating the input as the id.
        let customers = match self.agent.client().list_customers().await {
            Ok(customers) => customers,
            Err(AnalyzerError::Server { status: 404, .. }) => return Ok(input.to_owned()),
            Err(err) if err.is_transient() => return Err(AnalyzeError::Transient(err)),
            Err(err) => return Err(AnalyzeError::Terminal(err)),
        };
        if customers.iter().any(|c| c.customer_id == input) {
            return Ok(input.to_owned());
        }
        let by_name: Vec<&str> = customers
            .iter()
            .filter(|c| c.display_name == input)
            .map(|c| c.customer_id.as_str())
            .collect();
        match by_name.as_slice() {
            [id] => Ok((*id).to_owned()),
            [] => Err(AnalyzeError::NotFound(format!(
                "unknown customer id or name: {input}"
            ))),
            _ => Err(AnalyzeError::Terminal(AnalyzerError::Integrity(format!(
                "ambiguous customer name {input:?}: {} matches",
                by_name.len()
            )))),
        }
    }
}

#[async_trait::async_trait]
impl Analyzer for PipelineAnalyzer {
    fn active_jobs(&self) -> Result<Vec<JobRow>> {
        let active = self.active.lock().map_err(|_| {
            AnalyzerError::State("active analysis registry mutex poisoned".to_owned())
        })?;
        let mut rows: Vec<JobRow> = active.values().cloned().collect();
        rows.sort_by(|left, right| {
            (
                &left.created_at,
                &left.identity.dump_id,
                &left.identity.input_sha256,
                &left.identity.kind,
                &left.identity.analyzer_version,
            )
                .cmp(&(
                    &right.created_at,
                    &right.identity.dump_id,
                    &right.identity.input_sha256,
                    &right.identity.kind,
                    &right.identity.analyzer_version,
                ))
        });
        Ok(rows)
    }

    async fn analyze(&self, dump_id: &str) -> std::result::Result<Report, AnalyzeError> {
        // Gate: the dump must exist, be `available`, and carry a sealed hash.
        let detail = match self.agent.client().get_dump(dump_id).await {
            Ok(detail) => detail,
            Err(AnalyzerError::Server { status: 404, .. }) => {
                return Err(AnalyzeError::NotFound(dump_id.to_owned()));
            }
            Err(err) if err.is_transient() => return Err(AnalyzeError::Transient(err)),
            Err(err) => return Err(AnalyzeError::Terminal(err)),
        };
        if detail.phase != DumpPhase::Available {
            return Err(AnalyzeError::NotAvailable {
                dump_id: dump_id.to_owned(),
                reason: format!("phase is {}", detail.phase.as_str()),
            });
        }
        let Some(sha256) = detail.sha256 else {
            return Err(AnalyzeError::NotAvailable {
                dump_id: dump_id.to_owned(),
                reason: "not sealed (no sha256)".to_owned(),
            });
        };

        let identity = JobIdentity {
            dump_id: dump_id.to_owned(),
            input_sha256: sha256,
            kind: "triage".to_owned(),
            analyzer_version: self.config.version.clone(),
        };
        if let Some(stored) = self
            .store
            .local_reports()
            .get_rich(&identity)
            .map_err(AnalyzeError::Terminal)?
        {
            if stored.report.identity.analyzer_name != self.config.name {
                return Err(AnalyzeError::Terminal(AnalyzerError::Integrity("stored report attribution belongs to another analyzer name; use a distinct version".into())));
            }
            let projection = stored
                .report
                .compact_output()
                .map_err(AnalyzeError::Terminal)?;
            return Ok(Report {
                identity,
                outcome: projection.outcome,
                summary: projection.summary,
                facts: Some(projection.facts),
            });
        }
        if self
            .store
            .local_reports()
            .get(&identity)
            .map_err(AnalyzeError::Terminal)?
            .is_some()
        {
            return Err(AnalyzeError::NotAvailable {dump_id:dump_id.into(),reason:"A legacy report already uses this identity; select a new analyzer version for rich reanalysis".into()});
        }
        let _active_job = self.register_active_job(&identity)?;

        // Bounded retries, identical budget to the scheduled path; no
        // attempt counter is persisted for on-demand analysis.
        let mut attempts = 0u32;
        let output = loop {
            let attempt = self
                .agent
                .attempt(&identity)
                .await
                .map_err(AnalyzeError::Terminal)?;
            match attempt {
                Attempt::Completed(output) => break *output,
                Attempt::Purged => return Err(AnalyzeError::NotFound(dump_id.to_owned())),
                Attempt::Terminal(err) => return Err(AnalyzeError::Terminal(err)),
                Attempt::Transient(err) => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(AnalyzeError::Transient(err));
                    }
                }
            }
        };

        // Canonical evidence, compact projection and the idle-job handoff are
        // committed together. Scheduled active and terminal rows are preserved.
        let (_, submission) = verdict::prepare_report(
            &self.store,
            &identity,
            &output,
            &self.config,
            crate::state::ReportHandoff::Manual,
        )
        .map_err(AnalyzeError::Terminal)?;
        Ok(Report {
            identity,
            outcome: submission.outcome,
            summary: submission.summary,
            facts: submission.facts,
        })
    }

    async fn analyze_scope(
        &self,
        scope: &AnalysisScope,
    ) -> std::result::Result<ScopeReport, AnalyzeError> {
        // Gather the scope's available dumps from the catalog (paged).
        let mut query = DumpCatalogQuery {
            phase: Some(DumpPhase::Available),
            ..Default::default()
        };
        match scope {
            AnalysisScope::Case(id) => query.case_id = Some(id.clone()),
            AnalysisScope::Customer(input) => {
                query.customer_id = Some(self.resolve_customer(input).await?)
            }
        }
        let mut dump_ids: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .agent
                .client()
                .get_dumps(&query, cursor.as_deref())
                .await
                .map_err(|err| match err {
                    AnalyzerError::Server { status: 404, .. } => {
                        AnalyzeError::NotFound(scope.describe())
                    }
                    err if err.is_transient() => AnalyzeError::Transient(err),
                    err => AnalyzeError::Terminal(err),
                })?;
            for entry in &page.dumps {
                dump_ids.push(entry.dump_id.clone());
                if dump_ids.len() > MAX_SCOPE_DUMPS as usize {
                    return Err(AnalyzeError::Terminal(AnalyzerError::Integrity(format!(
                        "scope {} exceeds the {}-dump batch cap; narrow the scope",
                        scope.describe(),
                        MAX_SCOPE_DUMPS
                    ))));
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        let considered = dump_ids.len();
        let mut reports = Vec::new();
        let mut skipped = Vec::new();
        for dump_id in dump_ids {
            match self.analyze(&dump_id).await {
                Ok(report) => reports.push(report),
                Err(err) => {
                    tracing::warn!(dump_id, error = %err, "scope analysis skipped a dump");
                    skipped.push(SkippedDump {
                        dump_id,
                        reason: err.to_string(),
                    });
                }
            }
        }
        Ok(ScopeReport {
            scope: scope.describe(),
            considered,
            reports,
            skipped,
        })
    }
}
