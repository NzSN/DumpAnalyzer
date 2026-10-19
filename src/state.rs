//! Local SQLite state: jobs, cursors, byte-cache index, local reports
//! (task A3; docs/analyzer-design.md "Module design", "Correctness and
//! idempotency").
//!
//! [`Store`] owns one connection to `data/analyzer.sqlite` and hands out four
//! narrow sub-stores that share it: [`JobStore`], [`CursorStore`],
//! [`CacheIndex`], and [`LocalReportStore`]. The schema is applied through a
//! `schema_migrations` ledger; each migration is applied at most once per
//! database, and reopening an initialized database re-runs nothing.
//!
//! The tables back the job lifecycle modeled in `specs/DumpAnalyzer.tla`:
//!
//! * `jobs` — durable discovery candidates and claimed work, one row per
//!   [`JobIdentity`] with its persisted `phase`, bounded `attempts` counter,
//!   and per-run workspace path. The dashboard Jobs view excludes candidates
//!   still in `discovered`; those are browsed in the Dumps explorer.
//! * `settled_jobs` — terminal identities (`done`/`dropped`/`failed`), moved
//!   atomically out of `jobs`. These markers prevent rediscovery without
//!   leaving completed work in the queue. Phase history is deliberately not
//!   kept — the server audit feed is the history — so each identity has only
//!   its current phase. Local reports remain independently available.
//! * `cursors` — named cursors. The event-feed cursor is a zero-padded rowid
//!   and therefore compares lexically; [`CursorStore::set_monotonic`]
//!   enforces the spec's `CursorMonotonic` (never moves backward).
//! * `byte_cache` — index of already-downloaded dump bytes keyed by content
//!   sha256, carrying the `ETag` used for conditional revalidation and a
//!   `last_used_at` LRU stamp. A cache hit skips the download, never the
//!   sha256 verification.
//! * `local_reports` — verdicts assembled while the server write-back route
//!   is absent (local-verdict mode). `posted = 0` is the replay queue.
//!
//! All methods are synchronous: SQLite operations are short, and v1 runs one
//! writer process.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::report::{CrashReportV2, digest_json, legacy_id};
use crate::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome, Result};
use crate::wire::AnalysisReportSubmission;

/// One SQLite connection shared by every sub-store in this module.
type SharedConn = Arc<Mutex<Connection>>;

/// Handle to the local state database.
#[derive(Clone)]
pub struct Store {
    conn: SharedConn,
}

impl Store {
    /// Opens (creating if absent) the local state database at `path`.
    ///
    /// Missing parent directories are created. Migrations are applied inside
    /// the same transaction that records them in `schema_migrations`, so each
    /// runs exactly once per database and reopening an existing database
    /// re-runs nothing.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AnalyzerError::State(format!(
                        "create state directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        let mut conn = Connection::open(path).map_err(sql_err)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(sql_err)?;
        // WAL keeps committed phase transitions durable across process
        // crashes (the spec's Crash/CrashReset model) without blocking reads.
        let _mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(sql_err)?;
        migrate(&mut conn)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Named secrets (migration 2), e.g. the latest-used analyzer token.
    pub fn secrets(&self) -> Secrets {
        Secrets {
            conn: Arc::clone(&self.conn),
        }
    }

    /// The job table (phase, attempts, workspace).
    pub fn jobs(&self) -> JobStore {
        JobStore {
            conn: Arc::clone(&self.conn),
        }
    }

    /// The named-cursor table (event-feed position).
    pub fn cursors(&self) -> CursorStore {
        CursorStore {
            conn: Arc::clone(&self.conn),
        }
    }

    /// The byte-cache index.
    pub fn cache_index(&self) -> CacheIndex {
        CacheIndex {
            conn: Arc::clone(&self.conn),
        }
    }

    /// The local verdict store (local-verdict mode).
    pub fn local_reports(&self) -> LocalReportStore {
        LocalReportStore {
            conn: Arc::clone(&self.conn),
        }
    }
}

/// Migration ledger table; created before the versioned migrations run.
const SCHEMA_MIGRATIONS_SQL: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);";

/// Migration 1: the complete v1 schema (task A3 deliverable 1).
///
/// Identity columns and phases are declared `NOT NULL`: SQLite otherwise
/// permits NULLs inside a non-rowid composite `PRIMARY KEY`, which would make
/// job lookups and dedup unsound.
const MIGRATION_1_SQL: &str = "
CREATE TABLE jobs (
    dump_id          TEXT NOT NULL,
    input_sha256     TEXT NOT NULL,
    kind             TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    phase            TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    workspace_path   TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (dump_id, input_sha256, kind, analyzer_version)
);

CREATE TABLE cursors (
    name  TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE byte_cache (
    sha256       TEXT PRIMARY KEY NOT NULL,
    path         TEXT NOT NULL,
    byte_size    INTEGER NOT NULL,
    etag         TEXT,
    last_used_at TEXT NOT NULL
);

CREATE TABLE local_reports (
    dump_id          TEXT NOT NULL,
    input_sha256     TEXT NOT NULL,
    kind             TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    summary          TEXT NOT NULL,
    facts_json       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    posted           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dump_id, input_sha256, kind, analyzer_version)
);
";

/// Migration 2: small server-held secrets that must survive restarts
/// (currently: the latest-used analyzer token, so a boot without
/// `DUMP_ANALYZER_TOKEN` keeps working). Plaintext at rest — the state
/// directory gets the same volume-level protection as the ledger vault.
const MIGRATION_2_SQL: &str = "
CREATE TABLE secrets (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// Migration 3: terminal identities leave the active work queue while keeping
/// their dedup markers and lifecycle metadata. Existing databases are cleaned
/// up in the same transaction that installs the new table.
const MIGRATION_3_SQL: &str = "
CREATE TABLE settled_jobs (
    dump_id          TEXT NOT NULL,
    input_sha256     TEXT NOT NULL,
    kind             TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    phase            TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    workspace_path   TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (dump_id, input_sha256, kind, analyzer_version)
);

INSERT INTO settled_jobs
    SELECT * FROM jobs WHERE phase IN ('done', 'dropped', 'failed');
DELETE FROM jobs WHERE phase IN ('done', 'dropped', 'failed');
";

/// Canonical details are independent from compact compatibility verdicts.
/// Historical rows receive a stable locator without changing their evidence.
const MIGRATION_4_SQL: &str = "
ALTER TABLE local_reports ADD COLUMN report_id TEXT;
CREATE UNIQUE INDEX local_reports_report_id ON local_reports(report_id);
CREATE TABLE report_details (
    report_id        TEXT PRIMARY KEY NOT NULL,
    dump_id          TEXT NOT NULL,
    input_sha256     TEXT NOT NULL,
    kind             TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    digest           TEXT NOT NULL,
    report_json      TEXT NOT NULL,
    full_delivery    TEXT NOT NULL,
    UNIQUE (dump_id, input_sha256, kind, analyzer_version)
);
CREATE INDEX report_details_delivery ON report_details(full_delivery);
";

/// Applies any pending migrations. Reads and writes the ledger inside one
/// immediate transaction, so concurrent openers serialize and the second one
/// observes each migration as already applied.
fn migrate(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_MIGRATIONS_SQL).map_err(sql_err)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_err)?;
    let applied: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    if applied == 0 {
        tx.execute_batch(MIGRATION_1_SQL).map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?1)",
            params![now_utc()],
        )
        .map_err(sql_err)?;
    }
    let applied_v2: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 2",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    if applied_v2 == 0 {
        tx.execute_batch(MIGRATION_2_SQL).map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?1)",
            params![now_utc()],
        )
        .map_err(sql_err)?;
    }
    let applied_v3: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 3",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    if applied_v3 == 0 {
        tx.execute_batch(MIGRATION_3_SQL).map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (3, ?1)",
            params![now_utc()],
        )
        .map_err(sql_err)?;
    }
    let applied_v4: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 4",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    if applied_v4 == 0 {
        tx.execute_batch(MIGRATION_4_SQL).map_err(sql_err)?;
        let identities = {
            let mut stmt = tx
                .prepare("SELECT dump_id, input_sha256, kind, analyzer_version FROM local_reports")
                .map_err(sql_err)?;
            stmt.query_map([], |row| {
                Ok(JobIdentity {
                    dump_id: row.get(0)?,
                    input_sha256: row.get(1)?,
                    kind: row.get(2)?,
                    analyzer_version: row.get(3)?,
                })
            })
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?
        };
        for identity in identities {
            tx.execute(
                "UPDATE local_reports SET report_id = ?1 WHERE dump_id = ?2
                   AND input_sha256 = ?3 AND kind = ?4 AND analyzer_version = ?5",
                params![
                    legacy_id(&identity),
                    identity.dump_id,
                    identity.input_sha256,
                    identity.kind,
                    identity.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        }
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (4, ?1)",
            params![now_utc()],
        )
        .map_err(sql_err)?;
    }
    tx.commit().map_err(sql_err)?;
    Ok(())
}

/// Persistence for the active work queue and settled identity markers.
#[derive(Clone)]
pub struct JobStore {
    conn: SharedConn,
}

impl JobStore {
    /// Records a discovered job, inserting only when its identity is new.
    ///
    /// Returns `true` iff a row was inserted. An identity that already has an
    /// active or settled row stays untouched, so the local dedup never
    /// re-queues work the server would replay anyway.
    pub fn upsert_discovered(&self, job: &JobIdentity) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let now = now_utc();
        let inserted = guard
            .execute(
                "INSERT OR IGNORE INTO jobs
                     (dump_id, input_sha256, kind, analyzer_version,
                      phase, attempts, workspace_path, created_at, updated_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6
                 WHERE NOT EXISTS (
                     SELECT 1 FROM settled_jobs
                     WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                       AND analyzer_version = ?4
                 )",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version,
                    phase_str(JobPhase::Discovered),
                    now
                ],
            )
            .map_err(sql_err)?;
        Ok(inserted == 1)
    }

    /// Atomically moves the oldest `discovered` job to `claimed` and returns
    /// it together with its attempt count.
    ///
    /// Oldest is the earliest `created_at`; ties break on insertion order.
    /// The read-and-update runs in one immediate transaction, so two claimers
    /// can never take the same row.
    pub fn claim_next(&self) -> Result<Option<(JobIdentity, u32)>> {
        self.claim_matching_version(None)
    }

    /// A new capture profile must never execute an older analyzer's identity.
    pub fn claim_next_for_version(&self, version: &str) -> Result<Option<(JobIdentity, u32)>> {
        self.claim_matching_version(Some(version))
    }

    fn claim_matching_version(&self, version: Option<&str>) -> Result<Option<(JobIdentity, u32)>> {
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let found = tx
            .query_row(
                "SELECT dump_id, input_sha256, kind, analyzer_version, attempts
                   FROM jobs
                  WHERE phase = ?1 AND (?2 IS NULL OR analyzer_version = ?2)
                  ORDER BY created_at ASC, rowid ASC
                  LIMIT 1",
                params![phase_str(JobPhase::Discovered), version],
                |row| Ok((identity_from_row(row)?, row.get::<_, i64>(4)?)),
            )
            .optional()
            .map_err(sql_err)?;
        let claimed = match found {
            Some((job, attempts)) => {
                let changed = tx
                    .execute(
                        "UPDATE jobs
                            SET phase = ?1, updated_at = ?2
                          WHERE dump_id = ?3 AND input_sha256 = ?4 AND kind = ?5
                            AND analyzer_version = ?6 AND phase = ?7",
                        params![
                            phase_str(JobPhase::Claimed),
                            now_utc(),
                            job.dump_id,
                            job.input_sha256,
                            job.kind,
                            job.analyzer_version,
                            phase_str(JobPhase::Discovered)
                        ],
                    )
                    .map_err(sql_err)?;
                if changed != 1 {
                    return Err(AnalyzerError::State(format!(
                        "claim lost race for job {}",
                        job_key(&job)
                    )));
                }
                Some((job, attempts_u32(attempts)?))
            }
            None => None,
        };
        tx.commit().map_err(sql_err)?;
        Ok(claimed)
    }

    /// Persists a phase transition and refreshes `updated_at`. Terminal
    /// transitions atomically move the identity out of the active queue to
    /// `settled_jobs`, preserving its metadata. A settled identity can receive
    /// another terminal transition but cannot implicitly re-enter the queue.
    /// An unknown identity is a state error.
    pub fn set_phase(&self, job: &JobIdentity, phase: JobPhase) -> Result<()> {
        if !self.transition(job, None, phase)? {
            return Err(AnalyzerError::State(format!(
                "unknown job {}",
                job_key(job)
            )));
        }
        Ok(())
    }

    /// Transitions only if the persisted phase still equals `expected`.
    /// The comparison and transition share one immediate transaction, so
    /// settling discovered work cannot overwrite a concurrent claim.
    /// Returns `false` for a missing identity or phase mismatch. As with
    /// [`JobStore::set_phase`], settled identities cannot re-enter the queue.
    pub fn set_phase_if(
        &self,
        job: &JobIdentity,
        expected: JobPhase,
        phase: JobPhase,
    ) -> Result<bool> {
        self.transition(job, Some(expected), phase)
    }

    fn transition(
        &self,
        job: &JobIdentity,
        expected: Option<JobPhase>,
        phase: JobPhase,
    ) -> Result<bool> {
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let current: Option<(String, bool)> = tx
            .query_row(
                "SELECT phase, 1 FROM jobs
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4
                 UNION ALL
                 SELECT phase, 0 FROM settled_jobs
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4
                 LIMIT 1",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_err)?;
        let Some((current, active)) = current else {
            return Ok(false);
        };
        if expected.is_some_and(|expected| phase_str(expected) != current) {
            return Ok(false);
        }
        let terminal = is_terminal(phase);
        if !active && !terminal {
            return Err(AnalyzerError::State(format!(
                "settled job {} cannot re-enter the queue",
                job_key(job)
            )));
        }
        let now = now_utc();
        if active && terminal {
            tx.execute(
                "INSERT INTO settled_jobs
                     (dump_id, input_sha256, kind, analyzer_version,
                      phase, attempts, workspace_path, created_at, updated_at)
                 SELECT dump_id, input_sha256, kind, analyzer_version,
                        ?1, attempts, workspace_path, created_at, ?2
                   FROM jobs
                  WHERE dump_id = ?3 AND input_sha256 = ?4 AND kind = ?5
                    AND analyzer_version = ?6",
                params![
                    phase_str(phase),
                    now,
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
            tx.execute(
                "DELETE FROM jobs
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        } else {
            let sql = if active {
                "UPDATE jobs SET phase = ?1, updated_at = ?2
                  WHERE dump_id = ?3 AND input_sha256 = ?4 AND kind = ?5
                    AND analyzer_version = ?6"
            } else {
                "UPDATE settled_jobs SET phase = ?1, updated_at = ?2
                  WHERE dump_id = ?3 AND input_sha256 = ?4 AND kind = ?5
                    AND analyzer_version = ?6"
            };
            tx.execute(
                sql,
                params![
                    phase_str(phase),
                    now,
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        }
        tx.commit().map_err(sql_err)?;
        Ok(true)
    }

    /// Charges one transient failure against the job's bounded retry budget
    /// (the budget itself is policy: the agent compares the returned attempt
    /// count against its `MaxAttempts`-equivalent constant).
    pub fn record_attempt(&self, job: &JobIdentity) -> Result<()> {
        let guard = lock(&self.conn)?;
        let changed = guard
            .execute(
                "UPDATE jobs
                    SET attempts = attempts + 1, updated_at = ?1
                  WHERE dump_id = ?2 AND input_sha256 = ?3 AND kind = ?4
                    AND analyzer_version = ?5",
                params![
                    now_utc(),
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(AnalyzerError::State(format!(
                "unknown job {}",
                job_key(job)
            )));
        }
        Ok(())
    }

    /// The active or settled job's current phase, or `None` for an unknown
    /// identity. Settled identities remain queryable for lifecycle and dedup.
    pub fn phase_of(&self, job: &JobIdentity) -> Result<Option<JobPhase>> {
        let guard = lock(&self.conn)?;
        let raw: Option<String> = guard
            .query_row(
                "SELECT phase FROM jobs
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4
                 UNION ALL
                 SELECT phase FROM settled_jobs
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4
                 LIMIT 1",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        raw.map(|phase| phase_from_str(&phase)).transpose()
    }

    /// Lists identities currently in `phase`, oldest first, with their attempt
    /// counts. Active phases read the work queue; terminal phases read settled
    /// markers for lifecycle introspection, unlike [`JobStore::list`].
    /// Crash recovery uses this as specified: volatile phases
    /// (`fetching`/`staged`/`analyzing`) are reset to `claimed`, `reporting`
    /// is left for the verdict writer's reconciliation, and
    /// `done`/`dropped`/`failed` are terminal.
    pub fn jobs_in_phase(&self, phase: JobPhase) -> Result<Vec<(JobIdentity, u32)>> {
        let guard = lock(&self.conn)?;
        let table = if is_terminal(phase) {
            "settled_jobs"
        } else {
            "jobs"
        };
        let mut stmt = guard
            .prepare(&format!(
                "SELECT dump_id, input_sha256, kind, analyzer_version, attempts
                   FROM {table}
                  WHERE phase = ?1
                  ORDER BY created_at ASC, rowid ASC"
            ))
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![phase_str(phase)], |row| {
                Ok((identity_from_row(row)?, row.get::<_, i64>(4)?))
            })
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        rows.into_iter()
            .map(|(job, attempts)| Ok((job, attempts_u32(attempts)?)))
            .collect()
    }

    /// Marks the job `dropped`: the terminal state for a purge race or a 404
    /// at any server touch. Its settled marker prevents
    /// [`JobStore::upsert_discovered`] from re-queuing the identity.
    pub fn drop_job(&self, job: &JobIdentity) -> Result<()> {
        self.set_phase(job, JobPhase::Dropped)
    }

    /// Lists discovery candidates and active work with lifecycle timestamps,
    /// oldest first. Operator queue reads should use [`JobStore::work_queue`]
    /// to avoid loading the discovery inventory. Scheduling order is
    /// [`JobStore::claim_next`]'s, not this listing's.
    pub fn list(&self) -> Result<Vec<JobRow>> {
        self.list_where("1")
    }

    /// Lists only claimed, fetching, staged, analyzing, or reporting work,
    /// oldest first. Discovery candidates are excluded by SQLite so dashboard
    /// queue reads allocate and decode only the active work rows.
    pub fn work_queue(&self) -> Result<Vec<JobRow>> {
        self.list_where("phase IN ('claimed', 'fetching', 'staged', 'analyzing', 'reporting')")
    }

    // Predicates are private SQL literals from the two listing methods.
    fn list_where(&self, predicate: &str) -> Result<Vec<JobRow>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(&format!(
                "SELECT dump_id, input_sha256, kind, analyzer_version,
                        phase, attempts, created_at, updated_at
                   FROM jobs
                  WHERE {predicate}
                  ORDER BY created_at ASC, rowid ASC"
            ))
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    identity_from_row(row)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        rows.into_iter()
            .map(|(identity, phase, attempts, created_at, updated_at)| {
                Ok(JobRow {
                    identity,
                    phase: phase_from_str(&phase)?,
                    attempts: attempts_u32(attempts)?,
                    created_at,
                    updated_at,
                })
            })
            .collect()
    }
}

/// A job row with lifecycle timestamps, for observability reads.
#[derive(Debug, Clone)]
pub struct JobRow {
    pub identity: JobIdentity,
    pub phase: JobPhase,
    pub attempts: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// Named server-held secrets (migration 2). Values are written on change and
/// never logged; `Debug` is not implemented on purpose.
#[derive(Clone)]
pub struct Secrets {
    conn: SharedConn,
}

impl Secrets {
    /// Reads a secret by name.
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        let guard = lock(&self.conn)?;
        guard
            .query_row(
                "SELECT value FROM secrets WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)
    }

    /// Stores (insert-or-replace) the latest value of a secret.
    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        let guard = lock(&self.conn)?;
        guard
            .execute(
                "INSERT INTO secrets (name, value) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                params![name, value],
            )
            .map_err(sql_err)?;
        Ok(())
    }
}

/// Persistence for named cursors; the only consumer is the event-feed cursor
/// (`CursorMonotonic` in `specs/DumpAnalyzer.tla`: never backward).
#[derive(Clone)]
pub struct CursorStore {
    conn: SharedConn,
}

impl CursorStore {
    /// Reads the cursor, or `None` when `name` was never persisted.
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        let guard = lock(&self.conn)?;
        guard
            .query_row(
                "SELECT value FROM cursors WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)
    }

    /// Sets `name` to `value`, rejecting a value that is lexically smaller
    /// than the stored one with [`AnalyzerError::State`]. Cursors are
    /// zero-padded rowids, so lexical order is numeric order; an equal value
    /// is accepted as a no-op.
    pub fn set_monotonic(&self, name: &str, value: &str) -> Result<()> {
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT value FROM cursors WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if let Some(current) = current.as_deref()
            && value < current
        {
            return Err(AnalyzerError::State(format!(
                "cursor '{name}' would move backward: {current} -> {value}"
            )));
        }
        tx.execute(
            "INSERT INTO cursors (name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, value],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }
}

/// One byte-cache row: content hash mapped to a local file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub sha256: String,
    pub path: String,
    pub byte_size: u64,
    pub etag: Option<String>,
    pub last_used_at: String,
}

/// The byte-cache index: already-downloaded dump bytes keyed by content
/// sha256.
#[derive(Clone)]
pub struct CacheIndex {
    conn: SharedConn,
}

impl CacheIndex {
    /// Inserts or refreshes the index entry for `sha256` and stamps it as
    /// just used. `etag` may be `None` (the server sent none); a previously
    /// stored ETag is kept in that case so conditional revalidation is not
    /// silently lost.
    pub fn upsert(
        &self,
        sha256: &str,
        path: &str,
        byte_size: u64,
        etag: Option<&str>,
    ) -> Result<()> {
        let byte_size = i64::try_from(byte_size).map_err(|_| {
            AnalyzerError::State(format!("byte_cache.byte_size out of range: {byte_size}"))
        })?;
        let guard = lock(&self.conn)?;
        guard
            .execute(
                "INSERT INTO byte_cache (sha256, path, byte_size, etag, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sha256) DO UPDATE SET
                     path = excluded.path,
                     byte_size = excluded.byte_size,
                     etag = COALESCE(excluded.etag, byte_cache.etag),
                     last_used_at = excluded.last_used_at",
                params![sha256, path, byte_size, etag, now_utc()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// Stamps `last_used_at`; `false` when the sha256 is not indexed.
    pub fn touch(&self, sha256: &str) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let changed = guard
            .execute(
                "UPDATE byte_cache SET last_used_at = ?2 WHERE sha256 = ?1",
                params![sha256, now_utc()],
            )
            .map_err(sql_err)?;
        Ok(changed == 1)
    }

    /// Looks up the index entry without touching it.
    pub fn lookup(&self, sha256: &str) -> Result<Option<CacheEntry>> {
        let guard = lock(&self.conn)?;
        guard
            .query_row(
                "SELECT sha256, path, byte_size, etag, last_used_at
                   FROM byte_cache WHERE sha256 = ?1",
                params![sha256],
                |row| {
                    Ok(CacheEntry {
                        sha256: row.get(0)?,
                        path: row.get(1)?,
                        byte_size: byte_size_u64(row.get::<_, i64>(2)?)?,
                        etag: row.get(3)?,
                        last_used_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(sql_err)
    }

    /// Bytes accounted to the cache: the sum of every indexed `byte_size`.
    ///
    /// This is the bookkeeping total the cap is enforced against; the files
    /// on disk match it as long as the delete ordering (index row first,
    /// file second) is upheld by eviction.
    pub fn total_bytes(&self) -> Result<u64> {
        let guard = lock(&self.conn)?;
        let total: i64 = guard
            .query_row(
                "SELECT COALESCE(SUM(byte_size), 0) FROM byte_cache",
                [],
                |row| row.get(0),
            )
            .map_err(sql_err)?;
        u64::try_from(total)
            .map_err(|_| AnalyzerError::State(format!("byte_cache total out of range: {total}")))
    }

    /// Evicts least-recently-used entries — oldest `last_used_at` first,
    /// ties by insertion order — until at least `excess` bytes are accounted
    /// as freed or no further rows remain. Returns `(sha256, path)` for
    /// every row removed from the index so the caller can delete the files.
    ///
    /// The index rows are removed here, in one transaction; the caller
    /// deletes the returned files afterwards. A crash between the two leaves
    /// an unreferenced orphan file — which a later fetch of the same content
    /// overwrites and a sweep can delete — never an index row pointing at a
    /// missing file.
    pub fn evict_lru(&self, excess: u64) -> Result<Vec<(String, String)>> {
        if excess == 0 {
            return Ok(Vec::new());
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let rows: Vec<(String, String, i64)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT sha256, path, byte_size
                       FROM byte_cache
                      ORDER BY last_used_at ASC, rowid ASC",
                )
                .map_err(sql_err)?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?
        };
        let mut freed: u64 = 0;
        let mut evicted: Vec<(String, String)> = Vec::new();
        for (sha256, path, byte_size) in rows {
            if freed >= excess {
                break;
            }
            tx.execute("DELETE FROM byte_cache WHERE sha256 = ?1", params![sha256])
                .map_err(sql_err)?;
            freed = freed.saturating_add(byte_size_u64(byte_size).map_err(sql_err)?);
            evicted.push((sha256, path));
        }
        tx.commit().map_err(sql_err)?;
        Ok(evicted)
    }
}

/// One stored local verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReport {
    pub dump_id: String,
    pub input_sha256: String,
    pub kind: String,
    pub analyzer_version: String,
    pub outcome: ReportOutcome,
    pub summary: String,
    pub facts_json: String,
    pub created_at: String,
    pub posted: bool,
}

impl LocalReport {
    /// The job identity this report belongs to.
    pub fn identity(&self) -> JobIdentity {
        JobIdentity {
            dump_id: self.dump_id.clone(),
            input_sha256: self.input_sha256.clone(),
            kind: self.kind.clone(),
            analyzer_version: self.analyzer_version.clone(),
        }
    }
}

/// Full-detail publication is independent from v1 summary acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FullDelivery {
    LocalOnly,
    PendingFull,
    SummaryOnly,
    FullyDelivered,
    Abandoned,
}

impl FullDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "localOnly",
            Self::PendingFull => "pendingFull",
            Self::SummaryOnly => "summaryOnly",
            Self::FullyDelivered => "fullyDelivered",
            Self::Abandoned => "abandoned",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "localOnly" => Ok(Self::LocalOnly),
            "pendingFull" => Ok(Self::PendingFull),
            "summaryOnly" => Ok(Self::SummaryOnly),
            "fullyDelivered" => Ok(Self::FullyDelivered),
            "abandoned" => Ok(Self::Abandoned),
            _ => Err(AnalyzerError::State(format!(
                "unknown full report delivery {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportHandoff {
    Scheduled,
    Manual,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReport {
    pub report: CrashReportV2,
    pub report_json: String,
    pub digest: String,
    pub delivery: FullDelivery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportDetail {
    Rich(Box<StoredReport>),
    Legacy(LocalReport),
}

/// List projection: never contains or deserializes facts or canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportListRow {
    pub dump_id: String,
    pub input_sha256: String,
    pub kind: String,
    pub analyzer_version: String,
    pub outcome: ReportOutcome,
    pub summary: String,
    pub created_at: String,
    pub posted: bool,
    pub report_id: String,
    pub schema_version: u32,
    pub detail_available: bool,
    pub full_delivery: FullDelivery,
}

/// Filters and pagination for browsing local reports. Search terms are
/// literal substrings of the dump ID, kind, analyzer version, or summary;
/// ASCII case is ignored. Page sizes are bounded again by the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportQuery {
    pub q: String,
    pub outcome: Option<ReportOutcome>,
    pub posted: Option<bool>,
    pub page: u32,
    pub page_size: u32,
}

impl Default for ReportQuery {
    fn default() -> Self {
        Self {
            q: String::new(),
            outcome: None,
            posted: None,
            page: 1,
            page_size: 25,
        }
    }
}

/// One bounded report page with full-store counts for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPage {
    pub reports: Vec<ReportListRow>,
    pub total: u64,
    pub matching: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u64,
    pub pending: u64,
}

// Keep the count and page predicates identical. The optional LIKE pattern
// is bound after escaping its metacharacters; SQL syntax never comes from
// user input. LOWER supplies explicit ASCII-insensitive search semantics.
const REPORT_PAGE_FILTER: &str = r"
 WHERE (?1 IS NULL
        OR LOWER(dump_id) LIKE LOWER(?1) ESCAPE '\'
        OR LOWER(kind) LIKE LOWER(?1) ESCAPE '\'
        OR LOWER(analyzer_version) LIKE LOWER(?1) ESCAPE '\'
        OR LOWER(summary) LIKE LOWER(?1) ESCAPE '\')
   AND (?2 IS NULL OR outcome = ?2)
   AND (?3 IS NULL OR posted = ?3)";

/// Local verdicts produced in local-verdict mode (the server write-back
/// route is absent); kept until POSTed.
#[derive(Clone)]
pub struct LocalReportStore {
    conn: SharedConn,
}

impl LocalReportStore {
    /// Atomically preserve authoritative evidence, its compatibility projection,
    /// and the queue handoff. Canonical identities are immutable.
    pub fn save_rich(
        &self,
        report: &CrashReportV2,
        compact: &AnalysisReportSubmission,
        handoff: ReportHandoff,
        writeback_enabled: bool,
    ) -> Result<StoredReport> {
        report.validate()?;
        compact.validate()?;
        let job = report.identity.job();
        let report_json = report.canonical_json()?;
        let digest = digest_json(&report_json);
        let facts_json = compact
            .facts
            .as_ref()
            .map_or_else(|| "null".into(), ToString::to_string);
        let binding = compact.facts.as_ref();
        if compact.analyzer.name != report.identity.analyzer_name
            || compact.analyzer.version != job.analyzer_version
            || compact.kind != job.kind
            || compact.input_sha256 != job.input_sha256
            || compact.outcome != report.outcome
            || compact.summary != report.summary
            || binding
                .and_then(|f| f.get("reportId"))
                .and_then(|v| v.as_str())
                != Some(report.report_id.as_str())
            || binding
                .and_then(|f| f.get("reportDigest"))
                .and_then(|v| v.as_str())
                != Some(digest.as_str())
            || binding
                .and_then(|f| f.get("schemaVersion"))
                .and_then(|v| v.as_u64())
                != Some(2)
            || facts_json.len() > 4096
        {
            return Err(AnalyzerError::Integrity(
                "compact report does not preserve its canonical binding".into(),
            ));
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let existing = rich_for_identity(&tx, &job)?;
        if existing
            .as_ref()
            .is_some_and(|stored| stored.digest != digest || stored.report_json != report_json)
        {
            return Err(AnalyzerError::Integrity(format!(
                "immutable rich report conflict {}",
                job_key(&job)
            )));
        }
        let existing_compact = tx
            .query_row(
                "SELECT outcome, summary, facts_json, posted FROM local_reports
              WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3 AND analyzer_version = ?4",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(sql_err)?;
        if existing_compact
            .as_ref()
            .is_some_and(|(outcome, summary, facts, _)| {
                outcome != outcome_str(compact.outcome)
                    || summary != &compact.summary
                    || facts != &facts_json
            })
        {
            return Err(AnalyzerError::Integrity(format!(
                "immutable compact report conflict {}",
                job_key(&job)
            )));
        }
        let now = now_utc();
        tx.execute(
            "INSERT OR IGNORE INTO local_reports
              (dump_id,input_sha256,kind,analyzer_version,outcome,summary,facts_json,created_at,posted,report_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,?9)",
            params![job.dump_id,job.input_sha256,job.kind,job.analyzer_version,
                outcome_str(compact.outcome),compact.summary,facts_json,now,report.report_id],
        ).map_err(sql_err)?;
        tx.execute(
            "UPDATE local_reports SET report_id = ?1 WHERE dump_id = ?2 AND input_sha256 = ?3
              AND kind = ?4 AND analyzer_version = ?5",
            params![
                report.report_id,
                job.dump_id,
                job.input_sha256,
                job.kind,
                job.analyzer_version
            ],
        )
        .map_err(sql_err)?;
        let delivery = existing.as_ref().map_or(
            if writeback_enabled {
                FullDelivery::PendingFull
            } else {
                FullDelivery::LocalOnly
            },
            |stored| stored.delivery,
        );
        tx.execute(
            "INSERT OR IGNORE INTO report_details
              (report_id,dump_id,input_sha256,kind,analyzer_version,digest,report_json,full_delivery)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![report.report_id,job.dump_id,job.input_sha256,job.kind,job.analyzer_version,
                digest,report_json,delivery.as_str()],
        ).map_err(sql_err)?;
        rich_handoff(
            &tx,
            &job,
            handoff,
            writeback_enabled,
            existing_compact
                .as_ref()
                .is_some_and(|(_, _, _, posted)| *posted),
        )?;
        tx.commit().map_err(sql_err)?;
        Ok(StoredReport {
            report: report.clone(),
            report_json,
            digest,
            delivery,
        })
    }

    pub fn get_rich(&self, job: &JobIdentity) -> Result<Option<StoredReport>> {
        let guard = lock(&self.conn)?;
        rich_for_identity(&guard, job)
    }

    /// One lazy detail lookup. Legacy rows expose only their surviving v1 facts.
    pub fn get_detail(&self, report_id: &str) -> Result<Option<ReportDetail>> {
        let guard = lock(&self.conn)?;
        let rich = guard.query_row(
            "SELECT report_id, digest, report_json, full_delivery FROM report_details WHERE report_id = ?1",
            params![report_id], RawRichReport::from_row,
        ).optional().map_err(sql_err)?;
        if let Some(rich) = rich {
            return Ok(Some(ReportDetail::Rich(Box::new(rich.into_report()?))));
        }
        let raw = guard.query_row(
            "SELECT dump_id,input_sha256,kind,analyzer_version,outcome,summary,facts_json,created_at,posted
               FROM local_reports WHERE report_id = ?1", params![report_id], RawLocalReport::from_row,
        ).optional().map_err(sql_err)?;
        raw.map(|row| row.into_report().map(ReportDetail::Legacy))
            .transpose()
    }

    /// Full documents awaiting a v2 ACK, including summaries accepted by v1.
    /// Local-only reports require an explicit policy change before publication.
    pub fn pending_full(&self) -> Result<Vec<StoredReport>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(
                "SELECT report_id,digest,report_json,full_delivery FROM report_details
              WHERE full_delivery IN ('pendingFull','summaryOnly') ORDER BY rowid ASC LIMIT 32",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], RawRichReport::from_row)
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        rows.into_iter().map(RawRichReport::into_report).collect()
    }

    /// Outbox scan loads only identity columns. The caller fetches one full
    /// document at a time, independently of backlog size.
    pub fn pending_full_identities(&self) -> Result<Vec<JobIdentity>> {
        let guard = lock(&self.conn)?;
        let mut statement=guard.prepare("SELECT dump_id,input_sha256,kind,analyzer_version FROM report_details WHERE full_delivery IN ('pendingFull','summaryOnly') ORDER BY rowid").map_err(sql_err)?;
        statement
            .query_map([], identity_from_row)
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)
    }

    pub fn set_full_delivery(&self, job: &JobIdentity, delivery: FullDelivery) -> Result<()> {
        let guard = lock(&self.conn)?;
        let changed = guard.execute(
            "UPDATE report_details SET full_delivery = ?1 WHERE dump_id = ?2 AND input_sha256 = ?3
              AND kind = ?4 AND analyzer_version = ?5",
            params![delivery.as_str(),job.dump_id,job.input_sha256,job.kind,job.analyzer_version],
        ).map_err(sql_err)?;
        if changed != 1 {
            return Err(AnalyzerError::State(format!(
                "unknown rich report {}",
                job_key(job)
            )));
        }
        Ok(())
    }

    /// Records a locally assembled verdict, inserting only when the identity
    /// is new (a re-draft for an existing identity is ignored; the server's
    /// idempotent identity is the correctness boundary). `created_at` is
    /// stamped here.
    pub fn insert(
        &self,
        job: &JobIdentity,
        outcome: ReportOutcome,
        summary: &str,
        facts_json: &str,
    ) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let inserted = guard
            .execute(
                "INSERT OR IGNORE INTO local_reports
                     (dump_id, input_sha256, kind, analyzer_version, outcome,
                      summary, facts_json, created_at, posted, report_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version,
                    outcome_str(outcome),
                    summary,
                    facts_json,
                    now_utc(),
                    legacy_id(job)
                ],
            )
            .map_err(sql_err)?;
        Ok(inserted == 1)
    }

    /// Fetches the stored verdict for an identity, if any.
    pub fn get(&self, job: &JobIdentity) -> Result<Option<LocalReport>> {
        let guard = lock(&self.conn)?;
        let raw = guard
            .query_row(
                "SELECT dump_id, input_sha256, kind, analyzer_version, outcome,
                        summary, facts_json, created_at, posted
                   FROM local_reports
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
                RawLocalReport::from_row,
            )
            .optional()
            .map_err(sql_err)?;
        raw.map(RawLocalReport::into_report).transpose()
    }

    /// The replay queue: reports the server has not accepted yet
    /// (`posted = 0`), oldest first.
    pub fn pending(&self) -> Result<Vec<LocalReport>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(
                "SELECT dump_id, input_sha256, kind, analyzer_version, outcome,
                        summary, facts_json, created_at, posted
                   FROM local_reports
                  WHERE posted = 0
                  ORDER BY created_at ASC, rowid ASC",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], RawLocalReport::from_row)
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        rows.into_iter().map(RawLocalReport::into_report).collect()
    }

    /// Lists recent reports (posted and pending), newest first, bounded by
    /// `limit`. Read-only observability for the status UI.
    pub fn list_recent(&self, limit: u32) -> Result<Vec<LocalReport>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(
                "SELECT dump_id, input_sha256, kind, analyzer_version, outcome,
                        summary, facts_json, created_at, posted
                   FROM local_reports
                  ORDER BY created_at DESC, rowid DESC
                  LIMIT ?1",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![i64::from(limit)], RawLocalReport::from_row)
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        rows.into_iter().map(RawLocalReport::into_report).collect()
    }

    /// Counts all reports and all reports awaiting delivery, without a
    /// recent-report limit and without loading their facts into memory.
    pub fn counts(&self) -> Result<(u64, u64)> {
        let guard = lock(&self.conn)?;
        report_counts(&guard)
    }

    /// Browses reports newest first with bounded memory use. The shared
    /// connection lock keeps counts and rows consistent with this process's
    /// writers. Page zero becomes one, size is clamped to 1..=100, and pages
    /// beyond the matching result set become its last page. An empty result
    /// set has page one and zero total pages.
    pub fn page(&self, query: &ReportQuery) -> Result<ReportPage> {
        let guard = lock(&self.conn)?;
        let (total, pending) = report_counts(&guard)?;
        let pattern = if query.q.is_empty() {
            None
        } else {
            let mut escaped = String::with_capacity(query.q.len() + 2);
            escaped.push('%');
            for ch in query.q.chars() {
                if matches!(ch, '%' | '_' | '\\') {
                    escaped.push('\\');
                }
                escaped.push(ch);
            }
            escaped.push('%');
            Some(escaped)
        };
        let outcome = query.outcome.map(outcome_str);
        let matching: u64 = guard
            .query_row(
                &format!("SELECT COUNT(*) FROM local_reports {REPORT_PAGE_FILTER}"),
                params![pattern, outcome, query.posted],
                |row| row.get(0),
            )
            .map_err(sql_err)?;
        let page_size = query.page_size.clamp(1, 100);
        let total_pages = matching.div_ceil(u64::from(page_size));
        // The minimum is bounded by the requested u32 page. Computing the
        // offset in i64 is safe even for u32::MAX at the maximum size 100.
        let page = u64::from(query.page.max(1)).min(total_pages.max(1)) as u32;
        let offset = i64::from(page - 1) * i64::from(page_size);
        let mut stmt = guard
            .prepare(&format!(
                "SELECT dump_id, input_sha256, kind, analyzer_version, outcome,
                        summary, created_at, posted, report_id,
                        EXISTS(SELECT 1 FROM report_details d WHERE d.report_id = local_reports.report_id),
                        COALESCE((SELECT full_delivery FROM report_details d
                                   WHERE d.report_id = local_reports.report_id), CASE WHEN posted = 1 THEN 'summaryOnly' ELSE 'localOnly' END)
                   FROM local_reports
                   {REPORT_PAGE_FILTER}
                  ORDER BY created_at DESC, rowid DESC
                  LIMIT ?4 OFFSET ?5"
            ))
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(
                params![pattern, outcome, query.posted, i64::from(page_size), offset],
                RawReportListRow::from_row,
            )
            .map_err(sql_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err)?;
        let reports = rows
            .into_iter()
            .map(RawReportListRow::into_report)
            .collect::<Result<Vec<_>>>()?;
        Ok(ReportPage {
            reports,
            total,
            matching,
            page,
            page_size,
            total_pages,
            pending,
        })
    }

    /// Marks the stored verdict for `job` as POSTed. An unknown identity is
    /// a state error.
    pub fn mark_posted(&self, job: &JobIdentity) -> Result<()> {
        let guard = lock(&self.conn)?;
        let changed = guard
            .execute(
                "UPDATE local_reports SET posted = 1
                  WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3
                    AND analyzer_version = ?4",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(AnalyzerError::State(format!(
                "unknown local report {}",
                job_key(job)
            )));
        }
        Ok(())
    }
}

fn rich_handoff(
    tx: &rusqlite::Transaction<'_>,
    job: &JobIdentity,
    handoff: ReportHandoff,
    writeback_enabled: bool,
    posted: bool,
) -> Result<()> {
    if handoff == ReportHandoff::None {
        return Ok(());
    }
    let current: Option<String> = tx.query_row(
        "SELECT phase FROM jobs WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3 AND analyzer_version = ?4",
        params![job.dump_id,job.input_sha256,job.kind,job.analyzer_version], |row| row.get(0),
    ).optional().map_err(sql_err)?;
    let settled: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM settled_jobs WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3 AND analyzer_version = ?4)",
        params![job.dump_id,job.input_sha256,job.kind,job.analyzer_version], |row| row.get(0),
    ).map_err(sql_err)?;
    // A purge or another completion can race the capture. Keep its evidence,
    // while never resurrecting a settled identity.
    if settled {
        return Ok(());
    }
    let now = now_utc();
    match handoff {
        ReportHandoff::Scheduled => {
            if !matches!(current.as_deref(), Some("analyzing" | "reporting")) {
                return Err(AnalyzerError::State(format!(
                    "rich report handoff requires analyzing job {}",
                    job_key(job)
                )));
            }
            tx.execute(
                "UPDATE jobs SET phase = 'reporting', updated_at = ?1 WHERE dump_id = ?2
                  AND input_sha256 = ?3 AND kind = ?4 AND analyzer_version = ?5",
                params![
                    now,
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version
                ],
            )
            .map_err(sql_err)?;
        }
        ReportHandoff::Manual => {
            if current.is_none() {
                tx.execute(
                    "INSERT INTO jobs (dump_id,input_sha256,kind,analyzer_version,phase,attempts,created_at,updated_at)
                     VALUES (?1,?2,?3,?4,'discovered',0,?5,?5)",
                    params![job.dump_id,job.input_sha256,job.kind,job.analyzer_version,now],
                ).map_err(sql_err)?;
            }
            if current
                .as_deref()
                .is_some_and(|phase| !matches!(phase, "discovered" | "reporting"))
            {
                return Ok(());
            }
            if writeback_enabled && !posted {
                tx.execute(
                    "UPDATE jobs SET phase = 'reporting', updated_at = ?1 WHERE dump_id = ?2
                      AND input_sha256 = ?3 AND kind = ?4 AND analyzer_version = ?5",
                    params![
                        now,
                        job.dump_id,
                        job.input_sha256,
                        job.kind,
                        job.analyzer_version
                    ],
                )
                .map_err(sql_err)?;
            } else {
                tx.execute(
                    "INSERT INTO settled_jobs (dump_id,input_sha256,kind,analyzer_version,phase,attempts,workspace_path,created_at,updated_at)
                     SELECT dump_id,input_sha256,kind,analyzer_version,'done',attempts,workspace_path,created_at,?1
                       FROM jobs WHERE dump_id = ?2 AND input_sha256 = ?3 AND kind = ?4 AND analyzer_version = ?5",
                    params![now,job.dump_id,job.input_sha256,job.kind,job.analyzer_version],
                ).map_err(sql_err)?;
                tx.execute(
                    "DELETE FROM jobs WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3 AND analyzer_version = ?4",
                    params![job.dump_id,job.input_sha256,job.kind,job.analyzer_version],
                ).map_err(sql_err)?;
            }
        }
        ReportHandoff::None => (),
    }
    Ok(())
}

struct RawRichReport {
    report_id: String,
    digest: String,
    report_json: String,
    delivery: String,
}

impl RawRichReport {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            report_id: row.get(0)?,
            digest: row.get(1)?,
            report_json: row.get(2)?,
            delivery: row.get(3)?,
        })
    }
    fn into_report(self) -> Result<StoredReport> {
        if digest_json(&self.report_json) != self.digest {
            return Err(AnalyzerError::Integrity(
                "stored canonical report digest mismatch".into(),
            ));
        }
        let report: CrashReportV2 = serde_json::from_str(&self.report_json)
            .map_err(|err| AnalyzerError::Integrity(format!("stored canonical report: {err}")))?;
        report.validate()?;
        if report.report_id != self.report_id {
            return Err(AnalyzerError::Integrity(
                "stored canonical report locator mismatch".into(),
            ));
        }
        Ok(StoredReport {
            report,
            report_json: self.report_json,
            digest: self.digest,
            delivery: FullDelivery::parse(&self.delivery)?,
        })
    }
}

fn rich_for_identity(conn: &Connection, job: &JobIdentity) -> Result<Option<StoredReport>> {
    let raw = conn
        .query_row(
            "SELECT report_id,digest,report_json,full_delivery FROM report_details
          WHERE dump_id = ?1 AND input_sha256 = ?2 AND kind = ?3 AND analyzer_version = ?4",
            params![
                job.dump_id,
                job.input_sha256,
                job.kind,
                job.analyzer_version
            ],
            RawRichReport::from_row,
        )
        .optional()
        .map_err(sql_err)?;
    let stored = raw.map(RawRichReport::into_report).transpose()?;
    if stored
        .as_ref()
        .is_some_and(|stored| stored.report.identity.job() != *job)
    {
        return Err(AnalyzerError::Integrity(
            "stored canonical report identity mismatch".into(),
        ));
    }
    Ok(stored)
}

struct RawReportListRow {
    job: JobIdentity,
    outcome: String,
    summary: String,
    created_at: String,
    posted: bool,
    report_id: Option<String>,
    detail_available: bool,
    full_delivery: String,
}

impl RawReportListRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            job: JobIdentity {
                dump_id: row.get(0)?,
                input_sha256: row.get(1)?,
                kind: row.get(2)?,
                analyzer_version: row.get(3)?,
            },
            outcome: row.get(4)?,
            summary: row.get(5)?,
            created_at: row.get(6)?,
            posted: row.get(7)?,
            report_id: row.get(8)?,
            detail_available: row.get(9)?,
            full_delivery: row.get(10)?,
        })
    }
    fn into_report(self) -> Result<ReportListRow> {
        let report_id = self.report_id.unwrap_or_else(|| legacy_id(&self.job));
        Ok(ReportListRow {
            dump_id: self.job.dump_id,
            input_sha256: self.job.input_sha256,
            kind: self.job.kind,
            analyzer_version: self.job.analyzer_version,
            outcome: outcome_from_str(&self.outcome)?,
            summary: self.summary,
            created_at: self.created_at,
            posted: self.posted,
            report_id,
            schema_version: if self.detail_available { 2 } else { 1 },
            detail_available: self.detail_available,
            full_delivery: FullDelivery::parse(&self.full_delivery)?,
        })
    }
}

fn report_counts(conn: &Connection) -> Result<(u64, u64)> {
    conn.query_row(
        "SELECT COUNT(*), COUNT(CASE WHEN posted = 0 THEN 1 END) FROM local_reports",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(sql_err)
}

/// Raw `local_reports` row; outcome is parsed after collection so an unknown
/// spelling becomes a state error rather than a decode error.
struct RawLocalReport {
    dump_id: String,
    input_sha256: String,
    kind: String,
    analyzer_version: String,
    outcome: String,
    summary: String,
    facts_json: String,
    created_at: String,
    posted: i64,
}

impl RawLocalReport {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawLocalReport> {
        Ok(RawLocalReport {
            dump_id: row.get(0)?,
            input_sha256: row.get(1)?,
            kind: row.get(2)?,
            analyzer_version: row.get(3)?,
            outcome: row.get(4)?,
            summary: row.get(5)?,
            facts_json: row.get(6)?,
            created_at: row.get(7)?,
            posted: row.get(8)?,
        })
    }

    fn into_report(self) -> Result<LocalReport> {
        Ok(LocalReport {
            dump_id: self.dump_id,
            input_sha256: self.input_sha256,
            kind: self.kind,
            analyzer_version: self.analyzer_version,
            outcome: outcome_from_str(&self.outcome)?,
            summary: self.summary,
            facts_json: self.facts_json,
            created_at: self.created_at,
            posted: self.posted != 0,
        })
    }
}

/// The persisted phase spelling (kebab-case, matching `JobPhase`'s serde
/// representation).
///
/// `phase_from_str` is exposed so raw rows and logs can be interpreted with
/// the same mapping the store writes.
pub fn phase_from_str(value: &str) -> Result<JobPhase> {
    match value {
        "discovered" => Ok(JobPhase::Discovered),
        "claimed" => Ok(JobPhase::Claimed),
        "fetching" => Ok(JobPhase::Fetching),
        "staged" => Ok(JobPhase::Staged),
        "analyzing" => Ok(JobPhase::Analyzing),
        "reporting" => Ok(JobPhase::Reporting),
        "done" => Ok(JobPhase::Done),
        "dropped" => Ok(JobPhase::Dropped),
        "failed" => Ok(JobPhase::Failed),
        other => Err(AnalyzerError::State(format!(
            "jobs.phase unknown: {other:?}"
        ))),
    }
}

fn is_terminal(phase: JobPhase) -> bool {
    matches!(phase, JobPhase::Done | JobPhase::Dropped | JobPhase::Failed)
}

fn phase_str(phase: JobPhase) -> &'static str {
    match phase {
        JobPhase::Discovered => "discovered",
        JobPhase::Claimed => "claimed",
        JobPhase::Fetching => "fetching",
        JobPhase::Staged => "staged",
        JobPhase::Analyzing => "analyzing",
        JobPhase::Reporting => "reporting",
        JobPhase::Done => "done",
        JobPhase::Dropped => "dropped",
        JobPhase::Failed => "failed",
    }
}

fn outcome_str(outcome: ReportOutcome) -> &'static str {
    match outcome {
        ReportOutcome::Completed => "completed",
        ReportOutcome::Failed => "failed",
    }
}

fn outcome_from_str(value: &str) -> Result<ReportOutcome> {
    match value {
        "completed" => Ok(ReportOutcome::Completed),
        "failed" => Ok(ReportOutcome::Failed),
        other => Err(AnalyzerError::State(format!(
            "local_reports.outcome unknown: {other:?}"
        ))),
    }
}

fn identity_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobIdentity> {
    Ok(JobIdentity {
        dump_id: row.get(0)?,
        input_sha256: row.get(1)?,
        kind: row.get(2)?,
        analyzer_version: row.get(3)?,
    })
}

fn attempts_u32(value: i64) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| AnalyzerError::State(format!("jobs.attempts out of range: {value}")))
}

fn byte_size_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn job_key(job: &JobIdentity) -> String {
    format!(
        "{}/{}/{}/{}",
        job.dump_id, job.kind, job.analyzer_version, job.input_sha256
    )
}

fn lock(conn: &SharedConn) -> Result<MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| AnalyzerError::State("state database mutex poisoned".to_string()))
}

fn sql_err(error: rusqlite::Error) -> AnalyzerError {
    AnalyzerError::State(format!("sqlite: {error}"))
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (second precision).
pub(crate) fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    format_utc(secs)
}

/// Formats Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (civil UTC date via the
/// standard days-to-civil inversion; the approved manifest has no time
/// crate).
fn format_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to `(y, m, d)`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_format_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(2_147_483_647), "2038-01-19T03:14:07Z");
        assert_eq!(format_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn now_utc_has_canonical_shape() {
        let now = now_utc();
        assert_eq!(now.len(), 20, "unexpected timestamp: {now}");
        assert!(now.ends_with('Z'), "unexpected timestamp: {now}");
        for (index, byte) in now.bytes().enumerate() {
            let expected = match index {
                4 | 7 => b'-',
                10 => b'T',
                13 | 16 => b':',
                _ => continue,
            };
            assert_eq!(byte, expected, "unexpected timestamp: {now}");
        }
        assert!(
            now.bytes().enumerate().all(|(index, byte)| match index {
                4 | 7 | 10 | 13 | 16 => true,
                19 => byte == b'Z',
                _ => byte.is_ascii_digit(),
            }),
            "unexpected timestamp: {now}"
        );
    }

    #[test]
    fn phase_and_outcome_spellings_match_serde() {
        let phases = [
            JobPhase::Discovered,
            JobPhase::Claimed,
            JobPhase::Fetching,
            JobPhase::Staged,
            JobPhase::Analyzing,
            JobPhase::Reporting,
            JobPhase::Done,
            JobPhase::Dropped,
            JobPhase::Failed,
        ];
        for phase in phases {
            let serde = serde_json::to_value(phase).unwrap();
            let serde = serde.as_str().unwrap().to_string();
            assert_eq!(phase_str(phase), serde);
            assert_eq!(phase_from_str(&serde).unwrap(), phase);
        }
        assert!(phase_from_str("bogus").is_err());

        for outcome in [ReportOutcome::Completed, ReportOutcome::Failed] {
            let serde = serde_json::to_value(outcome).unwrap();
            let serde = serde.as_str().unwrap();
            assert_eq!(outcome_str(outcome), serde);
            assert_eq!(outcome_from_str(serde).unwrap(), outcome);
        }
        assert!(outcome_from_str("bogus").is_err());
    }
}
