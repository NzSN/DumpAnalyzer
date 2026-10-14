//! Local SQLite state: jobs, cursors, byte-cache index, local reports
//! (task A3; docs/analyzer-design.md "Module design", "Correctness and
//! idempotency").
//!
//! [`Store`] owns one connection to `data/analyzer.sqlite` and hands out four
//! narrow sub-stores that share it: [`JobStore`], [`CursorStore`],
//! [`CacheIndex`], and [`LocalReportStore`]. The schema is applied through a
//! `schema_migrations` ledger; migration 1 is the only migration, is applied
//! at most once per database, and reopening an initialized database re-runs
//! nothing.
//!
//! The tables back the job lifecycle modeled in `specs/DumpAnalyzer.tla`:
//!
//! * `jobs` — one row per [`JobIdentity`] with its persisted `phase`, bounded
//!   `attempts` counter, and per-run workspace path. Terminal rows
//!   (`done`/`dropped`/`failed`) persist, so a settled identity is never
//!   rediscovered (local dedup saves CDB runs; the server's idempotent
//!   replay is the correctness boundary). Phase history is deliberately not
//!   kept — the server audit feed is the history — so a job row is exactly
//!   its current phase.
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

use crate::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome, Result};

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
    /// Missing parent directories are created. Migration 1 is applied inside
    /// the same transaction that records it in `schema_migrations`, so it
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

/// Applies any pending migrations. Reads and writes the ledger inside one
/// immediate transaction, so concurrent openers serialize and the second one
/// observes version 1 as already applied.
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
    tx.commit().map_err(sql_err)?;
    Ok(())
}

/// Persistence for analysis jobs, one row per [`JobIdentity`].
#[derive(Clone)]
pub struct JobStore {
    conn: SharedConn,
}

impl JobStore {
    /// Records a discovered job, inserting only when its identity is new.
    ///
    /// Returns `true` iff a row was inserted. An identity that already has a
    /// row stays untouched in whatever phase it reached (including terminal
    /// `done`/`dropped`/`failed`), so the local dedup never re-queues work
    /// the server would replay anyway.
    pub fn upsert_discovered(&self, job: &JobIdentity) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let now = now_utc();
        let inserted = guard
            .execute(
                "INSERT OR IGNORE INTO jobs
                     (dump_id, input_sha256, kind, analyzer_version,
                      phase, attempts, workspace_path, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6)",
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
        let mut guard = lock(&self.conn)?;
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;
        let found = tx
            .query_row(
                "SELECT dump_id, input_sha256, kind, analyzer_version, attempts
                   FROM jobs
                  WHERE phase = ?1
                  ORDER BY created_at ASC, rowid ASC
                  LIMIT 1",
                params![phase_str(JobPhase::Discovered)],
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

    /// Persists a phase transition (and refreshes `updated_at`). Phase
    /// history is deliberately not kept. An unknown identity is a state
    /// error: silently losing a transition would corrupt recovery.
    pub fn set_phase(&self, job: &JobIdentity, phase: JobPhase) -> Result<()> {
        let guard = lock(&self.conn)?;
        let changed = guard
            .execute(
                "UPDATE jobs
                    SET phase = ?1, updated_at = ?2
                  WHERE dump_id = ?3 AND input_sha256 = ?4 AND kind = ?5
                    AND analyzer_version = ?6",
                params![
                    phase_str(phase),
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

    /// Lists the jobs currently in `phase`, oldest first, with their attempt
    /// counts. Crash recovery uses this as specified: volatile phases
    /// (`fetching`/`staged`/`analyzing`) are reset to `claimed`, `reporting`
    /// is left for the verdict writer's reconciliation, and
    /// `done`/`dropped`/`failed` are terminal.
    pub fn jobs_in_phase(&self, phase: JobPhase) -> Result<Vec<(JobIdentity, u32)>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(
                "SELECT dump_id, input_sha256, kind, analyzer_version, attempts
                   FROM jobs
                  WHERE phase = ?1
                  ORDER BY created_at ASC, rowid ASC",
            )
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
    /// at any server touch. The row is retained as the terminal marker, so
    /// [`JobStore::upsert_discovered`] will not re-queue the identity.
    pub fn drop_job(&self, job: &JobIdentity) -> Result<()> {
        self.set_phase(job, JobPhase::Dropped)
    }

    /// Lists every job with its lifecycle timestamps, oldest first.
    /// Read-only observability for the status UI; scheduling order is
    /// [`JobStore::claim_next`]'s, not this listing's.
    pub fn list(&self) -> Result<Vec<JobRow>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard
            .prepare(
                "SELECT dump_id, input_sha256, kind, analyzer_version,
                        phase, attempts, created_at, updated_at
                   FROM jobs
                  ORDER BY created_at ASC, rowid ASC",
            )
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

/// Local verdicts produced in local-verdict mode (the server write-back
/// route is absent); kept until POSTed.
#[derive(Clone)]
pub struct LocalReportStore {
    conn: SharedConn,
}

impl LocalReportStore {
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
                      summary, facts_json, created_at, posted)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                params![
                    job.dump_id,
                    job.input_sha256,
                    job.kind,
                    job.analyzer_version,
                    outcome_str(outcome),
                    summary,
                    facts_json,
                    now_utc()
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
fn now_utc() -> String {
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
