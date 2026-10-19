//! Integration tests for the local state store (task A3).
//!
//! Schema shape is asserted against raw SQLite (`PRAGMA table_info`) so the
//! migration contract is checked directly, and behavior is exercised through
//! the public `Store` API with `tempfile` databases.

use std::path::Path;

use dump_analyzer::state::{ReportQuery, Store};
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome};
use rusqlite::Connection;
use tempfile::TempDir;

fn open_temp() -> (TempDir, Store, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("analyzer.sqlite");
    let store = Store::open(&path).expect("open store");
    (dir, store, path)
}

fn raw(path: &Path) -> Connection {
    Connection::open(path).expect("raw connection")
}

fn job(dump: &str) -> JobIdentity {
    job_versioned(dump, "0.1.0")
}

fn job_versioned(dump: &str, version: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump.to_string(),
        input_sha256: format!("{dump:0>64}"),
        kind: "triage".to_string(),
        analyzer_version: version.to_string(),
    }
}

fn now_shape(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

#[derive(Debug, PartialEq)]
struct Column {
    name: String,
    ty: String,
    not_null: bool,
    default_value: Option<String>,
    pk: i64,
}

fn col(name: &str, ty: &str, not_null: bool, default_value: Option<&str>, pk: i64) -> Column {
    Column {
        name: name.to_string(),
        ty: ty.to_string(),
        not_null,
        default_value: default_value.map(str::to_string),
        pk,
    }
}

fn columns(conn: &Connection, table: &str) -> Vec<Column> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("pragma");
    stmt.query_map([], |row| {
        Ok(Column {
            name: row.get(1)?,
            ty: row.get(2)?,
            not_null: row.get::<_, i64>(3)? != 0,
            default_value: row.get(4)?,
            pk: row.get(5)?,
        })
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collect")
}

fn tables(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect")
}

#[test]
fn state_open_applies_migrations_once_and_reopen_preserves_data() {
    let (dir, store, path) = open_temp();
    store
        .cursors()
        .set_monotonic("events", "000042")
        .expect("set cursor");
    drop(store);

    let store = Store::open(&path).expect("reopen existing database");

    let conn = raw(&path);
    assert_eq!(
        tables(&conn),
        vec![
            "byte_cache",
            "cursors",
            "jobs",
            "local_reports",
            "report_details",
            "schema_migrations",
            "secrets",
            "settled_jobs"
        ]
    );
    let versions: Vec<i64> = {
        let mut stmt = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .expect("prepare");
        stmt.query_map([], |row| row.get(0))
            .expect("query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect")
    };
    assert_eq!(versions, vec![1, 2, 3, 4]);

    // Reopening neither re-ran the migrations nor reset the data.
    assert_eq!(
        store
            .cursors()
            .get("events")
            .expect("get cursor")
            .as_deref(),
        Some("000042")
    );
    drop(dir);
}

#[test]
fn state_schema_matches_the_specified_migration() {
    let (_dir, _store, path) = open_temp();
    let conn = raw(&path);

    assert_eq!(
        columns(&conn, "jobs"),
        vec![
            col("dump_id", "TEXT", true, None, 1),
            col("input_sha256", "TEXT", true, None, 2),
            col("kind", "TEXT", true, None, 3),
            col("analyzer_version", "TEXT", true, None, 4),
            col("phase", "TEXT", true, None, 0),
            col("attempts", "INTEGER", true, Some("0"), 0),
            col("workspace_path", "TEXT", false, None, 0),
            col("created_at", "TEXT", true, None, 0),
            col("updated_at", "TEXT", true, None, 0),
        ]
    );
    assert_eq!(columns(&conn, "settled_jobs"), columns(&conn, "jobs"));
    assert_eq!(
        columns(&conn, "cursors"),
        vec![
            col("name", "TEXT", true, None, 1),
            col("value", "TEXT", true, None, 0),
        ]
    );
    assert_eq!(
        columns(&conn, "byte_cache"),
        vec![
            col("sha256", "TEXT", true, None, 1),
            col("path", "TEXT", true, None, 0),
            col("byte_size", "INTEGER", true, None, 0),
            col("etag", "TEXT", false, None, 0),
            col("last_used_at", "TEXT", true, None, 0),
        ]
    );
    assert_eq!(
        columns(&conn, "local_reports"),
        vec![
            col("dump_id", "TEXT", true, None, 1),
            col("input_sha256", "TEXT", true, None, 2),
            col("kind", "TEXT", true, None, 3),
            col("analyzer_version", "TEXT", true, None, 4),
            col("outcome", "TEXT", true, None, 0),
            col("summary", "TEXT", true, None, 0),
            col("facts_json", "TEXT", true, None, 0),
            col("created_at", "TEXT", true, None, 0),
            col("posted", "INTEGER", true, Some("0"), 0),
            col("report_id", "TEXT", false, None, 0),
        ]
    );
}

#[test]
fn state_open_creates_missing_parent_directories() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir
        .path()
        .join("nested")
        .join("state")
        .join("analyzer.sqlite");
    let store = Store::open(&path).expect("open with missing parents");
    store
        .cursors()
        .set_monotonic("events", "000001")
        .expect("set cursor");
    assert!(path.is_file());
}

#[test]
fn state_upsert_discovered_is_idempotent_and_keyed_by_identity() {
    let (_dir, store, path) = open_temp();
    let first = job("d1");
    assert!(store.jobs().upsert_discovered(&first).expect("insert"));
    assert!(!store.jobs().upsert_discovered(&first).expect("re-insert"));

    let discovered = store
        .jobs()
        .jobs_in_phase(JobPhase::Discovered)
        .expect("phase");
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].0, first);
    assert_eq!(discovered[0].1, 0);

    // A different analyzer version is a different job identity.
    let other_version = job_versioned("d1", "0.2.0");
    assert!(
        store
            .jobs()
            .upsert_discovered(&other_version)
            .expect("insert")
    );
    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Discovered)
            .expect("phase")
            .len(),
        2
    );

    // The inserted row starts from the schema-defaulted state.
    let conn = raw(&path);
    let (attempts, workspace, phase, created, updated): (
        i64,
        Option<String>,
        String,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT attempts, workspace_path, phase, created_at, updated_at
               FROM jobs WHERE dump_id = 'd1' AND analyzer_version = '0.1.0'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("row");
    assert_eq!(attempts, 0);
    assert_eq!(workspace, None);
    assert_eq!(phase, "discovered");
    assert!(now_shape(&created), "created_at: {created}");
    assert_eq!(created, updated);
}

#[test]
fn state_claim_next_takes_oldest_discovered_and_persists_phase() {
    let (_dir, store, path) = open_temp();
    let d1 = job("d1");
    let d2 = job("d2");
    let d3 = job("d3");
    for id in [&d1, &d2, &d3] {
        assert!(store.jobs().upsert_discovered(id).expect("insert"));
    }

    // Same-second inserts: pin explicit created_at values to prove ordering
    // is by age, not insertion order.
    {
        let conn = raw(&path);
        for (dump, created) in [
            ("d1", "2026-01-03T00:00:00Z"),
            ("d2", "2026-01-02T00:00:00Z"),
            ("d3", "2026-01-01T00:00:00Z"),
        ] {
            conn.execute(
                "UPDATE jobs SET created_at = ?1 WHERE dump_id = ?2",
                rusqlite::params![created, dump],
            )
            .expect("pin created_at");
        }
    }

    let (first, attempts) = store.jobs().claim_next().expect("claim").expect("job");
    assert_eq!(first, d3);
    assert_eq!(attempts, 0);
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("phase")
            .iter()
            .any(|(id, _)| *id == d3)
    );
    assert!(
        !store
            .jobs()
            .jobs_in_phase(JobPhase::Discovered)
            .expect("phase")
            .iter()
            .any(|(id, _)| *id == d3)
    );

    let (second, _) = store.jobs().claim_next().expect("claim").expect("job");
    assert_eq!(second, d2);
    let (third, _) = store.jobs().claim_next().expect("claim").expect("job");
    assert_eq!(third, d1);
    assert!(store.jobs().claim_next().expect("claim").is_none());
    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("phase")
            .len(),
        3
    );

    // The persisted phase spelling is the kebab-case serde spelling.
    let phase: String = raw(&path)
        .query_row("SELECT phase FROM jobs WHERE dump_id = 'd3'", [], |row| {
            row.get(0)
        })
        .expect("row");
    assert_eq!(phase, "claimed");
}

#[test]
fn state_claims_are_unique_across_concurrent_claimers() {
    let (_dir, store, _path) = open_temp();
    for dump in ["d1", "d2", "d3", "d4"] {
        assert!(store.jobs().upsert_discovered(&job(dump)).expect("insert"));
    }

    let claimed = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let store = store.clone();
            let claimed = &claimed;
            scope.spawn(move || {
                while let Some((id, _)) = store.jobs().claim_next().expect("claim") {
                    claimed.lock().expect("lock").push(id);
                }
            });
        }
    });

    let mut dumps: Vec<String> = claimed
        .into_inner()
        .expect("lock")
        .into_iter()
        .map(|id| id.dump_id)
        .collect();
    dumps.sort();
    assert_eq!(dumps, vec!["d1", "d2", "d3", "d4"]);
}

#[test]
fn state_record_attempt_counts_up_and_unknown_jobs_are_state_errors() {
    let (_dir, store, _path) = open_temp();
    let id = job("d1");
    assert!(store.jobs().upsert_discovered(&id).expect("insert"));
    let (claimed, attempts) = store.jobs().claim_next().expect("claim").expect("job");
    assert_eq!(claimed, id);
    assert_eq!(attempts, 0);

    store.jobs().record_attempt(&id).expect("attempt");
    store.jobs().record_attempt(&id).expect("attempt");
    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("phase"),
        vec![(id.clone(), 2)]
    );

    for result in [
        store.jobs().record_attempt(&job("missing")),
        store.jobs().set_phase(&job("missing"), JobPhase::Done),
        store.jobs().drop_job(&job("missing")),
    ] {
        assert!(
            matches!(result, Err(AnalyzerError::State(_))),
            "expected state error, got {result:?}"
        );
    }
}

#[test]
fn state_set_phase_round_trips_every_phase_spelling() {
    let (_dir, store, path) = open_temp();
    let id = job("d1");
    store.jobs().upsert_discovered(&id).expect("insert");
    let conn = raw(&path);

    for phase in [
        JobPhase::Discovered,
        JobPhase::Claimed,
        JobPhase::Fetching,
        JobPhase::Staged,
        JobPhase::Analyzing,
        JobPhase::Reporting,
        JobPhase::Done,
        JobPhase::Dropped,
        JobPhase::Failed,
    ] {
        store.jobs().set_phase(&id, phase).expect("set phase");
        let expected = serde_json::to_value(phase).expect("serde");
        let expected = expected.as_str().expect("string");
        let stored: String = conn
            .query_row(
                "SELECT phase FROM jobs WHERE dump_id = 'd1'
                 UNION ALL
                 SELECT phase FROM settled_jobs WHERE dump_id = 'd1'",
                [],
                |row| row.get(0),
            )
            .expect("row");
        assert_eq!(stored, expected);
        assert!(
            store
                .jobs()
                .jobs_in_phase(phase)
                .expect("phase")
                .iter()
                .any(|(job, _)| *job == id)
        );
    }
}

#[test]
fn state_work_queue_selects_only_claimed_work_without_decoding_discovery_candidates() {
    let (_dir, store, path) = open_temp();
    let jobs = store.jobs();
    for index in 0..300 {
        jobs.upsert_discovered(&job(&format!("candidate-{index:03}")))
            .expect("discover candidate");
    }
    assert!(jobs.work_queue().expect("no work yet").is_empty());
    for (dump, phase, day) in [
        ("claimed", JobPhase::Claimed, 2),
        ("fetching", JobPhase::Fetching, 1),
        ("staged", JobPhase::Staged, 1),
        ("analyzing", JobPhase::Analyzing, 3),
        ("reporting", JobPhase::Reporting, 2),
    ] {
        let id = job(dump);
        jobs.upsert_discovered(&id).expect("insert work");
        jobs.set_phase(&id, phase).expect("active phase");
        raw(&path)
            .execute(
                "UPDATE jobs SET created_at = ?1 WHERE dump_id = ?2",
                rusqlite::params![format!("2026-01-{day:02}T00:00:00Z"), dump],
            )
            .expect("pin work timestamp");
    }
    assert_eq!(jobs.list().expect("legacy full list").len(), 305);
    // A discovery candidate's invalid attempts would fail the list decoder.
    // The operator queue must exclude these rows before loading or decoding
    // them, so its cost does not include the full discovery inventory.
    raw(&path)
        .execute(
            "UPDATE jobs SET attempts = -1 WHERE phase = 'discovered'",
            [],
        )
        .expect("corrupt candidate attempts");
    assert!(matches!(jobs.list(), Err(AnalyzerError::State(_))));

    let work = jobs.work_queue().expect("active work only");
    assert_eq!(work.len(), 5);
    assert_eq!(
        work.iter()
            .map(|row| row.identity.dump_id.as_str())
            .collect::<Vec<_>>(),
        ["fetching", "staged", "claimed", "reporting", "analyzing"]
    );
    assert!(
        work.iter()
            .all(|row| row.attempts == 0 && row.phase != JobPhase::Discovered)
    );
    assert_eq!(
        raw(&path)
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE phase = 'discovered'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("candidates preserved"),
        300
    );
}

#[test]
fn state_terminal_jobs_leave_the_queue_and_preserve_reports_and_dedup_on_restart() {
    let (_dir, store, path) = open_temp();
    let active = job("active");
    store
        .jobs()
        .upsert_discovered(&active)
        .expect("insert active");
    let mut settled = Vec::new();
    for (dump, terminal) in [
        ("done", JobPhase::Done),
        ("failed", JobPhase::Failed),
        ("dropped", JobPhase::Dropped),
    ] {
        let id = job(dump);
        store.jobs().upsert_discovered(&id).expect("insert");
        store.jobs().record_attempt(&id).expect("record attempt");
        store
            .local_reports()
            .insert(&id, ReportOutcome::Completed, "retained report", "{}")
            .expect("report");
        raw(&path)
            .execute(
                "UPDATE jobs SET workspace_path = '/work/run', created_at = '2026-01-01T00:00:00Z'
                 WHERE dump_id = ?1",
                [dump],
            )
            .expect("pin workspace and timestamp");

        store.jobs().set_phase(&id, terminal).expect("settle");
        assert_eq!(store.jobs().phase_of(&id).expect("phase"), Some(terminal));
        assert_eq!(
            store.jobs().jobs_in_phase(terminal).expect("archive"),
            vec![(id.clone(), 1)]
        );
        let (phase, attempts, workspace, created): (String, i64, String, String) = raw(&path)
            .query_row(
                "SELECT phase, attempts, workspace_path, created_at FROM settled_jobs WHERE dump_id = ?1",
                [dump],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("settled metadata");
        assert_eq!(phase, dump);
        assert_eq!(attempts, 1);
        assert_eq!(workspace, "/work/run");
        assert_eq!(created, "2026-01-01T00:00:00Z");
        settled.push((id, terminal));
    }

    let queued = store.jobs().list().expect("list queue");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].identity, active);
    assert_eq!(
        raw(&path)
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
            .expect("physical queue count"),
        1
    );
    drop(store);

    let reopened = Store::open(&path).expect("reopen");
    for (id, terminal) in settled {
        assert!(!reopened.jobs().upsert_discovered(&id).expect("rescan"));
        assert_eq!(
            reopened.jobs().phase_of(&id).expect("phase"),
            Some(terminal)
        );
        assert_eq!(
            reopened
                .local_reports()
                .get(&id)
                .expect("report")
                .expect("retained")
                .summary,
            "retained report"
        );
    }
    assert_eq!(reopened.jobs().list().expect("queue").len(), 1);
}

#[test]
fn state_settled_transitions_are_idempotent_and_cannot_implicitly_requeue() {
    let (_dir, store, path) = open_temp();
    let id = job("d1");
    store.jobs().upsert_discovered(&id).expect("insert");
    store.jobs().set_phase(&id, JobPhase::Done).expect("done");
    store
        .jobs()
        .set_phase(&id, JobPhase::Done)
        .expect("repeat done");
    store.jobs().drop_job(&id).expect("purged after completion");
    assert_eq!(
        store.jobs().phase_of(&id).expect("phase"),
        Some(JobPhase::Dropped)
    );
    assert!(matches!(
        store.jobs().set_phase(&id, JobPhase::Discovered),
        Err(AnalyzerError::State(_))
    ));
    assert!(store.jobs().list().expect("queue").is_empty());
    assert_eq!(
        raw(&path)
            .query_row("SELECT COUNT(*) FROM settled_jobs", [], |row| row
                .get::<_, i64>(0))
            .expect("settled count"),
        1
    );
}

#[test]
fn state_terminal_transition_rolls_back_archive_if_queue_removal_fails() {
    let (_dir, store, path) = open_temp();
    let id = job("d1");
    store.jobs().upsert_discovered(&id).expect("insert");
    raw(&path)
        .execute_batch(
            "CREATE TRIGGER reject_removal BEFORE DELETE ON jobs
             BEGIN SELECT RAISE(ABORT, 'injected removal failure'); END;",
        )
        .expect("inject failure");

    assert!(store.jobs().set_phase(&id, JobPhase::Done).is_err());
    assert_eq!(
        store.jobs().phase_of(&id).expect("phase"),
        Some(JobPhase::Discovered)
    );
    assert_eq!(store.jobs().list().expect("queue").len(), 1);
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Done)
            .expect("archive")
            .is_empty()
    );
}

#[test]
fn state_conditional_transition_does_not_settle_a_job_claimed_by_another_worker() {
    let (_dir, store, _path) = open_temp();
    let id = job("d1");
    store.jobs().upsert_discovered(&id).expect("insert");
    store.jobs().claim_next().expect("claim").expect("job");
    assert!(
        !store
            .jobs()
            .set_phase_if(&id, JobPhase::Discovered, JobPhase::Done)
            .expect("conditional settle")
    );
    assert_eq!(
        store.jobs().phase_of(&id).expect("phase"),
        Some(JobPhase::Claimed)
    );
    assert_eq!(store.jobs().list().expect("queue").len(), 1);
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Done)
            .expect("archive")
            .is_empty()
    );
    assert!(
        store
            .jobs()
            .set_phase_if(&id, JobPhase::Claimed, JobPhase::Done)
            .expect("conditional settle")
    );
    assert!(store.jobs().list().expect("queue").is_empty());
    assert!(
        !store
            .jobs()
            .set_phase_if(&id, JobPhase::Claimed, JobPhase::Done)
            .expect("already settled")
    );
    assert!(
        !store
            .jobs()
            .set_phase_if(&job("missing"), JobPhase::Discovered, JobPhase::Done)
            .expect("absent")
    );
}

#[test]
fn state_migration_archives_legacy_terminal_rows_and_preserves_active_work() {
    let (_dir, store, path) = open_temp();
    drop(store);
    let conn = raw(&path);
    // Recreate the migration-2 layout, whose jobs table held terminal work.
    conn.execute_batch(
        "DROP TABLE IF EXISTS settled_jobs;
         DELETE FROM schema_migrations WHERE version = 3;
         INSERT INTO jobs (dump_id, input_sha256, kind, analyzer_version, phase, attempts,
                           workspace_path, created_at, updated_at)
         VALUES ('done', 'done', 'triage', '0.1.0', 'done', 2, '/legacy/work',
                 '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'),
                ('failed', 'failed', 'triage', '0.1.0', 'failed', 3, NULL,
                 '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'),
                ('dropped', 'dropped', 'triage', '0.1.0', 'dropped', 0, NULL,
                 '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'),
                ('active', 'active', 'triage', '0.1.0', 'reporting', 1, NULL,
                 '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z');
         INSERT INTO local_reports
             (dump_id, input_sha256, kind, analyzer_version, outcome, summary, facts_json, created_at)
         VALUES ('done', 'done', 'triage', '0.1.0', 'completed', 'legacy report', '{}',
                 '2026-01-02T00:00:00Z');",
    ).expect("legacy database");
    drop(conn);

    let migrated = Store::open(&path).expect("migrate legacy database");
    let queued = migrated.jobs().list().expect("queue");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].identity.dump_id, "active");
    let conn = raw(&path);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM settled_jobs", [], |row| row
            .get::<_, i64>(0))
            .expect("archive count"),
        3
    );
    let preserved: (i64, String, String, String) = conn.query_row(
        "SELECT attempts, workspace_path, created_at, updated_at FROM settled_jobs WHERE dump_id = 'done'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).expect("legacy metadata");
    assert_eq!(
        preserved,
        (
            2,
            "/legacy/work".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-01-02T00:00:00Z".into()
        )
    );
    assert_eq!(
        conn.query_row("SELECT summary FROM local_reports", [], |row| row
            .get::<_, String>(0))
            .expect("legacy report"),
        "legacy report"
    );
    let settled = JobIdentity {
        input_sha256: "done".into(),
        ..job("done")
    };
    assert!(!migrated.jobs().upsert_discovered(&settled).expect("rescan"));
    drop(conn);
    drop(migrated);
    let reopened = Store::open(&path).expect("idempotent migration");
    assert_eq!(reopened.jobs().list().expect("queue").len(), 1);
}

#[test]
fn state_cursor_regression_is_rejected_and_equal_values_are_allowed() {
    let (_dir, store, _path) = open_temp();
    assert_eq!(store.cursors().get("events").expect("get"), None);

    store
        .cursors()
        .set_monotonic("events", "000042")
        .expect("set");
    assert_eq!(
        store.cursors().get("events").expect("get").as_deref(),
        Some("000042")
    );

    // Equal is a permitted no-op; smaller is refused and changes nothing.
    store
        .cursors()
        .set_monotonic("events", "000042")
        .expect("equal set");
    let err = store
        .cursors()
        .set_monotonic("events", "000041")
        .expect_err("regression");
    match err {
        AnalyzerError::State(message) => {
            assert!(message.contains("backward"), "message: {message}");
            assert!(message.contains("000041"), "message: {message}");
        }
        other => panic!("expected AnalyzerError::State, got: {other:?}"),
    }
    assert_eq!(
        store.cursors().get("events").expect("get").as_deref(),
        Some("000042")
    );

    store
        .cursors()
        .set_monotonic("events", "000043")
        .expect("advance");
    assert_eq!(
        store.cursors().get("events").expect("get").as_deref(),
        Some("000043")
    );

    // Cursors are independent per name.
    store
        .cursors()
        .set_monotonic("other", "000001")
        .expect("set");
    assert_eq!(
        store.cursors().get("other").expect("get").as_deref(),
        Some("000001")
    );
    assert_eq!(
        store.cursors().get("events").expect("get").as_deref(),
        Some("000043")
    );
}

#[test]
fn state_cache_index_upserts_looks_up_and_touches_by_sha256() {
    let (_dir, store, _path) = open_temp();
    let sha = "ab".repeat(32);
    assert!(store.cache_index().lookup(&sha).expect("lookup").is_none());

    store
        .cache_index()
        .upsert(&sha, "/data/bytes/ab.dmp", 4096, Some("W/\"etag-1\""))
        .expect("upsert");
    let entry = store
        .cache_index()
        .lookup(&sha)
        .expect("lookup")
        .expect("entry");
    assert_eq!(entry.sha256, sha);
    assert_eq!(entry.path, "/data/bytes/ab.dmp");
    assert_eq!(entry.byte_size, 4096);
    assert_eq!(entry.etag.as_deref(), Some("W/\"etag-1\""));
    assert!(
        now_shape(&entry.last_used_at),
        "stamp: {}",
        entry.last_used_at
    );

    // A refresh updates path and size but keeps a known ETag when the new
    // download reports none.
    store
        .cache_index()
        .upsert(&sha, "/data/bytes/ab.v2.dmp", 8192, None)
        .expect("upsert");
    let entry = store
        .cache_index()
        .lookup(&sha)
        .expect("lookup")
        .expect("entry");
    assert_eq!(entry.path, "/data/bytes/ab.v2.dmp");
    assert_eq!(entry.byte_size, 8192);
    assert_eq!(entry.etag.as_deref(), Some("W/\"etag-1\""));

    assert!(store.cache_index().touch(&sha).expect("touch"));
    assert!(!store.cache_index().touch(&"cd".repeat(32)).expect("touch"));
}

#[test]
fn state_local_reports_insert_or_ignore_pending_and_mark_posted() {
    let (_dir, store, path) = open_temp();
    let first = job("d1");
    let second = job("d2");

    assert!(
        store
            .local_reports()
            .insert(
                &first,
                ReportOutcome::Completed,
                "summary-1",
                "{\"frames\":3}"
            )
            .expect("insert")
    );
    // Insert-or-ignore: the identity is already present, the new draft is
    // dropped.
    assert!(
        !store
            .local_reports()
            .insert(&first, ReportOutcome::Failed, "summary-other", "{}")
            .expect("re-insert")
    );
    assert!(
        store
            .local_reports()
            .insert(&second, ReportOutcome::Failed, "summary-2", "{}")
            .expect("insert")
    );

    let stored = store
        .local_reports()
        .get(&first)
        .expect("get")
        .expect("stored report");
    assert_eq!(stored.identity(), first);
    assert_eq!(stored.outcome, ReportOutcome::Completed);
    assert_eq!(stored.summary, "summary-1");
    assert_eq!(stored.facts_json, "{\"frames\":3}");
    assert!(
        now_shape(&stored.created_at),
        "stamp: {}",
        stored.created_at
    );
    assert!(!stored.posted);

    let pending = store.local_reports().pending().expect("pending");
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].dump_id, "d1");
    assert_eq!(pending[1].dump_id, "d2");

    store.local_reports().mark_posted(&first).expect("mark");
    let pending = store.local_reports().pending().expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].dump_id, "d2");
    assert!(
        store
            .local_reports()
            .get(&first)
            .expect("get")
            .expect("stored")
            .posted
    );

    // The stored spellings match the wire spellings, and posted is durable.
    let conn = raw(&path);
    let stored_outcome: String = conn
        .query_row(
            "SELECT outcome FROM local_reports WHERE dump_id = 'd1'",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert_eq!(
        stored_outcome,
        serde_json::to_value(ReportOutcome::Completed)
            .expect("serde")
            .as_str()
            .expect("string")
    );
    let posted: i64 = conn
        .query_row(
            "SELECT posted FROM local_reports WHERE dump_id = 'd1'",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert_eq!(posted, 1);

    assert!(matches!(
        store.local_reports().mark_posted(&job("missing")),
        Err(AnalyzerError::State(_))
    ));
}

#[test]
fn state_report_pages_traverse_every_report_in_stable_newest_order() {
    let (_dir, store, path) = open_temp();
    let reports = store.local_reports();
    let conn = raw(&path);
    let mut expected: Vec<_> = (0..257).collect();
    for index in &expected {
        let id = job(&format!("dump-{index:03}"));
        reports
            .insert(
                &id,
                ReportOutcome::Completed,
                "retained summary",
                "{\"retained\":true}",
            )
            .expect("insert report");
        conn.execute(
            "UPDATE local_reports SET created_at = ?1 WHERE dump_id = ?2",
            rusqlite::params![
                format!("2026-10-{:02}T00:00:00Z", index % 7 + 1),
                id.dump_id
            ],
        )
        .expect("set deterministic timestamp");
        if index % 3 == 0 {
            reports.mark_posted(&id).expect("mark posted");
        }
    }
    expected.sort_by_key(|index| std::cmp::Reverse((index % 7, *index)));
    let expected: Vec<_> = expected
        .into_iter()
        .map(|index| format!("dump-{index:03}"))
        .collect();

    assert_eq!(reports.counts().expect("full counts"), (257, 171));
    let first = reports.page(&ReportQuery::default()).expect("first page");
    assert_eq!(first.page, 1);
    assert_eq!(first.page_size, 25);
    assert_eq!(first.total, 257);
    assert_eq!(first.matching, 257);
    assert_eq!(first.pending, 171);
    assert_eq!(first.total_pages, 11);
    assert_eq!(first.reports.len(), 25);

    let mut seen = Vec::new();
    for page in 1..=11 {
        let result = reports
            .page(&ReportQuery {
                page,
                ..ReportQuery::default()
            })
            .expect("page");
        assert_eq!(result.page, page);
        assert_eq!(result.reports.len(), if page == 11 { 7 } else { 25 });
        for report in result.reports {
            assert_eq!(report.summary, "retained summary");
            assert!(!report.detail_available);
            assert_eq!(report.schema_version, 1);
            assert_eq!(
                reports
                    .get(&JobIdentity {
                        dump_id: report.dump_id.clone(),
                        input_sha256: report.input_sha256.clone(),
                        kind: report.kind.clone(),
                        analyzer_version: report.analyzer_version.clone(),
                    })
                    .expect("legacy facts lookup")
                    .expect("legacy report")
                    .facts_json,
                "{\"retained\":true}"
            );
            seen.push(report.dump_id);
        }
    }
    assert_eq!(seen, expected);
    assert_eq!(reports.list_recent(200).expect("legacy list").len(), 200);

    drop(store);
    let reopened = Store::open(path).expect("reopen");
    assert_eq!(
        reopened.local_reports().counts().expect("durable counts"),
        (257, 171)
    );
    assert_eq!(
        reopened
            .local_reports()
            .pending()
            .expect("legacy pending")
            .len(),
        171
    );
}

#[test]
fn state_report_pages_search_literals_and_combine_outcome_and_delivery_filters() {
    let (_dir, store, _path) = open_temp();
    let reports = store.local_reports();
    let rows = [
        (
            "Dump%One",
            "triage",
            "0.1",
            "plain",
            ReportOutcome::Completed,
            true,
        ),
        (
            "dump-two",
            "kind_value",
            "0.1",
            "plain",
            ReportOutcome::Failed,
            false,
        ),
        (
            "dump-three",
            "triage",
            "version\\value",
            "plain",
            ReportOutcome::Completed,
            false,
        ),
        (
            "dump-four",
            "triage",
            "0.1",
            "MixedCase summary",
            ReportOutcome::Failed,
            true,
        ),
        (
            "dump-five",
            "triage",
            "0.1",
            "100%_\\' OR 1=1 --",
            ReportOutcome::Failed,
            false,
        ),
    ];
    for (dump, kind, version, summary, outcome, posted) in rows {
        let id = JobIdentity {
            kind: kind.into(),
            ..job_versioned(dump, version)
        };
        reports.insert(&id, outcome, summary, "{}").expect("insert");
        if posted {
            reports.mark_posted(&id).expect("posted");
        }
    }

    for (q, expected) in [
        ("DUMP%ONE", vec!["Dump%One"]),
        ("kind_", vec!["dump-two"]),
        ("VERSION\\", vec!["dump-three"]),
        ("mixedcase", vec!["dump-four"]),
        ("%_\\' OR 1=1 --", vec!["dump-five"]),
        ("%", vec!["dump-five", "Dump%One"]),
        ("_", vec!["dump-five", "dump-two"]),
        ("\\", vec!["dump-five", "dump-three"]),
    ] {
        let page = reports
            .page(&ReportQuery {
                q: q.into(),
                ..ReportQuery::default()
            })
            .expect("search");
        assert_eq!(page.matching, expected.len() as u64, "query {q:?}");
        assert_eq!(page.total, 5);
        assert_eq!(page.pending, 3);
        let found: Vec<_> = page
            .reports
            .iter()
            .map(|report| report.dump_id.as_str())
            .collect();
        assert_eq!(found, expected, "query {q:?}");
    }

    let failed_pending = reports
        .page(&ReportQuery {
            q: "dump".into(),
            outcome: Some(ReportOutcome::Failed),
            posted: Some(false),
            ..ReportQuery::default()
        })
        .expect("combined filters");
    assert_eq!(failed_pending.matching, 2);
    assert!(
        failed_pending
            .reports
            .iter()
            .all(|report| report.outcome == ReportOutcome::Failed && !report.posted)
    );
    let completed_posted = reports
        .page(&ReportQuery {
            outcome: Some(ReportOutcome::Completed),
            posted: Some(true),
            ..ReportQuery::default()
        })
        .expect("posted completed");
    assert_eq!(completed_posted.matching, 1);
    assert_eq!(completed_posted.reports[0].dump_id, "Dump%One");
    assert_eq!(reports.counts().expect("counts preserved"), (5, 3));
}

#[test]
fn state_report_pages_normalize_bounds_and_clamp_out_of_range_pages() {
    let (_dir, store, _path) = open_temp();
    let reports = store.local_reports();
    let empty = reports
        .page(&ReportQuery {
            page: u32::MAX,
            page_size: u32::MAX,
            ..ReportQuery::default()
        })
        .expect("empty page");
    assert_eq!(
        (empty.page, empty.page_size, empty.total_pages),
        (1, 100, 0)
    );
    assert_eq!((empty.total, empty.matching, empty.pending), (0, 0, 0));
    assert!(empty.reports.is_empty());
    for index in 0..101 {
        reports
            .insert(
                &job(&format!("bound-{index:03}")),
                ReportOutcome::Completed,
                "summary",
                "{}",
            )
            .expect("insert");
    }
    let normalized = reports
        .page(&ReportQuery {
            page: 0,
            page_size: 0,
            ..ReportQuery::default()
        })
        .expect("normalized");
    assert_eq!(
        (
            normalized.page,
            normalized.page_size,
            normalized.total_pages
        ),
        (1, 1, 101)
    );
    assert_eq!(normalized.reports.len(), 1);
    let last = reports
        .page(&ReportQuery {
            page: u32::MAX,
            page_size: u32::MAX,
            ..ReportQuery::default()
        })
        .expect("clamped final page");
    assert_eq!((last.page, last.page_size, last.total_pages), (2, 100, 2));
    assert_eq!(last.reports.len(), 1);
    let no_matches = reports
        .page(&ReportQuery {
            q: "absent".into(),
            page: 100,
            ..ReportQuery::default()
        })
        .expect("no matches");
    assert_eq!(
        (no_matches.page, no_matches.total_pages, no_matches.matching),
        (1, 0, 0)
    );
    assert_eq!((no_matches.total, no_matches.pending), (101, 101));
    assert!(no_matches.reports.is_empty());
}

#[test]
fn state_recovery_queries_reset_volatile_phases_and_keep_reporting() {
    let (_dir, store, _path) = open_temp();
    let fetching = job("d1");
    let staged = job("d2");
    let analyzing = job("d3");
    let reporting = job("d4");
    for id in [&fetching, &staged, &analyzing, &reporting] {
        assert!(store.jobs().upsert_discovered(id).expect("insert"));
    }
    store
        .jobs()
        .set_phase(&fetching, JobPhase::Fetching)
        .expect("phase");
    store
        .jobs()
        .set_phase(&staged, JobPhase::Staged)
        .expect("phase");
    store
        .jobs()
        .set_phase(&analyzing, JobPhase::Analyzing)
        .expect("phase");
    store
        .jobs()
        .set_phase(&reporting, JobPhase::Reporting)
        .expect("phase");

    // Crash recovery: volatile phases re-enter at `claimed` (spec
    // CrashReset); `reporting` stays for the verdict writer's reconciliation.
    let mut reset = 0;
    for phase in [
        JobPhase::Fetching,
        JobPhase::Staged,
        JobPhase::Analyzing,
        JobPhase::Reporting,
    ] {
        for (id, _) in store.jobs().jobs_in_phase(phase).expect("phase") {
            if phase.is_volatile() {
                store
                    .jobs()
                    .set_phase(&id, JobPhase::Claimed)
                    .expect("reset");
                reset += 1;
            }
        }
    }
    assert_eq!(reset, 3);
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Fetching)
            .expect("phase")
            .is_empty()
    );
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Staged)
            .expect("phase")
            .is_empty()
    );
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Analyzing)
            .expect("phase")
            .is_empty()
    );
    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Claimed)
            .expect("phase")
            .len(),
        3
    );
    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Reporting)
            .expect("phase"),
        vec![(reporting, 0)]
    );
}

#[test]
fn state_drop_job_marks_terminal_and_blocks_rediscovery() {
    let (_dir, store, _path) = open_temp();
    let id = job("d1");
    assert!(store.jobs().upsert_discovered(&id).expect("insert"));
    store.jobs().claim_next().expect("claim").expect("job");
    store.jobs().drop_job(&id).expect("drop");

    assert_eq!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Dropped)
            .expect("phase"),
        vec![(id.clone(), 0)]
    );
    assert!(store.jobs().claim_next().expect("claim").is_none());
    assert!(!store.jobs().upsert_discovered(&id).expect("re-insert"));

    // Submit-purged path: reporting -> dropped.
    let reporting = job("d2");
    assert!(store.jobs().upsert_discovered(&reporting).expect("insert"));
    store
        .jobs()
        .set_phase(&reporting, JobPhase::Reporting)
        .expect("phase");
    store.jobs().drop_job(&reporting).expect("drop");
    assert!(
        store
            .jobs()
            .jobs_in_phase(JobPhase::Dropped)
            .expect("phase")
            .iter()
            .any(|(job, _)| *job == reporting)
    );
}

#[test]
fn state_secrets_store_latest_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path().join("s.sqlite")).expect("store");

    let secrets = store.secrets();
    assert_eq!(secrets.get("analyzer_token").expect("get"), None);

    secrets.set("analyzer_token", "first").expect("set");
    assert_eq!(
        secrets.get("analyzer_token").expect("get"),
        Some("first".to_string())
    );

    // Latest wins.
    secrets.set("analyzer_token", "second").expect("set");
    assert_eq!(
        secrets.get("analyzer_token").expect("get"),
        Some("second".to_string())
    );

    // Survives a reopen (migration 2 is idempotent on the second open).
    drop(store);
    let store = Store::open(dir.path().join("s.sqlite")).expect("reopen");
    assert_eq!(
        store.secrets().get("analyzer_token").expect("get"),
        Some("second".to_string())
    );
}

#[test]
fn state_phase_of_reports_presence() {
    let (dir, store, _path) = open_temp();
    let _ = dir;
    let job = JobIdentity {
        dump_id: "dump_p1".into(),
        input_sha256: "ab".repeat(32),
        kind: "triage".into(),
        analyzer_version: "0.1.0".into(),
    };
    assert_eq!(store.jobs().phase_of(&job).expect("phase"), None);
    store.jobs().upsert_discovered(&job).expect("upsert");
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Discovered)
    );
    store
        .jobs()
        .set_phase(&job, JobPhase::Reporting)
        .expect("set");
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Reporting)
    );
}

#[test]
fn current_capture_profile_never_claims_old_discoveries() {
    let (_directory, store, _path) = open_temp();
    let old = job_versioned("old-profile", "0.1.0");
    let current = job_versioned("new-profile", "0.2.0");
    store.jobs().upsert_discovered(&old).unwrap();
    store.jobs().upsert_discovered(&current).unwrap();
    assert_eq!(
        store
            .jobs()
            .claim_next_for_version("0.2.0")
            .unwrap()
            .unwrap()
            .0,
        current
    );
    assert!(
        store
            .jobs()
            .claim_next_for_version("0.2.0")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.jobs().phase_of(&old).unwrap(),
        Some(JobPhase::Discovered)
    );
}
