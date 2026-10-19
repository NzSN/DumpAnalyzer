//! Canonical evidence durability, atomic handoff, and independent publication.
use dump_analyzer::report::{CrashReportV2, Evidence, ReportCapture, legacy_id};
use dump_analyzer::state::{FullDelivery, ReportDetail, ReportHandoff, ReportQuery, Store};
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome, RunOutput};
use dump_analyzer::wire::{AnalysisReportSubmission, Analyzer};
use rusqlite::{Connection, params};
use serde_json::json;

fn identity(dump_id: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump_id.into(),
        input_sha256: "a".repeat(64),
        kind: "triage".into(),
        analyzer_version: "0.2.0".into(),
    }
}

fn report(job: &JobIdentity) -> CrashReportV2 {
    let mut capture = ReportCapture::default();
    capture.provenance.provider = "fixture".into();
    capture.evidence.push(Evidence {
        id: "context".into(),
        command: "r".into(),
        text: "retained context\n".repeat(400),
        ..Evidence::default()
    });
    CrashReportV2::from_output(
        job,
        "dump-analyzer",
        &RunOutput {
            outcome: ReportOutcome::Completed,
            summary: "Captured exception evidence; origin unknown".into(),
            facts: json!({}),
            capture: Some(capture),
        },
    )
    .expect("valid report")
}

fn compact(report: &CrashReportV2) -> AnalysisReportSubmission {
    let output = report.compact_output().expect("projection");
    AnalysisReportSubmission::new(
        Analyzer {
            name: report.identity.analyzer_name.clone(),
            version: report.identity.analyzer_version.clone(),
        },
        report.identity.kind.clone(),
        report.identity.input_sha256.clone(),
        output.outcome,
        output.summary,
        Some(output.facts),
        None,
    )
    .expect("compact report")
}

#[test]
fn canonical_detail_exceeds_v1_budget_and_survives_reopen_exactly() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.sqlite");
    let store = Store::open(&path).expect("open");
    let job = identity("large-detail");
    let report = report(&job);
    let projection = compact(&report);
    let stored = store
        .local_reports()
        .save_rich(&report, &projection, ReportHandoff::Manual, false)
        .expect("save");
    assert!(stored.report_json.len() > 4096);
    assert!(projection.facts.as_ref().expect("facts").to_string().len() < 4096);
    assert_eq!(stored.delivery, FullDelivery::LocalOnly);
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Done)
    );
    assert!(store.jobs().work_queue().expect("queue").is_empty());
    drop(store);
    let store = Store::open(&path).expect("reopen");
    assert_eq!(
        store.local_reports().get_rich(&job).expect("lookup"),
        Some(stored.clone())
    );
    assert_eq!(
        store
            .local_reports()
            .get_detail(&report.report_id)
            .expect("detail"),
        Some(ReportDetail::Rich(Box::new(stored)))
    );
    assert_eq!(
        report.canonical_json().expect("canonical"),
        report.canonical_json().expect("unchanged")
    );
}

#[test]
fn scheduled_handoff_is_atomic_and_invalid_handoff_rolls_back_everything() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Store::open(directory.path().join("state.sqlite")).expect("open");
    let job = identity("scheduled");
    let report = report(&job);
    let projection = compact(&report);
    let error = store
        .local_reports()
        .save_rich(&report, &projection, ReportHandoff::Scheduled, true)
        .expect_err("missing job");
    assert!(matches!(error, AnalyzerError::State(_)));
    assert_eq!(store.local_reports().counts().expect("counts"), (0, 0));
    assert!(
        store
            .local_reports()
            .get_rich(&job)
            .expect("detail")
            .is_none()
    );
    store.jobs().upsert_discovered(&job).expect("discover");
    store
        .jobs()
        .set_phase(&job, JobPhase::Analyzing)
        .expect("analyzing");
    store
        .local_reports()
        .save_rich(&report, &projection, ReportHandoff::Scheduled, true)
        .expect("save");
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Reporting)
    );
    assert!(store.local_reports().get(&job).expect("compact").is_some());
    assert!(
        store
            .local_reports()
            .get_rich(&job)
            .expect("full")
            .is_some()
    );
}

#[test]
fn immutable_replay_keeps_id_digest_delivery_and_rejects_conflicting_evidence() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Store::open(directory.path().join("state.sqlite")).expect("open");
    let job = identity("immutable");
    let original = report(&job);
    let projection = compact(&original);
    let first = store
        .local_reports()
        .save_rich(&original, &projection, ReportHandoff::Manual, true)
        .expect("save");
    store
        .local_reports()
        .mark_posted(&job)
        .expect("summary accepted");
    store
        .local_reports()
        .set_full_delivery(&job, FullDelivery::SummaryOnly)
        .expect("full pending");
    let replay = store
        .local_reports()
        .save_rich(&original, &projection, ReportHandoff::Manual, false)
        .expect("replay");
    assert_eq!(replay.digest, first.digest);
    assert_eq!(replay.report.report_id, first.report.report_id);
    assert_eq!(replay.delivery, FullDelivery::SummaryOnly);
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Done)
    );
    let mut conflicting = original.clone();
    conflicting.capture.evidence[0]
        .text
        .push_str("different evidence");
    let error = store
        .local_reports()
        .save_rich(
            &conflicting,
            &compact(&conflicting),
            ReportHandoff::Manual,
            true,
        )
        .expect_err("immutable conflict");
    assert!(matches!(error, AnalyzerError::Integrity(_)));
    let surviving = store
        .local_reports()
        .get_rich(&job)
        .expect("read")
        .expect("saved");
    assert_eq!(surviving.report, original);
    assert_eq!(surviving.digest, first.digest);
    assert!(
        store
            .local_reports()
            .get(&job)
            .expect("read")
            .expect("saved")
            .posted
    );
    assert_eq!(
        store.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Done)
    );
}

#[test]
fn projection_binding_is_mandatory_and_cannot_mutate_canonical_detail() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Store::open(directory.path().join("state.sqlite")).expect("open");
    let job = identity("binding");
    let report = report(&job);
    let original_json = report.canonical_json().expect("canonical");
    let mut projection = compact(&report);
    projection.facts =
        Some(json!({"schemaVersion":2,"reportId":report.report_id,"reportDigest":"wrong"}));
    assert!(matches!(
        store
            .local_reports()
            .save_rich(&report, &projection, ReportHandoff::None, true),
        Err(AnalyzerError::Integrity(_))
    ));
    assert_eq!(store.local_reports().counts().expect("counts"), (0, 0));
    assert_eq!(report.canonical_json().expect("canonical"), original_json);
}

#[test]
fn summary_acceptance_does_not_claim_full_delivery_or_retain_a_phantom_job() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Store::open(directory.path().join("state.sqlite")).expect("open");
    let job = identity("delivery");
    let report = report(&job);
    store
        .local_reports()
        .save_rich(&report, &compact(&report), ReportHandoff::Manual, true)
        .expect("save");
    store.local_reports().mark_posted(&job).expect("v1 ack");
    store
        .jobs()
        .set_phase(&job, JobPhase::Done)
        .expect("settle queue");
    assert_eq!(
        store.local_reports().pending_full().expect("pending").len(),
        1
    );
    store
        .local_reports()
        .set_full_delivery(&job, FullDelivery::SummaryOnly)
        .expect("old server");
    assert_eq!(
        store.local_reports().pending_full().expect("pending")[0].delivery,
        FullDelivery::SummaryOnly
    );
    assert!(store.jobs().work_queue().expect("queue").is_empty());
    store
        .local_reports()
        .set_full_delivery(&job, FullDelivery::FullyDelivered)
        .expect("v2 ack");
    assert!(
        store
            .local_reports()
            .pending_full()
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        store
            .local_reports()
            .page(&ReportQuery::default())
            .expect("page")
            .reports[0]
            .full_delivery,
        FullDelivery::FullyDelivered
    );
}

#[test]
fn manual_save_preserves_another_active_run_and_purged_identity() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Store::open(directory.path().join("state.sqlite")).expect("open");
    for (id, phase) in [("busy", JobPhase::Analyzing), ("purged", JobPhase::Dropped)] {
        let job = identity(id);
        store.jobs().upsert_discovered(&job).expect("discover");
        store.jobs().set_phase(&job, phase).expect("phase");
        let report = report(&job);
        store
            .local_reports()
            .save_rich(&report, &compact(&report), ReportHandoff::Manual, false)
            .expect("save");
        assert_eq!(store.jobs().phase_of(&job).expect("phase"), Some(phase));
        assert!(
            store
                .local_reports()
                .get_rich(&job)
                .expect("detail")
                .is_some()
        );
    }
}

#[test]
fn report_pages_do_not_load_or_deserialize_full_detail_or_legacy_facts() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.sqlite");
    let store = Store::open(&path).expect("open");
    let job = identity("light-list");
    let report = report(&job);
    store
        .local_reports()
        .save_rich(&report, &compact(&report), ReportHandoff::None, true)
        .expect("save");
    let raw = Connection::open(&path).expect("raw");
    raw.execute(
        "UPDATE report_details SET report_json = ?1",
        params!["invalid detail".repeat(100_000)],
    )
    .expect("damage detail");
    raw.execute(
        "UPDATE local_reports SET facts_json = ?1",
        params!["invalid facts".repeat(100_000)],
    )
    .expect("damage facts");
    let page = store
        .local_reports()
        .page(&ReportQuery::default())
        .expect("list needs neither JSON document");
    assert_eq!(page.reports.len(), 1);
    assert_eq!(page.reports[0].report_id, report.report_id);
    assert_eq!(page.reports[0].schema_version, 2);
    assert!(page.reports[0].detail_available);
    assert!(matches!(
        store.local_reports().get_detail(&report.report_id),
        Err(AnalyzerError::Integrity(_))
    ));
}

#[test]
fn migration_from_v3_preserves_history_and_assigns_legacy_locators() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("state.sqlite");
    let store = Store::open(&path).expect("open");
    let mut job = identity("historical");
    job.analyzer_version = "0.1.0".into();
    store
        .local_reports()
        .insert(
            &job,
            ReportOutcome::Completed,
            "historical summary",
            "{\"legacy\":true}",
        )
        .expect("legacy");
    store.local_reports().mark_posted(&job).expect("posted");
    store.jobs().upsert_discovered(&job).expect("discover");
    store
        .jobs()
        .set_phase(&job, JobPhase::Done)
        .expect("settled");
    store
        .secrets()
        .set("analyzer_token", "preserved-secret")
        .expect("secret");
    store
        .cursors()
        .set_monotonic("events", "000042")
        .expect("cursor");
    let before = store
        .local_reports()
        .get(&job)
        .expect("get")
        .expect("report");
    drop(store);
    let raw = Connection::open(&path).expect("raw");
    raw.execute_batch(
        "DROP TABLE report_details;
        DROP INDEX local_reports_report_id;
        ALTER TABLE local_reports DROP COLUMN report_id;
        DELETE FROM schema_migrations WHERE version = 4;",
    )
    .expect("recreate v3 layout");
    drop(raw);
    let migrated = Store::open(&path).expect("migrate v3");
    assert_eq!(
        migrated.local_reports().get(&job).expect("get"),
        Some(before.clone())
    );
    assert_eq!(
        migrated
            .local_reports()
            .get_detail(&legacy_id(&job))
            .expect("legacy detail"),
        Some(ReportDetail::Legacy(before))
    );
    assert_eq!(
        migrated
            .secrets()
            .get("analyzer_token")
            .expect("secret")
            .as_deref(),
        Some("preserved-secret")
    );
    assert_eq!(
        migrated.cursors().get("events").expect("cursor").as_deref(),
        Some("000042")
    );
    assert_eq!(
        migrated.jobs().phase_of(&job).expect("phase"),
        Some(JobPhase::Done)
    );
    assert!(
        migrated
            .local_reports()
            .pending_full()
            .expect("outbox")
            .is_empty()
    );
    let row = &migrated
        .local_reports()
        .page(&ReportQuery::default())
        .expect("page")
        .reports[0];
    assert_eq!(row.report_id, legacy_id(&job));
    assert_eq!(row.schema_version, 1);
    assert!(!row.detail_available);
    assert!(row.posted);
    drop(migrated);
    Store::open(&path).expect("migration is idempotent");
}
