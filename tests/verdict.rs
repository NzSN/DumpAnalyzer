//! Verdict-writer tests (task D1): assembly bounds (summary truncation,
//! 16 KiB envelope shrinking, integrity failures), idempotent settle through
//! a wiremock DumpLedger, local-verdict mode with later replay, the
//! `invalid_request` bug signal, transient propagation, and boot
//! reconciliation in both directions.

use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use dump_analyzer::client::LedgerClient;
use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::state::Store;
use dump_analyzer::types::{AnalyzerError, JobIdentity, JobPhase, ReportOutcome, RunOutput};
use dump_analyzer::verdict::{self, MAX_BODY_BYTES, ReconcileReport, SUMMARY_TRUNCATION_MARKER};
use dump_analyzer::wire::{AnalysisReportSubmission, Analyzer, MAX_SUMMARY_CHARS};

const TOKEN: &str = "analyzer-token-0123456789abcdef";
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DUMP_ID: &str = "dump_01JABCXYZ";
const KIND: &str = "triage";
const VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    server: MockServer,
    store: Store,
    config: Config,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let state_dir = dir.path().join("state");
    let store = Store::open(state_dir.join("analyzer.sqlite")).expect("store");
    let config = test_config(
        Url::parse(&server.uri()).expect("mock server URI"),
        state_dir,
        "dump-analyzer",
    );
    Harness {
        server,
        store,
        config,
        _dir: dir,
    }
}

fn test_config(base_url: Url, state_dir: PathBuf, name: &str) -> Config {
    Config {
        base_url,
        token: Some(SecretToken::new(TOKEN)),
        state_dir,
        name: name.to_owned(),
        version: VERSION.to_owned(),
        poll_interval: Duration::from_millis(10_000),
        run_wall_timeout: Duration::from_millis(600_000),
        max_output_bytes: 1024 * 1024,
        max_workspace_bytes: 2 * 1024 * 1024 * 1024,
        byte_cache_max_bytes: 10 * 1024 * 1024 * 1024,
        ssh_target: None,
        symbol_cache_dir: None,
        http_addr: None,
        runner: dump_analyzer::types::RunnerKind::CdbSsh,
        claude_bin: "claude".to_string(),
        claude_model: None,
        tls_ca_cert: None,
        scheduler_enabled: true,
        writeback_enabled: true,
    }
}

/// A config for pure-assembly tests (no server is contacted).
fn pure_config() -> Config {
    test_config(
        Url::parse("https://ledger.example").expect("static URL"),
        PathBuf::from("./unused-in-verdict-tests"),
        "dump-analyzer",
    )
}

fn identity() -> JobIdentity {
    identity_for(DUMP_ID, KIND)
}

/// A job identity with the fixture sha256/version and the given dump/kind,
/// for tests that queue more than one report.
fn identity_for(dump_id: &str, kind: &str) -> JobIdentity {
    JobIdentity {
        dump_id: dump_id.to_owned(),
        input_sha256: SHA256.to_owned(),
        kind: kind.to_owned(),
        analyzer_version: VERSION.to_owned(),
    }
}

fn run_output(summary: impl Into<String>, facts: Value) -> RunOutput {
    RunOutput {
        capture: None,
        outcome: ReportOutcome::Completed,
        summary: summary.into(),
        facts,
    }
}

fn analyses_path() -> String {
    format!("/api/v1/dumps/{DUMP_ID}/analyses")
}

/// The server's stored-report shape (fixture).
fn analysis_report() -> Value {
    json!({
        "analysisId": "analysis_01JABC001",
        "dumpId": DUMP_ID,
        "analyzer": { "name": "dump-analyzer", "version": VERSION },
        "kind": KIND,
        "inputSha256": SHA256,
        "createdAt": "2026-10-13T03:00:00.000Z",
        "outcome": "completed",
        "summary": "Access violation writing location 0x0000000000000000"
    })
}

/// DumpLedger's handled-error envelope.
fn error_envelope(code: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": "Synthetic failure for the verdict test",
            "retryable": false
        }
    })
}

/// Fastify's default (unhandled) 404 body for an unregistered route: no
/// DumpLedger error envelope, which is exactly what distinguishes "the
/// analyses route does not exist yet" from a purged dump.
fn fastify_route_missing(http_method: &str) -> Value {
    json!({
        "message": format!("Route {http_method}:{} not found", analyses_path()),
        "error": "Not Found",
        "statusCode": 404
    })
}

fn set_up_reporting_job(store: &Store, identity: &JobIdentity) {
    store
        .jobs()
        .upsert_discovered(identity)
        .expect("job insert");
    store
        .jobs()
        .set_phase(identity, JobPhase::Reporting)
        .expect("phase");
}

fn set_up_stored_verdict(store: &Store, identity: &JobIdentity, summary: &str, facts_json: &str) {
    store
        .local_reports()
        .insert(identity, ReportOutcome::Completed, summary, facts_json)
        .expect("stored verdict");
}

fn assert_job_phase(store: &Store, phase: JobPhase) {
    let jobs = store.jobs().jobs_in_phase(phase).expect("phase query");
    assert_eq!(
        jobs.len(),
        1,
        "expected exactly one job in phase {phase:?}, got {jobs:?}"
    );
    assert_eq!(jobs[0].0, identity());
}

fn assert_row_posted(store: &Store, posted: bool) {
    assert_row_posted_for(store, &identity(), posted);
}

fn assert_row_posted_for(store: &Store, identity: &JobIdentity, posted: bool) {
    let row = store
        .local_reports()
        .get(identity)
        .expect("row query")
        .expect("row exists");
    assert_eq!(row.posted, posted);
}

// ---------------------------------------------------------------------------
// Assembly bounds
// ---------------------------------------------------------------------------

#[test]
fn verdict_assemble_truncates_summary_on_codepoint_boundaries() {
    let config = pure_config();
    // 'é' encodes as two UTF-8 bytes: a byte-based truncation would split it.
    let long = "é".repeat(2100);
    let submission =
        verdict::assemble(&identity(), run_output(long, Value::Null), &config).expect("assembly");

    assert_eq!(submission.summary.chars().count(), MAX_SUMMARY_CHARS);
    assert!(submission.summary.ends_with(SUMMARY_TRUNCATION_MARKER));
    assert_eq!(
        submission.summary,
        format!(
            "{}{}",
            "é".repeat(MAX_SUMMARY_CHARS - SUMMARY_TRUNCATION_MARKER.chars().count()),
            SUMMARY_TRUNCATION_MARKER
        )
    );
    assert_eq!(submission.facts, None);
    assert_eq!(submission.outcome, ReportOutcome::Completed);
    assert_eq!(submission.kind, KIND);
    assert_eq!(submission.input_sha256, SHA256);
    assert_eq!(submission.analyzer.name, "dump-analyzer");
    assert_eq!(submission.analyzer.version, VERSION);
    assert_eq!(submission.duplicate_of, None);

    let short = "Access violation in renderer".to_owned();
    let submission =
        verdict::assemble(&identity(), run_output(short.clone(), Value::Null), &config)
            .expect("assembly");
    assert_eq!(submission.summary, short);
}

#[test]
fn verdict_assemble_normalizes_facts_and_rejects_non_objects() {
    let config = pure_config();

    let facts = json!({ "exception": { "code": 3221225477u32 } });
    let submission =
        verdict::assemble(&identity(), run_output("s", facts.clone()), &config).expect("assembly");
    assert_eq!(submission.facts, Some(facts));

    let submission =
        verdict::assemble(&identity(), run_output("s", Value::Null), &config).expect("assembly");
    assert_eq!(submission.facts, None);

    let submission =
        verdict::assemble(&identity(), run_output("s", json!({})), &config).expect("assembly");
    assert_eq!(submission.facts, None);

    let err = verdict::assemble(
        &identity(),
        run_output("s", json!(["not", "an", "object"])),
        &config,
    )
    .expect_err("non-object facts must fail");
    assert!(matches!(err, AnalyzerError::Integrity(_)), "{err}");
}

#[test]
fn verdict_assemble_shrinks_facts_to_fit_the_envelope() {
    let config = pure_config();
    let frames: Vec<Value> = (0..3000)
        .map(|index| json!(format!("renderer!frame_{index}_with_a_quite_long_name")))
        .collect();
    let facts = json!({
        "exception": { "code": 3221225477u32, "name": "ACCESS_VIOLATION" },
        "failure": { "reason": "toolchain" },
        "frames": frames,
        "frames_total": 3000,
        "frames_truncated": true,
        "symbols": { "missing": ["renderer.pdb"] },
    });

    let submission = verdict::assemble(&identity(), run_output("short", facts.clone()), &config)
        .expect("shrink");
    let encoded = serde_json::to_vec(&submission).expect("encode");
    assert!(
        encoded.len() <= MAX_BODY_BYTES,
        "body is {} bytes",
        encoded.len()
    );

    let kept = submission
        .facts
        .as_ref()
        .and_then(Value::as_object)
        .expect("facts retained");
    assert_eq!(kept.get("exception"), facts.get("exception"));
    assert_eq!(kept.get("failure"), facts.get("failure"));
    assert!(!kept.contains_key("frames"));
    assert!(!kept.contains_key("symbols"));
    assert!(!kept.contains_key("frames_total"));
    assert!(!kept.contains_key("frames_truncated"));
}

#[test]
fn verdict_assemble_rejects_over_bound_analyzer_names() {
    // The analyzer attribution is contract-bounded (name 128, version 64
    // UTF-16 units, per analyses.ts); over-bound names are a decode failure,
    // never a submission.
    let mut config = pure_config();
    config.name = "n".repeat(129);
    let err = verdict::assemble(
        &identity(),
        run_output("short", json!({ "exception": { "code": 1 } })),
        &config,
    )
    .expect_err("over-bound analyzer name must fail");
    assert!(matches!(err, AnalyzerError::Decode(_)), "{err}");
}

#[test]
fn verdict_assemble_maximal_bounded_report_always_fits() {
    // With every field at its contract bound (name 128, version 64, kind 64,
    // summary 2000 chars, facts 4096 bytes), the 16 KiB envelope cannot
    // overflow — the unshrinkable case is unreachable by construction.
    let mut config = pure_config();
    config.name = "n".repeat(128);
    let mut identity = identity();
    identity.analyzer_version = "v".repeat(64);
    identity.kind = "k".repeat(64);
    let long_summary = "s".repeat(1990);
    let filler = "f".repeat(4050);
    let submission = verdict::assemble(
        &identity,
        run_output(&long_summary, json!({ "frames": filler })),
        &config,
    )
    .expect("maximal bounded report assembles");
    let bytes = serde_json::to_vec(&submission).expect("encode").len();
    assert!(
        bytes <= dump_analyzer::verdict::MAX_BODY_BYTES,
        "maximal bounded report fits the envelope: {bytes}"
    );
}

#[tokio::test]
async fn verdict_submit_rejects_mismatched_submission_before_io() {
    // submit() guards the pin: a submission whose sha256 does not match the
    // job identity is an integrity failure, before any network call.
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = AnalysisReportSubmission::new(
        Analyzer {
            name: "dump-analyzer".to_owned(),
            version: VERSION.to_owned(),
        },
        KIND.to_owned(),
        "f".repeat(64),
        ReportOutcome::Completed,
        "s".to_owned(),
        None,
        None,
    )
    .expect("valid submission");

    let err = verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect_err("mismatched pin must fail");
    assert!(matches!(err, AnalyzerError::Integrity(_)), "{err}");

    assert_job_phase(&harness.store, JobPhase::Reporting);
    assert!(
        harness
            .store
            .local_reports()
            .get(&identity)
            .expect("row query")
            .is_none(),
        "no local copy is written for a mismatched report"
    );
}

// ---------------------------------------------------------------------------
// Submit: settle paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verdict_submit_created_settles_done_and_marks_posted() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output(
            "Access violation",
            json!({ "exception": { "code": 3221225477u32 } }),
        ),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .and(body_json(
            serde_json::to_value(&submission).expect("encode"),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report()))
        .expect(1)
        .mount(&harness.server)
        .await;

    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("submit");

    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, true);
    let row = harness
        .store
        .local_reports()
        .get(&identity)
        .expect("row")
        .expect("row exists");
    assert_eq!(row.summary, submission.summary);
    assert_eq!(
        row.facts_json,
        submission.facts.as_ref().expect("facts").to_string()
    );
}

#[tokio::test]
async fn verdict_submit_replay_200_settles_done() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(analysis_report()))
        .expect(1)
        .mount(&harness.server)
        .await;

    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("replayed submit");

    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_submit_dump_404_drops_the_job() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_envelope("not_found")))
        .expect(1)
        .mount(&harness.server)
        .await;

    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("purged dump settles");

    assert_job_phase(&harness.store, JobPhase::Dropped);
    // The verdict can never be accepted; the copy is dequeued but retained.
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_submit_route_404_enters_local_verdict_mode_and_later_replays() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    // Pre-AI3 server: the route does not exist (Fastify default 404, no
    // DumpLedger error envelope).
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(fastify_route_missing("POST")))
        .up_to_n_times(1)
        .mount(&harness.server)
        .await;

    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("local-verdict mode settles");

    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, false);

    // AI3 ships: the next boot's replay sweep delivers the stored verdict.
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .and(body_json(
            serde_json::to_value(&submission).expect("encode"),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report()))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report: ReconcileReport =
        verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
            .await
            .expect("reconcile");
    assert_eq!(report.replayed, 1, "{report:?}");
    assert_eq!(report.abandoned, 0, "{report:?}");
    assert!(!report.route_absent, "{report:?}");
    assert!(report.errors.is_empty(), "{report:?}");

    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_submit_invalid_request_fails_the_job() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(400).set_body_json(error_envelope("invalid_request")))
        .expect(1)
        .mount(&harness.server)
        .await;

    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("bug signal settles the job");

    assert_job_phase(&harness.store, JobPhase::Failed);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_submit_transient_error_keeps_the_job_reporting() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(error_envelope("storage_unavailable")),
        )
        .expect(1)
        .mount(&harness.server)
        .await;

    let err = verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect_err("transient failure returns to the caller's retry budget");
    assert!(err.is_transient(), "{err}");

    assert_job_phase(&harness.store, JobPhase::Reporting);
    assert_row_posted(&harness.store, false);
}

// ---------------------------------------------------------------------------
// Boot reconciliation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verdict_reconcile_confirms_reporting_job_present_server_side() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    set_up_stored_verdict(&harness.store, &identity, "stored summary", "null");

    Mock::given(method("GET"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "analyses": [analysis_report()]
        })))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.confirmed, 1, "{report:?}");
    assert_eq!(report.reposted, 0, "{report:?}");
    assert!(report.unresolved.is_empty(), "{report:?}");
    assert!(report.errors.is_empty(), "{report:?}");
    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_reconcile_reposts_when_identity_is_absent() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let facts = json!({ "exception": { "code": 3221225477u32 } });
    set_up_stored_verdict(
        &harness.store,
        &identity,
        "stored summary",
        &facts.to_string(),
    );

    Mock::given(method("GET"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "analyses": [] })))
        .expect(1)
        .mount(&harness.server)
        .await;

    let expected = AnalysisReportSubmission::new(
        Analyzer {
            name: "dump-analyzer".to_owned(),
            version: VERSION.to_owned(),
        },
        KIND.to_owned(),
        SHA256.to_owned(),
        ReportOutcome::Completed,
        "stored summary".to_owned(),
        Some(facts),
        None,
    )
    .expect("expected submission");
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .and(body_json(serde_json::to_value(&expected).expect("encode")))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report()))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.reposted, 1, "{report:?}");
    assert_eq!(report.confirmed, 0, "{report:?}");
    assert!(report.errors.is_empty(), "{report:?}");
    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_reconcile_requeues_reporting_job_without_local_copy() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);

    Mock::given(method("GET"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "analyses": [] })))
        .expect(0)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.unresolved, vec![identity]);
    assert_job_phase(&harness.store, JobPhase::Discovered);
}

#[tokio::test]
async fn verdict_reconcile_drops_reporting_job_when_dump_is_gone() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    set_up_stored_verdict(&harness.store, &identity, "stored summary", "null");

    Mock::given(method("GET"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_envelope("not_found")))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.dropped, 1, "{report:?}");
    assert_job_phase(&harness.store, JobPhase::Dropped);
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_reconcile_route_still_absent_keeps_local_mode() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    set_up_stored_verdict(&harness.store, &identity, "stored summary", "null");

    // Pre-AI3: neither the GET nor the POST analyses route exists.
    Mock::given(method("GET"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(fastify_route_missing("GET")))
        .up_to_n_times(1)
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(fastify_route_missing("POST")))
        .up_to_n_times(1)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.local_mode, 1, "{report:?}");
    assert!(report.route_absent, "{report:?}");
    assert_eq!(report.replayed, 0, "{report:?}");
    assert_job_phase(&harness.store, JobPhase::Done);
    assert_row_posted(&harness.store, false);
}

#[tokio::test]
async fn verdict_reconcile_replay_sweep_abandons_verdicts_for_purged_dumps() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_stored_verdict(&harness.store, &identity, "stored summary", "null");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_envelope("not_found")))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .expect("reconcile");

    assert_eq!(report.abandoned, 1, "{report:?}");
    assert_eq!(report.replayed, 0, "{report:?}");
    assert!(!report.route_absent, "{report:?}");
    assert_row_posted(&harness.store, true);
}

#[test]
fn verdict_assemble_enforces_the_4kib_facts_budget() {
    // One huge value exceeds the server's per-field facts budget on its own;
    // the budget shrink drops keys lowest-value-first until it fits.
    let big = "x".repeat(5000);
    let facts = serde_json::json!({
        "exception": "0xc0000005",
        "frames": big,
    });
    let output = RunOutput {
        capture: None,
        outcome: ReportOutcome::Completed,
        summary: "bounded".to_string(),
        facts,
    };
    let submission =
        verdict::assemble(&identity(), output, &pure_config()).expect("assembles after shrinking");
    let facts = submission.facts.expect("some facts must remain");
    assert!(
        facts.to_string().len() <= dump_analyzer::verdict::MAX_FACTS_BYTES,
        "facts fit the 4 KiB budget"
    );
    // The high-signal key survived; the bulky low-value key was dropped.
    assert!(facts.get("exception").is_some());
    assert!(facts.get("frames").is_none());
}

#[test]
fn verdict_assemble_facts_budget_alone_can_absent_facts() {
    // A single key whose value alone exceeds the budget: dropping it leaves
    // an empty object, which becomes absent.
    let facts = serde_json::json!({ "frames": "x".repeat(5000) });
    let output = RunOutput {
        capture: None,
        outcome: ReportOutcome::Completed,
        summary: "bounded".to_string(),
        facts,
    };
    let submission = verdict::assemble(&identity(), output, &pure_config())
        .expect("assembles with facts absent");
    assert!(submission.facts.is_none());
}

// ---------------------------------------------------------------------------
// Continuous replay (R1): the standalone periodic sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verdict_replay_pending_delivers_stored_verdicts_when_route_appears() {
    // A verdict recorded in local-verdict mode (pre-AI3 server) is delivered
    // by the periodic sweep once the analyses route appears — no restart.
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    let submission = verdict::assemble(
        &identity,
        run_output("Access violation", Value::Null),
        &harness.config,
    )
    .expect("assembly");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(fastify_route_missing("POST")))
        .up_to_n_times(1)
        .mount(&harness.server)
        .await;
    verdict::submit(&client, &harness.store, &identity, &submission)
        .await
        .expect("local-verdict mode settles");
    assert_row_posted(&harness.store, false);

    // The route appears mid-run; the periodic sweep delivers the row.
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .and(body_json(
            serde_json::to_value(&submission).expect("encode"),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(analysis_report()))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .expect("sweep");

    assert_eq!(report.replayed, 1, "{report:?}");
    assert_eq!(report.abandoned, 0, "{report:?}");
    assert!(!report.route_absent, "{report:?}");
    assert!(report.errors.is_empty(), "{report:?}");
    assert_row_posted(&harness.store, true);
}

#[tokio::test]
async fn verdict_replay_pending_with_nothing_pending_makes_no_requests() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");

    let report = verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .expect("empty sweep");

    assert_eq!(report, dump_analyzer::verdict::ReplayReport::default());
    let requests = harness
        .server
        .received_requests()
        .await
        .expect("mock server records requests by default");
    assert!(
        requests.is_empty(),
        "an empty queue must not touch the network: {requests:?}"
    );
}

#[tokio::test]
async fn verdict_replay_pending_route_absent_keeps_rows_pending() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let first = identity();
    let second = identity_for(DUMP_ID, "classification");
    set_up_stored_verdict(&harness.store, &first, "first stored verdict", "null");
    set_up_stored_verdict(&harness.store, &second, "second stored verdict", "null");

    // The fast path: the first POST proves the route is absent, so the sweep
    // stops without touching the rest of the queue.
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(404).set_body_json(fastify_route_missing("POST")))
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .expect("route-absent sweep");

    assert!(report.route_absent, "{report:?}");
    assert_eq!(report.replayed, 0, "{report:?}");
    assert_eq!(report.abandoned, 0, "{report:?}");
    assert_row_posted_for(&harness.store, &first, false);
    assert_row_posted_for(&harness.store, &second, false);
}

#[tokio::test]
async fn verdict_replay_pending_transient_failure_keeps_rows_pending() {
    let harness = harness().await;
    let client = LedgerClient::new(&harness.config).expect("client");
    let identity = identity();
    set_up_stored_verdict(&harness.store, &identity, "stored summary", "null");

    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(error_envelope("storage_unavailable")),
        )
        .expect(1)
        .mount(&harness.server)
        .await;

    let report = verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .expect("transient sweep returns Ok with the failure recorded");

    assert_eq!(report.replayed, 0, "{report:?}");
    assert_eq!(report.abandoned, 0, "{report:?}");
    assert!(!report.route_absent, "{report:?}");
    assert_eq!(report.errors.len(), 1, "{report:?}");
    assert!(
        report.errors[0].contains(SHA256),
        "the error names the row: {report:?}"
    );
    assert_row_posted(&harness.store, false);
}

#[tokio::test]
async fn verdict_replay_sweep_settles_the_reporting_job_done() {
    let harness = harness().await;
    // A pending local report + a reporting job (the on-demand shape).
    let identity = identity();
    harness
        .store
        .jobs()
        .upsert_discovered(&identity)
        .expect("upsert");
    harness
        .store
        .jobs()
        .set_phase(&identity, JobPhase::Reporting)
        .expect("reporting");
    harness
        .store
        .local_reports()
        .insert(
            &identity,
            ReportOutcome::Completed,
            "a verdict",
            "{\"k\":1}",
        )
        .expect("insert");

    Mock::given(method("POST"))
        .and(path(format!("/api/v1/dumps/{}/analyses", identity.dump_id)))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "analysisId": "analysis_1",
            "dumpId": identity.dump_id,
            "analyzer": { "name": "dump-analyzer", "version": "0.1.0" },
            "kind": "triage",
            "inputSha256": identity.input_sha256,
            "outcome": "completed",
            "summary": "a verdict",
            "createdAt": "2026-10-14T08:00:00.000Z"
        })))
        .mount(&harness.server)
        .await;

    let client = LedgerClient::new(&harness.config).expect("client");
    let report = dump_analyzer::verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .expect("sweep");
    assert_eq!(report.replayed, 1);
    assert_eq!(
        harness.store.jobs().phase_of(&identity).expect("phase"),
        Some(JobPhase::Done),
        "the reporting job settles to done once its verdict posts"
    );
}

#[tokio::test]
async fn verdict_local_sink_records_and_settles_without_any_http() {
    let harness = harness().await;
    let identity = identity();
    harness
        .store
        .jobs()
        .upsert_discovered(&identity)
        .expect("upsert");
    harness
        .store
        .jobs()
        .set_phase(&identity, JobPhase::Reporting)
        .expect("reporting");

    let sink = dump_analyzer::verdict::LocalVerdictSink::new(
        harness.store.clone(),
        harness.config.clone(),
    );
    dump_analyzer::agent::VerdictSink::submit(
        &sink,
        &identity,
        RunOutput {
            capture: None,
            outcome: ReportOutcome::Completed,
            summary: "local only".to_string(),
            facts: json!({ "k": 1 }),
        },
    )
    .await
    .expect("submit");

    assert_eq!(
        harness.store.jobs().phase_of(&identity).expect("phase"),
        Some(JobPhase::Done)
    );
    let pending = harness.store.local_reports().pending().expect("pending");
    assert_eq!(pending.len(), 1, "recorded locally, never posted");
    // No HTTP happened at all: the mock server saw no requests.
    let requests = harness.server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "write-back off means zero ledger calls"
    );
}

#[tokio::test]
async fn verdict_local_recovery_requeues_reportless_jobs() {
    let harness = harness().await;
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    assert_eq!(
        verdict::settle_reporting_locally(&harness.store).unwrap(),
        0
    );
    assert_job_phase(&harness.store, JobPhase::Discovered);
    assert!(harness.store.local_reports().pending().unwrap().is_empty());
}

#[tokio::test]
async fn verdict_route_absent_dequeues_only_reporting_jobs_with_local_reports() {
    let harness = harness().await;
    let first = identity();
    let mut second = first.clone();
    second.dump_id = "dump_SECOND".into();
    let mut in_flight = first.clone();
    in_flight.dump_id = "dump_INFLIGHT".into();
    for job in [&first, &second, &in_flight] {
        set_up_reporting_job(&harness.store, job);
    }
    for job in [&first, &second] {
        set_up_stored_verdict(&harness.store, job, "local verdict", "{}");
    }
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&harness.server)
        .await;
    let client = LedgerClient::new(&harness.config).unwrap();
    let replay = verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .unwrap();
    assert!(replay.route_absent);
    for job in [&first, &second] {
        assert_eq!(
            harness.store.jobs().phase_of(job).unwrap(),
            Some(JobPhase::Done)
        );
    }
    assert_eq!(
        harness.store.jobs().phase_of(&in_flight).unwrap(),
        Some(JobPhase::Reporting)
    );
    assert_eq!(harness.store.jobs().list().unwrap().len(), 1);
    assert_eq!(harness.store.local_reports().pending().unwrap().len(), 2);
}

#[tokio::test]
async fn verdict_replay_dequeues_a_report_already_posted_before_queue_update() {
    let harness = harness().await;
    let identity = identity();
    set_up_stored_verdict(&harness.store, &identity, "delivered first", "{}");
    harness
        .store
        .local_reports()
        .mark_posted(&identity)
        .unwrap();
    // Delivery ran before manual completion created its reporting entry.
    set_up_reporting_job(&harness.store, &identity);
    let client = LedgerClient::new(&harness.config).unwrap();
    verdict::replay_pending(&client, &harness.store, &harness.config)
        .await
        .unwrap();
    assert_eq!(
        harness.store.jobs().phase_of(&identity).unwrap(),
        Some(JobPhase::Done)
    );
    assert!(harness.store.jobs().list().unwrap().is_empty());
    assert!(harness.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn verdict_boot_requeues_reportless_job_without_waiting_for_the_ledger() {
    let harness = harness().await;
    let identity = identity();
    set_up_reporting_job(&harness.store, &identity);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .expect(0)
        .mount(&harness.server)
        .await;
    let client = LedgerClient::new(&harness.config).unwrap();
    let report = verdict::reconcile_on_boot(&client, &harness.store, &harness.config)
        .await
        .unwrap();
    assert_eq!(report.unresolved, vec![identity]);
    assert_job_phase(&harness.store, JobPhase::Discovered);
}

fn prepare_rich(h: &Harness) -> (dump_analyzer::state::StoredReport, AnalysisReportSubmission) {
    let job = identity();
    h.store.jobs().upsert_discovered(&job).unwrap();
    h.store.jobs().set_phase(&job, JobPhase::Analyzing).unwrap();
    verdict::prepare_report(
        &h.store,
        &job,
        &run_output("Rich report; cause unknown", json!({})),
        &h.config,
        dump_analyzer::state::ReportHandoff::Scheduled,
    )
    .unwrap()
}
fn rich_ack(submission: &AnalysisReportSubmission) -> Value {
    let mut ack = analysis_report();
    ack["summary"] = json!(submission.summary);
    ack["outcome"] = json!(submission.outcome);
    ack["facts"] = json!(submission.facts);
    ack
}
fn rich_v2_ack(
    submission: &AnalysisReportSubmission,
    stored: &dump_analyzer::state::StoredReport,
) -> Value {
    let mut ack = rich_ack(submission);
    ack["reportJson"] = json!(stored.report_json);
    ack["reportDigest"] = json!(stored.digest);
    ack
}

#[tokio::test]
async fn rich_summary_fallback_later_promotes_full_detail_without_losing_it() {
    use dump_analyzer::state::FullDelivery;
    let h = harness().await;
    let (stored, compact) = prepare_rich(&h);
    Mock::given(method("POST"))
        .and(path(analyses_path()))
        .respond_with(ResponseTemplate::new(201).set_body_json(rich_ack(&compact)))
        .expect(1)
        .mount(&h.server)
        .await;
    let client = LedgerClient::new(&h.config).unwrap();
    // Unregistered v2 route is the old-server fallback.
    verdict::submit(&client, &h.store, &identity(), &compact)
        .await
        .unwrap();
    assert!(
        h.store
            .local_reports()
            .get(&identity())
            .unwrap()
            .unwrap()
            .posted
    );
    assert_eq!(
        h.store
            .local_reports()
            .get_rich(&identity())
            .unwrap()
            .unwrap()
            .delivery,
        FullDelivery::SummaryOnly
    );
    assert_eq!(
        h.store.jobs().phase_of(&identity()).unwrap(),
        Some(JobPhase::Done)
    );
    Mock::given(method("POST"))
        .and(path(format!("/api/v2/dumps/{DUMP_ID}/analyses")))
        .respond_with(ResponseTemplate::new(200).set_body_json(rich_v2_ack(&compact, &stored)))
        .expect(1)
        .mount(&h.server)
        .await;
    verdict::replay_pending(&client, &h.store, &h.config)
        .await
        .unwrap();
    let delivered = h
        .store
        .local_reports()
        .get_rich(&identity())
        .unwrap()
        .unwrap();
    assert_eq!(delivered.delivery, FullDelivery::FullyDelivered);
    assert_eq!(delivered.report_json, stored.report_json);
}

#[tokio::test]
async fn rich_ack_loss_replays_exact_document_and_rejects_wrong_ack_identity() {
    use dump_analyzer::state::FullDelivery;
    let h = harness().await;
    let (stored, compact) = prepare_rich(&h);
    let v2 = format!("/api/v2/dumps/{DUMP_ID}/analyses");
    Mock::given(method("POST"))
        .and(path(&v2))
        .respond_with(ResponseTemplate::new(503))
        .mount(&h.server)
        .await;
    let client = LedgerClient::new(&h.config).unwrap();
    assert!(
        verdict::submit(&client, &h.store, &identity(), &compact)
            .await
            .is_err()
    );
    assert_eq!(
        h.store
            .local_reports()
            .get_rich(&identity())
            .unwrap()
            .unwrap()
            .delivery,
        FullDelivery::PendingFull
    );
    h.server.reset().await;
    Mock::given(method("POST"))
        .and(path(&v2))
        .respond_with(ResponseTemplate::new(200).set_body_json(rich_v2_ack(&compact, &stored)))
        .expect(1)
        .mount(&h.server)
        .await;
    verdict::replay_pending(&client, &h.store, &h.config)
        .await
        .unwrap();
    let request = h.server.received_requests().await.unwrap().pop().unwrap();
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["reportJson"], stored.report_json);
    assert_eq!(body["reportDigest"], stored.digest);
    assert_eq!(
        h.store.jobs().phase_of(&identity()).unwrap(),
        Some(JobPhase::Done)
    );
    h.server.reset().await;
    let mut wrong = rich_v2_ack(&compact, &stored);
    wrong["inputSha256"] = json!("b".repeat(64));
    Mock::given(method("POST"))
        .and(path(&v2))
        .respond_with(ResponseTemplate::new(200).set_body_json(wrong))
        .mount(&h.server)
        .await;
    assert!(matches!(
        client.post_rich_analysis(&stored, &compact).await,
        Err(AnalyzerError::Integrity(_))
    ));
}

#[tokio::test]
async fn rich_remote_read_checks_digest_and_preserves_document() {
    let h = harness().await;
    let (stored, compact) = prepare_rich(&h);
    let endpoint = format!("/api/v2/dumps/{DUMP_ID}/analyses/analysis_01JABC001");
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(rich_v2_ack(&compact, &stored)))
        .mount(&h.server)
        .await;
    let client = LedgerClient::new(&h.config).unwrap();
    assert_eq!(
        client
            .get_rich_report(DUMP_ID, "analysis_01JABC001")
            .await
            .unwrap(),
        stored.report
    );
    h.server.reset().await;
    let mut invalid_digest = rich_v2_ack(&compact, &stored);
    invalid_digest["reportDigest"] = json!("b".repeat(64));
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(invalid_digest))
        .mount(&h.server)
        .await;
    assert!(matches!(
        client.get_rich_report(DUMP_ID, "analysis_01JABC001").await,
        Err(AnalyzerError::Integrity(_))
    ));
}

#[tokio::test]
async fn rich_prepare_rejects_conflicting_fresh_capture_without_hiding_it() {
    let h = harness().await;
    let (original, _) = prepare_rich(&h);
    let mut changed_capture = original.report.capture.clone();
    changed_capture
        .completeness
        .omissions
        .push("Different evidence from a concurrent run".into());
    let changed = RunOutput {
        outcome: original.report.outcome,
        summary: original.report.summary.clone(),
        facts: json!({}),
        capture: Some(changed_capture),
    };
    let result = verdict::prepare_report(
        &h.store,
        &identity(),
        &changed,
        &h.config,
        dump_analyzer::state::ReportHandoff::Scheduled,
    );
    assert!(
        matches!(result, Err(AnalyzerError::Integrity(_))),
        "fresh contradictory output must be an explicit conflict"
    );
    assert_eq!(
        h.store.local_reports().get_rich(&identity()).unwrap(),
        Some(original)
    );
    assert_eq!(
        h.store.jobs().phase_of(&identity()).unwrap(),
        Some(JobPhase::Reporting)
    );
}

#[tokio::test]
async fn rich_terminal_v1_fallback_abandons_full_delivery_and_settles_queue() {
    use dump_analyzer::state::FullDelivery;
    for (status, code, expected) in [
        (400, "invalid_request", JobPhase::Failed),
        (404, "not_found", JobPhase::Dropped),
        (410, "gone", JobPhase::Dropped),
        (409, "conflict", JobPhase::Failed),
    ] {
        let h = harness().await;
        let (_, compact) = prepare_rich(&h);
        // v2 is absent; v1 exists but permanently rejects this report.
        Mock::given(method("POST"))
            .and(path(analyses_path()))
            .respond_with(ResponseTemplate::new(status).set_body_json(error_envelope(code)))
            .expect(1)
            .mount(&h.server)
            .await;
        let client = LedgerClient::new(&h.config).unwrap();
        verdict::submit(&client, &h.store, &identity(), &compact)
            .await
            .unwrap();
        assert_eq!(
            h.store
                .local_reports()
                .get_rich(&identity())
                .unwrap()
                .unwrap()
                .delivery,
            FullDelivery::Abandoned,
            "status {status}"
        );
        assert!(
            h.store.local_reports().pending_full().unwrap().is_empty(),
            "status {status}"
        );
        assert_eq!(
            h.store.jobs().phase_of(&identity()).unwrap(),
            Some(expected),
            "status {status}"
        );
        assert!(
            h.store.jobs().work_queue().unwrap().is_empty(),
            "status {status}"
        );
    }
}
