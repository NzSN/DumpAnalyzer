use dump_analyzer::assessment::{assess, validate};
use dump_analyzer::report::CauseStatus;
use dump_analyzer::runner::capture_triage;
const LOG: &str = include_str!("fixtures/report-v2/marked-av.log");
#[test]
fn direct_mechanism_proof_keeps_underlying_cause_unknown() {
    let capture = capture_triage(LOG);
    assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
    assert_eq!(capture.root_cause.mechanism.status, CauseStatus::Confirmed);
    assert!(!capture.root_cause.next_checks.is_empty());
    validate(&capture).unwrap();
}
#[test]
fn plausible_invalid_origin_with_real_evidence_ids_is_rejected() {
    let mut capture = capture_triage(LOG);
    capture.root_cause.status = CauseStatus::Confirmed;
    capture.root_cause.conclusion = "Use-after-free caused the crash".into();
    capture.root_cause.evidence_refs = vec!["exception".into(), "context".into(), "stack".into()];
    capture.root_cause.rule_id = Some("model-says-source-confirmed".into());
    assert!(validate(&capture).is_err());
}
#[test]
fn changed_register_or_false_mechanism_defeats_confirmation() {
    let mut capture = capture_triage(LOG);
    capture
        .context
        .registers
        .insert("rcx".into(), "0x1234".into());
    assert!(validate(&capture).is_err());
    capture.root_cause = assess(&capture);
    assert_eq!(capture.root_cause.mechanism.status, CauseStatus::Unknown);
    validate(&capture).unwrap();
    capture.root_cause.mechanism.status = CauseStatus::Confirmed;
    capture.root_cause.mechanism.description = "The caller freed this object".into();
    assert!(validate(&capture).is_err());
}
#[test]
fn nonexistent_assessment_reference_is_rejected() {
    let mut capture = capture_triage(LOG);
    capture
        .root_cause
        .evidence_refs
        .push("invented-command".into());
    assert!(validate(&capture).is_err());
}
