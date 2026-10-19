use dump_analyzer::report::*;
use dump_analyzer::types::{JobIdentity, ReportOutcome, RunOutput};

fn document() -> CrashReportV2 {
    let identity = JobIdentity {
        dump_id: "dump_report_fixture".into(),
        input_sha256: "a".repeat(64),
        kind: "triage".into(),
        analyzer_version: "0.2.0".into(),
    };
    let capture = ReportCapture {
        evidence: vec![Evidence {
            id: "exception".into(),
            command: ".exr -1".into(),
            status: CaptureStatus::Present,
            text: "ExceptionCode: c0000005".into(),
            ..Default::default()
        }],
        exception: ExceptionRecord {
            status: CaptureStatus::Present,
            code: Some("0xc0000005".into()),
            address: Some("0xffffffffffffffff".into()),
            parameters: vec!["0x0".into(), "0xffffffffffffffff".into()],
            parameter_count: Some(2),
            evidence_refs: vec!["exception".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    CrashReportV2::from_output(
        &identity,
        "dump-analyzer",
        &RunOutput {
            outcome: ReportOutcome::Completed,
            summary: "A bounded fixture".into(),
            facts: serde_json::json!({}),
            capture: Some(capture),
        },
    )
    .unwrap()
}

#[test]
fn canonical_roundtrip_keeps_required_sections_and_64_bit_precision() {
    let report = document();
    let json = report.canonical_json().unwrap();
    let decoded: CrashReportV2 = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, report);
    decoded.validate().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["exception"]["parameters"][1], "0xffffffffffffffff");
    for section in [
        "exception",
        "context",
        "stack",
        "symbols",
        "rootCause",
        "evidence",
        "completeness",
    ] {
        assert!(value.get(section).is_some(), "{section}");
    }
    assert_eq!(report.digest().unwrap(), digest_json(&json));
    assert_eq!(json, decoded.canonical_json().unwrap());
}

#[test]
fn compact_projection_is_bound_and_cannot_mutate_canonical_evidence() {
    let mut report = document();
    report.capture.evidence[0].text = "long retained evidence\n".repeat(300);
    let before = report.canonical_json().unwrap();
    let compact = report.compact_output().unwrap();
    assert!(before.len() > 4096);
    assert!(compact.facts.to_string().len() < 4096);
    assert_eq!(compact.facts["reportId"], report.report_id);
    assert_eq!(compact.facts["reportDigest"], report.digest().unwrap());
    assert_eq!(before, report.canonical_json().unwrap());
}

#[test]
fn identity_evidence_and_symbol_claims_are_checked() {
    let mut report = document();
    report
        .capture
        .exception
        .evidence_refs
        .push("fabricated".into());
    assert!(report.validate().is_err());
    let mut report = document();
    report.capture.root_cause.status = CauseStatus::Confirmed;
    report
        .capture
        .root_cause
        .evidence_refs
        .push("exception".into());
    assert!(report.validate().is_err());
    let mut report = document();
    report.capture.stack.frames.push(StackFrame {
        module: Some("app".into()),
        resolution: SymbolQuality::Matched,
        ..Default::default()
    });
    assert!(report.validate().is_err());
    let mut report = document();
    report.capture.exception.address = Some("18446744073709551615".into());
    assert!(report.validate().is_err());
    let mut report = document();
    report.identity.analyzer_version = "0.3.0".into();
    assert!(report.validate().is_err());
}

#[test]
fn canonical_budget_failure_is_explicit() {
    let mut report = document();
    report.capture.evidence[0].text = "x".repeat(MAX_SECTION_BYTES + 1);
    assert!(report.validate().is_err());
    let mut report = document();
    report.capture.root_cause.conclusion = "x".repeat(MAX_REPORT_BYTES);
    assert!(report.validate().is_err());
}

#[test]
fn flattened_report_contract_rejects_unknown_root_and_nested_fields() {
    let mut value = serde_json::to_value(document()).unwrap();
    value["unexpectedRootField"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CrashReportV2>(value).is_err());
    let mut value = serde_json::to_value(document()).unwrap();
    value["exception"]["unexpectedExceptionField"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CrashReportV2>(value).is_err());
}

#[test]
fn actual_windows_canary_documents_preserve_qualified_and_missing_evidence() {
    let matching: CrashReportV2 = serde_json::from_str(include_str!(
        "fixtures/report-v2/qualification/actual-matching-report.json"
    ))
    .unwrap();
    matching.validate().unwrap();
    assert_eq!(
        matching.capture.exception.code.as_deref(),
        Some("0xc0000005")
    );
    assert_eq!(matching.capture.stack.frames.len(), 5);
    assert_eq!(
        matching.capture.stack.frames[0].function.as_deref(),
        Some("ReadNull")
    );
    assert_eq!(matching.capture.stack.frames[0].source_line, Some(12));
    assert_eq!(
        matching.capture.stack.frames[0].resolution,
        SymbolQuality::Matched
    );
    assert!(
        matching.capture.stack.frames[1]
            .instruction_pointer
            .is_none()
    );
    assert_eq!(matching.capture.root_cause.status, CauseStatus::Unknown);
    let wrong: CrashReportV2 = serde_json::from_str(include_str!(
        "fixtures/report-v2/qualification/actual-mismatched-report.json"
    ))
    .unwrap();
    wrong.validate().unwrap();
    assert_eq!(
        wrong.capture.exception.parameters,
        matching.capture.exception.parameters
    );
    assert!(
        wrong
            .capture
            .stack
            .frames
            .iter()
            .filter(|f| f.module.as_deref() == Some("null_read"))
            .all(|f| f.resolution != SymbolQuality::Matched && f.source_line.is_none())
    );
}
