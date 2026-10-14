//! Wire-type tests (task A1): exact design-doc shapes as fixtures, strict
//! decode, bound enforcement, and round-trip encode/decode identity.

use serde::Serialize;
use serde::de::DeserializeOwned;

use dump_analyzer::types::{AnalyzerError, ReportOutcome};
use dump_analyzer::wire::{
    ActivityItem, AnalysisReport, AnalysisReportSubmission, Analyzer, CoverageKind, DumpCaseRef,
    DumpCatalogEntry, DumpCatalogQuery, DumpCatalogResponse, DumpDetail, DumpPhase, ErrorEnvelope,
    EventFeedEntry, EventFeedParams, EventFeedResponse, MAX_ACTIVITY_ACTION_CHARS,
    MAX_ACTIVITY_ITEMS, MAX_ACTIVITY_OUTCOME_CHARS, MAX_ARCHITECTURE_CHARS,
    MAX_CANONICAL_DECIMAL_DIGITS, MAX_CASE_TITLE_CHARS, MAX_CATALOG_ITEMS, MAX_CURSOR_CHARS,
    MAX_DEBUG_FILE_CHARS, MAX_DEBUG_ID_CHARS, MAX_EVENT_DETAIL_LENGTH, MAX_EVENT_FEED_ITEMS,
    MAX_EVENT_PAGE_LIMIT, MAX_INSPECTION_ERROR_CHARS, MAX_MODULE_COVERAGE_ITEMS,
    MAX_MODULE_NAME_CHARS, MAX_ORIGINAL_NAME_CHARS, MAX_SAFE_INTEGER, ModuleSymbolCoverage,
    ModuleSymbolStatus, SymbolCoverage, ValidationState,
};

/// Canonical valid sha256 (64 lowercase hex characters).
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// `DumpCatalogEntry` aligned with dump-ledger's `catalog.test.ts` full
/// fixture: every optional inspector fact present, canonical forms.
const CATALOG_ENTRY_FULL: &str = r#"{
  "dumpId": "dump_01JTEST0000000000000000000",
  "caseId": "case_01JTEST0000000000000000000",
  "customerId": "customer_01JTEST0000000000000000000",
  "phase": "available",
  "validation": "valid",
  "originalName": "crash.dmp",
  "byteSize": "73400320",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "receivedAt": "2026-01-15T10:30:00.123Z",
  "availableAt": "2026-01-15T10:31:00.123Z",
  "purgeAt": "2026-02-14T10:30:00.123Z",
  "architecture": "x64",
  "exceptionCode": 3221225477,
  "exceptionAddress": "140698920429645",
  "symbolCoverage": { "present": 12, "missing": 3, "unidentified": 1 }
}"#;

/// `DumpCatalogEntry` aligned with dump-ledger's `catalog.test.ts` minimal
/// fixture: nullable keys present as null, inspector facts absent.
const CATALOG_ENTRY_NULLABLE: &str = r#"{
  "dumpId": "dump_01JTEST0000000000000000001",
  "caseId": "case_01JTEST0000000000000000000",
  "customerId": "customer_01JTEST0000000000000000000",
  "phase": "receiving",
  "validation": "not-checked",
  "originalName": "pending.dmp",
  "byteSize": null,
  "sha256": null,
  "receivedAt": "2026-01-15T10:30:00.123Z",
  "availableAt": null,
  "purgeAt": null,
  "symbolCoverage": { "present": 0, "missing": 0, "unidentified": 0 }
}"#;

/// `EventFeedResponse` exactly as shaped in the design's "Event feed" section:
/// `nextCursor` always present, nullable ids, object `detail`.
const EVENT_FEED: &str = r#"{
  "events": [
    {
      "cursor": "0000000000000042",
      "eventId": "event_01JABC001",
      "occurredAt": "2026-10-13T02:05:30.250Z",
      "action": "SealUpload",
      "customerId": "customer_01JAA0XYZ",
      "caseId": "case_01JAB0XYZ",
      "dumpId": "dump_01JABCXYZ",
      "detail": { "byteSize": "1073741824", "outcome": "sealed" }
    },
    {
      "cursor": "0000000000000043",
      "eventId": "event_01JABC002",
      "occurredAt": "2026-10-13T02:06:00.000Z",
      "action": "FinishPurge",
      "customerId": null,
      "caseId": null,
      "dumpId": "dump_02",
      "detail": {}
    }
  ],
  "nextCursor": "0000000000000043"
}"#;

/// A single `EventFeedEntry` (first row of [`EVENT_FEED`]) for standalone
/// round-trip coverage of the entry type itself.
const EVENT_ENTRY_FIRST: &str = r#"{
  "cursor": "0000000000000042",
  "eventId": "event_01JABC001",
  "occurredAt": "2026-10-13T02:05:30.250Z",
  "action": "SealUpload",
  "customerId": "customer_01JAA0XYZ",
  "caseId": "case_01JAB0XYZ",
  "dumpId": "dump_01JABCXYZ",
  "detail": { "byteSize": "1073741824", "outcome": "sealed" }
}"#;

/// Server-side `AnalysisReport` as shaped in the design's "Wire shape".
const ANALYSIS_REPORT: &str = r#"{
  "analysisId": "analysis_01JABC001",
  "dumpId": "dump_01JABCXYZ",
  "analyzer": { "name": "dump-analyzer", "version": "0.1.0" },
  "kind": "triage",
  "inputSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "createdAt": "2026-10-13T03:30:00.000Z",
  "outcome": "completed",
  "summary": "Access violation writing location 0x0000000000000000",
  "facts": { "exceptionCode": 3221225477, "faultingModule": "renderer.dll" },
  "duplicateOf": null
}"#;

/// Minimal server-side report: optional `facts`/`duplicateOf` absent.
const ANALYSIS_REPORT_MINIMAL: &str = r#"{
  "analysisId": "analysis_02",
  "dumpId": "dump_02",
  "analyzer": { "name": "dump-analyzer", "version": "0.1.0" },
  "kind": "triage",
  "inputSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "createdAt": "2026-10-13T03:31:00.000Z",
  "outcome": "failed",
  "summary": "CDB could not open the dump"
}"#;

/// `POST /api/v1/dumps/:dumpId/analyses` body: no server-assigned fields.
const SUBMISSION: &str = r#"{
  "analyzer": { "name": "dump-analyzer", "version": "0.1.0" },
  "kind": "triage",
  "inputSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "outcome": "failed",
  "summary": "CDB could not open the dump",
  "facts": { "stderr": "The dump file is corrupt" }
}"#;

/// Error envelope exactly as shaped in `http-api.md` section Errors.
const ERROR_ENVELOPE: &str = r#"{
  "error": {
    "code": "invalid_request",
    "message": "sha256 does not match the dump's sealed hash",
    "retryable": false
  }
}"#;

fn decode<T: DeserializeOwned>(json: &str) -> T {
    match serde_json::from_str(json) {
        Ok(value) => value,
        Err(error) => panic!("decode failed: {error}\ninput: {json}"),
    }
}

fn encode<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("encode must succeed")
}

/// Decodes, re-encodes, decodes again, and asserts identity in both directions.
fn round_trip<T>(json: &str) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
{
    let value: T = decode(json);
    let encoded = encode(&value);
    let decoded_again: T = decode(&encoded);
    assert_eq!(value, decoded_again, "round trip lost identity");
    assert_eq!(encoded, encode(&decoded_again), "re-encode drifted");
    value
}

fn catalog_value(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("fixture must be JSON")
}

fn analyzer() -> Analyzer {
    Analyzer {
        name: "dump-analyzer".to_string(),
        version: "0.1.0".to_string(),
    }
}

fn submission_with(
    summary: String,
    kind: String,
) -> Result<AnalysisReportSubmission, AnalyzerError> {
    AnalysisReportSubmission::new(
        analyzer(),
        kind,
        SHA256.to_string(),
        ReportOutcome::Completed,
        summary,
        None,
        None,
    )
}

// ---------------------------------------------------------------------------
// Deliverable 4a: design-doc shapes as fixtures, round-trip identity.
// ---------------------------------------------------------------------------

#[test]
fn wire_catalog_entry_full_fixture_round_trips() {
    let entry: DumpCatalogEntry = round_trip(CATALOG_ENTRY_FULL);
    assert_eq!(entry.dump_id, "dump_01JTEST0000000000000000000");
    assert_eq!(entry.case_id, "case_01JTEST0000000000000000000");
    assert_eq!(entry.customer_id, "customer_01JTEST0000000000000000000");
    assert_eq!(entry.phase, DumpPhase::Available);
    assert_eq!(entry.validation, ValidationState::Valid);
    assert_eq!(entry.original_name, "crash.dmp");
    assert_eq!(entry.byte_size.as_deref(), Some("73400320"));
    assert_eq!(entry.sha256.as_deref(), Some(SHA256));
    assert_eq!(entry.received_at, "2026-01-15T10:30:00.123Z");
    assert_eq!(
        entry.available_at.as_deref(),
        Some("2026-01-15T10:31:00.123Z")
    );
    assert_eq!(entry.purge_at.as_deref(), Some("2026-02-14T10:30:00.123Z"));
    assert_eq!(entry.architecture.as_deref(), Some("x64"));
    assert_eq!(entry.exception_code, Some(3221225477));
    assert_eq!(entry.exception_address.as_deref(), Some("140698920429645"));
    assert_eq!(
        entry.symbol_coverage,
        SymbolCoverage {
            present: 12,
            missing: 3,
            unidentified: 1,
        }
    );
    entry.validate().expect("fixture entry must validate");
    let encoded = encode(&entry);
    assert!(
        encoded.contains("\"symbolCoverage\":{\"present\":12"),
        "{encoded}"
    );
    assert!(
        encoded.contains("\"exceptionCode\":3221225477"),
        "{encoded}"
    );
}

#[test]
fn wire_catalog_entry_nullable_fixture_round_trips() {
    let entry: DumpCatalogEntry = round_trip(CATALOG_ENTRY_NULLABLE);
    assert_eq!(entry.phase, DumpPhase::Receiving);
    assert_eq!(entry.validation, ValidationState::NotChecked);
    assert_eq!(entry.byte_size, None);
    assert_eq!(entry.sha256, None);
    assert_eq!(entry.received_at, "2026-01-15T10:30:00.123Z");
    assert_eq!(entry.available_at, None);
    assert_eq!(entry.purge_at, None);
    assert_eq!(entry.architecture, None);
    assert_eq!(entry.exception_code, None);
    assert_eq!(entry.exception_address, None);
    let encoded = encode(&entry);
    assert!(
        encoded.contains("\"byteSize\":null"),
        "null must stay explicit: {encoded}"
    );
    assert!(encoded.contains("\"sha256\":null"), "{encoded}");
    assert!(encoded.contains("\"availableAt\":null"), "{encoded}");
    assert!(encoded.contains("\"purgeAt\":null"), "{encoded}");
    assert!(
        !encoded.contains("architecture"),
        "absent option must stay absent: {encoded}"
    );
}

#[test]
fn wire_catalog_response_round_trips_with_and_without_cursor() {
    let with_cursor = format!(
        r#"{{ "dumps": [{CATALOG_ENTRY_FULL}], "nextCursor": "eyJyZWNlaXZlZEF0IjoiMjAyNi0xMC0xMyJ9" }}"#
    );
    let response: DumpCatalogResponse = round_trip(&with_cursor);
    assert_eq!(response.dumps.len(), 1);
    assert_eq!(
        response.next_cursor.as_deref(),
        Some("eyJyZWNlaXZlZEF0IjoiMjAyNi0xMC0xMyJ9")
    );
    response.validate().expect("fixture response must validate");

    let without_cursor = format!(r#"{{ "dumps": [{CATALOG_ENTRY_NULLABLE}] }}"#);
    let response: DumpCatalogResponse = round_trip(&without_cursor);
    assert_eq!(response.next_cursor, None);
    let encoded = encode(&response);
    assert!(
        !encoded.contains("nextCursor"),
        "absent cursor must not be emitted: {encoded}"
    );

    // An explicit null is rejected for the optional page cursor: the
    // contract's `optional()` only skips absent keys.
    assert!(
        serde_json::from_str::<DumpCatalogResponse>(r#"{ "dumps": [], "nextCursor": null }"#)
            .is_err()
    );
}

#[test]
fn wire_catalog_page_fixture_round_trips() {
    let page = format!(
        r#"{{ "dumps": [{CATALOG_ENTRY_FULL}, {CATALOG_ENTRY_NULLABLE}], "nextCursor": "keyset-cursor" }}"#
    );
    let response: DumpCatalogResponse = round_trip(&page);
    assert_eq!(response.dumps.len(), 2);
    assert_eq!(response.dumps[0].phase, DumpPhase::Available);
    assert_eq!(response.dumps[1].phase, DumpPhase::Receiving);
    assert_eq!(response.next_cursor.as_deref(), Some("keyset-cursor"));
    response.validate().expect("page must validate");

    let minimal_page = format!(r#"{{ "dumps": [{CATALOG_ENTRY_NULLABLE}] }}"#);
    let response: DumpCatalogResponse = round_trip(&minimal_page);
    assert_eq!(response.dumps.len(), 1);
    assert_eq!(response.next_cursor, None);
}

#[test]
fn wire_catalog_entry_requires_nullable_keys() {
    // The contract requires the key even when the value is null.
    for key in ["byteSize", "sha256", "availableAt", "purgeAt"] {
        let mut value = catalog_value(CATALOG_ENTRY_NULLABLE);
        assert!(
            value
                .as_object_mut()
                .expect("object fixture")
                .remove(key)
                .is_some(),
            "{key} must be present in the fixture"
        );
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "an absent {key} must be rejected"
        );
    }
    // The same keys accept an explicit null.
    for key in ["byteSize", "sha256", "availableAt", "purgeAt"] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value[key] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_ok(),
            "{key} null must decode"
        );
    }
    // receivedAt is required and non-nullable.
    let mut absent = catalog_value(CATALOG_ENTRY_FULL);
    assert!(
        absent
            .as_object_mut()
            .expect("object fixture")
            .remove("receivedAt")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpCatalogEntry>(absent).is_err());
    let mut null = catalog_value(CATALOG_ENTRY_FULL);
    null["receivedAt"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<DumpCatalogEntry>(null).is_err());
}

#[test]
fn wire_catalog_entry_rejects_null_optionals() {
    // `optional()` in the contract only skips absent keys; an explicit null
    // is decoded (and rejected) like any other present value.
    for key in ["architecture", "exceptionCode", "exceptionAddress"] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value[key] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{key} null must be rejected"
        );
    }
    let entry: DumpCatalogEntry = decode(CATALOG_ENTRY_NULLABLE);
    assert_eq!(entry.architecture, None);
    assert_eq!(entry.exception_code, None);
    assert_eq!(entry.exception_address, None);
}

#[test]
fn wire_catalog_entry_vocabulary_is_closed() {
    for phase in [
        "receiving",
        "sealed",
        "quarantined",
        "available",
        "rejected",
        "deleting",
        "deleted",
    ] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value["phase"] = serde_json::json!(phase);
        let entry: DumpCatalogEntry = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("phase {phase:?}: {error}"));
        assert_eq!(encode(&entry.phase), format!("\"{phase}\""));
        assert_eq!(entry.phase.as_str(), phase);
    }
    for state in ["not-checked", "valid", "invalid", "transfer-failed"] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value["validation"] = serde_json::json!(state);
        let entry: DumpCatalogEntry = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("validation {state:?}: {error}"));
        assert_eq!(encode(&entry.validation), format!("\"{state}\""));
        assert_eq!(entry.validation.as_str(), state);
    }
    for (key, invalid) in [("phase", "uploading"), ("validation", "ok")] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value[key] = serde_json::json!(invalid);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{key}={invalid:?} must be rejected"
        );
    }
}

#[test]
fn wire_catalog_entry_as_str_matches_serde() {
    // `as_str` feeds the query serializer; pin it to the serde spelling.
    for phase in [
        DumpPhase::Receiving,
        DumpPhase::Sealed,
        DumpPhase::Quarantined,
        DumpPhase::Available,
        DumpPhase::Rejected,
        DumpPhase::Deleting,
        DumpPhase::Deleted,
    ] {
        assert_eq!(encode(&phase), format!("\"{}\"", phase.as_str()));
    }
    for state in [
        ValidationState::NotChecked,
        ValidationState::Valid,
        ValidationState::Invalid,
        ValidationState::TransferFailed,
    ] {
        assert_eq!(encode(&state), format!("\"{}\"", state.as_str()));
    }
}

#[test]
fn wire_catalog_entry_identifier_rules() {
    let mut at_bound = catalog_value(CATALOG_ENTRY_FULL);
    at_bound["dumpId"] = serde_json::json!("a".repeat(128));
    assert!(serde_json::from_value::<DumpCatalogEntry>(at_bound).is_ok());

    let reject = [
        ("dumpId", serde_json::json!("a".repeat(129))),
        ("dumpId", serde_json::json!("")),
        ("dumpId", serde_json::json!("dump id")),
        ("dumpId", serde_json::json!("dump\u{feff}id")),
        ("caseId", serde_json::json!("")),
        ("caseId", serde_json::json!("two words")),
        ("customerId", serde_json::json!("customer\nid")),
    ];
    for (key, bad) in reject {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value[key] = bad.clone();
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{key}={bad:?} must be rejected"
        );
    }
}

#[test]
fn wire_catalog_entry_canonical_timestamp_rules() {
    for bad in [
        "now",
        "2026-01-15",
        "2026-01-15T10:30:00Z",
        "2026-01-15T10:30:00+00:00",
        "2026-02-30T00:00:00.000Z",
        "2026-13-01T00:00:00.000Z",
    ] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value["receivedAt"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "receivedAt={bad:?} must be rejected"
        );
    }
    for key in ["availableAt", "purgeAt"] {
        let mut malformed = catalog_value(CATALOG_ENTRY_FULL);
        malformed[key] = serde_json::json!("2026-01-15T10:31:00Z");
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(malformed).is_err(),
            "{key} must reject a non-canonical timestamp"
        );
        let mut null = catalog_value(CATALOG_ENTRY_FULL);
        null[key] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(null).is_ok(),
            "{key} null must decode"
        );
    }
}

#[test]
fn wire_catalog_entry_canonical_decimal_rules() {
    let forty_digits = "1".repeat(MAX_CANONICAL_DECIMAL_DIGITS);
    let forty_one_digits = "1".repeat(MAX_CANONICAL_DECIMAL_DIGITS + 1);
    for key in ["byteSize", "exceptionAddress"] {
        for good in ["0", "73400320", forty_digits.as_str()] {
            let mut value = catalog_value(CATALOG_ENTRY_FULL);
            value[key] = serde_json::json!(good);
            assert!(
                serde_json::from_value::<DumpCatalogEntry>(value).is_ok(),
                "{key}={good:?} must decode"
            );
        }
        for bad in [
            "",
            "007",
            "-5",
            "+5",
            "1.5",
            "1e3",
            "0x7ff6",
            " 5",
            "5 ",
            forty_one_digits.as_str(),
        ] {
            let mut value = catalog_value(CATALOG_ENTRY_FULL);
            value[key] = serde_json::json!(bad);
            assert!(
                serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
                "{key}={bad:?} must be rejected as non-canonical"
            );
        }
    }

    let mut number = catalog_value(CATALOG_ENTRY_FULL);
    number["exceptionAddress"] = serde_json::json!(140_698_920_429_645i64);
    assert!(serde_json::from_value::<DumpCatalogEntry>(number).is_err());
}

#[test]
fn wire_catalog_entry_text_bounds() {
    // originalName: text({max: 1024}); architecture: optional text({max: 64}).
    let mut at_bound = catalog_value(CATALOG_ENTRY_FULL);
    at_bound["originalName"] = serde_json::json!("n".repeat(MAX_ORIGINAL_NAME_CHARS));
    at_bound["architecture"] = serde_json::json!("a".repeat(MAX_ARCHITECTURE_CHARS));
    assert!(serde_json::from_value::<DumpCatalogEntry>(at_bound).is_ok());

    for (key, bad) in [
        ("originalName", serde_json::json!("")),
        (
            "originalName",
            serde_json::json!("n".repeat(MAX_ORIGINAL_NAME_CHARS + 1)),
        ),
        ("originalName", serde_json::json!("bad\u{0001}name")),
        ("architecture", serde_json::json!("")),
        (
            "architecture",
            serde_json::json!("a".repeat(MAX_ARCHITECTURE_CHARS + 1)),
        ),
    ] {
        let mut value = catalog_value(CATALOG_ENTRY_FULL);
        value[key] = bad.clone();
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{key}={bad:?} must be rejected"
        );
    }
}

#[test]
fn wire_catalog_symbol_coverage_counter_rules() {
    // counterField: non-negative ECMAScript safe integers.
    let mut at_bound = catalog_value(CATALOG_ENTRY_FULL);
    at_bound["symbolCoverage"]["present"] = serde_json::json!(MAX_SAFE_INTEGER);
    assert!(serde_json::from_value::<DumpCatalogEntry>(at_bound).is_ok());

    let mut over = catalog_value(CATALOG_ENTRY_FULL);
    over["symbolCoverage"]["missing"] = serde_json::json!(MAX_SAFE_INTEGER + 1);
    assert!(serde_json::from_value::<DumpCatalogEntry>(over).is_err());

    let mut fractional = catalog_value(CATALOG_ENTRY_FULL);
    fractional["symbolCoverage"]["present"] = serde_json::json!(1.5);
    assert!(serde_json::from_value::<DumpCatalogEntry>(fractional).is_err());

    let mut incomplete = catalog_value(CATALOG_ENTRY_FULL);
    assert!(
        incomplete["symbolCoverage"]
            .as_object_mut()
            .expect("coverage object")
            .remove("unidentified")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpCatalogEntry>(incomplete).is_err());

    let mut unknown = catalog_value(CATALOG_ENTRY_FULL);
    unknown["symbolCoverage"]["system"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DumpCatalogEntry>(unknown).is_err());

    // validate() maps the bound to Decode for programmatic values.
    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.symbol_coverage.present = MAX_SAFE_INTEGER + 1;
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));
}

#[test]
fn wire_catalog_response_dumps_cap() {
    let entry = catalog_value(CATALOG_ENTRY_NULLABLE);
    let rows = |count: usize| serde_json::Value::Array(vec![entry.clone(); count]);

    let mut maximum = serde_json::json!({ "dumps": [] });
    maximum["dumps"] = rows(MAX_CATALOG_ITEMS);
    let page: DumpCatalogResponse = serde_json::from_value(maximum).expect("4096 rows are allowed");
    assert_eq!(page.dumps.len(), MAX_CATALOG_ITEMS);

    let mut over = serde_json::json!({ "dumps": [] });
    over["dumps"] = rows(MAX_CATALOG_ITEMS + 1);
    assert!(serde_json::from_value::<DumpCatalogResponse>(over).is_err());

    assert!(serde_json::from_str::<DumpCatalogResponse>(r#"{ "dumps": "none" }"#).is_err());
    assert!(serde_json::from_str::<DumpCatalogResponse>(r#"{}"#).is_err());
}

#[test]
fn wire_catalog_response_next_cursor_rules() {
    let cursor = "c".repeat(MAX_CURSOR_CHARS);
    let value = serde_json::json!({ "dumps": [], "nextCursor": cursor });
    assert!(serde_json::from_value::<DumpCatalogResponse>(value).is_ok());

    for bad in [
        serde_json::Value::Null,
        serde_json::json!(""),
        serde_json::json!("c".repeat(MAX_CURSOR_CHARS + 1)),
        serde_json::json!("two words"),
    ] {
        let mut value = serde_json::json!({ "dumps": [] });
        value["nextCursor"] = bad.clone();
        assert!(
            serde_json::from_value::<DumpCatalogResponse>(value).is_err(),
            "nextCursor={bad:?} must be rejected"
        );
    }

    // The length bound counts UTF-16 code units like ECMAScript
    // `String.length`: 128 astral characters are 256 units.
    let astral = serde_json::json!({ "dumps": [], "nextCursor": "\u{1F600}".repeat(128) });
    assert!(serde_json::from_value::<DumpCatalogResponse>(astral).is_ok());
    let astral_over = serde_json::json!({ "dumps": [], "nextCursor": "\u{1F600}".repeat(129) });
    assert!(serde_json::from_value::<DumpCatalogResponse>(astral_over).is_err());

    // The ECMAScript whitespace set includes U+FEFF.
    let bom = serde_json::json!({ "dumps": [], "nextCursor": "abc\u{feff}" });
    assert!(serde_json::from_value::<DumpCatalogResponse>(bom).is_err());

    let page: DumpCatalogResponse = decode(r#"{ "dumps": [] }"#);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn wire_event_feed_fixture_round_trips() {
    let response: EventFeedResponse = round_trip(EVENT_FEED);
    assert_eq!(response.events.len(), 2);
    assert_eq!(response.next_cursor, "0000000000000043");
    let first = &response.events[0];
    assert_eq!(first.cursor, "0000000000000042");
    assert_eq!(first.event_id, "event_01JABC001");
    assert_eq!(first.occurred_at, "2026-10-13T02:05:30.250Z");
    assert_eq!(first.action, "SealUpload");
    assert_eq!(first.customer_id.as_deref(), Some("customer_01JAA0XYZ"));
    assert_eq!(first.case_id.as_deref(), Some("case_01JAB0XYZ"));
    assert_eq!(first.dump_id.as_deref(), Some("dump_01JABCXYZ"));
    assert_eq!(
        first.detail,
        serde_json::json!({ "byteSize": "1073741824", "outcome": "sealed" })
    );
    let second = &response.events[1];
    assert_eq!(second.customer_id, None);
    assert_eq!(second.case_id, None);
    assert_eq!(second.detail, serde_json::json!({}));
    let encoded = encode(second);
    assert!(
        encoded.contains("\"customerId\":null"),
        "null ids stay on the wire: {encoded}"
    );
    response.validate().expect("fixture feed must validate");

    // The feed's nextCursor is always present; a missing key is rejected.
    let missing_cursor = EVENT_FEED.replace(
        "\"nextCursor\": \"0000000000000043\"",
        "\"nextCursorAbsent\": true",
    );
    assert!(serde_json::from_str::<EventFeedResponse>(&missing_cursor).is_err());
}

#[test]
fn wire_event_entry_fixture_round_trips() {
    let entry: EventFeedEntry = round_trip(EVENT_ENTRY_FIRST);
    assert_eq!(entry.cursor, "0000000000000042");
    assert_eq!(entry.action, "SealUpload");
    entry.validate().expect("fixture event must validate");

    // A malformed cursor on a standalone entry is rejected at decode time.
    let bad = EVENT_ENTRY_FIRST.replace("0000000000000042", "bad cursor");
    assert!(serde_json::from_str::<EventFeedEntry>(&bad).is_err());
}

/// Real-shape feed page built from the design's "Event feed" section (the
/// server-side AI2 contract and its test fixtures do not exist yet): intake,
/// seal with outcome, and purge with null customer/case.
const EVENT_FEED_PAGE: &str = r#"{
  "events": [
    {
      "cursor": "0000000000000101",
      "eventId": "event_01JTEST0000000000000000101",
      "occurredAt": "2026-01-15T10:30:00.123Z",
      "action": "BeginUpload",
      "customerId": "customer_01JTEST0000000000000000000",
      "caseId": "case_01JTEST0000000000000000000",
      "dumpId": "dump_01JTEST0000000000000000000",
      "detail": { "grantId": "grant_01JTEST0000000000000000000" }
    },
    {
      "cursor": "0000000000000102",
      "eventId": "event_01JTEST0000000000000000102",
      "occurredAt": "2026-01-15T10:31:00.123Z",
      "action": "SealUpload",
      "customerId": "customer_01JTEST0000000000000000000",
      "caseId": "case_01JTEST0000000000000000000",
      "dumpId": "dump_01JTEST0000000000000000000",
      "detail": { "byteSize": "73400320", "outcome": "sealed" }
    },
    {
      "cursor": "0000000000000103",
      "eventId": "event_01JTEST0000000000000000103",
      "occurredAt": "2026-02-14T10:30:00.123Z",
      "action": "FinishPurge",
      "customerId": null,
      "caseId": null,
      "dumpId": "dump_01JTEST0000000000000000000",
      "detail": { "outcome": "purged" }
    }
  ],
  "nextCursor": "0000000000000103"
}"#;

fn event_value(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("fixture must be JSON")
}

#[test]
fn wire_event_feed_page_fixture_round_trips() {
    let response: EventFeedResponse = round_trip(EVENT_FEED_PAGE);
    assert_eq!(response.events.len(), 3);
    assert_eq!(response.next_cursor, "0000000000000103");
    assert_eq!(response.events[0].action, "BeginUpload");
    assert_eq!(response.events[1].action, "SealUpload");
    assert_eq!(
        response.events[1].detail["outcome"],
        serde_json::json!("sealed")
    );
    assert_eq!(response.events[2].customer_id, None);
    assert_eq!(response.events[2].case_id, None);
    assert_eq!(
        response.events[2].dump_id.as_deref(),
        Some("dump_01JTEST0000000000000000000")
    );
    response.validate().expect("fixture feed must validate");
}

#[test]
fn wire_event_feed_entry_bounds() {
    let base = event_value(EVENT_FEED_PAGE);
    let first = base["events"][0].clone();

    let mutate = |key: &str, value: serde_json::Value| {
        let mut entry = first.clone();
        entry[key] = value;
        entry
    };

    let at_bound = mutate("eventId", serde_json::json!("a".repeat(128)));
    assert!(serde_json::from_value::<EventFeedEntry>(at_bound).is_ok());
    let over = mutate("eventId", serde_json::json!("a".repeat(129)));
    assert!(serde_json::from_value::<EventFeedEntry>(over).is_err());

    for (key, bad) in [
        ("eventId", serde_json::json!("")),
        ("eventId", serde_json::json!("event id")),
        ("occurredAt", serde_json::json!("now")),
        ("occurredAt", serde_json::json!("2026-01-15T10:30:00Z")),
        ("action", serde_json::json!("")),
        (
            "action",
            serde_json::json!("a".repeat(MAX_ACTIVITY_ACTION_CHARS + 1)),
        ),
        ("customerId", serde_json::json!("")),
        ("customerId", serde_json::json!("two words")),
        ("caseId", serde_json::json!("a".repeat(129))),
        ("dumpId", serde_json::json!("dump\u{feff}id")),
    ] {
        let entry = mutate(key, bad.clone());
        assert!(
            serde_json::from_value::<EventFeedEntry>(entry).is_err(),
            "{key}={bad:?} must be rejected"
        );
    }

    // Nullable ids still accept null.
    for key in ["customerId", "caseId", "dumpId"] {
        let entry = mutate(key, serde_json::Value::Null);
        assert!(
            serde_json::from_value::<EventFeedEntry>(entry).is_ok(),
            "{key} null must decode"
        );
    }
}

#[test]
fn wire_event_feed_detail_bound() {
    // `{"note":"<k x's>"}` serializes to k + 11 characters; 4085 + 11 == 4096.
    let at_bound = format!(r#"{{"note":"{}"}}"#, "x".repeat(4085));
    assert_eq!(at_bound.len(), MAX_EVENT_DETAIL_LENGTH);
    let mut entry = event_value(EVENT_FEED_PAGE)["events"][0].clone();
    entry["detail"] = serde_json::from_str(&at_bound).expect("detail JSON");
    assert!(serde_json::from_value::<EventFeedEntry>(entry.clone()).is_ok());

    let over = format!(r#"{{"note":"{}"}}"#, "x".repeat(4086));
    entry["detail"] = serde_json::from_str(&over).expect("detail JSON");
    assert!(serde_json::from_value::<EventFeedEntry>(entry).is_err());

    // `detail` is a JSON object, never a scalar, array, or null.
    for bad in [
        serde_json::json!("plain"),
        serde_json::json!([1, 2, 3]),
        serde_json::Value::Null,
    ] {
        let mut entry = event_value(EVENT_FEED_PAGE)["events"][0].clone();
        entry["detail"] = bad.clone();
        assert!(
            serde_json::from_value::<EventFeedEntry>(entry).is_err(),
            "detail={bad:?} must be rejected"
        );
    }
}

#[test]
fn wire_event_feed_events_cap() {
    let entry = event_value(EVENT_FEED_PAGE)["events"][0].clone();
    let rows = |count: usize| serde_json::Value::Array(vec![entry.clone(); count]);

    let mut maximum = serde_json::json!({ "events": [], "nextCursor": "0000000000000103" });
    maximum["events"] = rows(MAX_EVENT_FEED_ITEMS);
    let page: EventFeedResponse = serde_json::from_value(maximum).expect("4096 rows are allowed");
    assert_eq!(page.events.len(), MAX_EVENT_FEED_ITEMS);

    let mut over = serde_json::json!({ "events": [], "nextCursor": "0000000000000103" });
    over["events"] = rows(MAX_EVENT_FEED_ITEMS + 1);
    assert!(serde_json::from_value::<EventFeedResponse>(over).is_err());

    assert!(serde_json::from_str::<EventFeedResponse>(r#"{ "events": {} }"#).is_err());
    assert!(serde_json::from_str::<EventFeedResponse>(r#"{}"#).is_err());
}

#[test]
fn wire_event_feed_params_serialization() {
    let params = EventFeedParams {
        since: Some("0000000000000042".to_string()),
        actions: Some(vec!["SealUpload".to_string(), "FinishPurge".to_string()]),
        case_id: Some("case_01JTEST0000000000000000000".to_string()),
        limit: Some(MAX_EVENT_PAGE_LIMIT),
    };
    assert_eq!(
        params
            .to_pairs()
            .expect("valid")
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        vec!["since", "actions", "caseId", "limit"]
    );
    assert_eq!(
        params.to_query_string().expect("valid"),
        "since=0000000000000042&actions=SealUpload%2CFinishPurge&\
caseId=case_01JTEST0000000000000000000&limit=500"
    );

    assert_eq!(
        EventFeedParams::default().to_query_string().expect("empty"),
        ""
    );
    let partial = EventFeedParams {
        limit: Some(1),
        ..Default::default()
    };
    assert_eq!(partial.to_query_string().expect("partial"), "limit=1");
}

#[test]
fn wire_event_feed_params_rejects_bad_values() {
    let cases = [
        EventFeedParams {
            since: Some(String::new()),
            ..Default::default()
        },
        EventFeedParams {
            since: Some("with space".to_string()),
            ..Default::default()
        },
        EventFeedParams {
            since: Some("c".repeat(257)),
            ..Default::default()
        },
        EventFeedParams {
            actions: Some(Vec::new()),
            ..Default::default()
        },
        EventFeedParams {
            actions: Some(vec![String::new()]),
            ..Default::default()
        },
        EventFeedParams {
            actions: Some(vec!["a".repeat(MAX_ACTIVITY_ACTION_CHARS + 1)]),
            ..Default::default()
        },
        EventFeedParams {
            actions: Some(vec!["SealUpload,FinishPurge".to_string()]),
            ..Default::default()
        },
        EventFeedParams {
            case_id: Some("two words".to_string()),
            ..Default::default()
        },
        EventFeedParams {
            limit: Some(0),
            ..Default::default()
        },
        EventFeedParams {
            limit: Some(MAX_EVENT_PAGE_LIMIT + 1),
            ..Default::default()
        },
    ];
    for params in cases {
        assert!(
            matches!(params.to_query_string(), Err(AnalyzerError::Decode(_))),
            "{params:?} must be rejected"
        );
        assert!(matches!(params.to_pairs(), Err(AnalyzerError::Decode(_))));
    }

    // Boundary values that the server accepts.
    let accepted = [
        EventFeedParams {
            since: Some("c".repeat(256)),
            ..Default::default()
        },
        EventFeedParams {
            limit: Some(1),
            ..Default::default()
        },
        EventFeedParams {
            limit: Some(MAX_EVENT_PAGE_LIMIT),
            ..Default::default()
        },
        EventFeedParams {
            actions: Some(vec!["RecordAnalysis".to_string()]),
            ..Default::default()
        },
    ];
    for params in accepted {
        assert!(
            params.to_query_string().is_ok(),
            "{params:?} must be accepted"
        );
    }
}

#[test]
fn wire_analysis_report_round_trips_full_and_minimal() {
    let report: AnalysisReport = round_trip(ANALYSIS_REPORT);
    assert_eq!(report.analysis_id, "analysis_01JABC001");
    assert_eq!(report.dump_id, "dump_01JABCXYZ");
    assert_eq!(report.analyzer.name, "dump-analyzer");
    assert_eq!(report.analyzer.version, "0.1.0");
    assert_eq!(report.kind, "triage");
    assert_eq!(report.input_sha256, SHA256);
    assert_eq!(report.created_at, "2026-10-13T03:30:00.000Z");
    assert_eq!(report.outcome, ReportOutcome::Completed);
    assert_eq!(report.duplicate_of, None);
    assert!(report.facts.as_ref().is_some_and(|facts| facts.is_object()));
    report.validate().expect("fixture report must validate");

    let minimal: AnalysisReport = round_trip(ANALYSIS_REPORT_MINIMAL);
    assert_eq!(minimal.outcome, ReportOutcome::Failed);
    assert_eq!(minimal.facts, None);
    assert_eq!(minimal.duplicate_of, None);
    let encoded = encode(&minimal);
    assert!(!encoded.contains("facts"), "{encoded}");
    assert!(!encoded.contains("duplicateOf"), "{encoded}");
    minimal.validate().expect("minimal fixture must validate");
}

#[test]
fn wire_submission_round_trips_without_server_assigned_fields() {
    let submission: AnalysisReportSubmission = round_trip(SUBMISSION);
    assert_eq!(submission.outcome, ReportOutcome::Failed);
    let encoded = encode(&submission);
    for forbidden in ["analysisId", "dumpId", "createdAt"] {
        assert!(
            !encoded.contains(forbidden),
            "{forbidden} is server-assigned and must not be in the POST body: {encoded}"
        );
    }
    assert!(encoded.contains("\"inputSha256\""), "{encoded}");
    assert!(encoded.contains("\"outcome\":\"failed\""), "{encoded}");
}

#[test]
fn wire_error_envelope_round_trips_with_helpers() {
    let envelope: ErrorEnvelope = round_trip(ERROR_ENVELOPE);
    assert_eq!(envelope.code(), "invalid_request");
    assert!(!envelope.retryable());
    assert_eq!(
        envelope.error.message,
        "sha256 does not match the dump's sealed hash"
    );
}

#[test]
fn wire_decoded_fixtures_pass_validate() {
    decode::<DumpCatalogEntry>(CATALOG_ENTRY_FULL)
        .validate()
        .expect("entry");
    decode::<DumpCatalogResponse>(&format!(r#"{{ "dumps": [{CATALOG_ENTRY_FULL}] }}"#))
        .validate()
        .expect("catalog response");
    decode::<EventFeedResponse>(EVENT_FEED)
        .validate()
        .expect("feed");
    decode::<AnalysisReport>(ANALYSIS_REPORT)
        .validate()
        .expect("report");
    decode::<AnalysisReportSubmission>(SUBMISSION)
        .validate()
        .expect("submission");
}

// ---------------------------------------------------------------------------
// Deliverable 4b: unknown fields and wrong types are rejected.
// ---------------------------------------------------------------------------

#[test]
fn wire_unknown_fields_are_rejected() {
    let entry_extra =
        CATALOG_ENTRY_FULL.replace("\"symbolCoverage\"", "\"extra\": 1, \"symbolCoverage\"");
    assert!(serde_json::from_str::<DumpCatalogEntry>(&entry_extra).is_err());

    let nested_extra =
        CATALOG_ENTRY_FULL.replace("\"present\": 12", "\"present\": 12, \"system\": true");
    assert!(serde_json::from_str::<DumpCatalogEntry>(&nested_extra).is_err());

    let response_extra = format!(r#"{{ "dumps": [{CATALOG_ENTRY_NULLABLE}], "unknown": "x" }}"#);
    assert!(serde_json::from_str::<DumpCatalogResponse>(&response_extra).is_err());

    let event_extra = EVENT_FEED.replace(
        "\"action\": \"FinishPurge\"",
        "\"action\": \"FinishPurge\", \"agent\": \"x\"",
    );
    assert!(serde_json::from_str::<EventFeedResponse>(&event_extra).is_err());

    let report_extra = ANALYSIS_REPORT.replace(
        "\"kind\": \"triage\"",
        "\"kind\": \"triage\", \"serverNote\": \"x\"",
    );
    assert!(serde_json::from_str::<AnalysisReport>(&report_extra).is_err());

    let analyzer_extra = ANALYSIS_REPORT.replace(
        "\"name\": \"dump-analyzer\"",
        "\"name\": \"dump-analyzer\", \"digest\": \"x\"",
    );
    assert!(serde_json::from_str::<AnalysisReport>(&analyzer_extra).is_err());

    let submission_extra = SUBMISSION.replace(
        "\"outcome\": \"failed\"",
        "\"outcome\": \"failed\", \"analysisId\": \"x\"",
    );
    assert!(serde_json::from_str::<AnalysisReportSubmission>(&submission_extra).is_err());

    let envelope_extra = ERROR_ENVELOPE.replace(
        "\"retryable\": false",
        "\"retryable\": false, \"trace\": \"x\"",
    );
    assert!(serde_json::from_str::<ErrorEnvelope>(&envelope_extra).is_err());
}

#[test]
fn wire_wrong_types_are_rejected() {
    let base: serde_json::Value = serde_json::from_str(CATALOG_ENTRY_FULL).expect("fixture");

    let mut number_size = base.clone();
    number_size["byteSize"] = serde_json::json!(1073741824);
    assert!(serde_json::from_value::<DumpCatalogEntry>(number_size).is_err());

    let mut string_code = base.clone();
    string_code["exceptionCode"] = serde_json::json!("3221225477");
    assert!(serde_json::from_value::<DumpCatalogEntry>(string_code).is_err());

    let mut overflow_code = base.clone();
    overflow_code["exceptionCode"] = serde_json::json!(4_294_967_296u64);
    assert!(serde_json::from_value::<DumpCatalogEntry>(overflow_code).is_err());

    let mut negative_count = base.clone();
    negative_count["symbolCoverage"]["present"] = serde_json::json!(-1);
    assert!(serde_json::from_value::<DumpCatalogEntry>(negative_count).is_err());

    let mut number_address = base.clone();
    number_address["exceptionAddress"] = serde_json::json!(140703210000001i64);
    assert!(serde_json::from_value::<DumpCatalogEntry>(number_address).is_err());

    let mut missing_required = base.clone();
    assert!(
        missing_required
            .as_object_mut()
            .expect("object fixture")
            .remove("dumpId")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpCatalogEntry>(missing_required).is_err());

    let mut bad_outcome: serde_json::Value = serde_json::from_str(ANALYSIS_REPORT).unwrap();
    bad_outcome["outcome"] = serde_json::json!("unknown");
    assert!(serde_json::from_value::<AnalysisReport>(bad_outcome).is_err());

    let mut array_facts: serde_json::Value = serde_json::from_str(ANALYSIS_REPORT).unwrap();
    array_facts["facts"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<AnalysisReport>(array_facts).is_err());

    let mut string_detail: serde_json::Value = serde_json::from_str(EVENT_FEED).unwrap();
    string_detail["events"][0]["detail"] = serde_json::json!("not an object");
    assert!(serde_json::from_value::<EventFeedResponse>(string_detail).is_err());

    let mut string_retryable: serde_json::Value = serde_json::from_str(ERROR_ENVELOPE).unwrap();
    string_retryable["error"]["retryable"] = serde_json::json!("no");
    assert!(serde_json::from_value::<ErrorEnvelope>(string_retryable).is_err());
}

// ---------------------------------------------------------------------------
// Deliverable 4c: bound violations and malformed values are rejected.
// ---------------------------------------------------------------------------

#[test]
fn wire_sha256_rule_enforced() {
    let base: serde_json::Value = serde_json::from_str(CATALOG_ENTRY_FULL).expect("fixture");
    let candidates = [
        SHA256.to_uppercase(),
        SHA256[..63].to_string(),
        format!("{SHA256}0"),
        "g".repeat(64),
    ];
    for candidate in &candidates {
        let mut value = base.clone();
        value["sha256"] = serde_json::json!(candidate);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "catalog sha256 must reject {candidate}"
        );

        let result = AnalysisReportSubmission::new(
            analyzer(),
            "triage".to_string(),
            candidate.clone(),
            ReportOutcome::Completed,
            "ok".to_string(),
            None,
            None,
        );
        assert!(
            matches!(result, Err(AnalyzerError::Decode(_))),
            "inputSha256 must reject {candidate}"
        );
    }

    // null is allowed on the catalog entry until the dump is sealed
    let mut null_hash = base.clone();
    null_hash["sha256"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<DumpCatalogEntry>(null_hash).is_ok());
}

#[test]
fn wire_summary_bound_counts_chars() {
    // 2000 multi-byte characters are 4000 UTF-8 bytes but within the bound.
    let allowed = "é".repeat(2000);
    let submission = submission_with(allowed, "triage".to_string()).expect("2000 chars is allowed");
    assert_eq!(submission.summary.chars().count(), 2000);
    assert_eq!(submission.summary.len(), 4000);

    let too_long = "é".repeat(2001);
    let result = submission_with(too_long.clone(), "triage".to_string());
    assert!(matches!(result, Err(AnalyzerError::Decode(_))));

    let value = serde_json::json!({
        "analyzer": { "name": "a", "version": "1" },
        "kind": "triage",
        "inputSha256": SHA256,
        "outcome": "completed",
        "summary": too_long,
    });
    assert!(serde_json::from_value::<AnalysisReportSubmission>(value).is_err());
}

#[test]
fn wire_kind_bounds_enforced() {
    let ok = "k".repeat(64);
    assert!(submission_with("ok".to_string(), ok).is_ok());

    for bad in [String::new(), "k".repeat(65), "é".repeat(65)] {
        let result = submission_with("ok".to_string(), bad.clone());
        assert!(
            matches!(result, Err(AnalyzerError::Decode(_))),
            "kind must reject {bad:?}"
        );
    }

    let value = serde_json::json!({
        "analyzer": { "name": "a", "version": "1" },
        "kind": "",
        "inputSha256": SHA256,
        "outcome": "completed",
        "summary": "x",
    });
    assert!(serde_json::from_value::<AnalysisReportSubmission>(value).is_err());
}

#[test]
fn wire_decimal_string_rules() {
    let base: serde_json::Value = serde_json::from_str(CATALOG_ENTRY_FULL).expect("fixture");
    for good in ["0", "1073741824", "18446744073709551616"] {
        let mut value = base.clone();
        value["byteSize"] = serde_json::json!(good);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_ok(),
            "{good:?} is a decimal string"
        );
    }
    for bad in ["", "-1", "+1", "1.5", "1e3", "0x10", " 1", "1 073", "007"] {
        let mut value = base.clone();
        value["byteSize"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{bad:?} is not a decimal string"
        );

        let mut value = base.clone();
        value["exceptionAddress"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<DumpCatalogEntry>(value).is_err(),
            "{bad:?} is not a decimal string"
        );
    }
}

#[test]
fn wire_cursor_bound_and_whitespace() {
    let ok = "c".repeat(256);
    let response = format!(r#"{{ "dumps": [], "nextCursor": "{ok}" }}"#);
    assert!(serde_json::from_str::<DumpCatalogResponse>(&response).is_ok());

    let too_long = "c".repeat(257);
    let response = format!(r#"{{ "dumps": [], "nextCursor": "{too_long}" }}"#);
    assert!(serde_json::from_str::<DumpCatalogResponse>(&response).is_err());

    for bad in ["abc def", "abc\tdef", "abc\ndef"] {
        let value = serde_json::json!({ "dumps": [], "nextCursor": bad });
        assert!(
            serde_json::from_value::<DumpCatalogResponse>(value).is_err(),
            "{bad:?} contains whitespace"
        );
    }

    // Empty cursors are rejected (`min: 1` in the contract).
    let empty_cursor = serde_json::json!({ "dumps": [], "nextCursor": "" });
    assert!(serde_json::from_value::<DumpCatalogResponse>(empty_cursor).is_err());

    // Event entry cursors and the feed's always-present nextCursor follow the
    // same rule.
    let whitespace_cursor = EVENT_FEED.replace("0000000000000043", "ab cd");
    assert!(serde_json::from_str::<EventFeedResponse>(&whitespace_cursor).is_err());

    let mut entry: serde_json::Value = serde_json::from_str(EVENT_FEED).expect("fixture");
    entry["events"][0]["cursor"] = serde_json::json!("c".repeat(257));
    assert!(serde_json::from_value::<EventFeedResponse>(entry).is_err());

    let mut entry: serde_json::Value = serde_json::from_str(EVENT_FEED).expect("fixture");
    entry["events"][0]["cursor"] = serde_json::json!("");
    assert!(serde_json::from_value::<EventFeedResponse>(entry).is_err());
}

#[test]
fn wire_validate_maps_violations_to_decode() {
    let mut submission = submission_with("ok".to_string(), "triage".to_string()).expect("valid");
    submission.kind = String::new();
    assert!(matches!(
        submission.validate(),
        Err(AnalyzerError::Decode(_))
    ));

    let mut submission = submission_with("ok".to_string(), "triage".to_string()).expect("valid");
    submission.summary = "s".repeat(2001);
    assert!(matches!(
        submission.validate(),
        Err(AnalyzerError::Decode(_))
    ));

    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.sha256 = Some("nope".to_string());
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));

    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.received_at = "now".to_string();
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));

    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.byte_size = Some("007".to_string());
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));

    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.case_id = "two words".to_string();
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));

    let mut entry: DumpCatalogEntry = decode(CATALOG_ENTRY_FULL);
    entry.architecture = Some("x".repeat(MAX_ARCHITECTURE_CHARS + 1));
    assert!(matches!(entry.validate(), Err(AnalyzerError::Decode(_))));

    let mut feed: EventFeedResponse = decode(EVENT_FEED);
    feed.events[0].cursor = "has space".to_string();
    assert!(matches!(feed.validate(), Err(AnalyzerError::Decode(_))));
}

// ---------------------------------------------------------------------------
// Deliverable 3: catalog query-params serializer.
// ---------------------------------------------------------------------------

#[test]
fn wire_catalog_query_canonical_pairs() {
    let query = DumpCatalogQuery {
        case_id: Some("case_01JAB0XYZ".to_string()),
        customer_id: Some("customer_01JAA0XYZ".to_string()),
        phase: Some(DumpPhase::Available),
        validation: Some(ValidationState::Valid),
        received_after: Some("2026-10-13T00:00:00.000Z".to_string()),
        received_before: Some("2026-10-14T00:00:00.000Z".to_string()),
        architecture: Some("x64".to_string()),
        exception_code: Some(3221225477),
        sha256: Some(SHA256.to_string()),
        cursor: Some("0000000000000042".to_string()),
    };
    let pairs = query.to_pairs().expect("valid query");
    assert_eq!(
        pairs.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        vec![
            "caseId",
            "customerId",
            "phase",
            "validation",
            "receivedAfter",
            "receivedBefore",
            "architecture",
            "exceptionCode",
            "sha256",
            "cursor",
        ]
    );
    let expected = format!(
        "caseId=case_01JAB0XYZ&customerId=customer_01JAA0XYZ&phase=available&validation=valid\
&receivedAfter=2026-10-13T00%3A00%3A00.000Z&receivedBefore=2026-10-14T00%3A00%3A00.000Z\
&architecture=x64&exceptionCode=3221225477&sha256={SHA256}&cursor=0000000000000042"
    );
    assert_eq!(query.to_query_string().expect("valid query"), expected);
}

#[test]
fn wire_catalog_query_empty_and_partial() {
    assert_eq!(
        DumpCatalogQuery::default()
            .to_query_string()
            .expect("empty"),
        ""
    );
    let query = DumpCatalogQuery {
        phase: Some(DumpPhase::Available),
        exception_code: Some(0),
        ..Default::default()
    };
    assert_eq!(
        query.to_query_string().expect("partial"),
        "phase=available&exceptionCode=0"
    );
}

#[test]
fn wire_catalog_query_rejects_bad_values() {
    let cases = [
        DumpCatalogQuery {
            sha256: Some(SHA256.to_uppercase()),
            ..Default::default()
        },
        DumpCatalogQuery {
            sha256: Some("short".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            cursor: Some("c".repeat(MAX_CURSOR_CHARS + 1)),
            ..Default::default()
        },
        DumpCatalogQuery {
            cursor: Some("with space".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            cursor: Some(String::new()),
            ..Default::default()
        },
        DumpCatalogQuery {
            architecture: Some("a".repeat(MAX_ARCHITECTURE_CHARS + 1)),
            ..Default::default()
        },
        DumpCatalogQuery {
            architecture: Some(String::new()),
            ..Default::default()
        },
        DumpCatalogQuery {
            case_id: Some(String::new()),
            ..Default::default()
        },
        DumpCatalogQuery {
            case_id: Some("two words".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            customer_id: Some("customer\tid".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            received_after: Some(String::new()),
            ..Default::default()
        },
        DumpCatalogQuery {
            received_after: Some("2026-10-13".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            received_before: Some("2026-10-13T00:00:00Z".to_string()),
            ..Default::default()
        },
    ];
    for query in cases {
        assert!(
            matches!(query.to_query_string(), Err(AnalyzerError::Decode(_))),
            "{query:?} must be rejected"
        );
        assert!(matches!(query.to_pairs(), Err(AnalyzerError::Decode(_))));
    }

    // Boundary values that the server's decoder accepts.
    let accepted = [
        DumpCatalogQuery {
            architecture: Some("a".repeat(MAX_ARCHITECTURE_CHARS)),
            ..Default::default()
        },
        DumpCatalogQuery {
            cursor: Some("c".repeat(MAX_CURSOR_CHARS)),
            ..Default::default()
        },
        DumpCatalogQuery {
            case_id: Some("a".repeat(128)),
            ..Default::default()
        },
        DumpCatalogQuery {
            received_after: Some("2026-10-13T00:00:00.000Z".to_string()),
            ..Default::default()
        },
        DumpCatalogQuery {
            phase: Some(DumpPhase::Deleted),
            validation: Some(ValidationState::TransferFailed),
            ..Default::default()
        },
    ];
    for query in accepted {
        assert!(
            query.to_query_string().is_ok(),
            "{query:?} must be accepted"
        );
    }

    // Enum vocabularies serialize to their wire spelling.
    let query = DumpCatalogQuery {
        phase: Some(DumpPhase::Quarantined),
        validation: Some(ValidationState::NotChecked),
        ..Default::default()
    };
    assert_eq!(
        query.to_query_string().expect("valid"),
        "phase=quarantined&validation=not-checked"
    );
}

// ---------------------------------------------------------------------------
// Dump detail (`GET /api/v1/dumps/:dumpId`), shape from
// packages/http-contracts/src/dumps.ts / decode.ts.
// ---------------------------------------------------------------------------

/// Realistic available-dump detail payload: three module rows (present /
/// missing / unidentified) and two activity items (with and without an
/// outcome), exactly the contract's field set.
const DUMP_DETAIL_FULL: &str = r#"{
  "dumpId": "dump_01JABCXYZ",
  "case": { "caseId": "case_01JAB0XYZ", "title": "Renderer crash loop" },
  "phase": "available",
  "originalName": "renderer-crash.dmp",
  "byteSize": "1073741824",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "validation": "valid",
  "coverage": "full-memory-declared",
  "downloadable": true,
  "receivedAt": "2026-10-13T02:00:00.000Z",
  "availableAt": "2026-10-13T02:05:30.250Z",
  "purgeAt": "2026-11-12T02:00:00.000Z",
  "purgedAt": null,
  "inspectionError": null,
  "symbolCoverage": [
    {
      "name": "C:\\Windows\\System32\\ntdll.dll",
      "debugFile": "ntdll.pdb",
      "debugId": "6A0F3E1B2C3D4E5F60718293A4B5C6D71",
      "status": "present",
      "artifactId": "sym_01JABC999",
      "system": true
    },
    {
      "name": "renderer.dll",
      "debugFile": "renderer.pdb",
      "debugId": "1A2B3C4D5E6F708192A3B4C5D6E7F8091",
      "status": "missing",
      "artifactId": null,
      "system": false
    },
    {
      "name": "third_party.dll",
      "debugFile": null,
      "debugId": null,
      "status": "unidentified",
      "artifactId": null,
      "system": false
    }
  ],
  "activity": [
    { "occurredAt": "2026-10-13T02:05:30.250Z", "action": "SealUpload", "outcome": "sealed" },
    { "occurredAt": "2026-10-13T02:00:00.000Z", "action": "BeginUpload" }
  ]
}"#;

/// Sealed dump whose inspection failed: nulls, empty arrays, a bounded
/// `inspectionError`, and a `not-checked` validation state.
const DUMP_DETAIL_INSPECTION_FAILED: &str = r#"{
  "dumpId": "dump_02",
  "case": { "caseId": "case_02", "title": "Upload test" },
  "phase": "sealed",
  "originalName": "minidump.dmp",
  "byteSize": "524288",
  "sha256": null,
  "validation": "not-checked",
  "coverage": null,
  "downloadable": false,
  "receivedAt": "2026-10-13T04:00:00.000Z",
  "availableAt": null,
  "purgeAt": null,
  "purgedAt": null,
  "inspectionError": "Inspector could not parse the minidump header",
  "symbolCoverage": [],
  "activity": [
    { "occurredAt": "2026-10-13T04:01:00.000Z", "action": "SealUpload", "outcome": "rejected" },
    { "occurredAt": "2026-10-13T04:00:00.000Z", "action": "BeginUpload" }
  ]
}"#;

fn detail_value(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("fixture must be JSON")
}

#[test]
fn wire_dump_detail_fixture_round_trips() {
    let detail: DumpDetail = round_trip(DUMP_DETAIL_FULL);
    assert_eq!(detail.dump_id, "dump_01JABCXYZ");
    assert_eq!(detail.case_ref.case_id, "case_01JAB0XYZ");
    assert_eq!(detail.case_ref.title, "Renderer crash loop");
    assert_eq!(detail.phase, DumpPhase::Available);
    assert_eq!(detail.original_name, "renderer-crash.dmp");
    assert_eq!(detail.byte_size.as_deref(), Some("1073741824"));
    assert_eq!(detail.sha256.as_deref(), Some(SHA256));
    assert_eq!(detail.validation, ValidationState::Valid);
    assert_eq!(detail.coverage, Some(CoverageKind::FullMemoryDeclared));
    assert!(detail.downloadable);
    assert_eq!(detail.received_at, "2026-10-13T02:00:00.000Z");
    assert_eq!(
        detail.available_at.as_deref(),
        Some("2026-10-13T02:05:30.250Z")
    );
    assert_eq!(detail.purge_at.as_deref(), Some("2026-11-12T02:00:00.000Z"));
    assert_eq!(detail.purged_at, None);
    assert_eq!(detail.inspection_error, None);

    assert_eq!(detail.symbol_coverage.len(), 3);
    let ntdll = &detail.symbol_coverage[0];
    assert_eq!(
        ntdll.name.as_deref(),
        Some("C:\\Windows\\System32\\ntdll.dll")
    );
    assert_eq!(ntdll.status, ModuleSymbolStatus::Present);
    assert_eq!(ntdll.artifact_id.as_deref(), Some("sym_01JABC999"));
    assert!(ntdll.system);
    assert_eq!(
        detail.symbol_coverage[1].status,
        ModuleSymbolStatus::Missing
    );
    assert_eq!(
        detail.symbol_coverage[2].status,
        ModuleSymbolStatus::Unidentified
    );
    assert_eq!(detail.symbol_coverage[2].debug_file, None);

    assert_eq!(detail.activity.len(), 2);
    assert_eq!(detail.activity[0].action, "SealUpload");
    assert_eq!(detail.activity[0].outcome.as_deref(), Some("sealed"));
    assert_eq!(detail.activity[1].outcome, None);
    detail.validate().expect("fixture must validate");

    let encoded = encode(&detail);
    assert!(encoded.contains("\"case\":{"), "{encoded}");
    assert!(encoded.contains("\"purgedAt\":null"), "{encoded}");
    assert!(encoded.contains("\"inspectionError\":null"), "{encoded}");
    let second_activity = encode(&detail.activity[1]);
    assert!(!second_activity.contains("outcome"), "{second_activity}");
}

#[test]
fn wire_dump_detail_inspection_failure_fixture_round_trips() {
    let detail: DumpDetail = round_trip(DUMP_DETAIL_INSPECTION_FAILED);
    assert_eq!(detail.phase, DumpPhase::Sealed);
    assert_eq!(detail.validation, ValidationState::NotChecked);
    assert_eq!(detail.coverage, None);
    assert!(!detail.downloadable);
    assert_eq!(detail.symbol_coverage, Vec::new());
    assert_eq!(detail.activity.len(), 2);
    assert_eq!(detail.activity[0].outcome.as_deref(), Some("rejected"));
    assert_eq!(
        detail.inspection_error.as_deref(),
        Some("Inspector could not parse the minidump header")
    );
    detail.validate().expect("fixture must validate");

    // Contract-required-but-nullable keys: an absent key decodes the same as
    // null (serde's implicit Option default; tolerated by design).
    let mut value = detail_value(DUMP_DETAIL_INSPECTION_FAILED);
    assert!(
        value
            .as_object_mut()
            .expect("object fixture")
            .remove("purgedAt")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpDetail>(value).is_ok());
}

#[test]
fn wire_dump_detail_components_round_trip_standalone() {
    let row: ModuleSymbolCoverage = round_trip(
        r#"{
          "name": "renderer.dll",
          "debugFile": "renderer.pdb",
          "debugId": "1A2B3C4D5E6F708192A3B4C5D6E7F8091",
          "status": "missing",
          "artifactId": null,
          "system": false
        }"#,
    );
    row.validate().expect("row");
    let item: ActivityItem = round_trip(
        r#"{ "occurredAt": "2026-10-13T02:05:30.250Z", "action": "AuthorizeDownload", "outcome": "granted" }"#,
    );
    item.validate().expect("activity");
    let case_ref: DumpCaseRef = round_trip(r#"{ "caseId": "case_02", "title": "Upload test" }"#);
    case_ref.validate().expect("case ref");
}

#[test]
fn wire_dump_detail_unknown_fields_are_rejected() {
    let mut top_level = detail_value(DUMP_DETAIL_FULL);
    top_level["serverNote"] = serde_json::json!("x");
    assert!(serde_json::from_value::<DumpDetail>(top_level).is_err());

    let mut nested_case = detail_value(DUMP_DETAIL_FULL);
    nested_case["case"]["customerId"] = serde_json::json!("customer_01");
    assert!(serde_json::from_value::<DumpDetail>(nested_case).is_err());

    let mut nested_row = detail_value(DUMP_DETAIL_FULL);
    nested_row["symbolCoverage"][0]["kind"] = serde_json::json!("pe");
    assert!(serde_json::from_value::<DumpDetail>(nested_row).is_err());

    let mut nested_activity = detail_value(DUMP_DETAIL_FULL);
    nested_activity["activity"][0]["actor"] = serde_json::json!("operator");
    assert!(serde_json::from_value::<DumpDetail>(nested_activity).is_err());

    // The wire key for the case reference is exactly `case`.
    let mut wrong_case_key = detail_value(DUMP_DETAIL_FULL);
    let case = wrong_case_key["case"].take();
    wrong_case_key["caseRef"] = case;
    assert!(serde_json::from_value::<DumpDetail>(wrong_case_key).is_err());

    // Required fields cannot go missing.
    let mut missing_case = detail_value(DUMP_DETAIL_FULL);
    assert!(
        missing_case
            .as_object_mut()
            .expect("object fixture")
            .remove("case")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpDetail>(missing_case).is_err());

    let mut missing_received_at = detail_value(DUMP_DETAIL_FULL);
    assert!(
        missing_received_at
            .as_object_mut()
            .expect("object fixture")
            .remove("receivedAt")
            .is_some()
    );
    assert!(serde_json::from_value::<DumpDetail>(missing_received_at).is_err());
}

#[test]
fn wire_dump_detail_wrong_types_are_rejected() {
    for (pointer, wrong) in [
        ("/downloadable", serde_json::json!("true")),
        ("/byteSize", serde_json::json!(1073741824)),
        ("/receivedAt", serde_json::json!(1_761_000_000)),
        ("/symbolCoverage", serde_json::json!({})),
        ("/activity", serde_json::json!({})),
        ("/symbolCoverage/0/system", serde_json::json!(1)),
        ("/symbolCoverage/0/name", serde_json::json!(42)),
        ("/case/title", serde_json::json!(["Renderer crash loop"])),
        ("/phase", serde_json::json!(1)),
        ("/activity/0/occurredAt", serde_json::json!(false)),
    ] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = wrong;
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{pointer} must reject a wrong-typed value"
        );
    }
}

#[test]
fn wire_dump_detail_vocabulary_is_closed() {
    for phase in [
        "receiving",
        "sealed",
        "quarantined",
        "available",
        "rejected",
        "deleting",
        "deleted",
    ] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["phase"] = serde_json::json!(phase);
        let detail: DumpDetail = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("phase {phase:?}: {error}"));
        assert_eq!(encode(&detail.phase), format!("\"{phase}\""));
    }
    for state in ["not-checked", "valid", "invalid", "transfer-failed"] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["validation"] = serde_json::json!(state);
        let detail: DumpDetail = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("validation {state:?}: {error}"));
        assert_eq!(encode(&detail.validation), format!("\"{state}\""));
    }
    for kind in ["partial", "full-memory-declared", "unknown"] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["coverage"] = serde_json::json!(kind);
        let detail: DumpDetail = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("coverage {kind:?}: {error}"));
        assert_eq!(
            detail.coverage.map(|kind| encode(&kind)),
            Some(format!("\"{kind}\""))
        );
    }
    for status in ["present", "missing", "unidentified"] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["symbolCoverage"][0]["status"] = serde_json::json!(status);
        let detail: DumpDetail = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("status {status:?}: {error}"));
        assert_eq!(
            encode(&detail.symbol_coverage[0].status),
            format!("\"{status}\"")
        );
    }

    for (pointer, invalid) in [
        ("/phase", "uploading"),
        ("/validation", "ok"),
        ("/coverage", "full"),
        ("/symbolCoverage/0/status", "unknown"),
    ] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = serde_json::json!(invalid);
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{pointer}={invalid:?} must be rejected"
        );
    }
}

#[test]
fn wire_dump_detail_text_bounds_are_enforced() {
    let reject = [
        (
            "/originalName",
            serde_json::json!("a".repeat(MAX_ORIGINAL_NAME_CHARS + 1)),
        ),
        ("/originalName", serde_json::json!("")),
        (
            "/case/title",
            serde_json::json!("t".repeat(MAX_CASE_TITLE_CHARS + 1)),
        ),
        ("/case/title", serde_json::json!("bad\u{0001}title")),
        (
            "/inspectionError",
            serde_json::json!("e".repeat(MAX_INSPECTION_ERROR_CHARS + 1)),
        ),
        ("/inspectionError", serde_json::json!("")),
        (
            "/symbolCoverage/0/name",
            serde_json::json!("n".repeat(MAX_MODULE_NAME_CHARS + 1)),
        ),
        ("/symbolCoverage/0/name", serde_json::json!("")),
        (
            "/symbolCoverage/0/debugFile",
            serde_json::json!("f".repeat(MAX_DEBUG_FILE_CHARS + 1)),
        ),
        (
            "/symbolCoverage/0/debugId",
            serde_json::json!("d".repeat(MAX_DEBUG_ID_CHARS + 1)),
        ),
        (
            "/activity/0/action",
            serde_json::json!("a".repeat(MAX_ACTIVITY_ACTION_CHARS + 1)),
        ),
        ("/activity/0/action", serde_json::json!("")),
        (
            "/activity/0/outcome",
            serde_json::json!("o".repeat(MAX_ACTIVITY_OUTCOME_CHARS + 1)),
        ),
        ("/activity/0/outcome", serde_json::json!("")),
        ("/activity/0/outcome", serde_json::Value::Null),
    ];
    for (pointer, bad) in reject {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = bad.clone();
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{pointer}={bad:?} must be rejected"
        );
    }

    // Exactly-at-the-bound values are accepted.
    let accept = [
        (
            "/originalName",
            serde_json::json!("a".repeat(MAX_ORIGINAL_NAME_CHARS)),
        ),
        (
            "/case/title",
            serde_json::json!("t".repeat(MAX_CASE_TITLE_CHARS)),
        ),
        (
            "/inspectionError",
            serde_json::json!("e".repeat(MAX_INSPECTION_ERROR_CHARS)),
        ),
        (
            "/activity/0/outcome",
            serde_json::json!("o".repeat(MAX_ACTIVITY_OUTCOME_CHARS)),
        ),
    ];
    for (pointer, good) in accept {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = good;
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_ok(),
            "{pointer} at the bound must be accepted"
        );
    }

    // Lengths count UTF-16 code units like ECMAScript `String.length`: an
    // astral character is two units, so 150 emoji are 300 units.
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["case"]["title"] = serde_json::json!("\u{1F600}".repeat(150));
    assert!(serde_json::from_value::<DumpDetail>(value).is_ok());
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["case"]["title"] = serde_json::json!("\u{1F600}".repeat(151));
    assert!(serde_json::from_value::<DumpDetail>(value).is_err());
}

#[test]
fn wire_dump_detail_identifier_rules_are_enforced() {
    // Accepted: at the bound, no whitespace.
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["dumpId"] = serde_json::json!("a".repeat(128));
    assert!(serde_json::from_value::<DumpDetail>(value).is_ok());

    let reject = [
        ("/dumpId", serde_json::json!("a".repeat(129))),
        ("/dumpId", serde_json::json!("")),
        ("/dumpId", serde_json::json!("dump id")),
        ("/dumpId", serde_json::json!("dump\u{00a0}id")),
        ("/dumpId", serde_json::json!("dump\u{feff}id")),
        ("/dumpId", serde_json::json!("dump\nid")),
        ("/case/caseId", serde_json::json!("case id")),
        (
            "/symbolCoverage/0/artifactId",
            serde_json::json!("a".repeat(129)),
        ),
        ("/symbolCoverage/0/artifactId", serde_json::json!("")),
        ("/symbolCoverage/0/artifactId", serde_json::json!("sym 01")),
    ];
    for (pointer, bad) in reject {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = bad.clone();
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{pointer}={bad:?} must be rejected"
        );
    }

    // Nullable artifact ids may be null (nulled in the fixture already) and
    // exactly at the bound.
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["symbolCoverage"][0]["artifactId"] = serde_json::json!("a".repeat(128));
    assert!(serde_json::from_value::<DumpDetail>(value).is_ok());
}

#[test]
fn wire_dump_detail_canonical_timestamp_rules_are_enforced() {
    let accept = [
        "2026-10-13T02:00:00.000Z",
        "1970-01-01T00:00:00.000Z",
        "2024-02-29T23:59:59.999Z",
        "2099-12-31T23:59:59.999Z",
    ];
    for good in accept {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["receivedAt"] = serde_json::json!(good);
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_ok(),
            "{good} must decode"
        );
    }

    let reject = [
        "2026-10-13T02:00:00Z",
        "2026-10-13 02:00:00.000Z",
        "2026-10-13t02:00:00.000Z",
        "2026-10-13T02:00:00.000z",
        "2026-10-13T02:00:00.00Z",
        "2026-02-29T00:00:00.000Z",
        "2025-02-29T00:00:00.000Z",
        "2026-02-30T00:00:00.000Z",
        "2024-02-30T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-13-01T00:00:00.000Z",
        "2026-00-10T00:00:00.000Z",
        "2026-10-00T00:00:00.000Z",
        "2026-10-32T00:00:00.000Z",
        "2026-10-13T24:00:00.000Z",
        "2026-10-13T02:60:00.000Z",
        "2026-10-13T02:00:60.000Z",
        "+026-10-13T02:00:00.000Z",
        "2026-10-13T02:00:00.000+00:00",
    ];
    for bad in reject {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["receivedAt"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{bad} must be rejected"
        );
    }

    // Nullable timestamps follow the same rule; null stays valid.
    for pointer in ["/availableAt", "/purgeAt", "/purgedAt"] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") =
            serde_json::json!("2026-02-30T00:00:00.000Z");
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{pointer} must reject a non-canonical timestamp"
        );

        let mut value = detail_value(DUMP_DETAIL_FULL);
        *value.pointer_mut(pointer).expect("fixture pointer") = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_ok(),
            "{pointer} null must be accepted"
        );
    }
}

#[test]
fn wire_dump_detail_canonical_decimal_rules_are_enforced() {
    let forty_digits = "1".repeat(MAX_CANONICAL_DECIMAL_DIGITS);
    let forty_one_digits = "1".repeat(MAX_CANONICAL_DECIMAL_DIGITS + 1);

    for good in ["0", "1073741824", "140703210000001", forty_digits.as_str()] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["byteSize"] = serde_json::json!(good);
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_ok(),
            "{good:?} must decode"
        );
    }

    for bad in [
        "",
        "01",
        "00",
        "01073741824",
        "-1",
        "+1",
        "1.5",
        "1e3",
        " 1",
        "1 073",
        forty_one_digits.as_str(),
    ] {
        let mut value = detail_value(DUMP_DETAIL_FULL);
        value["byteSize"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<DumpDetail>(value).is_err(),
            "{bad:?} must be rejected as non-canonical"
        );
    }
}

#[test]
fn wire_dump_detail_sha256_rule_is_enforced() {
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["sha256"] = serde_json::json!(SHA256.to_uppercase());
    assert!(serde_json::from_value::<DumpDetail>(value).is_err());

    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["sha256"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<DumpDetail>(value).is_ok());

    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["sha256"] = serde_json::json!(SHA256[..63].to_string());
    assert!(serde_json::from_value::<DumpDetail>(value).is_err());
}

#[test]
fn wire_dump_detail_array_caps_are_enforced() {
    let row = serde_json::json!({
        "name": null,
        "debugFile": null,
        "debugId": null,
        "status": "unidentified",
        "artifactId": null,
        "system": false
    });
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["symbolCoverage"] =
        serde_json::Value::Array(vec![row.clone(); MAX_MODULE_COVERAGE_ITEMS]);
    let detail: DumpDetail = serde_json::from_value(value).expect("4096 rows are allowed");
    assert_eq!(detail.symbol_coverage.len(), MAX_MODULE_COVERAGE_ITEMS);

    let mut over = detail_value(DUMP_DETAIL_FULL);
    over["symbolCoverage"] = serde_json::Value::Array(vec![row; MAX_MODULE_COVERAGE_ITEMS + 1]);
    assert!(serde_json::from_value::<DumpDetail>(over).is_err());

    let item = serde_json::json!({
        "occurredAt": "2026-10-13T02:00:00.000Z",
        "action": "BeginUpload"
    });
    let mut value = detail_value(DUMP_DETAIL_FULL);
    value["activity"] = serde_json::Value::Array(vec![item.clone(); MAX_ACTIVITY_ITEMS]);
    let detail: DumpDetail = serde_json::from_value(value).expect("200 items are allowed");
    assert_eq!(detail.activity.len(), MAX_ACTIVITY_ITEMS);

    let mut over = detail_value(DUMP_DETAIL_FULL);
    over["activity"] = serde_json::Value::Array(vec![item; MAX_ACTIVITY_ITEMS + 1]);
    assert!(serde_json::from_value::<DumpDetail>(over).is_err());
}

#[test]
fn wire_dump_detail_validate_maps_violations_to_decode() {
    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.activity[0].action = "a".repeat(MAX_ACTIVITY_ACTION_CHARS + 1);
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.symbol_coverage[0].name = Some("n".repeat(MAX_MODULE_NAME_CHARS + 1));
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.case_ref.title = "t".repeat(MAX_CASE_TITLE_CHARS + 1);
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.byte_size = Some("01".to_string());
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.received_at = "2026-02-30T00:00:00.000Z".to_string();
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.inspection_error = Some(String::new());
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.symbol_coverage[0].artifact_id = Some("has space".to_string());
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));

    let mut detail: DumpDetail = decode(DUMP_DETAIL_FULL);
    detail.original_name = "a".repeat(MAX_ORIGINAL_NAME_CHARS + 1);
    assert!(matches!(detail.validate(), Err(AnalyzerError::Decode(_))));
}

#[test]
fn wire_analyzer_name_version_bounds() {
    // At-bound values pass (implemented contract: 128 / 64 UTF-16 units).
    let ok = serde_json::json!({
        "analyzer": { "name": "n".repeat(128), "version": "v".repeat(64) },
        "kind": "triage",
        "inputSha256": SHA256,
        "outcome": "completed",
        "summary": "bounded"
    });
    assert!(serde_json::from_value::<AnalysisReportSubmission>(ok).is_ok());

    for (field, over) in [("name", 129), ("version", 65)] {
        let mut bad = serde_json::json!({
            "analyzer": { "name": "n", "version": "v" },
            "kind": "triage",
            "inputSha256": SHA256,
            "outcome": "completed",
            "summary": "bounded"
        });
        bad["analyzer"][field] = serde_json::json!("x".repeat(over));
        assert!(
            serde_json::from_value::<AnalysisReportSubmission>(bad).is_err(),
            "{field} over the bound must be rejected"
        );
    }
}

#[test]
fn wire_event_detail_bound_counts_utf8_bytes() {
    // 2000 CJK chars serialize to 6000 UTF-8 bytes — over the 4 KiB budget
    // even though the UTF-16 length would be 2000 units. The implemented
    // contract counts bytes (events.ts utf8ByteLength).
    let mut entry = event_value(EVENT_FEED_PAGE)["events"][0].clone();
    entry["detail"] = serde_json::json!({ "note": "漢".repeat(2000) });
    assert!(serde_json::from_value::<EventFeedEntry>(entry).is_err());
}
