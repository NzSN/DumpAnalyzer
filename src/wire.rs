//! Wire types for the consumed DumpLedger surface (task A1 and its dump-detail follow-up).
//!
//! Strict serde shapes mirroring DumpLedger's symmetric decoder discipline:
//! unknown fields and wrong types are rejected on decode, and the bounded
//! values the server guarantees are enforced both by custom deserializers and
//! by `validate()` for programmatically built values. Catalog types mirror the
//! implemented `catalog.ts` decoder exactly: closed `phase`/`validation`
//! vocabularies, identifier bounds, canonical UTC timestamps, canonical
//! decimal strings, required-but-nullable keys, and the 4096-item page cap.
//! Dump-detail shapes enforce the implemented contract's identifier, text,
//! canonical-timestamp, canonical-decimal, and array bounds
//! (`packages/http-contracts/src/dumps.ts`, `decode.ts`); event-feed shapes
//! follow the integration design's bounds (identifiers, canonical timestamps,
//! 64-character actions, 4 KiB `detail` objects, 4096-item pages) until the
//! server-side AI2 contract lands; analysis write-back keeps its own bounds
//! (`summary` ≤ 2000 characters, `kind` 1–64 characters, 64 lowercase hex
//! `inputSha256`, cursors ≤ 256 non-empty non-whitespace characters).
//! Validation failures surface as [`AnalyzerError::Decode`]; nothing panics.
//!
//! Field shapes follow `~/Repos/dump-ledger/docs/analyzer-integration-design.md`
//! ("Dump catalog search", "Event feed", "Analysis write-back", "Contracts,
//! limits, and errors"); the error envelope follows
//! `~/Repos/dump-ledger/docs/http-api.md` §Errors.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::types::{AnalyzerError, ReportOutcome, Result};

/// Length of a sha256 digest in lowercase hex characters.
pub const SHA256_CHARS: usize = 64;
/// Upper bound for `summary`, counted in Unicode scalar values.
pub const MAX_SUMMARY_CHARS: usize = 2000;
/// Minimum `kind` length, counted in Unicode scalar values.
pub const MIN_KIND_CHARS: usize = 1;
/// Maximum `kind` length, counted in Unicode scalar values.
pub const MAX_KIND_CHARS: usize = 64;
/// Upper bound for cursors, counted in characters; whitespace is rejected.
pub const MAX_CURSOR_CHARS: usize = 256;
/// Upper bound for the `architecture` catalog filter.
pub const MAX_ARCHITECTURE_CHARS: usize = 64;
/// Hard ceiling for one decoded `dumps` page (the operational page cap is 200).
pub const MAX_CATALOG_ITEMS: usize = 4096;
/// Largest integer exactly representable by an ECMAScript number.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Hard ceiling for one decoded `events` page (the operational page cap is 500).
pub const MAX_EVENT_FEED_ITEMS: usize = 4096;
/// Largest accepted event-feed `limit` ("default and maximum 500").
pub const MAX_EVENT_PAGE_LIMIT: u32 = 500;
/// Largest accepted `detail` object: 4 KiB serialized, counted as UTF-8
/// string length (UTF-16 code units) of the compact JSON, like every other text bound here.
pub const MAX_EVENT_DETAIL_LENGTH: usize = 4096;

// Dump-detail bounds (implemented contracts: packages/http-contracts/src/
// dumps.ts plus the shared primitives in decode.ts). Length bounds count
// UTF-16 code units, matching ECMAScript `String.length`.

/// Longest accepted identifier (`identifierField`); no whitespace allowed.
pub const MAX_IDENTIFIER_CHARS: usize = 128;
/// Longest accepted `originalName`.
pub const MAX_ORIGINAL_NAME_CHARS: usize = 1024;
/// Longest accepted `case.title`.
pub const MAX_CASE_TITLE_CHARS: usize = 300;
/// Longest accepted module `name` on a detail row.
pub const MAX_MODULE_NAME_CHARS: usize = 1024;
/// Longest accepted `debugFile` identity.
pub const MAX_DEBUG_FILE_CHARS: usize = 255;
/// Longest accepted `debugId` identity.
pub const MAX_DEBUG_ID_CHARS: usize = 64;
/// Longest accepted `inspectionError`.
pub const MAX_INSPECTION_ERROR_CHARS: usize = 2000;
/// Most module symbol-coverage rows one dump-detail response may carry.
pub const MAX_MODULE_COVERAGE_ITEMS: usize = 4096;
/// Most activity items one dump-detail response may carry.
pub const MAX_ACTIVITY_ITEMS: usize = 200;
/// Longest accepted activity `action`.
pub const MAX_ACTIVITY_ACTION_CHARS: usize = 64;
/// Longest accepted activity `outcome`.
pub const MAX_ACTIVITY_OUTCOME_CHARS: usize = 256;
/// Most digits in a canonical decimal string.
pub const MAX_CANONICAL_DECIMAL_DIGITS: usize = 40;

// ---------------------------------------------------------------------------
// Bound checks shared by the custom deserializers and `validate()`.
// ---------------------------------------------------------------------------

fn check_sha256(field: &str, value: &str) -> std::result::Result<(), String> {
    let valid = value.len() == SHA256_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{field}: expected {SHA256_CHARS} lowercase hex characters"
        ))
    }
}

fn check_cursor(field: &str, value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field}: must not be empty"));
    }
    // `text({ max: 256, pattern: /^\S+$/ })` in the contract: the bound
    // counts UTF-16 code units and whitespace is the ECMAScript set.
    let units = value.encode_utf16().count();
    if units > MAX_CURSOR_CHARS {
        return Err(format!(
            "{field}: cursor is {units} chars, limit is {MAX_CURSOR_CHARS}"
        ));
    }
    if value.chars().any(is_ecmascript_whitespace) {
        return Err(format!("{field}: cursor must not contain whitespace"));
    }
    Ok(())
}

/// `counterField` from decode.ts: a non-negative ECMAScript safe integer.
fn check_counter(field: &str, value: u64) -> std::result::Result<(), String> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(format!("{field}: exceeds the safe integer range"))
    }
}

/// Analyzer `name` bound (implemented contract: `analyses.ts`,
/// 128 UTF-16 units, matching the server's JS string length).
pub const MAX_ANALYZER_NAME_CHARS: usize = 128;
/// Analyzer `version` bound (64 UTF-16 units).
pub const MAX_ANALYZER_VERSION_CHARS: usize = 64;

fn check_analyzer_name(field: &str, value: &str) -> std::result::Result<(), String> {
    let units = value.encode_utf16().count();
    if units == 0 || units > MAX_ANALYZER_NAME_CHARS {
        return Err(format!(
            "{field}: analyzer name is {units} UTF-16 units, limit is 1..={MAX_ANALYZER_NAME_CHARS}"
        ));
    }
    Ok(())
}

fn check_analyzer_version(field: &str, value: &str) -> std::result::Result<(), String> {
    let units = value.encode_utf16().count();
    if units == 0 || units > MAX_ANALYZER_VERSION_CHARS {
        return Err(format!(
            "{field}: analyzer version is {units} UTF-16 units, limit is 1..={MAX_ANALYZER_VERSION_CHARS}"
        ));
    }
    Ok(())
}

fn check_summary(field: &str, value: &str) -> std::result::Result<(), String> {
    let chars = value.chars().count();
    if chars <= MAX_SUMMARY_CHARS {
        Ok(())
    } else {
        Err(format!(
            "{field}: summary is {chars} chars, limit is {MAX_SUMMARY_CHARS}"
        ))
    }
}

fn check_kind(field: &str, value: &str) -> std::result::Result<(), String> {
    let chars = value.chars().count();
    if (MIN_KIND_CHARS..=MAX_KIND_CHARS).contains(&chars) {
        Ok(())
    } else {
        Err(format!(
            "{field}: kind must be {MIN_KIND_CHARS}-{MAX_KIND_CHARS} chars, got {chars}"
        ))
    }
}

/// `detail`: a JSON object whose compact serialization is at most
/// [`MAX_EVENT_DETAIL_LENGTH`] UTF-16 code units (identical to bytes for the
/// ASCII identifiers and outcomes the design admits).
fn check_detail(field: &str, value: &Value) -> std::result::Result<(), String> {
    if !value.is_object() {
        return Err(format!("{field}: detail must be a JSON object"));
    }
    let serialized = serde_json::to_string(value).map_err(|err| err.to_string())?;
    // The implemented contract (events.ts) counts compact-JSON UTF-8 bytes
    // (`utf8ByteLength`); Rust's `str::len` is exactly that.
    let bytes = serialized.len();
    if bytes > MAX_EVENT_DETAIL_LENGTH {
        return Err(format!(
            "{field}: detail is {bytes} serialized bytes, limit is {MAX_EVENT_DETAIL_LENGTH}"
        ));
    }
    Ok(())
}

fn check_object(field: &str, value: &Value) -> std::result::Result<(), String> {
    if matches!(value, Value::Object(_)) {
        Ok(())
    } else {
        Err(format!("{field}: expected a JSON object"))
    }
}

/// `[\u0000-\u001f\u007f]` rejection from `text()` in decode.ts.
fn is_control_character(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}')
}

/// ECMAScript `\s` (the `^\S+$` identifier pattern); unlike
/// `char::is_whitespace` this includes U+FEFF.
fn is_ecmascript_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000a}'
            | '\u{000b}'
            | '\u{000c}'
            | '\u{000d}'
            | '\u{0020}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `text({ max })` from decode.ts: at least one character, at most `max`
/// characters (UTF-16 code units), no control characters.
fn check_text(field: &str, value: &str, max: usize) -> std::result::Result<(), String> {
    let units = value.encode_utf16().count();
    if units == 0 {
        return Err(format!("{field}: must not be empty"));
    }
    if units > max {
        return Err(format!("{field}: exceeds {max} characters"));
    }
    if value.chars().any(is_control_character) {
        return Err(format!("{field}: contains control characters"));
    }
    Ok(())
}

/// `identifierField` from decode.ts: `text({ max: 128 })` with `^\S+$`.
fn check_identifier(field: &str, value: &str) -> std::result::Result<(), String> {
    check_text(field, value, MAX_IDENTIFIER_CHARS)?;
    if value.chars().any(is_ecmascript_whitespace) {
        return Err(format!("{field}: must not contain whitespace"));
    }
    Ok(())
}

/// `canonicalTimestamp` from decode.ts: millisecond precision, `Z` suffix,
/// and a real calendar date (`toISOString()` round-trip equivalence).
fn check_canonical_timestamp(field: &str, value: &str) -> std::result::Result<(), String> {
    fn invalid(field: &str) -> String {
        format!("{field}: must be a canonical UTC timestamp (YYYY-MM-DDTHH:MM:SS.mmmZ)")
    }

    if !value.is_ascii() || value.len() != 24 {
        return Err(invalid(field));
    }
    let bytes = value.as_bytes();
    const SEPARATORS: [(usize, u8); 7] = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    for (index, byte) in bytes.iter().enumerate() {
        match SEPARATORS.iter().find(|(position, _)| *position == index) {
            Some((_, expected)) if byte == expected => {}
            Some(_) => return Err(invalid(field)),
            None if byte.is_ascii_digit() => {}
            None => return Err(invalid(field)),
        }
    }

    let part = |range: std::ops::Range<usize>| -> u32 {
        value
            .get(range)
            .and_then(|digits| digits.parse::<u32>().ok())
            .unwrap_or(u32::MAX)
    };
    let (year, month, day) = (part(0..4), part(5..7), part(8..10));
    let (hour, minute, second) = (part(11..13), part(14..16), part(17..19));
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return Err(invalid(field));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(invalid(field));
    }
    Ok(())
}

/// Days in `month` (1-based) of a proleptic Gregorian `year`.
fn days_in_month(year: u32, month: u32) -> u32 {
    const DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        29
    } else {
        DAYS[(month - 1) as usize]
    }
}

/// `canonicalDecimal` from decode.ts: unsigned integer, no leading zeros,
/// fraction, or exponent, at most 40 digits.
fn check_canonical_decimal(field: &str, value: &str) -> std::result::Result<(), String> {
    let canonical = value == "0"
        || (!value.is_empty()
            && value.as_bytes()[0] != b'0'
            && value.bytes().all(|byte| byte.is_ascii_digit()));
    if canonical && value.len() <= MAX_CANONICAL_DECIMAL_DIGITS {
        Ok(())
    } else {
        Err(format!(
            "{field}: must be a canonical decimal string (no sign, leading zeros, fraction, or \
             exponent; at most {MAX_CANONICAL_DECIMAL_DIGITS} digits)"
        ))
    }
}

// ---------------------------------------------------------------------------
// Catalog search
// ---------------------------------------------------------------------------

/// Per-module symbol-coverage counts on a catalog row.
///
/// The full per-module rows stay on the dump detail route; the catalog only
/// carries the aggregate counts for pre-flight decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SymbolCoverage {
    #[serde(deserialize_with = "de::counter")]
    pub present: u64,
    #[serde(deserialize_with = "de::counter")]
    pub missing: u64,
    #[serde(deserialize_with = "de::counter")]
    pub unidentified: u64,
}

impl SymbolCoverage {
    /// Re-checks the ECMAScript safe-integer bound on every counter.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("present", self.present),
            ("missing", self.missing),
            ("unidentified", self.unidentified),
        ] {
            check_counter(field, value).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

/// One row of `GET /api/v1/dumps` ("Dump catalog search"), mirroring the
/// implemented `catalog.ts` decoder: closed `phase`/`validation` vocabularies,
/// identifier/text/timestamp/decimal bounds, required-but-nullable keys, and
/// optional inspector facts that reject an explicit `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpCatalogEntry {
    pub dump_id: String,
    pub case_id: String,
    pub customer_id: String,
    pub phase: DumpPhase,
    pub validation: ValidationState,
    pub original_name: String,
    /// Canonical decimal string; null until the upload is sealed.
    pub byte_size: Option<String>,
    /// 64 lowercase hex characters; null until the upload is sealed.
    pub sha256: Option<String>,
    /// Required canonical UTC timestamp (never null).
    pub received_at: String,
    pub available_at: Option<String>,
    pub purge_at: Option<String>,
    /// Inspector fact; encoded only when the inspection carried it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// Inspector fact: uint32 as a JSON number, when the inspection carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_code: Option<u32>,
    /// Inspector fact: uint64 as a canonical decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_address: Option<String>,
    pub symbol_coverage: SymbolCoverage,
}

impl<'de> Deserialize<'de> for DumpCatalogEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Raw wire shape: every key is required except the optional inspector
        /// facts, and `null` is allowed only on the nullable keys.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Raw {
            dump_id: String,
            case_id: String,
            customer_id: String,
            phase: DumpPhase,
            validation: ValidationState,
            original_name: String,
            #[serde(default, deserialize_with = "de::double_option")]
            byte_size: Option<Option<String>>,
            #[serde(default, deserialize_with = "de::double_option")]
            sha256: Option<Option<String>>,
            received_at: String,
            #[serde(default, deserialize_with = "de::double_option")]
            available_at: Option<Option<String>>,
            #[serde(default, deserialize_with = "de::double_option")]
            purge_at: Option<Option<String>>,
            #[serde(default, deserialize_with = "de::optional_present")]
            architecture: Option<String>,
            #[serde(default, deserialize_with = "de::optional_present")]
            exception_code: Option<u32>,
            #[serde(default, deserialize_with = "de::optional_present")]
            exception_address: Option<String>,
            symbol_coverage: SymbolCoverage,
        }

        let raw = Raw::deserialize(deserializer)?;
        let entry = Self {
            dump_id: raw.dump_id,
            case_id: raw.case_id,
            customer_id: raw.customer_id,
            phase: raw.phase,
            validation: raw.validation,
            original_name: raw.original_name,
            byte_size: de::require_present("byteSize", raw.byte_size)?,
            sha256: de::require_present("sha256", raw.sha256)?,
            received_at: raw.received_at,
            available_at: de::require_present("availableAt", raw.available_at)?,
            purge_at: de::require_present("purgeAt", raw.purge_at)?,
            architecture: raw.architecture,
            exception_code: raw.exception_code,
            exception_address: raw.exception_address,
            symbol_coverage: raw.symbol_coverage,
        };
        entry.validate().map_err(serde::de::Error::custom)?;
        Ok(entry)
    }
}

impl DumpCatalogEntry {
    /// Re-checks every bounded field of this row.
    pub fn validate(&self) -> Result<()> {
        check_identifier("dumpId", &self.dump_id).map_err(AnalyzerError::Decode)?;
        check_identifier("caseId", &self.case_id).map_err(AnalyzerError::Decode)?;
        check_identifier("customerId", &self.customer_id).map_err(AnalyzerError::Decode)?;
        check_text("originalName", &self.original_name, MAX_ORIGINAL_NAME_CHARS)
            .map_err(AnalyzerError::Decode)?;
        if let Some(value) = &self.byte_size {
            check_canonical_decimal("byteSize", value).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.sha256 {
            check_sha256("sha256", value).map_err(AnalyzerError::Decode)?;
        }
        check_canonical_timestamp("receivedAt", &self.received_at)
            .map_err(AnalyzerError::Decode)?;
        for (field, value) in [
            ("availableAt", &self.available_at),
            ("purgeAt", &self.purge_at),
        ] {
            if let Some(value) = value {
                check_canonical_timestamp(field, value).map_err(AnalyzerError::Decode)?;
            }
        }
        if let Some(value) = &self.architecture {
            check_text("architecture", value, MAX_ARCHITECTURE_CHARS)
                .map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.exception_address {
            check_canonical_decimal("exceptionAddress", value).map_err(AnalyzerError::Decode)?;
        }
        self.symbol_coverage.validate()?;
        Ok(())
    }
}

/// Page shape of `GET /api/v1/dumps`: `{ "dumps": [...], "nextCursor"? }`.
///
/// An absent `nextCursor` is the end of the keyset ordering; an explicit
/// `null` is rejected like every other present value in the contract's
/// `optional()` handling. The `dumps` array decodes at most 4096 rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DumpCatalogResponse {
    #[serde(deserialize_with = "de::catalog_page_array")]
    pub dumps: Vec<DumpCatalogEntry>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::optional_cursor"
    )]
    pub next_cursor: Option<String>,
}

impl DumpCatalogResponse {
    /// Re-checks every row and the page cursor.
    pub fn validate(&self) -> Result<()> {
        for entry in &self.dumps {
            entry.validate()?;
        }
        if let Some(cursor) = &self.next_cursor {
            check_cursor("nextCursor", cursor).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

/// Optional filters accepted by `GET /api/v1/dumps` ("Query parameters").
///
/// All parameters are optional; each appears at most once and unknown
/// parameters are rejected by the server. [`DumpCatalogQuery::to_pairs`] and
/// [`DumpCatalogQuery::to_query_string`] validate values with the same rules
/// as the server's `catalog.ts` parameter decoder: `phase`/`validation` are
/// closed vocabularies, identifiers are whitespace-free, received bounds are
/// canonical UTC timestamps, and no filter may be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DumpCatalogQuery {
    pub case_id: Option<String>,
    pub customer_id: Option<String>,
    pub phase: Option<DumpPhase>,
    pub validation: Option<ValidationState>,
    pub received_after: Option<String>,
    pub received_before: Option<String>,
    pub architecture: Option<String>,
    pub exception_code: Option<u32>,
    pub sha256: Option<String>,
    pub cursor: Option<String>,
}

impl DumpCatalogQuery {
    /// Re-checks the filter values against the server's decoder rules.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [("caseId", &self.case_id), ("customerId", &self.customer_id)] {
            if let Some(value) = value {
                check_identifier(field, value).map_err(AnalyzerError::Decode)?;
            }
        }
        for (field, value) in [
            ("receivedAfter", &self.received_after),
            ("receivedBefore", &self.received_before),
        ] {
            if let Some(value) = value {
                check_canonical_timestamp(field, value).map_err(AnalyzerError::Decode)?;
            }
        }
        if let Some(value) = &self.architecture {
            check_text("architecture", value, MAX_ARCHITECTURE_CHARS)
                .map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.sha256 {
            check_sha256("sha256", value).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.cursor {
            check_cursor("cursor", value).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }

    /// Canonical-order, validated query pairs (wire names, owned values).
    ///
    /// Order matches the design document's parameter table:
    /// `caseId`, `customerId`, `phase`, `validation`, `receivedAfter`,
    /// `receivedBefore`, `architecture`, `exceptionCode`, `sha256`, `cursor`.
    pub fn to_pairs(&self) -> Result<Vec<(&'static str, String)>> {
        self.validate()?;
        let mut pairs: Vec<(&'static str, String)> = Vec::new();
        if let Some(value) = &self.case_id {
            pairs.push(("caseId", value.clone()));
        }
        if let Some(value) = &self.customer_id {
            pairs.push(("customerId", value.clone()));
        }
        if let Some(value) = &self.phase {
            pairs.push(("phase", value.as_str().to_string()));
        }
        if let Some(value) = &self.validation {
            pairs.push(("validation", value.as_str().to_string()));
        }
        if let Some(value) = &self.received_after {
            pairs.push(("receivedAfter", value.clone()));
        }
        if let Some(value) = &self.received_before {
            pairs.push(("receivedBefore", value.clone()));
        }
        if let Some(value) = &self.architecture {
            pairs.push(("architecture", value.clone()));
        }
        if let Some(code) = self.exception_code {
            pairs.push(("exceptionCode", code.to_string()));
        }
        if let Some(value) = &self.sha256 {
            pairs.push(("sha256", value.clone()));
        }
        if let Some(value) = &self.cursor {
            pairs.push(("cursor", value.clone()));
        }
        Ok(pairs)
    }

    /// Percent-encoded query string without a leading `?`; empty when no
    /// filter is set.
    pub fn to_query_string(&self) -> Result<String> {
        Ok(query_string(&self.to_pairs()?))
    }
}

/// Joins validated name/value pairs into a percent-encoded query string.
fn query_string(pairs: &[(&'static str, String)]) -> String {
    let mut out = String::new();
    for (name, value) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        encode_query_component(value, &mut out);
    }
    out
}

/// RFC 3986 unreserved characters stay literal; everything else is
/// percent-encoded with uppercase hex digits.
fn encode_query_component(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dump detail (`GET /api/v1/dumps/:dumpId`)
// ---------------------------------------------------------------------------

/// Dump lifecycle phase (`DUMP_PHASES` in `vocab.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DumpPhase {
    Receiving,
    Sealed,
    Quarantined,
    Available,
    Rejected,
    Deleting,
    Deleted,
}

impl DumpPhase {
    /// Wire spelling; kept in lockstep with the serde representation by tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Receiving => "receiving",
            Self::Sealed => "sealed",
            Self::Quarantined => "quarantined",
            Self::Available => "available",
            Self::Rejected => "rejected",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        }
    }
}

/// Dump validation state (`VALIDATION_STATES` in `vocab.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationState {
    NotChecked,
    Valid,
    Invalid,
    TransferFailed,
}

impl ValidationState {
    /// Wire spelling; kept in lockstep with the serde representation by tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not-checked",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::TransferFailed => "transfer-failed",
        }
    }
}

/// Memory-coverage classification (`COVERAGE_KINDS` in `vocab.ts`); null
/// before classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageKind {
    Partial,
    FullMemoryDeclared,
    Unknown,
}

/// Symbol-store status of one module fact (`MODULE_SYMBOL_STATUSES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleSymbolStatus {
    Present,
    Missing,
    Unidentified,
}

/// Case breadcrumb on a dump detail response (`case: { caseId, title }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DumpCaseRef {
    #[serde(deserialize_with = "de::identifier")]
    pub case_id: String,
    #[serde(deserialize_with = "de::text_300")]
    pub title: String,
}

impl DumpCaseRef {
    /// Re-checks the identifier and title bounds.
    pub fn validate(&self) -> Result<()> {
        check_identifier("caseId", &self.case_id).map_err(AnalyzerError::Decode)?;
        check_text("case title", &self.title, MAX_CASE_TITLE_CHARS)
            .map_err(AnalyzerError::Decode)?;
        Ok(())
    }
}

/// One per-module `symbolCoverage` row on a dump detail response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleSymbolCoverage {
    #[serde(default, deserialize_with = "de::opt_text_1024")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "de::opt_text_255")]
    pub debug_file: Option<String>,
    #[serde(default, deserialize_with = "de::opt_text_64")]
    pub debug_id: Option<String>,
    pub status: ModuleSymbolStatus,
    #[serde(default, deserialize_with = "de::opt_identifier")]
    pub artifact_id: Option<String>,
    pub system: bool,
}

impl ModuleSymbolCoverage {
    /// Re-checks the nullable text and identifier bounds.
    pub fn validate(&self) -> Result<()> {
        if let Some(value) = &self.name {
            check_text("name", value, MAX_MODULE_NAME_CHARS).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.debug_file {
            check_text("debugFile", value, MAX_DEBUG_FILE_CHARS).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.debug_id {
            check_text("debugId", value, MAX_DEBUG_ID_CHARS).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.artifact_id {
            check_identifier("artifactId", value).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

/// One bounded, safely-echoable activity row on a dump detail response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityItem {
    #[serde(deserialize_with = "de::required_timestamp")]
    pub occurred_at: String,
    #[serde(deserialize_with = "de::text_64")]
    pub action: String,
    /// Absent when the audit detail carried no outcome; an explicit `null`
    /// is rejected (the contract's `optional()` + `text()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::activity_outcome"
    )]
    pub outcome: Option<String>,
}

impl ActivityItem {
    /// Re-checks the timestamp and text bounds.
    pub fn validate(&self) -> Result<()> {
        check_canonical_timestamp("occurredAt", &self.occurred_at)
            .map_err(AnalyzerError::Decode)?;
        check_text("action", &self.action, MAX_ACTIVITY_ACTION_CHARS)
            .map_err(AnalyzerError::Decode)?;
        if let Some(value) = &self.outcome {
            check_text("activity outcome", value, MAX_ACTIVITY_OUTCOME_CHARS)
                .map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

/// `GET /api/v1/dumps/:dumpId` response body (contract: `DumpDetailResponse`;
/// lifecycle, coverage, inspector facts, and audit excerpt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DumpDetail {
    #[serde(deserialize_with = "de::identifier")]
    pub dump_id: String,
    /// Wire key is the reserved word `case`.
    #[serde(rename = "case")]
    pub case_ref: DumpCaseRef,
    pub phase: DumpPhase,
    #[serde(deserialize_with = "de::text_1024")]
    pub original_name: String,
    #[serde(default, deserialize_with = "de::opt_canonical_decimal")]
    pub byte_size: Option<String>,
    #[serde(default, deserialize_with = "de::opt_sha256")]
    pub sha256: Option<String>,
    pub validation: ValidationState,
    #[serde(default)]
    pub coverage: Option<CoverageKind>,
    pub downloadable: bool,
    #[serde(deserialize_with = "de::required_timestamp")]
    pub received_at: String,
    #[serde(default, deserialize_with = "de::opt_timestamp")]
    pub available_at: Option<String>,
    #[serde(default, deserialize_with = "de::opt_timestamp")]
    pub purge_at: Option<String>,
    #[serde(default, deserialize_with = "de::opt_timestamp")]
    pub purged_at: Option<String>,
    #[serde(default, deserialize_with = "de::opt_text_2000")]
    pub inspection_error: Option<String>,
    #[serde(deserialize_with = "de::module_coverage_array")]
    pub symbol_coverage: Vec<ModuleSymbolCoverage>,
    #[serde(deserialize_with = "de::activity_array")]
    pub activity: Vec<ActivityItem>,
}

impl DumpDetail {
    /// Re-checks every bounded field, the nested rows, and the array caps.
    pub fn validate(&self) -> Result<()> {
        check_identifier("dumpId", &self.dump_id).map_err(AnalyzerError::Decode)?;
        self.case_ref.validate()?;
        check_text("originalName", &self.original_name, MAX_ORIGINAL_NAME_CHARS)
            .map_err(AnalyzerError::Decode)?;
        if let Some(value) = &self.byte_size {
            check_canonical_decimal("byteSize", value).map_err(AnalyzerError::Decode)?;
        }
        if let Some(value) = &self.sha256 {
            check_sha256("sha256", value).map_err(AnalyzerError::Decode)?;
        }
        check_canonical_timestamp("receivedAt", &self.received_at)
            .map_err(AnalyzerError::Decode)?;
        for (field, value) in [
            ("availableAt", &self.available_at),
            ("purgeAt", &self.purge_at),
            ("purgedAt", &self.purged_at),
        ] {
            if let Some(value) = value {
                check_canonical_timestamp(field, value).map_err(AnalyzerError::Decode)?;
            }
        }
        if let Some(value) = &self.inspection_error {
            check_text("inspectionError", value, MAX_INSPECTION_ERROR_CHARS)
                .map_err(AnalyzerError::Decode)?;
        }
        if self.symbol_coverage.len() > MAX_MODULE_COVERAGE_ITEMS {
            return Err(AnalyzerError::Decode(format!(
                "symbolCoverage: exceeds {MAX_MODULE_COVERAGE_ITEMS} items"
            )));
        }
        for row in &self.symbol_coverage {
            row.validate()?;
        }
        if self.activity.len() > MAX_ACTIVITY_ITEMS {
            return Err(AnalyzerError::Decode(format!(
                "activity: exceeds {MAX_ACTIVITY_ITEMS} items"
            )));
        }
        for item in &self.activity {
            item.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event feed
// ---------------------------------------------------------------------------

/// One `GET /api/v1/events` row ("Event feed"); bounds per the integration
/// design's "Event feed" and "Contracts, limits, and errors" sections (the
/// server-side AI2 contract is not implemented yet).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventFeedEntry {
    /// Zero-padded rowid; pass back as `?since=`.
    #[serde(deserialize_with = "de::cursor")]
    pub cursor: String,
    #[serde(deserialize_with = "de::identifier")]
    pub event_id: String,
    #[serde(deserialize_with = "de::required_timestamp")]
    pub occurred_at: String,
    #[serde(deserialize_with = "de::text_64")]
    pub action: String,
    #[serde(default, deserialize_with = "de::opt_identifier")]
    pub customer_id: Option<String>,
    #[serde(default, deserialize_with = "de::opt_identifier")]
    pub case_id: Option<String>,
    #[serde(default, deserialize_with = "de::opt_identifier")]
    pub dump_id: Option<String>,
    /// Bounded audit detail (identifiers and outcomes, never contents).
    #[serde(deserialize_with = "de::detail")]
    pub detail: Value,
}

impl EventFeedEntry {
    /// Re-checks the cursor, identifiers, timestamp, action, and detail bound.
    pub fn validate(&self) -> Result<()> {
        check_cursor("cursor", &self.cursor).map_err(AnalyzerError::Decode)?;
        check_identifier("eventId", &self.event_id).map_err(AnalyzerError::Decode)?;
        check_canonical_timestamp("occurredAt", &self.occurred_at)
            .map_err(AnalyzerError::Decode)?;
        check_text("action", &self.action, MAX_ACTIVITY_ACTION_CHARS)
            .map_err(AnalyzerError::Decode)?;
        for (field, value) in [
            ("customerId", &self.customer_id),
            ("caseId", &self.case_id),
            ("dumpId", &self.dump_id),
        ] {
            if let Some(value) = value {
                check_identifier(field, value).map_err(AnalyzerError::Decode)?;
            }
        }
        check_detail("detail", &self.detail).map_err(AnalyzerError::Decode)?;
        Ok(())
    }
}

/// Page shape of `GET /api/v1/events`: `{ "events": [...], "nextCursor" }`,
/// where `nextCursor` is always present (a beyond-end poll echoes the request
/// cursor, which is the sleep signal).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventFeedResponse {
    /// Decoded at most [`MAX_EVENT_FEED_ITEMS`] rows, mirroring the design's
    /// 4096-item list-decoder bound (the operational page cap is 500).
    #[serde(deserialize_with = "de::events_array")]
    pub events: Vec<EventFeedEntry>,
    #[serde(deserialize_with = "de::cursor")]
    pub next_cursor: String,
}

impl EventFeedResponse {
    /// Re-checks every row and the page cursor.
    pub fn validate(&self) -> Result<()> {
        for event in &self.events {
            event.validate()?;
        }
        check_cursor("nextCursor", &self.next_cursor).map_err(AnalyzerError::Decode)?;
        Ok(())
    }
}

/// Optional query parameters for `GET /api/v1/events` ("Event feed").
///
/// `since` absent means "from the beginning" (a beyond-end poll returns an
/// empty page whose `nextCursor` echoes the request cursor); `actions`
/// absent means all actions; `limit` defaults to and maxes at 500 on the
/// server. Values are validated with the rules of the design's parameter
/// table and never emitted empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFeedParams {
    pub since: Option<String>,
    /// Comma-list over the audit action vocabulary; joined on the wire.
    pub actions: Option<Vec<String>>,
    pub case_id: Option<String>,
    pub limit: Option<u32>,
}

impl EventFeedParams {
    /// Re-checks the filter values.
    pub fn validate(&self) -> Result<()> {
        if let Some(since) = &self.since {
            check_cursor("since", since).map_err(AnalyzerError::Decode)?;
        }
        if let Some(actions) = &self.actions {
            if actions.is_empty() {
                return Err(AnalyzerError::Decode(
                    "actions: must not be empty when provided".to_string(),
                ));
            }
            for action in actions {
                check_text("action", action, MAX_ACTIVITY_ACTION_CHARS)
                    .map_err(AnalyzerError::Decode)?;
                if action.contains(',') {
                    return Err(AnalyzerError::Decode(
                        "action: must not contain a comma".to_string(),
                    ));
                }
            }
        }
        if let Some(case_id) = &self.case_id {
            check_identifier("caseId", case_id).map_err(AnalyzerError::Decode)?;
        }
        if let Some(limit) = self.limit {
            if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
                return Err(AnalyzerError::Decode(format!(
                    "limit: must be between 1 and {MAX_EVENT_PAGE_LIMIT}"
                )));
            }
        }
        Ok(())
    }

    /// Canonical-order, validated query pairs (wire names, owned values):
    /// `since`, `actions`, `caseId`, `limit`.
    pub fn to_pairs(&self) -> Result<Vec<(&'static str, String)>> {
        self.validate()?;
        let mut pairs: Vec<(&'static str, String)> = Vec::new();
        if let Some(since) = &self.since {
            pairs.push(("since", since.clone()));
        }
        if let Some(actions) = &self.actions {
            pairs.push(("actions", actions.join(",")));
        }
        if let Some(case_id) = &self.case_id {
            pairs.push(("caseId", case_id.clone()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        Ok(pairs)
    }

    /// Percent-encoded query string without a leading `?`; empty when no
    /// filter is set.
    pub fn to_query_string(&self) -> Result<String> {
        Ok(query_string(&self.to_pairs()?))
    }
}

// ---------------------------------------------------------------------------
// Analysis write-back
// ---------------------------------------------------------------------------

/// Self-reported analyzer attribution (`analyzer {name, version}`); an
/// attribution hint, not identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Analyzer {
    #[serde(deserialize_with = "de::analyzer_name")]
    pub name: String,
    #[serde(deserialize_with = "de::analyzer_version")]
    pub version: String,
}

/// One server-side analysis report (`GET /api/v1/dumps/:dumpId/analyses` and
/// the `POST` replay response body).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisReport {
    pub analysis_id: String,
    pub dump_id: String,
    pub analyzer: Analyzer,
    #[serde(deserialize_with = "de::kind")]
    pub kind: String,
    #[serde(deserialize_with = "de::required_sha256")]
    pub input_sha256: String,
    /// Server clock, never the analyzer's.
    pub created_at: String,
    pub outcome: ReportOutcome,
    #[serde(deserialize_with = "de::summary")]
    pub summary: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_object"
    )]
    pub facts: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
}

impl AnalysisReport {
    /// Re-checks the bounded fields of this report.
    pub fn validate(&self) -> Result<()> {
        check_analyzer_name("analyzer.name", &self.analyzer.name).map_err(AnalyzerError::Decode)?;
        check_analyzer_version("analyzer.version", &self.analyzer.version)
            .map_err(AnalyzerError::Decode)?;
        check_kind("kind", &self.kind).map_err(AnalyzerError::Decode)?;
        check_sha256("inputSha256", &self.input_sha256).map_err(AnalyzerError::Decode)?;
        check_summary("summary", &self.summary).map_err(AnalyzerError::Decode)?;
        if let Some(facts) = &self.facts {
            check_object("facts", facts).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

/// The `POST /api/v1/dumps/:dumpId/analyses` body: the writable subset of
/// [`AnalysisReport`] (server-assigned `analysisId`, `dumpId`, and
/// `createdAt` are omitted; `dumpId` rides in the route).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisReportSubmission {
    pub analyzer: Analyzer,
    #[serde(deserialize_with = "de::kind")]
    pub kind: String,
    #[serde(deserialize_with = "de::required_sha256")]
    pub input_sha256: String,
    pub outcome: ReportOutcome,
    #[serde(deserialize_with = "de::summary")]
    pub summary: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_object"
    )]
    pub facts: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
}

impl AnalysisReportSubmission {
    /// Validating constructor for the write-back body.
    pub fn new(
        analyzer: Analyzer,
        kind: String,
        input_sha256: String,
        outcome: ReportOutcome,
        summary: String,
        facts: Option<Value>,
        duplicate_of: Option<String>,
    ) -> Result<Self> {
        let submission = Self {
            analyzer,
            kind,
            input_sha256,
            outcome,
            summary,
            facts,
            duplicate_of,
        };
        submission.validate()?;
        Ok(submission)
    }

    /// Re-checks the bounded fields of this body.
    pub fn validate(&self) -> Result<()> {
        check_analyzer_name("analyzer.name", &self.analyzer.name).map_err(AnalyzerError::Decode)?;
        check_analyzer_version("analyzer.version", &self.analyzer.version)
            .map_err(AnalyzerError::Decode)?;
        check_kind("kind", &self.kind).map_err(AnalyzerError::Decode)?;
        check_sha256("inputSha256", &self.input_sha256).map_err(AnalyzerError::Decode)?;
        check_summary("summary", &self.summary).map_err(AnalyzerError::Decode)?;
        if let Some(facts) = &self.facts {
            check_object("facts", facts).map_err(AnalyzerError::Decode)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

/// DumpLedger's handled-application-error envelope
/// (`http-api.md` §Errors and retry behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

/// One customer row (`GET /api/v1/customers`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomerSummary {
    pub customer_id: String,
    pub display_name: String,
    /// Sequential display number (DumpLedger `69eb3d3`); absent from older
    /// ledger builds, so it decodes optionally.
    #[serde(default)]
    pub customer_no: Option<u64>,
}

/// One webhook subscription row (`GET /api/v1/webhooks`; never carries the
/// signing secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookSubscription {
    pub id: String,
    pub url: String,
    pub actions: Option<Vec<String>>,
    pub case_id: Option<String>,
    pub cursor: String,
    pub created_at: String,
}

/// `GET /api/v1/webhooks` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookListResponse {
    pub subscriptions: Vec<WebhookSubscription>,
}

/// `POST /api/v1/webhooks` success; `secret` appears only in this response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWebhookResponse {
    pub subscription: WebhookSubscription,
    pub secret: String,
}

/// `GET /api/v1/customers` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomerListResponse {
    pub customers: Vec<CustomerSummary>,
}

/// The `error` object of [`ErrorEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl ErrorEnvelope {
    /// The stable error code, when the body was an error envelope.
    pub fn code(&self) -> &str {
        &self.error.code
    }

    /// Whether the server labeled the failure retryable.
    pub fn retryable(&self) -> bool {
        self.error.retryable
    }
}

// ---------------------------------------------------------------------------
// Custom deserializers: bound enforcement at decode time.
// ---------------------------------------------------------------------------

mod de {
    use super::*;

    pub(super) fn opt_sha256<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        if let Some(text) = &value {
            check_sha256("sha256", text).map_err(serde::de::Error::custom)?;
        }
        Ok(value)
    }

    pub(super) fn required_sha256<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_sha256("inputSha256", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// `counterField`: a non-negative ECMAScript safe integer.
    pub(super) fn counter<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        check_counter("symbolCoverage", value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    pub(super) fn cursor<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_cursor("cursor", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// A required-but-nullable key: absent stays `None` for the caller's
    /// presence check; an explicit `null` decodes to `Some(None)`; a value to
    /// `Some(Some(value))`.
    pub(super) fn double_option<'de, D, T>(
        deserializer: D,
    ) -> std::result::Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }

    /// Rejects an absent key with the field name; explicit `null` passes
    /// through as `None`.
    pub(super) fn require_present<T, E>(
        name: &str,
        value: Option<Option<T>>,
    ) -> std::result::Result<Option<T>, E>
    where
        E: serde::de::Error,
    {
        match value {
            Some(value) => Ok(value),
            None => Err(E::custom(format!("missing field `{name}`"))),
        }
    }

    /// A contract-optional key: absent decodes to `None`, while an explicit
    /// `null` is a type error like every other present value.
    pub(super) fn optional_present<'de, D, T>(
        deserializer: D,
    ) -> std::result::Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        T::deserialize(deserializer).map(Some)
    }

    /// `nextCursor`: optional, non-empty cursor of at most 256 non-whitespace
    /// characters; an explicit `null` is rejected.
    pub(super) fn optional_cursor<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_cursor("nextCursor", &value).map_err(serde::de::Error::custom)?;
        Ok(Some(value))
    }

    /// `dumps`: the page array, capped like the contract's 4096-item decoder.
    pub(super) fn catalog_page_array<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Vec<DumpCatalogEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<DumpCatalogEntry>::deserialize(deserializer)?;
        if value.len() > MAX_CATALOG_ITEMS {
            return Err(serde::de::Error::custom(format!(
                "dumps: exceeds {MAX_CATALOG_ITEMS} items"
            )));
        }
        Ok(value)
    }

    pub(super) fn summary<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_summary("summary", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    pub(super) fn kind<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_kind("kind", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// `analyzer.name`: bounded to [`MAX_ANALYZER_NAME_CHARS`].
    pub(super) fn analyzer_name<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_analyzer_name("analyzer.name", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// `analyzer.version`: bounded to [`MAX_ANALYZER_VERSION_CHARS`].
    pub(super) fn analyzer_version<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_analyzer_version("analyzer.version", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// `detail`: a JSON object bounded to [`MAX_EVENT_DETAIL_LENGTH`]
    /// serialized characters.
    pub(super) fn detail<'de, D>(deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        check_detail("detail", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    /// `events`: the feed-page array, capped like the design's 4096-item
    /// list-decoder bound.
    pub(super) fn events_array<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Vec<EventFeedEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<EventFeedEntry>::deserialize(deserializer)?;
        if value.len() > MAX_EVENT_FEED_ITEMS {
            return Err(serde::de::Error::custom(format!(
                "events: exceeds {MAX_EVENT_FEED_ITEMS} items"
            )));
        }
        Ok(value)
    }

    pub(super) fn opt_object<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<Value>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<Value>::deserialize(deserializer)?;
        if let Some(object) = &value {
            check_object("facts", object).map_err(serde::de::Error::custom)?;
        }
        Ok(value)
    }

    // Dump-detail decoders (contracts: dumps.ts / decode.ts).

    macro_rules! required_text_decoder {
        ($name:ident, $label:literal, $max:expr) => {
            pub(super) fn $name<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                check_text($label, &value, $max).map_err(serde::de::Error::custom)?;
                Ok(value)
            }
        };
    }

    macro_rules! optional_text_decoder {
        ($name:ident, $label:literal, $max:expr) => {
            pub(super) fn $name<'de, D>(
                deserializer: D,
            ) -> std::result::Result<Option<String>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Option::<String>::deserialize(deserializer)?;
                if let Some(text) = &value {
                    check_text($label, text, $max).map_err(serde::de::Error::custom)?;
                }
                Ok(value)
            }
        };
    }

    required_text_decoder!(text_64, "action", MAX_ACTIVITY_ACTION_CHARS);
    required_text_decoder!(text_300, "case title", MAX_CASE_TITLE_CHARS);
    required_text_decoder!(text_1024, "originalName", MAX_ORIGINAL_NAME_CHARS);

    optional_text_decoder!(opt_text_64, "debugId", MAX_DEBUG_ID_CHARS);
    optional_text_decoder!(opt_text_255, "debugFile", MAX_DEBUG_FILE_CHARS);
    optional_text_decoder!(opt_text_1024, "module name", MAX_MODULE_NAME_CHARS);
    optional_text_decoder!(opt_text_2000, "inspectionError", MAX_INSPECTION_ERROR_CHARS);

    pub(super) fn identifier<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_identifier("identifier", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    pub(super) fn opt_identifier<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        if let Some(identifier) = &value {
            check_identifier("identifier", identifier).map_err(serde::de::Error::custom)?;
        }
        Ok(value)
    }

    pub(super) fn required_timestamp<'de, D>(
        deserializer: D,
    ) -> std::result::Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_canonical_timestamp("timestamp", &value).map_err(serde::de::Error::custom)?;
        Ok(value)
    }

    pub(super) fn opt_timestamp<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        if let Some(timestamp) = &value {
            check_canonical_timestamp("timestamp", timestamp).map_err(serde::de::Error::custom)?;
        }
        Ok(value)
    }

    pub(super) fn opt_canonical_decimal<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        if let Some(decimal) = &value {
            check_canonical_decimal("byteSize", decimal).map_err(serde::de::Error::custom)?;
        }
        Ok(value)
    }

    /// Activity `outcome`: an absent key decodes to `None`, while an explicit
    /// `null` is a type error (`optional()` + `text()` in the contract).
    pub(super) fn activity_outcome<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        check_text("activity outcome", &value, MAX_ACTIVITY_OUTCOME_CHARS)
            .map_err(serde::de::Error::custom)?;
        Ok(Some(value))
    }

    pub(super) fn module_coverage_array<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Vec<ModuleSymbolCoverage>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<ModuleSymbolCoverage>::deserialize(deserializer)?;
        if value.len() > MAX_MODULE_COVERAGE_ITEMS {
            return Err(serde::de::Error::custom(format!(
                "symbolCoverage: exceeds {MAX_MODULE_COVERAGE_ITEMS} items"
            )));
        }
        Ok(value)
    }

    pub(super) fn activity_array<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Vec<ActivityItem>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<ActivityItem>::deserialize(deserializer)?;
        if value.len() > MAX_ACTIVITY_ITEMS {
            return Err(serde::de::Error::custom(format!(
                "activity: exceeds {MAX_ACTIVITY_ITEMS} items"
            )));
        }
        Ok(value)
    }
}
