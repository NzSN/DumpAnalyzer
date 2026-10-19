//! Canonical forensic report. Saved intact before the compatibility projection.
use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::types::{AnalyzerError, JobIdentity, ReportOutcome, Result, RunOutput};

pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_REPORT_BYTES: usize = 512 * 1024;
pub const MAX_TRANSCRIPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FRAMES: usize = 128;
pub const MAX_MODULES: usize = 64;
pub const MAX_EVIDENCE: usize = 32;
pub const MAX_SECTION_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureStatus {
    Present,
    Partial,
    Absent,
    #[default]
    Unavailable,
    Failed,
    TimedOut,
    Truncated,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SymbolQuality {
    Matched,
    ExportsOnly,
    Missing,
    Mismatched,
    #[default]
    Unverified,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CauseStatus {
    Confirmed,
    Hypothesis,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContextSource {
    Exception,
    Initial,
    OtherThread,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnwindStatus {
    Reported,
    Unreliable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportIdentity {
    pub dump_id: String,
    pub input_sha256: String,
    pub kind: String,
    pub analyzer_name: String,
    pub analyzer_version: String,
}

impl ReportIdentity {
    pub fn job(&self) -> JobIdentity {
        JobIdentity {
            dump_id: self.dump_id.clone(),
            input_sha256: self.input_sha256.clone(),
            kind: self.kind.clone(),
            analyzer_version: self.analyzer_version.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    pub provider: String,
    pub debugger_version: Option<String>,
    pub architecture: Option<String>,
    pub pointer_width: Option<u32>,
    pub process_id: Option<String>,
    pub model: Option<String>,
    pub analysis_revision: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub command: String,
    pub status: CaptureStatus,
    pub text: String,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessViolation {
    pub operation: String,
    pub address: String,
    pub underlying_status: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExceptionRecord {
    pub status: CaptureStatus,
    pub code: Option<String>,
    pub flags: Option<String>,
    pub address: Option<String>,
    pub record_pointer: Option<String>,
    pub parameter_count: Option<u32>,
    pub parameters: Vec<String>,
    pub access: Option<AccessViolation>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultInstruction {
    pub address: String,
    pub bytes: Option<String>,
    pub disassembly: String,
    pub effective_address: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExceptionContext {
    pub source: ContextSource,
    pub thread_id: Option<String>,
    pub registers: BTreeMap<String, String>,
    pub fault_instruction: Option<FaultInstruction>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StackFrame {
    pub index: u32,
    pub instruction_pointer: Option<String>,
    pub stack_pointer: Option<String>,
    pub frame_pointer: Option<String>,
    pub return_address: Option<String>,
    pub module: Option<String>,
    pub module_rva: Option<String>,
    pub function: Option<String>,
    pub displacement: Option<String>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub resolution: SymbolQuality,
    pub unwind: UnwindStatus,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedStack {
    pub thread_id: Option<String>,
    pub status: CaptureStatus,
    pub frames: Vec<StackFrame>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PdbIdentity {
    pub guid: String,
    pub age: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleSymbols {
    pub module: String,
    pub image_base: Option<String>,
    pub image_size: Option<String>,
    pub timestamp: Option<String>,
    pub expected_pdb: Option<PdbIdentity>,
    pub loaded_pdb: Option<PdbIdentity>,
    pub pdb_path: Option<String>,
    pub quality: SymbolQuality,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SymbolEvidence {
    pub modules: Vec<ModuleSymbols>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mechanism {
    pub status: CauseStatus,
    pub description: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hypothesis {
    pub explanation: String,
    pub evidence_refs: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub next_checks: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootCause {
    pub status: CauseStatus,
    pub mechanism: Mechanism,
    pub conclusion: String,
    pub evidence_refs: Vec<String>,
    pub hypotheses: Vec<Hypothesis>,
    pub missing_evidence: Vec<String>,
    pub next_checks: Vec<String>,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Completeness {
    pub omissions: Vec<String>,
    pub truncated: bool,
}

/// Owned capture: survives workspace cleanup; carries no run identity yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportCapture {
    pub provenance: Provenance,
    pub exception: ExceptionRecord,
    pub context: ExceptionContext,
    pub stack: ResolvedStack,
    pub symbols: SymbolEvidence,
    pub root_cause: RootCause,
    pub evidence: Vec<Evidence>,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrashReportV2 {
    pub schema_version: u32,
    pub report_id: String,
    pub identity: ReportIdentity,
    pub outcome: ReportOutcome,
    pub summary: String,
    #[serde(flatten)]
    pub capture: ReportCapture,
}

pub fn stable_id(identity: &ReportIdentity) -> String {
    let fields = [
        &identity.dump_id,
        &identity.input_sha256,
        &identity.kind,
        &identity.analyzer_name,
        &identity.analyzer_version,
    ];
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("r2_{}", hex::encode(hash.finalize()))
}

pub fn legacy_id(identity: &JobIdentity) -> String {
    let mut hash = Sha256::new();
    for field in [
        &identity.dump_id,
        &identity.input_sha256,
        &identity.kind,
        &identity.analyzer_version,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("legacy_{}", hex::encode(hash.finalize()))
}

pub fn digest_json(json: &str) -> String {
    hex::encode(Sha256::digest(json.as_bytes()))
}

impl CrashReportV2 {
    pub fn from_output(
        identity: &JobIdentity,
        analyzer_name: &str,
        output: &RunOutput,
    ) -> Result<Self> {
        let identity = ReportIdentity {
            dump_id: identity.dump_id.clone(),
            input_sha256: identity.input_sha256.clone(),
            kind: identity.kind.clone(),
            analyzer_name: analyzer_name.to_owned(),
            analyzer_version: identity.analyzer_version.clone(),
        };
        let mut capture = output.capture.clone().unwrap_or_default();
        if output.capture.is_none() {
            capture.provenance.provider = "legacy-adapter".into();
            capture
                .completeness
                .omissions
                .push("Runner did not capture detailed forensic evidence".into());
            capture.root_cause.conclusion =
                "Underlying cause is unknown; detailed evidence was not captured".into();
            capture
                .root_cause
                .next_checks
                .push("Reanalyze with a rich-report capture provider".into());
        }
        let report = Self {
            schema_version: SCHEMA_VERSION,
            report_id: stable_id(&identity),
            identity,
            outcome: output.outcome,
            summary: output.summary.chars().take(2000).collect(),
            capture,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn canonical_json(&self) -> Result<String> {
        // Value uses ordered maps: deterministic recursive key ordering across structs.
        serde_json::to_value(self)
            .and_then(|v| serde_json::to_string(&v))
            .map_err(|e| invalid(&e.to_string()))
    }

    pub fn digest(&self) -> Result<String> {
        Ok(digest_json(&self.canonical_json()?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION || self.report_id != stable_id(&self.identity) {
            return Err(invalid("schema or stable report ID mismatch"));
        }
        if self.identity.input_sha256.len() != 64
            || !self
                .identity
                .input_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(invalid("input hash must be lowercase SHA-256"));
        }
        if [
            &self.identity.dump_id,
            &self.identity.kind,
            &self.identity.analyzer_name,
            &self.identity.analyzer_version,
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
        {
            return Err(invalid("invalid identity field"));
        }
        if self.capture.stack.frames.len() > MAX_FRAMES
            || self.capture.symbols.modules.len() > MAX_MODULES
            || self.capture.evidence.len() > MAX_EVIDENCE
        {
            return Err(invalid("capture count limit exceeded"));
        }
        let mut ids = HashSet::new();
        for e in &self.capture.evidence {
            if e.id.is_empty()
                || e.id.len() > 80
                || !ids.insert(e.id.as_str())
                || e.text.len() > MAX_SECTION_BYTES
            {
                return Err(invalid(
                    "invalid/duplicate evidence ID or section budget exceeded",
                ));
            }
        }
        // Walk all nested reference arrays, including optional instruction and hypotheses.
        fn refs(value: &serde_json::Value, ids: &HashSet<&str>) -> Result<()> {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, v) in map {
                        if key == "evidenceRefs" {
                            for reference in v
                                .as_array()
                                .ok_or_else(|| invalid("evidenceRefs must be an array"))?
                            {
                                if !reference.as_str().is_some_and(|id| ids.contains(id)) {
                                    return Err(invalid("reference to uncaptured evidence"));
                                }
                            }
                        } else {
                            refs(v, ids)?;
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for v in values {
                        refs(v, ids)?;
                    }
                }
                _ => (),
            }
            Ok(())
        }
        refs(
            &serde_json::to_value(&self.capture).map_err(|e| invalid(&e.to_string()))?,
            &ids,
        )?;
        fn hex_values(value: &serde_json::Value, key: &str) -> Result<()> {
            const HEX_FIELDS: &[&str] = &[
                "code",
                "flags",
                "address",
                "recordPointer",
                "instructionPointer",
                "stackPointer",
                "framePointer",
                "returnAddress",
                "moduleRva",
                "displacement",
                "imageBase",
                "imageSize",
                "timestamp",
                "effectiveAddress",
                "underlyingStatus",
            ];
            match value {
                serde_json::Value::String(text)
                    if HEX_FIELDS.contains(&key)
                        || key == "parameters"
                        || key == "registerValue" =>
                {
                    let digits = text.strip_prefix("0x").ok_or_else(|| {
                        invalid("addresses and exception values require hexadecimal strings")
                    })?;
                    if digits.is_empty()
                        || digits.len() > 16
                        || !digits
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        return Err(invalid("noncanonical hexadecimal value"));
                    }
                }
                serde_json::Value::Object(map) => {
                    for (field, v) in map {
                        hex_values(
                            v,
                            if key == "registers" {
                                "registerValue"
                            } else {
                                field
                            },
                        )?;
                    }
                }
                serde_json::Value::Array(values) => {
                    for v in values {
                        hex_values(v, key)?;
                    }
                }
                _ => (),
            }
            Ok(())
        }
        hex_values(
            &serde_json::to_value(&self.capture).map_err(|e| invalid(&e.to_string()))?,
            "",
        )?;
        crate::assessment::validate(&self.capture)?;
        if self.capture.exception.status == CaptureStatus::Present
            && self.capture.exception.parameter_count.map(|n| n as usize)
                != Some(self.capture.exception.parameters.len())
        {
            return Err(invalid(
                "present exception parameter count must match retained parameters",
            ));
        }
        for hypothesis in &self.capture.root_cause.hypotheses {
            if hypothesis.evidence_refs.is_empty()
                || hypothesis.missing_evidence.is_empty()
                || hypothesis.next_checks.is_empty()
            {
                return Err(invalid(
                    "each hypothesis requires captured evidence, a missing causal link and a next check",
                ));
            }
        }
        for module in &self.capture.symbols.modules {
            if module.quality == SymbolQuality::Matched
                && (module.expected_pdb.is_none()
                    || module.expected_pdb != module.loaded_pdb
                    || module.evidence_refs.is_empty())
            {
                return Err(invalid(
                    "matched symbols require equal expected and loaded PDB identities",
                ));
            }
        }
        for frame in &self.capture.stack.frames {
            if frame.resolution == SymbolQuality::Matched
                && (frame.evidence_refs.is_empty()
                    || !self.capture.symbols.modules.iter().any(|m| {
                        Some(&m.module) == frame.module.as_ref()
                            && m.quality == SymbolQuality::Matched
                    }))
            {
                return Err(invalid("matched frame requires a matched module identity"));
            }
        }
        if self.canonical_json()?.len() > MAX_REPORT_BYTES {
            return Err(invalid("canonical report exceeds 512 KiB"));
        }
        Ok(())
    }

    /// Reserved projection fields never enter the legacy lossy shrinker.
    pub fn compact_output(&self) -> Result<RunOutput> {
        Ok(RunOutput {
            outcome: self.outcome,
            summary: self.summary.clone(),
            facts: json!({"schemaVersion":2,"reportId":self.report_id,"reportDigest":self.digest()?,"exceptionCode":self.capture.exception.code,"frameCount":self.capture.stack.frames.len(),"causeStatus":self.capture.root_cause.status}),
            capture: None,
        })
    }
}

fn invalid(message: &str) -> AnalyzerError {
    AnalyzerError::Integrity(format!("report v2: {message}"))
}
