//! Evidence-bound deterministic assessment. Fault mechanism and origin are
//! separate: an access violation does not establish use-after-free or blame.
use crate::report::{
    CaptureStatus, CauseStatus, ContextSource, Mechanism, ReportCapture, RootCause,
};
use crate::types::{AnalyzerError, Result};

fn address(text: &str) -> Option<u64> {
    u64::from_str_radix(&text.trim().trim_start_matches("0x").replace('`', ""), 16).ok()
}

/// The first deliberately narrow rule checks a simple register-indirect MOV
/// read. It proves the immediate memory-access mechanism, never its origin.
fn checked_mechanism(capture: &ReportCapture) -> Option<Mechanism> {
    if capture.context.source != ContextSource::Exception {
        return None;
    }
    let exception = &capture.exception;
    if exception.code.as_deref() != Some("0xc0000005") {
        return None;
    }
    let access = exception.access.as_ref()?;
    if access.operation != "read" {
        return None;
    }
    let instruction = capture.context.fault_instruction.as_ref()?;
    if address(&instruction.address)? != address(exception.address.as_deref()?)? {
        return None;
    }
    let code = instruction.disassembly.to_ascii_lowercase();
    let (mnemonic, operands) = code.split_once(char::is_whitespace)?;
    if mnemonic != "mov" {
        return None;
    }
    let (destination, source) = operands.split_once(',')?;
    if destination.contains('[') {
        return None;
    }
    let destination = destination.trim();
    if ![
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "eax", "ebx", "ecx", "edx", "esi",
        "edi", "ebp", "esp", "ax", "bx", "cx", "dx", "si", "di", "al", "bl", "cl", "dl", "r8",
        "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r8d", "r9d", "r10d", "r11d", "r12d",
        "r13d", "r14d", "r15d",
    ]
    .contains(&destination)
    {
        return None;
    }
    let start = source.find('[')?;
    if source[..start].contains(':') {
        return None;
    }
    let end = source[start + 1..].find(']')? + start + 1;
    let register = source[start + 1..end].trim();
    // Expressions, segment overrides, vector accesses, and implicit operands
    // need separate reviewed rules. Do not infer them from a nearby address.
    if !register.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let value = capture.context.registers.get(register)?;
    if address(value)? != address(&access.address)? {
        return None;
    }
    if exception.evidence_refs.is_empty()
        || instruction.evidence_refs.is_empty()
        || capture.context.evidence_refs.is_empty()
    {
        return None;
    }
    let mut evidence_refs = exception.evidence_refs.clone();
    evidence_refs.extend(capture.context.evidence_refs.iter().cloned());
    evidence_refs.extend(instruction.evidence_refs.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();
    if evidence_refs.iter().any(|id| {
        !capture
            .evidence
            .iter()
            .any(|e| e.id == *id && e.status == CaptureStatus::Present && !e.truncated)
    }) {
        return None;
    }
    Some(Mechanism {
        status: CauseStatus::Confirmed,
        description: format!(
            "The saved exception instruction reads through {register} at {}, matching the access-violation target {}. This establishes the immediate faulting read; the origin of the pointer is not established.",
            value, access.address
        ),
        evidence_refs,
    })
}

pub fn assess(capture: &ReportCapture) -> RootCause {
    let mechanism = checked_mechanism(capture).unwrap_or_else(|| {
        let (description, evidence_refs) = match &capture.exception.access {
            Some(access) => (format!("The exception record reports an invalid {} at {}. Instruction and register evidence do not independently establish the complete access mechanism.", access.operation, access.address), capture.exception.evidence_refs.clone()),
            None => ("The available evidence does not establish a fault mechanism.".into(), vec![]),
        };
        Mechanism { status: CauseStatus::Unknown, description, evidence_refs }
    });
    RootCause { status: CauseStatus::Unknown, mechanism, conclusion: "The underlying root cause is unknown. A faulting frame or invalid address alone does not establish the defect that produced it.".into(), missing_evidence: vec!["Source/runtime evidence tracing the faulting state back to its origin".into()], next_checks: vec!["Validate matching application PDB identities and inspect the faulting source location".into(), "Trace the relevant pointer or state lifetime using a controlled reproduction, instrumentation, or a time-travel recording".into()], ..RootCause::default() }
}

/// Structural citations alone never authorize a confirmed cause. No source or
/// runtime origin rule is implemented yet; a model cannot mint one by naming it.
pub fn validate(capture: &ReportCapture) -> Result<()> {
    let invalid = |message: &str| AnalyzerError::Integrity(format!("assessment: {message}"));
    let cause = &capture.root_cause;
    if cause.status == CauseStatus::Confirmed {
        return Err(invalid(
            "confirmed origin requires an implemented independently verified source/runtime rule",
        ));
    }
    if cause.rule_id.is_some() {
        return Err(invalid("unsupported root-cause confirmation rule"));
    }
    if cause.mechanism.status == CauseStatus::Confirmed
        && checked_mechanism(capture).as_ref() != Some(&cause.mechanism)
    {
        return Err(invalid(
            "confirmed mechanism does not match the deterministic instruction/register rule",
        ));
    }
    let ids: std::collections::HashSet<&str> =
        capture.evidence.iter().map(|e| e.id.as_str()).collect();
    let mut refs = cause.evidence_refs.clone();
    refs.extend(cause.mechanism.evidence_refs.iter().cloned());
    for hypothesis in &cause.hypotheses {
        refs.extend(hypothesis.evidence_refs.iter().cloned());
    }
    if refs.iter().any(|id| !ids.contains(id.as_str())) {
        return Err(invalid("reference to uncaptured evidence"));
    }
    if cause.status == CauseStatus::Hypothesis
        && (cause.evidence_refs.is_empty() || cause.missing_evidence.is_empty())
    {
        return Err(invalid(
            "hypothesis requires supporting evidence and missing evidence",
        ));
    }
    Ok(())
}
