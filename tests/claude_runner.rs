//! Fake host processes qualify protocol/deadline behavior without invoking Claude.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dump_analyzer::claude_runner::ClaudeCdbRunner;
use dump_analyzer::report::{CauseStatus, MAX_SECTION_BYTES};
use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::types::{AnalyzerError, RunBounds, RunRequest, ToolRunner};
use serde_json::{Value, json};

const LOG: &str = include_str!("fixtures/report-v2/marked-av.log");
const BOUNDS: RunBounds = RunBounds {
    wall_timeout: Duration::from_secs(3),
    max_output_bytes: 1 << 20,
    max_workspace_bytes: 1 << 21,
};

#[derive(Clone, Default)]
struct FakeTransport {
    puts: Arc<Mutex<Vec<(PathBuf, String)>>>,
    execs: Arc<Mutex<Vec<Vec<String>>>>,
    cdb_delay: Duration,
    cdb_log: Option<String>,
    fail_cdb: bool,
}
#[async_trait::async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        _stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> dump_analyzer::types::Result<TransportOutput> {
        let mut call = vec![program.to_owned()];
        call.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.execs.lock().expect("lock").push(call);
        if program == "cdb" {
            tokio::time::sleep(self.cdb_delay).await;
            if self.fail_cdb {
                return Err(AnalyzerError::Transport("CDB unavailable".into()));
            }
        }
        Ok(TransportOutput {
            status: Some(0),
            stdout: if program == "cdb" {
                self.cdb_log.as_deref().unwrap_or(LOG).as_bytes().to_vec()
            } else {
                vec![]
            },
            stderr: vec![],
        })
    }
    async fn put_file(&self, local: &Path, remote: &str) -> dump_analyzer::types::Result<()> {
        self.puts
            .lock()
            .expect("lock")
            .push((local.to_owned(), remote.to_owned()));
        Ok(())
    }
}

fn request(dir: &Path) -> (RunRequest, PathBuf) {
    let dump = dir.join("dump.dmp");
    std::fs::write(&dump, b"authored dummy dump; no RSDS module identity").expect("dump");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).expect("work");
    (
        RunRequest {
            dump_path: dump,
            symbol_path: "SRV*C:/symcache*https://ledger.example.test/symbols".into(),
            work_dir: work.clone(),
            bounds: BOUNDS,
        },
        work,
    )
}

/// The fake consumes the initial user message and records protocol traffic in
/// its parent workspace. Its own isolated process directory is removed later.
fn fake_host(dir: &Path, body: &str) -> PathBuf {
    let script = dir.join("fake-host.py");
    std::fs::write(
        &script,
        format!(
            r#"#!/usr/bin/env python3
import sys, json, os, time
from pathlib import Path
base = Path.cwd().parent
(base / 'argv.json').write_text(json.dumps(sys.argv[1:]))
initial = sys.stdin.readline()
(base / 'input.json').write_text(initial)
{body}
"#
        ),
    )
    .expect("script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    script
}
fn candidate() -> Value {
    json!({
        "status":"hypothesis",
        "mechanism":{"status":"unknown","description":"Preserve deterministic mechanism","evidenceRefs":[]},
        "conclusion":"A caller supplied an invalid pointer; its origin remains a hypothesis.",
        "evidenceRefs":["exception"],
        "hypotheses":[{"explanation":"Invalid state may have reached the call site","evidenceRefs":["exception"],"missingEvidence":["State origin"],"nextChecks":["Trace pointer lifetime"]}],
        "missingEvidence":["State origin"],"nextChecks":["Trace pointer lifetime"],"ruleId":null
    })
}
fn result_event(cause: &Value) -> String {
    json!({"type":"result","subtype":"success","is_error":false,"result":cause.to_string()})
        .to_string()
}
fn print_event(event: &str) -> String {
    format!("print({}, flush=True)", json!(event))
}
fn runner(transport: FakeTransport, binary: &Path) -> ClaudeCdbRunner<FakeTransport> {
    ClaudeCdbRunner::new(
        transport,
        "windows-dev",
        binary.to_string_lossy().into_owned(),
    )
}

#[tokio::test]
async fn deterministic_capture_precedes_host_and_model_cannot_replace_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = fake_host(
        dir.path(),
        &format!(
            "{}\ntime.sleep(30)",
            print_event(&result_event(&candidate()))
        ),
    );
    let transport = FakeTransport::default();
    let (req, work) = request(dir.path());
    let reference = SshCdbRunner::new(FakeTransport::default())
        .run(req.clone())
        .await
        .expect("capture");
    let started = Instant::now();
    let output = runner(transport.clone(), &bin)
        .with_remote_base("C:/da/test")
        .with_model(Some("fixture-model".into()))
        .run(req)
        .await
        .expect("report");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "persistent child ended after result"
    );
    let capture = output.capture.expect("owned capture");
    let expected = reference.capture.expect("reference capture");
    assert_eq!(capture.exception, expected.exception);
    assert_eq!(capture.context, expected.context);
    assert_eq!(capture.stack, expected.stack);
    assert_eq!(capture.symbols, expected.symbols);
    assert_eq!(capture.root_cause.mechanism, expected.root_cause.mechanism);
    assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
    assert_eq!(capture.provenance.provider, "claude-cdb");
    assert_eq!(capture.provenance.model.as_deref(), Some("fixture-model"));
    assert!(
        capture
            .evidence
            .iter()
            .any(|item| item.id == "assessment-model")
    );
    assert_eq!(output.outcome, reference.outcome);
    let staged = transport.puts.lock().expect("puts");
    assert_eq!(
        staged
            .iter()
            .filter(|(_, remote)| remote.ends_with("/dump.dmp"))
            .count(),
        1,
        "the deterministic collector stages one pinned dump"
    );
    assert!(
        staged
            .iter()
            .any(|(_, remote)| remote.ends_with("/triage.cdb"))
    );
    assert!(
        staged
            .iter()
            .all(|(_, remote)| remote.starts_with("C:/da/test/"))
    );
    let calls = transport.execs.lock().expect("calls");
    assert!(calls.iter().any(|call| call[0] == "cdb"));
    assert!(calls.iter().any(|call| call[0] == "rm"));
    let args: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(work.join("argv.json")).expect("args"))
            .expect("JSON args");
    for pair in [
        ["--input-format", "stream-json"],
        ["--output-format", "stream-json"],
        ["--permission-prompt-tool", "stdio"],
        ["--permission-mode", "default"],
        ["--tools", ""],
        ["--setting-sources", ""],
    ] {
        assert!(
            args.windows(2)
                .any(|args| args[0] == pair[0] && args[1] == pair[1]),
            "missing {pair:?}"
        );
    }
    assert!(
        !args
            .iter()
            .any(|arg| arg.contains("Bash(ssh:") || arg == "--dangerously-skip-permissions")
    );
    assert!(
        !args.iter().any(|arg| arg == "--json-schema"),
        "schema enforcement must not introduce an internal formatting tool"
    );
    let initial: Value =
        serde_json::from_str(&std::fs::read_to_string(work.join("input.json")).expect("input"))
            .expect("message");
    let prompt = initial["message"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(prompt.contains("untrusted data"));
    assert!(prompt.contains("OUTPUT_SCHEMA_JSON:"));
    assert!(prompt.contains("within 6000 UTF-8 bytes"));
    assert!(prompt.contains("at most 3 hypotheses"));
    assert!(prompt.contains("host preserves the deterministic immediate mechanism"));
    assert!(prompt.contains("command names, field paths, and frame numbers are not evidence IDs"));
    assert!(prompt.contains("\"missingEvidence\""));
    assert!(prompt.contains("ExceptionCode: c0000005"));
    let (_, schema_and_evidence) = prompt
        .split_once("OUTPUT_SCHEMA_JSON:\n")
        .expect("schema marker");
    let (schema_json, allowed_and_evidence) = schema_and_evidence
        .split_once("\n\nALLOWED_EVIDENCE_IDS_JSON:\n")
        .expect("allowed evidence marker");
    let (allowed_json, captured_json) = allowed_and_evidence
        .split_once("\n\nCAPTURED_EVIDENCE_JSON:\n")
        .expect("capture marker");
    let schema: Value = serde_json::from_str(schema_json).expect("valid output schema");
    let allowed: Value = serde_json::from_str(allowed_json).expect("allowed evidence IDs");
    let expected_ids = json!(
        expected
            .evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(allowed, expected_ids);
    for path in [
        "/properties/evidenceRefs/items",
        "/properties/mechanism/properties/evidenceRefs/items",
        "/properties/hypotheses/items/properties/evidenceRefs/items",
    ] {
        let items = schema.pointer(path).expect("citation schema");
        assert_eq!(items["type"], "string");
        assert_eq!(items["enum"], expected_ids, "only retained IDs at {path}");
    }
    let supplied_capture: Value = serde_json::from_str(captured_json).expect("capture JSON");
    let supplied_ids = json!(
        supplied_capture["evidence"]
            .as_array()
            .expect("evidence array")
            .iter()
            .map(|item| item["id"].as_str().expect("evidence ID"))
            .collect::<Vec<_>>()
    );
    assert_eq!(supplied_ids, allowed);
    assert!(
        std::fs::read_dir(&work).expect("work").all(|entry| !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with("reasoner-")),
        "private process directory removed"
    );
}

#[tokio::test]
async fn model_mechanism_is_discarded_before_validating_causal_hypotheses() {
    for (cdb_log, expected_mechanism_status) in [
        (None, CauseStatus::Confirmed),
        (
            Some(LOG.replace("rcx=0000000000000000", "rcx=0000000000000008")),
            CauseStatus::Unknown,
        ),
    ] {
        let dir = tempfile::tempdir().expect("directory");
        let mut cause = candidate();
        cause["mechanism"] = json!({
            "status":"confirmed",
            "description":"Model-authored mechanism paraphrase must never be retained",
            "evidenceRefs":["exception", "never-captured-mechanism"]
        });
        let binary = fake_host(dir.path(), &print_event(&result_event(&cause)));
        let transport = FakeTransport {
            cdb_log,
            ..FakeTransport::default()
        };
        let (request, _) = request(dir.path());
        let expected = SshCdbRunner::new(transport.clone())
            .run(request.clone())
            .await
            .expect("reference capture")
            .capture
            .expect("capture");
        assert_eq!(
            expected.root_cause.mechanism.status,
            expected_mechanism_status
        );
        let capture = runner(transport, &binary)
            .run(request)
            .await
            .expect("reasoned report")
            .capture
            .expect("capture");
        assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
        assert_eq!(capture.root_cause.mechanism, expected.root_cause.mechanism);
        assert_eq!(capture.exception, expected.exception);
        assert_eq!(capture.context, expected.context);
        assert_eq!(capture.stack, expected.stack);
        assert_eq!(capture.symbols, expected.symbols);
        assert_eq!(capture.completeness, expected.completeness);
        assert_eq!(capture.evidence.len(), expected.evidence.len() + 1);
        assert_eq!(
            capture.evidence[..expected.evidence.len()],
            expected.evidence
        );
        let model_evidence = capture.evidence.last().expect("model evidence");
        assert_eq!(model_evidence.id, "assessment-model");
        let accepted: Value = serde_json::from_str(&model_evidence.text).expect("assessment JSON");
        cause["mechanism"] =
            serde_json::to_value(&expected.root_cause.mechanism).expect("trusted mechanism");
        assert_eq!(
            accepted, cause,
            "only the trusted mechanism replaces model output"
        );
        assert_eq!(
            serde_json::to_value(&capture.root_cause).expect("accepted cause"),
            cause
        );
        dump_analyzer::assessment::validate(&capture).expect("accepted assessment proof gate");
    }
}

#[tokio::test]
async fn host_denies_control_requests_while_stdin_remains_open() {
    let dir = tempfile::tempdir().expect("directory");
    let control_request = json!({"type":"control_request","request_id":"attempt-shell","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"touch should-never-exist"}}}).to_string();
    let body = format!(
        "{}\nreply = sys.stdin.readline()\n(base / 'reply.json').write_text(reply)\nassert json.loads(reply)['response']['response']['behavior'] == 'deny'\n{}\ntime.sleep(30)",
        print_event(&control_request),
        print_event(&result_event(&candidate()))
    );
    let bin = fake_host(dir.path(), &body);
    let (req, work) = request(dir.path());
    let output = runner(FakeTransport::default(), &bin)
        .run(req)
        .await
        .expect("report");
    assert_eq!(
        output.capture.expect("capture").root_cause.status,
        CauseStatus::Hypothesis
    );
    let reply: Value =
        serde_json::from_str(&std::fs::read_to_string(work.join("reply.json")).expect("reply"))
            .expect("JSON");
    assert_eq!(reply["response"]["request_id"], "attempt-shell");
    assert_eq!(reply["response"]["response"]["behavior"], "deny");
    assert!(!work.join("should-never-exist").exists());
}

#[tokio::test]
async fn malformed_unavailable_and_invalid_causal_results_preserve_capture() {
    let mut unsupported = candidate();
    unsupported["status"] = json!("confirmed");
    // Plausible but invalid causal assertion cites a real captured section.
    unsupported["conclusion"] = json!("The null target proves a use-after-free caused by V8");
    let mut fabricated = candidate();
    fabricated["evidenceRefs"] = json!(["never-captured"]);
    let mut unsupported_rule = candidate();
    unsupported_rule["ruleId"] = json!("model-invented-origin-rule");
    let mut fabricated_hypothesis = candidate();
    fabricated_hypothesis["hypotheses"][0]["evidenceRefs"] = json!(["never-captured"]);
    for (index, event) in [
        "not JSON".to_owned(),
        json!({"type":"result","is_error":true}).to_string(),
        result_event(&unsupported),
        result_event(&fabricated),
        result_event(&unsupported_rule),
        result_event(&fabricated_hypothesis),
    ]
    .iter()
    .enumerate()
    {
        let dir = tempfile::tempdir().expect("directory");
        let bin = fake_host(
            dir.path(),
            &format!(
                "{}\nfollowup = sys.stdin.readline()\nif followup: (base / 'unexpected-correction.json').write_text(followup)\ntime.sleep(30)",
                print_event(event)
            ),
        );
        let (req, work) = request(dir.path());
        let started = Instant::now();
        let output = runner(FakeTransport::default(), &bin)
            .run(req)
            .await
            .expect("deterministic report survives");
        assert!(started.elapsed() < Duration::from_secs(2), "case {index}");
        assert!(
            !work.join("unexpected-correction.json").exists(),
            "case {index}"
        );
        let capture = output.capture.expect("capture");
        assert_eq!(
            capture.exception.code.as_deref(),
            Some("0xc0000005"),
            "case {index}"
        );
        assert!(!capture.stack.frames.is_empty(), "case {index}");
        assert_eq!(
            capture.root_cause.status,
            CauseStatus::Unknown,
            "case {index}"
        );
        assert!(
            capture
                .completeness
                .omissions
                .iter()
                .any(|line| line.contains("Optional causal reasoning unavailable")),
            "case {index}"
        );
    }
}

#[tokio::test]
async fn one_formatting_correction_accepts_valid_result_and_preserves_capture() {
    let mut oversized = candidate();
    oversized["conclusion"] = json!("do-not-echo-rejected".repeat(MAX_SECTION_BYTES));
    let malformed = json!({"type":"result","is_error":false,
        "result":"{\"status\" \"do-not-echo-rejected\"}"})
    .to_string();
    let wrong_shape = json!({"type":"result","is_error":false,
        "structured_output":{"conclusion":"do-not-echo-rejected"}})
    .to_string();
    let mut previous_correction = None;
    for first_result in [malformed, wrong_shape, result_event(&oversized)] {
        let dir = tempfile::tempdir().expect("directory");
        let control = json!({"type":"control_request","request_id":"after-correction",
            "request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"touch forbidden"}}}).to_string();
        let binary = fake_host(
            dir.path(),
            &format!(
                "{}\ncorrection = sys.stdin.readline()\n(base / 'correction.json').write_text(correction)\n{}\nreply = sys.stdin.readline()\nassert json.loads(reply)['response']['response']['behavior'] == 'deny'\n{}\ntime.sleep(30)",
                print_event(&first_result),
                print_event(&control),
                print_event(&result_event(&candidate()))
            ),
        );
        let (request, work) = request(dir.path());
        let expected = SshCdbRunner::new(FakeTransport::default())
            .run(request.clone())
            .await
            .expect("reference report")
            .capture
            .expect("reference capture");
        let capture = runner(FakeTransport::default(), &binary)
            .run(request)
            .await
            .expect("corrected report")
            .capture
            .expect("capture");
        assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
        assert_eq!(capture.root_cause.mechanism, expected.root_cause.mechanism);
        assert_eq!(capture.exception, expected.exception);
        assert_eq!(capture.context, expected.context);
        assert_eq!(capture.stack, expected.stack);
        assert_eq!(capture.symbols, expected.symbols);
        assert_eq!(capture.completeness, expected.completeness);
        assert_eq!(capture.evidence.len(), expected.evidence.len() + 1);
        assert_eq!(
            capture.evidence[..expected.evidence.len()],
            expected.evidence
        );
        assert_eq!(
            capture.evidence.last().expect("assessment").id,
            "assessment-model"
        );
        dump_analyzer::assessment::validate(&capture).expect("corrected assessment proof gate");
        let correction: Value = serde_json::from_str(
            &std::fs::read_to_string(work.join("correction.json")).expect("correction"),
        )
        .expect("correction message");
        assert_eq!(correction["type"], "user");
        assert_eq!(correction["message"]["role"], "user");
        let prompt = correction["message"]["content"][0]["text"]
            .as_str()
            .expect("prompt");
        assert!(prompt.contains("within 6000 UTF-8 bytes"));
        assert!(!prompt.contains("do-not-echo-rejected"));
        assert!(!prompt.contains("ExceptionCode"));
        if let Some(previous) = previous_correction.replace(correction.clone()) {
            assert_eq!(
                correction, previous,
                "correction must be static for every format failure"
            );
        }
    }
}

#[tokio::test]
async fn repeated_invalid_assessment_json_falls_back_without_a_second_correction() {
    let dir = tempfile::tempdir().expect("directory");
    let invalid = json!({"type":"result","is_error":false,"result":"{invalid JSON}"}).to_string();
    let binary = fake_host(
        dir.path(),
        &format!(
            "{}\ncorrection = sys.stdin.readline()\n(base / 'correction.json').write_text(correction)\n{}\nextra = sys.stdin.readline()\nif extra: (base / 'extra-correction.json').write_text(extra)\ntime.sleep(30)",
            print_event(&invalid),
            print_event(&invalid)
        ),
    );
    let (request, work) = request(dir.path());
    let expected = SshCdbRunner::new(FakeTransport::default())
        .run(request.clone())
        .await
        .expect("reference report")
        .capture
        .expect("reference capture");
    let started = Instant::now();
    let capture = runner(FakeTransport::default(), &binary)
        .run(request)
        .await
        .expect("fallback report")
        .capture
        .expect("capture");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(work.join("correction.json").exists());
    assert!(!work.join("extra-correction.json").exists());
    assert_eq!(capture.root_cause, expected.root_cause);
    assert_eq!(capture.evidence, expected.evidence);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("assessment is not JSON"))
    );
}

#[tokio::test]
async fn formatting_correction_keeps_the_original_deadline() {
    let dir = tempfile::tempdir().expect("directory");
    let invalid = json!({"type":"result","is_error":false,"result":"{invalid JSON}"}).to_string();
    let binary = fake_host(
        dir.path(),
        &format!(
            "time.sleep(0.25)\n{}\ncorrection = sys.stdin.readline()\n(base / 'correction.json').write_text(correction)\ntime.sleep(0.35)\n{}",
            print_event(&invalid),
            print_event(&result_event(&candidate()))
        ),
    );
    let (mut request, work) = request(dir.path());
    request.bounds.wall_timeout = Duration::from_millis(450);
    let started = Instant::now();
    let capture = runner(FakeTransport::default(), &binary)
        .run(request)
        .await
        .expect("bounded report")
        .capture
        .expect("capture");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(work.join("correction.json").exists());
    assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("wall timeout"))
    );
}

#[tokio::test]
async fn formatting_correction_keeps_the_cumulative_output_budget() {
    let dir = tempfile::tempdir().expect("directory");
    let invalid = json!({"type":"result","is_error":false,"result":"x".repeat(20_000)}).to_string();
    let extra_output = json!({"type":"assistant","padding":"x".repeat(20_000)}).to_string();
    let binary = fake_host(
        dir.path(),
        &format!(
            "{}\ncorrection = sys.stdin.readline()\n(base / 'correction.json').write_text(correction)\n{}\n{}\ntime.sleep(30)",
            print_event(&invalid),
            print_event(&extra_output),
            print_event(&result_event(&candidate()))
        ),
    );
    let (mut request, work) = request(dir.path());
    request.bounds.max_output_bytes = 32 << 10;
    let capture = runner(FakeTransport::default(), &binary)
        .run(request)
        .await
        .expect("bounded report")
        .capture
        .expect("capture");
    assert!(work.join("correction.json").exists());
    assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("stdout/stderr budget"))
    );
}

#[tokio::test]
async fn eof_before_process_exit_is_bounded_and_keeps_collected_report() {
    let dir = tempfile::tempdir().expect("directory");
    let bin = fake_host(dir.path(), "os.close(1)\nos.close(2)\ntime.sleep(30)");
    let (mut req, _) = request(dir.path());
    req.bounds.wall_timeout = Duration::from_millis(250);
    let started = Instant::now();
    let output = runner(FakeTransport::default(), &bin)
        .run(req)
        .await
        .expect("report");
    assert!(started.elapsed() < Duration::from_secs(2));
    let capture = output.capture.expect("capture");
    assert_eq!(capture.exception.code.as_deref(), Some("0xc0000005"));
    assert!(
        capture
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("wall timeout"))
    );
}

#[tokio::test]
async fn concurrent_stderr_drain_prevents_pipe_deadlock_and_enforces_output_budget() {
    for cap in [1 << 20, 16 << 10] {
        let dir = tempfile::tempdir().expect("directory");
        let bin = fake_host(
            dir.path(),
            &format!(
                "os.write(2,b'x'*(256*1024))\n{}",
                print_event(&result_event(&candidate()))
            ),
        );
        let (mut req, _) = request(dir.path());
        req.bounds.max_output_bytes = cap;
        let started = Instant::now();
        let output = runner(FakeTransport::default(), &bin)
            .run(req)
            .await
            .expect("report");
        assert!(started.elapsed() < Duration::from_secs(2));
        let capture = output.capture.expect("capture");
        assert_eq!(capture.exception.code.as_deref(), Some("0xc0000005"));
        if cap > 256 * 1024 {
            assert_eq!(capture.root_cause.status, CauseStatus::Hypothesis);
        } else {
            assert!(
                capture
                    .completeness
                    .omissions
                    .iter()
                    .any(|line| line.contains("stdout/stderr budget"))
            );
        }
    }
}

#[tokio::test]
async fn collection_and_reasoning_share_one_deadline() {
    let dir = tempfile::tempdir().expect("directory");
    let bin = fake_host(dir.path(), "time.sleep(30)");
    let (mut req, _) = request(dir.path());
    req.bounds.wall_timeout = Duration::from_millis(300);
    let transport = FakeTransport {
        cdb_delay: Duration::from_millis(150),
        ..FakeTransport::default()
    };
    let started = Instant::now();
    let output = runner(transport, &bin)
        .run(req)
        .await
        .expect("retained evidence");
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "stage deadlines must not add"
    );
    assert!(
        output
            .capture
            .expect("capture")
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("wall timeout"))
    );
}

#[tokio::test]
async fn missing_model_binary_keeps_evidence_but_collection_failure_is_still_runner_error() {
    let dir = tempfile::tempdir().expect("directory");
    let (req, _) = request(dir.path());
    let output = runner(
        FakeTransport::default(),
        Path::new("/nonexistent/claude-bin"),
    )
    .run(req.clone())
    .await
    .expect("deterministic fallback");
    assert_eq!(
        output.capture.expect("capture").exception.code.as_deref(),
        Some("0xc0000005")
    );
    let err = runner(
        FakeTransport {
            fail_cdb: true,
            ..FakeTransport::default()
        },
        Path::new("/nonexistent/claude-bin"),
    )
    .run(req)
    .await
    .expect_err("capture infrastructure failed");
    assert!(matches!(err, AnalyzerError::Runner(_)));
}

#[tokio::test]
async fn unexpected_tool_result_is_rejected_under_deny_all_policy() {
    let dir = tempfile::tempdir().expect("directory");
    let event = json!({"type":"user","message":{"content":[{"type":"tool_result","content":"tool executed without permission"}]}}).to_string();
    let bin = fake_host(dir.path(), &print_event(&event));
    let (req, _) = request(dir.path());
    let output = runner(FakeTransport::default(), &bin)
        .run(req)
        .await
        .expect("deterministic fallback");
    assert!(
        output
            .capture
            .expect("capture")
            .completeness
            .omissions
            .iter()
            .any(|line| line.contains("unexpected tool result"))
    );
}

#[tokio::test]
async fn resolved_model_and_reasoner_revision_survive_optional_reasoning_failure() {
    for (configured, header, valid_result, expected_model) in [
        (
            None,
            json!("claude-resolved-default"),
            true,
            Some("claude-resolved-default"),
        ),
        (
            Some("configured-alias"),
            json!("claude-resolved-override"),
            true,
            Some("claude-resolved-override"),
        ),
        (
            None,
            json!("claude-observed-before-failure"),
            false,
            Some("claude-observed-before-failure"),
        ),
        (
            Some("configured-alias"),
            json!("x".repeat(257)),
            true,
            Some("configured-alias"),
        ),
        (None, json!("hostile\nmodel"), true, None),
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let init = json!({"type":"system","subtype":"init","model":header}).to_string();
        let final_event = if valid_result {
            result_event(&candidate())
        } else {
            "malformed result".into()
        };
        let binary = fake_host(
            directory.path(),
            &format!("{}\n{}", print_event(&init), print_event(&final_event)),
        );
        let (request, _) = request(directory.path());
        let output = runner(FakeTransport::default(), &binary)
            .with_model(configured.map(str::to_owned))
            .run(request)
            .await
            .expect("captured report");
        let capture = output.capture.expect("capture");
        assert_eq!(capture.provenance.model.as_deref(), expected_model);
        assert!(
            capture
                .provenance
                .analysis_revision
                .contains("deterministic-cdb-")
        );
        assert!(
            capture
                .provenance
                .analysis_revision
                .contains("reasoner=claude-host-v2.3")
        );
        assert_eq!(capture.exception.code.as_deref(), Some("0xc0000005"));
        if !valid_result {
            assert_eq!(capture.root_cause.status, CauseStatus::Unknown);
            assert!(
                capture
                    .completeness
                    .omissions
                    .iter()
                    .any(|omission| omission.contains("Optional causal reasoning unavailable"))
            );
        }
    }
}

#[tokio::test]
async fn provider_error_results_keep_bounded_actionable_diagnostics() {
    let directory = tempfile::tempdir().expect("directory");
    let event = json!({"type":"result","subtype":"error_max_turns","is_error":true,
        "errors":[format!("Formatting tool denied\n{}","x".repeat(2000))],"result":"No final response"}).to_string();
    let binary = fake_host(directory.path(), &print_event(&event));
    let (request, _) = request(directory.path());
    let output = runner(FakeTransport::default(), &binary)
        .run(request)
        .await
        .expect("capture retained");
    let capture = output.capture.expect("capture");
    let omission = capture
        .completeness
        .omissions
        .iter()
        .find(|omission| omission.contains("Optional causal reasoning unavailable"))
        .expect("reasoning limitation");
    assert!(omission.contains("subtype=error_max_turns"));
    assert!(omission.contains("Formatting tool denied"));
    assert!(omission.contains("No final response"));
    assert!(!omission.contains('\n'));
    assert!(omission.len() < 700);
    assert_eq!(capture.exception.code.as_deref(), Some("0xc0000005"));
}

/// Explicit operator qualification: deterministic acquisition is fully fake,
/// and the real model receives only the authored, committed text fixture.
/// No SSH process or real dump transfer is possible through FakeTransport.
#[tokio::test]
#[ignore = "requires authenticated Claude; sends only authored fixture evidence"]
async fn live_reasoner_over_synthetic_fixture_without_remote_dump_transfer() {
    fn bounded_setting(name: &str, default: u64, maximum: u64) -> u64 {
        let value = match std::env::var(name) {
            Ok(raw) => raw.parse::<u64>().unwrap_or_else(|_| panic!("{name}")),
            Err(std::env::VarError::NotPresent) => default,
            Err(_) => panic!("{name}"),
        };
        assert!((1..=maximum).contains(&value), "{name}");
        value
    }

    let directory = tempfile::tempdir().expect("directory");
    let (mut request, _) = request(directory.path());
    let wall_timeout_ms =
        bounded_setting("DUMP_ANALYZER_LIVE_TEST_WALL_TIMEOUT_MS", 120_000, 600_000);
    request.bounds.wall_timeout = Duration::from_millis(wall_timeout_ms);
    request.bounds.max_output_bytes =
        bounded_setting("DUMP_ANALYZER_LIVE_TEST_MAX_OUTPUT_BYTES", 1 << 20, 8 << 20) as usize;
    let requested_bounds = json!({
        "wallTimeoutMs": wall_timeout_ms,
        "maxOutputBytes": request.bounds.max_output_bytes,
        "maxWorkspaceBytes": request.bounds.max_workspace_bytes,
    });
    let output = runner(FakeTransport::default(), Path::new("claude"))
        .run(request)
        .await
        .expect("deterministic fixture capture");
    let capture = output.capture.expect("owned capture");
    assert!(
        capture.provenance.model.is_some(),
        "actual model must be recorded"
    );
    assert!(
        capture
            .evidence
            .iter()
            .any(|entry| entry.id == "assessment-model"),
        "Actual reasoning did not complete: {:?}",
        capture.completeness.omissions
    );
    assert_ne!(capture.root_cause.status, CauseStatus::Confirmed);
    dump_analyzer::assessment::validate(&capture).expect("actual assessment proof gate");
    if let Some(path) = std::env::var_os("DUMP_ANALYZER_LIVE_TEST_OUTPUT") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("new isolated qualification receipt");
        let receipt = json!({"qualification":"Authored synthetic debugger fixture with actual deny-all Claude host; no SSH or dump transfer", "requestedBounds":requested_bounds, "capture":capture});
        std::io::Write::write_all(
            &mut file,
            serde_json::to_string_pretty(&receipt)
                .expect("receipt")
                .as_bytes(),
        )
        .expect("write receipt");
    }
}
