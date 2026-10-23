//! Local subprocess tests. The optional native test uses synthetic files only.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dump_analyzer::analysis_tools::{AnalysisTools, CdbSession};
use dump_analyzer::forensicator::ForensicatorTools;
use dump_analyzer::report::{CaptureStatus, MAX_SECTION_BYTES};
use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::types::{Result, RunBounds, RunRequest};
use serde_json::{Value, json};
use tokio::time::Instant;

#[derive(Clone)]
struct Debugger;

#[async_trait::async_trait]
impl ExecTransport for Debugger {
    async fn exec(
        &self,
        program: &str,
        _: &[&str],
        stdin: Option<&[u8]>,
        _: Duration,
    ) -> Result<TransportOutput> {
        let stdout = if program != "cdb" {
            String::new()
        } else if let Some(script) = stdin {
            let script = String::from_utf8_lossy(script);
            let marker = |prefix: &str| {
                script
                    .lines()
                    .find(|line| line.starts_with(prefix))
                    .unwrap()
                    .trim_start_matches(".echo ")
            };
            format!(
                "{}\n00001000  01 02 03 04\n{}\n",
                marker(".echo DA_QUERY_BEGIN:"),
                marker(".echo DA_QUERY_END:")
            )
        } else {
            include_str!("fixtures/report-v2/marked-av.log").into()
        };
        Ok(TransportOutput {
            status: Some(0),
            stdout: stdout.into_bytes(),
            stderr: vec![],
        })
    }
    async fn put_file(&self, _: &Path, _: &str) -> Result<()> {
        Ok(())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    request: RunRequest,
    session: Arc<CdbSession<Debugger>>,
    tools: Arc<ForensicatorTools>,
}

impl Fixture {
    async fn new(mode: &str, output_cap: usize, wall: Duration, native: Option<PathBuf>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("work");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("mode"), mode).unwrap();
        if mode == "javascript" {
            std::fs::write(
                workspace.join("javascript.json"),
                include_str!("fixtures/forensicator-v8-jit.json"),
            )
            .unwrap();
        }
        let bin = native.unwrap_or_else(|| {
            let bin = root.path().join("fake forensicator");
            std::fs::write(&bin, include_str!("fixtures/forensicator-mcp.py")).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
            bin
        });
        let dump = root.path().join("verified dump.dmp");
        std::fs::write(&dump, b"synthetic capture").unwrap();
        let request = RunRequest {
            dump_path: dump,
            work_dir: workspace,
            symbol_path: "C:/symbols".into(),
            bounds: RunBounds {
                wall_timeout: wall,
                max_output_bytes: output_cap,
                max_workspace_bytes: 1024 * 1024,
            },
        };
        let deadline = Instant::now() + wall;
        let (_, session) = SshCdbRunner::new(Debugger)
            .begin_session(request.clone(), deadline)
            .await
            .unwrap();
        let tools = Arc::new(ForensicatorTools::new(
            session.clone(),
            bin,
            &request,
            deadline,
        ));
        Self {
            root,
            request,
            session,
            tools,
        }
    }

    async fn standard(mode: &str) -> Self {
        Self::new(mode, 1024 * 1024, Duration::from_secs(10), None).await
    }

    fn wire(&self) -> Vec<Value> {
        std::fs::read_to_string(self.request.work_dir.join("wire.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn real_stdio_lifecycle_pins_dump_and_retains_all_four_tools() {
    let fixture = Fixture::standard("ok").await;
    let definitions = fixture.tools.definitions();
    assert_eq!(definitions.as_array().unwrap().len(), 11);
    for tool in definitions.as_array().unwrap() {
        assert!(tool["inputSchema"]["properties"].get("path").is_none());
    }
    std::fs::write(fixture.request.work_dir.join("module.pdb"), b"fixture").unwrap();
    std::fs::create_dir(fixture.request.work_dir.join("symbols")).unwrap();
    for (index, (name, arguments)) in [
        ("forensicator_list_plugins", json!({})),
        ("forensicator_inspect", json!({})),
        (
            "forensicator_analyze",
            json!({"plugins":["cause"], "symbols":"symbols"}),
        ),
        ("forensicator_match", json!({"pdbs":["module.pdb"]})),
    ]
    .into_iter()
    .enumerate()
    {
        let evidence = fixture.tools.call(name, arguments).await.unwrap();
        assert_eq!(evidence.status, CaptureStatus::Present, "{evidence:?}");
        assert_eq!(evidence.id, format!("query-{}", index + 1));
        let data: Value = serde_json::from_str(&evidence.text).unwrap();
        assert_eq!(data["confidence"], "unknown");
        assert_eq!(data["overall"], "mismatch");
        if index == 0 {
            assert_eq!(data["arguments"], json!({}));
        } else {
            assert_eq!(data["arguments"]["path"], json!(fixture.request.dump_path));
        }
    }
    let calls = fixture.wire();
    for conversation in calls.chunks_exact(4) {
        assert_eq!(conversation[0]["method"], "initialize");
        assert_eq!(conversation[1]["method"], "notifications/initialized");
        assert_eq!(conversation[2]["method"], "tools/list");
        assert_eq!(conversation[3]["method"], "tools/call");
    }
    assert_eq!(
        calls[15]["params"]["arguments"]["pdbs"],
        json!([fixture.request.work_dir.join("module.pdb")])
    );
    assert_eq!(
        fixture.tools.evidence().await,
        fixture.session.evidence().await
    );
    fixture.session.close().await;
    assert!(
        fixture
            .tools
            .call("forensicator_inspect", json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn debugger_and_forensicator_share_calls_ids_and_output_allowance() {
    let fixture = Fixture::standard("ok").await;
    for _ in 0..7 {
        fixture
            .tools
            .call("forensicator_inspect", json!({}))
            .await
            .unwrap();
    }
    let last = fixture
        .tools
        .call("read_memory", json!({"address":"0x1000", "length":4}))
        .await
        .unwrap();
    assert_eq!(last.id, "query-8");
    assert_eq!(last.status, CaptureStatus::Present);
    assert!(
        fixture
            .tools
            .call("forensicator_list_plugins", json!({}))
            .await
            .is_err()
    );
    assert!(
        fixture
            .tools
            .call("read_memory", json!({"address":"0x1000", "length":4}))
            .await
            .is_err()
    );
    fixture.session.close().await;

    let fixture = Fixture::new(
        "retained_limit",
        4 * MAX_SECTION_BYTES,
        Duration::from_secs(10),
        None,
    )
    .await;
    let evidence = fixture
        .tools
        .call("forensicator_inspect", json!({}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Truncated);
    assert!(evidence.truncated && evidence.text.len() <= MAX_SECTION_BYTES);
    assert!(
        fixture
            .tools
            .call("read_memory", json!({"address":"0x1000", "length":4}))
            .await
            .is_err()
    );
    fixture.session.close().await;

    let fixture = Fixture::standard("retained_limit").await;
    let evidence = fixture
        .tools
        .call("forensicator_inspect", json!({}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Truncated);
    assert!(
        evidence.truncated && !evidence.text.is_empty() && evidence.text.len() <= MAX_SECTION_BYTES
    );
    fixture.session.close().await;
}

#[tokio::test]
async fn rejects_dump_override_commands_unbounded_analysis_and_path_escapes() {
    let fixture = Fixture::standard("ok").await;
    for (name, arguments) in [
        ("forensicator_inspect", json!({"path":"/etc/passwd"})),
        ("forensicator_analyze", json!({"plugins":[]})),
        ("forensicator_analyze", json!({"plugins":["cause; bash"]})),
        (
            "forensicator_analyze",
            json!({"plugins":["cause"], "symbols":"../secrets"}),
        ),
        ("forensicator_match", json!({"exes":["/etc/passwd"]})),
        ("forensicator_match", json!({"pdbs":["../other.dmp"]})),
        ("forensicator_match", json!({})),
        ("forensicator_list_plugins", json!({"command":"sh"})),
    ] {
        assert!(fixture.tools.call(name, arguments).await.is_err());
    }
    assert!(
        fixture
            .tools
            .call("forensicator_inspect", json!({}))
            .await
            .is_err(),
        "invalid requests consume all eight attempts"
    );
    assert!(!fixture.request.work_dir.join("wire.jsonl").exists());
    fixture.session.close().await;

    let fixture = Fixture::standard("ok").await;
    let outside = fixture.root.path().join("outside.pdb");
    std::fs::write(&outside, b"private").unwrap();
    std::os::unix::fs::symlink(&outside, fixture.request.work_dir.join("escape.pdb")).unwrap();
    let evidence = fixture
        .tools
        .call("forensicator_match", json!({"pdbs":["escape.pdb"]}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Failed);
    assert!(!fixture.request.work_dir.join("wire.jsonl").exists());
    fixture.session.close().await;
}

#[tokio::test]
async fn protocol_transport_and_tool_failures_are_retained_without_raw_diagnostics() {
    for mode in [
        "bad_version",
        "missing_tools",
        "wrong_id",
        "malformed",
        "rpc_error",
        "wire_limit",
        "tool_error",
    ] {
        let fixture = Fixture::standard(mode).await;
        let evidence = fixture
            .tools
            .call("forensicator_inspect", json!({}))
            .await
            .unwrap();
        assert_eq!(
            evidence.status,
            if mode == "wire_limit" {
                CaptureStatus::Truncated
            } else {
                CaptureStatus::Failed
            },
            "{mode}"
        );
        assert!(!format!("{evidence:?}").contains("secret-do-not-retain"));
        assert_eq!(fixture.tools.evidence().await, vec![evidence]);
        fixture.session.close().await;
    }
    let fixture = Fixture::new(
        "",
        1024 * 1024,
        Duration::from_secs(5),
        Some(PathBuf::from("/nonexistent/forensicator")),
    )
    .await;
    let evidence = fixture
        .tools
        .call("forensicator_inspect", json!({}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Failed);
    assert!(evidence.error.unwrap().contains("could not be started"));
    fixture.session.close().await;
}

#[tokio::test]
async fn legacy_text_results_remain_citable() {
    let fixture = Fixture::standard("legacy").await;
    let evidence = fixture
        .tools
        .call("forensicator_analyze", json!({"plugins":["cause"]}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Present);
    assert_eq!(
        serde_json::from_str::<Value>(&evidence.text).unwrap()["tool"],
        "analyze"
    );
    fixture.session.close().await;
}

#[tokio::test]
async fn javascript_tool_recovers_optimized_frames_and_binds_jit_metadata() {
    let fixture = Fixture::standard("javascript").await;
    let evidence = fixture
        .tools
        .call(
            "forensicator_javascript_stack",
            json!({"thread_id":42,"include_jit":true}),
        )
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Present, "{evidence:?}");
    let data: Value = serde_json::from_str(&evidence.text).unwrap();
    assert_eq!(data["recoveredFrameCount"], 2);
    assert_eq!(data["optimizedFrameCount"], 1);
    assert_eq!(data["frames"][0]["function"], "optimizedFunction");
    assert_eq!(data["frames"][0]["frameType"], "OptimizedJavaScript");
    assert_eq!(data["frames"][0]["functionStartLine"], 2);
    assert_eq!(
        data["frames"][0]["jit"]["codeResolution"]["codeObject"],
        "0x600000100"
    );
    assert!(
        data["frames"][0]["jit"]["codeResolution"]
            .get("nativeOffset")
            .is_none()
    );
    assert_eq!(data["frames"][1]["function"], "plainFunction");
    assert!(
        data["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("inlined logical frames"))
    );
    let wire = fixture.wire();
    assert_eq!(wire[3]["params"]["name"], "analyze");
    assert_eq!(
        wire[3]["params"]["arguments"]["plugins"],
        json!(["v8", "jit"])
    );
    assert_eq!(
        wire[3]["params"]["arguments"]["path"],
        json!(fixture.request.dump_path)
    );
    assert!(
        wire[3]["params"]["arguments"].get("thread_id").is_none(),
        "upstream has no thread filter; the host projects the result"
    );
    let empty = fixture
        .tools
        .call("forensicator_javascript_stack", json!({"thread_id":7}))
        .await
        .unwrap();
    let data: Value = serde_json::from_str(&empty.text).unwrap();
    assert_eq!(data["candidateFrameCount"], 0);
    assert_eq!(data["selectedThreadFrameCount"], 0);
    assert!(data["frames"].as_array().unwrap().is_empty());
    fixture.session.close().await;
}

#[tokio::test]
async fn javascript_excerpt_limits_preserve_valid_json_and_mark_omissions() {
    let fixture = Fixture::standard("javascript").await;
    let evidence = fixture
        .tools
        .call("forensicator_javascript_stack", json!({"max_frames":1}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Truncated);
    let data: Value = serde_json::from_str(&evidence.text).unwrap();
    assert_eq!(data["frames"].as_array().unwrap().len(), 1);
    assert_eq!(data["omittedFrameCount"], 1);
    assert_eq!(data["includeJit"], false);
    assert!(data["frames"][0]["jit"].is_null());
    fixture.session.close().await;

    let fixture = Fixture::standard("javascript").await;
    let mut raw: Value =
        serde_json::from_str(include_str!("fixtures/forensicator-v8-jit.json")).unwrap();
    let mut frame = raw["plugins"][0]["custom"][0]["v8_frames"][0].clone();
    frame["script_name"] = json!("bundle".repeat(30));
    let frames: Vec<Value> = (0..32)
        .map(|depth| {
            let mut f = frame.clone();
            f["depth"] = json!(depth);
            f
        })
        .collect();
    raw["plugins"][0]["custom"][0]["v8_frames"] = json!(frames);
    raw["plugins"][0]["custom"][1]["v8_frame_count"] = json!(32);
    std::fs::write(
        fixture.request.work_dir.join("javascript.json"),
        raw.to_string(),
    )
    .unwrap();
    let evidence = fixture
        .tools
        .call("forensicator_javascript_stack", json!({"max_frames":32}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::Truncated, "{evidence:?}");
    let data: Value = serde_json::from_str(&evidence.text).unwrap();
    assert!(evidence.text.len() <= MAX_SECTION_BYTES);
    assert_eq!(data["recoveredFrameCount"], 32);
    assert!(data["omittedFrameCount"].as_u64().unwrap() > 0);
    assert!(!data["frames"].as_array().unwrap().is_empty());
    fixture.session.close().await;
}

#[tokio::test]
async fn invalid_javascript_arguments_or_source_data_never_become_recovered_frames() {
    let fixture = Fixture::standard("javascript").await;
    for args in [
        json!({"path":"/etc/passwd"}),
        json!({"thread_id":-1}),
        json!({"thread_id":4294967296u64}),
        json!({"max_frames":0}),
        json!({"max_frames":33}),
        json!({"include_jit":"yes"}),
        json!({"symbols":"../outside"}),
    ] {
        assert!(
            fixture
                .tools
                .call("forensicator_javascript_stack", args)
                .await
                .is_err()
        );
    }
    assert!(!fixture.request.work_dir.join("wire.jsonl").exists());
    fixture.session.close().await;
    for mismatch in [false, true] {
        let fixture = Fixture::standard("javascript").await;
        let mut raw: Value =
            serde_json::from_str(include_str!("fixtures/forensicator-v8-jit.json")).unwrap();
        if mismatch {
            raw["plugins"][1]["custom"][1]["jit_frames"][0]["function_name"] =
                json!("unrelatedFunction");
        } else {
            raw["plugins"][0]["custom"][1]["v8_frame_count"] = json!(999);
        }
        std::fs::write(
            fixture.request.work_dir.join("javascript.json"),
            raw.to_string(),
        )
        .unwrap();
        let evidence = fixture
            .tools
            .call("forensicator_javascript_stack", json!({"include_jit":true}))
            .await
            .unwrap();
        assert_eq!(evidence.status, CaptureStatus::Failed);
        assert!(evidence.text.is_empty());
        assert_eq!(fixture.tools.evidence().await, vec![evidence]);
        fixture.session.close().await;
    }
}

async fn wait_for_pid(workspace: &Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(pid) = std::fs::read_to_string(workspace.join("child.pid")) {
                if let Ok(pid) = pid.parse() {
                    break pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

async fn assert_reaped(pid: u32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("MCP child must be killed and reaped");
}

#[tokio::test]
async fn cancellation_close_and_deadline_kill_children_and_keep_receipts() {
    for close in [false, true] {
        let fixture = Fixture::standard("wait").await;
        let tools = fixture.tools.clone();
        let task = tokio::spawn(async move { tools.call("forensicator_inspect", json!({})).await });
        let pid = wait_for_pid(&fixture.request.work_dir).await;
        if close {
            tokio::time::timeout(Duration::from_secs(3), fixture.session.close())
                .await
                .unwrap();
            assert_eq!(task.await.unwrap().unwrap().status, CaptureStatus::Failed);
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            fixture.session.close().await;
        }
        assert_reaped(pid).await;
        let retained = fixture.tools.evidence().await;
        assert_eq!(retained.len(), 1);
        assert!(retained[0].error.as_ref().unwrap().contains("cancelled"));
    }
    let fixture = Fixture::new("wait", 1024 * 1024, Duration::from_millis(700), None).await;
    let evidence = fixture
        .tools
        .call("forensicator_inspect", json!({}))
        .await
        .unwrap();
    assert_eq!(evidence.status, CaptureStatus::TimedOut);
    let pid = wait_for_pid(&fixture.request.work_dir).await;
    assert_reaped(pid).await;
    fixture.session.close().await;
}

fn put(data: &mut [u8], offset: usize, bytes: &[u8]) {
    data[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Synthetic Windows x64 capture with one module, stack, exception and RSDS
/// identity, matching Forensicator's public MCP regression fixture layout.
fn native_inputs(workspace: &Path, dump: &Path) {
    let mut data = vec![0u8; 2400];
    for (offset, value) in [(0, 0x504d444d_u32), (4, 0xa793), (8, 5), (12, 2048)] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    for (i, (kind, size, rva)) in [
        (7_u32, 56_u32, 80_u32),
        (3, 52, 136),
        (4, 112, 188),
        (5, 20, 300),
        (6, 168, 2200),
    ]
    .into_iter()
    .enumerate()
    {
        for (j, value) in [kind, size, rva].into_iter().enumerate() {
            put(&mut data, 2048 + i * 12 + j * 4, &value.to_le_bytes());
        }
    }
    put(&mut data, 80, &9_u16.to_le_bytes());
    for (offset, value) in [
        (88, 10_u32),
        (100, 2),
        (136, 1),
        (140, 7),
        (172, 128),
        (176, 1792),
        (180, 1232),
        (184, 512),
        (560, 0x00100003),
        (188, 1),
        (200, 0x1000),
        (212, 320),
        (300, 1),
        (312, 128),
        (316, 1792),
        (2200, 7),
        (2208, 0xc0000005),
        (2232, 2),
        (2360, 1232),
        (2364, 512),
    ] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    for (offset, value) in [
        (164, 0x8000_u64),
        (664, 0x8000),
        (672, 0x8010),
        (760, 0x1000),
        (192, 0x1000),
        (304, 0x8000),
        (1808, 0x8020),
        (1816, 0x1010),
        (1832, 0x1020),
        (2224, 0x1000),
        (2248, 0xdeadbeef),
    ] {
        put(&mut data, offset, &value.to_le_bytes());
    }
    let name: Vec<u8> = "fixture.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put(&mut data, 320, &(name.len() as u32).to_le_bytes());
    put(&mut data, 324, &name);
    let mut rsds = b"RSDS".to_vec();
    rsds.extend(0u8..16);
    rsds.extend(7_u32.to_le_bytes());
    rsds.extend(b"fixture.pdb\0");
    put(&mut data, 268, &(rsds.len() as u32).to_le_bytes());
    put(&mut data, 272, &400_u32.to_le_bytes());
    put(&mut data, 400, &rsds);
    std::fs::write(dump, data).unwrap();

    let mut pdb = vec![0u8; 1280];
    put(&mut pdb, 0, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    for (offset, value) in [
        (32, 256_u32),
        (36, 1),
        (40, 5),
        (44, 16),
        (52, 2),
        (512, 3),
        (768, 2),
        (776, 28),
        (780, 4),
        (1024, 3),
        (1028, 0x1234),
        (1032, 8),
    ] {
        put(&mut pdb, offset, &value.to_le_bytes());
    }
    put(&mut pdb, 1036, &(0u8..16).collect::<Vec<_>>());
    std::fs::write(workspace.join("fixture.pdb"), pdb).unwrap();
}

async fn bridge_rpc(
    server: &dump_analyzer::analysis_mcp::McpServer,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let response = reqwest::Client::new()
        .post(server.endpoint())
        .bearer_auth(server.token())
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires FORENSICATOR_TEST_BIN pointing to the native Forensicator executable and loopback TCP"]
async fn native_forensicator_mcp_matches_cli_through_the_reasoner_bridge() {
    let executable =
        PathBuf::from(std::env::var("FORENSICATOR_TEST_BIN").expect("set FORENSICATOR_TEST_BIN"));
    assert!(executable.is_absolute());
    let fixture = Fixture::new(
        "",
        1024 * 1024,
        Duration::from_secs(30),
        Some(executable.clone()),
    )
    .await;
    native_inputs(&fixture.request.work_dir, &fixture.request.dump_path);
    let mut server = dump_analyzer::analysis_mcp::McpServer::start(
        fixture.tools.clone(),
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .unwrap();
    let init = bridge_rpc(&server, 1, "initialize", json!({"protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"native-test", "version":"1"}})).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    let list = bridge_rpc(&server, 2, "tools/list", json!({})).await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 11);
    let plugins = bridge_rpc(
        &server,
        3,
        "tools/call",
        json!({"name":"forensicator_list_plugins","arguments":{}}),
    )
    .await;
    assert_eq!(plugins["result"]["isError"], false, "{plugins}");
    let data: Value = serde_json::from_str(
        plugins["result"]["structuredContent"]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        data["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "cause")
    );
    assert!(
        data["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "jit")
    );
    for (i, (name, arguments, extra)) in [
        ("inspect", json!({}), vec![]),
        (
            "analyze",
            json!({"plugins":["cause"]}),
            vec!["--plugin".to_owned(), "cause".into()],
        ),
        (
            "match",
            json!({"pdbs":["fixture.pdb"]}),
            vec![
                "--pdb".to_owned(),
                fixture
                    .request
                    .work_dir
                    .join("fixture.pdb")
                    .to_str()
                    .unwrap()
                    .into(),
            ],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let result = bridge_rpc(
            &server,
            4 + i as u64,
            "tools/call",
            json!({"name":format!("forensicator_{name}"), "arguments":arguments}),
        )
        .await;
        assert_eq!(result["result"]["isError"], false, "{result}");
        let evidence = &result["result"]["structuredContent"];
        assert_eq!(evidence["status"], "present", "{evidence}");
        let data: Value = serde_json::from_str(evidence["text"].as_str().unwrap()).unwrap();
        let cli = std::process::Command::new(&executable)
            .arg(name)
            .arg(&fixture.request.dump_path)
            .arg("--json")
            .args(extra)
            .output()
            .unwrap();
        // A mismatched artifact is a successful MCP forensic result; the CLI
        // uses a nonzero exit status for the same mismatch.
        assert_eq!(data, serde_json::from_slice::<Value>(&cli.stdout).unwrap());
        if name == "match" {
            assert_eq!(data["overall"], "mismatch");
        }
        if name == "inspect" {
            assert_eq!(data["system_info"]["cpu"], "x64");
        }
    }
    assert!(server.tools_discovered());
    server.close().await;
    fixture.session.close().await;
    assert_eq!(fixture.tools.evidence().await.len(), 4);
}

#[tokio::test]
#[ignore = "requires FORENSICATOR_TEST_BIN, Python 3 and loopback TCP; only synthetic V8 heap data is used"]
async fn native_javascript_recovery_preserves_optimized_frames_and_missing_heap_limits() {
    let executable =
        PathBuf::from(std::env::var("FORENSICATOR_TEST_BIN").expect("set FORENSICATOR_TEST_BIN"));
    let fixture = Fixture::new("", 1024 * 1024, Duration::from_secs(30), Some(executable)).await;
    let generator = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/forensicator-js.py");
    let generate = |without_heap: bool| {
        let mut command = std::process::Command::new("python3");
        command
            .arg("-B")
            .arg(&generator)
            .arg(&fixture.request.dump_path);
        if without_heap {
            command.arg("--without-heap");
        }
        assert!(command.status().unwrap().success());
    };
    generate(false);
    let mut server = dump_analyzer::analysis_mcp::McpServer::start(
        fixture.tools.clone(),
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .unwrap();
    let result = bridge_rpc(&server, 1, "tools/call", json!({"name":"forensicator_javascript_stack","arguments":{"thread_id":42,"include_jit":true}})).await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    let data: Value = serde_json::from_str(
        result["result"]["structuredContent"]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["recoveredFrameCount"], 2);
    assert_eq!(data["optimizedFrameCount"], 1);
    assert_eq!(
        data["frames"][0]["framePc"], "0x200001010",
        "exception context takes priority over the thread's initial context"
    );
    assert_eq!(data["frames"][0]["function"], "optimizedFunction");
    assert_eq!(data["frames"][0]["script"], "fixture.js");
    assert_eq!(data["frames"][0]["functionStartLine"], 2);
    assert_eq!(
        data["frames"][0]["jit"]["codeResolution"]["codeObject"],
        "0x600000100"
    );
    assert_eq!(data["frames"][0]["jit"]["sfiCrosscheck"], true);
    assert_eq!(data["frames"][1]["function"], "plainFunction");
    generate(true);
    let result = bridge_rpc(
        &server,
        2,
        "tools/call",
        json!({"name":"forensicator_javascript_stack","arguments":{"include_jit":true}}),
    )
    .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    let missing: Value = serde_json::from_str(
        result["result"]["structuredContent"]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(missing["heapCaptured"], false);
    assert_eq!(missing["recoveredFrameCount"], 0);
    assert_eq!(missing["candidateFrameCount"], 2);
    for frame in missing["frames"].as_array().unwrap() {
        assert_eq!(frame["metadataRecovered"], false);
        assert!(frame["function"].is_null());
        assert!(frame["jit"].is_null());
    }
    server.close().await;
    fixture.session.close().await;
    assert_eq!(fixture.tools.evidence().await.len(), 2);
}
