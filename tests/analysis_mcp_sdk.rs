//! Optional interoperability check using the actual MCP client package shipped
//! with DSH. It contacts only a temporary loopback server with fake evidence;
//! no model, debugger, profile, credentials, or production service is used.
//!
//! Run with Node available on PATH and the installed client's ESM entrypoint:
//! ```text
//! DUMP_ANALYZER_MCP_CLIENT_PATH=/path/to/dsh/node_modules/@modelcontextprotocol/client/dist/index.mjs \
//!   cargo test --offline --locked --test analysis_mcp_sdk -- --ignored
//! ```

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dump_analyzer::analysis_mcp::McpServer;
use dump_analyzer::analysis_tools::AnalysisTools;
use dump_analyzer::report::{CaptureStatus, Evidence};
use dump_analyzer::types::Result;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

#[derive(Default)]
struct RetainedEvidence(Mutex<Vec<Evidence>>);

#[async_trait::async_trait]
impl AnalysisTools for RetainedEvidence {
    async fn call(&self, name: &str, arguments: Value) -> Result<Evidence> {
        assert_eq!(name, "read_memory");
        assert_eq!(arguments, json!({"address":"0x1000", "length":16}));
        let evidence = Evidence {
            id: "investigation-sdk-1".into(),
            command: "db 0x1000 L0x10".into(),
            status: CaptureStatus::Present,
            text: "00001000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".into(),
            truncated: false,
            error: None,
        };
        self.0.lock().unwrap().push(evidence.clone());
        Ok(evidence)
    }

    async fn evidence(&self) -> Vec<Evidence> {
        self.0.lock().unwrap().clone()
    }
}

const SDK_CLIENT: &str = r#"
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

let stage = 'input';
let client;
try {
  let inputText = '';
  for await (const chunk of process.stdin) inputText += chunk;
  const input = JSON.parse(inputText);
  stage = 'import';
  const { Client, StreamableHTTPClientTransport } = await import(pathToFileURL(input.module).href);
  const seen = [];
  const transport = new StreamableHTTPClientTransport(new URL(input.endpoint), {
    requestInit: { headers: { Authorization: `Bearer ${input.token}` } },
    fetch: async (url, options) => {
      // A future SDK change must not turn this local test into network access.
      assert.equal(String(url), input.endpoint);
      const message = typeof options?.body === 'string' ? JSON.parse(options.body) : {};
      const headers = new Headers(options?.headers);
      const response = await fetch(url, options);
      seen.push({ method: message.method ?? options?.method ?? 'GET',
        protocol: headers.get('mcp-protocol-version'), status: response.status });
      return response;
    },
  });
  // Match DSH's auto-negotiation mode, which first probes the modern protocol
  // and then falls back to the server's supported initialize handshake.
  client = new Client({ name: 'dump-analyzer-sdk-smoke', version: '1' }, {
    capabilities: {}, versionNegotiation: { mode: 'auto' },
  });
  stage = 'connect';
  await client.connect(transport, { timeout: 5000 });
  assert.equal(transport.protocolVersion, '2025-11-25');
  stage = 'list';
  const list = await client.listTools(undefined, { cacheMode: 'refresh' });
  assert.deepEqual(list.tools.map(tool => tool.name).sort(), [
    'disassemble', 'get_module_symbols', 'get_registers', 'get_stack', 'list_threads', 'read_memory',
  ]);
  stage = 'call';
  const tool = list.tools.find(tool => tool.name === 'read_memory');
  const result = await client.callTool({ name: 'read_memory', arguments: { address: '0x1000', length: 16 } },
    { timeout: 5000, toolDefinition: tool });
  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.id, 'investigation-sdk-1');
  assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
  assert.ok(seen.some(request => request.method === 'server/discover'));
  assert.ok(seen.some(request => request.method === 'initialize' && request.status === 200));
  assert.ok(seen.some(request => request.method === 'tools/call' && request.protocol === '2025-11-25'));
  stage = 'close';
  await client.close();
  process.stdout.write(JSON.stringify({ ok: true, protocol: transport.protocolVersion,
    tools: list.tools.length, evidenceId: result.structuredContent.id, requests: seen }));
} catch {
  // Never print exception objects, request headers, or capability credentials.
  if (client) await client.close().catch(() => {});
  process.stdout.write(JSON.stringify({ ok: false, stage }));
  process.exitCode = 1;
}
"#;

#[tokio::test]
#[ignore = "requires Node and DUMP_ANALYZER_MCP_CLIENT_PATH pointing to installed DSH MCP SDK"]
async fn installed_dsh_sdk_negotiates_discovers_and_calls_with_retained_evidence() {
    let module = std::env::var("DUMP_ANALYZER_MCP_CLIENT_PATH")
        .expect("set DUMP_ANALYZER_MCP_CLIENT_PATH to the installed client's dist/index.mjs");
    assert!(std::path::Path::new(&module).is_absolute());
    let tools = Arc::new(RetainedEvidence::default());
    let mut server = McpServer::start(tools.clone(), Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    let mut child = tokio::process::Command::new("node")
        .args(["--input-type=module", "--eval", SDK_CLIENT])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Node must be available on PATH");
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(
            json!({"module":module, "endpoint":server.endpoint(), "token":server.token()})
                .to_string()
                .as_bytes(),
        )
        .await
        .unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("SDK smoke deadline")
        .expect("SDK process completion");
    // Only our deliberately restricted result schema can enter diagnostics.
    let result: Value = serde_json::from_slice(&output.stdout)
        .expect("SDK smoke must return a result without diagnostic text");
    if !output.status.success() {
        panic!(
            "SDK interoperability failed at stage {}",
            result["stage"].as_str().unwrap_or("unknown")
        );
    }
    assert_eq!(result["ok"], true);
    assert_eq!(result["protocol"], "2025-11-25");
    assert_eq!(result["tools"], 6);
    assert!(server.tools_discovered());
    assert_eq!(tools.evidence().await.len(), 1);
    assert_eq!(tools.evidence().await[0].id, "investigation-sdk-1");
    server.close().await;
}
