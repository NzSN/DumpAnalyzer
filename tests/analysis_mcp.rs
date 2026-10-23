use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dump_analyzer::analysis_mcp::McpServer;
use dump_analyzer::analysis_tools::AnalysisTools;
use dump_analyzer::report::{CaptureStatus, Evidence};
use dump_analyzer::types::{AnalyzerError, Result};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::Instant;

#[derive(Default)]
struct FakeTools {
    calls: AtomicUsize,
    block: bool,
    fail: bool,
    started: Notify,
    cancelled: Arc<Notify>,
}

struct OnDrop(Arc<Notify>);

impl Drop for OnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[async_trait::async_trait]
impl AnalysisTools for FakeTools {
    async fn call(&self, name: &str, _arguments: Value) -> Result<Evidence> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _drop = OnDrop(Arc::clone(&self.cancelled));
        self.started.notify_one();
        if self.block {
            std::future::pending::<()>().await;
        }
        if self.fail {
            return Err(AnalyzerError::Runner(
                "private paths and internal details".into(),
            ));
        }
        Ok(Evidence {
            id: "investigation-1".into(),
            command: name.into(),
            status: CaptureStatus::Present,
            text: "thread 0: faulting frame".into(),
            truncated: false,
            error: None,
        })
    }

    async fn evidence(&self) -> Vec<Evidence> {
        Vec::new()
    }
}

async fn start(tools: Arc<FakeTools>) -> McpServer {
    McpServer::start(tools, Instant::now() + Duration::from_secs(30))
        .await
        .unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

fn request(server: &McpServer, body: Value) -> reqwest::RequestBuilder {
    client()
        .post(server.endpoint())
        .bearer_auth(server.token())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(body.to_string())
}

async fn rpc(server: &McpServer, body: Value) -> Value {
    let response = request(server, body).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    serde_json::from_str(&response.text().await.unwrap()).unwrap()
}

fn initialize(version: &str) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"test","version":"1"}
    }})
}

fn call() -> Value {
    json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_threads","arguments":{}}})
}

#[tokio::test]
async fn handshake_discovers_six_tools_and_calls_return_citable_evidence() {
    let tools = Arc::new(FakeTools::default());
    let mut server = start(Arc::clone(&tools)).await;
    assert!(server.endpoint().starts_with("http://127.0.0.1:"));
    assert!(!server.endpoint().contains(server.token()));
    assert_eq!(server.token().len(), 64);
    assert!(!server.tools_discovered());
    let initialized = rpc(&server, initialize("2026-07-28")).await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        initialized["result"]["capabilities"],
        json!({"tools":{"listChanged":false}})
    );
    for version in ["2025-11-25", "2025-06-18", "2025-03-26"] {
        assert_eq!(
            rpc(&server, initialize(version)).await["result"]["protocolVersion"],
            version
        );
    }
    let ready = request(
        &server,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .header("MCP-Protocol-Version", "2025-11-25")
    .send()
    .await
    .unwrap();
    assert_eq!(ready.status(), 202);
    assert!(ready.text().await.unwrap().is_empty());
    let list = rpc(
        &server,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert!(server.tools_discovered());
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 6);
    for expected in [
        "list_threads",
        "get_stack",
        "get_registers",
        "read_memory",
        "disassemble",
        "get_module_symbols",
    ] {
        assert!(names.contains(&expected));
    }
    let evidence = rpc(&server, call()).await;
    assert_eq!(evidence["id"], 4);
    assert_eq!(evidence["result"]["isError"], false);
    assert_eq!(
        evidence["result"]["structuredContent"]["id"],
        "investigation-1"
    );
    let text_evidence: Value =
        serde_json::from_str(evidence["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text_evidence, evidence["result"]["structuredContent"]);
    assert_eq!(tools.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        rpc(
            &server,
            json!({"jsonrpc":"2.0","id":"ping-id","method":"ping"})
        )
        .await["result"],
        json!({})
    );
    let cancelled = request(
        &server,
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(cancelled.status(), 202);
    server.close().await;
}

#[tokio::test]
async fn credentials_are_required_and_are_unique_to_each_run() {
    let tools = Arc::new(FakeTools::default());
    let mut one = start(Arc::clone(&tools)).await;
    let mut two = start(Arc::clone(&tools)).await;
    assert_ne!(one.token(), two.token());
    for token in ["wrong", one.token()] {
        let result = client()
            .post(two.endpoint())
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .body(call().to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), 401);
    }
    let no_auth = client()
        .post(two.endpoint())
        .header("Content-Type", "application/json")
        .body(call().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status(), 401);
    assert_eq!(tools.calls.load(Ordering::SeqCst), 0);
    one.close().await;
    two.close().await;
}

#[tokio::test]
async fn exact_host_origin_and_protocol_are_enforced() {
    let tools = Arc::new(FakeTools::default());
    let mut server = start(Arc::clone(&tools)).await;
    for (header, value, status) in [
        ("Host", "attacker.example", 403),
        ("Host", "localhost", 403),
        ("Origin", "https://attacker.example", 403),
        ("Origin", "null", 403),
        ("Origin", "http://127.0.0.1:1", 403),
        ("MCP-Protocol-Version", "bogus", 400),
    ] {
        let response = request(&server, call())
            .header(header, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status, "{header}: {value}");
    }
    let origin = server.endpoint().strip_suffix("/mcp").unwrap();
    let response = request(&server, call())
        .header("Origin", origin)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let get = client()
        .get(server.endpoint())
        .bearer_auth(server.token())
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 405);
    assert_eq!(get.headers()["allow"], "POST");
    assert_eq!(tools.calls.load(Ordering::SeqCst), 1);
    server.close().await;
}

#[tokio::test]
async fn invalid_rpc_and_domain_failures_are_distinguished_without_leaking_details() {
    let tools = Arc::new(FakeTools {
        fail: true,
        ..FakeTools::default()
    });
    let mut server = start(Arc::clone(&tools)).await;
    for (body, status, code) in [
        ("{".to_owned(), 400, -32700),
        ("[]".to_owned(), 400, -32600),
        (json!({"jsonrpc":"1.0","id":1,"method":"ping"}).to_string(), 400, -32600),
        (json!({"jsonrpc":"2.0","id":{},"method":"ping"}).to_string(), 400, -32600),
        (json!({"jsonrpc":"2.0","id":1,"method":"shell"}).to_string(), 200, -32601),
        (json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(), 200, -32602),
        (json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"}}).to_string(), 200, -32602),
        (json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_threads","arguments":[]}}).to_string(), 200, -32602),
    ] {
        let response = request(&server, Value::Null).body(body).send().await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        let value: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(value["error"]["code"], code);
    }
    assert_eq!(tools.calls.load(Ordering::SeqCst), 0);
    let failure = rpc(&server, call()).await;
    assert_eq!(failure["result"]["isError"], true);
    assert!(!failure.to_string().contains("private paths"));
    server.close().await;
}

async fn raw(server: &McpServer, headers: &str, body: &str) -> String {
    let authority = server
        .endpoint()
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix("/mcp")
        .unwrap();
    let mut stream = TcpStream::connect(authority).await.unwrap();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\n{headers}\r\n{body}",
        server.token()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap();
    if let Err(error) = read {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(!response.is_empty());
    }
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn framing_and_size_limits_reject_before_tool_dispatch() {
    let tools = Arc::new(FakeTools::default());
    let mut server = start(Arc::clone(&tools)).await;
    for (headers, status) in [
        ("Content-Length: 65537\r\n".to_owned(), 413),
        (
            "Content-Length: 99999999999999999999999999\r\n".to_owned(),
            413,
        ),
        ("Content-Length: 0\r\nContent-Length: 0\r\n".to_owned(), 400),
        ("Content-Length: -1\r\n".to_owned(), 400),
        (
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n".to_owned(),
            400,
        ),
        ("".to_owned(), 411),
    ] {
        assert!(
            raw(&server, &headers, "")
                .await
                .starts_with(&format!("HTTP/1.1 {status} "))
        );
    }
    let huge_header = format!("X-Large: {}\r\nContent-Length: 0\r\n", "x".repeat(9000));
    assert!(
        raw(&server, &huge_header, "")
            .await
            .starts_with("HTTP/1.1 431 ")
    );
    assert_eq!(tools.calls.load(Ordering::SeqCst), 0);
    server.close().await;
}

async fn pending_call(server: &McpServer, tools: &FakeTools) -> tokio::task::JoinHandle<()> {
    let request = request(server, call());
    let task = tokio::spawn(async move {
        let _ = request.send().await;
    });
    tokio::time::timeout(Duration::from_secs(2), tools.started.notified())
        .await
        .unwrap();
    task
}

#[tokio::test]
async fn close_stops_listener_and_cancels_in_flight_tool() {
    let tools = Arc::new(FakeTools {
        block: true,
        ..FakeTools::default()
    });
    let mut server = start(Arc::clone(&tools)).await;
    let pending = pending_call(&server, &tools).await;
    server.close().await;
    tokio::time::timeout(Duration::from_secs(2), tools.cancelled.notified())
        .await
        .unwrap();
    assert!(request(&server, call()).send().await.is_err());
    pending.await.unwrap();
    server.close().await;
}

#[tokio::test]
async fn drop_cancels_in_flight_tool() {
    let tools = Arc::new(FakeTools {
        block: true,
        ..FakeTools::default()
    });
    let server = start(Arc::clone(&tools)).await;
    let endpoint = server.endpoint().to_owned();
    let pending = pending_call(&server, &tools).await;
    drop(server);
    tokio::time::timeout(Duration::from_secs(2), tools.cancelled.notified())
        .await
        .unwrap();
    assert!(client().get(endpoint).send().await.is_err());
    pending.await.unwrap();
}

#[tokio::test]
async fn shared_deadline_closes_listener_and_cancels_tool() {
    let tools = Arc::new(FakeTools {
        block: true,
        ..FakeTools::default()
    });
    let mut server = McpServer::start(
        Arc::clone(&tools) as Arc<dyn AnalysisTools>,
        Instant::now() + Duration::from_millis(300),
    )
    .await
    .unwrap();
    let pending = pending_call(&server, &tools).await;
    tokio::time::timeout(Duration::from_secs(2), tools.cancelled.notified())
        .await
        .unwrap();
    assert!(request(&server, call()).send().await.is_err());
    pending.await.unwrap();
    server.close().await;
    assert!(McpServer::start(tools, Instant::now()).await.is_err());
}

#[tokio::test]
async fn slow_request_headers_have_their_own_read_deadline() {
    let mut server = start(Arc::new(FakeTools::default())).await;
    let authority = server
        .endpoint()
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix("/mcp")
        .unwrap();
    let mut stream = TcpStream::connect(authority).await.unwrap();
    stream.write_all(b"POST /mcp HTTP/1.1\r\n").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(7), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 408 "));
    // A slow client does not end the investigation or its listener.
    assert_eq!(rpc(&server, initialize("2025-11-25")).await["id"], 1);
    server.close().await;
}

#[tokio::test]
async fn active_connections_are_bounded_instead_of_waiting_in_unlimited_tasks() {
    let tools = Arc::new(FakeTools {
        block: true,
        ..FakeTools::default()
    });
    let mut server = start(Arc::clone(&tools)).await;
    let mut calls = Vec::new();
    for index in 0..16 {
        let mut body = call();
        body["id"] = json!(index + 100);
        let request = request(&server, body);
        calls.push(tokio::spawn(async move {
            let _ = request.send().await;
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while tools.calls.load(Ordering::SeqCst) < 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(request(&server, call()).send().await.is_err());
    assert_eq!(tools.calls.load(Ordering::SeqCst), 16);
    server.close().await;
    for call in calls {
        call.await.unwrap();
    }
}

#[tokio::test]
async fn cancellation_notification_drops_only_the_named_query() {
    let tools = Arc::new(FakeTools {
        block: true,
        ..FakeTools::default()
    });
    let mut server = start(Arc::clone(&tools)).await;
    let pending = pending_call(&server, &tools).await;
    let mut other_body = call();
    other_body["id"] = json!(5);
    let other_request = request(&server, other_body);
    let other = tokio::spawn(async move {
        let _ = other_request.send().await;
    });
    tokio::time::timeout(Duration::from_secs(2), tools.started.notified())
        .await
        .unwrap();
    let cancelled = request(
        &server,
        json!({
            "jsonrpc":"2.0", "method":"notifications/cancelled",
            "params":{"requestId":4,"reason":"client deadline"}
        }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(cancelled.status(), 202);
    tokio::time::timeout(Duration::from_secs(2), tools.cancelled.notified())
        .await
        .unwrap();
    pending.await.unwrap();
    assert!(!other.is_finished());
    assert_eq!(rpc(&server, initialize("2025-11-25")).await["id"], 1);
    server.close().await;
    other.await.unwrap();
}
