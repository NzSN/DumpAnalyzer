//! Read-only status UI (design amendment 2026-10-13: the "no listening port"
//! v1 line is superseded by this loopback-only, GET-only dashboard).
//!
//! The analyzer is a headless daemon; this optional listener lets an
//! operator watch it and trigger bounded actions. Reads are unauthenticated;
//! the mutating POST routes (`/-/analyze`, `/-/rescan`) require the analyzer
//! token, and the surface never exposes the token, dump bytes, or report
//! facts. The default bind is loopback (`DUMP_ANALYZER_HTTP_ADDR`, default
//! `127.0.0.1:4180`, empty disables). A non-loopback bind is a deployment
//! decision: the actions stay token-guarded, the read views do not.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value as Json, json};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::analyzer::{AnalysisScope, AnalyzeError, Report, ScopeReport};
use crate::client::LedgerClient;
use crate::config::Config;
use crate::state::{JobRow, LocalReport, Store};
use crate::sync::{CancellationToken, initial_scan};
use crate::types::{AnalyzerError, Result};

/// Hard cap on the request head; the surface is GET-only and bodyless.
const MAX_HEAD_BYTES: usize = 8192;
/// Rows returned by the reports endpoint/dashboard.
const REPORTS_LIMIT: u32 = 200;

/// Dependencies backing `POST /-/rescan` (R2): the catalog client, the job
/// store, and the configuration the scan schedules against.
///
/// `LedgerClient` is not `Clone`, so the client is shared through an `Arc`
/// (the daemon already holds one). The route runs
/// [`crate::sync::initial_scan`] inline on the connection task.
pub struct RescanDeps {
    client: Arc<LedgerClient>,
    store: Store,
    config: Config,
}

impl RescanDeps {
    /// Bundles the three handles a manual catalog scan needs.
    pub fn new(client: Arc<LedgerClient>, store: Store, config: Config) -> Self {
        Self {
            client,
            store,
            config,
        }
    }
}

/// Process-level context shared by every connection.
pub struct UiContext {
    /// The daemon's validated configuration (token redacts itself in Debug).
    /// Held so token probes clone it with the pinned CA intact.
    config: crate::config::Config,
    store: Store,
    name: String,
    version: String,
    base_url: String,
    poll_interval_ms: u64,
    ssh_configured: bool,
    started: Instant,
    analyzer: Option<Arc<dyn crate::analyzer::Analyzer>>,
    /// Manual catalog re-scan (`POST /-/rescan`); `None` when unwired.
    rescan: Option<RescanDeps>,
    /// sha256 of the analyzer token the mutation routes accept; compared in
    /// constant time. Interior mutability: storing a new token via
    /// `POST /-/store-token` updates it live. `None` when no token is
    /// configured at all (every guarded call then 401s). The token itself is
    /// never stored here.
    token_sha256: std::sync::RwLock<Option<[u8; 32]>>,
}

impl UiContext {
    /// Builds the context from configuration, redacting everything secret.
    pub fn new(config: &crate::config::Config, store: Store) -> Self {
        Self {
            config: config.clone(),
            store,
            name: config.name.clone(),
            version: config.version.clone(),
            base_url: config.base_url.to_string(),
            poll_interval_ms: config.poll_interval.as_millis() as u64,
            ssh_configured: config.ssh_target.is_some(),
            started: Instant::now(),
            analyzer: None,
            rescan: None,
            token_sha256: std::sync::RwLock::new(
                config
                    .token
                    .as_ref()
                    .map(|token| sha2::Sha256::digest(token.expose().as_bytes()).into()),
            ),
        }
    }

    /// Attaches the on-demand analysis component (`f : DumpId -> IO Report`)
    /// that backs `POST /-/analyze`. Without it the route answers 501.
    pub fn with_analyzer(mut self, analyzer: Arc<dyn crate::analyzer::Analyzer>) -> Self {
        self.analyzer = Some(analyzer);
        self
    }

    /// Attaches the manual catalog re-scan component
    /// ([`crate::sync::initial_scan`]) that backs `POST /-/rescan` and the
    /// dashboard's "Rescan now" form. Without it the route answers 500 and
    /// the form is not rendered.
    pub fn with_rescan(mut self, deps: RescanDeps) -> Self {
        self.rescan = Some(deps);
        self
    }
}

/// Binds the listener and serves until `shutdown` is cancelled. Binding
/// happens eagerly so a taken port fails the daemon boot loudly.
pub async fn serve(
    addr: SocketAddr,
    context: UiContext,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| AnalyzerError::State(format!("bind status UI on {addr}: {err}")))?;
    let local = listener
        .local_addr()
        .map_err(|err| AnalyzerError::State(format!("status UI local address: {err}")))?;
    tracing::info!(%local, "status UI listening (read-only, GET only)");
    serve_listener(listener, Arc::new(context), shutdown).await
}

/// Accept loop over an already-bound listener (tests bind port 0).
pub async fn serve_listener(
    listener: TcpListener,
    context: Arc<UiContext>,
    shutdown: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                tracing::info!("status UI stopped");
                return Ok(());
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let context = Arc::clone(&context);
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, &context).await {
                                tracing::debug!(%err, "status UI connection closed early");
                            }
                        });
                    }
                    Err(err) => {
                        return Err(AnalyzerError::State(format!("status UI accept: {err}")));
                    }
                }
            }
        }
    }
}

/// A parsed request: line, the headers we honor, and a bounded body.
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// Hard cap on a request body; the only body we accept is the small
/// `/-/analyze` payload.
const MAX_BODY_BYTES: usize = 16 * 1024;

async fn handle_connection(mut stream: TcpStream, context: &UiContext) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_len = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(()); // peer closed without a request
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD_BYTES + MAX_BODY_BYTES {
            return write_response(
                &mut stream,
                400,
                "application/json; charset=utf-8",
                br#"{"error":"request_too_large"}"#,
            )
            .await;
        }
    };

    // Parse the head into owned values before the body read mutates `buf`.
    let mut lines = buf[..head_len].split(|b| *b == b'\n');
    let request_line: Vec<u8> = lines.next().unwrap_or(&[]).to_vec();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let line = line.trim_end();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        } else if name.trim().eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_string());
        }
    }
    if content_length > MAX_BODY_BYTES {
        return write_response(
            &mut stream,
            400,
            "application/json; charset=utf-8",
            br#"{"error":"request_too_large"}"#,
        )
        .await;
    }
    // Read the body (already-buffered bytes after the head, then the socket).
    let body_start = head_len + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break; // peer closed early; route sees a truncated body
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD_BYTES + MAX_BODY_BYTES {
            return write_response(
                &mut stream,
                400,
                "application/json; charset=utf-8",
                br#"{"error":"request_too_large"}"#,
            )
            .await;
        }
    }
    let body = buf[body_start..buf.len().min(body_start + content_length)].to_vec();

    let (method, path) = parse_request_line(&request_line);
    let request = Request {
        method: method.unwrap_or_default(),
        path: path.unwrap_or_default(),
        authorization,
        body,
    };
    let response = route(&request, context).await;
    write_response(
        &mut stream,
        response.status,
        response.content_type,
        &response.body,
    )
    .await
}

/// Minimal request-line parse: `METHOD SP PATH SP HTTP/1.x CRLF`. Anything
/// else yields `None` for both fields and routes to 400/405 handling.
fn parse_request_line(line: &[u8]) -> (Option<String>, Option<String>) {
    let text = match std::str::from_utf8(line) {
        Ok(text) => text.trim_end(),
        Err(_) => return (None, None),
    };
    let mut parts = text.split(' ');
    let method = parts.next();
    let path = parts.next();
    let version = parts.next();
    match (method, path, version, parts.next()) {
        (Some(method), Some(path), Some(version), None)
            if version.starts_with("HTTP/1.") && path.starts_with('/') =>
        {
            (Some(method.to_string()), Some(path.to_string()))
        }
        _ => (None, None),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn json_response(status: u16, value: Json) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8",
        body: serde_json::to_vec_pretty(&value).expect("json serialization cannot fail"),
    }
}

async fn route(request: &Request, context: &UiContext) -> Response {
    if request.method.is_empty() || request.path.is_empty() {
        return json_response(400, json!({ "error": "invalid_request" }));
    }
    let path = request.path.split(['?', '#']).next().unwrap_or("/");
    match (request.method.as_str(), path) {
        ("GET", "/") => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: DASHBOARD_HTML.as_bytes().to_vec(),
        },
        ("GET", "/api/capabilities") => json_response(
            200,
            json!({
                "analyzer": context.analyzer.is_some(),
                "rescan": context.rescan.is_some(),
            }),
        ),
        ("GET", "/api/status") => json_response(200, status_json(context)),
        ("GET", "/api/jobs") => match context.store.jobs().list() {
            Ok(jobs) => json_response(200, json!({ "jobs": jobs_json(&jobs) })),
            Err(err) => json_response(500, json!({ "error": format!("state: {err}") })),
        },
        ("GET", "/api/reports") => match context.store.local_reports().list_recent(REPORTS_LIMIT) {
            Ok(reports) => json_response(200, json!({ "reports": reports_json(&reports) })),
            Err(err) => json_response(500, json!({ "error": format!("state: {err}") })),
        },
        ("POST", "/-/analyze") => {
            if !authorized(context, request.authorization.as_deref()) {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            let Some(dump_id) = parse_json_dump_id(&request.body) else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            match analyze(context, &dump_id).await {
                Ok(report) => json_response(200, report_json(&report)),
                Err(err) => analyze_error_json(&err),
            }
        }
        ("POST", "/-/store-token") => {
            let Some(token) = parse_json_id(&request.body, "token") else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            match store_token(context, &token).await {
                Ok(()) => json_response(200, json!({ "stored": true })),
                Err(err) => store_token_error_json(&err),
            }
        }
        ("POST", "/-/store-token-form") => {
            let form = parse_form(&request.body);
            let Some(token) = form.get("token").filter(|v| !v.is_empty()) else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            let outcome = store_token(context, token).await;
            Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: store_token_result_page(outcome).into_bytes(),
            }
        }
        ("POST", "/-/analyze-case") | ("POST", "/-/analyze-customer") => {
            if !authorized(context, request.authorization.as_deref()) {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            let is_case = path == "/-/analyze-case";
            let body_key = if is_case { "caseId" } else { "customerId" };
            let Some(id) = parse_json_id(&request.body, body_key) else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            let scope = if is_case {
                AnalysisScope::Case(id)
            } else {
                AnalysisScope::Customer(id)
            };
            match analyze_scope(context, &scope).await {
                Ok(report) => json_response(200, scope_json(&report)),
                Err(err) => analyze_error_json(&err),
            }
        }
        ("POST", "/-/analyze-case-form") | ("POST", "/-/analyze-customer-form") => {
            let form = parse_form(&request.body);
            let token_ok = form
                .get("token")
                .is_some_and(|token| ct_token(context, token));
            if !token_ok {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            let is_case = path == "/-/analyze-case-form";
            let body_key = if is_case { "caseId" } else { "customerId" };
            let Some(id) = form.get(body_key).filter(|v| !v.is_empty()) else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            let scope = if is_case {
                AnalysisScope::Case(id.clone())
            } else {
                AnalysisScope::Customer(id.clone())
            };
            let outcome = analyze_scope(context, &scope).await;
            Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: scope_result_page(&scope, outcome).into_bytes(),
            }
        }
        ("POST", "/-/analyze-form") => {
            let form = parse_form(&request.body);
            let token_ok = form
                .get("token")
                .is_some_and(|token| ct_token(context, token));
            if !token_ok {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            let Some(dump_id) = form.get("dumpId").filter(|v| !v.is_empty()) else {
                return json_response(400, json!({ "error": "invalid_request" }));
            };
            let outcome = analyze(context, dump_id).await;
            Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: analyze_result_page(dump_id, outcome).into_bytes(),
            }
        }
        ("POST", "/-/rescan") => {
            if !authorized(context, request.authorization.as_deref()) {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            match rescan(context).await {
                Ok(inserted) => json_response(200, json!({ "inserted": inserted })),
                Err(err) if err.is_transient() => {
                    json_response(503, json!({ "error": "transient" }))
                }
                Err(err) => json_response(
                    500,
                    json!({ "error": "terminal", "message": err.to_string() }),
                ),
            }
        }
        ("POST", "/-/rescan-form") => {
            let form = parse_form(&request.body);
            let token_ok = form
                .get("token")
                .is_some_and(|token| ct_token(context, token));
            if !token_ok {
                return json_response(401, json!({ "error": "unauthenticated" }));
            }
            let outcome = rescan(context).await;
            Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: rescan_result_page(outcome).into_bytes(),
            }
        }
        ("GET", "/-/rescan") => json_response(405, json!({ "error": "method_not_allowed" })),
        ("GET", _) => json_response(404, json!({ "error": "not_found" })),
        _ => json_response(405, json!({ "error": "method_not_allowed" })),
    }
}

/* ------------------------------------------------------------------------ */
/* On-demand analysis (f : DumpId -> IO Report)                              */
/* ------------------------------------------------------------------------ */

/// Stores a new latest-used analyzer token after proving it against the
/// ledger (`GET /api/v1/events?limit=1` with the candidate). The server is
/// the authority: a token it rejects is never stored. On success the state
/// store and the live auth digest both update, so later UI actions and the
/// next boot use it. (The running daemon's server-clients keep their
/// boot-time token until restart.)
async fn store_token(context: &UiContext, token: &str) -> std::result::Result<(), StoreTokenError> {
    if token.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(StoreTokenError::Invalid);
    }
    // Probe the candidate against the live ledger with a throwaway client
    // (cloned config keeps the pinned CA).
    let mut probe_config = context.config.clone();
    probe_config.token = Some(crate::config::SecretToken::new(token));
    let probe =
        crate::client::LedgerClient::new(&probe_config).map_err(|_| StoreTokenError::Invalid)?;
    match probe.get_events(None, None, None, Some(1)).await {
        Ok(_) => {}
        Err(AnalyzerError::Server { status: 401, .. }) => {
            return Err(StoreTokenError::Rejected);
        }
        Err(err) => return Err(StoreTokenError::Unreachable(err.to_string())),
    }
    context
        .store
        .secrets()
        .set("analyzer_token", token)
        .map_err(|err| StoreTokenError::Unreachable(err.to_string()))?;
    let digest: [u8; 32] = sha2::Sha256::digest(token.as_bytes()).into();
    *context.token_sha256.write().expect("token lock") = Some(digest);
    tracing::info!("analyzer token updated via the status UI (stored as latest-used)");
    Ok(())
}

/// Failure taxonomy for storing a token.
#[derive(Debug)]
enum StoreTokenError {
    /// Malformed (whitespace) or unusable as a bearer header.
    Invalid,
    /// The ledger rejected the candidate token.
    Rejected,
    /// The ledger (or the local store) could not be reached.
    Unreachable(String),
}

fn store_token_error_json(err: &StoreTokenError) -> Response {
    match err {
        StoreTokenError::Invalid => json_response(
            400,
            json!({ "error": "invalid_request", "message": "malformed token" }),
        ),
        StoreTokenError::Rejected => json_response(
            401,
            json!({ "error": "unauthenticated", "message": "the ledger rejected this token" }),
        ),
        StoreTokenError::Unreachable(message) => json_response(
            503,
            json!({ "error": "transient", "message": format!("ledger unreachable: {message}") }),
        ),
    }
}

fn store_token_result_page(outcome: std::result::Result<(), StoreTokenError>) -> String {
    let mut html = String::from(HTML_HEAD);
    html.push_str("<header><h1>Store analyzer token</h1></header><section class=\"card\">");
    match outcome {
        Ok(()) => html.push_str(
            "<p><span class=\"badge green\">stored</span> the token is the daemon's \
             latest-used credential and is used by action forms immediately and by the \
             pipeline from the next boot.</p>",
        ),
        Err(err) => {
            html.push_str(&format!(
                "<p><span class=\"badge red\">not stored</span> {}</p>",
                escape(&match err {
                    StoreTokenError::Invalid => "malformed token".to_string(),
                    StoreTokenError::Rejected => "the ledger rejected this token".to_string(),
                    StoreTokenError::Unreachable(m) => format!("ledger unreachable: {m}"),
                }),
            ));
        }
    }
    html.push_str("<p><a href=\"/\">back to status</a></p></section></body></html>");
    html
}

async fn analyze(context: &UiContext, dump_id: &str) -> std::result::Result<Report, AnalyzeError> {
    let Some(analyzer) = &context.analyzer else {
        return Err(AnalyzeError::Terminal(AnalyzerError::State(
            "on-demand analysis is not wired on this listener".to_owned(),
        )));
    };
    analyzer.analyze(dump_id).await
}

async fn analyze_scope(
    context: &UiContext,
    scope: &AnalysisScope,
) -> std::result::Result<ScopeReport, AnalyzeError> {
    let Some(analyzer) = &context.analyzer else {
        return Err(AnalyzeError::Terminal(AnalyzerError::State(
            "on-demand analysis is not wired on this listener".to_owned(),
        )));
    };
    analyzer.analyze_scope(scope).await
}

/// The JSON body contract of the scope routes: exactly `{"caseId": "..."}` or
/// `{"customerId": "..."}`.
fn parse_json_id(body: &[u8], key: &str) -> Option<String> {
    let parsed: std::collections::HashMap<String, String> = serde_json::from_slice(body).ok()?;
    if parsed.len() != 1 {
        return None;
    }
    parsed.get(key).filter(|v| !v.is_empty()).cloned()
}

fn scope_json(report: &ScopeReport) -> Json {
    json!({
        "scope": report.scope,
        "considered": report.considered,
        "reports": report.reports.iter().map(report_json).collect::<Vec<_>>(),
        "skipped": report
            .skipped
            .iter()
            .map(|skip| json!({ "dumpId": skip.dump_id, "reason": skip.reason }))
            .collect::<Vec<_>>(),
    })
}

fn scope_result_page(
    scope: &AnalysisScope,
    outcome: std::result::Result<ScopeReport, AnalyzeError>,
) -> String {
    let mut html = String::from(HTML_HEAD);
    html.push_str("<header><h1>Scope analysis</h1></header><section>");
    match outcome {
        Ok(report) => {
            html.push_str(&format!(
                "<p><b>{}</b>: {} considered, {} reported, {} skipped</p>",
                escape(&report.scope),
                report.considered,
                report.reports.len(),
                report.skipped.len()
            ));
            html.push_str("<table><thead><tr><th>Dump</th><th>Outcome</th><th>Summary</th></tr></thead><tbody>");
            for r in &report.reports {
                let outcome_str = match r.outcome {
                    crate::types::ReportOutcome::Completed => "completed",
                    crate::types::ReportOutcome::Failed => "failed",
                };
                html.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td><span class=\"{}\">{}</span></td><td>{}</td></tr>",
                    escape(&r.identity.dump_id),
                    if outcome_str == "completed" { "badge green" } else { "badge red" },
                    outcome_str,
                    escape(&r.summary),
                ));
            }
            for skip in &report.skipped {
                html.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td><span class=\"badge gray\">skipped</span></td><td class=\"muted\">{}</td></tr>",
                    escape(&skip.dump_id),
                    escape(&skip.reason),
                ));
            }
            html.push_str("</tbody></table>");
        }
        Err(err) => {
            html.push_str(&format!(
                "<p><span class=\"badge red\">error</span> {}: {}</p>",
                escape(&scope.describe()),
                escape(&err.to_string()),
            ));
        }
    }
    html.push_str("<p><a href=\"/\">back to status</a></p></section></body></html>");
    html
}

/// Constant-time comparison of a presented bearer token against the
/// configured token's digest.
fn ct_token(context: &UiContext, presented: &str) -> bool {
    let guard = context.token_sha256.read().expect("token lock");
    let Some(expected) = guard.as_ref() else {
        return false; // no token configured: nothing can authenticate
    };
    // An empty presented value means "use the daemon's configured
    // (latest-used) token": authorized iff one exists. A presented token must
    // digest-match.
    if presented.is_empty() {
        return true;
    }
    let digest: [u8; 32] = sha2::Sha256::digest(presented.as_bytes()).into();
    expected
        .iter()
        .zip(digest.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn authorized(context: &UiContext, authorization: Option<&str>) -> bool {
    // Header absent → "use the daemon's stored token". Header present but
    // mis-schemed (not `Bearer`) → reject: any Authorization header pins the
    // bearer path. A presented bearer token must digest-match.
    match authorization {
        None => ct_token(context, ""),
        Some(header) => match header.strip_prefix("Bearer ") {
            Some(token) => ct_token(context, token),
            None => false,
        },
    }
}

/* ------------------------------------------------------------------------ */
/* Manual catalog rescan (POST /-/rescan)                                    */
/* ------------------------------------------------------------------------ */

/// Runs one inline [`initial_scan`] with the rescan dependencies.
///
/// Unwired dependencies surface as `AnalyzerError::State` so the JSON route
/// answers 500 exactly like an unwired `/-/analyze`.
async fn rescan(context: &UiContext) -> Result<u64> {
    let Some(deps) = &context.rescan else {
        return Err(AnalyzerError::State(
            "manual rescan is not wired on this listener".to_owned(),
        ));
    };
    initial_scan(deps.client.as_ref(), &deps.store, &deps.config).await
}

/// Result page for the dashboard's "Rescan now" form (the browser cannot set
/// an `Authorization` header, so the form presents the token and posts to
/// `/-/rescan-form`; same pattern as `/-/analyze-form`).
fn rescan_result_page(outcome: Result<u64>) -> String {
    let mut html = String::from(HTML_HEAD);
    html.push_str("<header><h1>Catalog rescan</h1></header><section>");
    match outcome {
        Ok(inserted) => {
            html.push_str(&format!(
                "<p><span class=\"badge green\">ok</span> \
                 <span class=\"mono\">inserted: {inserted}</span></p>\
                 <p>{inserted} new job(s) scheduled from the catalog.</p>"
            ));
        }
        Err(err) => {
            html.push_str(&format!(
                "<p><span class=\"badge red\">error</span></p><p>{}</p>",
                escape(&err.to_string()),
            ));
        }
    }
    html.push_str("<p><a href=\"/\">back to status</a></p></section></body></html>");
    html
}

/// The JSON body contract of `POST /-/analyze`: exactly `{"dumpId": "..."}`.
fn parse_json_dump_id(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AnalyzeRequest {
        #[serde(rename = "dumpId")]
        dump_id: String,
    }
    let parsed: AnalyzeRequest = serde_json::from_slice(body).ok()?;
    if parsed.dump_id.is_empty() {
        return None;
    }
    Some(parsed.dump_id)
}

/// Minimal `application/x-www-form-urlencoded` decoding for the browser form.
fn parse_form(body: &[u8]) -> std::collections::HashMap<String, String> {
    let text = String::from_utf8_lossy(body);
    let mut map = std::collections::HashMap::new();
    for pair in text.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        map.insert(url_decode(name), url_decode(value));
    }
    map
}

fn url_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => out.push(b),
                    Err(_) => out.push(bytes[i]),
                }
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn report_json(report: &Report) -> Json {
    json!({
        "report": {
            "dumpId": report.identity.dump_id,
            "inputSha256": report.identity.input_sha256,
            "kind": report.identity.kind,
            "analyzerVersion": report.identity.analyzer_version,
            "outcome": match report.outcome {
                crate::types::ReportOutcome::Completed => "completed",
                crate::types::ReportOutcome::Failed => "failed",
            },
            "summary": report.summary,
            "facts": report.facts,
        }
    })
}

fn analyze_error_json(err: &AnalyzeError) -> Response {
    let (status, code) = match err {
        AnalyzeError::NotFound(_) => (404, "not_found"),
        AnalyzeError::NotAvailable { .. } => (409, "not_available"),
        AnalyzeError::Transient(_) => (503, "transient"),
        AnalyzeError::Terminal(_) => (500, "terminal"),
    };
    json_response(status, json!({ "error": code, "message": err.to_string() }))
}

fn analyze_result_page(
    dump_id: &str,
    outcome: std::result::Result<Report, AnalyzeError>,
) -> String {
    let mut html = String::from(HTML_HEAD);
    html.push_str("<header><h1>On-demand analysis</h1></header><section>");
    match outcome {
        Ok(report) => {
            let outcome_str = match report.outcome {
                crate::types::ReportOutcome::Completed => "completed",
                crate::types::ReportOutcome::Failed => "failed",
            };
            let facts = report
                .facts
                .as_ref()
                .map(|f| serde_json::to_string_pretty(f).unwrap_or_default())
                .unwrap_or_else(|| "{}".to_string());
            html.push_str(&format!(
                "<p><span class=\"{}\">{}</span> <span class=\"mono\">{}</span></p>                 <p>{}</p><pre class=\"mono\">{}</pre>",
                if outcome_str == "completed" {
                    "badge green"
                } else {
                    "badge red"
                },
                outcome_str,
                escape(dump_id),
                escape(&report.summary),
                escape(&facts),
            ));
        }
        Err(err) => {
            html.push_str(&format!(
                "<p><span class=\"badge red\">error</span> <span class=\"mono\">{}</span></p><p>{}</p>",
                escape(dump_id),
                escape(&err.to_string()),
            ));
        }
    }
    html.push_str("<p><a href=\"/\">back to status</a></p></section></body></html>");
    html
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn status_json(context: &UiContext) -> Json {
    let jobs = context.store.jobs().list().unwrap_or_default();
    let reports = context
        .store
        .local_reports()
        .list_recent(REPORTS_LIMIT)
        .unwrap_or_default();
    let mut by_phase = serde_json::Map::new();
    for row in &jobs {
        let phase = phase_name(row.phase);
        let entry = by_phase
            .entry(phase.to_string())
            .or_insert_with(|| json!(0));
        *entry = json!(entry.as_u64().unwrap_or(0) + 1);
    }
    let pending = reports.iter().filter(|r| !r.posted).count();
    json!({
        "name": context.name,
        "version": context.version,
        "baseUrl": context.base_url,
        "upSeconds": context.started.elapsed().as_secs(),
        "pollIntervalMs": context.poll_interval_ms,
        "sshConfigured": context.ssh_configured,
        "eventCursor": context.store.cursors().get("event_cursor").ok().flatten(),
        "jobs": { "total": jobs.len(), "byPhase": by_phase },
        "reports": { "shown": reports.len(), "pending": pending },
    })
}

fn jobs_json(jobs: &[JobRow]) -> Vec<Json> {
    jobs.iter()
        .map(|row| {
            json!({
                "dumpId": row.identity.dump_id,
                "kind": row.identity.kind,
                "analyzerVersion": row.identity.analyzer_version,
                "inputSha256": row.identity.input_sha256,
                "phase": phase_name(row.phase),
                "attempts": row.attempts,
                "createdAt": row.created_at,
                "updatedAt": row.updated_at,
            })
        })
        .collect()
}

fn reports_json(reports: &[LocalReport]) -> Vec<Json> {
    reports
        .iter()
        .map(|report| {
            json!({
                "dumpId": report.dump_id,
                "kind": report.kind,
                "analyzerVersion": report.analyzer_version,
                "outcome": match report.outcome {
                    crate::types::ReportOutcome::Completed => "completed",
                    crate::types::ReportOutcome::Failed => "failed",
                },
                "posted": report.posted,
                "createdAt": report.created_at,
                "summary": report.summary,
            })
        })
        .collect()
}

fn phase_name(phase: crate::types::JobPhase) -> &'static str {
    match serde_json::to_value(phase) {
        Ok(Json::String(name)) => Box::leak(name.into_boxed_str()),
        _ => "unknown",
    }
}

/* ------------------------------------------------------------------------ */
/* Dashboard                                                                */
/* ------------------------------------------------------------------------ */

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The status dashboard: a static shell that live-updates via `/api/*`.
/// Served verbatim; no server-side data is ever embedded in it.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

const HTML_HEAD: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>DumpAnalyzer status</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0 auto;
         max-width: 1080px; padding: 1.5rem; background: #f7f8fa; color: #1c2430; }
  header h1 { margin: 0; font-size: 1.4rem; }
  .version { color: #667; font-size: 0.9rem; font-weight: normal; }
  .muted { color: #667; }
  .mono { font-family: ui-monospace, monospace; font-size: 0.85rem; }
  .cards { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0; }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 8px;
          padding: 0.6rem 1rem; min-width: 110px; }
  .card-num { font-size: 1.3rem; font-weight: 600; }
  .card-label { font-size: 0.75rem; color: #667; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border: 1px solid #e3e6ea; border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 0.45rem 0.7rem; font-size: 0.85rem;
           border-bottom: 1px solid #eef1f4; }
  th { background: #f0f2f5; font-size: 0.75rem; text-transform: uppercase;
       letter-spacing: 0.04em; color: #556; }
  section { margin-bottom: 1.5rem; }
  h2 { font-size: 1rem; }
  .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
           font-size: 0.75rem; font-weight: 600; }
  .badge.gray { background: #eceff3; color: #556; }
  .badge.blue { background: #e2ecfd; color: #1a56c4; }
  .badge.amber { background: #fdf0d5; color: #9a6200; }
  .badge.purple { background: #efe2fd; color: #6a24b8; }
  .badge.green { background: #dcf5e3; color: #18743c; }
  .badge.dark { background: #d9dee5; color: #334; }
  .badge.red { background: #fde2e1; color: #b3261e; }
  footer a { color: #1a56c4; }
  form.inline { display: inline; }
</style>
</head><body>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_parsing() {
        assert_eq!(
            parse_request_line(b"GET /api/status HTTP/1.1"),
            (Some("GET".to_string()), Some("/api/status".to_string()))
        );
        assert_eq!(
            parse_request_line(b"GET /x?y=1 HTTP/1.0"),
            (Some("GET".to_string()), Some("/x?y=1".to_string()))
        );
        assert_eq!(parse_request_line(b"garbage"), (None, None));
        assert_eq!(
            parse_request_line(b"GET /only HTTP/1.1 EXTRA"),
            (None, None)
        );
        assert_eq!(parse_request_line(b"GET relative HTTP/1.1"), (None, None));
    }

    #[test]
    fn escaping_covers_html_metacharacters() {
        assert_eq!(
            escape("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn phase_names_match_spec_spellings() {
        assert_eq!(phase_name(crate::types::JobPhase::Discovered), "discovered");
        assert_eq!(phase_name(crate::types::JobPhase::Reporting), "reporting");
    }
}
