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
use crate::state::{JobRow, Store};
use crate::sync::{CancellationToken, initial_scan};
use crate::types::{AnalyzerError, Result};

/// Hard cap on the request head; the surface is GET-only and bodyless.
const MAX_HEAD_BYTES: usize = 8192;

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

/// Dependencies of the webhook receiver route (`POST /webhooks`): the
/// shared client/store/config plus the daemon shutdown token that
/// [`crate::sync::apply_event`] observes.
pub struct WebhookDeps {
    client: Arc<LedgerClient>,
    store: Store,
    config: Config,
    shutdown: CancellationToken,
}

impl WebhookDeps {
    /// Bundles the four handles a webhook delivery needs.
    pub fn new(
        client: Arc<LedgerClient>,
        store: Store,
        config: Config,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            client,
            store,
            config,
            shutdown,
        }
    }
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
    /// Catalog browsing is independent of automatic analysis and queue state.
    explorer: Option<Arc<crate::explorer::DumpsExplorer>>,
    /// Manual catalog re-scan (`POST /-/rescan`); `None` when unwired.
    rescan: Option<RescanDeps>,
    /// Ledger webhook receiver (`POST /webhooks`); `None` when disabled.
    webhook: Option<WebhookDeps>,
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
            explorer: None,
            rescan: None,
            webhook: None,
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

    /// Attaches the customer/case catalog backing `GET /api/dumps`.
    pub fn with_explorer(mut self, explorer: Arc<crate::explorer::DumpsExplorer>) -> Self {
        self.explorer = Some(explorer);
        self
    }

    /// Attaches the webhook receiver dependencies (`POST /webhooks`).
    /// Without them the route answers 404.
    pub fn with_webhook(mut self, deps: WebhookDeps) -> Self {
        self.webhook = Some(deps);
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
    tracing::info!(%local, "dashboard listening (read views and explicit analysis actions)");
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
    /// `X-DumpLedger-Signature-256` (webhook deliveries only).
    signature: Option<String>,
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
                &json_response(400, json!({"error":"request_too_large"})),
            )
            .await;
        }
    };

    // Parse the head into owned values before the body read mutates `buf`.
    let mut lines = buf[..head_len].split(|b| *b == b'\n');
    let request_line: Vec<u8> = lines.next().unwrap_or(&[]).to_vec();
    let mut content_length = 0usize;
    let mut authorization = None;
    let mut signature = None;
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
        } else if name
            .trim()
            .eq_ignore_ascii_case("x-dumpledger-signature-256")
        {
            signature = Some(value.trim().to_string());
        }
    }
    if content_length > MAX_BODY_BYTES {
        return write_response(
            &mut stream,
            &json_response(400, json!({"error":"request_too_large"})),
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
                &json_response(400, json!({"error":"request_too_large"})),
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
        signature,
        body,
    };
    let response = route(&request, context).await;
    write_response(&mut stream, &response).await
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
    headers: &'static [(&'static str, &'static str)],
    body: Vec<u8>,
}

/// Strict Content-Security-Policy for every HTML response: the shell and the
/// result pages may only load same-origin CSS/JS; inline SVG and `data:` images
/// are allowed. Inline styles, inline scripts and inline event handlers are
/// forbidden — the dashboard keeps all presentation in `src/ui/app.css` and
/// all behaviour in `src/ui/dashboard.js`.
const HTML_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; font-src 'self'; connect-src 'self'; \
     form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const HTML_HEADERS: &[(&str, &str)] = &[("content-security-policy", HTML_CSP)];

fn json_response(status: u16, value: Json) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8",
        headers: &[],
        body: serde_json::to_vec_pretty(&value).expect("json serialization cannot fail"),
    }
}

/// HTML response with the strict CSP headers (dashboard shell and result pages).
fn html_response(status: u16, body: impl Into<Vec<u8>>) -> Response {
    Response {
        status,
        content_type: "text/html; charset=utf-8",
        headers: HTML_HEADERS,
        body: body.into(),
    }
}

/// Static asset response (CSS/JS embedded in the binary at compile time).
fn asset_response(content_type: &'static str, body: &'static str) -> Response {
    Response {
        status: 200,
        content_type,
        headers: &[],
        body: body.as_bytes().to_vec(),
    }
}

fn invalid_query() -> Response {
    json_response(400, json!({"error":"invalid_query"}))
}

fn query_params(
    request: &Request,
    allowed: &[&str],
) -> std::result::Result<std::collections::BTreeMap<String, String>, Response> {
    let url = reqwest::Url::parse(&format!("http://localhost{}", request.path))
        .map_err(|_| invalid_query())?;
    let mut params = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if !allowed.contains(&key.as_ref())
            || (key == "q" && value.chars().count() > 256)
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(invalid_query());
        }
    }
    Ok(params)
}

fn query_page(
    params: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<(u32, u32), Response> {
    let number = |key: &str, default| match params.get(key) {
        None => Ok(default),
        Some(raw) => raw.parse::<u32>().map_err(|_| invalid_query()),
    };
    let page = number("page", 1)?;
    let size = number("pageSize", 25)?;
    if page == 0 || !(1..=100).contains(&size) {
        return Err(invalid_query());
    }
    Ok((page, size))
}

fn catalog_error(err: AnalyzerError) -> Response {
    let status = match &err {
        AnalyzerError::Server { status: 400, .. } => 400,
        AnalyzerError::Server { status: 404, code }
            if code.as_deref() == Some("scope_not_found") =>
        {
            404
        }
        _ if err.is_transient() => 503,
        _ => 500,
    };
    json_response(
        status,
        json!({"error":"catalog_unavailable", "message":err.to_string()}),
    )
}

fn overlay_manual_phases(
    context: &UiContext,
    dumps: &mut [crate::explorer::ExplorerDump],
) -> Result<()> {
    let active = active_manual_jobs(context)?;
    for dump in dumps {
        if let Some(run) = active.iter().find(|run| {
            run.identity.dump_id == dump.dump_id
                && dump.sha256.as_ref() == Some(&run.identity.input_sha256)
                && run.identity.analyzer_version == context.version
        }) {
            dump.analysis_phase = Some(run.phase);
        }
    }
    Ok(())
}

async fn route(request: &Request, context: &UiContext) -> Response {
    if request.method.is_empty() || request.path.is_empty() {
        return json_response(400, json!({ "error": "invalid_request" }));
    }
    let path = request.path.split(['?', '#']).next().unwrap_or("/");
    match (request.method.as_str(), path) {
        ("GET", "/") => html_response(200, DASHBOARD_HTML),
        // Static dashboard assets are embedded at compile time; the strict CSP
        // allows them because they are same-origin.
        ("GET", "/assets/gentelella.css") => {
            asset_response("text/css; charset=utf-8", GENTELELLA_CSS)
        }
        ("GET", "/assets/app.css") => asset_response("text/css; charset=utf-8", APP_CSS),
        ("GET", "/assets/dashboard.js") => {
            asset_response("text/javascript; charset=utf-8", DASHBOARD_JS)
        }
        ("GET", "/api/capabilities") => json_response(
            200,
            json!({
                "analyzer": context.analyzer.is_some(),
                "rescan": context.rescan.is_some(),
                "explorer": context.explorer.is_some(),
            }),
        ),
        ("GET", "/api/status") => json_response(200, status_json(context)),
        ("GET", detail_path) if detail_path.starts_with("/api/reports/") => {
            if request.path.contains('?') {
                return invalid_query();
            }
            let suffix = &detail_path["/api/reports/".len()..];
            let segments: Vec<&str> = suffix.split('/').collect();
            let report_id = segments[0];
            if report_id.len() > 80
                || !report_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return invalid_query();
            }
            match context.store.local_reports().get_detail(report_id) {
                Ok(Some(detail)) => {
                    let value = detail_json(detail);
                    if segments.len() == 1 {
                        json_response(200, value)
                    } else if segments.len() == 3 && segments[1] == "evidence" {
                        let found = value["report"]["evidence"].as_array().and_then(|entries| {
                            entries
                                .iter()
                                .find(|entry| entry["id"].as_str() == Some(segments[2]))
                        });
                        match found {
                            Some(evidence) => json_response(200, evidence.clone()),
                            None => json_response(404, json!({"error":"evidence_not_found"})),
                        }
                    } else {
                        json_response(404, json!({"error":"not_found"}))
                    }
                }
                Ok(None) => json_response(404, json!({"error":"report_not_found"})),
                Err(err) => json_response(500, json!({"error":format!("state: {err}")})),
            }
        }
        ("GET", "/api/jobs") => match queue_jobs(context) {
            Ok(jobs) => json_response(200, json!({ "jobs": jobs_json(&jobs) })),
            Err(err) => json_response(500, json!({ "error": format!("state: {err}") })),
        },
        ("GET", "/api/dumps/browse") => {
            let params =
                match query_params(request, &["customerId", "caseId", "q", "page", "pageSize"]) {
                    Ok(params) => params,
                    Err(response) => return response,
                };
            let (page, page_size) = match query_page(&params) {
                Ok(page) => page,
                Err(response) => return response,
            };
            let customer_id = params.get("customerId").cloned();
            let case_id = params.get("caseId").cloned();
            if (case_id.is_some() && customer_id.is_none())
                || (crate::wire::DumpCatalogQuery {
                    customer_id: customer_id.clone(),
                    case_id: case_id.clone(),
                    ..Default::default()
                })
                .validate()
                .is_err()
            {
                return invalid_query();
            }
            let Some(explorer) = &context.explorer else {
                return json_response(503, json!({"error":"explorer_unavailable"}));
            };
            let query = crate::explorer::BrowseQuery {
                customer_id,
                case_id,
                q: params.get("q").cloned().unwrap_or_default(),
                page: page as usize,
                page_size: page_size as usize,
            };
            match explorer.browse(&query).await {
                Ok(mut result) => {
                    if let Err(err) = overlay_manual_phases(context, &mut result.dumps) {
                        return json_response(500, json!({"error":err.to_string()}));
                    }
                    json_response(200, json!(result))
                }
                Err(err) => catalog_error(err),
            }
        }
        ("GET", "/api/dumps") => {
            let Some(explorer) = &context.explorer else {
                return json_response(503, json!({"error":"explorer_unavailable"}));
            };
            match explorer.snapshot().await {
                Ok(mut snapshot) => {
                    let active = match active_manual_jobs(context) {
                        Ok(active) => active,
                        Err(err) => {
                            return json_response(500, json!({"error":format!("state: {err}")}));
                        }
                    };
                    for customer in &mut snapshot.customers {
                        for case in &mut customer.cases {
                            for dump in &mut case.dumps {
                                if let Some(run) = active.iter().find(|run| {
                                    run.identity.dump_id == dump.dump_id
                                        && dump.sha256.as_ref() == Some(&run.identity.input_sha256)
                                        && run.identity.analyzer_version == context.version
                                }) {
                                    dump.analysis_phase = Some(run.phase);
                                }
                            }
                        }
                    }
                    json_response(200, json!(snapshot))
                }
                Err(err) => json_response(
                    if err.is_transient() { 503 } else { 500 },
                    json!({"error":"catalog_unavailable", "message":err.to_string()}),
                ),
            }
        }
        ("GET", "/api/reports") => {
            let params =
                match query_params(request, &["q", "outcome", "delivery", "page", "pageSize"]) {
                    Ok(params) => params,
                    Err(response) => return response,
                };
            let (page, page_size) = match query_page(&params) {
                Ok(page) => page,
                Err(response) => return response,
            };
            let outcome = match params.get("outcome").map(String::as_str) {
                None | Some("all") => None,
                Some("completed") => Some(crate::types::ReportOutcome::Completed),
                Some("failed") => Some(crate::types::ReportOutcome::Failed),
                _ => return invalid_query(),
            };
            let posted = match params.get("delivery").map(String::as_str) {
                None | Some("all") => None,
                Some("posted") => Some(true),
                Some("pending") => Some(false),
                _ => return invalid_query(),
            };
            let query = crate::state::ReportQuery {
                q: params.get("q").cloned().unwrap_or_default(),
                outcome,
                posted,
                page,
                page_size,
            };
            match context.store.local_reports().page(&query) {
                Ok(result) => json_response(
                    200,
                    json!({
                        "reports": reports_json(&result.reports), "total": result.total,
                        "matching": result.matching, "page": result.page,
                        "pageSize": result.page_size, "totalPages": result.total_pages,
                        "pending": result.pending,
                    }),
                ),
                Err(err) => json_response(500, json!({ "error": format!("state: {err}") })),
            }
        }
        ("POST", "/webhooks") => {
            let Some(deps) = &context.webhook else {
                return json_response(404, json!({ "error": "not_found" }));
            };
            let secret = match crate::webhook::stored_secret(&deps.store) {
                Ok(secret) => secret,
                Err(err) => return json_response(500, json!({ "error": err.to_string() })),
            };
            let Some(secret) = secret else {
                // Registration outstanding: the ledger retries with backoff.
                return json_response(503, json!({ "error": "webhook_unavailable" }));
            };
            let Some(signature) = request.signature.as_deref() else {
                return json_response(401, json!({ "error": "invalid_signature" }));
            };
            if !crate::webhook::verify_signature(&secret, &request.body, signature) {
                return json_response(401, json!({ "error": "invalid_signature" }));
            }
            let event: crate::wire::EventFeedEntry = match serde_json::from_slice(&request.body) {
                Ok(event) => event,
                Err(_) => return json_response(400, json!({ "error": "invalid_request" })),
            };
            if event.validate().is_err() {
                return json_response(400, json!({ "error": "invalid_request" }));
            }
            match crate::sync::apply_event(
                &deps.client,
                &deps.store,
                &deps.config,
                &event,
                &deps.shutdown,
            )
            .await
            {
                Ok(true) => json_response(200, json!({ "accepted": true })),
                // Shutdown mid-apply: not acknowledged, so the ledger retries.
                Ok(false) => json_response(503, json!({ "error": "shutting_down" })),
                Err(err) if err.is_transient() => {
                    json_response(503, json!({ "error": "transient" }))
                }
                Err(err) => json_response(500, json!({ "error": err.to_string() })),
            }
        }
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
            html_response(200, store_token_result_page(outcome))
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
            html_response(200, scope_result_page(&scope, outcome))
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
            html_response(200, analyze_result_page(dump_id, outcome))
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
            html_response(200, rescan_result_page(outcome))
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
    let mut body = String::new();
    match outcome {
        Ok(()) => body.push_str(
            "<p><span class=\"status status-green\">stored</span> the token is the daemon's \
             latest-used credential and is used by action forms immediately and by the \
             pipeline from the next boot.</p>",
        ),
        Err(err) => {
            body.push_str(&format!(
                "<p><span class=\"status status-red\">not stored</span> {}</p>",
                escape(&match err {
                    StoreTokenError::Invalid => "malformed token".to_string(),
                    StoreTokenError::Rejected => "the ledger rejected this token".to_string(),
                    StoreTokenError::Unreachable(m) => format!("ledger unreachable: {m}"),
                }),
            ));
        }
    }
    result_page("Store analyzer token", &body)
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
    let mut body = String::new();
    match outcome {
        Ok(report) => {
            body.push_str(&format!(
                "<p><strong>{}</strong>: {} considered, {} reported, {} skipped</p>",
                escape(&report.scope),
                report.considered,
                report.reports.len(),
                report.skipped.len()
            ));
            body.push_str(
                "<div class=\"table-responsive\"><table class=\"table\">\
                 <thead><tr><th scope=\"col\">Dump</th><th scope=\"col\">Outcome</th>\
                 <th scope=\"col\">Summary</th></tr></thead><tbody>",
            );
            for r in &report.reports {
                let outcome_str = match r.outcome {
                    crate::types::ReportOutcome::Completed => "completed",
                    crate::types::ReportOutcome::Failed => "failed",
                };
                body.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td><span class=\"status {}\">{}</span></td><td>{}</td></tr>",
                    escape(&r.identity.dump_id),
                    if outcome_str == "completed" {
                        "status-green"
                    } else {
                        "status-red"
                    },
                    outcome_str,
                    escape(&r.summary),
                ));
            }
            for skip in &report.skipped {
                body.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td><span class=\"status status-muted\">skipped</span></td><td class=\"muted\">{}</td></tr>",
                    escape(&skip.dump_id),
                    escape(&skip.reason),
                ));
            }
            body.push_str("</tbody></table></div>");
        }
        Err(err) => {
            body.push_str(&format!(
                "<p><span class=\"status status-red\">error</span> {}: {}</p>",
                escape(&scope.describe()),
                escape(&err.to_string()),
            ));
        }
    }
    result_page("Scope analysis", &body)
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
    let mut body = String::new();
    match outcome {
        Ok(inserted) => {
            body.push_str(&format!(
                "<p><span class=\"status status-green\">ok</span> \
                 <span class=\"mono\">inserted: {inserted}</span></p>\
                 <p>{inserted} new job(s) scheduled from the catalog.</p>"
            ));
        }
        Err(err) => {
            body.push_str(&format!(
                "<p><span class=\"status status-red\">error</span></p><p>{}</p>",
                escape(&err.to_string()),
            ));
        }
    }
    result_page("Catalog rescan", &body)
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
    let mut body = String::new();
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
            body.push_str(&format!(
                "<p><span class=\"status {}\">{}</span> <span class=\"mono\">{}</span></p>\
                 <p>{}</p><pre class=\"mono evidence-pre\">{}</pre>",
                if outcome_str == "completed" {
                    "status-green"
                } else {
                    "status-red"
                },
                outcome_str,
                escape(dump_id),
                escape(&report.summary),
                escape(&facts),
            ));
        }
        Err(err) => {
            body.push_str(&format!(
                "<p><span class=\"status status-red\">error</span> <span class=\"mono\">{}</span></p><p>{}</p>",
                escape(dump_id),
                escape(&err.to_string()),
            ));
        }
    }
    result_page("On-demand analysis", &body)
}
async fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    for (name, value) in response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await
}

/// Discovery candidates remain durable for automatic scheduling; the
/// operator's work queue starts once an execution has been claimed.
fn queue_jobs(context: &UiContext) -> Result<Vec<JobRow>> {
    let mut jobs: Vec<JobRow> = context
        .store
        .jobs()
        .work_queue()?
        .into_iter()
        .filter(|row| {
            matches!(
                row.phase,
                crate::types::JobPhase::Claimed
                    | crate::types::JobPhase::Fetching
                    | crate::types::JobPhase::Staged
                    | crate::types::JobPhase::Analyzing
                    | crate::types::JobPhase::Reporting
            )
        })
        .collect();
    for run in active_manual_jobs(context)? {
        if !jobs.iter().any(|row| row.identity == run.identity) {
            jobs.push(run);
        }
    }
    jobs.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.identity.dump_id.cmp(&right.identity.dump_id))
    });
    Ok(jobs)
}

fn active_manual_jobs(context: &UiContext) -> Result<Vec<JobRow>> {
    match &context.analyzer {
        Some(analyzer) => analyzer.active_jobs(),
        None => Ok(Vec::new()),
    }
}

fn status_json(context: &UiContext) -> Json {
    let jobs = queue_jobs(context).unwrap_or_default();
    let (reports, pending) = context.store.local_reports().counts().unwrap_or_default();
    let mut by_phase = serde_json::Map::new();
    for row in &jobs {
        let phase = phase_name(row.phase);
        let entry = by_phase
            .entry(phase.to_string())
            .or_insert_with(|| json!(0));
        *entry = json!(entry.as_u64().unwrap_or(0) + 1);
    }
    json!({
        "name": context.name,
        "version": context.version,
        "baseUrl": context.base_url,
        "upSeconds": context.started.elapsed().as_secs(),
        "pollIntervalMs": context.poll_interval_ms,
        "sshConfigured": context.ssh_configured,
        "eventCursor": context.store.cursors().get("event_cursor").ok().flatten(),
        "jobs": { "total": jobs.len(), "byPhase": by_phase },
        "reports": { "total": reports, "pending": pending },
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

fn reports_json(reports: &[crate::state::ReportListRow]) -> Vec<Json> {
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
                "reportId": report.report_id,
                "schemaVersion": report.schema_version,
                "detailAvailable": report.detail_available,
                "fullDelivery": report.full_delivery,
            })
        })
        .collect()
}

fn detail_json(detail: crate::state::ReportDetail) -> Json {
    match detail {
        crate::state::ReportDetail::Rich(stored) => json!({
            "reportId":stored.report.report_id,"schemaVersion":2,"detailAvailable":true,
            "fullDelivery":stored.delivery,"digest":stored.digest,"report":stored.report,
            "legacy":null,"warning":null,
        }),
        crate::state::ReportDetail::Legacy(row) => json!({
            "reportId":crate::report::legacy_id(&row.identity()),"schemaVersion":1,"detailAvailable":false,
            "fullDelivery":if row.posted {"summaryOnly"} else {"localOnly"},"digest":null,"report":null,
            "legacy":{"identity":row.identity(),"outcome":row.outcome,"summary":row.summary,
                "facts":serde_json::from_str::<Json>(&row.facts_json).unwrap_or(Json::Null),"createdAt":row.created_at,"posted":row.posted},
            "warning":"Legacy report — detailed sections were not captured",
        }),
    }
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
/// Served verbatim; no server-side data is ever embedded in it. The shell,
/// the vendored Gentelella base stylesheet, the DumpAnalyzer app layer and the
/// behaviour script are separate same-origin assets so the strict CSP can
/// forbid inline code and inline styles.
const DASHBOARD_HTML: &str = include_str!("ui/dashboard.html");
const GENTELELLA_CSS: &str = include_str!("ui/gentelella.css");
const APP_CSS: &str = include_str!("ui/app.css");
const DASHBOARD_JS: &str = include_str!("ui/dashboard.js");

/// Gentelella-styled public page for the browser form POST result routes.
///
/// It links the same static assets as the dashboard and embeds no credentials:
/// callers pass already-escaped body markup for the result card.
fn result_page(title: &str, body: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#f5f7fb">
<title>{title} · DumpAnalyzer</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Crect width='36' height='36' rx='8' fill='%231abb9c'/%3E%3Cpath d='M18 7 27 11v7c0 6-3.6 9.5-9 11.5C12.6 27.5 9 24 9 18v-7l9-4Z' fill='none' stroke='%2304231c' stroke-width='1.8'/%3E%3C/svg%3E">
<link rel="stylesheet" href="/assets/gentelella.css">
<link rel="stylesheet" href="/assets/app.css">
</head>
<body class="app-root public-page">
<a class="skip-link" href="#content">Skip to content</a>
<header class="auth-topbar">
<a class="auth-brand" href="/" aria-label="DumpAnalyzer dashboard"><span class="brand-icon" aria-hidden="true"><svg viewBox="0 0 36 36" aria-hidden="true" focusable="false"><path d="M18 3 31 8v9c0 8.4-5.2 13.4-13 16C10.2 30.4 5 25.4 5 17V8l13-5Z" fill="currentColor" opacity=".18"/><path d="M18 6.6 27.6 10v7c0 6.2-3.6 10.1-9.6 12.6C12 27.1 8.4 23.2 8.4 17v-7L18 6.6Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M13 15.2h10M13 19h10M13 22.8h6.2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span><span class="brand-name">DumpAnalyzer <small>Crash analysis daemon</small></span></a>
</header>
<main id="content" class="auth-page" tabindex="-1">
<section class="auth-card" aria-labelledby="result-title">
<h1 class="auth-title" id="result-title">{title}</h1>
<div class="result-body">{body}</div>
<p class="auth-footer"><a class="btn btn-outline btn-sm" href="/">Back to dashboard</a></p>
</section>
</main>
</body>
</html>
"##
    )
}

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
