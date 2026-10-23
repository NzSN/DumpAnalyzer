//! Deterministic CDB evidence followed by an optional evidence-only
//! assessment from a dedicated DeepSeek Harness (DSH) HTTP service: the
//! `dsh-http` tool-runner provider.
//!
//! Confinement (docs/analyzer-design.md, "DSH HTTP provider"): the service
//! is a dedicated analyzer-owned instance — loopback-bound or HTTPS with a
//! bearer token — running a zero-tool preset. Each run creates a fresh
//! session, anchors a bounded trajectory digest in the evidence record, and
//! a session prune is attempted on every path (success, reasoning failure,
//! and deadline alike). Reasoning failure preserves the owned debugger
//! evidence and deterministic assessment. The shared prompt/schema/
//! validation contract lives in [`crate::reason`].
//!
//! ## Analyzer adapter contract
//!
//! DSH ships as a developer preview, so the provider codes against this
//! minimal contract served by the pinned deployment's analyzer adapter; the
//! endpoint shapes live only here:
//!
//! * `POST /v1/analyzer-sessions` — body `{"preset": string, "provider"?:
//!   string, "model"?: string, "reasoningEffort"?: string,
//!   "contextWindow"?: number, "maxTokens"?: number, "apiKey"?: string}`;
//!   returns `{"sessionId": string}`. The route fields select one
//!   adapter-allowlisted provider and a model within it for the session's
//!   lifetime; the adapter owns the provider catalog and rejects anything
//!   else, so a request can never redirect evidence to an unconfigured
//!   gateway. The optional `apiKey` is the model provider credential for the
//!   session's headless runs: the adapter injects it into the child process
//!   environment under the selected provider's key variable, holds it only
//!   in memory, and drops it at session prune. It never enters prompts,
//!   evidence, logs, or reports.
//! * `POST /v1/analyzer-sessions/{id}/messages` — body `{"prompt":
//!   string}`; the server runs one zero-tool turn and returns `{"status":
//!   "completed", "response": <string|object>, "model"?: string}`. A
//!   string `response` carries the RootCause JSON text; an object carries
//!   it directly.
//! * `GET /v1/analyzer-sessions/{id}/events?limit=<n>` — bounded trajectory
//!   export, returns `{"events": [...]}`.
//! * `DELETE /v1/analyzer-sessions/{id}` — prunes the session; any 2xx or
//!   404 is accepted.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use reqwest::{Client, StatusCode, Url};
use serde_json::{Value, json};
use sha2::Digest;

/// JSON content type for request bodies (the approved reqwest feature
/// set has no `json` feature; bodies are encoded like the ledger client).
const JSON: &str = "application/json";
use tokio::time::Instant;

use crate::analysis_tools::AnalysisTools;
use crate::reason::{self, runner_error};
use crate::report::{ReportCapture, RootCause};
use crate::runner::{ExecTransport, SshCdbRunner};
use crate::types::{AnalyzerError, Result, RunOutput, RunRequest, ToolRunner};

/// reqwest read stall bound on every DSH route (deadline resets per
/// successful read; it never caps a healthy transfer). The shared run
/// deadline is the real budget for a reasoning turn.
const DSH_READ_TIMEOUT: Duration = Duration::from_secs(300);
/// A session prune gets its own small budget: the run deadline may already
/// be spent when it runs.
const PRUNE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded response sizes: session create, one message turn, and the
/// trajectory export.
const CREATE_RESPONSE_CAP: usize = 16 * 1024;
const MESSAGE_RESPONSE_CAP: usize = 64 * 1024;
const EVENTS_RESPONSE_CAP: usize = 2 * 1024 * 1024;
/// Bound on exported trajectory events for the evidence digest.
const EVENTS_EXPORT_LIMIT: usize = 256;

/// The analyzer-selected model route for one session. Every field is
/// optional; the adapter applies its pinned default route for unset fields
/// and rejects routes outside its allowlist. The route is fixed for the
/// session's lifetime.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DshRoute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
}

/// One session-create request: preset plus the optional route.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DshSessionRequest<'a> {
    preset: &'a str,
    #[serde(flatten)]
    route: &'a DshRoute,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis_mcp: Option<McpRequest<'a>>,
}

/// A capability for exactly one local analysis run. Never included in prompts,
/// evidence or trajectory labels; the bearer is redacted when formatted.
#[derive(Clone, Debug)]
pub struct DshAnalysisMcp {
    pub url: String,
    pub token: crate::config::SecretToken,
}

#[derive(serde::Serialize)]
struct McpRequest<'a> {
    url: &'a str,
    token: &'a str,
}

/// One completed message turn from the DSH service.
#[derive(Debug)]
pub struct DshTurn {
    /// The model's response: RootCause JSON text or the object itself.
    pub response: Value,
    /// Server-reported model identity, when present and well-formed.
    pub model: Option<String>,
}

/// Bounded trajectory anchor recorded in the assessment evidence entry.
#[derive(Debug)]
pub struct TrajectoryDigest {
    pub events: usize,
    /// Lowercase hex SHA-256 of the canonical exported event array.
    pub sha256: String,
}

/// The DSH analyzer adapter seam. The runner talks only to this trait;
/// `HttpDshApi` implements the contract above, tests implement it in-memory
/// or over wiremock.
#[async_trait::async_trait]
pub trait DshApi: Send + Sync {
    async fn create_session(
        &self,
        preset: &str,
        route: &DshRoute,
        api_key: Option<&str>,
    ) -> Result<String>;
    /// Opt-in capability handoff. An adapter must explicitly acknowledge it;
    /// implementations supporting only the original contract fail closed.
    async fn create_session_with_tools(
        &self,
        _preset: &str,
        _route: &DshRoute,
        _mcp: &DshAnalysisMcp,
    ) -> Result<String> {
        Err(runner_error("DSH adapter does not support analysis tools"))
    }
    async fn send_message(&self, session_id: &str, prompt: &str) -> Result<DshTurn>;
    async fn trajectory_digest(&self, session_id: &str) -> Result<TrajectoryDigest>;
    async fn close_session(&self, session_id: &str) -> Result<()>;
}

/// HTTP client for the adapter contract: one `reqwest` client with the
/// ledger client's posture (rustls, optional PEM pinning, read stall bound,
/// bearer token redacted by [`crate::config::SecretToken`]).
pub struct HttpDshApi {
    http: Client,
    base_url: Url,
    authorization: Option<HeaderValue>,
    /// Model API key forwarded per session create; held only as the secret
    /// wrapper, never formatted into requests other than the create body.
    api_key: Option<crate::config::SecretToken>,
}

impl HttpDshApi {
    /// Builds the client. `tls_ca_cert` pins a self-hosted instance's
    /// self-signed certificate in addition to system roots — the deliberate
    /// pinning path, never blanket verification-off (mirrors
    /// [`crate::client::LedgerClient`]).
    pub fn new(
        base_url: Url,
        token: Option<&crate::config::SecretToken>,
        tls_ca_cert: Option<&Path>,
    ) -> Result<Self> {
        Self::new_with_api_key(base_url, token, None, tls_ca_cert)
    }

    /// Like [`Self::new`], additionally forwarding `api_key` to the adapter
    /// at session create (`DUMP_ANALYZER_DSH_API_KEY`).
    pub fn new_with_api_key(
        base_url: Url,
        token: Option<&crate::config::SecretToken>,
        api_key: Option<&crate::config::SecretToken>,
        tls_ca_cert: Option<&Path>,
    ) -> Result<Self> {
        let authorization = match token {
            Some(token) => Some(
                HeaderValue::from_str(&format!("Bearer {}", token.expose())).map_err(|_| {
                    AnalyzerError::Config(
                        "DUMP_ANALYZER_DSH_TOKEN cannot form a valid `Authorization: Bearer` header value"
                            .to_owned(),
                    )
                })?,
            ),
            None => None,
        };
        let mut builder = Client::builder()
            // Session creation carries credentials and a private run capability.
            // Never forward either body to a redirected endpoint.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("dump-analyzer/", env!("CARGO_PKG_VERSION")))
            .read_timeout(DSH_READ_TIMEOUT);
        if let Some(path) = tls_ca_cert {
            let pem = std::fs::read(path).map_err(|err| {
                AnalyzerError::Config(format!(
                    "DUMP_ANALYZER_TLS_CA_CERT: cannot read {}: {err}",
                    path.display()
                ))
            })?;
            // from_pem_bundle — never from_pem: a file without a single
            // CERTIFICATE block must fail fast, not silently trust nothing
            // extra (from_pem accepts an empty bundle).
            let bundle = reqwest::Certificate::from_pem_bundle(&pem).map_err(|err| {
                AnalyzerError::Config(format!(
                    "DUMP_ANALYZER_TLS_CA_CERT: {} is not a PEM certificate: {err}",
                    path.display()
                ))
            })?;
            if bundle.is_empty() {
                return Err(AnalyzerError::Config(format!(
                    "DUMP_ANALYZER_TLS_CA_CERT: {} contains no CERTIFICATE block",
                    path.display()
                )));
            }
            for cert in bundle {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder.build().map_err(|err| {
            AnalyzerError::Config(format!("failed to build the DSH HTTP client: {err}"))
        })?;
        Ok(Self {
            http,
            base_url,
            authorization,
            api_key: api_key.cloned(),
        })
    }

    /// Joins contract path segments onto the configured base URL (a base
    /// path prefix is preserved).
    fn url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| runner_error("DSH base URL cannot carry path segments"))?
            .extend(segments);
        Ok(url)
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let mut builder = self.http.request(method, url);
        if let Some(authorization) = &self.authorization {
            builder = builder.header(AUTHORIZATION, authorization.clone());
        }
        builder
    }

    async fn create(
        &self,
        preset: &str,
        route: &DshRoute,
        api_key: Option<&str>,
        mcp: Option<&DshAnalysisMcp>,
    ) -> Result<String> {
        if mcp.is_some()
            && !matches!(
                self.base_url.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]")
            )
        {
            return Err(runner_error(
                "analysis MCP requires a co-located loopback DSH adapter",
            ));
        }
        if mcp.is_some() && self.authorization.is_none() {
            return Err(runner_error(
                "analysis MCP requires an authenticated DSH adapter",
            ));
        }
        let url = self.url(&["v1", "analyzer-sessions"])?;
        let body = DshSessionRequest {
            preset,
            route,
            api_key: api_key.or(self.api_key.as_ref().map(|key| key.expose())),
            analysis_mcp: mcp.map(|mcp| McpRequest {
                url: &mcp.url,
                token: mcp.token.expose(),
            }),
        };
        let response = self
            .request(reqwest::Method::POST, url)
            .header(CONTENT_TYPE, JSON)
            .body(serde_json::to_vec(&body).map_err(|err| runner_error(err.to_string()))?)
            .send()
            .await
            .map_err(|err| runner_error(format!("DSH session create failed: {err}")))?;
        let value = json_response(response, CREATE_RESPONSE_CAP, "session create").await?;
        let id = session_id(&value)?;
        if mcp.is_some() && value.get("analysisTools").and_then(Value::as_bool) != Some(true) {
            let _ = tokio::time::timeout(PRUNE_TIMEOUT, self.close_session(&id)).await;
            return Err(runner_error(
                "DSH adapter did not acknowledge analysis tools",
            ));
        }
        Ok(id)
    }
}

#[async_trait::async_trait]
impl DshApi for HttpDshApi {
    async fn create_session(
        &self,
        preset: &str,
        route: &DshRoute,
        api_key: Option<&str>,
    ) -> Result<String> {
        self.create(preset, route, api_key, None).await
    }

    async fn create_session_with_tools(
        &self,
        preset: &str,
        route: &DshRoute,
        mcp: &DshAnalysisMcp,
    ) -> Result<String> {
        self.create(preset, route, None, Some(mcp)).await
    }

    async fn send_message(&self, session_id: &str, prompt: &str) -> Result<DshTurn> {
        let url = self.url(&["v1", "analyzer-sessions", session_id, "messages"])?;
        let body = json!({"prompt": prompt});
        let response = self
            .request(reqwest::Method::POST, url)
            .header(CONTENT_TYPE, JSON)
            .body(serde_json::to_vec(&body).map_err(|err| runner_error(err.to_string()))?)
            .send()
            .await
            .map_err(|err| runner_error(format!("DSH message failed: {err}")))?;
        let value = json_response(response, MESSAGE_RESPONSE_CAP, "message").await?;
        message_turn(&value)
    }

    async fn trajectory_digest(&self, session_id: &str) -> Result<TrajectoryDigest> {
        let mut url = self.url(&["v1", "analyzer-sessions", session_id, "events"])?;
        url.query_pairs_mut()
            .append_pair("limit", &EVENTS_EXPORT_LIMIT.to_string());
        let response = self
            .request(reqwest::Method::GET, url)
            .send()
            .await
            .map_err(|err| runner_error(format!("DSH trajectory export failed: {err}")))?;
        let value = json_response(response, EVENTS_RESPONSE_CAP, "trajectory export").await?;
        let events = value
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| runner_error("DSH trajectory export has no events array"))?;
        let canonical = serde_json::to_vec(events).map_err(|err| runner_error(err.to_string()))?;
        Ok(TrajectoryDigest {
            events: events.len(),
            sha256: hex::encode(sha2::Sha256::digest(&canonical)),
        })
    }

    async fn close_session(&self, session_id: &str) -> Result<()> {
        let url = self.url(&["v1", "analyzer-sessions", session_id])?;
        let response = self
            .request(reqwest::Method::DELETE, url)
            .send()
            .await
            .map_err(|err| runner_error(format!("DSH session prune failed: {err}")))?;
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(runner_error(format!(
                "DSH session prune failed with HTTP {status}"
            )))
        }
    }
}

/// A validated, well-formed session identifier from the service.
fn session_id(value: &Value) -> Result<String> {
    let id = value
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| runner_error("DSH session response has no sessionId"))?;
    if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        return Err(runner_error(
            "DSH session response carries an invalid sessionId",
        ));
    }
    Ok(id.to_owned())
}

/// A validated message-turn envelope. `status` other than `"completed"` is
/// a reasoning failure; the model identity is accepted only when printable.
fn message_turn(value: &Value) -> Result<DshTurn> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("completed");
    if status != "completed" {
        let bounded: String = status
            .chars()
            .take(80)
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        return Err(runner_error(format!(
            "DSH message turn did not complete: status {bounded}"
        )));
    }
    let response = value
        .get("response")
        .cloned()
        .ok_or_else(|| runner_error("DSH message response has no response field"))?;
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty() && m.len() <= 256 && !m.chars().any(char::is_control))
        .map(str::to_owned);
    Ok(DshTurn { response, model })
}

/// Reads one bounded JSON response body; the cap fails the read, never
/// truncates into a partial parse.
async fn json_response(response: reqwest::Response, cap: usize, what: &str) -> Result<Value> {
    let status = response.status();
    if !status.is_success() {
        return Err(runner_error(format!(
            "DSH {what} failed with HTTP {status}"
        )));
    }
    let mut response = response;
    let mut buf = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| runner_error(format!("DSH {what} read failed: {err}")))?
    {
        if buf.len() + chunk.len() > cap {
            return Err(runner_error(format!(
                "DSH {what} response exceeds the {cap}-byte budget"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf)
        .map_err(|err| runner_error(format!("DSH {what} response is not JSON: {err}")))
}

/// Decodes one turn into a bounded [`RootCause`]: a string response carries
/// the JSON text, an object carries it directly.
fn decode_turn(turn: &DshTurn) -> Result<RootCause> {
    let payload = match &turn.response {
        Value::String(text) => serde_json::from_str(text)
            .map_err(|err| runner_error(format!("reasoner assessment is not JSON: {err}")))?,
        other => other.clone(),
    };
    reason::decode_root_cause(payload)
}

/// Deterministic CDB capture over SSH, then an optional evidence-only
/// assessment from the dedicated DSH service. See the module docs for the
/// confinement and adapter contract.
pub struct DshCdbRunner<T: ExecTransport> {
    collector: SshCdbRunner<T>,
    api: Arc<dyn DshApi>,
    preset: String,
    route: DshRoute,
    analysis_tools: bool,
    forensicator_bin: Option<std::path::PathBuf>,
}

impl<T: ExecTransport> DshCdbRunner<T> {
    pub fn new(transport: T, api: Arc<dyn DshApi>, preset: impl Into<String>) -> Self {
        Self {
            collector: SshCdbRunner::new(transport),
            api,
            preset: preset.into(),
            route: DshRoute::default(),
            analysis_tools: false,
            forensicator_bin: None,
        }
    }
    pub fn with_remote_base(mut self, base: impl Into<String>) -> Self {
        self.collector = self.collector.with_remote_base(base);
        self
    }
    pub fn with_model(mut self, model: Option<String>) -> Self {
        self.route.model = model;
        self
    }
    /// The full route selection (provider, model, reasoning effort, catalog
    /// sizes), overriding any earlier `with_model` value.
    pub fn with_route(mut self, route: DshRoute) -> Self {
        self.route = route;
        self
    }

    /// Opt in to the six dump-scoped debugger tools. The default remains
    /// the existing evidence-only reasoner contract.
    pub fn with_analysis_tools(mut self, enabled: bool) -> Self {
        self.analysis_tools = enabled;
        self
    }

    /// Add Forensicator's native stdio MCP tools to the same dump-scoped
    /// bridge. The executable is operator configuration, never model input.
    pub fn with_forensicator(mut self, executable: Option<std::path::PathBuf>) -> Self {
        self.forensicator_bin = executable;
        self
    }

    /// One isolated session per run: assessment prompt, at most one
    /// formatting-correction turn, best-effort trajectory anchor, and a
    /// prune attempt on every path. Returns the accepted cause, the
    /// observed model, and the evidence-entry provenance label.
    async fn reason(
        &self,
        capture: &ReportCapture,
        deadline: Instant,
        mcp: Option<&DshAnalysisMcp>,
    ) -> Result<(RootCause, Option<String>, String)> {
        let prompt = if mcp.is_some() {
            reason::tool_assessment_prompt(capture)?
        } else {
            reason::assessment_prompt(capture)?
        };
        let session = tokio::time::timeout_at(deadline, async {
            match mcp {
                Some(mcp) => {
                    self.api
                        .create_session_with_tools(&self.preset, &self.route, mcp)
                        .await
                }
                None => {
                    self.api
                        .create_session(&self.preset, &self.route, None)
                        .await
                }
            }
        })
        .await
        .map_err(|_| runner_error("DSH session create exceeded shared run wall timeout"))??;
        let mut session_guard = DshSessionGuard {
            api: Arc::clone(&self.api),
            id: session.clone(),
            closed: false,
        };
        let assessed = tokio::time::timeout_at(deadline, async {
            let outcome = self
                .assess_in_session(&session, &prompt, mcp.is_some())
                .await;
            // The trajectory digest only anchors evidence; its failure is
            // tolerated and noted in the label.
            let digest = self.api.trajectory_digest(&session).await.ok();
            (outcome, digest)
        })
        .await;
        // Export-then-prune: on timeout the exchange future was dropped, so
        // the prune runs here with its own small budget, never unbounded.
        session_guard.close().await;
        let (outcome, digest) =
            assessed.map_err(|_| runner_error("reasoner exceeded shared run wall timeout"))?;
        let (cause, model) = outcome?;
        let mut label = if mcp.is_some() {
            format!("bounded DSH HTTP assessment with dump analysis MCP tools (session {session})")
        } else {
            format!("bounded evidence-only DSH HTTP assessment (zero-tool session {session})")
        };
        if let Some(effort) = &self.route.reasoning_effort {
            label.push_str(&format!("; effort={effort}"));
        }
        match digest {
            Some(digest) => label.push_str(&format!(
                "; trajectory {} events sha256:{}",
                digest.events,
                &digest.sha256[..16]
            )),
            None => label.push_str("; trajectory export unavailable"),
        }
        Ok((cause, model, label))
    }

    async fn assess_in_session(
        &self,
        session: &str,
        prompt: &str,
        tools: bool,
    ) -> Result<(RootCause, Option<String>)> {
        let turn = self.api.send_message(session, prompt).await?;
        match decode_turn(&turn) {
            Ok(cause) => Ok((cause, turn.model)),
            Err(_) => {
                // Correct only the response format once, inside the original
                // deadline; no rejected model text is echoed back.
                let correction = if tools {
                    reason::tool_format_correction_prompt()
                } else {
                    reason::FORMAT_CORRECTION_PROMPT.to_owned()
                };
                let corrected = self.api.send_message(session, &correction).await?;
                let cause = decode_turn(&corrected)?;
                Ok((cause, corrected.model.or(turn.model)))
            }
        }
    }
}

struct DshSessionGuard {
    api: Arc<dyn DshApi>,
    id: String,
    closed: bool,
}

impl DshSessionGuard {
    async fn close(&mut self) {
        if matches!(
            tokio::time::timeout(PRUNE_TIMEOUT, self.api.close_session(&self.id)).await,
            Ok(Ok(()))
        ) {
            self.closed = true;
        }
    }
}

impl Drop for DshSessionGuard {
    fn drop(&mut self) {
        if !self.closed {
            let api = Arc::clone(&self.api);
            let id = self.id.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = tokio::time::timeout(PRUNE_TIMEOUT, api.close_session(&id)).await;
                });
            }
        }
    }
}

#[async_trait::async_trait]
impl<T: ExecTransport + 'static> ToolRunner for DshCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        let deadline = Instant::now() + request.bounds.wall_timeout;
        let mut collection = request.clone();
        // Reserve part of the shared budget for collector cleanup and
        // optional reasoning, rather than granting a second full run
        // timeout (mirrors the `claude-cdb` provider).
        collection.bounds.wall_timeout = request.bounds.wall_timeout.mul_f64(0.8);
        let tool_mode = self.analysis_tools || self.forensicator_bin.is_some();
        let (mut output, session) = if tool_mode {
            let (output, session) = self.collector.begin_session(collection, deadline).await?;
            (output, Some(session))
        } else {
            let output = tokio::time::timeout_at(deadline, self.collector.run(collection))
                .await
                .map_err(|_| {
                    runner_error("deterministic collection exceeded shared run wall timeout")
                })??;
            (output, None)
        };
        let capture = output.capture.get_or_insert_with(ReportCapture::default);
        capture.provenance.provider = "dsh-http".into();
        // The adapter reports the session's actual route as
        // `provider/model` on each turn, replacing this nominal value.
        capture.provenance.model = match (&self.route.provider, &self.route.model) {
            (Some(provider), Some(model)) => Some(format!("{provider}/{model}")),
            (None, Some(model)) => Some(model.clone()),
            (Some(provider), None) => Some(format!("{provider}/<default>")),
            (None, None) => None,
        };
        if !capture.provenance.analysis_revision.is_empty() {
            capture.provenance.analysis_revision.push(';');
        }
        capture
            .provenance
            .analysis_revision
            .push_str(if self.forensicator_bin.is_some() {
                "reasoner=dsh-http-mcp-v1;forensicator=mcp-stdio-v1"
            } else if tool_mode {
                "reasoner=dsh-http-mcp-v1"
            } else {
                "reasoner=dsh-http-v1"
            });
        let outcome = if let Some(session) = session {
            let tools: Arc<dyn AnalysisTools> = match &self.forensicator_bin {
                Some(executable) => Arc::new(crate::forensicator::ForensicatorTools::new(
                    session.clone(),
                    executable.clone(),
                    &request,
                    deadline,
                )),
                None => session.clone(),
            };
            let outcome = match crate::analysis_mcp::McpServer::start(tools, deadline).await {
                Ok(mut server) => {
                    let mcp = DshAnalysisMcp {
                        url: server.endpoint().to_owned(),
                        token: crate::config::SecretToken::new(server.token()),
                    };
                    let outcome = self.reason(capture, deadline, Some(&mcp)).await;
                    let discovered = server.tools_discovered();
                    // Revoke callbacks before snapshotting evidence or removing
                    // remote bytes. No query can race final report assembly.
                    server.close().await;
                    if outcome.is_ok() && !discovered {
                        Err(runner_error(
                            "DSH analysis MCP tool discovery did not complete",
                        ))
                    } else {
                        outcome
                    }
                }
                Err(err) => Err(err),
            };
            session.close().await;
            let evidence = session.evidence().await;
            for entry in &evidence {
                if entry.truncated {
                    capture.completeness.truncated = true;
                }
                if entry.status != crate::report::CaptureStatus::Present {
                    capture.completeness.omissions.push(format!(
                        "Analysis query {} was {:?}; inspect retained evidence for its limitation",
                        entry.id, entry.status,
                    ));
                }
            }
            capture.evidence.extend(evidence);
            outcome
        } else {
            self.reason(capture, deadline, None).await
        };
        match outcome {
            Ok((cause, observed_model, label)) => {
                if let Some(actual_model) = observed_model {
                    capture.provenance.model = Some(actual_model);
                }
                let adopted = reason::adopt_assessment(capture, cause);
                reason::apply_outcome(capture, adopted, &label)?;
            }
            Err(err) => reason::apply_outcome(capture, Err(err), "")?,
        }
        Ok(output)
    }
}
