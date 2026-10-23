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
//! * `POST /v1/analyzer-sessions` — body `{"preset": string, "model"?:
//!   string}`; returns `{"sessionId": string}`.
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
    async fn create_session(&self, preset: &str, model: Option<&str>) -> Result<String>;
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
}

#[async_trait::async_trait]
impl DshApi for HttpDshApi {
    async fn create_session(&self, preset: &str, model: Option<&str>) -> Result<String> {
        let url = self.url(&["v1", "analyzer-sessions"])?;
        let mut body = json!({"preset": preset});
        if let Some(model) = model {
            body["model"] = json!(model);
        }
        let response = self
            .request(reqwest::Method::POST, url)
            .header(CONTENT_TYPE, JSON)
            .body(serde_json::to_vec(&body).map_err(|err| runner_error(err.to_string()))?)
            .send()
            .await
            .map_err(|err| runner_error(format!("DSH session create failed: {err}")))?;
        let value = json_response(response, CREATE_RESPONSE_CAP, "session create").await?;
        session_id(&value)
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
    model: Option<String>,
}

impl<T: ExecTransport> DshCdbRunner<T> {
    pub fn new(transport: T, api: Arc<dyn DshApi>, preset: impl Into<String>) -> Self {
        Self {
            collector: SshCdbRunner::new(transport),
            api,
            preset: preset.into(),
            model: None,
        }
    }
    pub fn with_remote_base(mut self, base: impl Into<String>) -> Self {
        self.collector = self.collector.with_remote_base(base);
        self
    }
    pub fn with_model(mut self, model: Option<String>) -> Self {
        self.model = model;
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
    ) -> Result<(RootCause, Option<String>, String)> {
        let prompt = reason::assessment_prompt(capture)?;
        let session = tokio::time::timeout_at(
            deadline,
            self.api.create_session(&self.preset, self.model.as_deref()),
        )
        .await
        .map_err(|_| runner_error("DSH session create exceeded shared run wall timeout"))??;
        let assessed = tokio::time::timeout_at(deadline, async {
            let outcome = self.assess_in_session(&session, &prompt).await;
            // The trajectory digest only anchors evidence; its failure is
            // tolerated and noted in the label.
            let digest = self.api.trajectory_digest(&session).await.ok();
            (outcome, digest)
        })
        .await;
        // Export-then-prune: on timeout the exchange future was dropped, so
        // the prune runs here with its own small budget, never unbounded.
        let _ = tokio::time::timeout(PRUNE_TIMEOUT, self.api.close_session(&session)).await;
        let (outcome, digest) =
            assessed.map_err(|_| runner_error("reasoner exceeded shared run wall timeout"))?;
        let (cause, model) = outcome?;
        let mut label =
            format!("bounded evidence-only DSH HTTP assessment (zero-tool session {session})");
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
    ) -> Result<(RootCause, Option<String>)> {
        let turn = self.api.send_message(session, prompt).await?;
        match decode_turn(&turn) {
            Ok(cause) => Ok((cause, turn.model)),
            Err(_) => {
                // Correct only the response format once, inside the original
                // deadline; no rejected model text is echoed back.
                let corrected = self
                    .api
                    .send_message(session, reason::FORMAT_CORRECTION_PROMPT)
                    .await?;
                let cause = decode_turn(&corrected)?;
                Ok((cause, corrected.model.or(turn.model)))
            }
        }
    }
}

#[async_trait::async_trait]
impl<T: ExecTransport> ToolRunner for DshCdbRunner<T> {
    async fn run(&self, request: RunRequest) -> Result<RunOutput> {
        let deadline = Instant::now() + request.bounds.wall_timeout;
        let mut collection = request.clone();
        // Reserve part of the shared budget for collector cleanup and
        // optional reasoning, rather than granting a second full run
        // timeout (mirrors the `claude-cdb` provider).
        collection.bounds.wall_timeout = request.bounds.wall_timeout.mul_f64(0.8);
        let mut output = tokio::time::timeout_at(deadline, self.collector.run(collection))
            .await
            .map_err(|_| {
                runner_error("deterministic collection exceeded shared run wall timeout")
            })??;
        let capture = output.capture.get_or_insert_with(ReportCapture::default);
        capture.provenance.provider = "dsh-http".into();
        capture.provenance.model = self.model.clone();
        if !capture.provenance.analysis_revision.is_empty() {
            capture.provenance.analysis_revision.push(';');
        }
        capture
            .provenance
            .analysis_revision
            .push_str("reasoner=dsh-http-v1");
        match self.reason(capture, deadline).await {
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
