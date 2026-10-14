//! Typed HTTP client for the DumpLedger AI1–AI3 surface (task B1).
//!
//! [`LedgerClient`] wraps one `reqwest` client configured with the analyzer
//! bearer token and speaks the catalog, event-feed, content, and write-back
//! routes defined by `~/Repos/dump-ledger/docs/analyzer-integration-design.md`.
//! Response bodies decode through the strict [`crate::wire`] shapes; failures
//! map onto the [`AnalyzerError`] taxonomy so the scheduler's retry
//! classifier (`is_transient`) can act on them:
//!
//! - connect, timeout, and body-read failures → [`AnalyzerError::Transport`]
//!   (transient),
//! - any non-2xx status → [`AnalyzerError::Server`] with the error envelope's
//!   `code` when the body decodes as one (a framework/HTML failure decodes to
//!   `code: None` instead of failing the mapping),
//! - undecodable success bodies and locally invalid arguments →
//!   [`AnalyzerError::Decode`] (terminal for the job).
//!
//! # Deadlines
//!
//! JSON/API calls ([`LedgerClient::get_dumps`] and friends) carry a
//! per-request total deadline of [`DEFAULT_API_TIMEOUT`] (30 s), applied to
//! the [`reqwest::RequestBuilder`] rather than the HTTP client, so the
//! streaming content route is exempt from it and
//! [`LedgerClient::with_api_timeout`] can tune it per client (tests use a
//! millisecond value).
//!
//! Independently of that, the underlying HTTP client is built with a 30 s
//! reqwest `read_timeout` stall bound on every route, including content:
//! it bounds the wait for response headers and any stalled read (the
//! deadline resets after each successful read) without capping the total
//! transfer time.
//!
//! # Credential handling
//!
//! The token lives once in the `Authorization: Bearer …` header value held by
//! the client (`Debug` is implemented manually and redacts it). It never
//! appears in URLs, request bodies, error messages, or log output: this
//! module emits no log lines at all, and every error path here formats only
//! status codes, server-supplied error codes, paths, and `reqwest` messages
//! (which never include request headers).

use std::fmt;
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ETAG, HeaderValue, IF_NONE_MATCH};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::types::{AnalyzerError, Result};
use crate::wire::{
    AnalysisReport, AnalysisReportSubmission, CustomerListResponse, CustomerSummary,
    DumpCatalogEntry, DumpCatalogQuery, DumpCatalogResponse, DumpDetail, ErrorEnvelope,
    EventFeedResponse, MAX_ACTIVITY_ACTION_CHARS, MAX_CURSOR_CHARS, MAX_IDENTIFIER_CHARS,
    SHA256_CHARS,
};

/// Media type of JSON request and response bodies.
const JSON: &str = "application/json";
/// Media type of the raw dump-content route.
const OCTET_STREAM: &str = "application/octet-stream";
/// Largest accepted event-feed `limit` (design: default and maximum 500).
const MAX_EVENT_PAGE: u32 = 500;
/// Default per-request total deadline for JSON/API calls, and the stall
/// bound applied to every route (including streaming content) through
/// reqwest's client-level `read_timeout`.
pub const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard ceiling for one decoded `analyses` list, matching the contract's
/// 4096-item response-decoder bound.
const MAX_ANALYSES_ITEMS: usize = 4096;

/// Outcome of a conditional content fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentResult {
    /// `304`: the caller's cached bytes are current; nothing was transferred.
    NotModified,
    /// Fresh bytes plus the strong `ETag` validator to present on the next
    /// conditional request.
    Bytes { bytes: Vec<u8>, etag: String },
}

/// Outcome of an analysis write-back.
///
/// Both variants are success: the server identity tuple
/// `(dumpId, analyzer.name, analyzer.version, kind, inputSha256)` makes a
/// repeat `POST` an idempotent replay rather than an error.
#[derive(Debug, Clone, PartialEq)]
pub enum PostAnalysisResult {
    /// `201`: a new report was recorded.
    Created(AnalysisReport),
    /// `200`: the identity already existed; the stored report was returned.
    Replayed(AnalysisReport),
}

impl PostAnalysisResult {
    /// The stored report, whichever path produced it.
    pub fn report(&self) -> &AnalysisReport {
        match self {
            Self::Created(report) | Self::Replayed(report) => report,
        }
    }

    /// Whether the server replayed an existing report instead of creating one.
    pub fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

/// Typed, authenticated client for one DumpLedger instance.
pub struct LedgerClient {
    http: Client,
    base_url: Url,
    /// `Authorization: Bearer <token>`; never printed by the manual `Debug`.
    authorization: HeaderValue,
    /// Total deadline applied to each JSON/API request; content is exempt.
    api_timeout: Duration,
}

impl LedgerClient {
    /// Builds the client from validated configuration.
    ///
    /// # Errors
    ///
    /// [`AnalyzerError::Config`] when the token cannot form a valid
    /// `Authorization: Bearer` header value (the value itself is never
    /// echoed) or when the underlying HTTP client cannot be constructed.
    pub fn new(config: &Config) -> Result<Self> {
        // `HeaderValue::from_str` alone is not enough: the HTTP crate accepts
        // obs-text (bytes ≥ 0x80), which cannot round-trip through a real
        // HTTP parser. Require printable non-space ASCII explicitly; the
        // value itself is never echoed in the error.
        let Some(secret) = &config.token else {
            return Err(AnalyzerError::Config(
                "no analyzer token is configured: set DUMP_ANALYZER_TOKEN or keep the state \
                 directory of a previous run (the latest-used token is stored there)"
                    .to_owned(),
            ));
        };
        let token = secret.expose();
        let token_is_wire_safe =
            !token.is_empty() && token.bytes().all(|byte| (0x21..=0x7E).contains(&byte));
        if !token_is_wire_safe {
            return Err(AnalyzerError::Config(
                "DUMP_ANALYZER_TOKEN must be non-empty printable non-space ASCII to form an \
                 `Authorization: Bearer` header value"
                    .to_owned(),
            ));
        }
        let authorization = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            AnalyzerError::Config(
                "DUMP_ANALYZER_TOKEN cannot form a valid `Authorization: Bearer` header value"
                    .to_owned(),
            )
        })?;
        // The read timeout bounds the wait for response headers and any
        // stalled read on every route (deadline resets per successful read);
        // it never caps a healthy transfer's total duration. reqwest 0.12
        // exposes read deadlines only at the client level.
        let mut builder = Client::builder()
            .user_agent(concat!("dump-analyzer/", env!("CARGO_PKG_VERSION")))
            .read_timeout(DEFAULT_API_TIMEOUT);
        // Deliberate certificate pinning (never blanket verification-off):
        // trust the configured PEM in addition to the system roots.
        if let Some(path) = &config.tls_ca_cert {
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
            AnalyzerError::Config(format!("failed to build the HTTP client: {err}"))
        })?;
        Ok(Self {
            http,
            base_url: config.base_url.clone(),
            authorization,
            api_timeout: DEFAULT_API_TIMEOUT,
        })
    }

    /// Overrides the total deadline applied to each JSON/API request
    /// (default [`DEFAULT_API_TIMEOUT`], 30 s).
    ///
    /// Content streaming is not affected: [`Self::get_content`] never gets a
    /// total deadline. A zero duration is a degenerate deadline that makes
    /// every API call fail immediately, not "no timeout".
    pub fn with_api_timeout(mut self, timeout: Duration) -> Self {
        self.api_timeout = timeout;
        self
    }

    /// Absolute URL for `segments` under the configured base URL.
    ///
    /// The base URL's path is kept as a prefix (`https://host/base/` yields
    /// `/base/api/…`), so reverse-proxied deployments work. Segment values
    /// are percent-encoded by the URL parser.
    fn endpoint(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                AnalyzerError::Config(
                    "DUMP_ANALYZER_BASE_URL cannot carry path segments".to_owned(),
                )
            })?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }

    /// A GET request carrying the bearer credential (no `Accept` yet).
    fn get(&self, url: Url) -> RequestBuilder {
        self.http
            .get(url)
            .header(AUTHORIZATION, self.authorization.clone())
    }

    /// A GET request for a JSON response body.
    fn get_json(&self, url: Url) -> RequestBuilder {
        self.get(url).header(ACCEPT, JSON)
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response> {
        request
            .send()
            .await
            .map_err(|err| AnalyzerError::Transport(describe_reqwest(&err)))
    }

    /// Sends `request`, decodes a JSON body, and maps statuses.
    ///
    /// `expected` lists the route's defined success statuses; any non-2xx
    /// maps to [`AnalyzerError::Server`], and an unexpected 2xx maps to
    /// [`AnalyzerError::Decode`].
    async fn json_response<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected: &[StatusCode],
        what: &str,
    ) -> Result<T> {
        let response = self.send(request.timeout(self.api_timeout)).await?;
        let status = response.status();
        let body = read_body(response, what).await?;
        if !expected.contains(&status) {
            return Err(unexpected_status(status, &body, what));
        }
        serde_json::from_slice(&body)
            .map_err(|err| AnalyzerError::Decode(format!("{what}: invalid response body: {err}")))
    }

    /// `GET /api/v1/dumps` (AI1): one keyset page of the dump catalog.
    ///
    /// `cursor` is the pagination position; when `Some` it overrides
    /// [`DumpCatalogQuery::cursor`] (the argument exists so follow-the-cursor
    /// loops do not have to mutate the filter bag). Filter values, including
    /// the effective cursor, are validated by [`DumpCatalogQuery::to_pairs`]
    /// before the request is sent.
    ///
    /// # Errors
    ///
    /// `Decode` for invalid filters, `Server` for non-2xx, `Transport` for
    /// connect/timeout/body-read failures.
    pub async fn get_dumps(
        &self,
        params: &DumpCatalogQuery,
        cursor: Option<&str>,
    ) -> Result<DumpCatalogResponse> {
        let mut effective = params.clone();
        if let Some(cursor) = cursor {
            effective.cursor = Some(cursor.to_owned());
        }
        let pairs = effective.to_pairs()?;
        let mut url = self.endpoint(&["api", "v1", "dumps"])?;
        if !pairs.is_empty() {
            let mut query = url.query_pairs_mut();
            for (name, value) in pairs {
                query.append_pair(name, &value);
            }
        }
        self.json_response(self.get_json(url), &[StatusCode::OK], "GET /api/v1/dumps")
            .await
    }

    /// `GET /api/v1/dumps/by-sha256/:sha256` (AI1): the catalog entries
    /// carrying exactly this content hash (normally zero or one).
    ///
    /// # Errors
    ///
    /// `Decode` when `sha256` is not 64 lowercase hex characters; otherwise
    /// like [`Self::get_dumps`].
    pub async fn get_dump_by_sha256(&self, sha256: &str) -> Result<Vec<DumpCatalogEntry>> {
        check_sha256_arg(sha256)?;
        let url = self.endpoint(&["api", "v1", "dumps", "by-sha256", sha256])?;
        let response: DumpCatalogResponse = self
            .json_response(
                self.get_json(url),
                &[StatusCode::OK],
                "GET /api/v1/dumps/by-sha256",
            )
            .await?;
        Ok(response.dumps)
    }

    /// `GET /api/v1/dumps/:dumpId`: full dump detail, including the
    /// per-module `symbolCoverage` rows used for the symbolication preflight.
    ///
    /// The task list names the return type `DumpCatalogEntry`; the route
    /// actually returns the detail shape, which [`DumpDetail`] models (a
    /// catalog row cannot be produced from it: detail carries
    /// `case { caseId, title }`, not `caseId`/`customerId`).
    ///
    /// # Errors
    ///
    /// `Decode` for a malformed `dump_id`; otherwise like [`Self::get_dumps`].
    pub async fn get_dump(&self, dump_id: &str) -> Result<DumpDetail> {
        check_identifier_arg("dumpId", dump_id)?;
        let url = self.endpoint(&["api", "v1", "dumps", dump_id])?;
        self.json_response(
            self.get_json(url),
            &[StatusCode::OK],
            "GET /api/v1/dumps/:dumpId",
        )
        .await
    }

    /// `GET /api/v1/dumps/:dumpId/content` with an optional `If-None-Match`.
    ///
    /// `etag` is the exact header value previously returned in
    /// [`ContentResult::Bytes::etag`] (quoted, per the server's strong
    /// validator). A matching validator yields [`ContentResult::NotModified`];
    /// anything else yields fresh bytes plus the current validator.
    ///
    /// # Deadlines
    ///
    /// This route has **no client-side total timeout**: dump transfers are
    /// bounded by the server's own idle and total download deadlines and by
    /// the caller's byte budget, so a large dump may stream for as long as
    /// the server allows. The underlying HTTP client's client-level
    /// `read_timeout` does apply: it bounds the wait for response headers
    /// and any stalled read at 30 s (`DEFAULT_API_TIMEOUT`), resetting after
    /// each successful read, so a dead connection fails as
    /// `AnalyzerError::Transport` instead of hanging. reqwest 0.12 exposes
    /// read deadlines only on the client, not per request.
    ///
    /// # Errors
    ///
    /// `Decode` for a malformed `dump_id` or `etag`; otherwise like
    /// [`Self::get_dumps`].
    pub async fn get_content(&self, dump_id: &str, etag: Option<&str>) -> Result<ContentResult> {
        const WHAT: &str = "GET /api/v1/dumps/:dumpId/content";
        check_identifier_arg("dumpId", dump_id)?;
        let url = self.endpoint(&["api", "v1", "dumps", dump_id, "content"])?;
        let mut request = self.get(url).header(ACCEPT, OCTET_STREAM);
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, header_arg("If-None-Match", etag)?);
        }
        let response = self.send(request).await?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ContentResult::NotModified);
        }
        let etag = response
            .headers()
            .get(ETAG)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(|_| {
                AnalyzerError::Decode(format!("{WHAT}: the ETag header is not valid ASCII"))
            })?;
        let body = read_body(response, WHAT).await?;
        if status != StatusCode::OK {
            return Err(unexpected_status(status, &body, WHAT));
        }
        let etag = etag.ok_or_else(|| {
            AnalyzerError::Decode(format!(
                "{WHAT}: a 200 response is missing the ETag validator"
            ))
        })?;
        Ok(ContentResult::Bytes { bytes: body, etag })
    }

    /// `GET /api/v1/events` (AI2): one page of the audit feed.
    ///
    /// `since` resumes strictly after the last consumed cursor; `None` reads
    /// from the beginning, and a cursor beyond the end returns an empty page
    /// whose `nextCursor` echoes the request cursor (the follower's sleep
    /// signal). `actions` filters by audit action name; `limit` is the page
    /// size (1–500; the server default is 500).
    ///
    /// # Errors
    ///
    /// `Decode` for an invalid cursor, identifier, action name, or limit;
    /// otherwise like [`Self::get_dumps`].
    /// `GET /api/v1/customers` — every customer (id + display name).
    pub async fn list_customers(&self) -> Result<Vec<CustomerSummary>> {
        let url = self.endpoint(&["api", "v1", "customers"])?;
        let body: CustomerListResponse = self
            .json_response(
                self.get_json(url),
                &[StatusCode::OK],
                "GET /api/v1/customers",
            )
            .await?;
        Ok(body.customers)
    }

    pub async fn get_events(
        &self,
        since: Option<&str>,
        actions: Option<&[&str]>,
        case_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<EventFeedResponse> {
        if let Some(since) = since {
            check_cursor_arg("since", since)?;
        }
        if let Some(case_id) = case_id {
            check_identifier_arg("caseId", case_id)?;
        }
        let actions = actions.unwrap_or(&[]);
        for action in actions {
            check_action_arg(action)?;
        }
        if let Some(limit) = limit {
            if limit == 0 || limit > MAX_EVENT_PAGE {
                return Err(AnalyzerError::Decode(format!(
                    "limit: must be between 1 and {MAX_EVENT_PAGE} (got {limit})"
                )));
            }
        }
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if let Some(since) = since {
            pairs.push(("since", since.to_owned()));
        }
        if !actions.is_empty() {
            pairs.push(("actions", actions.join(",")));
        }
        if let Some(case_id) = case_id {
            pairs.push(("caseId", case_id.to_owned()));
        }
        if let Some(limit) = limit {
            pairs.push(("limit", limit.to_string()));
        }
        let mut url = self.endpoint(&["api", "v1", "events"])?;
        if !pairs.is_empty() {
            let mut query = url.query_pairs_mut();
            for (name, value) in pairs {
                query.append_pair(name, &value);
            }
        }
        self.json_response(self.get_json(url), &[StatusCode::OK], "GET /api/v1/events")
            .await
    }

    /// `POST /api/v1/dumps/:dumpId/analyses` (AI3): record or replay a
    /// verdict. `201` creates, `200` replays the stored report for the same
    /// identity tuple; both are success.
    ///
    /// The submission is validated locally before the request is sent, so a
    /// programmatically built out-of-bounds report fails as `Decode` without
    /// a network round-trip.
    ///
    /// # Errors
    ///
    /// `Decode` for a malformed `dump_id`, invalid submission, or undecodable
    /// response; otherwise like [`Self::get_dumps`].
    pub async fn post_analysis(
        &self,
        dump_id: &str,
        report: &AnalysisReportSubmission,
    ) -> Result<PostAnalysisResult> {
        const WHAT: &str = "POST /api/v1/dumps/:dumpId/analyses";
        check_identifier_arg("dumpId", dump_id)?;
        report.validate()?;
        let body = serde_json::to_vec(report)
            .map_err(|err| AnalyzerError::Decode(format!("{WHAT}: failed to encode: {err}")))?;
        let url = self.endpoint(&["api", "v1", "dumps", dump_id, "analyses"])?;
        let request = self
            .http
            .post(url)
            .header(AUTHORIZATION, self.authorization.clone())
            .header(ACCEPT, JSON)
            .header(CONTENT_TYPE, JSON)
            .timeout(self.api_timeout)
            .body(body);
        let response = self.send(request).await?;
        let status = response.status();
        let body = read_body(response, WHAT).await?;
        let replayed = match status {
            StatusCode::CREATED => false,
            StatusCode::OK => true,
            _ => return Err(unexpected_status(status, &body, WHAT)),
        };
        let report = serde_json::from_slice(&body).map_err(|err| {
            AnalyzerError::Decode(format!("{WHAT}: invalid response body: {err}"))
        })?;
        Ok(if replayed {
            PostAnalysisResult::Replayed(report)
        } else {
            PostAnalysisResult::Created(report)
        })
    }

    /// `GET /api/v1/dumps/:dumpId/analyses` (AI3): the reports recorded for
    /// one dump, for restart reconciliation.
    ///
    /// # Errors
    ///
    /// `Decode` for a malformed `dump_id`; otherwise like [`Self::get_dumps`].
    pub async fn get_analyses(&self, dump_id: &str) -> Result<Vec<AnalysisReport>> {
        check_identifier_arg("dumpId", dump_id)?;
        let url = self.endpoint(&["api", "v1", "dumps", dump_id, "analyses"])?;
        let response: AnalysesResponse = self
            .json_response(
                self.get_json(url),
                &[StatusCode::OK],
                "GET /api/v1/dumps/:dumpId/analyses",
            )
            .await?;
        Ok(response.analyses)
    }
}

impl fmt::Debug for LedgerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerClient")
            .field("base_url", &self.base_url)
            .field("authorization", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// `GET /api/v1/dumps/:dumpId/analyses` list envelope.
///
/// `wire` carries the report row (`AnalysisReport`) but not this route's list
/// envelope (an AI3 shape); the client keeps the minimal local struct instead
/// of editing the A1-owned module. Unknown fields are rejected like every
/// other consumed shape.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AnalysesResponse {
    #[serde(deserialize_with = "analyses_page")]
    analyses: Vec<AnalysisReport>,
}

/// Bounds the analyses array like the contract's 4096-item response decoders.
fn analyses_page<'de, D>(deserializer: D) -> std::result::Result<Vec<AnalysisReport>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Vec::<AnalysisReport>::deserialize(deserializer)?;
    if value.len() > MAX_ANALYSES_ITEMS {
        return Err(serde::de::Error::custom(format!(
            "analyses: exceeds {MAX_ANALYSES_ITEMS} items"
        )));
    }
    Ok(value)
}

/// Reads the full response body, mapping read failures to `Transport`.
async fn read_body(response: Response, what: &str) -> Result<Vec<u8>> {
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| {
            AnalyzerError::Transport(format!("{what}: failed to read the response body: {err}"))
        })
}

/// Extracts the stable error code from a DumpLedger error envelope, if the
/// body decodes as one; framework responses decode to `None`.
fn error_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .map(|envelope| envelope.error.code)
}

/// Maps a non-expected status: `Server` for any non-2xx (with the envelope's
/// code when decodable), `Decode` for a 2xx the route contract does not
/// define.
fn unexpected_status(status: StatusCode, body: &[u8], what: &str) -> AnalyzerError {
    if status.is_success() {
        AnalyzerError::Decode(format!("{what}: unexpected success status {status}"))
    } else {
        AnalyzerError::Server {
            status: status.as_u16(),
            code: error_code(body),
        }
    }
}

/// Renders a `reqwest` failure without any request headers (the transport
/// error text carries the URL only).
fn describe_reqwest(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        format!("timeout: {err}")
    } else if err.is_connect() {
        format!("connect: {err}")
    } else {
        format!("request: {err}")
    }
}

/// Builds an outbound header value from caller input, rejecting values that
/// cannot be represented on the HTTP wire (control bytes and, unlike
/// `HeaderValue::from_str`, non-ASCII obs-text).
fn header_arg(field: &str, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value)
        .ok()
        .filter(|parsed| parsed.to_str().is_ok())
        .ok_or_else(|| AnalyzerError::Decode(format!("{field}: not a valid HTTP header value")))
}

/// Local mirror of the wire module's sha256 rule: 64 lowercase hex characters.
fn check_sha256_arg(value: &str) -> Result<()> {
    let valid = value.len() == SHA256_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if valid {
        Ok(())
    } else {
        Err(AnalyzerError::Decode(format!(
            "sha256: expected {SHA256_CHARS} lowercase hex characters"
        )))
    }
}

/// Local mirror of the wire module's cursor rule (non-empty, at most
/// [`MAX_CURSOR_CHARS`] characters, no whitespace).
fn check_cursor_arg(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(AnalyzerError::Decode(format!("{field}: must not be empty")));
    }
    if value.chars().count() > MAX_CURSOR_CHARS {
        return Err(AnalyzerError::Decode(format!(
            "{field}: cursor exceeds {MAX_CURSOR_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AnalyzerError::Decode(format!(
            "{field}: cursor must not contain whitespace"
        )));
    }
    Ok(())
}

/// Local mirror of the wire module's identifier rule (non-empty, at most
/// [`MAX_IDENTIFIER_CHARS`] characters, no whitespace).
fn check_identifier_arg(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(AnalyzerError::Decode(format!("{field}: must not be empty")));
    }
    if value.chars().count() > MAX_IDENTIFIER_CHARS {
        return Err(AnalyzerError::Decode(format!(
            "{field}: identifier exceeds {MAX_IDENTIFIER_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AnalyzerError::Decode(format!(
            "{field}: identifier must not contain whitespace"
        )));
    }
    Ok(())
}

/// An audit action name as accepted by the events `actions` filter: nonempty,
/// at most [`MAX_ACTIVITY_ACTION_CHARS`] characters, no comma (the separator)
/// and no whitespace.
fn check_action_arg(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.chars().count() <= MAX_ACTIVITY_ACTION_CHARS
        && !value.contains(',')
        && !value.chars().any(char::is_whitespace);
    if valid {
        Ok(())
    } else {
        Err(AnalyzerError::Decode(format!(
            "actions: {value:?} is not a valid audit action name"
        )))
    }
}
