//! Environment configuration and secrets handling (task A2).
//!
//! [`Config::from_env`] parses a snapshot of `(name, value)` pairs — tests
//! pass a synthetic iterator and never touch the real process environment;
//! [`Config::from_process_env`] reads the real environment once at startup.
//! Malformed values fail fast with [`AnalyzerError::Config`], naming the
//! offending variable. Token values are never echoed: token errors omit the
//! value, and [`SecretToken`] (and therefore [`Config`]) redacts it in
//! `Debug`/`Display` (docs/analyzer-design.md, "Security considerations").

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;

use crate::types::{AnalyzerError, Result, RunBounds};

/// `DUMP_ANALYZER_BASE_URL`: required DumpLedger base URL.
const BASE_URL_VAR: &str = "DUMP_ANALYZER_BASE_URL";
/// `DUMP_ANALYZER_TOKEN`: required analyzer bearer token.
const TOKEN_VAR: &str = "DUMP_ANALYZER_TOKEN";
/// `DUMP_ANALYZER_STATE_DIR`: local state directory (default `./data`).
const STATE_DIR_VAR: &str = "DUMP_ANALYZER_STATE_DIR";
/// `DUMP_ANALYZER_NAME`: analyzer name used in the report identity.
const NAME_VAR: &str = "DUMP_ANALYZER_NAME";
/// `DUMP_ANALYZER_VERSION`: analyzer version used in the report identity.
const VERSION_VAR: &str = "DUMP_ANALYZER_VERSION";
/// `DUMP_ANALYZER_POLL_INTERVAL_MS`: poll cadence, 5 000–30 000 ms.
const POLL_INTERVAL_VAR: &str = "DUMP_ANALYZER_POLL_INTERVAL_MS";
/// `DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS`: hard per-run wall timeout.
const RUN_WALL_TIMEOUT_VAR: &str = "DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS";
/// `DUMP_ANALYZER_MAX_OUTPUT_BYTES`: hard output-capture cap.
const MAX_OUTPUT_BYTES_VAR: &str = "DUMP_ANALYZER_MAX_OUTPUT_BYTES";
/// `DUMP_ANALYZER_MAX_WORKSPACE_BYTES`: hard workspace-size cap.
const MAX_WORKSPACE_BYTES_VAR: &str = "DUMP_ANALYZER_MAX_WORKSPACE_BYTES";
/// `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES`: hard byte-cache cap.
const BYTE_CACHE_MAX_BYTES_VAR: &str = "DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES";
/// `DUMP_ANALYZER_HTTP_ADDR`: read-only status UI bind address; default
/// `127.0.0.1:4180`, empty disables the listener.
const HTTP_ADDR_VAR: &str = "DUMP_ANALYZER_HTTP_ADDR";
/// Default status-UI bind: loopback only.
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:4180";
/// `DUMP_ANALYZER_RUNNER`: tool-runner provider (`cdb-ssh` default,
/// `claude-cdb`, `dsh-http`).
const RUNNER_VAR: &str = "DUMP_ANALYZER_RUNNER";
/// `DUMP_ANALYZER_CLAUDE_BIN`: claude CLI executable for the `claude-cdb`
/// provider; default `claude` (PATH lookup).
const CLAUDE_BIN_VAR: &str = "DUMP_ANALYZER_CLAUDE_BIN";
/// `DUMP_ANALYZER_CLAUDE_MODEL`: optional model override for the provider.
const CLAUDE_MODEL_VAR: &str = "DUMP_ANALYZER_CLAUDE_MODEL";
/// `DUMP_ANALYZER_DSH_BASE_URL`: base URL of the dedicated DSH analyzer
/// service; required when `DUMP_ANALYZER_RUNNER=dsh-http`.
const DSH_BASE_URL_VAR: &str = "DUMP_ANALYZER_DSH_BASE_URL";
/// `DUMP_ANALYZER_DSH_TOKEN`: optional bearer token for that service.
const DSH_TOKEN_VAR: &str = "DUMP_ANALYZER_DSH_TOKEN";
/// `DUMP_ANALYZER_DSH_MODEL`: optional model override for the `dsh-http`
/// provider.
const DSH_MODEL_VAR: &str = "DUMP_ANALYZER_DSH_MODEL";
/// `DUMP_ANALYZER_DSH_PROVIDER`: optional provider route for the `dsh-http`
/// provider; the adapter allowlists the selectable providers.
const DSH_PROVIDER_VAR: &str = "DUMP_ANALYZER_DSH_PROVIDER";
/// `DUMP_ANALYZER_DSH_REASONING_EFFORT`: optional reasoning effort for the
/// `dsh-http` route (`low`, `medium`, `high`, `max`).
const DSH_REASONING_EFFORT_VAR: &str = "DUMP_ANALYZER_DSH_REASONING_EFFORT";
/// `DUMP_ANALYZER_DSH_CONTEXT_WINDOW`: optional catalog context-window size
/// for a route model the adapter does not pre-list.
const DSH_CONTEXT_WINDOW_VAR: &str = "DUMP_ANALYZER_DSH_CONTEXT_WINDOW";
/// `DUMP_ANALYZER_DSH_MAX_TOKENS`: optional catalog max-tokens size for such
/// a model; must not exceed the context window.
const DSH_MAX_TOKENS_VAR: &str = "DUMP_ANALYZER_DSH_MAX_TOKENS";
/// Upper bound accepted for catalog context-window/max-tokens values.
const MAX_DSH_CONTEXT_WINDOW: u64 = 2_000_000;
/// `DUMP_ANALYZER_DSH_API_KEY`: optional model API key forwarded to the
/// DSH adapter at session create; the adapter injects it as the provider key
/// for each headless run. When unset, the adapter's own launch-environment
/// key is used.
const DSH_API_KEY_VAR: &str = "DUMP_ANALYZER_DSH_API_KEY";
/// `DUMP_ANALYZER_DSH_PRESET`: server-side zero-tool preset name; default
/// `analyzer-triage`.
const DSH_PRESET_VAR: &str = "DUMP_ANALYZER_DSH_PRESET";
/// Default DSH preset; the dedicated instance must serve it with no tools.
const DEFAULT_DSH_PRESET: &str = "analyzer-triage";
/// Bound on the preset name (carried in the JSON session-create body).
const MAX_DSH_PRESET_CHARS: usize = 128;
/// `DUMP_ANALYZER_WRITE_BACK`: `on` (default) or `off`; `off` treats the
/// ledger as a read-only dump source — verdicts are recorded locally and
/// jobs settle without ever POSTing analyses.
const WRITE_BACK_VAR: &str = "DUMP_ANALYZER_WRITE_BACK";
/// `DUMP_ANALYZER_SCHEDULER`: `on` (default) or `off`; `off` runs the feed,
/// status UI, and on-demand analysis but never claims jobs.
const SCHEDULER_VAR: &str = "DUMP_ANALYZER_SCHEDULER";
/// `DUMP_ANALYZER_TLS_CA_CERT`: PEM certificate (or chain) to trust in
/// addition to system roots — the deliberate way to pin a self-hosted
/// DumpLedger's self-signed TLS cert (analyzer-guide.md, "Prerequisites").
const TLS_CA_CERT_VAR: &str = "DUMP_ANALYZER_TLS_CA_CERT";
/// `DUMP_ANALYZER_SSH_TARGET`: SSH target of the analysis box.
const SSH_TARGET_VAR: &str = "DUMP_ANALYZER_SSH_TARGET";
/// `DUMP_ANALYZER_SYMBOL_CACHE_DIR`: symbol cache dir on the analysis box.
const SYMBOL_CACHE_DIR_VAR: &str = "DUMP_ANALYZER_SYMBOL_CACHE_DIR";
/// `DUMP_ANALYZER_WEBHOOK`: `on` enables the ledger webhook receiver and
/// boot-time self-registration; unset/off keeps feed-polling alone.
const WEBHOOK_VAR: &str = "DUMP_ANALYZER_WEBHOOK";
/// `DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN`: WH2 webhook-admin bearer token used
/// for idempotent self-registration; required when the webhook is on.
const WEBHOOK_ADMIN_TOKEN_VAR: &str = "DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN";
/// `DUMP_ANALYZER_WEBHOOK_URL`: this daemon's externally reachable webhook
/// URL registered at the ledger; required when the webhook is on.
const WEBHOOK_URL_VAR: &str = "DUMP_ANALYZER_WEBHOOK_URL";
/// `DUMP_ANALYZER_WEBHOOK_ACTIONS`: comma-separated audit actions to
/// subscribe; defaults to the feed follower's action set.
const WEBHOOK_ACTIONS_VAR: &str = "DUMP_ANALYZER_WEBHOOK_ACTIONS";
/// Bound on the webhook action filter (mirrors the ledger's limit).
const MAX_WEBHOOK_ACTIONS: usize = 32;
/// Bound on one action name (mirrors the ledger's limit).
const MAX_WEBHOOK_ACTION_CHARS: usize = 64;

/// Default state directory.
const DEFAULT_STATE_DIR: &str = "./data";
/// Default analyzer name.
const DEFAULT_NAME: &str = "dump-analyzer";
/// Default poll interval (10 s).
const DEFAULT_POLL_INTERVAL_MS: u64 = 10_000;
/// Lower bound for the poll interval (5 s).
const MIN_POLL_INTERVAL_MS: u64 = 5_000;
/// Upper bound for the poll interval (30 s).
const MAX_POLL_INTERVAL_MS: u64 = 30_000;
/// Default run wall timeout (10 min).
const DEFAULT_RUN_WALL_TIMEOUT_MS: u64 = 600_000;
/// Default output-capture cap (1 MiB).
const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Default workspace-size cap (2 GiB).
const DEFAULT_MAX_WORKSPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default byte-cache cap (10 GiB).
const DEFAULT_BYTE_CACHE_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Bearer credential for the DumpLedger analyzer token.
///
/// The value is reachable only through [`SecretToken::expose`]; `Debug` and
/// `Display` always redact, so `format!("{config:?}")`, `tracing` fields, and
/// error formatting cannot leak it (docs/analyzer-design.md, "Security
/// considerations").
#[derive(Clone, PartialEq, Eq)]
pub struct SecretToken(String);

impl SecretToken {
    /// Wraps a trusted token value, without validation.
    ///
    /// Environment-sourced tokens are validated by [`Config::from_env`];
    /// this constructor exists for tests and non-environment secret stores.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The token value; the single explicit read path.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken([redacted])")
    }
}

impl fmt::Display for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Process configuration parsed from the environment.
///
/// `Debug` derives over all fields; the token redacts itself, so the derived
/// `Debug` is safe to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// DumpLedger base URL: absolute `https://`, without credentials, query,
    /// or fragment.
    pub base_url: Url,
    /// Analyzer bearer token (redacts in `Debug`/`Display`). Optional at
    /// parse time: the daemon resolves it at boot from the environment or,
    /// failing that, the state store's latest-used token (and persists an
    /// env-provided token for the next boot).
    pub token: Option<SecretToken>,
    /// Local state directory (SQLite, byte cache, lockfile); default
    /// `./data`.
    pub state_dir: PathBuf,
    /// Analyzer name used in the report identity; default `dump-analyzer`.
    pub name: String,
    /// Analyzer version used in the report identity; default
    /// `env!("CARGO_PKG_VERSION")`.
    pub version: String,
    /// Catalog/event-feed poll cadence; default 10 s, allowed 5–30 s.
    pub poll_interval: Duration,
    /// Hard wall timeout for one toolchain run; default 10 min.
    pub run_wall_timeout: Duration,
    /// Hard cap on captured toolchain output; default 1 MiB.
    pub max_output_bytes: usize,
    /// Hard cap on per-run workspace size; default 2 GiB.
    pub max_workspace_bytes: u64,
    /// Hard cap on the local byte-cache size; default 10 GiB.
    pub byte_cache_max_bytes: u64,
    /// SSH target of the analysis box, e.g. `windows-dev`; unset by default.
    pub ssh_target: Option<String>,
    /// Symbol cache directory on the analysis box; unset by default.
    pub symbol_cache_dir: Option<String>,
    /// Read-only status UI bind address; default `127.0.0.1:4180`, `None`
    /// disables the listener (docs/analyzer-design.md, status UI).
    pub http_addr: Option<std::net::SocketAddr>,
    /// Tool-runner provider wired at boot; default `cdb-ssh`.
    pub runner: crate::types::RunnerKind,
    /// claude CLI executable for the `claude-cdb` provider; default `claude`
    /// (PATH lookup).
    pub claude_bin: String,
    /// Optional model override for the `claude-cdb` provider.
    pub claude_model: Option<String>,
    /// Base URL of the dedicated DSH analyzer service (`dsh-http`
    /// provider): absolute `https://` (loopback `http` accepted for a
    /// co-located confined instance), without credentials, query, or
    /// fragment. Required when the provider is selected.
    pub dsh_base_url: Option<Url>,
    /// Optional bearer token for the DSH service (redacts in
    /// `Debug`/`Display`).
    pub dsh_token: Option<SecretToken>,
    /// Optional model override for the `dsh-http` provider.
    pub dsh_model: Option<String>,
    /// Optional model API key forwarded to the DSH adapter at session
    /// create (redacts in `Debug`/`Display`). Never persisted, never echoed
    /// into prompts, evidence, or reports.
    pub dsh_api_key: Option<SecretToken>,
    /// Optional provider route for the `dsh-http` provider; the adapter
    /// allowlists the selectable providers.
    pub dsh_provider: Option<String>,
    /// Optional reasoning effort (`low`, `medium`, `high`, `max`).
    pub dsh_reasoning_effort: Option<String>,
    /// Optional catalog context-window size for a route model the adapter
    /// does not pre-list; bounded by 2,000,000.
    pub dsh_context_window: Option<u32>,
    /// Optional catalog max-tokens size; never exceeds the context window.
    pub dsh_max_tokens: Option<u32>,
    /// Server-side zero-tool preset name; default `analyzer-triage`.
    pub dsh_preset: String,
    /// Optional path to a PEM certificate (or chain) to trust in addition to
    /// the system roots — pins a self-signed DumpLedger TLS endpoint.
    pub tls_ca_cert: Option<PathBuf>,
    /// Whether the webhook receiver and boot-time registration run.
    pub webhook_enabled: bool,
    /// WH2 webhook-admin bearer token for self-registration.
    pub webhook_admin_token: Option<SecretToken>,
    /// This daemon's externally reachable webhook URL.
    pub webhook_url: Option<String>,
    /// Subscription action filter (defaults to the feed follower's set).
    pub webhook_actions: Vec<String>,
    /// Whether the scheduler claims jobs; default on. Off = manual operation:
    /// feed, status UI, and on-demand analysis run, nothing auto-executes.
    pub scheduler_enabled: bool,
    /// Whether verdicts are written back to the ledger; default on. Off = the
    /// ledger is a read-only dump source: verdicts record locally and jobs
    /// settle `done` without any `POST …/analyses`.
    pub writeback_enabled: bool,
}

impl Config {
    /// Parses configuration from an environment snapshot.
    ///
    /// `iter` yields `(name, value)` pairs; duplicate names take the last
    /// value, unknown names are ignored. Tests drive this with synthetic
    /// pairs and never touch the real process environment.
    ///
    /// # Errors
    ///
    /// Fails fast with [`AnalyzerError::Config`] on the first missing or
    /// malformed variable, naming it. Token values never appear in errors.
    pub fn from_env(iter: impl Iterator<Item = (String, String)>) -> Result<Self> {
        let vars: HashMap<String, String> = iter.collect();

        let base_url = Self::parse_base_url(&vars)?;
        let token = Self::parse_token(&vars)?;
        let state_dir = match Self::optional_value(&vars, STATE_DIR_VAR) {
            Some(raw) => PathBuf::from(raw),
            None => PathBuf::from(DEFAULT_STATE_DIR),
        };
        let name = match Self::optional_value(&vars, NAME_VAR) {
            Some(raw) => raw,
            None => DEFAULT_NAME.to_owned(),
        };
        let version = match Self::optional_value(&vars, VERSION_VAR) {
            Some(raw) => raw,
            None => env!("CARGO_PKG_VERSION").to_owned(),
        };
        if version == "0.1.0" {
            return Err(AnalyzerError::Config(format!(
                "{VERSION_VAR}=0.1.0 is reserved for legacy compact reports; use the new default 0.2.0 or a distinct reanalysis version"
            )));
        }
        let poll_interval_ms = Self::u64_value(&vars, POLL_INTERVAL_VAR, DEFAULT_POLL_INTERVAL_MS)?;
        if !(MIN_POLL_INTERVAL_MS..=MAX_POLL_INTERVAL_MS).contains(&poll_interval_ms) {
            return Err(AnalyzerError::Config(format!(
                "{POLL_INTERVAL_VAR} must be between {MIN_POLL_INTERVAL_MS} and {MAX_POLL_INTERVAL_MS} milliseconds (got {poll_interval_ms})"
            )));
        }
        let run_wall_timeout_ms =
            Self::positive_u64_value(&vars, RUN_WALL_TIMEOUT_VAR, DEFAULT_RUN_WALL_TIMEOUT_MS)?;
        let max_output_bytes =
            Self::positive_u64_value(&vars, MAX_OUTPUT_BYTES_VAR, DEFAULT_MAX_OUTPUT_BYTES)?;
        let max_output_bytes = usize::try_from(max_output_bytes).map_err(|_| {
            AnalyzerError::Config(format!(
                "{MAX_OUTPUT_BYTES_VAR} exceeds the maximum value supported on this platform"
            ))
        })?;
        let max_workspace_bytes =
            Self::positive_u64_value(&vars, MAX_WORKSPACE_BYTES_VAR, DEFAULT_MAX_WORKSPACE_BYTES)?;
        let byte_cache_max_bytes = Self::positive_u64_value(
            &vars,
            BYTE_CACHE_MAX_BYTES_VAR,
            DEFAULT_BYTE_CACHE_MAX_BYTES,
        )?;
        let ssh_target = Self::optional_value(&vars, SSH_TARGET_VAR);
        let symbol_cache_dir = Self::optional_value(&vars, SYMBOL_CACHE_DIR_VAR);
        let http_addr = Self::parse_http_addr(&vars)?;
        let runner = Self::parse_runner(&vars)?;
        let claude_bin = match Self::optional_value(&vars, CLAUDE_BIN_VAR) {
            Some(raw) => raw,
            None => "claude".to_owned(),
        };
        let claude_model = Self::optional_value(&vars, CLAUDE_MODEL_VAR);
        let dsh_base_url = Self::parse_dsh_base_url(&vars)?;
        let dsh_token = Self::parse_dsh_token(&vars)?;
        let dsh_model = Self::optional_value(&vars, DSH_MODEL_VAR);
        let dsh_api_key = Self::parse_dsh_api_key(&vars)?;
        let dsh_provider = match Self::optional_value(&vars, DSH_PROVIDER_VAR) {
            Some(raw) => {
                if raw.chars().count() > 128 || raw.chars().any(char::is_control) {
                    return Err(AnalyzerError::Config(format!(
                        "{DSH_PROVIDER_VAR} must be at most 128 chars without control characters"
                    )));
                }
                Some(raw)
            }
            None => None,
        };
        let dsh_reasoning_effort = match Self::optional_value(&vars, DSH_REASONING_EFFORT_VAR) {
            Some(raw) => match raw.as_str() {
                "low" | "medium" | "high" | "max" => Some(raw),
                other => {
                    return Err(AnalyzerError::Config(format!(
                        "{DSH_REASONING_EFFORT_VAR} must be low, medium, high, or max (got {other:?})"
                    )));
                }
            },
            None => None,
        };
        let dsh_context_window = Self::bounded_catalog_value(&vars, DSH_CONTEXT_WINDOW_VAR)?;
        let dsh_max_tokens = Self::bounded_catalog_value(&vars, DSH_MAX_TOKENS_VAR)?;
        if let (Some(window), Some(max_tokens)) = (dsh_context_window, dsh_max_tokens) {
            if max_tokens > window {
                return Err(AnalyzerError::Config(format!(
                    "{DSH_MAX_TOKENS_VAR} must not exceed {DSH_CONTEXT_WINDOW_VAR} ({max_tokens} > {window})"
                )));
            }
        }
        let dsh_preset = match Self::optional_value(&vars, DSH_PRESET_VAR) {
            Some(raw) => {
                if raw.chars().count() > MAX_DSH_PRESET_CHARS || raw.chars().any(char::is_control) {
                    return Err(AnalyzerError::Config(format!(
                        "{DSH_PRESET_VAR} must be at most {MAX_DSH_PRESET_CHARS} chars without control characters"
                    )));
                }
                raw
            }
            None => DEFAULT_DSH_PRESET.to_owned(),
        };
        if runner == crate::types::RunnerKind::DshHttp && dsh_base_url.is_none() {
            return Err(AnalyzerError::Config(format!(
                "{DSH_BASE_URL_VAR} is required when {RUNNER_VAR}=dsh-http"
            )));
        }
        let tls_ca_cert = Self::optional_value(&vars, TLS_CA_CERT_VAR).map(PathBuf::from);
        let webhook_enabled = match Self::optional_value(&vars, WEBHOOK_VAR).as_deref() {
            None => false,
            Some("on") => true,
            Some("off") => false,
            Some(other) => {
                return Err(AnalyzerError::Config(format!(
                    "{WEBHOOK_VAR} must be on or off (got {other:?})"
                )));
            }
        };
        let webhook_admin_token =
            Self::optional_value(&vars, WEBHOOK_ADMIN_TOKEN_VAR).map(SecretToken::new);
        let webhook_url = Self::optional_value(&vars, WEBHOOK_URL_VAR);
        if webhook_enabled {
            if webhook_admin_token.is_none() {
                return Err(AnalyzerError::Config(format!(
                    "{WEBHOOK_VAR}=on requires {WEBHOOK_ADMIN_TOKEN_VAR}"
                )));
            }
            match &webhook_url {
                None => {
                    return Err(AnalyzerError::Config(format!(
                        "{WEBHOOK_VAR}=on requires {WEBHOOK_URL_VAR}"
                    )));
                }
                Some(url)
                    if !(url.starts_with("http://") || url.starts_with("https://"))
                        || url.chars().any(char::is_whitespace) =>
                {
                    return Err(AnalyzerError::Config(format!(
                        "{WEBHOOK_URL_VAR} must be an http(s) URL without whitespace"
                    )));
                }
                _ => {}
            }
        }
        let webhook_actions = match Self::optional_value(&vars, WEBHOOK_ACTIONS_VAR) {
            None => crate::sync::FEED_ACTIONS.map(str::to_owned).to_vec(),
            Some(raw) => {
                let actions: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_owned)
                    .collect();
                if actions.len() > MAX_WEBHOOK_ACTIONS
                    || actions.iter().any(|a| a.len() > MAX_WEBHOOK_ACTION_CHARS)
                {
                    return Err(AnalyzerError::Config(format!(
                        "{WEBHOOK_ACTIONS_VAR} allows at most {MAX_WEBHOOK_ACTIONS} entries of {MAX_WEBHOOK_ACTION_CHARS} chars"
                    )));
                }
                actions
            }
        };
        let writeback_enabled = match Self::optional_value(&vars, WRITE_BACK_VAR).as_deref() {
            None => true,
            Some("on") => true,
            Some("off") => false,
            Some(other) => {
                return Err(AnalyzerError::Config(format!(
                    "{WRITE_BACK_VAR} must be on or off (got {other:?})"
                )));
            }
        };
        let scheduler_enabled = match Self::optional_value(&vars, SCHEDULER_VAR).as_deref() {
            None => true,
            Some("on") => true,
            Some("off") => false,
            Some(other) => {
                return Err(AnalyzerError::Config(format!(
                    "{SCHEDULER_VAR} must be on or off (got {other:?})"
                )));
            }
        };

        Ok(Self {
            base_url,
            token,
            state_dir,
            name,
            version,
            poll_interval: Duration::from_millis(poll_interval_ms),
            run_wall_timeout: Duration::from_millis(run_wall_timeout_ms),
            max_output_bytes,
            max_workspace_bytes,
            byte_cache_max_bytes,
            ssh_target,
            symbol_cache_dir,
            http_addr,
            runner,
            claude_bin,
            claude_model,
            dsh_base_url,
            dsh_token,
            dsh_model,
            dsh_api_key,
            dsh_provider,
            dsh_reasoning_effort,
            dsh_context_window,
            dsh_max_tokens,
            dsh_preset,
            tls_ca_cert,
            webhook_enabled,
            webhook_admin_token,
            webhook_url,
            webhook_actions,
            scheduler_enabled,
            writeback_enabled,
        })
    }

    /// Reads the real process environment once at startup.
    ///
    /// # Errors
    ///
    /// Same as [`Config::from_env`]. Panics if an environment value is not
    /// valid Unicode (`std::env::vars` semantics).
    pub fn from_process_env() -> Result<Self> {
        Self::from_env(std::env::vars())
    }

    /// The [`RunBounds`] every toolchain run is pinned to.
    pub fn run_bounds(&self) -> RunBounds {
        RunBounds {
            wall_timeout: self.run_wall_timeout,
            max_output_bytes: self.max_output_bytes,
            max_workspace_bytes: self.max_workspace_bytes,
        }
    }

    /// A trimmed, non-empty value; `None` when absent or empty.
    ///
    /// An empty or whitespace-only value means "unset" for optional
    /// variables, mirroring DumpLedger's own "unset or empty disables"
    /// handling of optional configuration. The two required variables use
    /// [`Self::required_value`] / [`Self::parse_token`] instead, which
    /// reject emptiness explicitly.
    /// Parses the tool-runner provider selector.
    fn parse_runner(vars: &HashMap<String, String>) -> Result<crate::types::RunnerKind> {
        match Self::optional_value(vars, RUNNER_VAR).as_deref() {
            None => Ok(crate::types::RunnerKind::CdbSsh),
            Some("cdb-ssh") => Ok(crate::types::RunnerKind::CdbSsh),
            Some("claude-cdb") => Ok(crate::types::RunnerKind::ClaudeCdb),
            Some("dsh-http") => Ok(crate::types::RunnerKind::DshHttp),
            Some(other) => Err(AnalyzerError::Config(format!(
                "{RUNNER_VAR} must be cdb-ssh, claude-cdb, or dsh-http (got {other:?})"
            ))),
        }
    }

    /// Parses the status-UI bind address: unset → the loopback default,
    /// empty/whitespace → disabled, otherwise a `host:port` socket address.
    fn parse_http_addr(vars: &HashMap<String, String>) -> Result<Option<std::net::SocketAddr>> {
        match vars.get(HTTP_ADDR_VAR) {
            None => Ok(Some(
                DEFAULT_HTTP_ADDR
                    .parse()
                    .expect("default http addr is a valid socket address"),
            )),
            Some(raw) if raw.trim().is_empty() => Ok(None),
            Some(raw) => raw
                .trim()
                .parse::<std::net::SocketAddr>()
                .map(Some)
                .map_err(|err| {
                    AnalyzerError::Config(format!(
                        "{HTTP_ADDR_VAR} must be a host:port socket address: {err}"
                    ))
                }),
        }
    }

    fn optional_value(vars: &HashMap<String, String>, name: &str) -> Option<String> {
        vars.get(name)
            .map(|raw| raw.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }

    /// A required, trimmed, non-empty value.
    fn required_value(vars: &HashMap<String, String>, name: &str) -> Result<String> {
        match vars.get(name) {
            None => Err(AnalyzerError::Config(format!(
                "{name} is required but not set"
            ))),
            Some(raw) => {
                let value = raw.trim();
                if value.is_empty() {
                    Err(AnalyzerError::Config(format!(
                        "{name} is required and must not be empty"
                    )))
                } else {
                    Ok(value.to_owned())
                }
            }
        }
    }

    /// Required `https://` base URL, parsed with [`reqwest::Url`].
    fn parse_base_url(vars: &HashMap<String, String>) -> Result<Url> {
        let raw = Self::required_value(vars, BASE_URL_VAR)?;
        let url = Url::parse(&raw).map_err(|err| {
            AnalyzerError::Config(format!("{BASE_URL_VAR} is not an absolute URL: {err}"))
        })?;
        let scheme = url.scheme();
        // http is accepted only for loopback development stubs (mirrors
        // DumpLedger's own loopback exception); anything remote is https-only.
        let loopback = matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("::1") | Some("localhost")
        );
        if scheme != "https" && !(scheme == "http" && loopback) {
            return Err(AnalyzerError::Config(format!(
                "{BASE_URL_VAR} must use the https:// scheme (got \"{scheme}\")"
            )));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(AnalyzerError::Config(format!(
                "{BASE_URL_VAR} must not carry a query string or fragment"
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AnalyzerError::Config(format!(
                "{BASE_URL_VAR} must not embed credentials"
            )));
        }
        Ok(url)
    }

    /// Optional DSH analyzer service URL: absolute `https://` (loopback
    /// `http` accepted for a co-located confined instance, mirroring the
    /// ledger base-URL policy), without credentials, query, or fragment.
    fn parse_dsh_base_url(vars: &HashMap<String, String>) -> Result<Option<Url>> {
        let Some(raw) = Self::optional_value(vars, DSH_BASE_URL_VAR) else {
            return Ok(None);
        };
        let url = Url::parse(&raw).map_err(|err| {
            AnalyzerError::Config(format!("{DSH_BASE_URL_VAR} is not an absolute URL: {err}"))
        })?;
        let scheme = url.scheme();
        let loopback = matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("::1") | Some("localhost")
        );
        if scheme != "https" && !(scheme == "http" && loopback) {
            return Err(AnalyzerError::Config(format!(
                "{DSH_BASE_URL_VAR} must use the https:// scheme (got \"{scheme}\")"
            )));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(AnalyzerError::Config(format!(
                "{DSH_BASE_URL_VAR} must not carry a query string or fragment"
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AnalyzerError::Config(format!(
                "{DSH_BASE_URL_VAR} must not embed credentials"
            )));
        }
        Ok(Some(url))
    }

    /// Optional DSH model API key, taken verbatim like the analyzer token
    /// (never trimmed, whitespace rejected, value never echoed).
    fn parse_dsh_api_key(vars: &HashMap<String, String>) -> Result<Option<SecretToken>> {
        let Some(raw) = vars.get(DSH_API_KEY_VAR) else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.chars().any(|c| c.is_ascii_whitespace()) {
            return Err(AnalyzerError::Config(format!(
                "{DSH_API_KEY_VAR} must not contain whitespace (a single API key value without spaces)"
            )));
        }
        Ok(Some(SecretToken::new(raw.clone())))
    }

    /// Optional positive catalog size (context window, max tokens),
    /// bounded by [`MAX_DSH_CONTEXT_WINDOW`].
    fn bounded_catalog_value(vars: &HashMap<String, String>, name: &str) -> Result<Option<u32>> {
        let Some(raw) = Self::optional_value(vars, name) else {
            return Ok(None);
        };
        let value: u64 = raw.parse().map_err(|_| {
            AnalyzerError::Config(format!("{name} must be a positive integer (got {raw:?})"))
        })?;
        if value == 0 || value > MAX_DSH_CONTEXT_WINDOW {
            return Err(AnalyzerError::Config(format!(
                "{name} must be between 1 and {MAX_DSH_CONTEXT_WINDOW} (got {value})"
            )));
        }
        u32::try_from(value)
            .map(Some)
            .map_err(|_| AnalyzerError::Config(format!("{name} exceeds the u32 range")))
    }

    /// Optional DSH bearer token, taken verbatim like the analyzer token
    /// (never trimmed, whitespace rejected, value never echoed).
    fn parse_dsh_token(vars: &HashMap<String, String>) -> Result<Option<SecretToken>> {
        let Some(raw) = vars.get(DSH_TOKEN_VAR) else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.chars().any(|c| c.is_ascii_whitespace()) {
            return Err(AnalyzerError::Config(format!(
                "{DSH_TOKEN_VAR} must not contain whitespace (the service accepts a single `Authorization: Bearer <token>` credential without spaces)"
            )));
        }
        Ok(Some(SecretToken::new(raw.clone())))
    }

    /// Required bearer token, taken verbatim (never trimmed or rewritten).
    ///
    /// Empty or whitespace-bearing values are rejected: the server presents
    /// the credential as `Authorization: Bearer <token>` parsed as a single
    /// non-space token, so such values cannot authenticate. Error messages
    /// never echo the value.
    fn parse_token(vars: &HashMap<String, String>) -> Result<Option<SecretToken>> {
        // Unset or empty means "not from the environment"; the boot
        // resolution may still find the latest-used token in the state store.
        let Some(raw) = vars.get(TOKEN_VAR) else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.chars().any(|c| c.is_ascii_whitespace()) {
            return Err(AnalyzerError::Config(format!(
                "{TOKEN_VAR} must not contain whitespace (the server accepts a single `Authorization: Bearer <token>` credential without spaces)"
            )));
        }
        Ok(Some(SecretToken::new(raw.clone())))
    }

    /// Optional non-negative integer; absent or empty yields `default`.
    fn u64_value(vars: &HashMap<String, String>, name: &str, default: u64) -> Result<u64> {
        match Self::optional_value(vars, name) {
            None => Ok(default),
            Some(raw) => raw.parse::<u64>().map_err(|_| {
                AnalyzerError::Config(format!(
                    "{name} must be a non-negative integer (got {raw:?})"
                ))
            }),
        }
    }

    /// Like [`Self::u64_value`], but zero is rejected (a zero cap would fail
    /// every run instead of bounding it).
    fn positive_u64_value(vars: &HashMap<String, String>, name: &str, default: u64) -> Result<u64> {
        let value = Self::u64_value(vars, name, default)?;
        if value == 0 {
            return Err(AnalyzerError::Config(format!(
                "{name} must be greater than zero"
            )));
        }
        Ok(value)
    }
}
