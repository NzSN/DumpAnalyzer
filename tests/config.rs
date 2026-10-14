//! Integration tests for `dump_analyzer::config` (task A2).
//!
//! Every test drives [`Config::from_env`] with a synthetic `(name, value)`
//! iterator; the real process environment is never read (per the A2 brief),
//! so `Config::from_process_env` is intentionally not exercised here.

use std::path::PathBuf;
use std::time::Duration;

use dump_analyzer::config::{Config, SecretToken};
use dump_analyzer::types::{AnalyzerError, RunBounds};

const BASE_URL: &str = "https://ledger.example:4080";
const TOKEN: &str = "test-token-abcdef0123456789";

fn vars(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut vars = vec![
        ("DUMP_ANALYZER_BASE_URL".to_owned(), BASE_URL.to_owned()),
        ("DUMP_ANALYZER_TOKEN".to_owned(), TOKEN.to_owned()),
    ];
    vars.extend(
        overrides
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    vars
}

fn expect_ok(raw: Vec<(String, String)>) -> Config {
    Config::from_env(raw.into_iter()).expect("config should parse")
}

fn expect_err(raw: Vec<(String, String)>) -> String {
    match Config::from_env(raw.into_iter()) {
        Err(AnalyzerError::Config(message)) => message,
        Ok(config) => panic!("expected AnalyzerError::Config, got a valid config: {config:?}"),
        Err(other) => panic!("expected AnalyzerError::Config, got {other:?}"),
    }
}

fn parse(overrides: &[(&str, &str)]) -> Config {
    expect_ok(vars(overrides))
}

fn parse_err(overrides: &[(&str, &str)]) -> String {
    expect_err(vars(overrides))
}

#[test]
fn config_defaults_when_only_required_vars_are_set() {
    let config = parse(&[]);

    assert_eq!(config.base_url.as_str(), "https://ledger.example:4080/");
    assert_eq!(config.token.as_ref().expect("token").expose(), TOKEN);
    assert_eq!(config.state_dir, PathBuf::from("./data"));
    assert_eq!(config.name, "dump-analyzer");
    assert_eq!(config.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(config.poll_interval, Duration::from_millis(10_000));
    assert_eq!(config.run_wall_timeout, Duration::from_millis(600_000));
    assert_eq!(config.max_output_bytes, 1_048_576);
    assert_eq!(config.max_workspace_bytes, 2_147_483_648);
    assert_eq!(config.byte_cache_max_bytes, 10_737_418_240);
    assert_eq!(config.ssh_target, None);
    assert_eq!(config.symbol_cache_dir, None);
}

#[test]
fn config_overrides_every_optional_variable() {
    let config = parse(&[
        ("DUMP_ANALYZER_BASE_URL", "https://other.example:4443"),
        ("DUMP_ANALYZER_TOKEN", "override-token"),
        ("DUMP_ANALYZER_STATE_DIR", "/var/lib/dump-analyzer"),
        ("DUMP_ANALYZER_NAME", "da-02"),
        ("DUMP_ANALYZER_VERSION", "9.9.9"),
        ("DUMP_ANALYZER_POLL_INTERVAL_MS", "30000"),
        ("DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS", "1000"),
        ("DUMP_ANALYZER_MAX_OUTPUT_BYTES", "2048"),
        ("DUMP_ANALYZER_MAX_WORKSPACE_BYTES", "4096"),
        ("DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES", "8192"),
        ("DUMP_ANALYZER_SSH_TARGET", "windows-dev"),
        ("DUMP_ANALYZER_SYMBOL_CACHE_DIR", "D:/symcache"),
    ]);

    assert_eq!(config.base_url.as_str(), "https://other.example:4443/");
    assert_eq!(
        config.token.as_ref().expect("token").expose(),
        "override-token"
    );
    assert_eq!(config.state_dir, PathBuf::from("/var/lib/dump-analyzer"));
    assert_eq!(config.name, "da-02");
    assert_eq!(config.version, "9.9.9");
    assert_eq!(config.poll_interval, Duration::from_millis(30_000));
    assert_eq!(config.run_wall_timeout, Duration::from_millis(1_000));
    assert_eq!(config.max_output_bytes, 2_048);
    assert_eq!(config.max_workspace_bytes, 4_096);
    assert_eq!(config.byte_cache_max_bytes, 8_192);
    assert_eq!(config.ssh_target.as_deref(), Some("windows-dev"));
    assert_eq!(config.symbol_cache_dir.as_deref(), Some("D:/symcache"));
}

#[test]
fn config_trims_surrounding_whitespace_of_non_secret_values() {
    let config = parse(&[
        ("DUMP_ANALYZER_POLL_INTERVAL_MS", " 12000 "),
        ("DUMP_ANALYZER_STATE_DIR", " /tmp/da-state "),
        ("DUMP_ANALYZER_NAME", " da "),
        ("DUMP_ANALYZER_VERSION", " 1.2.3 "),
        ("DUMP_ANALYZER_SSH_TARGET", " windows-dev "),
        ("DUMP_ANALYZER_SYMBOL_CACHE_DIR", " D:/symcache "),
    ]);

    assert_eq!(config.poll_interval, Duration::from_millis(12_000));
    assert_eq!(config.state_dir, PathBuf::from("/tmp/da-state"));
    assert_eq!(config.name, "da");
    assert_eq!(config.version, "1.2.3");
    assert_eq!(config.ssh_target.as_deref(), Some("windows-dev"));
    assert_eq!(config.symbol_cache_dir.as_deref(), Some("D:/symcache"));
}

#[test]
fn config_accepts_poll_interval_boundaries() {
    let low = parse(&[("DUMP_ANALYZER_POLL_INTERVAL_MS", "5000")]);
    assert_eq!(low.poll_interval, Duration::from_millis(5_000));

    let high = parse(&[("DUMP_ANALYZER_POLL_INTERVAL_MS", "30000")]);
    assert_eq!(high.poll_interval, Duration::from_millis(30_000));
}

#[test]
fn config_rejects_poll_intervals_outside_the_allowed_range() {
    for bad in ["4999", "30001", "0", "-1000"] {
        let message = parse_err(&[("DUMP_ANALYZER_POLL_INTERVAL_MS", bad)]);
        assert!(
            message.contains("DUMP_ANALYZER_POLL_INTERVAL_MS"),
            "for {bad:?}: {message}"
        );
    }
}

#[test]
fn config_requires_base_url_and_token() {
    let message = expect_err(vec![("DUMP_ANALYZER_TOKEN".to_owned(), TOKEN.to_owned())]);
    assert!(message.contains("DUMP_ANALYZER_BASE_URL"), "{message}");

    // An unset token is no longer a parse error: the boot resolution falls
    // back to the state store's latest-used token (or fails there).
    let config = expect_ok(vec![(
        "DUMP_ANALYZER_BASE_URL".to_owned(),
        BASE_URL.to_owned(),
    )]);
    assert!(config.token.is_none());

    let message = expect_err(Vec::new());
    assert!(message.contains("DUMP_ANALYZER_BASE_URL"), "{message}");
}

#[test]
fn config_rejects_malformed_base_urls() {
    for bad in [
        "http://ledger.example:4080",
        "ftp://ledger.example",
        "/relative/path",
        "not a url",
        "https://",
    ] {
        let message = parse_err(&[("DUMP_ANALYZER_BASE_URL", bad)]);
        assert!(
            message.contains("DUMP_ANALYZER_BASE_URL"),
            "for {bad:?}: {message}"
        );
    }

    let message = parse_err(&[("DUMP_ANALYZER_BASE_URL", "")]);
    assert!(message.contains("DUMP_ANALYZER_BASE_URL"), "{message}");
}

#[test]
fn config_rejects_base_url_credentials_query_and_fragment() {
    let message = parse_err(&[("DUMP_ANALYZER_BASE_URL", "https://user:pass@ledger.example")]);
    assert!(message.contains("DUMP_ANALYZER_BASE_URL"), "{message}");
    assert!(message.contains("credentials"), "{message}");

    let message = parse_err(&[("DUMP_ANALYZER_BASE_URL", "https://ledger.example:4080/?x=1")]);
    assert!(message.contains("query"), "{message}");

    let message = parse_err(&[(
        "DUMP_ANALYZER_BASE_URL",
        "https://ledger.example:4080/#fragment",
    )]);
    assert!(message.contains("fragment"), "{message}");
}

#[test]
fn config_accepts_base_url_with_path_prefix() {
    let config = parse(&[(
        "DUMP_ANALYZER_BASE_URL",
        "https://ledger.example:4080/base/",
    )]);
    assert_eq!(config.base_url.path(), "/base/");
}

#[test]
fn config_normalizes_base_url_through_url_parsing() {
    let config = parse(&[("DUMP_ANALYZER_BASE_URL", "HTTPS://LEDGER.EXAMPLE:4080")]);
    assert_eq!(config.base_url.scheme(), "https");
    assert_eq!(config.base_url.host_str(), Some("ledger.example"));
    assert_eq!(config.base_url.port(), Some(4080));
    assert_eq!(config.base_url.path(), "/");
}

#[test]
fn config_rejects_empty_or_whitespace_bearing_tokens() {
    // Empty means "not from the environment" (the store may still hold one).
    let config = parse(&[("DUMP_ANALYZER_TOKEN", "")]);
    assert!(config.token.is_none());

    for bad in [" ", "two words", "trailing\t", "leading\n"] {
        let message = parse_err(&[("DUMP_ANALYZER_TOKEN", bad)]);
        assert!(
            message.contains("DUMP_ANALYZER_TOKEN"),
            "for {bad:?}: {message}"
        );
    }
}

#[test]
fn config_rejects_malformed_numeric_values() {
    for (name, bad) in [
        ("DUMP_ANALYZER_POLL_INTERVAL_MS", "abc"),
        ("DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS", "0"),
        ("DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS", "1.5"),
        ("DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS", "18446744073709551616"),
        ("DUMP_ANALYZER_MAX_OUTPUT_BYTES", "0"),
        ("DUMP_ANALYZER_MAX_OUTPUT_BYTES", "abc"),
        ("DUMP_ANALYZER_MAX_WORKSPACE_BYTES", "0"),
        ("DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES", "0"),
        ("DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES", "abc"),
    ] {
        let message = parse_err(&[(name, bad)]);
        assert!(message.contains(name), "for {name}={bad:?}: {message}");
    }
}

#[test]
fn config_treats_empty_optional_values_as_unset() {
    let config = parse(&[
        ("DUMP_ANALYZER_STATE_DIR", ""),
        ("DUMP_ANALYZER_NAME", "   "),
        ("DUMP_ANALYZER_VERSION", ""),
        ("DUMP_ANALYZER_POLL_INTERVAL_MS", ""),
        ("DUMP_ANALYZER_SSH_TARGET", ""),
        ("DUMP_ANALYZER_SYMBOL_CACHE_DIR", "  "),
    ]);

    assert_eq!(config.state_dir, PathBuf::from("./data"));
    assert_eq!(config.name, "dump-analyzer");
    assert_eq!(config.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(config.poll_interval, Duration::from_millis(10_000));
    assert_eq!(config.ssh_target, None);
    assert_eq!(config.symbol_cache_dir, None);
}

#[test]
fn config_ignores_unknown_variables() {
    let config = parse(&[
        ("PATH", "/usr/bin:/bin"),
        ("DUMP_ANALYZER_UNKNOWN", "ignored"),
        ("duMP_analyzer_name", "wrong-case-is-unknown"),
    ]);

    assert_eq!(config.name, "dump-analyzer");
    assert_eq!(config.token.as_ref().expect("token").expose(), TOKEN);
}

#[test]
fn config_takes_the_last_duplicate_value() {
    let raw = vec![
        (
            "DUMP_ANALYZER_BASE_URL".to_owned(),
            "https://first.example".to_owned(),
        ),
        (
            "DUMP_ANALYZER_BASE_URL".to_owned(),
            "https://second.example".to_owned(),
        ),
        ("DUMP_ANALYZER_TOKEN".to_owned(), "first-token".to_owned()),
        ("DUMP_ANALYZER_TOKEN".to_owned(), TOKEN.to_owned()),
    ];
    let config = expect_ok(raw);

    assert_eq!(config.base_url.host_str(), Some("second.example"));
    assert_eq!(config.token.as_ref().expect("token").expose(), TOKEN);
}

#[test]
fn config_debug_output_never_exposes_the_token() {
    let config = parse(&[]);

    let debug = format!("{config:?}");
    assert!(
        !debug.contains(TOKEN),
        "Config Debug leaked the token: {debug}"
    );
    assert!(
        debug.contains("redacted"),
        "Config Debug should mark redaction: {debug}"
    );

    let token = &config.token;
    let token_debug = format!("{token:?}");
    assert!(
        !token_debug.contains(TOKEN),
        "token Debug leaked: {token_debug}"
    );

    let token_display = config.token.as_ref().expect("token").to_string();
    assert_eq!(token_display, "[redacted]");

    let direct = SecretToken::new("hunter2");
    assert_eq!(format!("{direct:?}"), "SecretToken([redacted])");
    assert_eq!(format!("{direct}"), "[redacted]");
}

#[test]
fn config_token_errors_never_echo_the_value() {
    const MARKER: &str = "shhhh9f2csecrettoken";

    let message = parse_err(&[("DUMP_ANALYZER_TOKEN", "shhhh9f2csecrettoken with-space")]);
    assert!(message.contains("DUMP_ANALYZER_TOKEN"), "{message}");
    assert!(
        !message.contains(MARKER),
        "token error leaked the value: {message}"
    );
}

#[test]
fn config_run_bounds_match_the_configured_caps() {
    let config = parse(&[
        ("DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS", "1234"),
        ("DUMP_ANALYZER_MAX_OUTPUT_BYTES", "4096"),
        ("DUMP_ANALYZER_MAX_WORKSPACE_BYTES", "1048576"),
    ]);

    let bounds: RunBounds = config.run_bounds();
    assert_eq!(bounds.wall_timeout, Duration::from_millis(1_234));
    assert_eq!(bounds.max_output_bytes, 4_096);
    assert_eq!(bounds.max_workspace_bytes, 1_048_576);
}

#[test]
fn config_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Config>();
    assert_send_sync::<SecretToken>();
}

#[test]
fn config_http_addr_defaults_to_loopback_4180() {
    let config = parse(&[]);
    assert_eq!(
        config.http_addr,
        Some("127.0.0.1:4180".parse().expect("default addr"))
    );
}

#[test]
fn config_http_addr_empty_disables() {
    let config = parse(&[("DUMP_ANALYZER_HTTP_ADDR", "")]);
    assert_eq!(config.http_addr, None);
    let config = parse(&[("DUMP_ANALYZER_HTTP_ADDR", "   ")]);
    assert_eq!(config.http_addr, None);
}

#[test]
fn config_http_addr_custom_and_malformed() {
    let config = parse(&[("DUMP_ANALYZER_HTTP_ADDR", "127.0.0.1:9999")]);
    assert_eq!(
        config.http_addr,
        Some("127.0.0.1:9999".parse().expect("custom addr"))
    );
    let err = parse_err(&[("DUMP_ANALYZER_HTTP_ADDR", "not-an-addr")]);
    assert!(
        err.contains("DUMP_ANALYZER_HTTP_ADDR"),
        "names the variable: {err}"
    );
}

#[test]
fn config_runner_defaults_to_cdb_ssh() {
    let config = parse(&[]);
    assert_eq!(config.runner, dump_analyzer::types::RunnerKind::CdbSsh);
    assert_eq!(config.claude_bin, "claude");
    assert_eq!(config.claude_model, None);
}

#[test]
fn config_runner_claude_cdb() {
    let config = parse(&[
        ("DUMP_ANALYZER_RUNNER", "claude-cdb"),
        ("DUMP_ANALYZER_CLAUDE_BIN", "/opt/claude/bin/claude"),
        ("DUMP_ANALYZER_CLAUDE_MODEL", "opus"),
    ]);
    assert_eq!(config.runner, dump_analyzer::types::RunnerKind::ClaudeCdb);
    assert_eq!(config.claude_bin, "/opt/claude/bin/claude");
    assert_eq!(config.claude_model.as_deref(), Some("opus"));
}

#[test]
fn config_runner_rejects_unknown_provider() {
    let err = parse_err(&[("DUMP_ANALYZER_RUNNER", "wat")]);
    assert!(
        err.contains("DUMP_ANALYZER_RUNNER"),
        "names the variable: {err}"
    );
    assert!(err.contains("cdb-ssh"), "lists the valid values: {err}");
}

#[test]
fn config_base_url_http_allowed_only_on_loopback() {
    let config = parse(&[("DUMP_ANALYZER_BASE_URL", "http://127.0.0.1:4999")]);
    assert_eq!(config.base_url.scheme(), "http");
    let config = parse(&[("DUMP_ANALYZER_BASE_URL", "http://localhost:4999/path")]);
    assert_eq!(config.base_url.scheme(), "http");
    let err = parse_err(&[("DUMP_ANALYZER_BASE_URL", "http://192.168.150.219:4080")]);
    assert!(
        err.contains("https://"),
        "non-loopback http rejected: {err}"
    );
    let err = parse_err(&[("DUMP_ANALYZER_BASE_URL", "http://ledger.example.test")]);
    assert!(err.contains("https://"), "remote http rejected: {err}");
}

#[test]
fn config_tls_ca_cert_optional_path() {
    let config = parse(&[]);
    assert_eq!(config.tls_ca_cert, None);
    let config = parse(&[("DUMP_ANALYZER_TLS_CA_CERT", "/etc/ssl/ledger.pem")]);
    assert_eq!(
        config.tls_ca_cert,
        Some(std::path::PathBuf::from("/etc/ssl/ledger.pem"))
    );
}
