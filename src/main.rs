//! Binary entry point (task D2): parse configuration, initialize tracing,
//! build the SSH/CDB tool runner, and run the daemon until SIGTERM/SIGINT.
//!
//! The daemon body lives in [`dump_analyzer::scheduler::run`] (testable with
//! a fake tool runner); this file only owns the process concerns the daemon
//! does not share with tests:
//!
//! * `Config::from_process_env` — fail fast, naming the offending variable;
//! * tracing with `RUST_LOG` env-filter and an `info` default (health is the
//!   process journal plus exit codes; the dashboard is optional);
//! * the production tool runner: CDB over SSH to the configured analysis box
//!   (`DUMP_ANALYZER_SSH_TARGET` is required — the design's only v1
//!   transport);
//! * exit codes: 0 clean shutdown, 1 runtime/boot failure (including a held
//!   state lock), 2 configuration failure.

use std::process::ExitCode;
use std::sync::Arc;

use dump_analyzer::config::Config;
use dump_analyzer::runner::{SshCdbRunner, SshTransport};
use dump_analyzer::scheduler;
use dump_analyzer::types::{AnalyzerError, Result, ToolRunner};

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_process_env() {
        Ok(config) => config,
        Err(err) => {
            // Tracing is not up yet; this must not be lost.
            eprintln!("dump-analyzer: {err}");
            return ExitCode::from(2);
        }
    };
    init_tracing();

    let runner = match build_runner(&config) {
        Ok(runner) => runner,
        Err(err) => {
            tracing::error!(%err, "configuration error");
            return ExitCode::from(2);
        }
    };

    match scheduler::run_until_signal(config, runner).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(%err, "dump-analyzer exited with an error");
            ExitCode::from(1)
        }
    }
}

/// Tracing subscriber with `RUST_LOG` env-filter semantics and an `info`
/// default. Invalid `RUST_LOG` values fall back to the default instead of
/// aborting startup.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Builds the v1 tool runner: CDB over SSH on the analysis box.
///
/// `DUMP_ANALYZER_SSH_TARGET` is optional in the configuration parser (the
/// library has other uses than the daemon), but required to run the daemon:
/// the design's only v1 toolchain transport is SSH to a designated Windows
/// box, and a daemon without one could never settle a job.
fn build_runner(config: &Config) -> Result<Arc<dyn ToolRunner>> {
    let Some(target) = config.ssh_target.as_deref() else {
        return Err(AnalyzerError::Config(
            "DUMP_ANALYZER_SSH_TARGET is required to run the daemon: both v1 tool-runner \
             providers execute CDB on the analysis box over SSH"
                .to_owned(),
        ));
    };
    let runner: Arc<dyn ToolRunner> = match config.runner {
        dump_analyzer::types::RunnerKind::CdbSsh => {
            Arc::new(SshCdbRunner::new(SshTransport::new(target)))
        }
        dump_analyzer::types::RunnerKind::DshHttp => {
            let base_url = config.dsh_base_url.clone().ok_or_else(|| {
                AnalyzerError::Config(
                    "DUMP_ANALYZER_DSH_BASE_URL is required for DUMP_ANALYZER_RUNNER=dsh-http"
                        .to_owned(),
                )
            })?;
            let api = dump_analyzer::dsh_runner::HttpDshApi::new_with_api_key(
                base_url,
                config.dsh_token.as_ref(),
                config.dsh_api_key.as_ref(),
                config.tls_ca_cert.as_deref(),
            )?;
            let route = dump_analyzer::dsh_runner::DshRoute {
                provider: config.dsh_provider.clone(),
                model: config.dsh_model.clone(),
                reasoning_effort: config.dsh_reasoning_effort.clone(),
                context_window: config.dsh_context_window,
                max_tokens: config.dsh_max_tokens,
            };
            Arc::new(
                dump_analyzer::dsh_runner::DshCdbRunner::new(
                    SshTransport::new(target),
                    Arc::new(api),
                    &config.dsh_preset,
                )
                .with_route(route)
                .with_analysis_tools(config.dsh_tools)
                .with_forensicator(config.forensicator_bin.clone()),
            )
        }
    };
    Ok(runner)
}
