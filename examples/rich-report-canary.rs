//! Explicit, isolated operator canary; never scans a catalog or posts a report.
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use dump_analyzer::report::CrashReportV2;
use dump_analyzer::runner::{SshCdbRunner, SshTransport};
use dump_analyzer::types::{JobIdentity, RunBounds, RunRequest, ToolRunner};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() < 4 || arguments.len() > 6 {
        return Err("usage: rich-report-canary <local-dump> <symbol-path> <new-report.json> [ssh-target] [cdb-ssh|claude-cdb]".into());
    }
    let dump_path = std::path::PathBuf::from(&arguments[1]);
    let destination = std::path::PathBuf::from(&arguments[3]);
    if destination.exists() {
        return Err("canary destination already exists; choose a new file".into());
    }
    let target = arguments.get(4).map_or("windows-dev", String::as_str);
    let provider = arguments.get(5).map_or("cdb-ssh", String::as_str);
    let mut file = std::fs::File::open(&dump_path)?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 65536];
    loop {
        let size = file.read(&mut chunk)?;
        if size == 0 {
            break;
        }
        digest.update(&chunk[..size]);
    }
    let sha256 = hex::encode(digest.finalize());
    let workspace = tempfile::tempdir()?;
    let runner: Arc<dyn ToolRunner> = match provider {
        "cdb-ssh" => Arc::new(SshCdbRunner::new(SshTransport::new(target))),
        "claude-cdb" => Arc::new(dump_analyzer::claude_runner::ClaudeCdbRunner::new(
            SshTransport::new(target),
            target,
            "claude",
        )),
        _ => return Err("provider must be cdb-ssh or claude-cdb".into()),
    };
    let output = runner
        .run(RunRequest {
            dump_path,
            symbol_path: arguments[2].clone(),
            work_dir: workspace.path().into(),
            bounds: RunBounds {
                wall_timeout: Duration::from_secs(120),
                max_output_bytes: 4 * 1024 * 1024,
                max_workspace_bytes: 2 * 1024 * 1024 * 1024,
            },
        })
        .await?;
    let identity = JobIdentity {
        dump_id: "dump_00000000000000000000000001".into(),
        input_sha256: sha256,
        kind: "triage".into(),
        analyzer_version: "0.2.0-canary".into(),
    };
    let report = CrashReportV2::from_output(&identity, "dump-analyzer", &output)?;
    let json = report.canonical_json()?;
    let mut output_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)?;
    std::io::Write::write_all(&mut output_file, json.as_bytes())?;
    println!(
        "{}",
        serde_json::json!({"reportId":report.report_id,"digest":report.digest()?,"path":destination,"exception":report.capture.exception.status,"frames":report.capture.stack.frames.len(),"symbols":report.capture.symbols.modules.iter().map(|m|serde_json::json!({"module":m.module,"quality":m.quality})).collect::<Vec<_>>(),"rootCause":report.capture.root_cause.status})
    );
    Ok(())
}
