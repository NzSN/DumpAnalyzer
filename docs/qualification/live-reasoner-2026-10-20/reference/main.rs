//! Offline P6 baseline: exact authored fixture, request and transport semantics
//! from tests/claude_runner.rs at f269ce82d2ac28e9ba77f7f393ffc231e639a164.
//! No Claude runner is imported or constructed; no process transport exists.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dump_analyzer::runner::{ExecTransport, SshCdbRunner, TransportOutput};
use dump_analyzer::types::{AnalyzerError, RunBounds, RunRequest, ToolRunner};
use serde_json::json;

const LOG: &str = include_str!("/home/nzsn/Repos/DumpAnalyzer/tests/fixtures/report-v2/marked-av.log");
const BOUNDS: RunBounds = RunBounds {
    wall_timeout: Duration::from_secs(3),
    max_output_bytes: 1 << 20,
    max_workspace_bytes: 1 << 21,
};

#[derive(Clone, Default)]
struct FakeTransport {
    puts: Arc<Mutex<Vec<(PathBuf, String)>>>,
    execs: Arc<Mutex<Vec<Vec<String>>>>,
    cdb_delay: Duration,
    fail_cdb: bool,
}
#[async_trait::async_trait]
impl ExecTransport for FakeTransport {
    async fn exec(
        &self,
        program: &str,
        args: &[&str],
        _stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> dump_analyzer::types::Result<TransportOutput> {
        let mut call = vec![program.to_owned()];
        call.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.execs.lock().expect("lock").push(call);
        if program == "cdb" {
            tokio::time::sleep(self.cdb_delay).await;
            if self.fail_cdb {
                return Err(AnalyzerError::Transport("CDB unavailable".into()));
            }
        }
        Ok(TransportOutput {
            status: Some(0),
            stdout: if program == "cdb" {
                LOG.as_bytes().to_vec()
            } else {
                vec![]
            },
            stderr: vec![],
        })
    }
    async fn put_file(&self, local: &Path, remote: &str) -> dump_analyzer::types::Result<()> {
        self.puts.lock().expect("lock").push((local.to_owned(), remote.to_owned()));
        Ok(())
    }
}

fn request(dir: &Path) -> (RunRequest, PathBuf) {
    let dump = dir.join("dump.dmp");
    std::fs::write(&dump, b"authored dummy dump; no RSDS module identity").expect("dump");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).expect("work");
    (
        RunRequest {
            dump_path: dump,
            symbol_path: "SRV*C:/symcache*https://ledger.example.test/symbols".into(),
            work_dir: work.clone(),
            bounds: BOUNDS,
        },
        work,
    )
}

#[tokio::main]
async fn main() {
    let base = Path::new("/tmp/dumpanalyzer-p6-live-20261020/reference");
    let directory = tempfile::Builder::new().prefix("baseline-").tempdir_in(base).expect("private tempdir");
    let (mut req, _) = request(directory.path());
    req.bounds.wall_timeout = Duration::from_secs(120);
    let transport = FakeTransport::default();
    let output = SshCdbRunner::new(transport.clone()).run(req).await.expect("deterministic fixture capture");
    let capture = output.capture.expect("owned deterministic capture");
    dump_analyzer::assessment::validate(&capture).expect("deterministic assessment validation");
    assert!(!capture.evidence.iter().any(|item| item.id == "assessment-model"));
    // Match ClaudeCdbRunner::run's mutation immediately before reason().
    // Serialize the typed struct directly, matching production compact bytes.
    let mut prepared_capture = capture.clone();
    prepared_capture.provenance.provider = "claude-cdb".into();
    prepared_capture.provenance.model = None;
    if !prepared_capture.provenance.analysis_revision.is_empty() {
        prepared_capture.provenance.analysis_revision.push(';');
    }
    prepared_capture.provenance.analysis_revision.push_str("reasoner=claude-host-v2.1");
    let prepared_json = serde_json::to_string(&prepared_capture).expect("typed pre-reasoner capture");
    let mut prepared_options = std::fs::OpenOptions::new();
    prepared_options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        prepared_options.mode(0o600);
    }
    let mut prepared_file = prepared_options.open(base.join("prepared-capture.json")).expect("new exact pre-reasoner capture");
    std::io::Write::write_all(&mut prepared_file,prepared_json.as_bytes()).expect("write exact pre-reasoner capture");
    let receipt = json!({
        "qualification": "Offline deterministic baseline using production SshCdbRunner with exact authored fixture and FakeTransport; no Claude, SSH, CDB process or network",
        "sourceCommit": "f269ce82d2ac28e9ba77f7f393ffc231e639a164",
        "bounds": {"wallTimeoutSeconds":120,"maxOutputBytes":1<<20,"maxWorkspaceBytes":1<<21},
        "outcome": output.outcome,
        "summary": output.summary,
        "facts": output.facts,
        "capture": capture,
        "fakeTransport": {"execs": &*transport.execs.lock().expect("execs"), "puts": &*transport.puts.lock().expect("puts")}
    });
    let output_path = base.join("baseline.json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&output_path).expect("new baseline receipt");
    std::io::Write::write_all(&mut file,serde_json::to_string_pretty(&receipt).expect("receipt JSON").as_bytes()).expect("write receipt");
    println!("Baseline written to {}",output_path.display());
}
