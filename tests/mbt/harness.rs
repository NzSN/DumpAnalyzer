//! MBT harness: replays `specs/DumpAnalyzer.tla` traces against the real
//! analyzer state layer.
//!
//! Per spec action, the harness drives the real modules — `state.rs`
//! (jobs, cursors, local reports), `agent.rs` (`Agent::recover_job`) — while
//! the server truth (dump availability, accepted reports, feed length) is
//! scripted here. Observation provenance per variable:
//!
//! - SUT-real (SQLite): `jobState`, `attempts`, `eventCursor`
//! - harness truth (the server is out of process): `serverDump`,
//!   `serverReports`, `eventsSeen`, `agentUp`, `lastEventCursor`
//! - harness shadow of volatile pipeline state the store deliberately does
//!   not persist: `jobContent`, `bytesVerified`
//! - echoed trace inputs: `action_taken`, `parameters`
//!
//! The HTTP/agent/runner stages behind these transitions are covered by the
//! integration tiers, not by this replay (docs/analyzer-design.md, evidence
//! boundary).

use std::collections::BTreeMap;

use dump_analyzer::agent::Agent;
use dump_analyzer::state::Store;
use dump_analyzer::types::{JobIdentity, JobPhase, ReportOutcome};
use mirrorrust::{State, StateComputer, Value};
use num_bigint::BigInt;

const PHASES: [JobPhase; 9] = [
    JobPhase::Discovered,
    JobPhase::Claimed,
    JobPhase::Fetching,
    JobPhase::Staged,
    JobPhase::Analyzing,
    JobPhase::Reporting,
    JobPhase::Done,
    JobPhase::Dropped,
    JobPhase::Failed,
];

fn phase_str(phase: JobPhase) -> &'static str {
    match phase {
        JobPhase::Discovered => "discovered",
        JobPhase::Claimed => "claimed",
        JobPhase::Fetching => "fetching",
        JobPhase::Staged => "staged",
        JobPhase::Analyzing => "analyzing",
        JobPhase::Reporting => "reporting",
        JobPhase::Done => "done",
        JobPhase::Dropped => "dropped",
        JobPhase::Failed => "failed",
    }
}

fn int(value: i64) -> Value {
    Value::Int(BigInt::from(value))
}

fn as_i64(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Int(n)) => n.try_into().expect("small model int"),
        _ => 0,
    }
}

/// Identity of the job for dump slot `d` (1-based, matching the model).
fn identity(d: usize) -> JobIdentity {
    JobIdentity {
        dump_id: format!("dump-{d}"),
        // 64 lowercase hex: passes the canonical sha256 shape check.
        input_sha256: format!("{:064x}", d),
        kind: "triage".to_string(),
        analyzer_version: "mbt".to_string(),
    }
}

fn slot_of(job: &JobIdentity) -> usize {
    job.dump_id
        .strip_prefix("dump-")
        .and_then(|rest| rest.parse().ok())
        .expect("harness identity")
}

/// One replay instance; reset on every trace's `init` state.
pub struct Harness {
    storage: Option<(tempfile::TempDir, Store)>,
    job_content: [i64; 2],
    bytes_verified: [bool; 2],
    server_dump_purged: [bool; 2],
    server_reports: Vec<(i64, i64)>,
    events_seen: i64,
    last_event_cursor: i64,
    agent_up: bool,
}

impl Harness {
    pub fn new() -> Self {
        Self {
            storage: None,
            job_content: [0, 0],
            bytes_verified: [false, false],
            server_dump_purged: [false, false],
            server_reports: Vec::new(),
            events_seen: 0,
            last_event_cursor: 0,
            agent_up: true,
        }
    }

    fn store(&self) -> &Store {
        &self.storage.as_ref().expect("init must open the store").1
    }

    fn reset(&mut self) {
        let dir = tempfile::tempdir().expect("temp state dir");
        let store = Store::open(dir.path().join("analyzer.sqlite")).expect("open store");
        self.storage = Some((dir, store));
        self.job_content = [0, 0];
        self.bytes_verified = [false, false];
        self.server_dump_purged = [false, false];
        self.server_reports = Vec::new();
        self.events_seen = 0;
        self.last_event_cursor = 0;
        self.agent_up = true;
    }

    fn set_phase(&self, d: usize, phase: JobPhase) {
        self.store()
            .jobs()
            .set_phase(&identity(d), phase)
            .expect("set_phase");
    }

    fn drop(&self, d: usize) {
        self.store()
            .jobs()
            .drop_job(&identity(d))
            .expect("drop_job");
    }

    /// Current stored phase of dump `d`'s job, if a row exists.
    fn stored_phase(&self, d: usize) -> Option<JobPhase> {
        let wanted = identity(d);
        for phase in PHASES {
            for (job, _) in self
                .store()
                .jobs()
                .jobs_in_phase(phase)
                .expect("jobs_in_phase")
            {
                if job == wanted {
                    return Some(phase);
                }
            }
        }
        None
    }

    fn apply(&mut self, action: &str, d: usize) {
        match action {
            "intake" => self.events_seen += 1,
            "discover" => {
                let inserted = self
                    .store()
                    .jobs()
                    .upsert_discovered(&identity(d))
                    .expect("upsert_discovered");
                assert!(inserted, "discover must insert a fresh job");
            }
            "claim" => self.set_phase(d, JobPhase::Claimed),
            "begin-fetch" => self.set_phase(d, JobPhase::Fetching),
            "stage" => {
                self.set_phase(d, JobPhase::Staged);
                self.job_content[d - 1] = d as i64;
                self.bytes_verified[d - 1] = false;
            }
            "fetch-purged" => {
                self.drop(d);
                self.job_content[d - 1] = 0;
            }
            "verify-ok" => {
                self.set_phase(d, JobPhase::Analyzing);
                self.bytes_verified[d - 1] = true;
            }
            "verify-corrupt" => {
                self.store()
                    .jobs()
                    .record_attempt(&identity(d))
                    .expect("record_attempt");
                self.set_phase(d, JobPhase::Fetching);
                self.bytes_verified[d - 1] = false;
            }
            "analyze-completes" => {
                self.set_phase(d, JobPhase::Reporting);
                // verdict.rs discipline: the local copy exists before any
                // server contact (crash-safe write-back).
                self.store()
                    .local_reports()
                    .insert(&identity(d), ReportOutcome::Completed, "mbt verdict", "{}")
                    .expect("local_reports insert");
            }
            "runner-failed" => {
                self.store()
                    .jobs()
                    .record_attempt(&identity(d))
                    .expect("record_attempt");
                self.set_phase(d, JobPhase::Claimed);
                self.bytes_verified[d - 1] = false;
            }
            "job-failed" => {
                self.set_phase(d, JobPhase::Failed);
                self.bytes_verified[d - 1] = false;
            }
            "submit-accept" => {
                // Server accepts the report; the job stays reporting until
                // the client observes the response (submit-replay).
                self.server_reports
                    .push((d as i64, self.job_content[d - 1]));
                self.store()
                    .local_reports()
                    .mark_posted(&identity(d))
                    .expect("mark_posted");
            }
            "submit-replay" => self.set_phase(d, JobPhase::Done),
            "submit-purged" => {
                self.drop(d);
                self.job_content[d - 1] = 0;
            }
            "purge" => {
                self.server_dump_purged[d - 1] = true;
                self.server_reports.retain(|(dump, _)| *dump != d as i64);
                self.events_seen += 1;
            }
            "purge-observed" => {
                self.drop(d);
                self.job_content[d - 1] = 0;
                self.bytes_verified[d - 1] = false;
            }
            "crash" => self.agent_up = false,
            "crash-reset" => {
                let phase = self.stored_phase(d).expect("crash-reset needs a job row");
                Agent::recover_job(self.store(), &identity(d), phase).expect("recover_job");
                self.bytes_verified[d - 1] = false;
            }
            "recover" => self.agent_up = true,
            "follow" => {
                let old = self
                    .store()
                    .cursors()
                    .get("event_cursor")
                    .expect("cursor get")
                    .map(|value| value.parse::<i64>().expect("numeric cursor"));
                self.last_event_cursor = old.unwrap_or(0);
                self.store()
                    .cursors()
                    .set_monotonic("event_cursor", &format!("{:020}", self.events_seen))
                    .expect("set_monotonic");
            }
            other => panic!("unknown spec action: {other}"),
        }
    }

    fn observe(&self, action: &str, params: (i64, i64, &str)) -> State {
        let mut phases = ["none", "none"];
        let mut attempts = [0i64, 0];
        for phase in PHASES {
            for (job, count) in self
                .store()
                .jobs()
                .jobs_in_phase(phase)
                .expect("jobs_in_phase")
            {
                let slot = slot_of(&job) - 1;
                phases[slot] = phase_str(phase);
                attempts[slot] = i64::from(count);
            }
        }
        let event_cursor: i64 = self
            .store()
            .cursors()
            .get("event_cursor")
            .expect("cursor get")
            .map(|value| value.parse().expect("numeric cursor"))
            .unwrap_or(0);
        let seq_str = |items: [&str; 2]| {
            Value::Seq(items.iter().map(|s| Value::Str((*s).to_string())).collect())
        };
        let seq_int = |items: [i64; 2]| Value::Seq(items.iter().map(|v| int(*v)).collect());
        let seq_bool =
            |items: [bool; 2]| Value::Seq(items.iter().map(|b| Value::Bool(*b)).collect());
        let mut parameters = BTreeMap::new();
        parameters.insert("dump".to_string(), int(params.0));
        parameters.insert("content".to_string(), int(params.1));
        parameters.insert("kind".to_string(), Value::Str(params.2.to_string()));
        State::from([
            ("jobState".to_string(), seq_str(phases)),
            ("jobContent".to_string(), seq_int(self.job_content)),
            ("bytesVerified".to_string(), seq_bool(self.bytes_verified)),
            ("attempts".to_string(), seq_int(attempts)),
            (
                "serverDump".to_string(),
                seq_str(
                    self.server_dump_purged
                        .map(|p| if p { "purged" } else { "available" }),
                ),
            ),
            (
                "serverReports".to_string(),
                Value::Set(
                    self.server_reports
                        .iter()
                        .map(|(dump, content)| Value::Tuple(vec![int(*dump), int(*content)]))
                        .collect(),
                ),
            ),
            ("eventsSeen".to_string(), int(self.events_seen)),
            ("eventCursor".to_string(), int(event_cursor)),
            ("lastEventCursor".to_string(), int(self.last_event_cursor)),
            ("agentUp".to_string(), Value::Bool(self.agent_up)),
            ("action_taken".to_string(), Value::Str(action.to_string())),
            ("parameters".to_string(), Value::Record(parameters)),
        ])
    }
}

impl StateComputer for Harness {
    fn compute(&mut self, action: &str, params: &State, _prev: &State) -> State {
        if action == "init" {
            self.reset();
        }
        // InitialState carries the whole state map; NextStep carries the
        // parameters record directly.
        let record: &State = match params.get("parameters") {
            Some(Value::Record(inner)) => inner,
            _ => params,
        };
        let dump = as_i64(record.get("dump"));
        let content = as_i64(record.get("content"));
        let kind = match record.get("kind") {
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        };
        if action != "init" {
            // Dump-targeted actions carry slots 1..=2; environment actions
            // (intake, crash, recover, follow) carry 0 and never index jobs.
            assert!((0..=2).contains(&dump), "dump slot out of range");
            self.apply(action, dump as usize);
        }
        self.observe(action, (dump, content, &kind))
    }
}
