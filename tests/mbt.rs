//! MirrorRust MBT replay: every corpus trace in `tests/mbt/traces/` is
//! stepped through the real state layer (see `harness.rs`) by the `mirror`
//! executable, which diffs each reported state against the spec's computed
//! state. Corpus regeneration is an explicit maintainer action:
//! `python3 tools/mbt/gen_traces.py`.

#[path = "mbt/harness.rs"]
mod harness;

use std::path::PathBuf;

use mirrorrust::{ApalacheConfig, run_client_with_traces};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn mbt_replay_corpus() {
    let mirror = match std::env::var("MIRROR_BIN") {
        Ok(bin) if !bin.is_empty() => bin,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT replay");
            return;
        }
    };
    let traces_dir = repo_root().join("tests/mbt/traces");
    let mut traces: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&traces_dir).expect("traces dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path.file_name().and_then(|n| n.to_str()) != Some("manifest.json")
        {
            traces.push(path.to_string_lossy().into_owned());
        }
    }
    traces.sort();
    assert!(
        !traces.is_empty(),
        "empty MBT corpus; run tools/mbt/gen_traces.py"
    );

    let config = ApalacheConfig {
        spec_path: repo_root()
            .join("specs/DumpAnalyzerReplay.tla")
            .to_string_lossy()
            .into_owned(),
        init_predicate: None,
        next_predicate: None,
        const_init: None,
        invariant: "TraceComplete".to_string(),
        length_bound: 40,
        param_vars: Some("parameters".to_string()),
    };
    run_client_with_traces(&mirror, config, traces, harness::Harness::new())
        .expect("MBT replay must match the spec states");
}
