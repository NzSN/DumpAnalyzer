#!/usr/bin/env python3
"""Generate the DumpAnalyzer MBT trace corpus (specs/DumpAnalyzerReplay.tla).

Runs TLC (a build with -dumpTrace support; see TLC_JAR below) twice over:
  1. BFS mode: the shortest TraceComplete violation (canonical witness).
  2. Simulation mode over a seed range: varied interleavings of crash,
     purge, retry, and feed-follow paths.

Each raw TLC JSON trace is converted to ITF (the Mirrors wire format),
deduplicated, and checked for corpus-wide action coverage. Artifacts:

  tests/mbt/traces/<name>.itf.json   replay inputs for tests/mbt.rs
  tests/mbt/traces/manifest.json     hashes, tool versions, coverage

Regeneration is an explicit maintainer action: `python3 tools/mbt/gen_traces.py`.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent.parent
SPECS = ROOT / "specs"
OUT = ROOT / "tests/mbt/traces"
WORK = ROOT / "target/mbt-traces"

# A TLC build with -dumpTrace (the 2.19 wrapper on PATH predates it).
TLC_JAR = Path("/home/nzsn/.cache/coursier/v1/https/github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar")
TLC = ["java", "-cp", str(TLC_JAR), "tlc2.TLC"]

SIM_SEEDS = range(1, 13)
SIM_DEPTH = 40


# Actions the corpus must cover between all traces (the full action alphabet
# of specs/DumpAnalyzer.tla).
REQUIRED_ACTIONS = {
    "intake", "discover", "claim", "begin-fetch", "stage", "fetch-purged",
    "verify-ok", "verify-corrupt", "analyze-completes", "runner-failed",
    "job-failed", "submit-accept", "submit-replay", "submit-purged",
    "purge", "purge-observed", "crash", "crash-reset", "recover", "follow",
}

VAR_TYPES = {
    "jobState": "Seq(Str)",
    "jobContent": "Seq(Int)",
    "bytesVerified": "Seq(Bool)",
    "attempts": "Seq(Int)",
    "serverDump": "Seq(Str)",
    "serverReports": "Set(<<Int, Int>>)",
    "eventsSeen": "Int",
    "eventCursor": "Int",
    "lastEventCursor": "Int",
    "agentUp": "Bool",
    "action_taken": "Str",
    "parameters": "{ dump: Int, content: Int, kind: Str }",
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, *, cwd, expected=(0,), timeout=300):
    result = subprocess.run([str(c) for c in command], cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    if result.returncode not in expected:
        raise RuntimeError(
            f"command exited {result.returncode}: {command!r}\n{result.stdout[-8000:]}")
    return result


def bigint(value):
    if type(value) is not int:
        raise ValueError(f"expected int, got {value!r}")
    return {"#bigint": str(value)}


def seq(values, convert):
    if not isinstance(values, list):
        raise ValueError(f"expected TLC sequence as array, got {values!r}")
    return [convert(v) for v in values]


def identity(value):
    return value


CONVERTERS = {
    "jobState": lambda v: seq(v, identity),
    "jobContent": lambda v: seq(v, bigint),
    "bytesVerified": lambda v: seq(v, identity),
    "attempts": lambda v: seq(v, bigint),
    "serverDump": lambda v: seq(v, identity),
    "eventsSeen": bigint,
    "eventCursor": bigint,
    "lastEventCursor": bigint,
    "agentUp": identity,
    "action_taken": identity,
    "parameters": lambda r: {
        "dump": bigint(r["dump"]),
        "content": bigint(r["content"]),
        "kind": identity(r["kind"]),
    },
}


def server_reports(value):
    if not isinstance(value, list):
        raise ValueError(f"expected TLC set as array, got {value!r}")
    rows = []
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError(f"malformed report pair: {pair!r}")
        rows.append({"#tup": [bigint(pair[0]), bigint(pair[1])]})
    return {"#set": rows}


CONVERTERS["serverReports"] = server_reports


def convert(raw_path, out_path):
    raw = json.loads(raw_path.read_text())
    states_in = raw["counterexample"]["state"]
    if sorted(raw["vars"]) != sorted(VAR_TYPES):
        raise ValueError(f"TLC vars {raw['vars']} differ from expected {sorted(VAR_TYPES)}")
    states = []
    for expected_index, entry in enumerate(states_in):
        index, state = entry
        if index != expected_index + 1:
            raise ValueError("noncontiguous trace indices")
        if set(state) != set(VAR_TYPES):
            raise ValueError(f"state {index} variables differ from the model")
        states.append({
            "#meta": {"index": index - 1},
            **{name: CONVERTERS[name](state[name]) for name in VAR_TYPES},
        })
    if not states or states[0]["action_taken"] != "init":
        raise ValueError("trace does not start at init")
    itf = {
        "#meta": {"format": "ITF", "varTypes": VAR_TYPES},
        "vars": sorted(VAR_TYPES),
        "params": [],
        "param_vars": ["parameters"],
        "states": states,
    }
    out_path.write_text(json.dumps(itf, indent=1, sort_keys=False) + "\n")
    return [s["action_taken"] for s in states]


def write_cfg(path, *, invariants, target=""):
    path.write_text(
        "INIT Init\nNEXT Next\n"
        f"INVARIANTS {invariants}\n"
        f'CONSTANT TargetAction = "{target}"\n'
        "CHECK_DEADLOCK FALSE\n")


def check():
    """Freshness gate: the corpus matches its manifest and current specs."""
    manifest = json.loads((OUT / "manifest.json").read_text())
    problems = []
    for key, path in [("specSha256", SPECS / "DumpAnalyzer.tla"),
                      ("replaySpecSha256", SPECS / "DumpAnalyzerReplay.tla")]:
        if sha256(path) != manifest[key]:
            problems.append(f"stale oracle input: {path}")
    for name, digest in manifest["traces"].items():
        trace = OUT / f"{name}.itf.json"
        if not trace.is_file() or sha256(trace) != digest:
            problems.append(f"corpus artifact changed: {name}")
    if problems:
        for problem in problems:
            print(f"STALE: {problem}", file=sys.stderr)
        raise SystemExit(1)
    print(f"corpus fresh: {len(manifest['traces'])} traces, "
          f"{len(manifest['coveredActions'])} actions covered")


def main():
    if "--check" in sys.argv:
        return check()
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    spec = SPECS / "DumpAnalyzerReplay.tla"
    for stale in OUT.glob("*.itf.json"):
        stale.unlink()

    traces = {}  # name -> action list
    digests = {}

    def add(name, raw):
        itf_path = OUT / f"{name}.itf.json"
        actions = convert(raw, itf_path)
        digest = sha256(itf_path)
        if digest in digests:
            itf_path.unlink()
            return False
        digests[digest] = name
        traces[name] = actions
        return True

    # 1. Canonical BFS witness: shortest completion.
    cfg = WORK / "witness.cfg"
    write_cfg(cfg, invariants="TraceComplete")
    raw = WORK / "bfs-witness.json"
    witness = run([*TLC, "-workers", "1", "-noGenerateSpecTE", "-config", cfg,
                   "-metadir", WORK / "states-bfs", "-dumpTrace", "json", raw,
                   spec], cwd=WORK, expected=(12,))
    if "Invariant TraceComplete is violated" not in witness.stdout:
        raise RuntimeError("BFS witness run failed for another reason:\n" + witness.stdout[-4000:])
    add("bfs-witness", raw)

    # 2. Per-action witnesses: the shortest trace executing each required
    # action (BFS via NeverTarget violations). Deterministic coverage of the
    # deep pipeline stages that random simulation loses to purge/crash.
    for action in sorted(REQUIRED_ACTIONS):
        cfg = WORK / f"witness-{action}.cfg"
        write_cfg(cfg, invariants="NeverTarget", target=action)
        raw = WORK / f"action-{action}.json"
        witness = run([*TLC, "-workers", "1", "-noGenerateSpecTE", "-config", cfg,
                       "-metadir", WORK / f"states-action-{action}",
                       "-dumpTrace", "json", raw, spec], cwd=WORK, expected=(12,))
        if f"Invariant NeverTarget is violated" not in witness.stdout:
            raise RuntimeError(f"action witness for {action} failed:\n" + witness.stdout[-4000:])
        add(f"action-{action}", raw)

    # 3. Simulation traces over the seed range (interleaving variety).
    cfg = WORK / "witness.cfg"
    write_cfg(cfg, invariants="TraceComplete")
    for seed in SIM_SEEDS:
        raw = WORK / f"sim-{seed}.json"
        result = run([*TLC, "-workers", "1", "-noGenerateSpecTE", "-config", cfg,
                      "-metadir", WORK / f"states-sim-{seed}",
                      "-simulate", "-depth", SIM_DEPTH, "-seed", seed,
                      "-dumpTrace", "json", raw, spec],
                     cwd=WORK, expected=(0, 12))
        if "Invariant TraceComplete is violated" in result.stdout and raw.is_file():
            add(f"sim-{seed:02d}", raw)

    covered = {a for actions in traces.values() for a in actions} - {"init"}
    missing = sorted(REQUIRED_ACTIONS - covered)
    print(f"{len(traces)} unique traces; covered actions: {len(covered)}/{len(REQUIRED_ACTIONS)}")
    for name, actions in sorted(traces.items()):
        print(f"  {name}: {len(actions)} states, actions: {sorted(set(actions) - {'init'})}")
    if missing:
        print(f"MISSING ACTIONS: {missing}", file=sys.stderr)

    manifest = {
        "schema": "dump-analyzer.mbt-corpus/v1",
        "specSha256": sha256(SPECS / "DumpAnalyzer.tla"),
        "replaySpecSha256": sha256(spec),
        "tlcJarSha256": sha256(TLC_JAR),
        "generatorSha256": sha256(Path(__file__).resolve()),
        "simSeeds": [min(SIM_SEEDS), max(SIM_SEEDS)],
        "simDepth": SIM_DEPTH,
        "traces": {name: sha256(OUT / f"{name}.itf.json") for name in sorted(traces)},
        "coveredActions": sorted(covered),
        "missingActions": missing,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if missing:
        raise RuntimeError(f"corpus misses required actions: {missing}")
    print(f"Corpus published to {OUT}")


if __name__ == "__main__":
    main()
