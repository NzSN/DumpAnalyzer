# DumpAnalyzer

DumpAnalyzer continuously analyzes Windows crash dumps cataloged by a
DumpLedger instance while keeping analysis verdicts attached to the evidence
they describe.

## Language

Inherited from DumpLedger (`~/Repos/dump-ledger/CONTEXT.md` and
`docs/analyzer-integration-design.md`): **Case**, **case workflow**, **dump
lifecycle**, **upload grant**, **module**, **symbol artifact**, **symbol
store**, **Analyzer**, **analyzer token**, **analysis report**, **event
feed**. Those terms are not redefined here.

**Analysis job**:
The unit of analysis work identified by `(dumpId, inputSha256, kind,
analyzerVersion)`. Completed, failed, and dropped jobs leave the queue;
their reports and settled identities remain.
_Avoid_: task, scan

**Work queue**:
Jobs that have been claimed, are running, or are waiting for report delivery.
Discovered dumps and settled work are outside this queue.
_Avoid_: job history

**Discovered dump**:
An available dump known to the analyzer and eligible for a future run.
It is browseable in the dumps explorer before a job is claimed.
_Avoid_: queued job

**Dumps explorer**:
The catalog of available dumps grouped by customer and case, including dumps
awaiting analysis and dumps with completed reports.
_Avoid_: work queue

**Agent**:
The internal component executing a job end to end (staging, symbols,
toolchain, facts). Only the agent touches the tool runner and workspace.
_Avoid_: worker, plugin

**Run**:
One execution of the agent pipeline for one job. Runs are at-least-once;
exactly-once effect comes from the server's idempotent write-back.
_Avoid_: attempt, session

**Tool-runner provider**:
The selected agent backend implementation: `cdb-ssh` (deterministic script),
`claude-cdb` (a local claude CLI host assesses bounded captured evidence),
or `dsh-http` (a dedicated DeepSeek Harness HTTP service does the same).
Selected by `DUMP_ANALYZER_RUNNER`.
_Avoid_: plugin, worker

**Tool runner**:
The seam executing CDB on a Windows analysis host (v1: SSH), with hard
time/output caps.
_Avoid_: executor, sandbox

**Workspace**:
Per-run directory for staged bytes and intermediate output; wiped after the
run.
_Avoid_: temp folder

**Byte cache**:
Bounded local store of downloaded dump bytes keyed by content hash,
revalidated by ETag. A hit skips the download, never the verification.
_Avoid_: dump archive

**Feed cursor**:
Persisted position in the DumpLedger event feed. Monotonic across restarts;
applied-then-persisted with idempotent replay.
_Avoid_: offset, bookmark

**Analyzer component**:
The on-demand capability `f : DumpId -> IO Report`: one call, one report.
Completed analysis leaves the work queue once its report is settled under
the configured delivery policy.
_Avoid_: ad-hoc analysis

**Local-verdict mode**:
Reports stored in `local_reports` when the server predates AI3; replayed
when the write-back route appears.
_Avoid_: offline queue
