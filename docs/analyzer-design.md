# DumpAnalyzer design

Status: active. The server milestones AI1–AI3 landed in DumpLedger at
`98e484c` (2026-10-14), with the operator-facing `docs/analyzer-guide.md`;
our wire types and verdict writer are aligned to the implemented contracts
(`catalog.ts`, `events.ts`, `analyses.ts`), including the 4 KiB UTF-8
`facts`/`detail` budgets and the analyzer name/version bounds. Companion to
DumpLedger's
`docs/analyzer-integration-design.md` (repo-local:
`~/Repos/dump-ledger/docs/analyzer-integration-design.md`). That document
defines the **server surface** (milestones AI1–AI3); this document defines the
**consumer**: DumpAnalyzer, the Analyzer that pulls dumps from DumpLedger,
analyzes them with an internal agent, and writes verdicts back.

## Purpose and scope

DumpAnalyzer is a machine consumer of a DumpLedger instance. It exists to turn
"an operator downloads a dump and runs CDB by hand" into a continuous,
auditable pipeline:

- **Discover** work through the dump catalog (`GET /api/v1/dumps`, AI1) and
  keep current through the event feed (`GET /api/v1/events`, AI2).
- **Fetch** dump bytes and symbols over the authenticated read surface and
  the symsrv store, with hash verification and conditional revalidation.
- **Analyze** each dump with an internal **agent**: an isolated pipeline
  driver that stages bytes, acquires symbols, runs the debugger toolchain,
  and extracts facts.
- **Report** verdicts back as analysis reports
  (`POST /api/v1/dumps/:dumpId/analyses`, AI3), so results live next to the
  evidence they describe and survive analyzer restarts.

Non-goals for v1:

- No operator UI and no human workflow; DumpLedger remains the operator
  surface. DumpAnalyzer is a headless daemon plus logs. (The loopback
  status UI added 2026-10-13 is observability only: no actions, no
  workflow.)
- No execution of analysis inside DumpLedger, and no changes to DumpLedger's
  engine beyond what AI1–AI3 already specify.
- No general debugger-automation framework: exactly one analysis **kind**
  (`triage`) ships first; the architecture admits more.
- No push delivery, no cross-instance federation, no storage of analysis
  artifacts beyond the bounded JSON `facts` object (stack captures and
  derived files stay in DumpAnalyzer's own bounded workspace, per the
  integration design's non-goals).
- DumpAnalyzer never ingests symbols into DumpLedger and never holds an
  operator session; its only credential is the analyzer token.

## Vocabulary

Per CONTEXT.md discipline in DumpLedger, the terms fixed here are the ones
DumpAnalyzer adds. **Analyzer**, **analyzer token**, **analysis report**, and
**event feed** are inherited from the integration design and are not
redefined.

**Analysis job**:
The unit of work: one dump at one pinned content hash, to be analyzed with
one kind by one analyzer version. Job identity is
`(dumpId, inputSha256, kind, analyzerVersion)`, mirroring the server-side
report identity so local dedup and server idempotency align.
_Avoid_: task, scan

**Agent**:
The internal component that executes an analysis job end to end: staging,
symbol acquisition, toolchain execution, and fact extraction. The agent is
the only component that touches the tool runner and the workspace.
_Avoid_: worker, plugin

**Run**:
One execution of the agent pipeline for one job. Runs are at-least-once:
crashes and transient failures re-run; exactly-once *effect* comes from the
server's idempotent write-back, not from suppressing re-runs.
_Avoid_: attempt (reserved for retry counting), session

**Tool runner**:
The seam that executes the debugger toolchain (CDB) on a Windows analysis
host, given a staged dump and a symbol path, returning bounded output. v1
transport: SSH to a designated Windows box. The DumpLedger host never runs
the toolchain.
_Avoid_: executor service, sandbox (overloaded)

**Workspace**:
A per-run, wipe-after-use directory holding the staged dump and intermediate
output. Workspaces are never shared between runs and never persist after
write-back.
_Avoid_: temp folder (under-specified)

**Byte cache**:
A bounded local store of already-downloaded dump bytes, keyed by content
hash, validated with the content `ETag` (`If-None-Match`). A cache hit skips
the download, never the verification.
_Avoid_: dump archive

**Feed cursor**:
The persisted position in the DumpLedger event feed (the opaque, rowid-based
cursor). It is monotonic: it never moves backward, including across restarts.
_Avoid_: offset, bookmark

## Reference deployment

```text
+--------------------+        HTTPS (analyzer token)         +----------------------+
| DumpAnalyzer host  | ------------------------------------> | DumpLedger           |
|  (Linux, Rust)     |   catalog, events, bytes, write-back  |  https://<host>:4080 |
|                    |                                       |  symsrv listener     |
|  agent             | <------------------------------------ |  (symbol artifacts)  |
|    | tool runner   |        symsrv symbol fetch            +----------------------+
|    v               |
|  SSH transport     |
+--------|-----------+
         v
+--------------------+
| Windows analysis   |
| box (CDB + symsrv) |
+--------------------+
```

The current DumpLedger deployment on the LAN is `https://192.168.150.219:4080`
(time-specific; confirm before use). The analyzer host and the Windows
analysis box may be the same machine, but the tool-runner transport seam is
kept regardless: dumps are hostile input, and where CDB executes is a
deployment decision, not a code change.

## Module design

One Rust process (decided 2026-10-13, superseding the earlier TypeScript
note): a single `dump-analyzer` binary, tokio async runtime, `reqwest` over
rustls for the server surface, `rusqlite` (bundled SQLite) for local state,
`serde`/`serde_json` for wire types with symmetric decode/encode and
unknown-field rejection, `sha2` for content verification. Toolchain
discipline mirrors DumpLedger's: `cargo test` tiers (unit + integration),
`cargo clippy -- -D warnings` and `cargo fmt --check` as gates, no new
dependencies outside the approved manifest. No listening HTTP port in v1;
health is the process journal (tracing) plus exit codes.

| Module | Responsibility | Does not |
|---|---|---|
| `ledger-client` | Typed HTTP client for the AI1–AI3 surface; analyzer-token auth; strict response decoding; ETag conditional GETs | retry policy, caching decisions |
| `catalog-sync` | Initial keyset scan of `GET /api/v1/dumps`; event-follower loop on `GET /api/v1/events`; persists the feed cursor | job execution |
| `scheduler` | Job table, dedup on job identity, bounded run concurrency (v1: 1), retry with capped backoff, drop rules | HTTP, toolchain |
| `agent` | The pipeline driver (below); owns workspace lifecycle | scheduling, server writes beyond its own run |
| `tool-runner` | Transport + CDB script execution with hard time/output bounds | dump staging, report assembly |
| `verdict-writer` | Report assembly, idempotent POST, restart reconciliation | analysis |
| `state` | `data/analyzer.sqlite`: jobs, cursors, cache index | — |

Process-local state only. DumpAnalyzer's SQLite file is its own; it never
opens DumpLedger's ledger, and it can be deleted and rebuilt from the server
catalog at the cost of re-analysis.

## Agent pipeline

The agent runs one job through these stages. "Persisted" means the stage
boundary is recorded in the job table before the stage's side effects begin,
so a crash recovers from the boundary, not from a guess.

| # | Stage | Server touch | Persisted at entry | Crash recovery |
|---|---|---|---|---|
| 1 | claim | — (local) | job row: `claimed` | — |
| 2 | fetch | `GET …/content` (ETag) | `fetching` | re-fetch; partial file is discarded |
| 3 | verify | — | sha256 of staged bytes == catalog `sha256`, else refetch (bounded) then `failed` | re-fetch |
| 4 | acquire symbols | symsrv `GET /symbols/…` | module list from bounded inspection + CDB module load needs | re-run |
| 5 | execute | — (tool runner is local/SSH) | `analyzing` | re-run (bytes re-verified) |
| 6 | extract facts | — | bounded CDB output parsed into `facts` | re-run |
| 7 | report | `POST …/analyses` | `reporting`, with pinned `inputSha256` | re-POST; `200` replay is success |
| 8 | settle | — | `done`/`dropped`/`failed` | — |

Stage rules:

- **Pinning.** The job pins `inputSha256` at fetch time and carries it into
  the POST. Dump bytes are immutable once `available`, so a mismatch at
  verify time means local corruption (refetch), and a `404`/`410` at any
  later touch means the dump was purged: the job is `dropped`, never
  retried.
- **Outcome vs. infrastructure failure.** A dump that cannot be analyzed
  (corrupt minidump, missing critical symbols, CDB cannot load) produces a
  report with `outcome: "failed"` — that is a verdict. A tool-runner failure
  (SSH down, CDB crashed, timeout) is transient: bounded retry, then job
  `failed` with no report. The two paths are never conflated.
- **Idempotent settle.** `201` and `200` (identity replay) both settle the
  job as `done`. Re-running the same analyzer version against the same bytes
  is a server-side no-op by design; local dedup exists to save CDB runs, not
  to guarantee correctness.
- **Bounded everything.** Download size, CDB wall time, captured output, and
  workspace size all have hard caps; exceeding a cap fails the run, never
  hangs it.

Two agent backends sit behind the tool-runner seam (the scheduler, sync, and
write-back modules touch neither): the deterministic CDB script runner
(`cdb-ssh`, default) and, per the 2026-10-13 decision, the `claude-cdb`
provider, which lets the `claude` CLI drive CDB agentically over SSH under
`--restricted` containment with schema-forced output (src/claude_runner.rs).
Both honor the same `RunBounds`; a malformed agent result is a runner error,
never a verdict.

## On-demand component

`src/analyzer.rs` defines the capability `f : DumpId -> IO Report` (trait
`analyzer::Analyzer`, production `PipelineAnalyzer`): one effectful call that
takes a DumpLedger dump ID and returns a `Report` — detail lookup gated on
`available` + sealed sha256, then the shared pipeline stages (cache + ETag
fetch, sha256 verification, bounded toolchain run via `Agent::attempt`).
It creates no job rows and persists no attempts (the by-phase pipeline shows
scheduled work only); the report is recorded as a pending local report for
dashboard visibility and written back lazily by the replay path (boot
reconciliation / idle sweep). Errors map to `NotFound`,
`NotAvailable`, `Transient` (budget exhausted), `Terminal`. The status UI
exposes it as token-guarded `POST /-/analyze` (plus a browser form); the
token is digest-compared in constant time and never stored or rendered.

## Server surface consumed

| DumpLedger surface | Milestone | DumpAnalyzer use |
|---|---|---|
| `GET /api/v1/dumps` (+ filters, keyset pages) | AI1 | initial scan; revalidation sweeps |
| `GET /api/v1/dumps/by-sha256/:sha256` | AI1 | upstream duplicate check before scheduling |
| `GET /api/v1/dumps/:dumpId` | existing | per-dump detail, `symbolCoverage` preflight |
| `GET /api/v1/dumps/:dumpId/content` (+ ETag/304) | existing + AI1 | byte fetch and cache revalidation |
| `GET /api/v1/events?since=…` | AI2 | change tracking; new dumps and purges |
| `GET /symbols/:name/:id/:file` (symsrv) | existing | symbol acquisition for CDB |
| `POST/GET /api/v1/dumps/:dumpId/analyses` | AI3 | verdict write-back; restart reconciliation |
| analyzer token (`Authorization: Bearer`) | AI1 | sole credential, read scope + AI3 POST |

Until AI3 ships on the server, DumpAnalyzer runs in **local-verdict mode**:
reports are written to its own store with the same identity tuple, and the
write-back module replays them when the server surface appears. This keeps
AN2 deliverable against AI1+AI2 alone.

## Correctness and idempotency

- **Write-back is optional.** `DUMP_ANALYZER_WRITE_BACK=off` treats the
  ledger as a read-only dump source: the verdict sink is `LocalVerdictSink`
  (assemble + record locally + settle `done` — no POST, no acceptance wait),
  the boot reconcile and the idle replay sweep are skipped, and stale
  `reporting` rows settle `done` at boot.
- **Exactly-once effect, at-least-once execution.** The server identity
  `(dumpId, analyzer.name, analyzer.version, kind, inputSha256)` plus
  idempotent replay gives exactly-once visible effect. DumpAnalyzer never
  relies on suppressing a re-run for correctness.
- **Pinned input.** A report is only ever submitted for the hash that was
  actually analyzed, and `inputSha256` mismatch is a server-side
  `invalid_request`, so a verdict cannot silently attach to different bytes.
- **Cursor monotonicity.** Event application is idempotent, so the follower
  applies a page and *then* persists the cursor (apply-then-persist): a crash
  between the two replays the page rather than losing it. The cursor never
  moves backward; a beyond-end poll returns the request cursor, which is the
  sleep signal (5–30 s cadence).
- **Purge races.** A purge at any point invalidates the job at its next
  server touch; accepted reports are cascade-deleted server-side, so no local
  reconciliation is needed beyond dropping the job.
- **Restart reconciliation.** On boot: jobs in `reporting` check
  `GET …/analyses` for their identity tuple (present → `done`, absent →
  re-POST); jobs in `claimed`/`fetching`/`analyzing` re-enter at fetch with
  byte re-verification; the cursor resumes the feed.
- **Single-writer discipline.** One DumpAnalyzer process per configured
  `(analyzer.name, analyzer.version)`: the token has no per-client identity,
  so two concurrent writers would share one attribution. v1 enforces this
  with a process lock on the state directory.

## Security considerations

- The analyzer token comes from an environment variable or secret store, is
  sent only over TLS, and never appears in URLs, logs, crash output, or the
  workspace. CDB symbol paths embed no credentials.
- Dumps are hostile input. The toolchain runs only on the designated analysis
  box, never on the DumpLedger host, with hard time/output bounds and a
  wiped workspace. Symbol download over symsrv is read-only; GUID/age and
  timestamp/size are lookup metadata, not authentication of bytes (per
  DumpLedger's security model).
- `facts` and `summary` are stored and later rendered by DumpLedger's web UI:
  the agent emits plain text only, within the 16 KiB body bound, and must not
  copy raw dump memory into a report.
- The analyzer's own SQLite and byte cache contain dump-derived data and get
  the same volume-level protection as the DumpLedger vault.

## Test and model strategy

- **Unit:** wire decoders for every consumed shape (including duplicate-key
  and bound rejection), job-identity dedup, retry/drop classification.
- **Integration:** against a fixture DumpLedger server (in-process Fastify
  with the real contracts): scan + follow + fetch + ETag 304, token
  precedence (`401` on wrong token), write-back replay, purge mid-pipeline,
  crash-recovery at every persisted stage boundary.
- **Formal:** `specs/DumpAnalyzer.tla` models the job lifecycle, crash/
  recovery, purge races, and idempotent write-back; checked invariants are
  listed in `specs/DumpAnalyzer.cfg`:

  ```sh
  tlc -config specs/DumpAnalyzer.cfg specs/DumpAnalyzer.tla
  apalache-mc check --no-deadlock --init=Init --next=Next \
    --inv=PinnedReport --length=10 specs/DumpAnalyzer.tla
  ```

  The 2026-10-13 revision (split submit accept/settle, honest purge
  semantics) produced 1,621,239 TLC-generated states, 428,704 distinct
  states, depth 33, with no invariant violation; Apalache found no
  counterexample through length 10 for `PinnedReport`. These are bounded
  finite-model results. They do not establish that the analyzer is formally
  verified; the model abstracts HTTP, hashing, and the toolchain, and covers
  safety only, not liveness.
- **MBT (MirrorRust):** `tests/mbt.rs` replays the checked corpus
  (`tests/mbt/traces/`, generated by `tools/mbt/gen_traces.py` from
  `specs/DumpAnalyzerReplay.tla`: per-action witnesses plus BFS and
  simulation traces, 33 traces covering all 20 actions) against the real
  state layer — jobs, cursors, local reports, `Agent::recover_job` — through
  the `mirror` executable (`MIRROR_BIN`; the Mirrors checkout builds it).
  `python3 tools/mbt/gen_traces.py --check` is the corpus freshness gate.
  Observation provenance and the harness's scripted-server boundary are
  documented in `tests/mbt/harness.rs`; HTTP and toolchain behavior stay
  with the integration tiers.
- **Field evidence:** first real runs execute against the LAN instance with
  known case dumps; CDB output and symbol-load evidence are preserved per
  run, matching the project's dump-forensics evidence conventions.

## Phasing

| Milestone | Content | Server dependency |
|---|---|---|
| AN1 | `ledger-client`, `catalog-sync`, `state`; scan + follow + fetch + verify; no analysis | AI1 (AI2 for the feed; scan-only fallback exists) |
| AN2 | `agent` + `tool-runner` with CDB triage kind; local-verdict mode | — |
| AN3 | `verdict-writer` live write-back + restart reconciliation; field run | AI3 |
| AN4 (optional) | second analysis kind; long-poll if cadence proves insufficient | AI4 if it lands |

## Open questions

1. **Symbol acquisition topology.** Point CDB's sympath at DumpLedger's
   symsrv listener directly (single-HTTP-store-last rule), or pre-seed a
   local store on the analysis box? Direct is simpler; pre-seeding may win
   for repeat analyses of one product version.
2. **Where the analysis box lives.** SSH to the existing Windows dev box is
   the v1 transport, but a dedicated, more disposable analysis machine is the
   better long-term answer for hostile dumps.
3. **Multiple kinds per dump.** The job table admits `kind` already, but
   scheduling policy (which kinds run for which dumps) is undefined beyond
   "triage everything".
4. **Report enrichment.** Whether `facts` should carry CDB command excerpts
   or stay strictly structured fields; the 16 KiB bound forces the question
   for noisy stacks.
