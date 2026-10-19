# DumpAnalyzer

DumpAnalyzer is the **Analyzer** for a DumpLedger instance: a headless Rust
daemon that discovers Windows minidumps through the DumpLedger catalog,
analyzes them with an internal agent (CDB toolchain on a Windows analysis
box via SSH), and writes verdicts back as analysis reports.

Architecture baseline: [block, control-flow and data-flow diagrams](docs/architecture.md)
([rendered view](docs/architecture.html)).
Rich reports: [capture, evidence, detail API, delivery, and rollout](docs/rich-reports.md).
Design: [`docs/analyzer-design.md`](docs/analyzer-design.md).
Formal model of the job lifecycle: [`specs/DumpAnalyzer.tla`](specs/DumpAnalyzer.tla)
(TLC-clean; see the design doc for the bounded evidence).
Task plan: [`Plans/rust-implementation-tasks.md`](Plans/rust-implementation-tasks.md).

## Build and test

Rust 1.85+ (developed on 1.95). Dependencies are pinned by `Cargo.lock`;
with a warm registry cache everything runs offline:

```sh
cargo build --offline --locked
cargo test --offline --locked        # full suite (needs loopback TCP for wiremock)
cargo clippy --offline --locked --all-targets -- -D warnings
cargo fmt --check
```

## Run

```sh
export DUMP_ANALYZER_BASE_URL='https://<dumpledger-host>:4080'
export DUMP_ANALYZER_TOKEN='<analyzer bearer token>'   # sha256 goes to the server config
# The latest-used token is persisted in the state store (migration 2): later
# boots may omit the variable, and the dashboard action forms may leave the
# token field empty to use it. At rest it lives in data/analyzer.sqlite —
# same volume protection as the ledger vault; never logged.
#
# The dashboard's "Analyzer token" card stores a new token without a restart:
# `POST /-/store-token` (or the form) probes the candidate against the live
# ledger first — a token the server rejects is never stored. On success the
# UI's action auth uses it immediately; the daemon's server-side pipeline
# picks it up at the next boot.
export DUMP_ANALYZER_SSH_TARGET='windows-dev'          # Windows analysis box running CDB
export DUMP_ANALYZER_SYMBOL_CACHE_DIR='C:\symcache'  # on the analysis box;
# symsrv requires the Windows-native backslash form (C:/symcache makes dbghelp
# reject the store as "not a valid store"). In a systemd EnvironmentFile the
# backslash must be doubled: DUMP_ANALYZER_SYMBOL_CACHE_DIR=C:\\symcache
dump-analyzer
```

Optional knobs (see `src/config.rs`): `DUMP_ANALYZER_STATE_DIR` (`./data`),
`DUMP_ANALYZER_NAME`/`DUMP_ANALYZER_VERSION` (report attribution),
`DUMP_ANALYZER_WRITE_BACK` (`off` treats the ledger as a read-only dump
source: verdicts record locally and jobs settle without `POST …/analyses`),
`DUMP_ANALYZER_POLL_INTERVAL_MS` (5–30 s feed cadence),
`DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS`, `DUMP_ANALYZER_MAX_OUTPUT_BYTES`,
`DUMP_ANALYZER_MAX_WORKSPACE_BYTES`, `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES`.

The token never appears in logs, errors, or URLs.

## Tool-runner providers

The agent's analysis backend is selected with `DUMP_ANALYZER_RUNNER`:

- **`cdb-ssh`** (default): deterministic CDB collection runs over SSH
  (`src/runner.rs`). Essential exception/context evidence is collected before
  optional symbol refinement. A symbol-stage failure preserves that evidence.
- **`claude-cdb`**: the same deterministic collector runs first, then a
  persistent, isolated Claude host assesses bounded captured evidence
  (`src/claude_runner.rs`). Tools and MCP servers are disabled; every tool
  request is denied. Malformed or unavailable reasoning leaves the captured
  report readable, with a deterministic assessment and an explicit omission.

Both produce the same canonical report: exception record/context, qualified
native stack, module/PDB evidence and an assessment separating the immediate
mechanism from the underlying cause. Full evidence is saved before generating
the compact v1 verdict. The default analyzer version is now `0.2.0`; legacy
reports remain readable and require a new version for detailed reanalysis.

```sh
export DUMP_ANALYZER_RUNNER='claude-cdb'
export DUMP_ANALYZER_CLAUDE_BIN='claude'        # default; PATH lookup
export DUMP_ANALYZER_CLAUDE_MODEL=''            # optional override
# claude itself needs its own auth (subscription or API key) on this host.
```

Both providers require `DUMP_ANALYZER_SSH_TARGET` (the Windows analysis box).
Run bounds cover local staging/execution waits and captured output; cleanup has
a separate two-second grace. Killing local SSH does not prove remote CDB
termination. See the rich-report guide for the precise containment limits.

## On-demand analysis

The `Analyzer` component (`src/analyzer.rs`) is the typed capability
`f : DumpId -> IO Report`: given a dump ID from DumpLedger it runs the full
pipeline (detail gate → fetch/verify → bounded toolchain run) and returns
the verdict as a `Report` and preserves a local copy. With write-back on,
pending delivery appears in the work queue until the report is accepted
or retained in local-verdict mode. With write-back off, it settles locally
immediately.

Hand-trigger through the status UI (loopback, token-guarded):

```sh
curl -X POST http://127.0.0.1:4180/-/analyze \
     -H "Authorization: Bearer $DUMP_ANALYZER_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"dumpId": "dump_01J…"}'
```

or the dashboard's action forms (no token field — they run with the
daemon's stored token). Use the analysis actions to run a dump again.
The Jobs widget shows **claimed, running, and reporting work**. Discovered
dumps appear in the separate **Dumps explorer**, grouped by customer and case,
with search and analysis actions at each level. Completed dumps remain
browseable there. Terminal jobs (`done`/`failed`/`dropped`) leave Jobs
immediately. Reports remain available, and settled identities are
retained separately so a rescan does not enqueue completed work again.
Existing terminal rows are moved out of the queue automatically when the
updated daemon opens its state database.

Scope actions analyze every `available` dump of a case or a customer
(sequential, capped at 64 dumps per call):

```sh
curl -X POST http://127.0.0.1:4180/-/analyze-case \
     -H "Authorization: Bearer $DUMP_ANALYZER_TOKEN" \
     -d '{"caseId": "case_01J…"}'          # → {"considered": n, "reports": [...], "skipped": [...]}
curl -X POST http://127.0.0.1:4180/-/analyze-customer \
     -H "Authorization: Bearer $DUMP_ANALYZER_TOKEN" -d '{"customerId": "customer_01J…"}'
# A customer display name works too — it is resolved to the id via the
# server's customer list (exact match; ambiguous names are rejected).
```

A per-dump failure never aborts the batch — it lands in `skipped` with its
reason. `POST /-/rescan` (same bearer guard, plus a dashboard form) re-runs
the full catalog sweep on demand. Pending local verdicts are replayed every
60 s when write-back is enabled, including during analysis and with automatic
scheduling disabled. A write-back route appearing mid-run is picked up
without a restart. The call is synchronous — a real dump takes
minutes. Responses: `200` report JSON · `400` malformed · `401` wrong/missing
token · `404` unknown or purged dump · `409` not `available` · `503`
transient budget exhausted · `500` terminal.

## Status UI

The dashboard has separate **Queue**, **Dumps**, **Reports**, and **Settings**
panels. Queue shows current analysis work. Dumps navigates from customers to
cases to a page of dumps. Reports has search, outcome/delivery filters, and
lazy full detail with stack, exception/context, assessment and evidence.
Settings holds credentials, manual actions, and
diagnostics. The listener binds to loopback by default:

```sh
export DUMP_ANALYZER_HTTP_ADDR='127.0.0.1:4180'   # default; empty disables
```

`http://127.0.0.1:4180/` is the dashboard: a static shell
(`src/dashboard.html`) with direct links `#queue`, `#dumps`, `#reports`, and
`#settings`. Navigation preserves scope, filters, and page selection, including
browser Back/Forward. Only the visible list is loaded: the queue polls every
5 seconds, and the selected Dumps or Reports panel every 15 seconds. Both
browser lists show 25 rows per page; hidden panels make no list requests.
Daemon status uses lightweight counts. The System/Light/Dark theme is retained.
No server data is embedded in the shell; HTML/JSON injection is client-escaped. A
non-loopback bind is a deployment decision: there is no authentication on
this surface. Dumps are hostile input:
CDB runs only on the designated analysis box, under hard time/output caps,
with per-run workspaces wiped afterwards.

`GET /api/dumps/browse` returns one hierarchy level, with optional `customerId`,
`caseId`, `q`, `page`, and `pageSize` parameters. Root rows are customers;
selecting a customer lists its cases, and selecting a case lists its dumps.
Customer and case rows contain counts rather than nested dump lists. The
legacy `GET /api/dumps` snapshot remains available for API consumers.
Remote catalog metadata is cached on the daemon for 30 seconds; the browser
receives one page and analysis state is read only for returned dumps.

`GET /api/reports` accepts `q`, `outcome` (`all`, `completed`, `failed`),
`delivery` (`all`, `pending`, `posted`), `page`, and `pageSize`. It returns the
page, matching count, complete report count, and pending count. Both page APIs
default to 25 rows and accept sizes from 1 through 100. Search/filter changes
reset the page. Details loads only the selected `GET /api/reports/:reportId`;
the paged list never loads canonical evidence JSON. Legacy reports are explicitly
labelled when detailed evidence was not captured.

Catalog and report errors stay inside their panels, retaining the last loaded
results. Browsing never starts analysis. A manual run appears in Jobs while
executing; its temporary execution record clears on completion or cancellation,
while pending report delivery remains visible as `reporting`.

## Model-based tests

The job lifecycle spec (`specs/DumpAnalyzer.tla`) is replayed against the
real state layer via [MirrorRust](../MirrorRust) and the Mirrors toolchain:

```sh
cargo test --offline --locked --test mbt   # needs MIRROR_BIN=<path to mirror>
python3 tools/mbt/gen_traces.py --check    # corpus freshness gate
python3 tools/mbt/gen_traces.py            # explicit corpus regeneration
```

## Server dependencies

DumpLedger's analyzer milestones AI1–AI3 landed at `98e484c` (catalog +
token + ETag, event feed, analysis write-back; see its
`docs/analyzer-guide.md` for the operator-facing contract). Against older
servers without the write-back route, reports are kept in local-verdict mode
(`data/analyzer.sqlite`, `local_reports`) and replayed when the route
appears. Without the event feed, restart-triggered `initial_scan` still
finds work.
