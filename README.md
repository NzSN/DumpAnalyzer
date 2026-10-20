# DumpAnalyzer

DumpAnalyzer is the **Analyzer** for a DumpLedger instance: a headless Rust
daemon that discovers Windows minidumps through the DumpLedger catalog,
analyzes them with an internal agent (CDB toolchain on a Windows analysis
box via SSH), and writes verdicts back as analysis reports.

Architecture: [block, control-flow and data-flow diagrams](docs/architecture.md)
([rendered view](docs/architecture.html)).
Rich reports: [capture, evidence, detail API, delivery, and rollout](docs/rich-reports.md).
Design: [`docs/analyzer-design.md`](docs/analyzer-design.md).
Lifecycle model (bounded historical checks): [`specs/DumpAnalyzer.tla`](specs/DumpAnalyzer.tla)
(see the design doc for the evidence and abstraction boundary).
Documentation map ([full index](docs/README.md)):

- [Domain vocabulary](CONTEXT.md), [current architecture](docs/architecture.md),
  [consumer design](docs/analyzer-design.md), and [rich report operations](docs/rich-reports.md)
  describe the maintained implementation.
- [Rust implementation plan](Plans/rust-implementation-plan.md),
  [task ledger](Plans/rust-implementation-tasks.md), and
  [rich report implementation plan](Plans/rich-report-implementation-plan.md)
  preserve the implementation and qualification history.
- [Phase 2 readiness](Plans/phase2-live-readiness.md),
  [field run](Plans/field-run.md), and
  [local deployment receipt](docs/local-deployment-2026-10-15.md)
  are dated operational records, not current service health guarantees.
- [Report fixture inventory](tests/fixtures/report-v2/README.md) and
  [qualification fixtures](tests/fixtures/report-v2/qualification/README.md)
  record reproducible evidence and its limits.

## Build and test

Rust 1.85+ (developed on 1.95). Dependencies are pinned by `Cargo.lock`;
the dev dependency also requires the sibling `../MirrorRust` checkout.
With that checkout and a warm registry cache, the standard checks run offline:

```sh
cargo build --offline --locked
cargo test --offline --locked        # default suite (needs loopback TCP for wiremock)
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
# UI's token fallback uses it immediately; the daemon's server-side pipeline
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
`DUMP_ANALYZER_SCHEDULER` (`off` disables automatic claiming, while feed and
manual operation continue), `DUMP_ANALYZER_TLS_CA_CERT` (additional PEM trust),
`DUMP_ANALYZER_WRITE_BACK` (`off` treats the ledger as a read-only dump
source: verdicts record locally and jobs settle without `POST …/analyses`),
`DUMP_ANALYZER_POLL_INTERVAL_MS` (5–30 s feed cadence),
`DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS`, `DUMP_ANALYZER_MAX_OUTPUT_BYTES`,
`DUMP_ANALYZER_MAX_WORKSPACE_BYTES`, `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES`,
`DUMP_ANALYZER_WEBHOOK` (`on` arms the ledger webhook tap: boot-time
self-registration plus signed `POST /webhooks` deliveries),
`DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN` (WH2 webhook-admin bearer used for that
registration; required when the webhook is on), `DUMP_ANALYZER_WEBHOOK_URL`
(this daemon's externally reachable webhook URL, e.g.
`http://<lan-ip>:4180/webhooks`; required when the webhook is on),
`DUMP_ANALYZER_WEBHOOK_ACTIONS` (comma-separated audit actions to subscribe;
defaults to the feed follower's action set). The webhook tap needs
`DUMP_ANALYZER_HTTP_ADDR` to be reachable from the ledger host; the feed
follower remains the resumable truth and the webhook never advances its
cursor.

`SecretToken` formatting redacts the credential. The stored token is plaintext
inside SQLite: restrict access to the state directory and its backups.

## Tool-runner providers

The agent's analysis backend is selected with `DUMP_ANALYZER_RUNNER`:

- **`cdb-ssh`** (default): deterministic CDB collection runs over SSH
  (`src/runner.rs`). Essential exception/context evidence is collected before
  optional symbol refinement. A symbol-stage failure preserves that evidence.
  Successful refinement can
  upgrade an initially failed essential capture to `completed` when the refined
  result qualifies; optional-stage failure does not downgrade the baseline.
- **`claude-cdb`**: the same deterministic collector runs first, then a
  persistent, isolated Claude host assesses bounded captured evidence
  (`src/claude_runner.rs`). Tools and MCP servers are disabled; every tool
  request is denied. Malformed or unavailable reasoning leaves the captured
  report readable, with a deterministic assessment and an explicit omission.

Both produce the same canonical report: exception record/context, qualified
native stack, module/PDB evidence and an assessment separating the immediate
mechanism from the underlying cause. Full capture is retained while deriving
the compact v1 projection; both are persisted transactionally before delivery.
The default analyzer version is now `0.2.0`; legacy
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

Hand-trigger through the status UI (loopback by default). An explicit bearer
must match when supplied. An absent Authorization header or an empty form token
uses the daemon's configured token. This fallback does not authenticate the caller:

```sh
curl -X POST http://127.0.0.1:4180/-/analyze \
     -H "Authorization: Bearer $DUMP_ANALYZER_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"dumpId": "dump_01J…"}'
```

or the dashboard's action forms (no token field — they run with the
daemon's configured token). A matching canonical report is reused without
another CDB run; a legacy report under the same identity is rejected. For fresh
capture, configure a distinct `DUMP_ANALYZER_VERSION` and restart. Version
`0.1.0` is reserved for legacy records and rejected at configuration time.
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
reason. `POST /-/rescan` (same token fallback, plus a dashboard form) re-runs
the full catalog sweep on demand. Pending local verdicts are replayed every
60 s when write-back is enabled, including during analysis and with automatic
scheduling disabled. A write-back route appearing mid-run is picked up
without a restart. The call is synchronous — a real dump takes
minutes. Responses: `200` report JSON · `400` malformed · `401` explicit wrong
token or no configured token · `404` unknown or purged dump · `409` unavailable
(including an occupied legacy identity) · `503` transient budget exhausted ·
`500` terminal.

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
No server data is embedded in the shell; rendered catalog/report text is
client-escaped. Read endpoints are unauthenticated, and action token fallback
allows callers to act without presenting a credential. Keep the listener on a
trusted local boundary; a non-loopback deployment needs an access-control layer.
CDB runs on the designated analysis box with bounded local waits/output and
best-effort remote cleanup. These controls do not prove remote termination or
provide a remote disk quota.

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
executing; its temporary execution record clears on completion or cancellation.
An eligible pending handoff may remain `reporting`; full-report delivery can
remain pending after its queue row settles, including after V1 summary acceptance.

## Model-based tests

The checked corpus contains 33 traces covering 20 modeled actions. The job
lifecycle replay spec (`specs/DumpAnalyzerReplay.tla`) is connected to the real
state/recovery layer by the handwritten `tests/mbt/harness.rs` adapter via
MirrorRust (the required sibling `../MirrorRust` checkout) and the Mirrors
toolchain:

```sh
MIRROR_BIN=/absolute/path/to/mirror cargo test --offline --locked --test mbt
python3 tools/mbt/gen_traces.py --check    # corpus freshness gate
python3 tools/mbt/gen_traces.py            # explicit corpus regeneration
```

Without `MIRROR_BIN`, the MBT test returns early and the ordinary test run does
not establish replay coverage. Live TLS and Claude tests require their explicit
ignored-test flags and environment prerequisites; see the qualification guide.
This documentation refresh did not run tests or contact live services.

## Server dependencies

DumpLedger's analyzer milestones AI1–AI3 landed at `98e484c` (catalog +
token + ETag, event feed, analysis write-back; see its
`docs/analyzer-guide.md` for the operator-facing contract). Against older
servers without the write-back route, reports are kept in local-verdict mode
(`data/analyzer.sqlite`, `local_reports`) and replayed when the route
appears. Without the event feed, the boot scan still finds work; there is no
periodic full-catalog sweep. Restart or use `POST /-/rescan` to discover later changes.
The rich-report path attempts full v2 delivery first and can fall back to the
v1 compact projection. Summary acceptance is tracked separately from full
evidence delivery; see the rich-report guide before enabling write-back.
