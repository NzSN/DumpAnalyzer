# DumpAnalyzer Rust implementation — fine-grained tasks

Historical task briefs and acceptance receipts for 2026-10-13–14. All task
headings marked ● were accepted in that wave; measured results in
[Stage gates](#stage-gates) are dated evidence, not newly run checks. Source
review on 2026-10-20 used `6a19ea297bb219509c994780c96bdd6ce6c4bfab` and
found the planned modules implemented. No builds, tests or live checks were
run for this documentation update.

Use the [README](../README.md), [architecture](../docs/architecture.md),
[analyzer design](../docs/analyzer-design.md) and
[rich-report guide](../docs/rich-reports.md) for maintained behavior. These
briefs preserve the original interfaces, v1 limits and ownership rules;
later token storage, provider containment, rich-report storage/delivery and
queue behavior supersede parts of those initial instructions. Phase-two
completion is recorded [separately](phase2-live-readiness.md).

Derived from [`rust-implementation-plan.md`](rust-implementation-plan.md).
Execution used delegated `general-purpose-flash` agents; one agent per task,
disjoint file ownership, self-contained briefs (no inherited context).

## Delegation conventions (all tasks)

- Agents receive: repo path, read-first docs, exact owned files, conventions,
  scoped build/test commands, report format.
- **Build discipline**: `cargo build|test --offline --locked` only; never
  plain `cargo build` (network is restricted). Never edit `Cargo.toml`,
  `Cargo.lock`, `src/lib.rs`, `src/main.rs`, `src/types.rs`, or any module
  owned by another task. Never run `cargo fmt` on files outside ownership
  (`cargo fmt --check` globally is fine; `cargo fmt -- <own files>` or
  hand-format to satisfy it).
- Wave gates are run by the integrator: scoped tests, then
  `cargo test --offline --locked`, `cargo clippy --offline --locked
  --all-targets -- -D warnings`, `cargo fmt --check`.
- Report format: files changed, what was delivered per numbered deliverable,
  test evidence (command + tail output), deviations/open issues.
- Status: ☐ pending · ◐ assigned · ● accepted.

## Stage R0 — skeleton (integrator, ● done)

Cargo workspace, approved manifest, `src/types.rs` kernel (`JobPhase`,
`JobIdentity`, `ToolRunner`, `RunRequest/RunOutput/RunBounds`,
`ReportOutcome`, `AnalyzerError` with `is_transient`), module stubs,
Cargo.lock, offline build/test/clippy/fmt verified.

## Wave W1

### A1 — Wire types ●

- **Owns**: `src/wire.rs`, `tests/wire.rs`.
- **Read first**: `docs/analyzer-design.md` §"Server surface consumed";
  `~/Repos/dump-ledger/docs/analyzer-integration-design.md` §§"Dump catalog
  search", "Event feed", "Analysis write-back", "Contracts, limits, and
  errors" for exact field shapes; `src/types.rs`.
- **Deliver**:
  1. Serde types (decode + encode, `#[serde(deny_unknown_fields)]`) for:
     `DumpCatalogEntry` (`dumpId`, `caseId`, `customerId`, `phase`,
     `validation`, `byteSize` decimal-string-or-null, `sha256`
     64-lowercase-hex-or-null, `receivedAt`/`availableAt`/`purgeAt`
     ISO-string-or-null, optional `architecture`, `exceptionCode` (u32),
     `exceptionAddress` decimal string, `symbolCoverage {present, missing,
     unidentified}`), `DumpCatalogResponse { dumps, nextCursor? }`;
     `EventFeedEntry { cursor, eventId, occurredAt, action, customerId?,
     caseId?, dumpId?, detail }` and `EventFeedResponse { events, nextCursor }`;
     `AnalysisReport` (server: `analysisId`, `dumpId`, `analyzer {name,
     version}`, `kind`, `inputSha256`, `createdAt`, `outcome`, `summary`,
     optional `facts`, optional `duplicateOf`) and the POST body
     `AnalysisReportSubmission` (same minus server-assigned fields);
     the error envelope per `~/Repos/dump-ledger/docs/http-api.md` §Errors.
  2. Validating constructors or custom deserializers enforcing: sha256 is 64
     lowercase hex; `summary` ≤ 2000 chars; `kind` 1–64 chars; byte counts
     are decimal strings; cursors ≤ 256 non-whitespace chars. Validation
     failures are `AnalyzerError::Decode`, never panics.
  3. Catalog query-params serializer (optional `caseId`, `customerId`,
     `phase`, `validation`, `receivedAfter`, `receivedBefore`,
     `architecture`, `exceptionCode`, `sha256`, `cursor`).
  4. Tests: round-trip encode→decode identity; rejection of unknown fields,
     wrong types, bound violations, malformed sha256; the design doc's exact
     example shapes as fixtures.
- **Acceptance**: `cargo test --offline --locked wire` green; clippy/fmt
  clean on owned files.

### A2 — Config and secrets ●

- **Owns**: `src/config.rs`, `tests/config.rs`.
- **Read first**: `docs/analyzer-design.md` §§"Module design", "Security";
  `src/types.rs`.
- **Deliver**:
  1. `Config::from_env(iter: impl Iterator<Item = (String, String)>) ->
     Result<Config>` (tests never touch the real environment) plus
     `Config::from_process_env()`.
  2. Variables: `DUMP_ANALYZER_BASE_URL` (required; absolute `https://`,
     parsed via `reqwest::Url`); `DUMP_ANALYZER_TOKEN` (required bearer;
     `SecretToken` newtype whose `Debug`/`Display` redact; exposed only as
     `expose(&self) -> &str`); `DUMP_ANALYZER_STATE_DIR` (default `./data`);
     `DUMP_ANALYZER_NAME` (default `dump-analyzer`), `DUMP_ANALYZER_VERSION`
     (default `env!("CARGO_PKG_VERSION")`); `DUMP_ANALYZER_POLL_INTERVAL_MS`
     (default 10000, allowed 5000–30000); `DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS`
     (default 600000); `DUMP_ANALYZER_MAX_OUTPUT_BYTES` (default 1 MiB);
     `DUMP_ANALYZER_MAX_WORKSPACE_BYTES` (default 2 GiB);
     `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES` (default 10 GiB);
     `DUMP_ANALYZER_SSH_TARGET` (analysis box, e.g. `windows-dev`);
     `DUMP_ANALYZER_SYMBOL_CACHE_DIR` (symcache dir on the analysis box).
  3. Fail-fast `AnalyzerError::Config` on malformed values, listing the
     variable name — but never echoing the token value.
  4. Tests: defaults, each malformed variable, token redaction in
     `format!("{config:?}")`.
- **Acceptance**: `cargo test --offline --locked config` green; clippy/fmt
  clean on owned files.

### A3 — Local state ●

- **Owns**: `src/state.rs`, `tests/state.rs`.
- **Read first**: `docs/analyzer-design.md` §§"Module design", "Correctness
  and idempotency"; `specs/DumpAnalyzer.tla` (job phases); `src/types.rs`.
- **Deliver**:
  1. `Store::open(path) -> Result<Store>` on rusqlite (bundled), with a
     `schema_migrations` table and migration 1 creating:
     `jobs(dump_id TEXT, input_sha256 TEXT, kind TEXT, analyzer_version TEXT,
     phase TEXT, attempts INTEGER NOT NULL DEFAULT 0, workspace_path TEXT,
     created_at TEXT, updated_at TEXT, PRIMARY KEY (dump_id, input_sha256,
     kind, analyzer_version))`;
     `cursors(name TEXT PRIMARY KEY, value TEXT NOT NULL)`;
     `byte_cache(sha256 TEXT PRIMARY KEY, path TEXT NOT NULL, byte_size
     INTEGER NOT NULL, etag TEXT, last_used_at TEXT NOT NULL)`;
     `local_reports(dump_id TEXT, input_sha256 TEXT, kind TEXT,
     analyzer_version TEXT, outcome TEXT NOT NULL, summary TEXT NOT NULL,
     facts_json TEXT NOT NULL, created_at TEXT NOT NULL, posted INTEGER NOT
     NULL DEFAULT 0, PRIMARY KEY (dump_id, input_sha256, kind,
     analyzer_version))`.
  2. `JobStore` API: `upsert_discovered(&JobIdentity) -> Result<bool>`
     (insert-or-ignore; true iff newly inserted), `claim_next() ->
     Result<Option<(JobIdentity, u32)>>` (oldest `discovered`, atomically →
     `claimed`, returning attempts), `set_phase(&JobIdentity, JobPhase)`,
     `record_attempt(&JobIdentity)`, `jobs_in_phase(JobPhase) ->
     Result<Vec<(JobIdentity, u32)>>` (recovery: `reporting` re-submit,
     volatile phases → `claimed`), `drop_job`, phase history is **not**
     kept (the server audit feed is the history).
  3. `CursorStore`: `get(name) -> Result<Option<String>>`,
     `set_monotonic(name, value)` — rejects a lexically smaller cursor with
     `AnalyzerError::State` (cursors are zero-padded rowids; monotonic per
     the spec's `CursorMonotonic`).
  4. `CacheIndex` (upsert/touch/lookup by sha256) and `LocalReportStore`
     (insert-or-ignore, `pending() -> posted = 0`, `mark_posted`).
  5. Tests with `tempfile`: idempotent upsert, claim ordering + phase
     transition, cursor regression rejected, recovery queries, opening an
     existing database re-runs no migration.
- **Acceptance**: `cargo test --offline --locked state` green; clippy/fmt
  clean on owned files.

### C2 — Tool runner ●

- **Owns**: `src/runner.rs`, `tests/runner.rs`, `tests/fixtures/cdb/`.
- **Read first**: `docs/analyzer-design.md` §§"Agent pipeline", "Security";
  `src/types.rs` (`ToolRunner`, `RunRequest`, `RunOutput`, `RunBounds`).
- **Deliver**:
  1. An `ExecTransport` seam (owned here): `async fn exec(&self, program:
     &str, args: &[&str], stdin: Option<&[u8]>, timeout: Duration) ->
     Result<TransportOutput>` plus `async fn put_file(&self, local: &Path,
     remote: &str) -> Result<()>`; the SSH/scp implementation uses
     `tokio::process::Command` with the configured target; a fake transport
     lives in the tests.
  2. `SshCdbRunner: ToolRunner`: stages the dump to the analysis box, writes
     a bounded triage CDB script (`.sympath` with the DumpLedger symsrv
     store, `.reload`, `!analyze -v` is out of scope — v1: `.ecxr`, `kc`,
     `lm`, `|`), runs CDB with `RunBounds` enforced (wall-timeout kill,
     output truncated at `max_output_bytes`, workspace size checked), and
     returns the bounded raw log through the parser.
  3. `parse_triage(log: &str) -> Result<RunOutput>`: extracts exception code
     and address, faulting module, bounded top frames, per-module symbol
     load status; classifies `ReportOutcome::Failed` (a verdict) when CDB
     cannot open the dump or the log shows corruption — versus transport/
     timeout failures which are `Err(AnalyzerError::Runner(_))`.
  4. Tests: parser against 3 authored fixture logs under
     `tests/fixtures/cdb/` (clean analysis; bad/missing symbols; corrupt
     dump), output-cap truncation, timeout mapping; the SSH transport is
     exercised only through the fake — no live SSH in tests.
- **Acceptance**: `cargo test --offline --locked runner` green; clippy/fmt
  clean on owned files.

## Wave W2

### B1 — Ledger client ●

- **Owns**: `src/client.rs`, `tests/client.rs`.
- **Depends on**: A1 (wire types), A2 (config).
- **Read first**: `docs/analyzer-design.md` §§"Server surface consumed",
  "Security"; `~/Repos/dump-ledger/docs/http-api.md` (authentication, error
  envelope); `src/types.rs`, `src/wire.rs`, `src/config.rs`.
- **Deliver**:
  1. `LedgerClient::new(&Config) -> Result<LedgerClient>` (reqwest, rustls,
     bearer token from the redacted config; token never logged, never in
     error messages, never in URLs).
  2. Methods: `get_dumps(params, cursor) -> Result<DumpCatalogResponse>`,
     `get_dump_by_sha256(sha) -> Result<Vec<DumpCatalogEntry>>`,
     `get_dump(dump_id) -> Result<DumpCatalogEntry>` (detail shape per
     http-api.md; reuse wire types),
     `get_content(dump_id, etag: Option<&str>) -> Result<ContentResult>`
     where `ContentResult` is `NotModified` or `Bytes { bytes: Vec<u8>,
     etag: String }`,
     `get_events(since, actions, case_id, limit) -> Result<EventFeedResponse>`,
     `post_analysis(&AnalysisReportSubmission) ->
     Result<PostAnalysisResult>` (`Created` on 201, `Replayed` on 200),
     `get_analyses(dump_id) -> Result<Vec<AnalysisReport>>`.
  3. Error mapping: non-2xx → `AnalyzerError::Server { status, code }` with
     the envelope's `code` when decodable; connect/timeout → `Transport`;
     body decode failure → `Decode`. 401/403/404 are never retried by the
     caller-side classification (`is_transient` already encodes this).
  4. wiremock tests: happy paths with exact request assertions (path, query,
     `Authorization: Bearer`, `If-None-Match`), 304 → `NotModified`, 401,
     404, malformed JSON, 200-replay on POST.
- **Acceptance**: `cargo test --offline --locked client` green; clippy/fmt
  clean on owned files.

## Wave W3

### B2 — Catalog sync and event follower ●

- **Owns**: `src/sync.rs`, `tests/sync.rs`.
- **Depends on**: B1 (client), A3 (state).
- **Read first**: `docs/analyzer-design.md` §§"Module design", "Correctness
  and idempotency"; `specs/DumpAnalyzer.tla` (Discover, Purge, FollowFeed).
- **Deliver**:
  1. `initial_scan(client, store) -> Result<u64>`: keyset-paginated
     `get_dumps`, upserting one `JobIdentity` per dump whose `phase` is
     `available` and whose `sha256` is present (kind `triage`, configured
     analyzer version); returns jobs inserted.
  2. `follow_feed(client, store, poll_interval)`: loop over
     `get_events(since)`; apply idempotently (intake/seal actions with a
     `dumpId` → `upsert_discovered`; purge/delete actions → `drop_job`;
     everything else ignored), then `set_monotonic("event_cursor",
     nextCursor)`; empty page with unchanged cursor is the sleep signal.
     Shutdown via `tokio::select!` on a cancellation token.
  3. Tests (wiremock + real `tempfile` store): gapless multi-page scan,
     interleaved insert between pages not double-scheduled, purge event
     drops the job, cursor regression impossible, duplicate event replay
     idempotent.
- **Acceptance**: `cargo test --offline --locked sync` green; clippy/fmt
  clean on owned files.

### C1 — Agent pipeline ●

- **Owns**: `src/agent.rs`, `tests/agent.rs`.
- **Depends on**: A3 (state), B1 (client). Talks to `types::ToolRunner`
  only — never to `runner` internals.
- **Read first**: `docs/analyzer-design.md` §"Agent pipeline";
  `specs/DumpAnalyzer.tla` (the whole lifecycle); `src/types.rs`,
  `src/state.rs`, `src/client.rs`.
- **Deliver**:
  1. `Agent::run_job(identity) -> Result<()>` implementing the spec's stage
     machine with `set_phase` persisted at every entry: `claimed → fetching
     → staged → analyzing → reporting` and terminal `done`/`dropped`/
     `failed`.
  2. Fetch stage: byte-cache lookup by sha256 → ETag-conditional
     `get_content`; on `NotModified` reuse cached bytes; on `Bytes` write to
     cache and index. sha256 of the staged file is recomputed and compared
     to the job pin: mismatch → `record_attempt` + refetch (bounded by
     `MaxAttempts`-equivalent config constant, default 2), exhausted →
     `failed`. 404 → `dropped`.
  3. Analysis stage: per-run workspace via `tempfile` under the state dir,
     symbol path assembled from config (base URL → `SRV*<cache>*<base>/symbols`),
     `ToolRunner::run` with `RunBounds`; `RunOutput` → hand to the verdict
     writer (D1's API, used via a small owned-here seam function the
     integrator wires in D2); `AnalyzerError::Runner` → `record_attempt` +
     `claimed`; exhausted → `failed`.
  4. Crash recovery: `recover(store)` — volatile phases → `claimed`,
     `reporting` left for the verdict writer's reconciliation; matches the
     spec's `Crash`/`CrashReset`.
  5. Tests with a fake `ToolRunner` and wiremock client: full happy path,
     hash-mismatch refetch, 404 drop, runner failure retry then `failed`,
     recovery transitions.
- **Acceptance**: `cargo test --offline --locked agent` green; clippy/fmt
  clean on owned files.

### D1 — Verdict writer ●

- **Owns**: `src/verdict.rs`, `tests/verdict.rs`.
- **Depends on**: A1 (wire), A3 (state), B1 (client).
- **Read first**: `docs/analyzer-design.md` §§"Agent pipeline", "Correctness
  and idempotency"; `~/Repos/dump-ledger/docs/analyzer-integration-design.md`
  §"Analysis write-back"; `src/wire.rs`, `src/state.rs`, `src/client.rs`.
- **Deliver**:
  1. `assemble(identity, output: RunOutput, config) ->
     Result<AnalysisReportSubmission>`: `summary` ≤ 2000 chars
     (truncate-with-marker, never mid-codepoint); whole body must fit the
     server's 16 KiB JSON envelope (`facts` shrunk by dropping lowest-value
     keys, else `AnalyzerError::Integrity`).
  2. `submit(client, store, identity) -> Result<()>`: `Created`/`Replayed` →
     `done`; 404 on the dump → `dropped`; 404 on the *route* (pre-AI3
     server) → **local-verdict mode**: insert into `local_reports`
     (`posted = 0`) and settle `done`; `invalid_request` on sha mismatch →
     `failed` (a bug signal, loudly logged); transient → caller's retry
     budget.
  3. `reconcile_on_boot(client, store) -> Result<ReconcileReport>`:
     `reporting` jobs → `get_analyses(dump_id)` → identity present → `done`,
     absent → re-assemble from `local_reports` if present else re-POST from
     stored output metadata; `pending()` local reports → replay sweep.
  4. Tests (wiremock + tempfile store): 201, 200 replay, dump-404 drop,
     route-404 local mode + later replay when the route appears, sha-mismatch
     400 → `failed`, reconciliation both directions.
- **Acceptance**: `cargo test --offline --locked verdict` green; clippy/fmt
  clean on owned files.

## Wave W4

### D2 — Scheduler and daemon ●

- **Owns**: `src/scheduler.rs`, `src/main.rs`, `tests/daemon.rs`.
- **Depends on**: all above.
- **Read first**: everything above plus `src/lib.rs`.
- **Deliver**:
  1. `Scheduler`: claim → `Agent::run_job` → verdict submit loop,
     concurrency 1, transient-error backoff (bounded, e.g. 1s → 30s cap),
     no busy spin when no work (poll cadence).
  2. `main.rs`: `Config::from_process_env`, tracing init (`env-filter`,
     default `info`), single-instance lock (`create_new` lockfile under the
     state dir, fail-fast if held, remove on exit), `Agent::recover` +
     `verdict::reconcile_on_boot`, then sync follower + scheduler under
     `tokio::select!` with SIGTERM/SIGINT graceful shutdown.
  3. `tests/daemon.rs` end-to-end against a wiremock DumpLedger and a fake
     `ToolRunner`: two dumps complete, a purge mid-run drops one job, a
     second process start with a held lock fails fast.
- **Acceptance**: full `cargo test --offline --locked` green; clippy/fmt
  clean; integrator runs the wave gate.

### E1 — Documentation (integrator or delegated, after D2) ●

- README.md (setup, env vars, run, evidence boundary), CONTEXT.md (design
  vocabulary), design-doc status flip.

## Stage gates

| Gate | Command | Result |
|---|---|---|
| R0 | offline build/test/clippy/fmt | ● green (integrator, 2026-10-13) |
| W1 | scoped tests A1/A2/A3/C2 | ● green 2026-10-13 (102 tests: wire 45, config 19, runner 22, state 16; clippy+fmt clean; types.rs Runner→transient fix by integrator; A1 followed up with DumpDetail + catalog.ts-exact tightening) |
| W2 | `cargo test --offline --locked client` | ● green 2026-10-13 (136 total: wire 51 incl. events bounds, client 28 incl. timeouts, config 19, runner 22, state 16; clippy+fmt clean; note: wiremock tests need loopback binds, gate runs escalated) |
| W3 | `cargo test --offline --locked` (sync/agent/verdict) | ● green 2026-10-13 (174 tests across 9 targets + lib, 0 failed; clippy+fmt clean; design-doc cursor-order line corrected to apply-then-persist) |
| W4 | full `cargo test --offline --locked` + clippy + fmt | ● green 2026-10-13 (181 tests, 0 failed; clippy+fmt clean; binary boots to fail-fast config error) E1 done by integrator (README.md, CONTEXT.md) |
| M1 | MirrorRust MBT (spec corpus → replay via `mirror`) | ● green 2026-10-13 (33 traces covering all 20 actions; TLC 1,621,239 states / 428,704 distinct / depth 33 clean; Apalache length-10 clean for PinnedReport; mutant sanity: injected attempts+1 produced a StepMismatch with the exact path) |
| U1 | Status UI (read-only loopback dashboard + JSON API, `src/http.rs`) | ● green 2026-10-13 (integrator-implemented; 191 tests total incl. http integration + config parsing; clippy+fmt clean) |
| P1 | `claude-cdb` tool-runner provider (claude CLI drives CDB; `--restricted` + schema-forced output) | ● green 2026-10-13 (integrator-implemented; config selector + runner + 6 provider tests + 3 config tests; full gate 200 tests, clippy+fmt clean) |
| O1 | On-demand `Analyzer` component (`f : DumpId -> IO Report`) + token-guarded `POST /-/analyze` (+browser form) | ● green 2026-10-13 (integrator; 6 component tests + 4 HTTP tests; full gate 211, clippy+fmt clean) |
| U2 | Contextual actions on the dashboard (per-phase Re-analyze form, running state, unwired note) | ● green 2026-10-13 (integrator; 2 new HTTP tests; full gate 213, clippy+fmt clean) |
| X1 | Server-contract alignment after dump-ledger `98e484c` (AI1–AI3 landed): facts 4 KiB UTF-8 budget, detail UTF-8 bytes, analyzer name/version bounds, 409 documented | ● green 2026-10-14 (218 tests, clippy+fmt clean) |
