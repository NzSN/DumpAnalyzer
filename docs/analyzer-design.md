# DumpAnalyzer design

Status: implemented v0.2.0, reviewed against source baseline
`6a19ea297bb219509c994780c96bdd6ce6c4bfab` on 2026-10-20. This is the
consumer design; DumpLedger owns the catalog, vault, symbol store and server
analysis contracts. Deployment receipts and test results are dated evidence,
not guarantees about a running service.

Use [README](../README.md) for setup and commands,
[architecture](architecture.md) for flow diagrams,
[rich reports](rich-reports.md) for evidence and delivery details, and
[CONTEXT.md](../CONTEXT.md) for domain vocabulary.

## Purpose and boundaries

DumpAnalyzer discovers available Windows dumps, verifies their bytes, runs CDB
on a designated Windows analysis host over SSH, and retains reports locally.
When enabled, write-back publishes them to DumpLedger. Analysis never executes
inside DumpLedger. The only implemented analysis kind is `triage`.

The Rust daemon includes a loopback HTTP dashboard with Queue, Dumps, Reports
and Settings panels, manual dump/case/customer analysis, token storage, and
catalog rescan. Browsing never starts analysis. The HTTP surface is optional;
its failure is logged without stopping the pipeline.

The two providers share deterministic capture. `cdb-ssh` returns its assessment;
`claude-cdb` additionally asks a local Claude CLI host to assess bounded captured
evidence. Claude does not drive CDB or receive tools. Neither provider ingests
symbols into DumpLedger. Full canonical evidence is durable local data, rather
than a transient workspace artifact or only the compact server verdict.

## Vocabulary and identity

| Term | Meaning |
|---|---|
| Analysis job | Durable scheduling identity `(dumpId, inputSha256, kind, analyzerVersion)` |
| Agent | Shared pipeline driver owning fetch, verification and per-run local workspace |
| Run | One execution of that pipeline; transient errors can consume another attempt |
| Tool runner | Windows CDB transport/capture seam, with optional evidence-only reasoning |
| Workspace | Per-run local staging directory plus a separate remote CDB directory |
| Byte cache | Bounded local content-addressed dump bytes, revalidated with ETag and hash |
| Feed cursor | Durable monotonic event position, persisted after page application |
| Canonical report | `CrashReportV2` with identity, evidence, assessment, report ID and digest |
| Compact projection | Bounded v1-compatible summary derived from the canonical report |

Server report identity also includes `analyzer.name`. Local job keys omit that
name: a state directory should retain one analyzer attribution. Manual reuse
checks the stored canonical name and rejects a conflicting name. Choose a
distinct version for a changed capture profile instead of overwriting evidence.
The package default is `0.2.0`; configuration rejects legacy version `0.1.0`.

## Deployment and module ownership

```text
DumpAnalyzer (Rust, local SQLite/cache/dashboard)
  | HTTPS: catalog, feed, content, analysis publication
  v
DumpLedger (vault/catalog + symbol service)
  ^
  | symsrv lookup from CDB; credential-free symbol path
Windows analysis host (CDB), reached by DumpAnalyzer over SSH/SCP
```

The daemon needs a DumpLedger URL and an environment or previously stored
analyzer token, SSH/SCP access to the Windows host, and CDB on that host.
Remote ledger URLs require HTTPS; HTTP is accepted only for loopback development
stubs. `DUMP_ANALYZER_TLS_CA_CERT` adds PEM trust without disabling validation.
The Windows host separately needs trust/connectivity for symsrv. Use a native
Windows symbol-cache path such as `C:\symcache`; double backslashes in a
systemd `EnvironmentFile`. See the [dated deployment receipt](local-deployment-2026-10-15.md)
for that environment's checkpoint and rollback, not a portable provisioning recipe.

| Source | Responsibility |
|---|---|
| [config.rs](../src/config.rs), [main.rs](../src/main.rs) | Validated configuration, provider wiring and process exit behavior |
| [client.rs](../src/client.rs), [wire.rs](../src/wire.rs) | Typed ledger requests, token handling and contract validation |
| [sync.rs](../src/sync.rs) | Boot/manual catalog scan and event-feed application |
| [scheduler.rs](../src/scheduler.rs) | State lock, recovery, configured-version claims, feed supervision and delivery loop |
| [agent.rs](../src/agent.rs) | Fetch/cache verification, workspace lifecycle, execution and retry classification |
| [runner.rs](../src/runner.rs), [symbols.rs](../src/symbols.rs) | CDB capture/refinement and independent module/PDB identity evidence |
| [claude_runner.rs](../src/claude_runner.rs), [assessment.rs](../src/assessment.rs) | Isolated evidence-only reasoning and deterministic assessment fallback |
| [report.rs](../src/report.rs), [verdict.rs](../src/verdict.rs) | Canonical report, compact projection, publication and reconciliation |
| [state.rs](../src/state.rs) | SQLite migrations, jobs, settled identities, cursors, secrets, cache and reports |
| [analyzer.rs](../src/analyzer.rs) | Synchronous manual `DumpId -> IO Report` capability and scope batches |
| [http.rs](../src/http.rs), [explorer.rs](../src/explorer.rs), [dashboard.html](../src/dashboard.html) | Local actions, paged catalog/report views and UI |

The state directory is authoritative for local evidence and credentials. It is
not a disposable catalog index: deleting `analyzer.sqlite` loses canonical
reports, legacy history, pending delivery, settled markers, cursor and token.
Back up the stopped service's state before a migration or rollback; restore the
matching database and binary checkpoint together when following a dated receipt.
Never open or modify DumpLedger's own database from this process.

## Discovery, scheduling and recovery

Boot acquires `analyzer.lock` using exclusive file creation, opens/migrates
SQLite, and resolves the token (environment wins and is stored; otherwise the
stored token is required). It resets volatile execution phases to `claimed`,
retires execution rows from other analyzer versions, reconciles report delivery,
and sweeps orphaned local `run-*` workspaces before the initial catalog scan.
Reporting work from earlier versions is preserved for delivery. The lock guards
one state directory; it does not coordinate separate hosts or state directories.

After the boot scan, the event feed, scheduler and delivery replay run
independently. The scan is not a periodic full-catalog sweep. A missing event
route permits scan-only operation: later changes require restart or manual
`POST /-/rescan`. Transient scan/feed failures use capped 1–30 second backoff;
non-transient contract/auth/state failures can stop the daemon. Feed page
application precedes cursor persistence, so interrupted pages replay idempotently.

The automatic scheduler claims only the configured version, resumes its
recovered claims, and runs one scheduled job at a time. That is not a global
concurrency limit: manual requests can overlap scheduled or other manual work.
Duplicate concurrent manual execution of one identity is rejected within the
manual analyzer registry. A scope request gathers at most 64 available dumps
and executes them sequentially, recording per-dump failures as skips.

`DUMP_ANALYZER_SCHEDULER=off` disables claiming while scan, feed, UI and manual
analysis remain active. `DUMP_ANALYZER_WRITE_BACK=off` disables server submission
and delivery reconciliation, settling reports locally. With write-back enabled,
pending report replay runs every 60 seconds, even while automatic execution is
disabled or busy. SIGTERM/SIGINT cancels the loops; the scheduler drains its
current bounded run before exiting. This is distinct from crash recovery.

## Capture and report handoff

Scheduled execution follows persisted phases
`claimed -> fetching -> staged -> analyzing -> reporting`. Hash verification
must succeed before analysis. A corrupt cache entry is discarded and re-fetched
within the retry budget. The agent allows at most two attempts; transient
transport/runner failures consume that budget, while terminal errors settle the
job. A report with outcome `failed` is a captured result, distinct from an
infrastructure error that prevented capture.

The deterministic collector captures essential exception/context and preliminary
stack evidence before optional symbol refinement. Refinement failure or timeout
preserves the baseline with explicit limitations. Successful refinement can
upgrade a failed preliminary result to `completed` when the refined capture
qualifies. Loaded-PDB quality uses dump CodeView and independent PDB Info-stream
GUID/age evidence: a debugger `(pdb symbols)` label alone does not establish a
match. Probe omissions and stack/module truncation remain visible limitations.

`claude-cdb` first runs that collector, reserving a portion of the shared wall
budget for optional reasoning. Its isolated host disables tools and MCP servers
and denies every tool request. Malformed output, unavailable reasoning or a
reasoning timeout preserves readable deterministic evidence/assessment and an
omission. The assessment distinguishes immediate mechanism from underlying
cause; captured evidence does not automatically establish original-incident
attribution. See [rich reports](rich-reports.md) for claim qualification rules.

`verdict::prepare_report` constructs and validates the canonical document and
its compact projection. SQLite commits canonical evidence, digest, projection
and applicable job handoff together before publication. It rejects incompatible
replacement under an occupied identity. The v1 projection is a compatibility
view; it is not the complete evidence store.

Terminal jobs move atomically from `jobs` to `settled_jobs`; reports survive
independently. Settled identities suppress rediscovery. Queue views include
claimed/running/reporting work, while discovered candidates and completed dumps
remain browseable through the catalog explorer. Manual executions have transient
active records that clear on completion, failure or cancellation.

## Manual reuse and fresh capture

`PipelineAnalyzer::analyze` first resolves detail and requires `available` with
a sealed hash. For that identity, an existing canonical report with matching
analyzer attribution returns its compact projection without another CDB run.
An existing legacy compact report blocks replacement and asks for a distinct
version. Changing `DUMP_ANALYZER_VERSION` and restarting creates a fresh capture
identity; pressing Analyze or Rescan does not force evidence replacement.

Manual execution shares `Agent::attempt`, with the same two-attempt budget but
no durable attempt counter or intermediate phases. It saves report and handoff
transactionally; pending delivery can remain `reporting`, while local-only
completion settles immediately. A manual completion preserves active scheduled
execution and settled identities. Scope actions apply the same reuse rules.

## Publication and restart reconciliation

Full v2 publication is attempted before legacy v1 submission. Missing/unsupported
v2 routes permit a digest-bound compact fallback. Acceptance of that fallback is
`summaryOnly`, separately tracked from `fullyDelivered`: the replay path can
later promote full evidence when the route appears. Missing write-back support
retains local verdicts for later replay. Invalid/conflicting/purged submissions
can abandon full delivery; transient failures retain pending work. Local report
history is not removed merely because its server dump is purged.

On restart, reporting jobs reconcile against server analyses or repost durable
reports. A reporting row without a durable report can return to discovery;
volatile capture phases restart with byte verification and retained attempt
counts. With write-back off, reporting rows with evidence settle locally and
reportless rows return to discovery. Server-side idempotency is scoped to the
full server identity; local transactional storage and dedup avoid unnecessary
runs but do not make remote execution exactly once.

Consumed surfaces are catalog/customer/case/detail reads, conditional content
GETs, events, symsrv and analysis read/write routes. The typed client also
exposes by-hash lookup; automatic sync does not currently use it as an upstream
duplicate gate. Protocol budgets and rich endpoint compatibility are documented
in [rich reports](rich-reports.md) and enforced in client/wire/report code.

## HTTP trust and execution bounds

The default listener is `127.0.0.1:4180`; an empty `DUMP_ANALYZER_HTTP_ADDR`
disables it. Read endpoints have no authentication. For action routes, a
explicit bearer must digest-match; absent authorization or an empty form token
uses the configured token when one exists. An empty bearer header is rejected.
This fallback checks credential
availability, not caller identity. Browser forms intentionally use it. Token
storage probes a candidate against DumpLedger and updates the UI digest live;
existing pipeline clients pick up the replacement after restart. Protect the
listener boundary before exposing it beyond trusted local callers.

The token is plaintext in SQLite, redacted by `SecretToken` formatting and
excluded from symbol paths. Protect state and backups as sensitive dump-derived
data. Reports contain bounded excerpts and metadata; avoid treating them as
non-sensitive just because the original dump is not served by the dashboard.

Default configured bounds are 10 minutes of runner wall time, 1 MiB captured
output, 2 GiB workspace allowance and 10 GiB byte cache. Runner deadlines cover
local staging/execution waits; remote cleanup has a separate two-second
best-effort grace. Local SSH/SCP/Claude children are terminated on cancellation
or applicable bounds. Killing SSH does not prove remote CDB termination.
Workspace checks are not a continuous remote disk quota, and cleanup is not a
guarantee that every remote artifact was removed. These are resource controls,
not a sandbox or an overall HTTP/request deadline.

## Validation and proof boundary

The repository's tests include wiremock HTTP contracts, state migrations and
transaction integrity, fetch/hash/cache paths, runner parsing and containment,
reasoning fallback, manual lifecycle, report delivery compatibility and UI
escaping/pagination. Test presence is static evidence of intended coverage;
this documentation refresh ran no Rust tests, remote commands or live probes.

The historical 2026-10-13 lifecycle check recorded 1,621,239 TLC-generated
states, 428,704 distinct states and depth 33 without invariant violation, and
no Apalache counterexample through length 10 for `PinnedReport`. These bounded
results describe that model revision, not formal verification of the current
application. The model abstracts HTTP, hashing and debugger behavior and does
not prove liveness, rich-report delivery or provider containment.

The checked MBT corpus has 33 traces covering 20 lifecycle actions. The
handwritten [harness](../tests/mbt/harness.rs) connects modeled transitions to
real state/recovery operations and a scripted server boundary. It is not a
model-generated implementation or a proof of HTTP/toolchain execution.
[tests/mbt.rs](../tests/mbt.rs) returns early when `MIRROR_BIN` is absent;
ordinary `cargo test` success alone does not establish replay coverage. Use the
explicit MBT and corpus-freshness commands in [README](../README.md).

Dated qualification reports in [rich reports](rich-reports.md),
[field run](../Plans/field-run.md) and [readiness](../Plans/phase2-live-readiness.md)
retain their historical counts, fixtures and live gates. Runtime TLS trust,
Windows CDB/PDB availability, corrected live Claude qualification and companion
v2 availability require their own environment checks. Do not infer those passes
from a documentation-only review.
