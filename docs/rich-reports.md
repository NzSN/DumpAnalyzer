# Rich reports and operator workflow

The supported providers are `cdb-ssh` and `dsh-http`. The `claude-cdb` provider
and its live test have been removed; dated qualification sections below
describe the former implementation.

Source revision: `6a19ea297bb219509c994780c96bdd6ce6c4bfab`, inspected 2026-10-20. The implementation sections describe that source review, which made no live debugger, model or service calls. A later, explicitly authorized [2026-10-20 qualification](qualification/live-reasoner-2026-10-20/README.md) at checkout `f269ce82d2ac28e9ba77f7f393ffc231e639a164` passed the configured CLI/gateway reasoner subgate. Its CLI-reported model was `deepseek-flash`; this is not an Anthropic Claude model qualification. The separate 2026-10-15 qualification and deployment receipts remain historical evidence and do not establish the current deployed binary or service state.

The [2026-10-20 production rollout checkpoint](qualification/production-rollout-2026-10-20/README.md) records completed analyzer/companion deployment and preserved databases. After the user explicitly approved the exact selected report and destination, the [production canary](qualification/production-canary-2026-10-20/README.md) passed publication, idempotent replay, exact readback, publisher-store reopen and native backend restart durability. **P6 production rollout and the bounded selected-report canary are complete at this checkpoint.** Global scheduling and write-back remain off. The earlier rejected action did not publish a report, and its dated receipt remains unchanged.

## Report path

```text
verified dump bytes → offline essential CDB pass → optional symbol CDB pass
                                               ↓
                                  deterministic assessment
                                               ↓
                    optional DSH assessment: evidence-only narrative / hypotheses
                                               ↓
                         canonical CrashReportV2 + SHA-256 digest
                                               ↓
                SQLite transaction: full detail + compact row + phase handoff
                              ↙                              ↘
                   lazy report detail                  publication outbox
                                                       v2 full report
                                                       v1 bound summary fallback
```

The canonical report contains exception record/context, address-bearing native stack, module/PDB qualification, causal assessment, retained command excerpts and explicit completeness limits. Addresses and exception parameters are hexadecimal strings. The CDB parser targets native Windows x64. With Forensicator configured, the DSH reasoner can request `forensicator_javascript_stack` to recover physical JavaScript and optimized JIT frames from captured V8 metadata. Its bounded observations stay in retained evidence and render in a separate JavaScript frame table; they do not replace the native stack or change the canonical report schema. Inlined logical frames, asynchronous ancestry and managed stacks are not reconstructed. Source lines identify function starts, not exact executing statements. See [Forensicator recovery and limits](dsh-http-guide.md#forensicator-mcp-tools).

### Two-pass collection and quality

The production SSH runner first starts CDB with a symbol path pointing only at its per-run workspace. This essential pass captures target information, `.exr -1`, `.ecxr` and registers, instructions, a preliminary numbered native stack, and the initial module list. It supplies no HTTP symbol store. Once that structured evidence is owned, a second CDB process may load symbols, collect detailed modules and obtain a final numbered stack within the remaining deadline and shared transcript budget. See [the collector and merge](../src/runner.rs) (`analyze`, `essential_script`, `refine_symbols`).

Successful refinement merges its module/stack evidence while retaining the essential exception and context. If the offline baseline was `failed` and the refinement parses the same dump as `completed`, the runner upgrades the outcome to `completed`: missing symbols in the essential pass can reflect collection order. This is conditional on a parsed refinement with structured capture; it does not turn a corrupt/unopenable dump into a successful analysis by assumption.

Refinement failure, timeout, an exhausted output budget or missing structured refinement preserves the essential capture and its existing outcome. The report records completeness omissions, a preliminary-stack limitation and a `symbols-load` evidence status such as `failed`, `timedOut` or `truncated`. Capture status, symbol identity quality and report outcome are separate fields. A usable report can therefore retain raw addresses and a checked immediate mechanism while symbols or reasoning remain incomplete. An essential acquisition that fails before usable evidence can still return a runner error.

Deterministic collection precedes reasoning. The underlying cause can be `unknown` even when the immediate fault mechanism is `confirmed`. The first mechanism rule verifies a simple register-indirect MOV read against the saved exception address, operation, registers and faulting instruction. It does not establish pointer lifetime, corruption origin or source ownership. No confirmed-origin rule is currently implemented. A model cannot create one by supplying valid citations or a rule name.

The optional `dsh-http` provider uses the same deterministic collector, then a dedicated DSH HTTP adapter for bounded reasoning. The default profile has no tools; optional bounded MCP investigation is described in the [DSH guide](dsh-http-guide.md). Model, transport, timeout or validation failure retains the deterministic report and records the missing reasoning stage. Model output cannot replace the captured exception, context, stack, symbols or checked mechanism.

## Identity and preservation

Local staging, both CDB passes, stream reads, PDB identity probes and child reaping share a deadline; cleanup has a separate two-second grace. Per-stream SSH reads use the smaller transport/request cap before the combined transcript is reduced to the per-run budget. Killing the local SSH client does not prove that a remote CDB process or its children terminated; the inspected implementation does not implement a Windows Job Object supervisor.

The default analyzer version is `0.2.0`. `DUMP_ANALYZER_VERSION=0.1.0` is rejected because that identity belongs to legacy compact capture. Use a distinct version for intentional new evidence or a changed analysis profile. Discovery, manual requests and explorer overlays share this configured version. Automatic claims are restricted to that version; obsolete active executions other than `Reporting` are archived `Dropped` at boot, while historical reports and pending legacy delivery remain intact. Old discovered inventory is not claimed by the current-version scheduler.

Report IDs are `r2_` plus SHA-256 over length-prefixed dump ID, input SHA-256, kind, analyzer name and analyzer version. The JSON digest hashes UTF-8 canonical JSON, with recursively sorted object keys. Delivery transmits the exact JSON string so JavaScript and Rust do not disagree about reserialization. Delivery metadata is stored outside the immutable document.

Migration 4 adds report detail storage and stable list IDs without replacing jobs, cursors, secrets, cache indexes or old reports. The code constructs and validates the canonical report, derives the compact submission from it, then commits full JSON, digest, compact row and eligible `Reporting` handoff in one transaction. Different evidence under the same immutable identity is an explicit conflict. After confirming that the catalog dump is available and sealed, a manual request returns the existing rich report projection under the same identity before registering a new run. It refuses to replace a legacy compact report under that identity; choose a new analyzer version for rich reanalysis. An existing rich report attributed to another analyzer name is also an integrity conflict. Late completion preserves a concurrent purge or terminal settlement.

Dump bytes remain in the filesystem cache. Structured evidence is owned by the report before workspaces are wiped. The implementation retains bounded command excerpts in canonical JSON; it does not promise a durable complete raw-transcript artifact. Locally retained reports survive a catalog purge, matching the previous local report policy; remote publication is abandoned when the dump is gone. Companion details cascade when the remote analysis row is purged.

| Limit | Value / behavior |
| --- | --- |
| Canonical JSON | 512 KiB; invalid oversized documents are rejected explicitly. |
| Native stack | 128 frames with declared truncation. |
| Detailed modules | 64. A symbol-looking function name is insufficient for matching. |
| Evidence excerpts | Up to 32 entries, 8 KiB UTF-8 text per entry; truncation is explicit. |
| Transcript acquisition ceiling | 4 MiB maximum retained by the report acquisition policy; the configured run output bound can be smaller. |
| Legacy projection | Summary up to 2,000 characters, facts 4 KiB, v1 body 16 KiB. Schema, report ID and digest are reserved fields. |
| V2 request | 1 MiB route-specific envelope bound. V1 limits remain unchanged. |

Expected PDB GUID/age come from the dump's RSDS data. Loaded PDB GUID/age are read independently from the actual loaded file. Only equality qualifies `matched`; unreadable identity remains `unverified`, and mismatches never gain source/symbol qualification. Exports, missing PDBs and unwind reliability are separate states. Source labels carry the module's qualification and are not a claim that a local source checkout was verified.

## Local interfaces and UI

`GET /api/reports` remains a bounded summary page. Rows add `reportId`, `schemaVersion`, `detailAvailable` and `fullDelivery`; SQL does not load canonical JSON or legacy facts for list rows.

`GET /api/reports/:reportId` returns one detail wrapper (the nested canonical report is abbreviated here):

```json
{
  "reportId": "r2_…", "schemaVersion": 2, "detailAvailable": true,
  "fullDelivery": "localOnly", "digest": "…",
  "report": {
    "schemaVersion": 2,
    "exception": {}, "context": {}, "stack": {}, "rootCause": {}
  },
  "legacy": null, "warning": null
}
```

`GET /api/reports/:reportId/evidence/:evidenceId` selects a retained excerpt. Detail and excerpt reads use the dashboard's existing local-viewer read policy: anonymous, with a loopback listener by default. Report IDs are locators, not access credentials. Deployments exposing this listener must supply their intended viewer access controls; this feature does not add a new caller-authentication scheme.

Details opens `#reports?reportId=…` with the prior page and filters retained. It fetches on selection, uses a small bounded cache and pauses list polling while inspecting a report. The view shows conclusion/quality, exception and registers/instructions, frames with symbol/unwind quality, module evidence and command excerpts. All debugger/model text is escaped. JSON download exports the selected detail without another full-list request.

Legacy reports show **Legacy report — detailed sections were not captured**. Their surviving summary/facts remain readable. Reanalysis under a new version is necessary to obtain missing evidence; history is not upgraded by inventing fields.

## Full delivery and compatibility

| State | Meaning |
| --- | --- |
| `localOnly` | Full report is retained locally; publication was disabled. |
| `pendingFull` | Full report awaits a v2 acknowledgement. |
| `summaryOnly` | An older server accepted the digest-bound v1 summary; full detail remains outstanding. |
| `fullyDelivered` | V2 acknowledged the exact full JSON, digest and compact metadata. |
| `abandoned` | The report cannot attach remotely, for example after purge or permanent rejection. Local evidence remains. |

The legacy `posted` flag continues to support old reports; it is not proof of full delivery. The independent full outbox scans identity metadata and loads one document at a time. With write-back enabled, boot reconciliation and a separate 60-second delivery loop visit durable pending reports even when automatic analysis is disabled or busy. With write-back disabled, reporting jobs settle locally and the delivery loop makes no publication attempts. Summary acceptance never suppresses later full delivery. Queue settlement remains separate from delivery completeness, so old-server compatibility does not leave a phantom running analysis.

The rich-report companion protocol uses authenticated `GET /api/v2/capabilities`, `POST /api/v2/dumps/:dumpId/analyses` and lazy `GET /api/v2/dumps/:dumpId/analyses/:analysisId`. A v2 submission adds `reportJson` and `reportDigest` to the existing compact submission. A response echoes the compact stored analysis and both full-detail fields. The analyzer validates that acknowledgement before marking full delivery.

Equal identity/content replays. Conflicting content rejects with 409. A v1 summary may be promoted atomically under its existing analysis ID only if its metadata and reserved digest/ID binding match; an unbound legacy summary cannot be promoted by assumption. The companion's old transfer format cannot preserve rich details, so affected exports/imports are explicitly blocked instead of silently discarding them. See the companion's `docs/rich-reports.md` for its contract and transfer restriction.

## Configured gateway reasoner qualification (2026-10-20)

The [separate dated receipt](qualification/live-reasoner-2026-10-20/README.md) records successful evidence-only assessment through the configured Claude CLI/gateway path at source/test checkout `f269ce82d2ac28e9ba77f7f393ffc231e639a164`. The user explicitly authorized importing only connection/model settings from `~/.claude`; this did not enable the user's tools, hooks or other host policy. Program source and tests were unchanged for this qualification.

| Recorded check | Result and scope |
| --- | --- |
| Configured execution | Gateway `https://claude.jlcops.com/api/`; Claude CLI `2.1.300`; configured alias `opus`; **CLI-reported model `deepseek-flash`**. The alias is not proof of an Anthropic backend. |
| Ignored live reasoner test | **1/1 passed**, 16.45 seconds, over authored synthetic debugger evidence. No live CDB or SSH acquisition was part of this test. |
| Offline fake-host controls | **10/10 passed**, including the separate tool-denial control. These are offline controls, not an observed live denial challenge. |
| Preservation comparison | **21/21 passed**; independent review **20/20 passed**. All nine original evidence entries, exception, context, stack, symbols, deterministic mechanism and completeness were unchanged; one accepted model assessment was added. |
| Causal boundary | Underlying cause remained `unknown`; the deterministic immediate mechanism remained `confirmed`. Acceptance of a validated assessment does not prove every narrative statement or establish incident origin. |
| Host lifecycle | CLI child PID `482105` exited and was reaped. This observation is for that local test process, not remote debugger containment. |

The host retained `--tools ''`, strict empty MCP configuration, disabled hooks, empty settings sources and no session persistence. No live tool-denial challenge or instrumented request counter was recorded; the deny policy and passing fake-host denial control must not be represented as such a live measurement.

An initial attempt against `https://api.anthropic.com` failed with `Not logged in` and produced no accepted assessment. The subsequent configured gateway pass therefore closes **only the configured CLI/gateway evidence-only reasoner subgate**. It does not qualify an Anthropic Claude model, complete all P6 acceptance/rollout work, deploy a daemon or companion service, or establish current CDB/SSH acquisition, TLS/service health, or DumpLedger delivery. Historical native acquisition, migration, browser and delivery receipts retain their original dates and scope.

## Production deployment checkpoint (2026-10-20)

The [separate production rollout receipt](qualification/production-rollout-2026-10-20/README.md) records the following completed deployment substeps. These identities, process IDs, counts and endpoints are observations at that checkpoint, rather than ongoing health guarantees.

| Substep | Recorded result |
| --- | --- |
| Local analyzer | Rebuilt from application source `f269ce8` and deployed as PID `495042`; binary SHA-256 `cc284ecacd1f03d5ed4e5ae8b9659e082139d7b94e2135eb78ccc4088d5541ff`. Five rich reports and the existing reports, secrets, byte cache and settled identities were preserved. |
| Local settings | `cdb-ssh`, scheduler off and write-back off, with the prior configuration retained. The deployment did not enable automatic acquisition or publication. |
| Analyzer checks | Full Rust suite: **356 passed, 2 ignored**; Clippy and rustfmt passed. A format-only change was made in `tests/runner.rs`; this was not a new live debugger or model qualification. |
| Windows companion | Rolled from `69eb3d3` to `7c2a51b51d2638c462778c17fe9421632297b236`, excluding the later WH1 work. Node `24.21.0`; backend PID `42476`, ports `4081`/`4082`; existing proxy PID `63648`, port `4080`, unchanged. All **501** candidate build-file hashes were verified. |
| Companion migration | Additive migration 9 was applied after the database already contained migration 10. Dry-run and live comparisons preserved hashes of all eight prior tables; database integrity passed. Counts remained **128 dumps, 33 analyses, 20 customers and 18 cases**. The new `analysis_details` table contained **0 rows**. |
| Companion checks | Candidate suites passed: **153 unit**, **156 integration**, **28 MBT** and **173 contract** tests. |
| Capability/authentication | TLS was validated. Authenticated v2 capabilities returned **200**, schema version **2**, maximum report **524,288 bytes** and request **1,048,576 bytes**; the unauthenticated request returned **401**. This establishes capability/authentication behavior, not report delivery. |
| Backups | Local: `~/.local/state/dump-analyzer/backups/p6-production-20261020T075807Z`. Windows companion: `D:/Services/dump-ledger-runtime/backups/p6-production-20261020-verified`. Use the receipt's matching binary/config/database checkpoint when evaluating rollback. |

**At this deployment checkpoint, the publication gate remained open.** Automatic approval review had rejected the single real crash-report publication because the broad rollout request did not explicitly authorize that exact payload and destination; explicit approval was then pending. The rejected action did not execute, add a remote report or change analysis counts: `analysis_details` remained empty and `analyses` remained 33. That receipt therefore did not establish a production full-detail publication/readback/restart canary or full P6 completion. The subsequent authorized publication result is recorded separately below.

The earlier configured gateway reasoner qualification remains separate and unchanged, including its CLI-reported `deepseek-flash` model boundary. This deployment checkpoint performed no new CDB, SSH acquisition or model run. The historical 2026-10-15 and 2026-10-20 reasoner evidence bundles retain their original bytes and scope.

## Completed production canary (2026-10-20)

After the user explicitly approved the exact selected real report and destination, the [new canary receipt](qualification/production-canary-2026-10-20/README.md) recorded successful production publication and restart durability. The earlier rollout receipt, including its then-pending publication status and zero detail rows, remains an unchanged historical checkpoint.

| Check | Recorded result |
| --- | --- |
| Immutable report | `r2_1e11b6bae3ee7e131c472a6b8b87e07328bc8375177ed11bcc3009a736cc07d8`; **63,438 bytes**; SHA-256 `d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb`. |
| Production publication | The Rust publisher obtained accepted analysis `analysis_06F9B90BAB5F449199FA9C9C93`. Idempotent replay returned the same ID; exact full-report readback and local publisher-store reopen passed. |
| Authentication/compatibility | Before and after restart, authenticated detail GET returned **200**, unauthenticated access **401**, and the same analysis ID/exact report was returned. The v1 list remained compact, prior analysis content was preserved, and only the one approved analysis was added. |
| Delivery policy | The standalone publisher store recorded `fullyDelivered`. The main live analyzer retained its five canonical reports and existing `localOnly` policy with scheduler and global write-back **off**, using `cdb-ssh`. |
| Restart durability | The exact approved report survived a native backend restart. Backend PID `51868` owned ports `4081`/`4082`; proxy PID `63648` remained unchanged. All **10 post-canary table hashes** matched before/after restart, with all old rows preserved. |
| Bounded data change | Exactly one row was added to each of `dump_analyses` (**33 → 34**), `analysis_details` (**0 → 1**) and `audit_events` (**941 → 942**). Counts of **128 dumps, 20 customers and 18 cases** were unchanged. |
| Recovery checkpoint | Post-canary online and stopped backups were saved. No database restore was performed; a saved backup is not a tested restore claim. |

The completed deployment and selected-report publication/readback/restart checks close the bounded P6 production rollout and canary at this dated checkpoint. This canary published an existing immutable report; it ran no new CDB acquisition or model assessment. The earlier configured gateway's CLI-reported `deepseek-flash` qualification remains unchanged. Successful transport/storage is not new proof of incident origin, and one selected publication does not enable broad scheduling, global write-back or catalog-wide reanalysis.

## Historical qualification and rollout

The following results are recorded in the [2026-10-15 integrated receipt](../tests/fixtures/report-v2/qualification/integration-receipt.json). Its source scope is the then-uncommitted rich-report implementation on DumpAnalyzer `0bb92ae` and DumpLedger `80fb95a`. These are preserved measurements, not a fresh qualification of revision `6a19ea2`.

The fixture inventory is in [tests/fixtures/report-v2/qualification](../tests/fixtures/report-v2/qualification/README.md). Binary dump, EXE and PDB artifacts remain outside Git. The fixture has a known null read and independently checked matching/mismatched GUID/age; it is separate from customer dumps.

An isolated canary helper runs one explicitly selected local dump through the actual configured SSH runner and writes a new canonical file. It does not scan the catalog or publish reports:

```sh
cargo run --offline --locked --example rich-report-canary -- \
  /tmp/rich-report-canary-20261015/null-read.dmp \
  D:/da/rich-report-canary-20261015/matching \
  /tmp/rich-report-matching.json windows-dev cdb-ssh
```

Before replacing any deployed binary, stop it gracefully, back up SQLite using its backup API, and dry-run the additive migration on a copy. Compare integrity, pre-existing table counts and retained data, then keep the daemon in manual/write-back-off mode. Inspect a bounded canary before widening reanalysis or enabling full publication. Restore the saved binary/config/database checkpoint for rollback, accounting for any writes after upgrade. The documented rollout does not authorize catalog-wide automatic reanalysis.

The 2026-10-15 receipt records **355 passing Rust tests**, including MirrorRust replay of 33 traces/20 actions, and **506 passing companion tests**, including contracts, migrations, HTTP and MBT. The two Rust tests ignored in that run were the existing live TLS probe and the approval-gated live Claude check. Formatting, Clippy with warnings denied, corpus freshness and companion model-interface checks passed in that qualification.

The same qualification recorded seventeen synthetic browser checks covering a 10,000-report list, lazy selection, Back/Forward, partial/legacy states, escaping, bounded caching and mobile. Its [GET-only browser canary](../tests/fixtures/report-v2/qualification/actual-browser-receipt.json) also inspected the actual captured report from SQLite: five frames, matching PDB, source line 12, raw exception/context and a visible unknown cause, fetched once on selection.

The native matching canary qualified `ReadNull -> CanaryEntry -> main` at source lines 12/14/15. The wrong PDB retained raw addresses without qualified source. The exact 24,259-byte report survived Rust publication, idempotent replay, local reopen and an isolated DumpLedger restart under one analysis ID and digest. The historical local database migration was checked on private copies: all old table data, including 34 reports, 79 inventory/queue rows and secrets, remained unchanged. Both isolated test services stopped cleanly.

Receipts and controlled reports: [qualification manifest](../tests/fixtures/report-v2/qualification/manifest.json), [integrated results](../tests/fixtures/report-v2/qualification/integration-receipt.json), [migration receipt](../tests/fixtures/report-v2/qualification/local-migration-receipt.json), [matching report](../tests/fixtures/report-v2/qualification/actual-matching-report.json), [restart/delivery provenance](../tests/fixtures/report-v2/qualification/ledger-roundtrip-provenance.json).

### Historical Claude qualification gate (2026-10-15)

The receipt records that the initial actual Claude host started and recorded its model, but its structured-output path returned an error while preserving deterministic evidence. The corrected adapter requests plain JSON and validates it locally, avoiding a formatting tool under the deny-all policy. Fake-host tests cover this path. **The receipt did not verify successful live reasoning after that correction.** The source-only documentation review initially left that dated result unchanged; the later configured gateway result is recorded separately above. Automatic approval review rejected the authored-fixture live test because it would transmit evidence to an external Claude destination without explicit user authorization. No blocked command was executed or bypassed.

The historical check was designed to send only authored synthetic debugger evidence, without SSH or dump transfer, while denying every model tool. At that checkpoint, a future live qualification needed its own explicitly authorized external destination and a new dated receipt. The authorized 2026-10-20 configured gateway run above is a separate, narrower qualification; it does not rewrite this historical record.

On 2026-10-15, the [local deployment receipt](local-deployment-2026-10-15.md) recorded DumpAnalyzer 0.2.0 in manual mode with write-back off and 34 historical legacy reports. It also recorded that the remote companion had not been upgraded and that full publication and catalog-wide reanalysis had not been performed. Read that receipt as an event at that date, not as the present service state.

## Source map

| Concern | Inspected source |
| --- | --- |
| Essential acquisition, optional refinement and outcome merge | [src/runner.rs](../src/runner.rs), especially `analyze`, `essential_script`, `refine_symbols` and `mark_refinement_failure`. |
| Capture statuses, identity, canonical bounds and validation | [src/report.rs](../src/report.rs). |
| Existing rich report reuse and legacy identity refusal | [src/analyzer.rs](../src/analyzer.rs), `PipelineAnalyzer::analyze`. |
| Version restriction, boot recovery and independent delivery cadence | [src/scheduler.rs](../src/scheduler.rs), `run`, `scheduler_loop` and `replay_loop`. |
| Atomic local report handoff and durable delivery state | [src/state.rs](../src/state.rs) and [src/verdict.rs](../src/verdict.rs). |
| Bounded DSH reasoning and assessment validation | [src/dsh_runner.rs](../src/dsh_runner.rs), [src/reason.rs](../src/reason.rs). |
| Detail, evidence and manual-action HTTP behavior | [src/http.rs](../src/http.rs). |
