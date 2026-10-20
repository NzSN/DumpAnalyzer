# DumpAnalyzer rich report implementation plan

Historical plan authorized and implemented on 2026-10-15, with its dated receipt in §9. Sections 1–8 preserve the pre-implementation gaps, proposed interfaces and acceptance requirements; future-tense task wording is not a current backlog. Planning baselines were DumpAnalyzer `0bb92ae` and DumpLedger `80fb95a`. Source review on 2026-10-20 used DumpAnalyzer `6a19ea297bb219509c994780c96bdd6ce6c4bfab` without rerunning builds, tests or live checks.

At the 2026-10-15 receipt, local rollout to 0.2.0 was complete, corrected live Claude qualification was unrun and remote companion rollout had not been performed. Use the maintained [rich-report guide](../docs/rich-reports.md), [architecture](../docs/architecture.md), [analyzer design](../docs/analyzer-design.md) and [README](../README.md) for current implementation behavior and qualification boundaries. The [deployment receipt](../docs/local-deployment-2026-10-15.md) remains evidence for that dated rollout only.

The intended result is a report detail view containing **a symbol-resolved native stack, the exception record and context, and an evidence-backed root-cause assessment**. The report must preserve those sections through storage, restart, and optional write-back. A short summary remains useful in the paged Reports list.

**Recommended approach:** introduce one versioned, typed full report, save it before producing the compact legacy verdict, and load its detail only when selected. Build deterministic debugger evidence first, then run causal analysis over that evidence. Deliver the local detail view first; complete versioned DumpLedger delivery before claiming that the full report is preserved remotely.

## 1. Baseline gaps before implementation (2026-10-15)

The recorded source line references in this table identify observations at the planning baseline; they are not links to today's implementation.

| Layer | Implementation at the planning baseline | Required change in this plan |
| --- | --- | --- |
| Capture | The script runs `.sympath`, `.reload`, `.ecxr`, `kc`, `lm`, and process information. It does not explicitly collect the exception record. Recorded reference: `src/runner.rs:1443`. | Capture named exception, context, stack, symbol, and fault-site evidence sections. |
| Stack | Up to 32 call-site strings survive, with each string limited to 160 characters. Frame addresses, resolution state, and module attribution are not preserved in the emitted frame objects. Recorded references: `src/runner.rs:53`, `src/runner.rs:1138`. | Typed frames with addresses, symbols, offsets, provenance, and explicit unwind/coverage limitations. |
| Provider contract | Claude accepts an arbitrary `facts` object and uses a different field vocabulary from the deterministic runner. Neither contract requires causal analysis. Recorded reference: `src/claude_runner.rs:34`. | Both providers satisfy the same report schema and evidence-validation rules. |
| Preservation | Assembly enforces 4 KiB of facts and a 16 KiB submission, dropping complete keys to fit. The reduced submission is what local storage receives. Recorded references: `src/verdict.rs:49`, `src/verdict.rs:180`. | Save the full report independently; derive a deliberately compact compatibility projection afterward. |
| Display | The report list omits facts, and its Details disclosure repeats the summary. Recorded references: `src/http.rs:1147`, `src/dashboard.html:510`. | A lazy report-detail endpoint and view with the three requested sections. |
| Reanalysis | Local insertion ignores an existing identity; remote replay is also immutable by analyzer version. Recorded reference: `src/state.rs:977`. | Use a new analyzer version for v2 analysis; preserve old reports and require explicit scoped reanalysis. |

Increasing the prompt length or adding more fields to the existing `facts` object would leave the preservation and display gaps unresolved.

## 2. What a complete report must contain

| Requested section | Required information | Acceptance rule |
| --- | --- | --- |
| Resolved stack | Exception thread ID; numbered frames; reported frame/stack/return addresses; module and RVA; function and displacement; source file/line when available; per-frame resolution and unwind status. | A controlled fixture with matching symbols resolves the expected application frames. Missing or mismatched symbols retain raw addresses and explain the limitation. |
| Exception record | Raw exception code, flags, exception address, associated-record pointer when available, parameter count, raw parameters, and code-specific interpretation. Also record context source, registers, fault-site instruction bytes/disassembly, process/thread IDs, architecture, and pointer width. | Captured fields agree with debugger evidence. Missing records are labelled absent or unavailable; a different thread's context cannot masquerade as exception context. |
| Root-cause analysis | Concise conclusion; immediate fault mechanism; underlying cause assessment; evidence references; competing hypotheses; missing information; next verification steps. | Every causal assertion cites captured evidence. The report distinguishes an established mechanism from an unresolved origin. |

The first release targets native Windows x64 user-mode crash dumps. Other architectures must have explicit parser/fixture qualification before being marked supported. Native stack coverage does not imply reconstruction of JavaScript, managed, or asynchronous logical stacks.

All addresses, pointer values, and exception parameter values use canonical hexadecimal strings. JavaScript number conversion must not lose 64-bit precision. Unknown values stay unknown rather than becoming zero.

**Symbol resolution means verified attribution.** Record the expected module/PDB identity from the dump, loaded PDB identity and path/artifact reference, GUID and age where available, and relevant image metadata. A symbol-looking function name alone is insufficient. Distinguish matching PDB, exports only, missing PDB, mismatched PDB, and unverified identity. Source lines require matching source/build provenance; optimized frames and missing line information are reported honestly. Unwind reliability is separate from symbol resolution.

**Root-cause vocabulary:**

| State | Meaning | Example |
| --- | --- | --- |
| `confirmed` | Captured evidence and verified program/source facts establish the causal chain being claimed. | A controlled fixture's matching source and instruction establish the erroneous null argument and its dereference. |
| `hypothesis` | Evidence supports a candidate explanation, but a necessary causal link is missing. | Memory corruption is plausible, but the writer was not captured. |
| `unknown` | The available evidence cannot establish an underlying cause. | The faulting read is established, but the origin of the invalid pointer is unavailable. |

These states describe the underlying cause. A report may have a **confirmed immediate mechanism and an unknown root cause**. `!analyze -v` output is retained as debugger assessment; its suggested blame is not automatically promoted to a confirmed cause. A hardware model, module name, or a crash inside V8 is not sufficient causal evidence.

Automatic confirmation requires an implemented deterministic claim rule or recorded, build-matched source/runtime verification of the claimed causal chain. Valid evidence IDs alone do not prove that prose follows from the evidence. Model-generated conclusions remain `hypothesis` or `unknown` unless that stronger gate passes. Keep execution outcome, report completeness, symbol quality, and cause status separate, so partial evidence remains inspectable.

## 3. Report and evidence design

Use a new `src/report.rs` module to define `CrashReportV2`, validation, and compact projection. Its interface is shared by scheduled analysis, manual analysis, both runner providers, storage, and display.

```text
Debugger collection → EvidenceBundle → causal assessment → CrashReportV2
                                                        ↓
                                               durable full-report save
                                                        ↓
                            lazy detail view ← report ID → publication outbox
                                                               ↓
                                          v1 summary / v2 full-report delivery
```

The canonical report contains these groups:

```json
{
  "schemaVersion": 2,
  "reportId": "stable ID assigned at durable save",
  "identity": {
    "dumpId": "...", "inputSha256": "...", "kind": "triage",
    "analyzerName": "dump-analyzer", "analyzerVersion": "0.2.0"
  },
  "provenance": { "provider": "cdb-ssh", "debuggerVersion": "...", "architecture": "x64" },
  "exception": { "status": "present", "code": "0xc0000005", "parameters": [] },
  "context": { "source": "exception", "registers": {}, "faultInstruction": {} },
  "stack": { "threadId": "...", "status": "partial", "frames": [], "limitations": [] },
  "symbols": { "modules": [], "limitations": [] },
  "rootCause": {
    "status": "unknown", "mechanism": "...", "conclusion": "...",
    "evidenceRefs": [], "hypotheses": [], "missingEvidence": [], "nextChecks": []
  },
  "evidence": [],
  "completeness": { "omissions": [], "truncated": false }
}
```

This was an illustrative planning shape, not the finalized wire schema. P0 finalized the implemented contract in [`src/report.rs`](../src/report.rs); `ReportCapture` is flattened into the serialized report. Use that source and the maintained rich-report guide for exact fields, nullability, limits and validation rules.

Each evidence entry has an ID, command or acquisition method, result status, transcript range or retained artifact reference, and truncation/error information. Findings refer to those IDs. Evidence unavailable in the dump is different from a command failure, timeout, or parser failure.

**Proposed limits for P0 review:** 128 primary-thread frames, 64 detailed module records, a 512 KiB canonical JSON limit, and a separate 4 MiB transcript budget per run. Allocate bounded sections within the JSON budget. If a limit is reached, retain all required section headers and explicit omission counts/reasons. Preserve the most relevant frames and evidence; never silently remove an entire requested section. Avoid collecting arbitrary memory pages or unbounded heap dumps.

The canonical report is authoritative. Legacy 4 KiB facts are a projection carrying a compact exception/stack/assessment summary, schema version, and full-report reference/digest. Its reduction must never mutate the saved canonical document. The reference/digest are mandatory projection fields with a reserved budget; they cannot pass through a shrinker that might drop them.

## 4. Debugger collection and reasoning

**Collection order matters:** capture the exception record and saved context before potentially expensive symbol loading. Record explicit begin/end markers for every section so parsing does not confuse command echoes, warnings, disassembly, and frames.

| Step | Capture | Design constraint |
| --- | --- | --- |
| C1 | Debugger version, target architecture, process/thread information, initial module inventory. | Pin the dump SHA-256 and identify which thread/context each later section describes. |
| C2 | `.exr -1`, `.ecxr`, registers, and bounded fault-site bytes/disassembly. | `.exr -1` exposes the most recent exception record; `.ecxr` selects the saved exception context. If unavailable, label the fallback context explicitly. [Microsoft .exr](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-), [Microsoft .ecxr](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-ecxr--display-exception-context-record-) |
| C3 | Preliminary stack; identify faulting and stack-referenced modules. | Preserve addresses even before symbols resolve. Bound the number of frames and modules. |
| C4 | Force symbol loading for relevant modules, then gather verbose module/PDB diagnostics. | Use the configured HTTPS symbol store and cache; verify identities. `.reload /f` forces loading; `/i` ignores mismatches and must not be used for qualified reports. [Microsoft .reload](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-reload--reload-module-) |
| C5 | Restore exception context and collect the final numbered, address-bearing stack with offsets and available source lines. | Replace `kc` as the sole stack representation. Validate the bounded `kn`/`kv` command form on the deployed CDB version; explicit frame counts avoid radix ambiguity. Return addresses must not be mislabeled as instruction pointers. [Microsoft stack commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-) |
| C6 | Optional bounded `!analyze -v` assessment. | Preserve its provenance and deadline; failure does not discard earlier evidence. [Microsoft !analyze](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-analyze) |

Decode exception parameters by exception code, retaining the raw values. For access violations, interpret operation and target address; in-page errors also carry an underlying status. Unknown/custom exception codes keep raw parameters without invented meanings. Nested records are followed only when captured and within a fixed depth. [Microsoft EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)

**Reasoning stage:** introduce a small assessment interface accepting the typed evidence bundle and returning the validated root-cause section. Deterministic code establishes directly checkable mechanisms, such as instruction/register/address consistency. A configured Claude adapter can produce the narrative, hypotheses, and next checks from that evidence. Record provider/model and analysis revision. If reasoning is unavailable, preserve the collected report with an explicit status and useful next checks.

Require both `cdb-ssh` and `claude-cdb` to produce the same mandatory evidence/schema. Claims supplied by Claude must resolve to actual captured evidence; fabricated command IDs and missing required sections fail structural validation. Confirmation additionally needs the deterministic/source/runtime gate above. Test a plausible but invalid causal claim that cites real evidence IDs, not only nonexistent citations. The first implementation should provide the reasoner with bounded evidence and no general shell capability. Additional debugger probes, if later enabled, go through a typed allowlist and a shared time/output budget.

For Codex-driven Claude execution/qualification, use the persistent host-mode bridge described by the existing [Claude CLI skill](/home/nzsn/Repos/skills/skills/misc/claude-cli/SKILL.md). An unattended adapter needs an explicit host and reviewed policy as well. The present one-shot invocation must not be treated as evidence that supervised reasoning already works.

Before extending agent work, cover the existing timeout edge around stdout EOF and child exit, concurrent bounded stderr draining, staging deadlines, and cleanup. Preserve useful evidence on optional-stage failure. Tool failure, incomplete evidence, and an unknown cause are separate states.

## 5. Durable storage and delivery

**Local first.** Add an additive migration for canonical report details and stable report IDs. Store the full validated JSON and digest separately from compact v1 facts. Keep existing reports, cursors, secrets, cache indexes, and settled identities intact. Keep report-list queries light: select list columns only, without loading full JSON or transcript data.

Persist the canonical report and its job/reporting transition in one transaction before marking completion. Retained evidence must be copied or returned as owned data before local/remote workspaces are wiped. A retry reuses the durable report ID and digest instead of generating a new document. An immutable identity with conflicting content is an explicit conflict, not `INSERT OR IGNORE` silently hiding the new content.

Raw transcripts are optional, bounded artifacts with a separate retention policy. Structured stack, exception, and assessment content must remain readable if raw artifacts expire. Extend the existing purge policy consistently to details/artifacts and make artifact availability explicit.

**Versioned remote completion.** Keep the current 16 KiB v1 route and 4 KiB facts contract intact. Propose a dedicated v2 write/read surface in DumpLedger:

| Proposed interface | Behavior |
| --- | --- |
| `POST /api/v2/dumps/:dumpId/analyses` | Accept the compact attribution/summary plus canonical report and digest, with a route-specific bounded request limit. Validate input hash, schema, evidence references, and full-report size. |
| `GET /api/v2/dumps/:dumpId/analyses/:analysisId` | Return one full report on demand under the analyzer/session authorization model. |
| Existing v1 analysis listing | Continue returning compact compatible rows. Do not embed every full report into list responses. |

A proposed 1 MiB v2 request ceiling accommodates the 512 KiB document and envelope; finalize byte limits in the contract task. Store summary and detail atomically under one analysis identity, with a detail table keyed by `analysisId`. Equal identity and digest replay successfully; conflicting content returns an explicit conflict. Purge cascades and import/export behavior must include the new details, or be explicitly blocked until supported.

**Summary-to-detail promotion is required.** If v1 summary fallback created the analysis row first, v2 must reuse that `analysisId` and atomically attach the absent detail only when identity, compact metadata, and the stored v2 document digest match the incoming document. An existing equal detail digest is a replay; a mismatch is a conflict. A legacy row without a verifiable v2 binding cannot be promoted by assumption. Implement this path before the current engine's early identity-replay return, with one audited attach effect. Otherwise a summary-only report could remain permanently unable to upload its full detail after the server is upgraded.

Delivery status must distinguish **local-only**, **summary-only/awaiting-v2**, **pending full delivery**, and **fully delivered**. A successful v1 POST is not proof that full detail was delivered. When the server is older, retain canonical detail locally and follow the established local-verdict compatibility policy; show the outstanding full delivery separately. Preserve current queue settlement policy rather than leaving a phantom running analysis.

Use a new analyzer version, proposed `0.2.0`, for v2 reanalysis. Centralize profile/version selection across discovery, manual analysis, report identity, and explorer status. Do not rewrite historical reports or silently reuse a legacy identity. Existing reports display their surviving evidence with **Legacy report — detailed sections were not captured**. Missing data can only be recovered by reanalysis.

## 6. Report detail UI

Keep the dedicated, paginated Reports panel. Add a stable report ID and detail-availability metadata to list rows. Selecting Details opens a focused detail route/view, such as `#reports?reportId=…`, and calls `GET /api/reports/:reportId` once. Back returns to the prior page and filters.

The detail view presents:

1. **Analysis conclusion:** immediate mechanism, root-cause state, conclusion, important limitations, and next checks.
2. **Exception record and context:** raw fields, decoded access information, registers, instruction bytes/disassembly, and context provenance.
3. **Resolved stack:** numbered frames with module/function/offset, addresses, source location, and clear resolution/unwind labels.
4. **Evidence and symbols:** referenced command sections, module/PDB identity checks, acquisition errors, and explicit truncation/retention states.

Show a compact quality strip: exception captured, stack coverage, symbol verification, and cause status. An unknown root cause must be visible without opening raw JSON. Preserve text escaping and never render debugger/model output as trusted HTML. Keep full detail and transcripts out of background list polling; provide a bounded JSON/text download when requested. Retain the local loopback default and apply the intended viewer authorization to detail/artifact reads; a report ID is a locator, not a credential.

## 7. Implementation waves and ownership

The integrator owns shared interfaces, manifest/version changes, and cross-module integration. Workers receive disjoint file ownership and must preserve each other's changes. No dependency additions are assumed; any needed parser/runtime package is reviewed in P0.

| Wave | Tasks | Depends on | Gate |
| --- | --- | --- | --- |
| W0 | P0 contract, fixture inventory, budgets, and compatibility decisions | — | Shared schema and acceptance examples reviewed before parallel edits. |
| W1 | P1 canonical report/store; P2 capture/symbol evidence | P0 | Exact preservation and parser fixtures pass, including bad/missing evidence. |
| W2 | P3 root-cause assessment/provider parity; P4 local detail interface/UI | P1, P2 interfaces | Three requested sections visible through the real local report path. |
| W3 | P5 versioned DumpLedger delivery | P0; integrated after P1 | Full remote round-trip and replay/purge tests pass. |
| W4 | P6 integration, compatibility, qualification, and rollout | P1–P5 | Local and remote acceptance matrix passes with preserved historical data. |

| Task | Owner / owned files | Deliverable | Acceptance |
| --- | --- | --- | --- |
| P0.1 | Integrator: design doc, `src/report.rs` interface, `src/types.rs` | Final schema, statuses, identity, digest and budget rules; sample complete/partial/legacy documents. | Both providers, detail reader, and projection can use one contract. |
| P0.2 | Qualification owner: `tests/fixtures/report-v2/` inventory | Known matching/mismatched symbols, missing exception, truncated unwind, oversized output, and a controlled known-cause fixture. | Every fixture has expected fields/provenance; real dump bytes are not committed casually. |
| P1.1 | Storage owner: `src/state.rs`, `tests/state.rs` | Additive detail/ID/delivery migration, immutable save/get, list-column queries. | Migration preserves old rows; reopen is identical; full details survive beyond 4 KiB. |
| P1.2 | Integrator: `src/verdict.rs`, `src/agent.rs`, `src/analyzer.rs`, scheduler integration | Save before compact projection, atomic phase handoff, retained evidence before cleanup. | Simulated crashes cannot leave a completed job without its full report. |
| P2.1 | Capture owner: `src/runner.rs`, runner fixtures/tests | Named exception/context/stack sections and bounded command results. | Expected raw and typed values agree; no exception or wrong context is handled explicitly. |
| P2.2 | Symbol owner: proposed `src/symbols.rs`, symbol fixtures/tests | Module/PDB identity verification and per-frame resolution quality. | Correct PDB resolves; wrong GUID/age cannot pass; unresolved addresses survive. |
| P2.3 | Capture owner + integrator: runner/process tests | Shared deadlines, bounded streams, timeout/EOF/staging cleanup coverage. | Optional stage failure preserves prior capture and cannot leave an unbounded wait. |
| P3.1 | Assessment owner: proposed `src/assessment.rs`, fixtures/tests | Mechanism checks, evidence-linked cause/hypothesis/unknown output, deterministic confirmation rules. | Real citations with an invalid causal inference cannot produce `confirmed`; nonexistent references are rejected. |
| P3.2 | Provider owner: `src/claude_runner.rs`, provider tests | Shared schema, supervised host transport, provenance, bounded reasoning. | Fake-provider tests prove malformed output handling; later supervised live check proves real wiring. |
| P4.1 | Detail interface owner: `src/http.rs`, HTTP tests | Stable ID in light lists; lazy detail/selected-evidence reads; legacy detail conversion. | Lists remain bounded and do not deserialize full report JSON. |
| P4.2 | UI owner: `src/dashboard.html`, browser fixtures | Focused detail view with exception, resolved stack, assessment, and evidence. | Deep links, Back, escaping, partial states, and mobile views pass. |
| P5.1 | DumpLedger contract owner: `packages/http-contracts`, HTTP route contract/tests | v2 schema, limits, authorization, digest conflicts, capabilities. | v1 behavior remains compatible; old server is detected truthfully. |
| P5.2 | DumpLedger storage owner: ledger/engine, migration and transfer tests | Atomic summary/detail persistence, digest-bound promotion before early replay, purge, import/export handling. | v1-summary then v2-detail reuses one analysis ID; replay is stable; no orphan details after purge/rollback. |
| P5.3 | Integrator: DumpAnalyzer client/wire/verdict/delivery tests | v2 publisher and independent summary/full delivery state. | ACK loss replays once; old servers cannot falsely mark full detail delivered. |
| P6.1 | QA/integrator: integration and MBT coverage | End-to-end capture → save → restart → detail → remote replay. | Relevant tests pass across normal, failure, and lifecycle races. |
| P6.2 | Release owner: docs and operator runbook | Manual canary, scoped reanalysis, data backup/migration proof, rollback. | Selected live reports satisfy all three requirements; counts and unrelated history remain intact. |

P1 storage and P2 capture can run in parallel after P0. P3 and P4 can run in parallel once their shared interfaces are fixed. P5 contract work may begin earlier, but remote publication is not accepted before canonical local preservation works.

## 8. Acceptance matrix and rollout

| Scenario | Required result |
| --- | --- |
| Matching PDB + intact exception/unwind | Qualified application frames, correct exception fields, evidence-linked causal assessment, identical detail after restart. |
| Missing or mismatched PDB | Partial stack with addresses and exact symbol limitation; no invented function/source names or unsupported confirmed cause. |
| No exception stream / damaged unwind | Explicit absence/failure state; available thread evidence retained and labelled with its source. |
| Access violation | Raw parameters and context preserved; decoded operation/address agree with instruction/register evidence when captured. |
| Fault mechanism known, origin unknown | Mechanism explained; underlying cause remains unknown or a labelled hypothesis with a concrete next check. |
| Model unavailable, malformed output, or hostile captured text | Deterministic evidence remains readable; assessment status is explicit; no arbitrary tool execution or fabricated evidence acceptance. |
| Output/document size reached | Report declares omissions/truncation; required sections remain present; compact projection cannot erase saved detail. |
| Crash before save / after local save / after remote commit before ACK | Recoverable job state, intact full local document, and idempotent remote effect. |
| Legacy reports and old server | Historical rows stay readable; unavailable sections are labelled; full delivery remains local/pending truthfully. A digest-bound v2 summary posted through v1 can later gain full detail atomically under the same analysis ID. |
| 10,000 reports | Lists remain paged and light; no detail or transcript request until selected. |
| Purge / import-export / rollback | Detail and artifact behavior follows the approved lifecycle policy without orphan or silently missing report content. |

Use focused Rust tests during each task, then integrator-run `cargo test --offline --locked`, Clippy with warnings denied, formatting, corpus freshness, and MirrorRust replay. Existing MBT does not prove symbol correctness or causal validity; add real interface tests for those claims. Run companion DumpLedger contract/migration/replay tests for P5. Heavy Windows fixture generation and CDB qualification belong on the analysis host.

Before rollout, back up each affected SQLite database and prove migrations on copies. Preserve the current manual operation and write-back-off settings until a bounded canary is reviewed. Reanalyze selected fixture/real dump IDs under the new analyzer version first; do not automatically sweep the catalog. Enable wider reanalysis and full write-back only after local and remote detail retrieval agree. Rollback restores compatible binaries and the relevant database/artifact checkpoint, with any post-upgrade writes accounted for.

**Completion has two explicit gates:** P1–P4 provide the requested rich report in DumpAnalyzer. P5–P6 establish that the same full report is durably attached to the dump in DumpLedger. A concise summary, successful model invocation, or resolved top frame alone does not satisfy the three requirements.

## 9. Implementation receipt (2026-10-15)

At this 2026-10-15 receipt, P0–P5 were implemented in the working trees; no commit or push had been performed for that implementation wave. P6 native acquisition, exact local preservation, real HTTP delivery/replay/restart, migration-on-copy and browser gates passed. The corrected live reasoner and remote companion rollout were not marked passed. Local rollout is recorded in `docs/local-deployment-2026-10-15.md`. These statements record that checkpoint, not the later repository or live-service state.

| Work | Result |
| --- | --- |
| P0 | Typed schema, fixed budgets, authored failure fixtures and controlled Windows x64 source/PDB/dump provenance. |
| P1 | Migration 4, immutable canonical JSON/digest, atomic compact/detail/phase handoff and lightweight list queries. |
| P2 | Essential/optional CDB phases, complete EXR/context/stack capture, independent RSDS/PDB identities, bounded transport and explicit partial states. |
| P3 | Checked immediate-mechanism rule, unknown/hypothesis cause, evidence validation and isolated deny-all Claude host. Corrected live success requires authorization. |
| P4 | Stable report IDs, lazy detail/evidence reads, legacy conversion, focused escaped UI and JSON download. |
| P5 | Companion migration 9, authenticated closed v2 contract, atomic promotion/replay, digest-bound ACK, purge cascade and explicit transfer restriction. |
| P6 | 355 Rust tests, 506 companion tests, formatting/Clippy, 33-trace model replay, synthetic/real browser checks, real CDB matching/mismatch, local migration preservation, real client/server restart round-trip. Local daemon deployed at 0.2.0; companion service unchanged. |

Resolved implementation detail: the compatibility projection is a pure calculation over an immutable full document. Full detail, compact row and reporting handoff commit together; a crash before commit leaves recoverable execution state, and a crash after commit cannot lose the canonical document. This avoids a partially committed summary/detail pair while preserving full evidence through projection.

See [the operator and qualification guide](../docs/rich-reports.md) and [integrated receipt](../tests/fixtures/report-v2/qualification/integration-receipt.json). A local SSH timeout does not prove remote process-tree termination; a Windows Job Object supervisor remains outside this release's guarantees.

## 10. Configured reasoner qualification addendum (2026-10-20)

The [dated qualification receipt](../docs/qualification/live-reasoner-2026-10-20/README.md)
records a separately authorized evidence-only reasoner run at source/test
revision `f269ce82d2ac28e9ba77f7f393ffc231e639a164`. It closes the configured
CLI/gateway reasoner subgate only. The 2026-10-15 receipt above remains
unchanged; this addendum does not mark full P6, production deployment,
SSH/CDB acquisition or DumpLedger delivery passed.

The user authorized importing only connection/model settings from
`~/.claude`. Claude Code CLI 2.1.300 used the configured gateway
`https://claude.jlcops.com/api/` with selection alias `opus`; the CLI init
event reported model `deepseek-flash`. That reported identity is not an
independent attestation of the backend, and the result does not qualify an
Anthropic Claude model. The earlier `api.anthropic.com` attempt failed with
`Not logged in` and produced no accepted assessment.

The explicitly selected ignored live test passed **1/1 in 16.45 seconds**.
Fake-host controls passed **10/10**, preservation checks **21/21**, and the
independent review **20/20**. All nine original evidence entries and the
exception, context, stack, symbols, deterministic mechanism and completeness
sections were unchanged. One accepted assessment was added; the underlying
cause stayed `unknown` and the deterministic immediate mechanism stayed
`confirmed`. Structural acceptance does not prove every model hypothesis.

The existing isolation settings were retained: no enabled tools, strict empty
MCP configuration, hooks disabled, empty setting sources and no session
persistence. CLI child PID `482105` was reaped. There was no observed live
denial challenge or instrumented tool-request counter; denial behavior was
tested separately with fake hosts.

Companion verification/rollout and a selected production full-detail canary
remain separate gates before wider reanalysis or write-back under §8. This
synthetic run establishes no new real-dump, PDB, service, persistence/restart
or remote-publication qualification. The original controlled-canary
qualification README, manifest and payload bytes are preserved.

## 11. Production rollout checkpoint (2026-10-20)

The [production rollout receipt](../docs/qualification/production-rollout-2026-10-20/README.md)
records a passed deployment substep, separate from the earlier qualification
receipts and the production report canary. The analyzer application at
`f269ce82d2ac28e9ba77f7f393ffc231e639a164` was rebuilt and deployed with
manual operation, write-back off and `cdb-ssh` retained. Existing secrets,
cache, settled identities and reports were preserved; five rich reports
remained present. The receipt records the binary/process identities and
private rollback checkpoints.

The remote companion advanced from `69eb3d3` to
`7c2a51b51d2638c462778c17fe9421632297b236` for rich reports, excluding later
WH1 work. Migration 9 was added to the ledger that already contained version
10. Dry-run and live comparisons preserved all eight old table hashes, with
integrity `ok`: 128 dumps, 33 analyses, 20 customers and 18 cases.
Authenticated v2 capabilities returned 200 with schema version 2, a 524,288-byte
report limit and a 1,048,576-byte request limit; unauthenticated access returned
401, with TLS verified. This checks deployed protocol availability, not a
full-report write/read-back round-trip.

Recorded validation passed **356 Rust tests, 2 ignored**, Clippy and rustfmt
after a formatting-only correction in `tests/runner.rs`. Companion candidate
gates passed **153 unit, 156 integration, 28 MBT and 173 contract tests**.
The original 2026-10-15 and configured-reasoner evidence bundles are unchanged;
the earlier CLI-reported `deepseek-flash` result retains its original scope.

**Production canary and full P6 remain open.** Automatic approval review
rejected publication of the selected real report because the broader rollout
request did not explicitly authorize that crash payload and destination.
Explicit approval is pending. No canary publication or new remote analysis
was performed: `analysis_details` remained empty and the analyses count stayed
33. This gate initiated no new CDB or model calls. The production full-detail
publication, read-back and restart canary still needs its own completed
receipt before wider reanalysis or write-back under §8.

## 12. Approved production canary closeout (2026-10-20)

The [production canary receipt](../docs/qualification/production-canary-2026-10-20/README.md)
records the user's later explicit approval of the selected real-report
payload and destination. The blocked checkpoint in §11 remains historical
evidence; it was followed by this authorized publication and durability proof.

The actual Rust publisher accepted the **63,438-byte** canonical report as
`analysis_06F9B90BAB5F449199FA9C9C93`. Idempotent replay returned the same
analysis ID, with exact remote JSON/digest and local reopen verified. Its
SHA-256 was
`d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb`.
Authenticated HTTP detail reads returned 200 and unauthenticated reads 401;
compact v1 access and the prior analysis were preserved.

The reviewed companion restart and subsequent HTTP verification passed.
All ten table hashes matched across restart. The only approved additions
were one analysis (**33 → 34**), one detail (**0 → 1**) and one audit event
(**941 → 942**); all pre-existing rows, including 128 dumps, 20 customers
and 18 cases, were preserved. The companion restarted as PID `51868` on
ports 4081/4082; proxy PID `63648` on 4080 was unchanged. Post-canary online
and stopped-state backups were saved; no database restore was performed.
The same report ID, exact canonical bytes and digest remained readable
through authenticated HTTP after restart.

**The P6 production rollout and bounded publication/read-back/restart canary
gates are complete.** This result publishes an existing report; it does not
claim a new CDB acquisition or model run. The isolated publisher reached
`fullyDelivered`; the main daemon's five rich reports remained `localOnly`.
Manual operation, automatic scheduling off, write-back off and `cdb-ssh`
were retained. Wider automatic reanalysis/publication was not enabled.
Causality and provider qualification limits remain unchanged, including the
earlier configured gateway's CLI-reported `deepseek-flash` scope. The
2026-10-15 qualification and both earlier 2026-10-20 evidence bundles remain
byte-for-byte unchanged.
