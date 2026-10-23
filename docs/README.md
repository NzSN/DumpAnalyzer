# Documentation guide

Reviewed against DumpAnalyzer source `6a19ea297bb219509c994780c96bdd6ce6c4bfab`
on 2026-10-20. These guides describe the checked-out implementation; they do
not establish which binary or settings a running service currently uses.
The separately authorized 2026-10-20 reasoner qualification below records
its own source revision and narrower execution scope.

## Current implementation

| Document | Scope |
| --- | --- |
| [Project README](../README.md) | Build, configuration, providers, operator actions, dashboard, and model-based tests. |
| [Architecture](architecture.md) · [interactive diagrams](architecture.html) | Process boundaries, startup and scheduling, immutable report identity, capture, persistence, delivery, and lazy detail. |
| [Analyzer design](analyzer-design.md) | Component contracts, storage, recovery, trust boundaries, and formal-model scope. |
| [Rich reports](rich-reports.md) · [HTML](rich-reports.html) | Typed evidence, deterministic assessment, symbol qualification, canonical report storage, detail APIs, and full-delivery states. |
| [Analysis triggers](trigger-paths.html) | Discovery, automatic claims, recovery, manual requests, report reuse, rescan, and delivery. |
| [DSH HTTP provider guide](dsh-http-guide.md) | `dsh-http` setup, adapter deployment, route selection, credentials, verification, and operations. |
| [Domain vocabulary](../CONTEXT.md) | Project terms and responsibilities. |
| [Report fixtures](../tests/fixtures/report-v2/README.md) | Source fixtures and regression-test boundaries. |

The architecture Markdown and Graphviz DOT files are the editable sources.
Run `python3 docs/architecture/render.py` to regenerate all five SVGs and the
self-contained architecture HTML after changing those sources. Rendering alone
does not re-inspect the code or refresh a source-revision claim.

## Historical plans and evidence

| Record | Interpretation |
| --- | --- |
| [Original Rust plan](../Plans/rust-implementation-plan.md) · [task breakdown](../Plans/rust-implementation-tasks.md) | Historical implementation waves and their dated acceptance results. |
| [Phase 2 readiness](../Plans/phase2-live-readiness.md) · [field-run procedure](../Plans/field-run.md) | Historical readiness decisions and a procedure requiring its own execution authorization. |
| [Rich-report plan](../Plans/rich-report-implementation-plan.md) | Baseline gaps, implemented waves, and dated qualification limits. |
| [2026-10-15 deployment receipt](local-deployment-2026-10-15.md) | Point-in-time process, database, binary, and browser observations. |
| [Controlled canary qualification](../tests/fixtures/report-v2/qualification/README.md) | Historical debugger, PDB identity, report preservation, and delivery receipts. |
| [2026-10-20 configured reasoner qualification](qualification/live-reasoner-2026-10-20/README.md) | Passed the evidence-only CLI/gateway reasoner subgate at source `f269ce8`; alias `opus` reported model `deepseek-flash`. This does not qualify an Anthropic Claude model, full P6 or deployment. |
| [2026-10-20 production rollout checkpoint](qualification/production-rollout-2026-10-20/README.md) | Analyzer application `f269ce8` rebuilt/deployed in manual/write-back-off mode; companion upgraded `69eb3d3` → `7c2a51b` for rich reports, excluding later WH1 work. Deployment passed; publication/read-back/restart canary and full P6 were still pending at this checkpoint. |
| [2026-10-20 approved production canary](qualification/production-canary-2026-10-20/README.md) | One explicitly approved 63,438-byte real-dump report published, replayed and read back exactly, then preserved through companion restart. The P6 production rollout and bounded canary gates passed; automatic scheduling/write-back remain off. |
| [2026-10-23 `dsh-http` live qualification](qualification/dsh-http-2026-10-23/README.md) | Bounded contract/confinement gates for the DSH provider against the real runtime, including route selection and the per-session key path. Dated evidence; not production rollout, load, or delivery qualification. |

Recorded PIDs, service state, endpoints, file locations, hashes, test counts,
and remote companion status are snapshot-specific. The earlier documentation
refresh made no live calls, ran no qualification tests, performed no deployment
and published no report. The later, explicitly authorized 2026-10-20 run
passed only the configured CLI/gateway evidence-only reasoner subgate; its
dated receipt preserves the model identity and limits. It does not establish
current service state, establish fresh acquisition, delivery or rollout
qualification, or complete full P6.

The subsequent production rollout has its own dated receipt: both service
upgrades, data preservation and authenticated v2 capability checks passed.
At that checkpoint, automatic approval review rejected the selected
real-report publication because explicit approval of its crash payload and
destination was missing. Approval was then pending; no canary publication or
new remote analysis had occurred. That deployment checkpoint did not close
the production publication/read-back/restart canary or full P6.

The later approved production canary records the user's explicit payload and
destination approval, successful Rust publication and idempotent replay,
exact authenticated HTTP read-back and preservation through companion
restart. Only one analysis, one full detail and one audit event were added;
pre-existing rows were preserved. The P6 production rollout and bounded
canary gates are complete. This published an existing report without new
CDB or model calls. Automatic scheduling and write-back remain off with
`cdb-ssh`; the isolated publisher reached `fullyDelivered`, while the main
daemon's five rich reports remained `localOnly`. Causality and provider
qualification limits are unchanged.

The controlled-canary qualification README is itself listed with an exact hash
in its historical manifest, so that file and all qualification payloads remain
byte-for-byte unchanged. Use the maintained guides above for current behavior;
interpret the canary README as part of its dated 2026-10-15 evidence capture.
