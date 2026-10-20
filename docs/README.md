# Documentation guide

Reviewed against DumpAnalyzer source `6a19ea297bb219509c994780c96bdd6ce6c4bfab`
on 2026-10-20. These guides describe the checked-out implementation; they do
not establish which binary or settings a running service currently uses.

## Current implementation

| Document | Scope |
| --- | --- |
| [Project README](../README.md) | Build, configuration, providers, operator actions, dashboard, and model-based tests. |
| [Architecture](architecture.md) · [interactive diagrams](architecture.html) | Process boundaries, startup and scheduling, immutable report identity, capture, persistence, delivery, and lazy detail. |
| [Analyzer design](analyzer-design.md) | Component contracts, storage, recovery, trust boundaries, and formal-model scope. |
| [Rich reports](rich-reports.md) · [HTML](rich-reports.html) | Typed evidence, deterministic assessment, symbol qualification, canonical report storage, detail APIs, and full-delivery states. |
| [Analysis triggers](trigger-paths.html) | Discovery, automatic claims, recovery, manual requests, report reuse, rescan, and delivery. |
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

Recorded PIDs, service state, endpoints, file locations, hashes, test counts,
and remote companion status are snapshot-specific. The documentation refresh
does not rerun those tests, perform a deployment, start an analysis, publish a
report, or establish a successful live Claude reasoning gate. Current
implementation behavior and historical qualification evidence remain separate.

The controlled-canary qualification README is itself listed with an exact hash
in its historical manifest, so that file and all qualification payloads remain
byte-for-byte unchanged. Use the maintained guides above for current behavior;
interpret the canary README as part of its dated 2026-10-15 evidence capture.
