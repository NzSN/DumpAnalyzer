# DumpAnalyzer Rust implementation plan

Historical plan for the 2026-10-13 Rust implementation. The waves below were
completed; their original task constraints and stage mapping are retained as
planning history, not current setup instructions. Source review on 2026-10-20
used DumpAnalyzer `6a19ea297bb219509c994780c96bdd6ce6c4bfab` without rerunning
builds, tests or live checks.

For maintained behavior and configuration, use the [README](../README.md),
[architecture](../docs/architecture.md) and [analyzer design](../docs/analyzer-design.md).
The [task receipts](rust-implementation-tasks.md#stage-gates) and
[phase-two receipt](phase2-live-readiness.md) record the original gates;
[rich reports](../docs/rich-reports.md) describes the later 0.2.0 report path.

Derived from [`docs/analyzer-design.md`](../docs/analyzer-design.md) (Rust
decision of 2026-10-13) and checked against `specs/DumpAnalyzer.tla`, which
pins the job lifecycle every task had to honor. This plan covered design
milestones AN1–AN3; AN4 was deferred in the original scope.

## Implementation status at the documentation review

The planned modules are present in `src/`: wire/config/state, client/sync,
agent/runner/verdict and scheduler/main. On-demand analysis is implemented
separately in `src/analyzer.rs`, with the HTTP dashboard in `src/http.rs`
and `src/dashboard.html`. Later additions include persisted token resolution,
manual rescan, periodic delivery, cache eviction and canonical rich reports.
The original brief below predates those additions; its v1-only report limits
and required-environment-token wording do not describe the complete current
implementation. Historical gate results remain in the linked receipts.

## Conventions for every task

- Rust edition 2024, `#![forbid(unsafe_code)]`, async on tokio. rustfmt
  style; `cargo clippy -- -D warnings` clean.
- **No new dependencies.** The manifest is integrator-owned and complete;
  `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/main.rs`, and `src/types.rs`
  are never touched by tasks (except D2 rewriting `main.rs`).
- Always build/test with `cargo ... --offline --locked`; the registry cache
  is warm and network access is restricted.
- Shared kernel types (`JobPhase`, `JobIdentity`, `ToolRunner`, `RunOutput`,
  `AnalyzerError`, …) come from `src/types.rs`; tasks never redefine them.
- Tests live in `tests/<module>.rs` (integration style) plus `#[cfg(test)]`
  units inside the owned module where simpler. Fixture files live in
  `tests/fixtures/<area>/`.
- Acceptance = scoped tests green + no clippy warnings from owned files +
  `cargo fmt --check` clean. Wave gates are run by the integrator, never
  self-reported.
- Agents share the worktree with other agents and the integrator: touch only
  owned files; never revert foreign edits; unrelated dirty work in
  `git status` is not theirs. (This repo also holds untracked `docs/` and
  `specs/` — leave them alone.)
- The job lifecycle must match `specs/DumpAnalyzer.tla`: pinning at fetch,
  volatile phases (`fetching`/`staged`/`analyzing`) reset to `claimed` on
  crash, `reporting` re-submits idempotently, purge ⇒ `dropped`, retry
  budget bounded.

## Waves and gates

| Wave | Tasks | Depends on | Gate (integrator-run) |
|---|---|---|---|
| R0 | skeleton + kernel (done by integrator) | — | offline build/test/clippy/fmt green |
| W1 | A1 wire, A2 config, A3 state, C2 runner | R0 | scoped tests + clippy + fmt |
| W2 | B1 client | A1, A2 | scoped integration tests green |
| W3 | B2 sync, C1 agent, D1 verdict | B1 (B2, D1), A3 + B1 (C1) | scoped tests green |
| W4 | D2 daemon + scheduler | all above | full `cargo test --offline --locked` + clippy + fmt |
| — | E1 docs (README, CONTEXT) | W4 | integrator review |

Server-side dependency is unchanged: live runs need DumpLedger AI1
(catalog/token/ETag), the feed needs AI2, live write-back needs AI3; until
then D1's local-verdict mode keeps the pipeline usable.

## Stage/milestone mapping

- **AN1** = A1 + A2 + B1 + B2 (sync and fetch against the read surface)
- **AN2** = A3 + C1 + C2 (agent pipeline, local-verdict mode)
- **AN3** = D1 live write-back + reconciliation, then D2 daemonization
