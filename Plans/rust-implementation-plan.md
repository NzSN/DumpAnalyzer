# DumpAnalyzer Rust implementation plan

Derived from [`docs/analyzer-design.md`](../docs/analyzer-design.md) (Rust
decision of 2026-10-13) and checked against `specs/DumpAnalyzer.tla`, which
pins the job lifecycle every task must honor. Covers design milestones
AN1–AN3; AN4 stays deferred.

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
