# Phase 2 — live-readiness tasks

Historical phase-two task plan and 2026-10-14 completion receipt. The
baseline gaps described in R1, R3 and R4 were the reasons for that wave;
they are not outstanding gaps in the current implementation. The dated
gate counts below are retained without rerunning them. Documentation review
on 2026-10-20 used source `6a19ea297bb219509c994780c96bdd6ce6c4bfab` only.

Current navigation: [README](../README.md),
[architecture](../docs/architecture.md),
[analyzer design](../docs/analyzer-design.md) and
[rich-report workflow](../docs/rich-reports.md). The [field-run receipt](field-run.md)
records the separate 2026-10-14 live exercise.

Derived from the state after phase 1 (all tasks ●, 218 tests green) and the
server-side landing of AI1–AI3 in dump-ledger at `98e484c` +
`docs/analyzer-guide.md`. Same delegation conventions as
[`rust-implementation-tasks.md`](rust-implementation-tasks.md): disjoint file
ownership, `--offline --locked` gates, integrator-run wave gates.

| ID | Task | Agent | Owns | Depends on | Status |
|---|---|---|---|---|---|
| R1 | Continuous local-report replay sweep (boot-only → periodic while running) | d1_verdict | `src/verdict.rs` (additive), `tests/verdict.rs` | — | ● |
| R2 | `POST /-/rescan` manual catalog re-scan (token-guarded) | b1_client | `src/http.rs`, `tests/http.rs` | — | ● |
| R3 | Server-side feed action filter + vocabulary pin to the guide | b2_sync | `src/sync.rs`, `tests/sync.rs` | — | ● |
| R4 | Byte-cache size cap enforcement (LRU by `last_used_at`) | c1_agent | `src/agent.rs`, `src/state.rs` (additive), `tests/agent.rs` | — | ● |
| R5 | Integrator wiring + docs: scheduler.rs wires R1/R2; README, `docs/architecture.html`, `docs/trigger-paths.html` refresh; `Plans/field-run.md` checklist (no execution) | integrator | — | R1–R4 | ● (2026-10-14 receipt below) |

## R1 — Continuous local-report replay

At the phase-one baseline, boot reconciliation (`reconcile_on_boot`)
replayed `local_reports.posted = 0` only at startup; a long-running daemon
with the route appearing mid-run waited until the next boot. This task added
a periodic sweep. Current delivery is handled independently by the
write-back-enabled replay loop in `src/scheduler.rs`; full rich-report
delivery has its own state, described in the rich-report guide.

- **Deliver**:
  1. `pub async fn replay_pending(client, store, config) -> Result<ReplayReport>`
     in verdict.rs (extracted from/reused by `reconcile_on_boot`'s sweep —
     keep behavior identical, including the route-absent fast path).
  2. Scheduler integration is the integrator's (R5); provide the function +
     tests only.
  3. Tests: pending reports replay when the route appears, none pending →
     no requests, route still absent → still pending, replay failure keeps
     the row pending.
- **Acceptance**: `cargo test --offline --locked verdict` green; clippy/fmt.

## R2 — `POST /-/rescan`

- **Deliver** (http.rs owns the route; the scheduler wiring is R5):
  1. `RescanDeps` held by `UiContext` (client + store + config handles),
     attached via `with_rescan(...)`. Route `POST /-/rescan`, same bearer
     guard as `/-/analyze`. Runs `sync::initial_scan` inline and returns
     `200 {"inserted": n}`; `503` on transient failure. The 401/405 matrix
     stays consistent with `/-/analyze`.
  2. Dashboard: a "Rescan now" form next to the analyze form, rendered only
     when deps are wired.
  3. Tests: 401 without/wrong token, 200 with counts, 405 on GET.
- **Acceptance**: `cargo test --offline --locked http` green; clippy/fmt.

## R3 — Feed action filter + vocabulary pin

At the phase-one baseline, the feed passed no `actions` filter (all events
over the wire, all classified locally by keywords). This task pinned the
dump-relevant vocabulary from the server guide.

- **Deliver**:
  1. `follow_feed` passes `actions` = `AcceptDump, RejectDump, BeginPurge,
     FinishPurge, SealUpload, PromoteObject, MarkQuarantined` (intake family
     stays: the `get_dump` gate is the real guard; cost of a generous family
     is one lookup). Keep the keyword classifier as the local safety net for
     unknown future actions — but only when the server ignored the filter.
  2. A comment mapping each filtered action to the guide's table; the
     classifier's unit test gains the exact guide spellings.
  3. Tests: the wiremock feed asserts the `actions` query is sent verbatim;
     filtered pages still drive upsert/drop identically.
- **Acceptance**: `cargo test --offline --locked sync` green; clippy/fmt.

## R4 — Byte-cache cap enforcement

At the phase-one baseline, `DUMP_ANALYZER_BYTE_CACHE_MAX_BYTES` was parsed
but not enforced. This task added eviction to the content-addressed cache;
a miss refetches the bytes. `src/agent.rs` and `src/state.rs` contain the
current cap enforcement and LRU bookkeeping.

- **Deliver**:
  1. `state.rs` (additive): `CacheIndex::total_bytes() -> u64` and
     `CacheIndex::evict_lru(excess) -> Vec<(sha256, path)>` (oldest
     `last_used_at` first; never evict a pinned in-flight fetch).
  2. `agent.rs`: after every successful `write_cache`, enforce the cap —
     evict LRU entries (delete file + index row) until under budget; the just
     written entry is never evicted in the same call.
  3. Tests: cap enforcement with three small entries (write third → first
     evicted), in-flight pin survives, evicted bytes refetch correctly
     (304/200 path), index/file consistency after eviction.
- **Acceptance**: `cargo test --offline --locked agent` green; clippy/fmt.

## Wave gate (integrator)

`cargo test --offline --locked` + clippy `-D warnings` + `cargo fmt --check`
after R1–R4 land, then R5 wiring and docs.

**Wave result (2026-10-14):** R1–R4 all ●; integrator gate green — 240 tests,

**Scope actions (2026-10-14):** `analyze_case`/`analyze_customer` on the `Analyzer` trait + token-guarded routes/forms; 3 component + 1 route tests; gate 247/0, clippy+fmt clean.

**Modern UI (2026-10-14):** static shell + fetch-driven live updates (`src/dashboard.html`, zero new deps), `/api/capabilities`, client-side theming/filtering/actions; stale-server-render tests rewritten; gate 246/0, clippy+fmt clean.

**Token persistence (2026-10-14):** latest-used analyzer token stored in the state DB (migration 2, `secrets` table); boot resolution env→store with the source logged; empty form token uses the stored one; gate 249/0, clippy+fmt clean; live-verified both boots.

**Token via Web UI (2026-10-14):** `POST /-/store-token` + dashboard card; ledger-probe guard (rejects what the server rejects); live digest update via RwLock; 3 new tests; gate 252/0; live-verified store + rejection against the LAN instance.
0 failed, clippy `-D warnings` + rustfmt clean. R5 done: `/-/rescan` wired in
the scheduler, 60 s idle replay sweep, docs refreshed.
