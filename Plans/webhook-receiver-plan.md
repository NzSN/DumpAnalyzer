# DumpAnalyzer webhook receiver plan

Status: ☐ pending — awaiting implementation authorization (2026-10-20).

Derived from the shipped ledger surface:
[`webhook-notifications.md`](../../dump-ledger/docs/webhook-notifications.md)
(WH1, deployed and verified on windows-dev 2026-10-20) and
[`webhook-admin-token-design.md`](../../dump-ledger/docs/webhook-admin-token-design.md)
(WH2). Ledger instance: `https://192.168.150.219:4080` at `444cf1b`,
dispatcher on, zero subscriptions. Admin token plaintext staged at
`~/.dump-ledger-webhook-admin-token` (mode 600) — move into the daemon
environment at rollout; never into the repo or logs.

Planning baseline: DumpAnalyzer `6d5d04c` (runner refinement-upgrade fix,
docs/qualification bundles committed).

## Purpose

Give the daemon a low-latency tap for new-dump events: the ledger POSTs
signed audit events (`AcceptDump` = "new dump available") to the daemon
instead of waiting for the feed follower's 5–30 s poll. The feed follower
remains the resumable truth; webhooks only accelerate discovery. Scheduler
stays `off`, write-back stays `off`; this plan changes neither.

## Design decisions

1. **One route**: `POST /webhooks` on the existing status listener
   (`src/http.rs`). Machine-to-machine callback, authorized by the
   per-subscription HMAC signature alone — not the UI action token.
2. **Verification before parsing**: `X-DumpLedger-Signature-256` is
   `sha256=<hex>` HMAC-SHA256 over the *raw* body keyed by the stored
   subscription secret; constant-time compare (same discipline as the
   existing action-token digest compare). Bad/absent signature → `401`;
   malformed JSON → `400`. Both are permanent failures the ledger records
   as `exhausted` after its retry budget — visible by design.
3. **Apply via the existing feed path**: the body *is* the feed `Event`
   object, so decode it as `EventFeedEntry` and hand it to
   `sync::apply_event`. Feed application is already idempotent, so
   redelivery (at-least-once) needs no extra dedupe state. Ack `2xx` only
   after the apply completes; an apply failure answers `500` and lets the
   ledger's backoff redeliver.
4. **Feed parity subscription**: register for the same action set the feed
   follower uses (`AcceptDump`, `RejectDump`, `BeginPurge`, `FinishPurge`,
   `SealUpload`, `PromoteObject`, `MarkQuarantined`), so tap and truth cover
   the same stream. The webhook never advances the feed cursor.
5. **Boot-time self-registration** (WH2 path, idempotent): with the
   webhook-admin bearer token, `GET /api/v1/webhooks`, reuse the entry whose
   `url` is ours, create only when absent. The signing secret exists only in
   the `201` create response, so: persisted in the keyed `secrets` table at
   creation; if a matching subscription exists but no local secret (e.g.
   state rebuilt), delete + recreate to obtain a fresh one (documented
   rotation path). Registration failure must not fail the daemon: log,
   back off, retry on a slow cadence; the feed follower carries the truth
   meanwhile.
6. **LAN bind is an explicit operator gate**: the ledger POSTs from
   windows-dev, so the listener must leave loopback
   (`DUMP_ANALYZER_HTTP_ADDR=0.0.0.0` or the WSL address). That exposes the
   read-only dashboard views to the LAN; action routes stay token-guarded,
   `/webhooks` stays HMAC-guarded. Rollout section below treats this as a
   conscious checkbox, not a default.

## Configuration additions (`src/config.rs`)

| Variable | Default | Meaning |
|---|---|---|
| `DUMP_ANALYZER_WEBHOOK` | unset (off) | `on` arms receiver + boot registration |
| `DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN` | — | WH2 bearer for list/create/delete; env-only, redacted like the analyzer token |
| `DUMP_ANALYZER_WEBHOOK_URL` | — | this daemon's externally reachable URL, e.g. `http://<lan-ip>:4180/webhooks`; required when on |
| `DUMP_ANALYZER_WEBHOOK_ACTIONS` | feed-follower set | optional override, bounded like the ledger's filter limits |

## Storage additions (`src/state.rs`)

Reuse the keyed `secrets` table (migration 2): keys
`webhook.subscription_id` and `webhook.secret`. No schema migration needed;
additive accessor pairs with tests. Existing secrets (analyzer token)
untouched.

## Waves

Delegation per repo convention: `general-purpose-flash`, one task per agent,
disjoint file ownership, `--offline --locked` gates, integrator-run wave
gates.

| ID | Task | Owns | Depends on | Status |
|---|---|---|---|---|
| W1 | Config knobs + secrets accessors | `src/config.rs`, `src/state.rs`, `tests/{config,state}.rs` | — | ☐ |
| W2 | Webhook-admin client: `listWebhooks` / `createWebhook` / `deleteWebhook` + strict wire types | `src/client.rs`, `src/wire.rs`, `tests/client.rs` | W1 (token config) | ☐ |
| W3 | Receiver route: raw-body HMAC verify, event decode, `apply_event`, ack mapping; redelivery + tamper tests | `src/http.rs`, `tests/http.rs` | W1 | ☐ |
| W4 | Boot wiring: registration task (list → reuse/create → persist secret → delete+recreate on missing secret), slow retry, shutdown; docs: README env section, `docs/analyzer-design.md` webhook note | `src/main.rs`/`src/scheduler.rs`, `README.md`, `docs/analyzer-design.md` | W2, W3 | ☐ |
| W5 | Integrator: full gates (`cargo test --offline --locked`, clippy `-D warnings`, `fmt --check`), then live proof below | — | W1–W4 | ☐ |

## Live proof (W5 checklist, against the deployed ledger)

1. Rollout: token file → daemon env (not logged), set
   `DUMP_ANALYZER_WEBHOOK=on`, `DUMP_ANALYZER_WEBHOOK_URL`, and the
   consciously-chosen `DUMP_ANALYZER_HTTP_ADDR`; restart the service.
2. Boot log shows registration; ledger-side `GET /api/v1/webhooks` (admin
   token) lists the daemon's URL.
3. Next real dump upload (or operator canary upload) ⇒ daemon log applies
   `AcceptDump` within one dispatcher tick; ledger
   `GET /api/v1/webhooks/:id/deliveries` shows `200`, zero retries.
4. Kill-restart the daemon: no re-registration (subscription reused), events
   continue.
5. Tamper probe: hand-POST with a wrong signature ⇒ `401`, delivery row
   records the failure.

## Boundaries / non-goals

- No scheduled analysis: webhook events update discovery only; claiming jobs
   stays manual while `DUMP_ANALYZER_SCHEDULER=off`.
- No guaranteed delivery and no wake-on-intake (ledger WH1 boundaries).
- The feed follower, cursor, and reconciliation are untouched; the webhook
   is additive.
- No change to write-back (`off`) or report publication (`localOnly`).

## Status

| Wave | Status |
|---|---|
| W1–W5 | ☐ pending authorization |
