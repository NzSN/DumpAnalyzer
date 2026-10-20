# Production rollout checkpoint — 2026-10-20

**Both services were upgraded and passed their deployment checks. The real-report
delivery canary is blocked pending explicit payload/destination approval; full P6
is not complete.** See [gate status](summary.json) and the
[publication approval record](publication-approval.json).

## Deployed state

| Component | Verified checkpoint |
| --- | --- |
| Local WSL analyzer | Application source at `f269ce82d2ac28e9ba77f7f393ffc231e639a164`; rebuilt binary SHA-256 `cc284ecacd1f03d5ed4e5ae8b9659e082139d7b94e2135eb78ccc4088d5541ff`; systemd PID `495042`; version `0.2.0`; HTTP `127.0.0.1:4180`. |
| Analyzer mode | `cdb-ssh`, scheduler off, write-back off; existing configuration unchanged. Five canonical reports, secrets, cache and settled records preserved. |
| Windows DumpLedger | Upgraded `69eb3d3ad177421f8b28697ca5e9a95254c68530` to its direct child `7c2a51b51d2638c462778c17fe9421632297b236`, the rich-report release only. Later WH1/webhook work was excluded. |
| Companion runtime | Node `24.21.0`; backend PID `42476` on loopback ports 4081/4082; existing HTTPS proxy PID `63648` on 4080 unchanged. |
| Companion database | Missing migration 9 applied despite already-applied migration 10. Versions 1–10 now present; integrity and foreign keys clean. All eight pre-existing data-table hashes unchanged. |
| Companion inventory | 128 dumps, 33 analyses, 20 customers, 18 cases, 13 modules, 13 symbol artifacts, 30 grants, 941 audit events; **zero** `analysis_details` rows. |

The [deployment receipt](companion/deployment.json) verifies all 501 shipped
build files against the [build manifest](checks/build-manifest.json), old table
hashes, configuration, unrelated `.msf-diag.mjs` and unchanged proxy. The
[read-only audit](companion/post-deployment-read.json) confirms no report was
published. The analyzer's [deployment receipt](analyzer/deployment.json) and
[detail check](analyzer/http-detail.json) preserve its five-report baseline and
the selected report's 23 frames, 11 evidence entries and `unknown` origin.

The production HTTPS endpoint was checked using the configured CA and existing
analyzer bearer credential. Authenticated `/api/v2/capabilities` returns 200,
schema 2, a 524,288-byte report bound and 1,048,576-byte request bound;
unauthenticated access returns 401. The selected dump's prior analysis list is
unchanged. These [checks](http/deployed.json) also passed after the completed
deployment SSH connection was closed. They establish read/authentication and
capability behavior, not successful production publication.

## Release checks and backups

| Gate | Actual result |
| --- | --- |
| Analyzer | 356 tests passed; 2 live tests ignored under the normal policy; Clippy with warnings denied and rustfmt passed. |
| Exact companion candidate | Unit 153/153, integration 156/156, MBT 28/28; separate HTTP contracts 173/173. Typecheck, model-interface checks and production build passed. |
| Migration on a consistent copy | Versions 1–10, empty new detail table, all eight old data-table hashes preserved, integrity/FK checks passed on Windows. |
| Live migration and health | Same preservation result; exact native backend identity owns both loopback ports; existing proxy retained. |

The [migration proof](companion/migration-proof.json), test logs under `checks/`
and [build environment](checks/build-environment.json) record the exact inputs.
The companion candidate's 361 tracked source files were unchanged by build/test.
Its dependencies and lockfile match the previous deployment. Current local
DumpLedger work, including unrelated uncommitted webhook administration work,
was preserved. Analyzer application code was unchanged; one existing rustfmt
layout error in `tests/runner.rs` received a formatting-only correction.

Private durable checkpoints are:

- Local: `~/.local/state/dump-analyzer/backups/p6-production-20261020T075807Z`
  — online/stopped SQLite backups, prior executable, unit/environment copies,
  selected canonical report and execution receipts.
- Windows: `D:/Services/dump-ledger-runtime/backups/p6-production-20261020-verified`
  — online/stopped SQLite backups, migration copy, previous build, launch
  configuration/certificates and deployment receipts.
- Staged Windows release:
  `D:/Services/dump-ledger-runtime/releases/p6-7c2a51b-20261020` — complete tested
  build and manifest for verification/recovery.

Credential values, private environment/certificate keys, SQLite files and the
real canonical report are excluded from this repository receipt.

## Remaining publication gate

The prepared canary is one existing completed report, not a new analysis:

```text
reportId: r2_1e11b6bae3ee7e131c472a6b8b87e07328bc8375177ed11bcc3009a736cc07d8
dumpId: dump_4142A5B57E5A4C01A1C47C883E
canonical bytes: 63438
canonical SHA-256: d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb
destination: https://192.168.150.219:4080/api/v2/dumps/dump_4142A5B57E5A4C01A1C47C883E/analyses
```

It contains real exception, register/context, stack, symbol and debugger
evidence. Automatic approval review rejected launching the selective publisher
because the broad rollout request did not explicitly authorize this exact
payload and destination. **The rejected command did not execute.** A specific
approval question was presented; no approval had arrived at this checkpoint.

Once explicitly authorized, the prepared production Rust publisher can post
only that report using an isolated local store, repeat the request to prove
idempotency, retrieve the exact full detail/digest, and reopen its local store.
A subsequent bounded companion restart and authenticated read-back must prove
production durability while preserving unrelated rows. These gates remain
unexecuted. The global production outbox must remain off during this canary:
enabling it would attempt other pending local reports too.

There was no new dump transfer, CDB execution, external model call, production
report publication or catalog-wide reanalysis in this rollout. The separate
[configured live reasoner receipt](../live-reasoner-2026-10-20/README.md) retains
its original CLI-reported `deepseek-flash` identity and scope; this deployment
does not qualify an Anthropic Claude backend.

## Recovery and execution boundaries

The existing Windows backend was stopped with targeted `taskkill /F` after
quiet-intake, native creation-identity and backup checks. Its exit was confirmed
before the stopped-state backup and build swap. The new launcher records native
PID, creation time and command hash; health must belong to that process.
Rollback terminates that tracked child even before it listens and refuses to
swap files if its exit is uncertain. The isolated no-socket child check passed
before deployment. This was a controlled Windows process termination, not a
claim of graceful application shutdown.

Files under `execution/` are exact machine-specific execution snapshots. Their
revision/PID/hash guards and exclusive receipt paths intentionally prevent
blind reuse. They are not portable or idempotent deployment tooling. Earlier
preparation corrections and the pre-execution review are recorded in
`summary.json`; no production changes occurred during those failed preparations.

Rollback uses the saved executable/build and configuration with a freshly
verified database state. Migration 9 is additive and the new table is currently
empty. Preserve any later writes before recovery; restoring an old database
alone must not discard subsequent intake/audit/vault changes. After rich detail
is published, preserve native database/vault backups: the older transfer format
does not preserve rich detail, and the upgraded server deliberately blocks
detail-carrying v1 exports.

The [implementation plan](../../../Plans/rich-report-implementation-plan.md)
retains the bounded-canary gate before wider reanalysis/write-back. The
2026-10-15 evidence and the earlier 2026-10-20 reasoner bundle remain unchanged.
