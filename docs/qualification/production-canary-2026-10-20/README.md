# Approved production canary — 2026-10-20

**Passed: P6 production rollout and the selected single-report delivery canary.**
The user explicitly approved the report and production destination after the
earlier automatic-review rejection. Publication, idempotent replay, exact
read-back, local publisher reopen and a native companion restart all passed.
Scheduling and global write-back remain off.

The [summary](summary.json) records each completed gate. The
[earlier deployment checkpoint](../production-rollout-2026-10-20/README.md)
retains its original then-pending status and evidence; this receipt closes that
checkpoint's publication/read-back/restart gate.

## Approved report and results

```text
reportId: r2_1e11b6bae3ee7e131c472a6b8b87e07328bc8375177ed11bcc3009a736cc07d8
analysisId: analysis_06F9B90BAB5F449199FA9C9C93
dumpId: dump_4142A5B57E5A4C01A1C47C883E
canonical bytes: 63438
canonical SHA-256: d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb
destination: https://192.168.150.219:4080/api/v2/dumps/dump_4142A5B57E5A4C01A1C47C883E/analyses
```

| Check | Observed result |
| --- | --- |
| Specific authorization | User replied `approve` to the named single report, canonical size/digest, destination and bounded canary. [Approval](approval.json). |
| Production Rust publisher | One report accepted; full-delivery acknowledgement; exact replay returned the same analysis ID; canonical JSON/digest matched; isolated local store reopened successfully. [Publication](publication.json). |
| HTTPS before restart | Authenticated detail GET 200; all canonical bytes/digest identical; no-auth GET 401; v1 list remained compact; prior analysis unchanged and exactly one analysis added. [Read-back](read-back.json). |
| Post-publication checkpoint | Online and stopped-state backups include the accepted detail. Every old row preserved; only one analysis, one detail and one `RecordAnalysis` audit event added. [Durability proof](companion/durability.json). |
| Native restart | Verified backend PID `42476` exited; same tested build restarted as PID `51868`. Both loopback ports belong to that native creation identity. Proxy PID `63648` unchanged. |
| State across restart | All ten post-canary table hashes matched exactly; canonical detail survived; integrity/FK checks passed; no database restored. [Final audit](companion/final-state.json). |
| HTTPS after restart | Same analysis ID and all 63,438 canonical bytes/digest; authenticated 200, unauthenticated 401; compact list/prior analysis preserved. Also passed after the completed launcher SSH connection was closed. [Read-back](read-back-after-restart.json), [connection closure](companion/connection-closure.json). |
| Local analyzer | Active PID `495042`; five canonical reports, secrets, cache and settled records unchanged; same binary/configuration and `cdb-ssh`, scheduler-off/write-back-off settings. [Local proof](analyzer/final-state.json). |

The selected report already existed locally. The production
`report-delivery-canary` example used an isolated SQLite store so no other local
report could be published. That store records `fullyDelivered`. The live
analyzer's five reports retain their unchanged `localOnly` delivery policy while
global write-back is off; the accepted production report is independently bound
to the analysis ID and digest above.

## Preservation and deployed identity

| Table | Before approved publication | After publication and restart |
| --- | ---: | ---: |
| `dump_analyses` | 33 | 34 |
| `analysis_details` | 0 | 1 |
| `audit_events` | 941 | 942 |
| `dumps` | 128 | 128 |
| `customers` | 20 | 20 |
| `cases` | 18 | 18 |
| `modules` / `symbol_artifacts` / `upload_grants` | 13 / 13 / 30 | 13 / 13 / 30 |

Pre-existing rows were compared individually against the pre-publication
backup. All post-publication tables, including migration metadata and full
detail, were then compared by hash across restart. The only allowed additions
were the three explicitly listed canary rows.

The companion remains at rich-report revision
`7c2a51b51d2638c462778c17fe9421632297b236`; all 501 deployed build-file hashes
matched the earlier tested manifest. Migrations 1–10 and existing configuration
were preserved. The local analyzer application remains at `f269ce8`, binary
SHA-256 `cc284ecacd1f03d5ed4e5ae8b9659e082139d7b94e2135eb78ccc4088d5541ff`.
No application or test changes were made during this approval wave. The earlier
release test results remain in the deployment checkpoint; this wave exercised
the actual production integration.

Post-publication recovery checkpoints are retained on Windows:

```text
D:/Services/dump-ledger-runtime/backups/p6-production-20261020-verified/post-canary-online.sqlite
D:/Services/dump-ledger-runtime/backups/p6-production-20261020-verified/post-canary-stopped.sqlite
```

Recovery must preserve the accepted report and any later writes. This operation
did not restore a database or run older transfer tools. Native SQLite/vault
backups remain necessary because the old transfer format cannot carry rich
detail. Files under `execution/` are machine-specific snapshots with exclusive
checkpoint/PID guards; they are not portable rerunnable deployment commands.

## Scope

This closes the bounded production rollout and canary in
[plan §12](../../../Plans/rich-report-implementation-plan.md). It does not enable
automatic scheduling, wider reanalysis or global write-back. No new CDB
acquisition, raw dump transfer or model call occurred. The preserved assessment
remains `unknown`; successful delivery is not evidence of causal truth. The
earlier configured reasoner qualification retains its CLI-reported
`deepseek-flash` scope and does not attest an Anthropic Claude backend.

The [manifest](manifest.json) pins this metadata-only bundle. Raw customer report
contents, SQLite databases and credential values are excluded. The historical
2026-10-15 evidence and both earlier 2026-10-20 bundles remain byte-for-byte
unchanged.
