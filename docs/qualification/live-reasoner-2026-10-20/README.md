# Configured live reasoner qualification — 2026-10-20

**Passed for the production Claude CLI host through the configured gateway.**
The run used connection/model settings from `~/.claude/settings.json`, as
authorized by the user. Selection alias `opus` produced CLI init model
`deepseek-flash` through `https://claude.jlcops.com/api/`. This qualifies that
observed CLI/gateway path; it does not qualify an Anthropic Claude backend or
independently attest the gateway's backend implementation.

The source/test revision was
`f269ce82d2ac28e9ba77f7f393ffc231e639a164`. No application code, tests, user
settings, service configuration or deployment changed during this qualification.
The [manifest](manifest.json) pins the exported evidence and source inputs.

## Results

| Check | Result | Evidence |
| --- | --- | --- |
| Actual ignored live test | 1 passed, 0 failed; 16.45 seconds | [Test log](attempts/02-configured-gateway/live-test.log), [execution metadata](attempts/02-configured-gateway/execution.json) |
| Existing offline fake-host controls | 10 passed, 0 failed | [Control log](offline-controls.log) |
| Deterministic preservation comparison | 21/21 checks passed | [Comparison](attempts/02-configured-gateway/comparison.json), [comparator](reference/compare.py) |
| Independent source/receipt review | 20/20 checks passed | [Review](attempts/02-configured-gateway/independent-review.json) |
| Accepted model evidence | Exactly one present, untruncated `assessment-model` entry | [Live capture](attempts/02-configured-gateway/live-capture.json) |
| Original capture | All nine evidence entries and exception, context, stack, symbols, completeness and deterministic mechanism preserved | [Offline baseline](reference/baseline.json) |
| Cause qualification | Underlying cause `unknown`; immediate mechanism `confirmed` | [Qualification summary](attempts/02-configured-gateway/qualification.json) |

The live test is
`tests/claude_runner.rs::live_reasoner_over_synthetic_fixture_without_remote_dump_transfer`.
It calls the production collector and reasoner with an authored access-violation
fixture and an in-process fake transport. The transport returns fixture bytes;
it does not invoke SSH, SCP or CDB. The reasoner launches the real Claude Code CLI
and performs the external model request. No customer dump was used.

## Configuration and execution

The existing host isolation arguments were retained: duplex `stream-json`,
permission control over stdio in default mode, empty enabled tools, strict empty
MCP configuration, hooks disabled, empty setting sources, and no session
persistence. Only the connection/model environment values were imported from the
user profile. Credential values are absent from this bundle. Telemetry, error
reporting and nonessential traffic were disabled for the child.

The [launch record](attempts/02-configured-gateway/claude-launch.json) records the
actual arguments and executable. Its exec-only recorder writes metadata, then
replaces itself with the real CLI while retaining the PID and unmodified streams.
CLI 2.1.300 resolved to `/home/nzsn/.local/share/claude/versions/2.1.300`, SHA-256
`674deba0bba9aee479f4503c438b49303b6fdd304b9a471b14977aaec5215453`.
Child PID `482105` had exited after the test.

The earlier [official-endpoint attempt](attempts/01-official-no-login/attempt.json)
failed authentication with `Not logged in · Please run /login` and produced no
accepted assessment. That failure remains recorded. The user's subsequent
instruction, `with settings at ~/.claude`, authorized the configured-gateway
attempt in response to the named gateway/payload choice; see its
[authorization record](attempts/02-configured-gateway/authorization.json).

## Evidence and reproduction

`reference/prepared-capture.json` is the exact 6,054-byte typed JSON prepared for
the reasoner, SHA-256
`7365cb3338a2b643d367bb096843710a0bd991b63e8004908690ed00b197514b`.
The prompt also contains the fixed production assessment instructions/schema.
`attempts/02-configured-gateway/live-capture.json` is the accepted 17,257-byte
receipt, SHA-256
`d20cd31562099ceeb74e912fe971fda1bc0779033977b32a879cba20c2ad0110`.

The [reference manifest](reference/manifest.json) records the separately built,
offline deterministic baseline. All 175 registry packages matched the root lock
file by version, source and checksum; see
[lock verification](reference/lock-verification.json). Both `reference/main.rs`
and `reference/src/main.rs` contain the same helper source: the former preserves
the artifact name in that manifest, and the latter preserves its Cargo layout.

From this receipt directory, the preserved comparison can be repeated without a
model call:

```sh
python3 reference/compare.py attempts/02-configured-gateway/live-capture.json
```

The actual test command was run from the pinned DumpAnalyzer checkout:

```sh
cargo test --offline --locked --test claude_runner \
  live_reasoner_over_synthetic_fixture_without_remote_dump_transfer \
  -- --ignored --exact --nocapture
```

[The execution wrapper](run-configured-qualification.py) and
[launch recorder](attempts/02-configured-gateway/bridge/claude) are exact execution
snapshots with the original machine and temporary paths. Repeating a live run
requires fresh output paths, the intended current provider credentials, and an
explicit receipt path via `DUMP_ANALYZER_LIVE_TEST_OUTPUT`; the recorder refuses
to overwrite its launch record. The original files are evidence, not portable
launch tooling. A new run must have a separate receipt and its own source/model
identity; generated model text need not repeat byte for byte.

## Qualification boundaries

There was no live tool-denial challenge and no instrumented live tool-request
counter. The launch policy was checked from the actual arguments; denial behavior
was exercised separately by the fake-host controls. The existing live receipt
omits the runner outcome, so direct cross-receipt outcome equality is not claimed.

Structural validation and preserved citations do not prove every model narrative.
The independent review found that the second hypothesis attributes a null
module-RVA field to `modules` evidence although the field belongs to the typed
stack. The assessment remains an unconfirmed explanation with missing evidence
and next checks; this run does not establish causal correctness.

This synthetic run does not qualify real dump acquisition, PDB matching,
remote-process termination, persistence/restart, DumpLedger publication,
companion availability, service deployment or wider write-back. Full P6 and the
companion rollout remain separate gates in the
[implementation plan](../../../Plans/rich-report-implementation-plan.md).
The 2026-10-15 controlled-canary receipts, manifest and hash-pinned README remain
byte-for-byte unchanged; this dated addendum does not replace them.
