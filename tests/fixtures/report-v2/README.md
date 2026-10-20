# Rich-report fixture inventory

Maintained fixture guidance reviewed against source
`6a19ea297bb219509c994780c96bdd6ce6c4bfab` on 2026-10-20. No fixture or
qualification test was executed during the initial source-only documentation review.

The authored logs and binary layouts in this directory are deterministic parser fixtures. They
are not captures from a qualified real dump and do not prove debugger command
compatibility, PDB provenance on the analysis host, or a real root cause.
The separate [qualification directory](qualification/README.md) retains the
controlled 2026-10-15 native acquisition and delivery evidence.

- `marked-av.log`: named sections, full access-violation record, saved AMD64
  context, a directly checkable null read, numbered stack with addresses/source.
- `tests/symbols.rs` constructs minimal matching/mismatching RSDS and MSF7 Info
  stream identities, including little-endian GUID fields and corrupt offsets.
- `tests/runner.rs` derives unavailable/truncated/oversized captures from the
  named log and checks explicit completeness states.
- `tests/assessment.rs` checks that valid citations cannot confirm an unsupported
  use-after-free claim and that inconsistent register evidence defeats the
  immediate-mechanism rule.

The maintained report contract is `src/report.rs`: schema version 2,
canonical JSON and a digest independent of the compact v1 projection. Both
`cdb-ssh` and `claude-cdb` use deterministic capture; the latter adds a
bounded evidence-only reasoner through a host that denies every tool request.
`tests/claude_runner.rs` uses fake host processes by default. The separately
ignored live reasoner test is not covered by those fake-host results. See
the [rich-report guide](../../../docs/rich-reports.md) for limits, provider
behavior and dated qualification boundaries.

Focused offline checks, from the repository root:

```sh
cargo test --offline --locked --test report --test runner --test symbols --test assessment --test claude_runner
```

This runs the selected test binaries with their default ignored-test policy;
it does not invoke the isolated SSH/CDB canary or the ignored live reasoner.

## Configured reasoner qualification — 2026-10-20

After the documentation review, a separately authorized run explicitly
selected the ignored evidence-only reasoner test at source/test revision
`f269ce82d2ac28e9ba77f7f393ffc231e639a164`. The live test passed 1/1 in
16.45 seconds through Claude Code CLI 2.1.300 and the configured gateway
`https://claude.jlcops.com/api/`. Selection alias `opus` produced the
CLI-reported model `deepseek-flash`; backend identity was not independently
attested, and this result does not qualify an Anthropic Claude model.

The recorded controls passed 10/10 fake-host tests, 21/21 preservation
checks and 20/20 independent review checks. All nine original evidence
entries and exception/context/stack/symbol/mechanism/completeness sections
were preserved; one accepted model assessment was added. The deterministic
mechanism remained `confirmed` and the underlying cause remained `unknown`.
No live denial challenge or instrumented tool-request count was recorded;
fake-host denial coverage is separate from that live result.

See the [dated receipt](../../../docs/qualification/live-reasoner-2026-10-20/README.md)
for authorization, isolation, failed official-endpoint attempt and proof
limits. Only the configured CLI/gateway reasoner subgate is closed; real
SSH/CDB acquisition, Ledger delivery, deployment and full P6 are outside this
run. The 2026-10-15 qualification README, manifest and payloads remain unchanged.

## Production rollout checkpoint — 2026-10-20

The [production rollout receipt](../../../docs/qualification/production-rollout-2026-10-20/README.md)
records deployment of the rebuilt analyzer application at `f269ce8`, retaining
manual operation, write-back off and `cdb-ssh`. The companion advanced from
`69eb3d3` to rich-report revision `7c2a51b`, excluding later WH1 work; migration
9 preserved existing data. This passed the deployment substep.

At that checkpoint, automatic approval review rejected the selected
real-report publication because explicit approval of the crash payload and
destination was missing; approval was pending. No canary publication or new
remote analysis had occurred, and this gate initiated no new CDB or model
calls. Production publication/read-back/restart canary qualification and
full P6 were still open. The earlier controlled-canary and configured-reasoner
evidence bundles remain unchanged.

## Approved production canary — 2026-10-20

After the user approved the exact real-report payload and destination, the
[production canary receipt](../../../docs/qualification/production-canary-2026-10-20/README.md)
records one accepted publication and idempotent replay under analysis ID
`analysis_06F9B90BAB5F449199FA9C9C93`. The 63,438-byte canonical JSON and
SHA-256 `d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb`
matched remote read-back, local reopen and the authenticated HTTP detail
after companion restart. Authenticated reads returned 200, unauthenticated
reads 401; compact v1 access and the prior analysis remained intact.

Only the approved analysis, full detail and audit event were added; all ten
table hashes matched across restart. This completes the P6 production
rollout and bounded publication/read-back/restart canary gates. It reused an
existing report without new CDB or model calls. The isolated publisher
reached `fullyDelivered`; the main daemon's five rich reports remained
`localOnly`, with automatic scheduling/write-back off and `cdb-ssh` retained.
The earlier evidence bundles and causality/provider qualification limits
are unchanged; wider automatic publication was not enabled.
