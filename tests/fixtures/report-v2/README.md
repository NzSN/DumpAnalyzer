# Rich-report fixture inventory

Maintained fixture guidance reviewed against source
`6a19ea297bb219509c994780c96bdd6ce6c4bfab` on 2026-10-20. No fixture or
qualification test was executed during this documentation review.

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
behavior and the remaining live qualification boundary.

Focused offline checks, from the repository root:

```sh
cargo test --offline --locked --test report --test runner --test symbols --test assessment --test claude_runner
```

This runs the selected test binaries with their default ignored-test policy;
it does not invoke the isolated SSH/CDB canary or the ignored live reasoner.
