These logs and binary layouts are authored deterministic parser fixtures. They
are not captures from a qualified real dump and do not prove debugger command
compatibility, PDB provenance on the analysis host, or a real root cause.

- `marked-av.log`: named sections, full access-violation record, saved AMD64
  context, a directly checkable null read, numbered stack with addresses/source.
- `tests/symbols.rs` constructs minimal matching/mismatching RSDS and MSF7 Info
  stream identities, including little-endian GUID fields and corrupt offsets.
- `tests/runner.rs` derives unavailable/truncated/oversized captures from the
  named log and checks explicit completeness states.
- `tests/assessment.rs` checks that valid citations cannot confirm an unsupported
  use-after-free claim and that inconsistent register evidence defeats the
  immediate-mechanism rule.
