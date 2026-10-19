# Controlled Windows x64 rich-report canary

Prepared on 2026-10-15. This directory contains source, scripts, bounded debugger logs, and identity metadata. Dump, executable, and PDB binaries remain outside the repository.

The fixture deliberately reads a null pointer at `null-read.cpp:12`. Variant 1 produced the dump. Variant 2 produces a different PDB identity for a rejection check. Both are tiny `/Od /Zi /GS- /NODEFAULTLIB /ENTRY:main /SUBSYSTEM:CONSOLE /MACHINE:X64` programs. The CRT-free entry point avoids changing the analysis host's incomplete `LIB` environment. `/PDBALTPATH:null-read.pdb` prevents an embedded absolute matching-PDB path from defeating the mismatch check.

## Artifact locations

- Remote directory: `D:/da/rich-report-canary-20261015`.
- Remote dump: `D:/da/rich-report-canary-20261015/null-read.dmp`.
- Matching symbols: `D:/da/rich-report-canary-20261015/matching`.
- Deliberately wrong symbols: `D:/da/rich-report-canary-20261015/mismatched`.
- Verified local binary copies: `/tmp/rich-report-canary-20261015`, with the same subdirectories.
- Dump SHA-256: `31994b27ca9885d54dae6a6f6c0a7fa56c0a4c99e2523a71fb15ed57969a146b` (7,989,357 bytes).

`artifact-identities.json` records all EXE/PDB hashes and directly parsed PE, minidump, and PDB Info-stream identities. The dump module's RSDS record, matching EXE CodeView record, and matching PDB Info stream agree on **B567793D-D929-4C92-A4DA-43554EBE240A / age 2**. The wrong PDB is **6D9F3521-DD5B-4888-AD83-03E9EB56A6FB / age 1**. Image timestamp and size are `0x6ad0932e` and `0x5000`.

## Tools and capture

CDB is `10.0.29617.1000 AMD64` from `C:/Program Files/WindowsApps/Microsoft.WinDbg_1.2606.22001.0_x64__8wekyb3d8bbwe/amd64/cdb.exe`. MSVC is `19.44.35227.0`; linker is `14.44.35227.0`. The host reports Windows 10 build 19045 x64.

`prepare-windows.sh` compiles both variants and starts only the controlled executable under CDB. Its first-chance access-violation handler runs `.dump /ma` and terminates the controlled process. `capture.log` preserves that session. The live session's `.ecxr` reports no saved exception context at that instant; the saved dump contains a verified exception stream and AMD64 context, and `.ecxr` succeeds when the dump is reopened.

`verify-windows.sh` opens only that saved dump with each symbol directory. `verify-matching.log` records private symbols and lines, `ReadNull -> CanaryEntry -> main`, and `null-read.cpp(12)+0x5`. `verify-mismatched.log` explicitly records `mismatched pdb`, rejects it, and retains raw `null_read+offset` frames.

The preserved exception is `0xc0000005` with parameters `[0, 0]` (read from null). The instruction is `8b 00`, `mov eax,dword ptr [rax]`; saved `RAX` is zero and `RIP` is `0x00007ff7c281100a`. Addresses remain strings in metadata. No claim is made about unrelated crashes or customer dumps.

## Rechecking identities

With the binary copies available:

```sh
python3 tests/fixtures/report-v2/qualification/inspect-artifacts.py /tmp/rich-report-canary-20261015
```

The script reads binaries without changing them. It checks matching GUID/age across dump, EXE, and PDB; proves the deliberate mismatch; and checks the exception parameters and null register.

## Integrated qualification receipt

The actual SSH/CDB runner captured `actual-matching-report.json`: exception/context and five native frames, independent matching GUID/age, and source lines 12/14/15. The deliberately wrong PDB retained exception/raw addresses without qualified application symbols (`actual-mismatched-report.json`). The immediate null-read mechanism is confirmed; the underlying cause remains unknown.

The real Rust client published the 24,259-byte canonical report to an isolated Node DumpLedger and verified exact read-back, idempotent replay, local reopen and service restart. One analysis, one detail and one audit event survived repeated replay. The actual dashboard rendered that stored report using one lazy detail GET; mobile and Back checks passed with no POSTs. Both isolated services exited cleanly. Receipts are in `integration-receipt.json`, `actual-browser-receipt.json` and the `ledger-*.json` files.

The corrected live Claude reasoner test remains unrun because automatic approval review rejected external transmission of fixture evidence without explicit user authorization. Fake-host tests pass; the initial actual host started and recorded its model, but its old structured-output path failed while preserving deterministic evidence. Production services and databases were not upgraded.

## Local deployment migration dry-run

`local-migration-receipt.json` records a read-only online backup of `/tmp/da-field/state/analyzer.sqlite` and migration of a private copy using the compiled current `Store::open`. The production database was never passed to writable Rust code; the helper rejects paths outside its private canary directory and requires the basename `dryrun.sqlite`.

The rollback backup and migrated copy are under `/tmp/dumpanalyzer-rich-migration-canary-5tmdan8h` (directory mode `0700`; both database files `0600`). The schema advanced from migrations `[1,2,3]` to `[1,2,3,4]`. All original table columns, row counts, and hashes of sorted typed rows were preserved, including secrets, cursors, cache entries, queued/settled identities, and reports. Only aggregate hashes appear in the receipt; no token or row values are recorded. Migration ledger comparison covers its original versions; version 4 is the expected addition.

All **34** existing reports received unique, independently verified stable legacy IDs. The new `report_details` table is empty, both integrity checks passed, and repeating `Store::open` left the migrated database bytes unchanged. A final read-only snapshot of the source matched the backup snapshot. This proves the migration on that consistent copy; production migration and restart remain unperformed.
