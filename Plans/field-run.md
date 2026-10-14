# Field run — DumpAnalyzer against the LAN DumpLedger

Target: `https://192.168.150.219:4080` (windows-dev `DESKTOP-6DKB5JD`).
Discipline: the dump-ledger deployment runbook (backup `ledger.sqlite` before
any restart; dry-run migrations on a copy; verify health + symbol hash after).

## Checklist

(2026-10-14: all steps executed; evidence below.)

## Field findings that changed the code

1. **TLS**: the proxy's self-signed cert had `CA:TRUE` and served as the
   end-entity cert; rustls/webpki rejects that (`CaUsedAsEndEntity`) where
   OpenSSL tolerates it. Fixed server-side: minted a proper end-entity cert
   (`proxy-server-cert.pem`, CA:FALSE, EKU serverAuth, same SANs) signed by
   the existing CA, pointed `proxy.mjs` at it (rollback: `proxy.mjs.bak-*`
   plus the original pair), restarted the proxy only. Our client pins the CA
   PEM — unchanged. (reqwest `from_pem_bundle`, never `from_pem`: an empty
   bundle must fail fast, not silently trust nothing extra.)
2. **Remote shell**: the box's SSH default shell is git-bash, which mangles
   `cmd /c` (`/c` → `C:\`). Both runners now use POSIX built-ins
   (`mkdir -p` / `rm -rf`) with `C:/…` → `/c/…` path conversion
   (`runner::bash_path`); CDB itself is invoked directly (no leading-slash
   args), which git-bash converts correctly for the native exe.

## Evidence (2026-10-14)

- Token auth: bogus → 401, real → 200 (`/api/v1/events`).
- On-demand `f(dumpId)`: `POST /-/analyze` for `dump_7AC2AAB6531543D18F646FAE2B`
  → 200 in 8.6 s, report `completed` (no stored exception record at
  0x00007ff67e57abb2 in lceda_pro; missing symbols lceda_pro, ntdll).
- Scheduled write-back: `dump_048B10C302A4460D8A1FC75088` →
  `analysis_434D8028B9FB44F2A5E090F5FA` (completed, AV 0xc0000005 in
  lceda_pro) listed by `GET …/analyses`; `RecordAnalysis` event on the feed.
- Clean full sweep running: 113 available dumps discovered.


1. ☑ Pre-flight: `/health` reachable; analyzer routes exist
   (`GET /api/v1/events` without a token → 401 with the error envelope proves
   the route is deployed; a bare 404 means the server predates `98e484c`).
2. ☑ If the server predates AI1–AI3: redeploy per the runbook (backup →
   migrate copy → integrity check → restart → verify).
3. ☑ Fetch the TLS cert `D:\Services\dump-ledger-runtime\proxy-cert.pem` from
   windows-dev → `DUMP_ANALYZER_TLS_CA_CERT` (pin, never disable verification).
4. ☑ Generate the analyzer token (`openssl rand -hex 32`); configure only its
   sha256 (`DUMP_LEDGER_ANALYZER_TOKEN_HASH`) on the server; restart; verify
   the same request flips 401 → 200. The token goes to the local env only.
5. ☑ Runner: `cdb-ssh` with `DUMP_ANALYZER_SSH_TARGET=windows-dev` (CDB +
   symcache on the box; the box already trusts the proxy cert for symsrv).
6. ☑ Run: `DUMP_ANALYZER_BASE_URL=https://192.168.150.219:4080` + token +
   cert; watch the status UI; jobs must flow discovered → done.
7. ☑ Evidence: server `GET /api/v1/dumps/:id/analyses` lists the reports;
   `RecordAnalysis` events appear on the feed; UI shows them.
8. ☐ Rollback: stop the daemon; the server-side token hash removal +
   restart restores pre-field-run behavior. Analyzer state dir is disposable.
