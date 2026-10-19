# Local DumpAnalyzer deployment — 2026-10-15

Deployed **0.2.0** at [http://127.0.0.1:4180](http://127.0.0.1:4180), verified 2026-10-15T09:45:53.237320+00:00. PID `355896`. The release is built from the rich-report working tree on baseline `0bb92ae`; it has not been committed or pushed.

- Running executable SHA-256: `b7e7a833ba340c1966a27ed86ea638f466f4f2458724f7391c615d49711ec4a8`.
- Source manifest digest: `1f2b56505a3b06ead00a475a20357c2fbc7644bcc2241098a9319fa06b94c787`.
- SQLite migration **3 → 4** passed on a fresh stopped-state copy before restart.
- **34 reports**, existing archive/cache records and saved credentials were preserved and compared by original-column hashes; integrity is `ok`.
- The active queue is empty. **79 old-profile discoveries** are retained; **113 current-profile candidates** are available for explicit analysis and do not appear in Jobs.
- Automatic scheduling and write-back remain **off**; runner remains **cdb-ssh**.
- API verification and **12 GET-only browser checks** passed, including report pagination (25 + 9), legacy details, Back navigation, customer/case dump browsing and 390px layout. No analyses or POST requests were initiated.

Historical reports are marked **Legacy report — detailed sections were not captured**. Reanalyzing a selected dump under 0.2.0 generates a new rich report; the deployment does not invent missing evidence for old reports.

The companion Windows DumpLedger service was not upgraded. The separately approval-gated live Claude test was not run as part of this deployment.

## Checkpoint and rollback

Private checkpoint: `/tmp/dumpanalyzer-rich-migration-canary-deploy-xi4bdmg1`. It contains the previous executable, launch configuration and `pre-deploy.sqlite`. Configuration files contain credentials and must remain private.

A data-preserving binary rollback is prepared:

```sh
python3 /tmp/dumpanalyzer-rich-migration-canary-deploy-xi4bdmg1/rollback-local.py
```

The rollback helper leaves the additive migrated database intact. Restore the stopped-state SQLite backup only after checking for and preserving any post-deployment reports or other writes.

Machine-readable receipt: [local-deployment-2026-10-15.json](local-deployment-2026-10-15.json).
