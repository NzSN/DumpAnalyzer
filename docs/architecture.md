# DumpAnalyzer architecture

Source revision: `0bb92ae716a32e77a3f92fc9c4830080cf0abfdb` · inspected 2026-10-15.

This snapshot predates rich-report implementation. The current canonical capture, storage, detail and publication path is documented in [rich reports](rich-reports.md).

These diagrams describe the implemented checkout. They show logical process and storage boundaries, rather than asserting a live deployment configuration. Open [the rendered diagrams](architecture.html) for zoom controls. Arrow labels distinguish calls, control transitions and transferred data.

DumpAnalyzer discovers dumps from DumpLedger, executes CDB on a configured Windows analysis host, saves compact reports locally, and optionally delivers them back to DumpLedger. Its web dashboard exposes a work queue, a customer/case dump explorer, reports and manual actions.

## 1. Runtime block diagram

![Runtime blocks and process boundaries](architecture/blocks.svg)

Blue blocks are Rust components; purple blocks are runner providers or their subprocesses; green blocks are durable local storage; amber blocks are operator interfaces; gray blocks are external services. The Rust components share one process and a SQLite store. A `LedgerClient` box represents the common client implementation; several components own separate instances with the same boot configuration.

The Windows CDB process and DumpLedger service have distinct responsibilities and can share a physical host. DumpLedger supplies catalog metadata, audit events, bytes and symbols, and receives reports. DumpAnalyzer owns analysis execution. The optional Claude CLI runs on the daemon host and drives remote CDB over SSH.

| Component | Responsibility and implementation |
| --- | --- |
| Entry point / configuration | Validate environment, select runner, start daemon: [main.rs](../src/main.rs#L26), [config.rs](../src/config.rs#L128). |
| Scheduler / intake | Boot, recovery and supervised loops: [scheduler.rs](../src/scheduler.rs#L104). Catalog scan and durable event feed: [sync.rs](../src/sync.rs#L192). |
| Agent / manual facade | Scheduled execution and shared attempt pipeline: [agent.rs](../src/agent.rs#L213). On-demand analysis, scope batches and active registry: [analyzer.rs](../src/analyzer.rs#L274). |
| ToolRunner providers | Typed request/result interface: [types.rs](../src/types.rs#L113). Deterministic SSH/CDB adapter: [runner.rs](../src/runner.rs#L1333). Optional Claude adapter: [claude_runner.rs](../src/claude_runner.rs#L78). |
| Persistence / delivery | SQLite tables and migrations: [state.rs](../src/state.rs#L122). Bounded report assembly, local recording and delivery: [verdict.rs](../src/verdict.rs#L134). |
| Dashboard / explorer | HTTP dispatch and JSON projections: [http.rs](../src/http.rs#L145). Catalog hierarchy/cache: [explorer.rs](../src/explorer.rs#L163). Browser panels: [dashboard.html](../src/dashboard.html#L528). |

The default HTTP listener is `127.0.0.1:4180`; an empty address disables it. Reads are anonymous. Actions can use the daemon's stored token when no Authorization header is supplied, so the token mechanism is not caller authentication for an exposed listener. The configured analyzer credential authenticates outbound DumpLedger API calls. Updating the stored token changes UI action checks immediately; running pipeline clients take the token from boot configuration.

## 2. Daemon control flow

![Startup and concurrent daemon control flow](architecture/daemon-control.svg)

Startup completes recovery and the initial catalog scan before starting HTTP. An unavailable catalog can therefore delay the dashboard. Discovery runs even when automatic scheduling is disabled.

After boot, the feed follower, automatic scheduler and delivery loop advance independently under the supervisor. HTTP runs in a separate spawned task. Each feed page is applied before its cursor is committed. The automatic scheduler resumes persisted `Claimed` work before claiming new discoveries and runs one scheduled job at a time. Delivery retries pending reports every 60 seconds, including while analysis is busy or scheduling is disabled.

| Configuration | What it changes |
| --- | --- |
| `DUMP_ANALYZER_SCHEDULER=off` | Disables automatic claims. Catalog intake, browsing, manual analysis and report delivery remain available. |
| `DUMP_ANALYZER_WRITE_BACK=off` | Saves reports locally and settles eligible work without posting analyses. Catalog/content/symbol reads remain in use; delivery replay is disabled. |
| `DUMP_ANALYZER_HTTP_ADDR=''` | Disables the dashboard and HTTP action surface. The daemon loops still operate. |
| `DUMP_ANALYZER_RUNNER` | Selects `cdb-ssh` or `claude-cdb` at boot. Both use the designated Windows CDB host. |

On restart, `Fetching`, `Staged` and `Analyzing` reset to `Claimed`, preserving attempt counts. `Reporting` is reconciled separately against local reports and, when enabled, the remote analyses API. SIGINT/SIGTERM cancels the loops; the automatic scheduler finishes its in-flight job. HTTP connection tasks are not joined by that drain guarantee. An HTTP serving failure is logged without terminating the pipeline.

Sources: [boot ordering](../src/scheduler.rs#L109), [concurrent loops](../src/scheduler.rs#L225), [automatic scheduling](../src/scheduler.rs#L408), [delivery loop](../src/scheduler.rs#L513), [recovery](../src/agent.rs#L167), [feed cursor](../src/sync.rs#L246).

## 3. Job and manual-request control flow

![Scheduled and manual analysis control flow](architecture/job-control.svg)

The upper lane records scheduled phases in SQLite. The lower lane handles synchronous HTTP analysis. Both use the Agent's fetch/verification/runner machinery, but manual attempts do not persist each intermediate phase. Their temporary registry entry displays `Claimed` and clears when the request returns, fails or is cancelled. A scope request enumerates available dumps, rejects scopes larger than 64 dumps, and analyzes the accepted scope sequentially; individual failures are returned as skipped items.

Three queue rules matter:

1. **Discovered is inventory.** It is stored as an automatic scheduling candidate, but the Jobs widget excludes it. The Dumps explorer reads the available catalog independently and includes already analyzed dumps.
2. **Jobs means active work.** The API merges persistent `Claimed`, `Fetching`, `Staged`, `Analyzing` and `Reporting` rows with active manual requests, deduplicating identities for display.
3. **Terminal transitions remove queue rows atomically.** `Done`, `Failed` and `Dropped` move to `settled_jobs`. Their identities remain available for deduplication, so an ordinary rescan cannot silently enqueue settled work again.

`Done` describes settlement. A report with analysis outcome `failed` can still settle `Done` after successful storage/delivery. A missing legacy analyses route also settles a scheduled job locally while retaining its report for later replay. Transient delivery errors retain pending work; permanent rejection or purge can settle `Failed` or `Dropped`.

With write-back enabled, scheduled analysis posts after recording locally; manual analysis returns its report after local storage and relies on the delivery loop for posting. Manual completion changes an eligible idle job using compare-and-set; it preserves an already running scheduled job or archived terminal identity. Reanalyzing an archived identity therefore need not create a new persistent `Reporting` row, although the manual run remains visible while active.

Automatic concurrency of one is not a global execution limit. Independent manual requests can overlap the scheduler and each other. Manual duplicate protection is scoped to the manual registry, not a shared scheduler lock.

Sources: [scheduled pipeline](../src/agent.rs#L213), [manual pipeline](../src/analyzer.rs#L274), [manual completion](../src/analyzer.rs#L328), [terminal archive](../src/state.rs#L358), [queue projection](../src/http.rs#L1069).

## 4. Analysis and report data flow

![Dump bytes, symbols, reports and delivery data flow](architecture/analysis-data.svg)

The local identity is `(dumpId, inputSha256, kind, analyzerVersion)`; configured analyzer name completes the remote report identity. Bytes are cached by SHA-256 and verified before runner execution, including cache reuse after a `304` response. Downloads currently buffer the content body before writing the cache. Dump bytes live on the filesystem; SQLite stores the cache index and job/report metadata.

`RunRequest` carries the verified dump path, symbol path, per-run workspace and configured bounds. The default runner stages the dump and a deterministic script over SCP, invokes CDB over SSH, and parses its output. Its script uses `.sympath`, `.reload`, `.ecxr`, `kc`, `lm`, `|` and `q`. CDB obtains symbols through `SRV*<remote-cache>*<ledger-base>/symbols`. The optional Claude provider stages the dump and invokes a local CLI that drives remote CDB and returns JSON. These providers share `RunOutput { outcome, summary, facts }`, but do not enforce a common typed forensic-evidence schema.

The default runner extracts basic exception code/name/address, up to 32 frame call-site strings, module symbol status and process information. This is not a complete exception record, validated symbol provenance or an evidence-backed root-cause analysis. Run bounds are passed to the adapters; the diagram does not claim that every staging, cleanup or subprocess operation is covered by one global timeout. Local per-run workspaces are wiped after execution; remote scratch cleanup is best effort. There is no durable full-transcript report store.

**The amber reduction block is a current information-loss boundary.** `verdict::assemble` limits the summary to 2,000 characters, facts to 4 KiB and the JSON submission to 16 KiB, dropping whole facts keys when necessary. This happens before local persistence for both entry points. Frames can be removed, and the local copy cannot recover discarded evidence. Report delivery reuses the persisted compact payload.

`local_reports.posted` is a delivery bookkeeping flag; some permanently abandoned reports also set it. A displayed Posted label alone does not prove remote acceptance. A failed report outcome describes analysis, rather than delivery state.

The requested rich report—resolved stack, complete exception information and supported root-cause analysis—is planned in [rich-report-implementation-plan.md](../Plans/rich-report-implementation-plan.md). Its canonical report store and detail API are not implemented in this revision.

Sources: [identity and runner types](../src/types.rs#L82), [manual shared attempt](../src/agent.rs#L350), [cache/fetch](../src/agent.rs#L403), [symbol path](../src/agent.rs#L579), [CDB parsing](../src/runner.rs#L1138), [report limits](../src/verdict.rs#L51), [assembly](../src/verdict.rs#L134), [local persistence](../src/verdict.rs#L180).

## 5. Dashboard data flow and information load

![Bounded explorer, queue and reports data flow](architecture/ui-data.svg)

The browser loads one list panel at a time. Status counts refresh every 5 seconds; Queue refreshes every 5 seconds while visible; Dumps and Reports refresh every 15 seconds while visible. Search is debounced by 250 ms. Navigation preserves panel, scope, filters and page in the URL hash. Browsing never starts analysis.

| View | Data source and boundary |
| --- | --- |
| Queue | SQL active work plus the ephemeral manual registry. No discovered or terminal rows. |
| Dumps | Available DumpLedger catalog, customer display names and case titles → shared 30-second daemon snapshot → one page of customers, cases or dumps. Local phases are overlaid for returned dump rows. |
| Reports | SQLite counts and a filtered, stably ordered page → summary JSON. Facts are omitted from the response, although SQL still reads them internally for selected rows. Details currently expands the same summary. |
| Status / Settings | Lightweight daemon state and report counts; configuration, token storage, manual actions, rescan and diagnostics. |

Both list APIs default to 25 rows and cap page size at 100 rows. Customer/case rows contain counts instead of nested descendant lists. This bounds the response and browser DOM, while the explorer's server cache still holds the complete catalog. The legacy `/api/dumps` endpoint still returns a full snapshot; the dashboard uses `/api/dumps/browse`. There is currently no lazy full-report detail endpoint.

Sources: [explorer paging](../src/explorer.rs#L163), [snapshot construction](../src/explorer.rs#L284), [report SQL paging](../src/state.rs#L1087), [report JSON projection](../src/http.rs#L1147), [summary disclosure](../src/dashboard.html#L521), [panel fetch](../src/dashboard.html#L528), [polling](../src/dashboard.html#L668).

## Diagram sources

Graphviz sources and generated SVGs are in [docs/architecture/](architecture/). Regenerate the SVGs and this document's self-contained HTML view with:

```sh
python3 docs/architecture/render.py
wslview docs/architecture.html
```

Rendering requires Graphviz `dot` and Python's `markdown-it-py`. It does not build or run DumpAnalyzer. The HTML contains the SVGs inline, zoom controls and source links pinned to the revision above.
