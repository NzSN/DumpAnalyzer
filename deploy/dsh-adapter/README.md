# DSH analyzer adapter

Serves the `dsh-http` provider contract (`src/dsh_runner.rs`, "Analyzer
adapter contract") in front of a dedicated, confined DeepSeek Harness
profile. Deployment tool, not part of the Rust crate.

## Setup

1. Create a dedicated harness home and the `analyzer` profile from the
   shipped headless template:

   ```sh
   DSH_HOME=/path/to/dsh-home dsh --profile analyzer \
     --from-default-profile headless --dump-config >/dev/null
   cp analyzer-cordis.patch.yml \
     /path/to/dsh-home/profiles/analyzer/cordis.patch.yml
   ```

   The patch supplies a placeholder model route (`gateway-a` / `example-model`)
   and disables every tool, skill, content-channel, subagent, telemetry,
   and self-editing plugin. The home must be dedicated to the analyzer —
   never share it with an interactive DSH instance.

2. Run the adapter (loopback-only by default) — directly, or as a user
   service with [../systemd/dump-analyzer-dsh-adapter.service](../systemd/dump-analyzer-dsh-adapter.service)
   (env template: [../systemd/dsh-adapter.env.example](../systemd/dsh-adapter.env.example)):

   ```sh
   DSH_HOME=/path/to/dsh-home \
   DSH_ANALYZER_ADAPTER_TOKEN=<scoped token> \
   OPENCODE_API_KEY=<gateway key> \
     node server.mjs    # binds 127.0.0.1:4181
   ```

   Environment reference is at the top of `server.mjs`. For a non-loopback
   bind, front it with TLS and a host firewall restricted to the analyzer;
   the adapter itself speaks plain HTTP.

   Model key sources, in order: a per-session `apiKey` from the analyzer's
   `DUMP_ANALYZER_DSH_API_KEY` (injected into each headless child under the
   selected provider's `apiKeyEnv`; held in memory only, dropped at session
   prune), then the adapter's launch environment, then `$DSH_HOME/.env`.

## Route table

The analyzer may select a route per session (`provider`, `model`,
`reasoningEffort` `low|medium|high|max`, and catalog `contextWindow` /
`maxTokens` for models the table does not list). Selectable providers are
allowlisted in a **user-provided** route table (`DSH_ANALYZER_ROUTES`, or
`$XDG_CONFIG_HOME/dump-analyzer/dsh-routes.json`; the adapter ships only
`routes.example.json` and refuses to start without a real table); a request
can never introduce a gateway the deployment did not configure. Provider entries
additionally carry `api` + `baseURL` for custom gateways (e.g.
`anthropic-messages` / `https://gateway-b.example/api`), an optional
per-provider `reasoningEffort` default (`null` declares the route takes no
reasoning level and omits the control), and per-model `reasoningEfforts`
wire mappings. See docs/dsh-http-guide.md, "Adding a custom gateway
provider", for a worked entry. The selected
route generates a `--patch` overlay (`$DSH_HOME/overlays/`, mode 0600,
pruned with the session) overriding the profile's `agent-default-model`
and, for `kind: "pi-ai"` providers, the complete provider block — overlays
replace an entry's config wholesale (verified on dsh 0.2.1-rc.2). At boot
the adapter composes every allowlisted route's overlay and refuses to start
on failure; `DSH_ANALYZER_SKIP_BOOT_CHECK=1` skips this.

3. Point the analyzer at it:

   ```sh
   export DUMP_ANALYZER_RUNNER='dsh-http'
   export DUMP_ANALYZER_DSH_BASE_URL='http://127.0.0.1:4181'
   export DUMP_ANALYZER_DSH_TOKEN='<scoped token>'
   ```

## Optional dump investigation tools

The default remains evidence-only. Enable both ends explicitly to let the
reasoner request additional debugger evidence from the current dump:

```sh
# DumpAnalyzer environment (~/.config/dump-analyzer/environment):
DUMP_ANALYZER_DSH_TOOLS=on
DUMP_ANALYZER_DSH_TOKEN='<scoped adapter token>'
# Adapter environment (~/.config/dump-analyzer/dsh-adapter.env):
DSH_ANALYZER_ALLOW_MCP=on
DSH_ANALYZER_ADAPTER_TOKEN='<same scoped adapter token>'
```

MCP mode requires adapter authentication and refuses to start without a
nonempty printable adapter token. Run the adapter on the same host as
DumpAnalyzer. The analyzer creates an
ephemeral loopback MCP bridge for one verified dump and supplies
`analysisMcp: {"url":"http://127.0.0.1:<port>/mcp","token":"<run bearer>"}`
in its session-create request. The adapter rejects this field unless enabled,
rejects other hosts, paths, URL credentials and query parameters, and returns
`analysisTools: true` when it accepts the configuration. This is a configuration
acknowledgement; DumpAnalyzer separately requires authenticated discovery of
the bridge's tool list before accepting a tool-enabled assessment. Retained
debugger receipts establish which tools actually ran; discovery alone does
not require a tool call when the initial capture already answers the question.

A generated session overlay adds only `@deepseek-ai/dsh-mcp-client` under the
`dump_analysis` namespace. MCP resource tools stay disabled, as do the base
profile's shell, filesystem, web and other general tools. The persona permits
only the dump tools and treats captures and tool output as untrusted evidence.
The MCP bearer is injected into the child environment, read by a fixed `!!js`
expression, and never written into the overlay. The bridge enforces the dump,
argument, call, time and output limits; the adapter caps each MCP call at 30
seconds and disables automatic reconnect. Use a distinct analyzer version
when enabling tools so existing report identities remain reproducible.

The same endpoint can expose Forensicator's four native stdio MCP tools and
the focused `forensicator_javascript_stack` recovery tool.
Set `DUMP_ANALYZER_FORENSICATOR_BIN` in the **daemon** environment to the
absolute built executable, with `DUMP_ANALYZER_DSH_TOOLS=on`. DumpAnalyzer
launches `forensicator mcp` and publishes the `forensicator_*` tools through
the existing namespace, retaining their evidence and enforcing the shared
budget. `deploy/deploy.py` fetches the verified GitHub release into
`~/.local/libexec/dump-analyzer/forensicator` by default; use its absolute
path in the daemon environment. The adapter needs no second MCP server or dump-file mount. See
[Forensicator setup](../../docs/dsh-http-guide.md#forensicator-mcp-tools).

Deleting a session revokes queued work, kills its active child, waits for it
to exit, and prunes the overlay and known persisted DSH session. Abandoned
sessions expire after ten minutes; at most 64 sessions are retained. Child
stdout is limited to 8 MiB during acquisition, stderr retention to 64 KiB,
and retained events to 256 entries and 8 MiB. API keys and bearer tokens known
to the adapter are redacted from returned text/events; stderr is not exposed.

The installed DSH `0.2.1-rc.2` supports this overlay. Its MCP plugin's
`failOnStartupError` rejects the plugin, but DSH may continue without that
optional plugin. If tool discovery never succeeds, DumpAnalyzer records the
missing capability and retains its deterministic fallback.

Local tests use fake headless children and loopback HTTP only:

```sh
node --test deploy/dsh-adapter/server.test.mjs
```

## Qualification status

Bounded live qualification (contract, confinement, prune, one injection
probe): [docs/qualification/dsh-http-2026-10-23](../../docs/qualification/dsh-http-2026-10-23/README.md).
That receipt is dated evidence, not production readiness: per-message cost
is one headless `dsh` boot plus one model turn, and runs are serialized.
It predates the optional MCP mode and does not qualify live dump investigation.
