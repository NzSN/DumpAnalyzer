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

   The patch pins the model route (`opencode-go` / `deepseek-v4.1-flash`)
   and disables every tool, skill, content-channel, subagent, telemetry,
   and self-editing plugin. The home must be dedicated to the analyzer —
   never share it with an interactive DSH instance.

2. Run the adapter (loopback-only by default):

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
allowlisted in `routes.json` (path: `DSH_ANALYZER_ROUTES`); a request can
never introduce a gateway the deployment did not configure. The selected
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

## Qualification status

Bounded live qualification (contract, confinement, prune, one injection
probe): [docs/qualification/dsh-http-2026-10-23](../../docs/qualification/dsh-http-2026-10-23/README.md).
That receipt is dated evidence, not production readiness: per-message cost
is one headless `dsh` boot plus one model turn, and runs are serialized.
