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
