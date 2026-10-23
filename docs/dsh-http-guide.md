# DSH HTTP provider guide (`dsh-http`)

The `dsh-http` tool-runner provider analyzes each dump with the deterministic
CDB collector first, then asks a dedicated DeepSeek Harness (DSH) HTTP service
for an evidence-only assessment of the captured evidence. This guide covers
setup, configuration, route selection, credential handling, verification, and
operations. Design contracts live in [analyzer-design.md](analyzer-design.md)
("DSH HTTP provider"); the bounded live evidence is the
[2026-10-23 qualification receipt](qualification/dsh-http-2026-10-23/README.md)
— a dated snapshot, not a current-state guarantee.

```text
DumpAnalyzer (Rust daemon)                    DSH adapter (Node, confined)
  CDB capture via SSH ──> Windows box           zero-tool `analyzer` profile
  session create/message ──> 127.0.0.1:4181 ──> dsh headless run per message
  <── bounded RootCause JSON + trajectory anchor      └──> model gateway API
  session prune (every path) ──> DELETE
```

## Prerequisites

- `dsh` CLI (`@deepseek-ai/dsh`; qualified with `0.2.1-rc.2`) and Node.js
  (qualified with v24) on the adapter host.
- A model gateway reachable from the adapter host, with an API key.
- The Windows analysis box over SSH, as for every provider
  (`DUMP_ANALYZER_SSH_TARGET`); the DSH side never touches it.

## Scripted deployment

`deploy/deploy.py` performs the full install into the live user layout, or
under a staging directory for inspection:

```sh
python3 deploy/deploy.py --dry-run                 # print the plan, change nothing
python3 deploy/deploy.py --root /tmp/stage         # stage a tree under /tmp/stage
python3 deploy/deploy.py                           # deploy to the real user layout
python3 deploy/deploy.py --skip-dsh                # daemon only, no adapter
```

It builds the release binary (unless `--no-build`), backs up a replaced
binary with a dated suffix, installs helper scripts, units, the adapter, and
the confined DSH profile — and **never overwrites user configuration**:
existing `environment`, `dsh-adapter.env`, `dsh-routes.json`, and an
installed profile patch are kept unless `--force-config` is given. It never
starts or restarts services; it prints the remaining manual steps (fill
secrets, enable the adapter, restart the daemon). The manual path below
remains the reference for what the script does.

## Step 1 — the confined analyzer profile (one-time)

The adapter drives a dedicated, zero-tool DSH profile. Never reuse an
interactive DSH home: state must not mix with any other DSH instance.

```sh
# Create a dedicated harness home and the analyzer profile from the shipped
# headless template:
DSH_HOME=/srv/dsh-analyzer dsh --profile analyzer \
  --from-default-profile headless --dump-config >/dev/null

# Install the pinned analyzer patch (zero tools, no skills/MCP/subagents/
# telemetry, pinned default route):
cp deploy/dsh-adapter/analyzer-cordis.patch.yml \
  /srv/dsh-analyzer/profiles/analyzer/cordis.patch.yml
```

Use a persistent, owner-only directory in production (`/tmp` was the
qualification home and is wiped on reboot). The patch's baseline route is a placeholder
(`gateway-a` / `example-model`) that every adapter run shadows with the
session's resolved route; the real routes live in the route table (Step 2).

## Step 2 — the route table (user-provided)

The route table is **your deployment's configuration**, never shipped by the
implementation: the adapter fails to start without one. Install the example
and edit it into your real gateways:

```sh
cp deploy/dsh-adapter/routes.example.json ~/.config/dump-analyzer/dsh-routes.json
chmod 0600 ~/.config/dump-analyzer/dsh-routes.json   # endpoint URLs are infrastructure detail
$EDITOR ~/.config/dump-analyzer/dsh-routes.json
```

The table is configuration, so it lives in the config home (the DSH home is
state: sessions, overlays, profile data). The adapter reads
`$DSH_ANALYZER_ROUTES` or, by default,
`$XDG_CONFIG_HOME/dump-analyzer/dsh-routes.json`. A session request can only *select* among these
routes — it can never introduce a gateway the deployment did not configure.

| Field | Meaning |
| --- | --- |
| `default` | Route used when a session request carries no route fields. |
| `providers.<id>.kind` | `pi-ai` for custom gateways (the overlay emits the complete provider catalog block); `builtin` for DSH's shipped providers (their own catalog applies). |
| `providers.<id>.apiKeyEnv` | Environment variable the per-session API key is injected under for this provider. |
| `providers.<id>.models.<model>` | Optional catalog entry: `contextWindow` and `maxTokens`. Models absent here require the caller to supply both numbers. |

## Step 3 — run the adapter

```sh
DSH_HOME=/srv/dsh-analyzer \
DSH_ANALYZER_ROUTES=/srv/dsh-analyzer/routes.json \
DSH_ANALYZER_ADAPTER_TOKEN='<scoped bearer token>' \
  node deploy/dsh-adapter/server.mjs
```

For a supervised deployment, install the supplied user unit
[dump-analyzer-dsh-adapter.service](../deploy/systemd/dump-analyzer-dsh-adapter.service)
with its env template
[dsh-adapter.env.example](../deploy/systemd/dsh-adapter.env.example)
(mode 0600); the daemon's `environment.example` carries the matching
commented `dsh-http` block.

At boot the adapter composes every allowlisted route's generated overlay and
refuses to start on failure (`DSH_ANALYZER_SKIP_BOOT_CHECK=1` skips this
check). It binds `127.0.0.1:4181` by default; for a non-loopback bind, front
it with TLS and a host firewall restricted to the analyzer — the adapter
itself speaks plain HTTP.

| Adapter variable | Default | Meaning |
| --- | --- | --- |
| `DSH_HOME` | — (required) | Dedicated harness home. |
| `DSH_ANALYZER_PROFILE` | `analyzer` | Profile name inside the home. |
| `DSH_ANALYZER_ROUTES` | `$XDG_CONFIG_HOME/dump-analyzer/dsh-routes.json` | Route table path; user-provided, required to boot. |
| `DSH_ANALYZER_ADAPTER_TOKEN` | unset | Bearer token required on every route when set. |
| `DSH_ANALYZER_ADAPTER_ADDR` | `127.0.0.1:4181` | Bind address; keep loopback unless proxied. |
| `DSH_ANALYZER_PRESET` | `analyzer-triage` | The only accepted preset value. |
| `DSH_ANALYZER_MESSAGE_TIMEOUT_MS` | `170000` | Per-message headless run cap. |
| `DSH_ANALYZER_API_KEY_ENV` | `OPENCODE_API_KEY` | Fallback key variable name. |
| `DSH_ANALYZER_SKIP_BOOT_CHECK` | unset | `1` skips the route-composition check. |

Model key sources, in order: the session's forwarded key (Step 4), then the
adapter's launch environment, then `$DSH_HOME/.env`.

## Step 4 — configure DumpAnalyzer

```sh
export DUMP_ANALYZER_RUNNER='dsh-http'
export DUMP_ANALYZER_DSH_BASE_URL='http://127.0.0.1:4181'
export DUMP_ANALYZER_DSH_TOKEN='<scoped bearer token>'      # adapter token
export DUMP_ANALYZER_DSH_API_KEY='<model gateway key>'      # forwarded per session
```

| Analyzer variable | Required | Meaning |
| --- | --- | --- |
| `DUMP_ANALYZER_DSH_BASE_URL` | yes (with `dsh-http`) | Adapter URL. HTTPS off-loopback; loopback HTTP accepted; no credentials, query, or fragment. Honors `DUMP_ANALYZER_TLS_CA_CERT`. |
| `DUMP_ANALYZER_DSH_TOKEN` | recommended | Bearer token; must match the adapter's. |
| `DUMP_ANALYZER_DSH_API_KEY` | one key source required | Model key, forwarded once per session over the token-protected channel; the adapter injects it under the selected provider's `apiKeyEnv`, holds it in memory only, and drops it at session prune. Never persisted by the daemon; never enters prompts, evidence, or reports. |
| `DUMP_ANALYZER_DSH_PROVIDER` | no | Provider id from the route table. |
| `DUMP_ANALYZER_DSH_MODEL` | no | Model id within the provider's catalog, or an unlisted id with both catalog sizes set. |
| `DUMP_ANALYZER_DSH_REASONING_EFFORT` | no | `low`, `medium`, `high`, or `max`. |
| `DUMP_ANALYZER_DSH_CONTEXT_WINDOW` | with unlisted models | Catalog context window, 1–2,000,000. |
| `DUMP_ANALYZER_DSH_MAX_TOKENS` | with unlisted models | Catalog max tokens; must not exceed the context window. |
| `DUMP_ANALYZER_DSH_PRESET` | no | Default `analyzer-triage`. |

Route fields are fixed for each analysis session's lifetime. The route tuple
is part of the capture profile: use a distinct `DUMP_ANALYZER_VERSION` per
route on a live deployment so reports from different routes never share a
job identity. The provider remains off by default (`cdb-ssh`).

## Route selection examples

```sh
# Default route (table's default): no route variables at all.

# Alternate listed model, low effort:
export DUMP_ANALYZER_DSH_PROVIDER='opencode-go'
export DUMP_ANALYZER_DSH_MODEL='qwen3.8-flash'
export DUMP_ANALYZER_DSH_REASONING_EFFORT='low'

# Model not in the route table: supply its catalog numbers.
export DUMP_ANALYZER_DSH_PROVIDER='opencode-go'
export DUMP_ANALYZER_DSH_MODEL='new-gateway-model'
export DUMP_ANALYZER_DSH_CONTEXT_WINDOW='1000000'
export DUMP_ANALYZER_DSH_MAX_TOKENS='131072'
```

### Adding a custom gateway provider

A gateway the route table does not ship — e.g. an Anthropic-compatible relay
— is one `dsh-routes.json` entry away (then restart the adapter; the boot
check composes its overlay):

```json
"gateway-b": {
  "kind": "pi-ai",
  "api": "anthropic-messages",
  "baseURL": "https://gateway-b.example/api",
  "apiKeyEnv": "GATEWAY_B_API_KEY",
  "reasoningEffort": null,
  "models": {
    "example-chat": {"contextWindow": 1000000, "maxTokens": 131072}
  }
}
```

- `api` is the wire protocol: `anthropic-messages`, `openai-completions`, or
  `openai-responses`. `baseURL` is the endpoint root the protocol expects.
- `reasoningEffort: null` declares the route takes no reasoning level (the
  control is omitted from the generated overlay). Providers that do support
  levels pin their default with a plain value, and individual models may
  carry a `reasoningEfforts` wire mapping (emitted into the overlay).
- Select it analyzer-side with `DUMP_ANALYZER_DSH_PROVIDER=gateway-b`;
  the forwarded `DUMP_ANALYZER_DSH_API_KEY` is injected as `GATEWAY_B_API_KEY`.
- Auth header note: `anthropic-messages` sends the key as `x-api-key`. A
  gateway that insists on `Authorization: Bearer` exclusively can instead
  declare a static `headers` map in the provider entry with a
  `!!js process.env.GATEWAY_B_API_KEY` reference, so the key stays out of files.

Reports record the route as `provider/model` in provenance and the effort in
the assessment evidence label.

## Credential map

| Secret | Lives in | Presented to | Never in |
| --- | --- | --- | --- |
| DumpLedger analyzer token (`DUMP_ANALYZER_TOKEN`) | daemon env / state store | DumpLedger | DSH traffic |
| Adapter bearer (`DSH_ANALYZER_ADAPTER_TOKEN` / `DUMP_ANALYZER_DSH_TOKEN`) | both process environments | adapter HTTP | model traffic |
| Model key (`DUMP_ANALYZER_DSH_API_KEY` or adapter env) | daemon env → adapter memory → child env | model gateway | prompts, evidence, reports, logs |

## Verify a deployment

With the adapter running and the daemon configured, the ignored-by-default
gate replays the fixture through the live chain:

```sh
DUMP_ANALYZER_DSH_LIVE_BASE_URL="$DUMP_ANALYZER_DSH_BASE_URL" \
DUMP_ANALYZER_DSH_LIVE_TOKEN="$DUMP_ANALYZER_DSH_TOKEN" \
DUMP_ANALYZER_DSH_LIVE_API_KEY="$DUMP_ANALYZER_DSH_API_KEY" \
cargo test --offline --test dsh_runner live_dsh -- --ignored --nocapture
```

Optional `…_LIVE_PROVIDER` / `_MODEL` / `_REASONING_EFFORT` /
`_CONTEXT_WINDOW` / `_MAX_TOKENS` exercise a non-default route. A pass shows
`provider=dsh-http`, the adapter-reported `provider/model`, an adopted
bounded assessment or an explicit omission, and the trajectory anchor
(`N events sha256:…`) in the evidence label.

## Operations

- **Session lifecycle**: one fresh zero-tool DSH session per analysis run;
  the trajectory digest is anchored in the report's `assessment-model`
  evidence entry; a session prune is attempted on every path — success,
  reasoning failure, and the run deadline alike — removing the in-memory
  record, the generated overlay, and the persisted DSH session.
- **Fallback**: any reasoning failure (adapter error, malformed or
  out-of-schema answer after one correction turn, timeout) preserves the
  deterministic evidence and assessment; the report gains an explicit
  completeness omission. The daemon never fails a run because the reasoner
  failed.
- **Concurrency**: the adapter serializes headless runs through a FIFO
  queue; the daemon's run wall deadline bounds the wait. Treat the
  provider's throughput as one analysis at a time per adapter.
- **Cost/latency**: each message turn is one headless `dsh` boot plus one
  model turn (observed 25–58 s on the fixture prompt, gateway-dependent).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Boot failure naming `DUMP_ANALYZER_DSH_BASE_URL` | provider selected without the URL | set it (loopback HTTP or HTTPS) |
| Adapter start failure in the route boot check | route overlay does not compose against the profile | fix `routes.json`; check the profile patch is installed |
| HTTP 401 from the adapter | token missing/mismatched | align `DUMP_ANALYZER_DSH_TOKEN` with `DSH_ANALYZER_ADAPTER_TOKEN` |
| HTTP 400 `provider … is not allowlisted` | provider absent from the route table | add it to `routes.json` (adapter-owned), restart the adapter |
| HTTP 400 asking for catalog numbers | unlisted model without sizes | set `DUMP_ANALYZER_DSH_CONTEXT_WINDOW` and `_MAX_TOKENS` |
| HTTP 409/400 `model …` pin errors | stale adapter from before route selection | upgrade the adapter |
| Omission containing `MISSING_CREDENTIAL` | no model key in any source | set `DUMP_ANALYZER_DSH_API_KEY`, the adapter launch env, or `$DSH_HOME/.env` |
| HTTP 500 `UNSUPPORTED_REASONING_EFFORT` | the route's model takes no reasoning levels | set the provider's `reasoningEffort` to `null` in your `routes.json`, or declare the model's `reasoningEfforts` mapping |
| Adapter start failure `no route table at …` | the table is user-provided and missing | install `dsh-routes.json` under the config home (see `routes.example.json`) or set `DSH_ANALYZER_ROUTES` |
| HTTP 500 with gateway `Invalid API key format` | the key failed the gateway's format/policy check before any request | confirm the exact key with the gateway owner; for Bearer-only gateways see the auth header note above |
| Omission containing `exceeded shared run wall timeout` | model turn outran the run budget | raise `DUMP_ANALYZER_RUN_WALL_TIMEOUT_MS` or lower the effort |
| Report shows the deterministic assessment only | reasoning fallback engaged | read the completeness omission; the evidence is intact |

## Security checklist for a deployment

- [ ] Dedicated `DSH_HOME`, owner-only, persistent; nothing shares it.
- [ ] Analyzer profile patch installed; no tools/skills/MCP/subagents enabled.
- [ ] Adapter loopback-bound, or TLS + host firewall restricted to the analyzer.
- [ ] Bearer token set on both sides; model key forwarded per session or
      scoped to the adapter's environment.
- [ ] Route table reviewed: only intended gateways are allowlisted.
- [ ] Egress from the adapter host limited to the model gateway API.
- [ ] Distinct `DUMP_ANALYZER_VERSION` per route profile.

## Qualification status

Wiremock contract tests and one bounded live qualification
([receipt](qualification/dsh-http-2026-10-23/README.md), dsh 0.2.1-rc.2,
`deepseek-v4.1-flash` and `qwen3.8-flash` via the configured gateway):
session lifecycle, bearer auth, zero-tool confinement, trajectory anchoring,
export-then-prune, configurable route/effort/catalog sizes, per-session key
path with a negative control, and one indirect-injection probe. That
evidence is dated: it is not production rollout, not a model-quality
benchmark, not a concurrency/load result, and not DumpLedger delivery
evidence.
