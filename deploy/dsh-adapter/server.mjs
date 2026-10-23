#!/usr/bin/env node
// DumpAnalyzer DSH analyzer adapter — serves the `dsh-http` provider contract
// (src/dsh_runner.rs, "Analyzer adapter contract") in front of a dedicated,
// confined DeepSeek Harness profile.
//
// Confinement posture (docs/analyzer-design.md, "DSH HTTP provider"):
// * dedicated DSH_HOME with its own zero-tool `analyzer` profile — state
//   never mixes with any other DSH instance;
// * loopback-only bind by default; bearer token when
//   DSH_ANALYZER_ADAPTER_TOKEN is set;
// * one fresh DSH session per analyzer session; messages resume it via
//   `dsh --profile <p> --json [--session-id <id>]` one-shot runs;
// * DELETE prunes the in-memory trajectory and the persisted DSH session.
//
// Route selection (v2): a session-create body may carry provider, model,
// reasoningEffort, contextWindow, and maxTokens. The adapter resolves them
// against its own route table (DSH_ANALYZER_ROUTES, default
// <adapter>/routes.json): the provider must be allowlisted there — a request
// can never introduce a gateway the deployment did not configure — and the
// model's catalog numbers come from the table or, for an unlisted model,
// from the request's contextWindow/maxTokens. The selected route is pinned
// for the session's lifetime and drives a generated `--patch` overlay
// (validated YAML scalars, 0600, pruned with the session) that overrides
// the profile's agent-default-model and, for pi-ai providers, the complete
// provider block (overlays replace an entry's config wholesale in dsh
// 0.2.1-rc.2 — verified by --dump-config).
//
// A session-create body may carry "apiKey": the model provider credential
// for that session's headless runs. The adapter injects it into the child
// process environment as DSH_ANALYZER_API_KEY_ENV (default OPENCODE_API_KEY,
// matching the analyzer profile's apiKeyEnv), holds it only in the in-memory
// session record, and drops it at DELETE. It is never logged and never
// appears in prompts, events, or responses. Without "apiKey", the launch
// environment's own key applies (headless profile: process env, then
// <cwd>/.env, then $DSH_HOME/.env).
//
// Environment:
//   DSH_HOME                       dedicated harness home (required)
//   DSH_ANALYZER_PROFILE           profile name (default: analyzer)
//   DSH_ANALYZER_MODEL             default-route model id (default: deepseek-v4.1-flash)
//   DSH_ANALYZER_ROUTES            route table JSON path (default: <adapter>/routes.json)
//   DSH_ANALYZER_PRESET            only accepted preset (default: analyzer-triage)
//   DSH_ANALYZER_ADAPTER_TOKEN     optional bearer token
//   DSH_ANALYZER_ADAPTER_ADDR      bind address (default: 127.0.0.1:4181)
//   DSH_ANALYZER_MESSAGE_TIMEOUT_MS  per-message run cap (default: 170000)
//   DSH_ANALYZER_API_KEY_ENV       child env var name for per-session keys
//                                  (default: OPENCODE_API_KEY)

import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

const DSH_HOME = process.env.DSH_HOME;
if (!DSH_HOME) {
  console.error("dsh-analyzer-adapter: DSH_HOME is required (dedicated harness home)");
  process.exit(2);
}
const PROFILE = process.env.DSH_ANALYZER_PROFILE ?? "analyzer";
const MODEL = process.env.DSH_ANALYZER_MODEL ?? "deepseek-v4.1-flash";
const PRESET = process.env.DSH_ANALYZER_PRESET ?? "analyzer-triage";
const TOKEN = process.env.DSH_ANALYZER_ADAPTER_TOKEN ?? null;
const ADDR = process.env.DSH_ANALYZER_ADAPTER_ADDR ?? "127.0.0.1:4181";
const MESSAGE_TIMEOUT_MS = Number(process.env.DSH_ANALYZER_MESSAGE_TIMEOUT_MS ?? 170_000);
const MAX_BODY = 1024 * 1024;
const MAX_EVENTS = 256;
const API_KEY_ENV = process.env.DSH_ANALYZER_API_KEY_ENV ?? "OPENCODE_API_KEY";
const ROUTES_PATH =
  process.env.DSH_ANALYZER_ROUTES ?? new URL("./routes.json", import.meta.url).pathname;
const EFFORTS = new Set(["low", "medium", "high", "max"]);
const MAX_CATALOG_SIZE = 2_000_000;

// Adapter-owned route table: the only providers a request may select.
async function loadRoutes(path) {
  try {
    const table = JSON.parse(await readFile(path, "utf8"));
    if (!table?.default?.provider || !table?.providers?.[table.default.provider]) {
      throw new Error("default provider missing from providers map");
    }
    return table;
  } catch (err) {
    if (err.code === "ENOENT" && !process.env.DSH_ANALYZER_ROUTES) {
      // No table shipped next to the adapter: the pinned default only.
      return {
        default: { provider: "opencode-go", model: MODEL, reasoningEffort: "max" },
        providers: { "opencode-go": { kind: "pi-ai", apiKeyEnv: API_KEY_ENV, models: {} } },
      };
    }
    throw new Error(`cannot load route table ${path}: ${err.message}`);
  }
}
const ROUTES = await loadRoutes(ROUTES_PATH);

// Resolve one request's route against the allowlist. Returns
// { provider, model, reasoningEffort, contextWindow, maxTokens, apiKeyEnv, kind }
// or throws RouteError (400).
class RouteError extends Error {}
function resolveRoute(body) {
  const providerId = body.provider ?? ROUTES.default.provider;
  const provider = ROUTES.providers[providerId];
  if (!provider) throw new RouteError(`provider ${String(providerId).slice(0, 128)} is not allowlisted`);
  const model = body.model ?? (providerId === ROUTES.default.provider ? ROUTES.default.model : null);
  if (!model) throw new RouteError(`model is required for provider ${providerId}`);
  const effort = body.reasoningEffort ?? ROUTES.default.reasoningEffort;
  if (!EFFORTS.has(effort)) throw new RouteError("reasoningEffort must be low, medium, high, or max");
  const catalog = provider.models?.[model];
  let contextWindow = body.contextWindow ?? catalog?.contextWindow ?? null;
  let maxTokens = body.maxTokens ?? catalog?.maxTokens ?? null;
  for (const [name, value] of [["contextWindow", contextWindow], ["maxTokens", maxTokens]]) {
    if (value !== null && (!Number.isInteger(value) || value < 1 || value > MAX_CATALOG_SIZE)) {
      throw new RouteError(`${name} must be an integer between 1 and ${MAX_CATALOG_SIZE}`);
    }
  }
  if (provider.kind === "pi-ai" && (contextWindow === null || maxTokens === null)) {
    throw new RouteError(
      `model ${String(model).slice(0, 128)} is not in the route table for ${providerId}; ` +
        "supply contextWindow and maxTokens for an unlisted model",
    );
  }
  if (contextWindow !== null && maxTokens !== null && maxTokens > contextWindow) {
    throw new RouteError("maxTokens must not exceed contextWindow");
  }
  return {
    provider: providerId,
    model,
    reasoningEffort: effort,
    contextWindow,
    maxTokens,
    apiKeyEnv: provider.apiKeyEnv ?? API_KEY_ENV,
    kind: provider.kind ?? "pi-ai",
  };
}

// Generated --patch overlay: JSON.stringify quoting is valid YAML 1.2 and
// needs no hand-rolled escaping. For pi-ai providers the complete provider
// block is emitted because overlays replace an entry's config wholesale.
function overlayFor(route) {
  const q = (v) => JSON.stringify(String(v));
  const lines = [
    "- id: agent-default-model",
    "  config:",
    `    provider: ${q(route.provider)}`,
    `    model: ${q(route.model)}`,
    `    reasoningEffort: ${q(route.reasoningEffort)}`,
  ];
  if (route.kind === "pi-ai") {
    lines.push(
      "- id: llm-pi-ai",
      "  config:",
      "    providers:",
      `      ${q(route.provider)}:`,
      `        apiKeyEnv: ${q(route.apiKeyEnv)}`,
      "        models:",
      `          - id: ${q(route.model)}`,
      `            name: ${q(route.model)}`,
      `            contextWindow: ${route.contextWindow}`,
      `            maxTokens: ${route.maxTokens}`,
      "            input:",
      "              - text",
    );
  }
  return lines.join("\n") + "\n";
}

// Dedicated empty working directory: no AGENTS.md, skills, or other
// cwd-scoped content channels exist even if a profile change re-enabled one.
const WORKSPACE = join(DSH_HOME, "workspace");

/** @type {Map<string, {dshSessionId: string|null, apiKey: string|null, route: object, overlayPath: string, events: unknown[], created: string, turns: number}>} */
const sessions = new Map();

// FIFO queue: one headless run at a time keeps the model gateway and the
// box predictable; the provider's run deadline bounds the wait.
let queue = Promise.resolve();
function enqueue(work) {
  const run = queue.then(work, work);
  queue = run.catch(() => {});
  return run;
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" }).end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("body exceeds the 1 MiB budget"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function authorized(req) {
  if (TOKEN === null) return true;
  return req.headers.authorization === `Bearer ${TOKEN}`;
}

// One headless turn: fresh process, prompt on stdin, NDJSON on stdout.
// Returns { dshSessionId, text, events } or throws with a bounded message.
// `apiKey`, when present, is injected as the provider key env var for this
// child only; it is never written to argv, files, or logs.
function runTurn(dshSessionId, prompt, apiKey, route, overlayPath) {
  return new Promise((resolve, reject) => {
    const args = ["--profile", PROFILE, "--patch", overlayPath, "--json"];
    if (dshSessionId) args.push("--session-id", dshSessionId);
    const env = { ...process.env, DSH_HOME };
    if (apiKey) env[route?.apiKeyEnv ?? API_KEY_ENV] = apiKey;
    const child = spawn("dsh", args, {
      cwd: WORKSPACE,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const events = [];
    let stdout = "";
    let stderrTail = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`headless run exceeded the ${MESSAGE_TIMEOUT_MS}ms adapter budget`));
    }, MESSAGE_TIMEOUT_MS);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => {
      stderrTail = (stderrTail + d).slice(-500);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`spawn dsh failed: ${err.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      for (const line of stdout.split("\n")) {
        if (!line.trim()) continue;
        try {
          events.push(JSON.parse(line));
        } catch {
          events.push({ type: "unparsed", bytes: line.length });
        }
      }
      const sessionEvent = events.find((e) => e?.type === "session");
      const finalEvent = events.findLast((e) => e?.type === "final");
      if (code !== 0) {
        reject(new Error(`dsh exited ${code}: ${stderrTail || "no stderr"}`));
        return;
      }
      if (!finalEvent) {
        reject(new Error("run completed without a final event"));
        return;
      }
      resolve({
        dshSessionId: sessionEvent?.sessionId ?? dshSessionId ?? null,
        text: typeof finalEvent.text === "string" ? finalEvent.text : "",
        events: events.slice(0, MAX_EVENTS),
      });
    });
    child.stdin.end(prompt);
  });
}

async function prunePersistedSession(dshSessionId) {
  // Session logs persist as $DSH_HOME/sessions/<cwd-slug>/<session-id>/;
  // remove that directory (best effort).
  if (!dshSessionId) return;
  const root = join(DSH_HOME, "sessions");
  try {
    for (const dir of await readdir(root)) {
      await rm(join(root, dir, dshSessionId), { recursive: true, force: true });
    }
  } catch {
    /* best-effort prune */
  }
}

const server = createServer((req, res) => {
  handle(req, res).catch((err) => {
    sendJson(res, 500, { error: String(err?.message ?? err).slice(0, 300) });
  });
});

async function handle(req, res) {
  if (!authorized(req)) {
    sendJson(res, 401, { error: "unauthorized" });
    return;
  }
  const url = new URL(req.url, "http://loopback");
  const parts = url.pathname.split("/").filter(Boolean);
  if (req.method === "POST" && url.pathname === "/v1/analyzer-sessions") {
    const body = JSON.parse(await readBody(req));
    if (body?.preset !== PRESET) {
      sendJson(res, 400, { error: `unknown preset; this instance serves only ${PRESET}` });
      return;
    }
    let route;
    try {
      route = resolveRoute(body);
    } catch (err) {
      if (err instanceof RouteError) {
        sendJson(res, 400, { error: err.message.slice(0, 300) });
        return;
      }
      throw err;
    }
    let apiKey = null;
    if (body.apiKey != null) {
      if (typeof body.apiKey !== "string" || body.apiKey.length === 0 || body.apiKey.length > 4096 || /[\s\p{Cc}]/u.test(body.apiKey)) {
        sendJson(res, 400, { error: "apiKey must be a non-empty printable string" });
        return;
      }
      apiKey = body.apiKey;
    }
    const id = `dshan-${randomUUID().replaceAll("-", "").slice(0, 24)}`;
    const overlayPath = join(DSH_HOME, "overlays", `${id}.yml`);
    await mkdir(join(DSH_HOME, "overlays"), { recursive: true });
    await writeFile(overlayPath, overlayFor(route), { mode: 0o600 });
    sessions.set(id, {
      dshSessionId: null,
      apiKey,
      route,
      overlayPath,
      events: [],
      created: new Date().toISOString(),
      turns: 0,
    });
    sendJson(res, 200, { sessionId: id });
    return;
  }
  const match = url.pathname.match(/^\/v1\/analyzer-sessions\/([A-Za-z0-9-]+)(\/messages|\/events)?$/);
  if (!match || !sessions.has(match[1])) {
    sendJson(res, 404, { error: "unknown session" });
    return;
  }
  const session = sessions.get(match[1]);
  if (req.method === "POST" && match[2] === "/messages") {
    const body = JSON.parse(await readBody(req));
    if (typeof body?.prompt !== "string" || body.prompt.length === 0) {
      sendJson(res, 400, { error: "prompt must be a non-empty string" });
      return;
    }
    const result = await enqueue(() =>
      runTurn(session.dshSessionId, body.prompt, session.apiKey, session.route, session.overlayPath),
    );
    session.dshSessionId = result.dshSessionId ?? session.dshSessionId;
    session.events.push(...result.events);
    session.events = session.events.slice(0, MAX_EVENTS);
    session.turns += 1;
    sendJson(res, 200, {
      status: "completed",
      response: result.text,
      model: `${session.route.provider}/${session.route.model}`,
    });
    return;
  }
  if (req.method === "GET" && match[2] === "/events") {
    const limit = Math.min(Number(url.searchParams.get("limit") ?? MAX_EVENTS) || MAX_EVENTS, MAX_EVENTS);
    sendJson(res, 200, { events: session.events.slice(0, limit) });
    return;
  }
  if (req.method === "DELETE" && match[2] === undefined) {
    sessions.delete(match[1]);
    await prunePersistedSession(session.dshSessionId);
    await rm(session.overlayPath, { force: true }).catch(() => {});
    res.writeHead(204).end();
    return;
  }
  sendJson(res, 404, { error: "unknown route" });
}

await mkdir(WORKSPACE, { recursive: true });

// Boot check: every allowlisted route's generated overlay must compose
// against the pinned profile. This validates overlay syntax and profile
// compatibility, not gateway reachability.
if (!process.env.DSH_ANALYZER_SKIP_BOOT_CHECK) {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  for (const providerId of Object.keys(ROUTES.providers)) {
    const entry = ROUTES.providers[providerId];
    const model = entry.models && Object.keys(entry.models)[0]
      ? Object.keys(entry.models)[0]
      : (providerId === ROUTES.default.provider ? ROUTES.default.model : null);
    if (!model) continue;
    const route = {
      provider: providerId,
      model,
      reasoningEffort: ROUTES.default.reasoningEffort,
      contextWindow: entry.models?.[model]?.contextWindow ?? 1_000_000,
      maxTokens: entry.models?.[model]?.maxTokens ?? 131_072,
      kind: entry.kind ?? "pi-ai",
    };
    const probe = join(DSH_HOME, "overlays", "boot-check.yml");
    await mkdir(join(DSH_HOME, "overlays"), { recursive: true });
    await writeFile(probe, overlayFor(route), { mode: 0o600 });
    try {
      await run("dsh", ["--profile", PROFILE, "--patch", probe, "--dump-config"], {
        env: { ...process.env, DSH_HOME },
        timeout: 30_000,
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (err) {
      console.error(`dsh-analyzer-adapter: route ${providerId} overlay failed to compose: ${err.message}`);
      process.exit(2);
    }
    await rm(probe, { force: true });
  }
}

const [host, port] = ADDR.split(":");
server.listen(Number(port), host, () => {
  const marker = createHash("sha256").update(`${PROFILE}:${MODEL}:${PRESET}`).digest("hex").slice(0, 12);
  console.log(`dsh-analyzer-adapter: ${ADDR} profile=${PROFILE} default=${ROUTES.default.provider}/${ROUTES.default.model}@${ROUTES.default.reasoningEffort} routes=${Object.keys(ROUTES.providers).length} preset=${PRESET} identity=${marker}`);
});
