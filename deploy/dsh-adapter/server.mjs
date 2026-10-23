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
// The profile pins the model route, so a request `model` different from
// DSH_ANALYZER_MODEL is rejected rather than silently redirected.
//
// Environment:
//   DSH_HOME                       dedicated harness home (required)
//   DSH_ANALYZER_PROFILE           profile name (default: analyzer)
//   DSH_ANALYZER_MODEL             pinned model id (default: deepseek-v4.1-flash)
//   DSH_ANALYZER_PRESET            only accepted preset (default: analyzer-triage)
//   DSH_ANALYZER_ADAPTER_TOKEN     optional bearer token
//   DSH_ANALYZER_ADAPTER_ADDR      bind address (default: 127.0.0.1:4181)
//   DSH_ANALYZER_MESSAGE_TIMEOUT_MS  per-message run cap (default: 170000)

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

// Dedicated empty working directory: no AGENTS.md, skills, or other
// cwd-scoped content channels exist even if a profile change re-enabled one.
const WORKSPACE = join(DSH_HOME, "workspace");

/** @type {Map<string, {dshSessionId: string|null, events: unknown[], created: string, turns: number}>} */
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
function runTurn(dshSessionId, prompt) {
  return new Promise((resolve, reject) => {
    const args = ["--profile", PROFILE, "--json"];
    if (dshSessionId) args.push("--session-id", dshSessionId);
    const child = spawn("dsh", args, {
      cwd: WORKSPACE,
      env: { ...process.env, DSH_HOME },
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
    if (body.model != null && body.model !== MODEL) {
      sendJson(res, 409, { error: `model is pinned to ${MODEL} by the analyzer profile` });
      return;
    }
    const id = `dshan-${randomUUID().replaceAll("-", "").slice(0, 24)}`;
    sessions.set(id, { dshSessionId: null, events: [], created: new Date().toISOString(), turns: 0 });
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
    const result = await enqueue(() => runTurn(session.dshSessionId, body.prompt));
    session.dshSessionId = result.dshSessionId ?? session.dshSessionId;
    session.events.push(...result.events);
    session.events = session.events.slice(0, MAX_EVENTS);
    session.turns += 1;
    sendJson(res, 200, { status: "completed", response: result.text, model: MODEL });
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
    res.writeHead(204).end();
    return;
  }
  sendJson(res, 404, { error: "unknown route" });
}

await mkdir(WORKSPACE, { recursive: true });
const [host, port] = ADDR.split(":");
server.listen(Number(port), host, () => {
  const marker = createHash("sha256").update(`${PROFILE}:${MODEL}:${PRESET}`).digest("hex").slice(0, 12);
  console.log(`dsh-analyzer-adapter: ${ADDR} profile=${PROFILE} model=${MODEL} preset=${PRESET} identity=${marker}`);
});
