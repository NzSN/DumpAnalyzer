import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { createAdapter, overlayFor, resolveRoute, runTurn, SessionRevoked, validateAnalysisMcp } from "./server.mjs";

const routes = {
  default: { provider: "test", model: "test-model", reasoningEffort: "high" },
  providers: { test: { kind: "pi-ai", apiKeyEnv: "TEST_PROVIDER_KEY", models: {
    "test-model": { contextWindow: 8192, maxTokens: 1024 },
  } } },
};
const route = resolveRoute({}, routes);
const mcp = { url: "http://127.0.0.1:49152/mcp", token: "mcp-secret-unique" };

function fakeChild(onPrompt = () => {}, killDelay = 0) {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.closed = false;
  child.close = (code = 0) => {
    if (child.closed) return;
    child.closed = true;
    child.emit("close", code);
  };
  child.kill = (signal) => {
    child.killed = signal;
    setTimeout(() => child.close(null), killDelay);
    return true;
  };
  child.stdin.on("finish", () => queueMicrotask(() => onPrompt(child)));
  return child;
}
function turnOptions(extra = {}) {
  return { home: "/tmp/test-dsh-home", prompt: "assess", route,
    overlayPath: "/tmp/test-overlay.yml", timeoutMs: 500, ...extra };
}
async function adapter(t, options = {}) {
  const home = await mkdtemp(join(tmpdir(), "dump-analyzer-adapter-test-"));
  const server = createAdapter({ home, routes, token: "adapter-secret-unique", ...options });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(home, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}/v1/analyzer-sessions`;
  async function request(path = "", method = "GET", body) {
    return fetch(base + path, { method,
      headers: { authorization: "Bearer adapter-secret-unique", "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }
  async function create(body = {}) {
    const res = await request("", "POST", { preset: "analyzer-triage", ...body });
    assert.equal(res.status, 200);
    return res.json();
  }
  return { home, request, create };
}

test("MCP is opt-in and accepts only literal loopback bridge URLs and printable tokens", () => {
  assert.equal(validateAnalysisMcp(undefined, false), null);
  assert.throws(() => validateAnalysisMcp(mcp, false), /DSH_ANALYZER_ALLOW_MCP/);
  assert.deepEqual(validateAnalysisMcp(mcp, true), mcp);
  for (const url of ["https://127.0.0.1:42/mcp", "http://localhost:42/mcp", "http://127.1:42/mcp",
    "http://2130706433:42/mcp", "http://127.0.0.1/mcp", "http://127.0.0.1:0/mcp",
    "http://127.0.0.1:65536/mcp", "http://127.0.0.1:42/a/../mcp", "http://127.0.0.1:42/mcp?x=1",
    "http://127.0.0.1:42/mcp#x", "http://user@127.0.0.1:42/mcp", "http://[::1]:42/mcp",
    "http://127.0.0.1:42/mcp\n", "http://127.0.0.1:042/mcp"]) {
    assert.throws(() => validateAnalysisMcp({ ...mcp, url }, true), /analysisMcp.url/);
  }
  for (const token of ["", "bad\nkey", "has space", "é", "a".repeat(4097), null]) {
    assert.throws(() => validateAnalysisMcp({ ...mcp, token }, true), /analysisMcp.token/);
  }
  for (const value of [null, [], "url", { ...mcp, command: "bash" }]) {
    assert.throws(() => validateAnalysisMcp(value, true), /analysisMcp/);
  }
});

test("MCP overlay adds only fixed dump tools, keeps resources disabled, and contains no credential", () => {
  const plain = overlayFor(route);
  assert.doesNotMatch(plain, /mcp|system-prompt/);
  const enabled = overlayFor(route, mcp);
  assert.match(enabled, /- insert:\n    - id: mcp-dump-analysis/);
  assert.match(enabled, /name: "@deepseek-ai\/dsh-mcp-client"/);
  assert.match(enabled, /serverName: dump_analysis/);
  assert.match(enabled, /toolCallTimeoutMs: 30000/);
  assert.match(enabled, /maxInstructionBytes: 2048/);
  assert.match(enabled, /reconnect:\n          enabled: false/);
  assert.match(enabled, /id: mcp-resources\n  disabled: true/);
  assert.match(enabled, /process.env.DUMP_ANALYZER_MCP_TOKEN/);
  assert.doesNotMatch(enabled, /mcp-secret-unique|tool-bash|tool-fs|tool-web/);
});

test("MCP mode refuses an unauthenticated adapter while evidence-only mode remains compatible", () => {
  for (const token of [null, "", " ", "bad\nkey", "x".repeat(4097)]) {
    assert.throws(() => createAdapter({ home: "/tmp/unused-adapter", routes, allowMcp: true, token }),
      /requires.*DSH_ANALYZER_ADAPTER_TOKEN/);
  }
  assert.doesNotThrow(() => createAdapter({ home: "/tmp/unused-adapter", routes, allowMcp: false, token: null }));
});

test("headless child receives per-run credentials only through env and output is redacted", async () => {
  let options;
  const key = "provider-secret-unique";
  const child = fakeChild((proc) => {
    proc.stdout.write(JSON.stringify({ type: "session", sessionId: "session-123" }) + "\n");
    const value = { type: "final", text: [key, mcp.token, "adapter-secret-unique"].join(" ") };
    // Redaction must happen after JSON decoding, including escaped secrets.
    proc.stdout.write(JSON.stringify(value).replace("provider", "\\u0070rovider") + "\n");
    proc.close();
  });
  const result = await runTurn(turnOptions({ apiKey: key, analysisMcp: mcp,
    adapterToken: "adapter-secret-unique", spawnImpl: (_, args, opts) => {
      options = opts;
      assert.doesNotMatch(JSON.stringify(args), /secret/);
      return child;
    },
  }));
  assert.equal(options.env.TEST_PROVIDER_KEY, key);
  assert.equal(options.env.DUMP_ANALYZER_MCP_TOKEN, mcp.token);
  assert.equal(result.text, "[redacted] [redacted] [redacted]");
  assert.doesNotMatch(JSON.stringify(result.events), /secret-unique/);
});

test("stdout acquisition cap kills the child during streaming and hides stderr", async () => {
  const child = fakeChild((proc) => {
    proc.stderr.write("provider-secret".repeat(10_000));
    proc.stdout.write("x".repeat(65));
    assert.equal(proc.killed, "SIGKILL");
  });
  await assert.rejects(runTurn(turnOptions({ spawnImpl: () => child, maxStdoutBytes: 64, maxStderrBytes: 32 })),
    /stdout exceeded.*acquisition budget/);
  assert.equal(child.closed, true);
});

test("abort waits for child exit and an already revoked run never spawns", async () => {
  const controller = new AbortController();
  const child = fakeChild(() => controller.abort(), 20);
  await assert.rejects(runTurn(turnOptions({ signal: controller.signal, spawnImpl: () => child })), SessionRevoked);
  assert.equal(child.closed, true);
  await assert.rejects(runTurn(turnOptions({ signal: controller.signal,
    spawnImpl: () => { assert.fail("revoked turn spawned"); },
  })), SessionRevoked);
});

test("callback and stdin failures kill the child without exposing exception text", async () => {
  const child = fakeChild((proc) => proc.stdout.write('{"type":"session","sessionId":"okay"}\n'));
  await assert.rejects(runTurn(turnOptions({ spawnImpl: () => child,
    onSession: () => { throw new Error("provider-secret"); },
  })), /headless output processing failed/);
  assert.equal(child.killed, "SIGKILL");
  const broken = fakeChild((proc) => proc.stdin.emit("error", new Error("provider-secret")));
  await assert.rejects(runTurn(turnOptions({ spawnImpl: () => broken })), /headless prompt delivery failed/);
});

test("DELETE kills active work, prevents a queued turn, prunes evidence and overlay", async (t) => {
  let starts = 0;
  let active;
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const app = await adapter(t, { allowMcp: true, spawnImpl: () => {
    starts += 1;
    active = fakeChild((proc) => {
      proc.stdout.write('{"type":"session","sessionId":"persisted-session"}\n');
      started();
    }, 20);
    return active;
  } });
  const session = await app.create({ analysisMcp: mcp, apiKey: "provider-secret-unique" });
  assert.equal(session.analysisTools, true);
  const overlay = join(app.home, "overlays", `${session.sessionId}.yml`);
  assert.doesNotMatch(await readFile(overlay, "utf8"), /secret-unique/);
  const persisted = join(app.home, "sessions", "workspace", "persisted-session");
  await mkdir(persisted, { recursive: true });
  await writeFile(join(persisted, "events"), "private");
  const first = app.request(`/${session.sessionId}/messages`, "POST", { prompt: "first" });
  await ready;
  const second = app.request(`/${session.sessionId}/messages`, "POST", { prompt: "queued" });
  // Ensure the second HTTP request has reached the adapter before DELETE.
  await app.request(`/${session.sessionId}/events`);
  const deleted = await app.request(`/${session.sessionId}`, "DELETE");
  assert.equal(deleted.status, 204);
  assert.equal(active.closed, true);
  assert.equal(active.killed, "SIGKILL");
  assert.equal((await first).status, 410);
  assert.ok([404, 410].includes((await second).status));
  assert.equal(starts, 1);
  await assert.rejects(access(persisted));
  await assert.rejects(access(overlay));
  assert.equal((await app.request(`/${session.sessionId}/events`)).status, 404);
});

test("sessions without MCP keep the zero-tool contract and disabled mode rejects metadata", async (t) => {
  const app = await adapter(t);
  const rejected = await app.request("", "POST", { preset: "analyzer-triage", analysisMcp: mcp });
  assert.equal(rejected.status, 400);
  assert.doesNotMatch(await rejected.text(), /mcp-secret/);
  const session = await app.create();
  assert.equal(session.analysisTools, undefined);
  assert.doesNotMatch(await readFile(join(app.home, "overlays", `${session.sessionId}.yml`), "utf8"), /mcp/);
  assert.equal((await app.request(`/${session.sessionId}`, "DELETE")).status, 204);
});

test("abandoned sessions expire and remove their overlay", async (t) => {
  const app = await adapter(t, { allowMcp: true, sessionTtlMs: 30 });
  const session = await app.create({ analysisMcp: mcp });
  const deadline = Date.now() + 1000;
  while ((await app.request(`/${session.sessionId}/events`)).status !== 404 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal((await app.request(`/${session.sessionId}/events`)).status, 404);
  // Removal follows revocation asynchronously.
  while ((await readdir(join(app.home, "overlays"))).length && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.deepEqual(await readdir(join(app.home, "overlays")), []);
});
