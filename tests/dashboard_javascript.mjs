import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

// Execute the real pure rendering helpers, without starting the dashboard or
// requiring a browser. This checks retained-evidence handling and HTML escaping.
// The dashboard behaviour moved to a same-origin asset so the HTML can run
// under a strict CSP; these helpers remain the DOM-free pure block in it.
const page = readFileSync(new URL("../src/ui/dashboard.js", import.meta.url), "utf8");
const escape = page.split("\n").find(line => line.startsWith("const esc ="));
const helpers = page.slice(page.indexOf("function statusLabel("), page.indexOf("function cancelDetailRequest("));
assert.ok(escape && helpers.includes("function javascriptStackMarkup("));
const context = vm.createContext({});
vm.runInContext(`${escape}\n${helpers}\nglobalThis.render = javascriptStackMarkup;`, context);

function report(overrides = {}) {
  return { evidence: [{
    id: "query-1", command: 'Forensicator MCP javascript_stack; {"include_jit":true}; dump=current verified dump',
    status: "present", text: JSON.stringify({
      kind: "forensicator.javascriptStack.v1", threadId: 42, heapCaptured: true,
      recoveredFrameCount: 1, optimizedFrameCount: 1, candidateFrameCount: 1, omittedFrameCount: 0,
      frames: [{threadId: 42, depth: 0, frameType: "OptimizedJavaScript", function: "optimizedFunction",
        script: "fixture.js", functionStartLine: 2, metadataRecovered: true, framePc: "0xffffffffffffffff", framePointer: "0x10000",
        jit: {codeResolution: {codeObject: "0x600000100", entrypoint: "0x200001000"}, slotCount: 3, sfiCrosscheck: true}}],
      limitations: ["Physical frames only; inlined logical frames are unavailable."], ...overrides,
    }),
  }] };
}

test("optimized frames show physical locations, JIT evidence and function-start semantics", () => {
  const html = context.render(report());
  assert.match(html, /optimizedFunction/);
  assert.match(html, /OptimizedJavaScript/);
  assert.match(html, /function starts at line 2/);
  assert.match(html, /0xffffffffffffffff/);
  assert.match(html, /0x600000100/);
  assert.match(html, /inlined logical frames/);
  assert.match(html, /data-evidence-index="0"/);
});

test("untrusted function, script and limitation text is escaped", () => {
  const html = context.render(report({frames: [{function: '<img src=x onerror="alert(1)">', script: "<script>evil()</script>"}], limitations: ["<svg onload=evil()>"]}));
  assert.doesNotMatch(html, /<img|<script>|<svg/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script&gt;/);
});

test("missing, failed and truncated observations remain explicit and do not fabricate frames", () => {
  assert.equal(context.render({evidence: []}), "");
  const failed = report();
  Object.assign(failed.evidence[0], {status: "failed", text: "", error: "Recovery failed"});
  assert.match(context.render(failed), /No complete JavaScript recovery result/);
  const html = context.render(report({frames: [], recoveredFrameCount: 0, heapCaptured: false, omittedFrameCount: 2}));
  assert.match(html, /No JavaScript frame candidates/);
  assert.match(html, /Not established/);
  assert.doesNotMatch(html, /optimizedFunction/);
  const unrelated = report();
  unrelated.evidence[0].command = "model-supplied transcript";
  assert.equal(context.render(unrelated), "");
});
