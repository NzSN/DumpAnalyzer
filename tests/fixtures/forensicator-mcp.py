#!/usr/bin/python3
"""Controlled MCP peer for the bridge tests; no network or real captures."""
import json
import os
from pathlib import Path
import sys
import time

assert sys.argv[1:] == ["mcp"]
assert not any(name.startswith(("DUMP_ANALYZER_", "DSH_")) for name in os.environ)
mode = Path("mode").read_text() if Path("mode").exists() else "ok"
stage = 0
for line in sys.stdin:
    request = json.loads(line)
    with Path("wire.jsonl").open("a") as log:
        log.write(json.dumps(request) + "\n")
    method = request["method"]
    if method == "initialize":
        assert stage == 0
        stage = 1
        result = {"protocolVersion": "2024-11-05" if mode == "legacy" else "2025-11-25",
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture-forensicator", "version": "1"}}
        if mode == "bad_version":
            result["protocolVersion"] = "unsupported"
    elif method == "notifications/initialized":
        assert stage == 1
        stage = 2
        continue
    elif method == "tools/list":
        assert stage == 2
        stage = 3
        result = {"tools": [{"name": name} for name in
                            ["inspect", "analyze", "match", "list_plugins"]]}
        if mode == "missing_tools":
            result["tools"] = []
    else:
        assert method == "tools/call" and stage == 3
        stage = 4
        params = request["params"]
        if mode == "wait":
            Path("child.pid").write_text(str(os.getpid()))
            time.sleep(60)
        if mode == "wire_limit":
            sys.stdout.write("x" * (1024 * 1024 + 1))
            sys.stdout.flush()
            time.sleep(60)
        if mode == "malformed":
            print("invalid JSON secret-do-not-retain", flush=True)
            continue
        if mode == "rpc_error":
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32603, "message": "secret-do-not-retain"}}), flush=True)
            continue
        data = {"tool": params["name"], "arguments": params["arguments"],
                "confidence": "unknown", "overall": "mismatch"}
        if mode == "javascript":
            assert params["name"] == "analyze"
            data = json.loads(Path("javascript.json").read_text())
            data["plugins"] = [p for p in data["plugins"] if p["name"] in params["arguments"]["plugins"]]
        if mode == "retained_limit":
            data["large"] = "é" * 10000
        result = {"structuredContent": data, "isError": False,
                  "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}]}
        if mode == "tool_error":
            result = {"isError": True, "content": [{"type": "text", "text": "Malformed synthetic dump"}]}
        if mode == "legacy":
            del result["structuredContent"]
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"] + (1 if mode == "wrong_id" else 0),
                      "result": result}, ensure_ascii=False), flush=True)
