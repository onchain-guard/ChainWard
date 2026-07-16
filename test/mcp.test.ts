// Live MCP handshake test: spawns the real server, performs initialize → tools/list →
// tools/call over stdio JSON-RPC, and asserts the responses. Proves the server speaks
// real MCP (a real client — Claude Desktop, ElizaOS MCP plugin — can connect).
//
// Run: npx tsx --test test/mcp.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

function rpc(child: any, messages: object[]): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const out: any[] = [];
    let buf = "";
    const timer = setTimeout(() => reject(new Error("MCP timeout")), 15000);
    child.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) out.push(JSON.parse(line));
        if (out.length >= messages.filter((m: any) => m.id !== undefined).length) {
          clearTimeout(timer);
          resolve(out);
        }
      }
    });
    for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
  });
}

test("MCP server: initialize + tools/list + tools/call", async () => {
  const child = spawn("npx", ["tsx", "src/mcp/server.ts"], { stdio: ["pipe", "pipe", "inherit"] });
  try {
    const responses = await rpc(child, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "scan_onchain_data", arguments: { kind: "token", chain: "base", address: "0xdead1111111111111111111111111111beef0001" } } },
    ]);

    const init = responses.find((r) => r.id === 1);
    assert.equal(init.result.serverInfo.name, "chainward");

    const list = responses.find((r) => r.id === 2);
    assert.equal(list.result.tools[0].name, "scan_onchain_data");

    const call = responses.find((r) => r.id === 3);
    assert.equal(call.result.isError, true); // the injection token is MALICIOUS
    const report = JSON.parse(call.result.content[0].text);
    assert.equal(report.severity, "MALICIOUS");
  } finally {
    child.kill();
  }
});
