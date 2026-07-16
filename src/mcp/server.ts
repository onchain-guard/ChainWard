// MCP server exposing ChainWard as a tool ANY MCP client can call (Claude Desktop,
// ElizaOS's MCP plugin, etc.). This is the "framework integration for free" path:
// ElizaOS consumes MCP servers, so this single file wires ChainWard into ElizaOS with
// zero ElizaOS-specific code.
//
// It speaks REAL MCP: newline-delimited JSON-RPC 2.0 over stdio (initialize / tools/list
// / tools/call). A real MCP client can connect to it today:
//   npx tsx src/mcp/server.ts
// then send an initialize message on stdin. (See test/mcp.test.ts for a live handshake.)
//
// PRODUCTION: replace the hand-rolled dispatch with @modelcontextprotocol/sdk —
//   const server = new Server({ name, version }, { capabilities: { tools: {} } });
//   server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: [TOOL] }));
//   server.setRequestHandler(CallToolRequestSchema, handleCall);
//   await server.connect(new StdioServerTransport());
// The tool schema and handler below are exactly what you register.

import { createInterface } from "node:readline";
import type { FieldKind } from "../core/types.ts";
import { defaultScanner } from "../core/scanner.ts";
import { MockOnchainDataSource } from "../adapters/onchain.ts";

const PROTOCOL_VERSION = "2024-11-05";
const scanner = defaultScanner();
const source = new MockOnchainDataSource(); // REAL IMPL: new RpcOnchainDataSource()

const TOOL = {
  name: "scan_onchain_data",
  description:
    "Scan on-chain text (token name/symbol, NFT metadata, tx memo) for prompt-injection " +
    "and honeypot deception BEFORE an agent acts on it. Returns a per-field verdict and a " +
    "model-safe 'sanitized' rendering to use in place of the raw text.",
  inputSchema: {
    type: "object",
    properties: {
      kind: { type: "string", enum: ["token", "nft", "tx", "text"] },
      chain: { type: "string", default: "ethereum" },
      address: { type: "string" },
      tokenId: { type: "string" },
      txHash: { type: "string" },
      text: { type: "string", description: "raw text (kind='text')" },
      fieldKind: { type: "string", description: "field kind for kind='text'" },
    },
    required: ["kind"],
  },
} as const;

async function runScan(args: any) {
  if (args.kind === "text") {
    const f = await scanner.scanField((args.fieldKind ?? "tx_memo") as FieldKind, String(args.text ?? ""));
    return { severity: f.severity, fields: [f], summary: `${f.severity} (${f.kind})` };
  }
  const chain = args.chain ?? "ethereum";
  let fields;
  const target = { kind: args.kind, chain, address: args.address, tokenId: args.tokenId, txHash: args.txHash };
  if (args.kind === "token") fields = (await source.fetchToken(chain, args.address)).fields;
  else if (args.kind === "nft") fields = (await source.fetchNft(chain, args.address, args.tokenId ?? "1")).fields;
  else if (args.kind === "tx") fields = (await source.fetchTx(chain, args.txHash)).fields;
  else throw new Error(`unknown kind: ${args.kind}`);
  return scanner.scanTarget(target, fields);
}

function reply(id: unknown, result: unknown) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
function replyError(id: unknown, code: number, message: string) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

async function dispatch(msg: any) {
  const { id, method, params } = msg;
  switch (method) {
    case "initialize":
      return reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "chainward", version: "0.1.0-demo" },
      });
    case "notifications/initialized":
      return; // notification, no response
    case "tools/list":
      return reply(id, { tools: [TOOL] });
    case "tools/call": {
      try {
        const report = await runScan(params?.arguments ?? {});
        return reply(id, {
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
          isError: report.severity === "MALICIOUS",
        });
      } catch (e) {
        return reply(id, { content: [{ type: "text", text: `scan error: ${(e as Error).message}` }], isError: true });
      }
    }
    default:
      if (id !== undefined) replyError(id, -32601, `method not found: ${method}`);
  }
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const t = line.trim();
  if (!t) return;
  let msg: any;
  try { msg = JSON.parse(t); } catch { return; }
  void dispatch(msg);
});

process.stderr.write("chainward MCP server ready (stdio, protocol " + PROTOCOL_VERSION + ")\n");
