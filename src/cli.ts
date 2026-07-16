#!/usr/bin/env -S npx tsx
// ChainWard CLI — real, wired to the real engine (mock data source + mock oracle).
//
//   npx tsx src/cli.ts scan token <chain> <address>
//   npx tsx src/cli.ts scan nft   <chain> <address> <tokenId>
//   npx tsx src/cli.ts scan tx    <chain> <txHash>
//   npx tsx src/cli.ts text <fieldKind> "<arbitrary text>"
//
// To run against real chains: swap MockOnchainDataSource -> RpcOnchainDataSource in the
// factory below (see src/adapters/onchain.ts).

import type { FieldKind, ScanTarget } from "../packages/core/src/core/types.ts";
import { defaultScanner } from "../packages/core/src/core/scanner.ts";
import { MockOnchainDataSource } from "./adapters/onchain.ts";
import { renderReport, renderField } from "../packages/core/src/render.ts";

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);

  // subcommands that hand off to a long-running server (they read process.argv themselves)
  if (cmd === "proxy") { await import("./proxy/server.ts"); return; }
  if (cmd === "mcp") { await import("./mcp/server.ts"); return; }

  const scanner = defaultScanner();
  const source = new MockOnchainDataSource(); // REAL IMPL: new RpcOnchainDataSource()

  if (cmd === "text") {
    const kind = (rest[0] ?? "tx_memo") as FieldKind;
    const text = rest.slice(1).join(" ");
    if (!text) return usage("text mode needs a string");
    const f = await scanner.scanField(kind, text);
    console.log(renderField(f));
    process.exit(f.severity === "MALICIOUS" ? 2 : f.severity === "SUSPICIOUS" ? 1 : 0);
  }

  if (cmd !== "scan") return usage();
  const [kind, chain, address, tokenId] = rest;
  if (!kind || !chain) return usage();

  let fields;
  const target: ScanTarget = { kind: kind as ScanTarget["kind"], chain, address, tokenId, txHash: kind === "tx" ? address : undefined };
  if (kind === "token") fields = (await source.fetchToken(chain, address)).fields;
  else if (kind === "nft") fields = (await source.fetchNft(chain, address, tokenId ?? "1")).fields;
  else if (kind === "tx") { target.txHash = address; target.address = undefined; fields = (await source.fetchTx(chain, address)).fields; }
  else return usage(`unknown target kind: ${kind}`);

  const report = await scanner.scanTarget(target, fields);
  console.log(renderReport(report));
  process.exit(report.severity === "MALICIOUS" ? 2 : report.severity === "SUSPICIOUS" ? 1 : 0);
}

function usage(err?: string) {
  if (err) console.error(`error: ${err}\n`);
  console.log(
    [
      "chainward — on-chain input integrity guard",
      "",
      "  scan token <chain> <address>",
      "  scan nft   <chain> <address> <tokenId>",
      "  scan tx    <chain> <txHash>",
      "  text <fieldKind> \"<text>\"",
      "",
      "demo addresses (mock source):",
      "  token 0xdead1111111111111111111111111111beef0001   (injection in name)",
      "  token 0xhoneypot000000000000000000000000000000dead (honeypot + safety claim)",
      "  token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48   (USDC, clean)",
      "  nft   0xnft22222222222222222222222222222222c0de 1  (metadata injection)",
      "  tx    0xabc...0001                                 (memo injection)",
    ].join("\n"),
  );
  process.exit(err ? 64 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
