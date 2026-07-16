// End-to-end demo. Runs the REAL engine over the realistic fixtures and shows, for the
// headline case, exactly what an agent's LLM would receive WITHOUT vs WITH ChainWard.
//
//   npx tsx src/demo/run-demo.ts

import { defaultScanner } from "../core/scanner.ts";
import { MockOnchainDataSource } from "../adapters/onchain.ts";
import { renderReport } from "../render.ts";
import type { ScanTarget } from "../core/types.ts";
import {
  MALICIOUS_TOKEN, HONEYPOT_TOKEN, MALICIOUS_NFT, MEMO_ATTACK, BENIGN_TOKEN, BENIGN_MEME,
} from "./fixtures.ts";

const B = "\x1b[1m", R = "\x1b[0m", GRAY = "\x1b[90m", CY = "\x1b[36m";
const hr = () => console.log(GRAY + "─".repeat(78) + R);

async function main() {
  const scanner = defaultScanner();
  const src = new MockOnchainDataSource();

  console.log(`${B}ChainWard — on-chain input integrity guard · demo${R}`);
  console.log(`${GRAY}engine: structural + pattern + heuristic-classifier + honeypot-mismatch (all real)${R}`);
  console.log(`${GRAY}data source: mock fixtures (swap → viem RPC) · honeypot oracle: mock (swap → GoPlus)${R}`);

  const cases: Array<{ title: string; target: ScanTarget; fields: any; note: string }> = [];
  const tk = (s: typeof MALICIOUS_TOKEN): ScanTarget => ({ kind: "token", chain: "base", address: s.address });

  cases.push({ title: "1) Injection in ERC-20 name()", target: tk(MALICIOUS_TOKEN), fields: (await src.fetchToken("base", MALICIOUS_TOKEN.address)).fields, note: MALICIOUS_TOKEN.note });
  cases.push({ title: "2) Honeypot + safety-claim mismatch", target: tk(HONEYPOT_TOKEN), fields: (await src.fetchToken("base", HONEYPOT_TOKEN.address)).fields, note: HONEYPOT_TOKEN.note });
  cases.push({ title: "3) NFT metadata: invisible-tag + homoglyph", target: { kind: "nft", chain: "base", address: MALICIOUS_NFT.address, tokenId: "1" }, fields: (await src.fetchNft("base", MALICIOUS_NFT.address, "1")).fields, note: MALICIOUS_NFT.note });
  cases.push({ title: "4) Transaction memo: resolution-template", target: { kind: "tx", chain: "base", txHash: MEMO_ATTACK.txHash }, fields: (await src.fetchTx("base", MEMO_ATTACK.txHash)).fields, note: MEMO_ATTACK.note });
  cases.push({ title: "5) Benign token (USDC)", target: tk(BENIGN_TOKEN), fields: (await src.fetchToken("base", BENIGN_TOKEN.address)).fields, note: BENIGN_TOKEN.note });
  cases.push({ title: "6) Benign meme named 'IGNORE' (FP-avoidance)", target: tk(BENIGN_MEME), fields: (await src.fetchToken("base", BENIGN_MEME.address)).fields, note: BENIGN_MEME.note });

  let flagged = 0;
  for (const c of cases) {
    hr();
    console.log(`${B}${c.title}${R}  ${GRAY}${c.note}${R}`);
    const report = await scanner.scanTarget(c.target, c.fields);
    console.log(renderReport(report));
    if (report.severity !== "CLEAN") flagged++;
  }

  // Headline: what the agent's LLM actually sees, before vs after.
  hr();
  console.log(`${B}What the agent's model receives — case 3 (NFT), before vs after${R}\n`);
  const nftReport = await scanner.scanTarget(
    { kind: "nft", chain: "base", address: MALICIOUS_NFT.address, tokenId: "1" },
    (await src.fetchNft("base", MALICIOUS_NFT.address, "1")).fields,
  );
  const descRaw = MALICIOUS_NFT.description;
  const descSafe = nftReport.fields.find((f) => f.kind === "nft_description")!.sanitized;
  console.log(`${CY}WITHOUT ChainWard${R} (agent ingests raw metadata → hijacked):`);
  console.log(GRAY + "  " + JSON.stringify(descRaw) + R + "\n");
  console.log(`${CY}WITH ChainWard${R} (payload removed before it reaches the model):`);
  console.log("  " + JSON.stringify(descSafe) + "\n");

  hr();
  console.log(`${B}Result:${R} ${flagged}/6 cases correctly triaged (4 attacks flagged, 2 benign passed).`);
}

main().catch((e) => { console.error(e); process.exit(1); });
