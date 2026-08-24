// Scan a REAL deployed contract, read live off the chain.
//
//   npx tsx src/live.ts                      # the built-in pair: a real impersonator + the genuine article
//   npx tsx src/live.ts ethereum 0xabc…      # any address you like
//
// Every other measurement in this repo runs on fixtures, which is the right call for a
// benchmark — determinism is what makes runs comparable. But a fixture cannot demonstrate
// the one claim that matters most: that L3 refutes a lie by checking it against reality
// rather than by judging how the text reads. A fixture agrees with whatever its author
// wrote. So this reads the chain.
//
// Read-only, no key, no funds, no account. `eth_call` costs nothing and changes nothing.
// The addresses below are verifiable by anyone: paste them into a block explorer.

import { ChainWardScanner, defaultRegistry, HeuristicClassifier } from "chainward";
import type { Severity, TargetContext } from "chainward";
import { readToken, type OnchainToken } from "./onchain-rpc.ts";
import { GoPlusHoneypotOracle } from "./goplus.ts";

const TARGET_CONTEXTS: TargetContext[] = ["llm-chat", "markdown-ui"];

/** The demo pair. The control matters as much as the attack: a detector that flags the
 *  impersonator but also flags Circle's own contract has not demonstrated anything. */
const DEFAULT_TARGETS: Array<{ chain: string; address: string; note: string }> = [
  {
    chain: "ethereum",
    address: "0x7558f7F023d676841ab118D4637a68943e650196",
    note: "ticker-squats USDC at an address that is not Circle's",
  },
  {
    chain: "ethereum",
    address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    note: "CONTROL — the genuine Circle USDC; must stay CLEAN",
  },
];

const ICON: Record<Severity, string> = { CLEAN: "✅", SUSPICIOUS: "⚠️ ", MALICIOUS: "🚨" };

async function scanOne(t: OnchainToken): Promise<void> {
  console.log(`\n  ${t.chain} · ${t.address}`);
  if (!t.hasCode) {
    console.log("    체인에 컨트랙트가 없다 — 판정할 대상 자체가 없음");
    return;
  }
  console.log(`    체인이 돌려준 값 (RPC ${t.rpc})`);
  console.log(`      name()   = ${JSON.stringify(t.name)}`);
  console.log(`      symbol() = ${JSON.stringify(t.symbol)}`);
  console.log(`      decimals = ${t.decimals ?? "—"}`);

  // Both halves of L3 are real here: identity is refuted against the chain (above), and
  // behavior comes from GoPlus rather than a fixture. `defaultScanner()` would have wired
  // the mock oracle, which is the thing this demo exists to stop doing.
  const oracle = new GoPlusHoneypotOracle();
  const scanner = new ChainWardScanner({
    registry: defaultRegistry({ classifier: new HeuristicClassifier(), honeypot: oracle }),
  });

  // Print the behavior verdict even when it is clean. A check whose result never surfaces
  // is indistinguishable from a check that never ran — and "no signal" here has two very
  // different causes worth telling apart: the contract behaved fine, or GoPlus had nothing
  // to say about it.
  const behavior = await oracle.check(t.chain, t.address);
  console.log(`    컨트랙트 행동 (${oracle.name})`);
  if (!behavior) {
    console.log("      판정 없음 — 이 컨트랙트에 대한 데이터가 없다 (≠ 안전하다)");
  } else {
    console.log(
      `      honeypot=${behavior.isHoneypot} sellable=${behavior.sellable} ` +
        `buyTax=${behavior.buyTaxPct ?? "?"}% sellTax=${behavior.sellTaxPct ?? "?"}%` +
        (behavior.flags.length ? ` flags=[${behavior.flags.join(", ")}]` : ""),
    );
  }
  const fields: Array<{ key: string; kind: "token_name" | "token_symbol"; value: string }> = [
    { key: "name", kind: "token_name", value: t.name },
    { key: "symbol", kind: "token_symbol", value: t.symbol },
  ];

  console.log("    ChainWard 판정");
  for (const f of fields) {
    if (!f.value) {
      console.log(`      ${f.key.padEnd(7)} (빈 값 — 스캔 생략)`);
      continue;
    }
    const s = await scanner.scanField(f.kind, f.value, {
      chain: t.chain,
      address: t.address,
      targetContexts: TARGET_CONTEXTS,
    });
    console.log(`      ${f.key.padEnd(7)} ${ICON[s.severity]} ${s.severity}`);
    for (const sig of s.signals) console.log(`                └─ ${sig.code} — ${sig.detail}`);
  }
}

async function main(): Promise<void> {
  const [chain, address] = process.argv.slice(2);
  const targets = chain && address ? [{ chain, address, note: "사용자 지정" }] : DEFAULT_TARGETS;

  console.log("실제 체인에서 읽어 스캔 — 읽기 전용, 키·자금 불필요");
  for (const t of targets) {
    console.log(`\n──── ${t.note}`);
    try {
      await scanOne(await readToken(t.chain, t.address));
    } catch (e) {
      // A public endpoint that rate-limits should not read as "this contract is fine".
      console.log(`    RPC 실패 — 판정 없음: ${(e as Error).message}`);
    }
  }
  console.log(
    "\n주의: 티커 사칭은 체인이 확인해주는 사실이다 — 배포자의 의도가 사기였는지는 별개이고, " +
      "이 도구는 그걸 주장하지 않는다.",
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
