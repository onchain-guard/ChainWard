// LAYER 3 — Deception cross-check (the differentiator).
//
// Honeypot tokens advertise safety in TEXT ("100% safe, audited, liquidity locked")
// while their CONTRACT BEHAVIOR is malicious (unsellable, 99% sell tax, upgradeable proxy).
// GoPlus/Honeypot.is already detect the *behavior*. Nobody cross-checks the *claim* against
// it. ChainWard does: claim ∧ malicious-behavior = high-confidence deception.
//
// Claim extraction is real. The behavior oracle is an INTERFACE: the demo uses a
// deterministic MockHoneypotOracle with GoPlus-shaped data; the real GoPlus adapter is
// written out (REAL IMPL) and swaps in with no other changes.

import type { Signal } from "./types.ts";

export interface HoneypotResult {
  isHoneypot: boolean;
  sellable: boolean;
  buyTaxPct?: number;
  sellTaxPct?: number;
  flags: string[]; // e.g. "cannot_sell_all", "hidden_owner", "proxy_upgradeable"
  source: string;
}

export interface HoneypotOracle {
  readonly name: string;
  check(chain: string, address: string): Promise<HoneypotResult | null>;
}

const CLAIM_RE =
  /\b(100% safe|safe|audited|verified|trusted|official|legit(?:imate)?|liquidity locked|lp locked|renounced|no ?tax|rug ?proof|kyc)\b/gi;

export function extractSafetyClaims(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(CLAIM_RE)) found.add(m[0].toLowerCase());
  return [...found];
}

/** Fuse a text's safety claims with real contract behavior into a deception Signal. */
export function deceptionSignal(claims: string[], behavior: HoneypotResult | null): Signal | null {
  if (!behavior) return null;
  const badBehavior = behavior.isHoneypot || !behavior.sellable || (behavior.sellTaxPct ?? 0) >= 50;
  if (claims.length > 0 && badBehavior) {
    return {
      layer: "deception",
      code: "CLAIM_BEHAVIOR_MISMATCH",
      detail:
        `Text claims [${claims.join(", ")}] but contract behavior is malicious ` +
        `(${behavior.flags.join(", ") || "honeypot"}; sellable=${behavior.sellable}, sellTax=${behavior.sellTaxPct ?? "?"}%). ` +
        `Classic honeypot bait aimed at an auto-trading agent.`,
      weight: 0.9,
      evidence: behavior.source,
      hard: true,
    };
  }
  if (badBehavior) {
    return {
      layer: "deception",
      code: "MALICIOUS_CONTRACT_BEHAVIOR",
      detail: `Contract behaves like a honeypot (${behavior.flags.join(", ")}), independent of its text.`,
      weight: 0.6,
      evidence: behavior.source,
    };
  }
  return null;
}

/** The address `MockHoneypotOracle` answers as a honeypot.
 *
 *  Exported because the benchmark corpus, the demo fixtures and the CLI examples must key
 *  off the SAME value. It used to be a magic string copied into five files, and the earlier
 *  copy (`0xhoneypot…`) was not even valid hex — so "clean up the malformed addresses"
 *  would have silently turned the honeypot case CLEAN while every test still passed. */
export const MOCK_HONEYPOT_ADDRESS = "0xdeadbeef0000000000000000000000000000dead";

/** Deterministic mock oracle with GoPlus-shaped responses. Address-keyed fixtures. */
export class MockHoneypotOracle implements HoneypotOracle {
  readonly name = "mock-goplus";
  private fixtures: Record<string, HoneypotResult>;

  constructor(fixtures?: Record<string, HoneypotResult>) {
    this.fixtures = fixtures ?? {
      // a honeypot: buyable, pumps, but cannot be sold
      [MOCK_HONEYPOT_ADDRESS]: {
        isHoneypot: true, sellable: false, buyTaxPct: 0, sellTaxPct: 100,
        flags: ["cannot_sell_all", "hidden_owner"], source: "mock-goplus",
      },
    };
  }

  async check(_chain: string, address: string): Promise<HoneypotResult | null> {
    const key = address.toLowerCase();
    return (
      this.fixtures[key] ?? {
        isHoneypot: false, sellable: true, buyTaxPct: 0, sellTaxPct: 0, flags: [], source: "mock-goplus",
      }
    );
  }
}

/* REAL IMPL — GoPlus Token Security API. Same interface, real network call.
 * Free, no key. Swap MockHoneypotOracle -> GoPlusHoneypotOracle in the scanner factory.
 *
 *   export class GoPlusHoneypotOracle implements HoneypotOracle {
 *     readonly name = "goplus";
 *     async check(chain: string, address: string): Promise<HoneypotResult | null> {
 *       const chainId = { ethereum: "1", base: "8453" }[chain] ?? chain;
 *       const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}` +
 *                   `?contract_addresses=${address.toLowerCase()}`;
 *       const r = await fetch(url);
 *       const j = await r.json();
 *       const t = j.result?.[address.toLowerCase()];
 *       if (!t) return null;
 *       const flags: string[] = [];
 *       if (t.cannot_sell_all === "1") flags.push("cannot_sell_all");
 *       if (t.hidden_owner === "1")    flags.push("hidden_owner");
 *       if (t.is_proxy === "1")        flags.push("proxy_upgradeable");
 *       if (t.is_blacklisted === "1")  flags.push("blacklist");
 *       return {
 *         isHoneypot: t.is_honeypot === "1",
 *         sellable:   t.cannot_sell_all !== "1",
 *         buyTaxPct:  Number(t.buy_tax) * 100,
 *         sellTaxPct: Number(t.sell_tax) * 100,
 *         flags, source: "goplus",
 *       };
 *     }
 *   }
 */
