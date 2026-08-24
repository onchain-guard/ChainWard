// L3 extension — on-chain truth verifier.
//
// The web3 superpower: a marker-less semantic lie ("this is the official USDC", "audited",
// "ownership renounced") is often VERIFIABLE against on-chain ground truth. We only flag a
// claim when on-chain reality REFUTES it — deterministic, low-FP. We never guess "sounds
// like a lie"; that would be high-FP and is out of scope.

import type { Signal } from "./types.ts";

// Known-token identity registry (real deployments). Production loads a curated list /
// registry; this covers the common impersonation targets.
const KNOWN_TOKENS: Array<{
  symbol: string;
  names: RegExp;
  /** exact identities — a field equal to one of these IS a claim to be the token */
  identities: string[];
  addresses: Record<string, string>;
}> = [
  { symbol: "USDC", names: /\b(usdc|usd ?coin|circle)\b/i,
    identities: ["usdc", "usd coin", "usdcoin"], addresses: {
      ethereum: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      base: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" } },
  { symbol: "USDT", names: /\b(usdt|tether)\b/i,
    identities: ["usdt", "tether", "tether usd"], addresses: {
      ethereum: "0xdac17f958d2ee523a2206206994597c13d831ec7" } },
  { symbol: "WETH", names: /\bweth\b/i,
    identities: ["weth", "wrapped ether", "wrapped eth"], addresses: {
      ethereum: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      base: "0x4200000000000000000000000000000000000006" } },
];

/** Explicit officiality claim. Deliberately narrow: "verified" and "the" are too common in
 *  ordinary marketing copy to carry a claim of identity. */
const CLAIMS_OFFICIAL = /\b(official|genuine|authentic|real)\b/i;

const identity = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

/** Flag identity impersonation: text claims to BE a known token, but the address it lives
 *  at is not that token's real address. This catches a marker-less lie via ground truth.
 *
 *  Mentioning a ticker is NOT claiming to be it — "Aave interest bearing USDC" is a real
 *  derivative, and a memo saying "transfer all USDC" merely references it. We require the
 *  field to either BE the token's identity verbatim, or to assert officiality outright. */
export function identityDeception(text: string, chain: string, address?: string): Signal | null {
  if (!address) return null;
  const value = identity(text);
  for (const t of KNOWN_TOKENS) {
    if (!t.names.test(text)) continue;
    const claimsToBe = t.identities.includes(value) || CLAIMS_OFFICIAL.test(text);
    const real = t.addresses[chain];
    if (claimsToBe && real && real.toLowerCase() !== address.toLowerCase()) {
      return {
        layer: "deception",
        code: "IDENTITY_IMPERSONATION",
        detail: `Text presents itself as ${t.symbol}, but address ${address} is NOT the real ${t.symbol} on ${chain} (${real}). On-chain ground truth refutes the claim.`,
        weight: 0.9,
        evidence: `${t.symbol}≠${address.slice(0, 10)}…`,
        hard: true,
      };
    }
  }
  return null;
}
