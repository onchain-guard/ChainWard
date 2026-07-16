import type { Detector } from "../detector.ts";
import type { Signal } from "../types.ts";
import type { HoneypotOracle } from "../honeypot.ts";
import { deceptionSignal, extractSafetyClaims } from "../honeypot.ts";
import { identityDeception } from "../truth.ts";

const CHECKED = new Set(["token_name", "token_symbol", "nft_description", "nft_name"]);

// Wraps the honeypot oracle. Only fires for token/nft fields that carry a contract address.
export function deceptionDetector(oracle: HoneypotOracle): Detector {
  return {
    id: "l3.deception",
    layer: "deception",
    async detect({ normalized, kind, ctx }): Promise<Signal[]> {
      if (!ctx.address || !CHECKED.has(kind)) return [];
      const out: Signal[] = [];
      const claims = extractSafetyClaims(normalized);
      const behavior = await oracle.check(ctx.chain ?? "ethereum", ctx.address);
      const dec = deceptionSignal(claims, behavior);
      if (dec) out.push(dec);
      const idSig = identityDeception(normalized, ctx.chain ?? "ethereum", ctx.address);
      if (idSig) out.push(idSig);
      return out;
    },
  };
}
