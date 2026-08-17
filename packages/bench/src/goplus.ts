// A real HoneypotOracle backed by the GoPlus Token Security API.
//
// L3 fuses a text claim ("100% safe, audited") with what the contract actually does. Until
// now the behavior half came from `MockHoneypotOracle` — fixtures that agree with whatever
// the fixture author wrote, which is exactly what a claim-vs-reality check must not rest on.
// This asks a real service about a real contract.
//
// Not in `chainward` core, for the same reason as the RPC reader: core is zero-dependency
// and side-effect-free, and a library should not reach the network on its own. Core takes an
// oracle; supplying a real one is the caller's decision.
//
// PRIVACY: this sends the contract address to a third party (gopluslabs.io). The address is
// public on-chain data, but the *query* reveals what you are looking at. Anyone wiring this
// into a product should know that before it ships.

import type { HoneypotOracle, HoneypotResult } from "chainward";

const CHAIN_ID: Record<string, string> = {
  ethereum: "1",
  base: "8453",
  bsc: "56",
  polygon: "137",
  arbitrum: "42161",
};

/** GoPlus encodes booleans as the strings "0"/"1", and OMITS fields it has not determined.
 *  The distinction matters: a missing `cannot_sell_all` means "unknown", not "sellable". */
function tri(v: unknown): boolean | undefined {
  if (v === "1") return true;
  if (v === "0") return false;
  return undefined;
}

/** Taxes arrive as fractional strings ("0.1" = 10%). An absent or unparseable value is
 *  unknown — never 0, which would read as "no tax" and clear a 100%-sell-tax honeypot. */
function pct(v: unknown): number | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n * 100 : undefined;
}

export interface GoPlusOptions {
  timeoutMs?: number;
  /** override for tests; the default is the public endpoint */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class GoPlusHoneypotOracle implements HoneypotOracle {
  readonly name = "goplus";
  private readonly timeoutMs: number;
  private readonly baseUrl: string;
  private readonly doFetch: typeof fetch;

  constructor(opts: GoPlusOptions = {}) {
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.baseUrl = opts.baseUrl ?? "https://api.gopluslabs.io/api/v1/token_security";
    this.doFetch = opts.fetchImpl ?? fetch;
  }

  async check(chain: string, address: string): Promise<HoneypotResult | null> {
    const chainId = CHAIN_ID[chain];
    if (!chainId) return null; // an unsupported chain is "no data", not "clean"

    const key = address.toLowerCase();
    let body: { code?: number; result?: Record<string, Record<string, unknown>> };
    try {
      const res = await this.doFetch(`${this.baseUrl}/${chainId}?contract_addresses=${key}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) return null;
      body = (await res.json()) as typeof body;
    } catch {
      // A network failure must not be reported as a clean bill of health. Returning null
      // means "no behavior evidence", and `deceptionSignal` then emits no signal at all —
      // the scan degrades to text-only rather than silently asserting the contract is fine.
      return null;
    }

    // code 1 is a complete answer. Anything else (2 = still analysing, 4xx codes) is not
    // something to draw a verdict from.
    if (body.code !== 1) return null;
    const t = body.result?.[key];
    if (!t) return null;

    return this.map(t);
  }

  /** Exposed for tests: the mapping is where absent-means-safe bugs live, and it deserves
   *  coverage that does not depend on a third party being up. */
  map(t: Record<string, unknown>): HoneypotResult | null {
    const isHoneypot = tri(t.is_honeypot);
    const cannotSell = tri(t.cannot_sell_all);
    const buyTaxPct = pct(t.buy_tax);
    const sellTaxPct = pct(t.sell_tax);

    // GoPlus returns a thin record for tokens it has not fully analysed — real USDC comes
    // back without `cannot_sell_all` at all. If none of the load-bearing fields are present
    // there is nothing to judge, and inventing `sellable: true` from silence would let an
    // unanalysed honeypot pass as verified-safe.
    if (isHoneypot === undefined && cannotSell === undefined && sellTaxPct === undefined) {
      return null;
    }

    const flags: string[] = [];
    if (cannotSell === true) flags.push("cannot_sell_all");
    if (tri(t.hidden_owner)) flags.push("hidden_owner");
    if (tri(t.is_proxy)) flags.push("proxy_upgradeable");
    if (tri(t.is_blacklisted)) flags.push("blacklist");
    if (tri(t.transfer_pausable)) flags.push("transfer_pausable");
    if (tri(t.is_open_source) === false) flags.push("closed_source");
    if (tri(t.slippage_modifiable)) flags.push("slippage_modifiable");

    return {
      isHoneypot: isHoneypot === true,
      // Only assert unsellable when GoPlus actually said so. Unknown stays sellable here
      // because `deceptionSignal` treats `!sellable` as evidence of harm, and unknown is
      // not evidence.
      sellable: cannotSell !== true,
      buyTaxPct,
      sellTaxPct,
      flags,
      source: "goplus",
    };
  }
}
