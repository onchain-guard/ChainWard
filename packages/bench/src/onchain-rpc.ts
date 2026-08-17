// A real ERC-20 reader over JSON-RPC. No dependencies — `fetch` and two selectors.
//
// Why this exists: L3 is the layer a general-purpose injection filter cannot replicate,
// because it refutes a claim against ground truth rather than judging how the text reads.
// That argument is only worth as much as the ground truth behind it, and until now every
// L3 measurement in this repo ran on fixtures. A fixture cannot refute anything — it agrees
// with whatever the fixture author wrote. So this reads the actual deployed contract.
//
// Deliberately not in `chainward` core: core is a zero-dependency, side-effect-free library
// and should not open sockets on its own. Reading the chain is the caller's job; core's job
// is to judge what the caller read. That split is why `scanField` takes `address` instead of
// fetching anything.

/** ERC-20 selectors. `name()` and `symbol()` are the two attacker-writable identity fields. */
const SELECTOR = {
  name: "0x06fdde03",
  symbol: "0x95d89b41",
  decimals: "0x313ce567",
} as const;

/** Public endpoints, read-only. No key, no account, no funds — an `eth_call` costs nothing
 *  and changes nothing, which is what makes this safe to put in a demo someone else runs. */
export const PUBLIC_RPC: Record<string, string> = {
  ethereum: "https://ethereum-rpc.publicnode.com",
  base: "https://mainnet.base.org",
};

export class RpcError extends Error {}

async function jsonRpc(url: string, method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let body: { result?: unknown; error?: { code: number; message: string } };
  try {
    body = JSON.parse(text);
  } catch {
    // Several "public" endpoints answer with an HTML interstitial or a rate-limit page.
    // Reporting that as a decode failure would send the reader looking in the wrong place.
    throw new RpcError(`${url} returned non-JSON (HTTP ${res.status}): ${text.slice(0, 80)}`);
  }
  if (body.error) throw new RpcError(`${url} ${method}: ${body.error.code} ${body.error.message}`);
  return body.result;
}

/**
 * Decode an ABI-encoded `string` return value: a 32-byte offset, a 32-byte length, then the
 * bytes, right-padded to a 32-byte boundary.
 *
 * Tolerates two real-world deviations. Some early tokens (MKR is the canonical example)
 * declare `bytes32` rather than `string`, returning exactly 32 bytes of NUL-padded text —
 * decoding that as a header yields garbage, so it is detected by length and handled. And a
 * declared length longer than the payload is truncated rather than trusted, because the
 * value is attacker-controlled and a bogus length must not become an allocation.
 */
export function decodeAbiString(hex: string): string {
  const h = (hex ?? "").replace(/^0x/, "");
  if (!h) return "";

  // bytes32 form: exactly one word, no offset/length header.
  if (h.length === 64) {
    const raw = Buffer.from(h, "hex").toString("utf8").replace(/\0+$/, "");
    return /^[\x20-\x7e]*$/.test(raw) ? raw : "";
  }

  if (h.length < 128) return "";
  const declared = Number.parseInt(h.slice(64, 128), 16);
  if (!Number.isFinite(declared) || declared < 0) return "";
  const available = (h.length - 128) / 2;
  const len = Math.min(declared, available);
  const out = Buffer.from(h.slice(128, 128 + len * 2), "hex").toString("utf8");

  // When the header lied, `available` includes the word's zero padding, so the fallback
  // read drags NUL bytes in with the text. Those are an artifact of the malformed encoding,
  // not something the contract said — and handing them to the scanner would manufacture a
  // C0_CONTROL signal out of our own decode. Strip them only on this path: a NUL inside a
  // correctly-declared string is real data the chain did return, and worth flagging.
  return declared > available ? out.replace(/\0+$/, "") : out;
}

export interface OnchainToken {
  chain: string;
  address: string;
  /** what the contract calls itself — attacker-writable, and the input L3 judges */
  name: string;
  symbol: string;
  decimals: number | null;
  /** false when nothing is deployed at the address; every field below is then meaningless */
  hasCode: boolean;
  rpc: string;
}

/** Read a token's self-reported identity straight off the chain. */
export async function readToken(
  chain: string,
  address: string,
  opts: { rpcUrl?: string; timeoutMs?: number } = {},
): Promise<OnchainToken> {
  const rpc = opts.rpcUrl ?? PUBLIC_RPC[chain];
  if (!rpc) throw new RpcError(`no RPC endpoint for chain "${chain}" (known: ${Object.keys(PUBLIC_RPC).join(", ")})`);
  const timeoutMs = opts.timeoutMs ?? 15_000;

  const code = await jsonRpc(rpc, "eth_getCode", [address, "latest"], timeoutMs);
  const hasCode = typeof code === "string" && code.length > 2;

  // A reverting `name()` is ordinary — plenty of contracts are not ERC-20 — so a failed
  // call reads as "no claim", not as an error to propagate.
  const call = async (selector: string): Promise<string> => {
    try {
      const out = await jsonRpc(rpc, "eth_call", [{ to: address, data: selector }, "latest"], timeoutMs);
      return typeof out === "string" ? decodeAbiString(out) : "";
    } catch (e) {
      if (e instanceof RpcError) return "";
      throw e;
    }
  };

  const [name, symbol, decimalsHex] = await Promise.all([
    call(SELECTOR.name),
    call(SELECTOR.symbol),
    jsonRpc(rpc, "eth_call", [{ to: address, data: SELECTOR.decimals }, "latest"], timeoutMs).catch(() => null),
  ]);

  const decimals =
    typeof decimalsHex === "string" && decimalsHex.length > 2 ? Number.parseInt(decimalsHex, 16) : null;

  return { chain, address, name, symbol, decimals: Number.isFinite(decimals as number) ? decimals : null, hasCode, rpc };
}
