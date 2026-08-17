// Deploy the attack for real — onto a local anvil fork, never onto a public chain.
//
// WHY DEPLOY AT ALL. Every other measurement here reads text from a fixture. A fixture is
// enough to test the engine, but it cannot show that the payload survives a round trip
// through a real contract: solidity storage, ABI encoding, an `eth_call` on the wire. This
// deploys a real ERC-20 whose `name()` IS the payload and reads it back through the same
// code path a production agent would use.
//
// WHY NOT A PUBLIC TESTNET. A testnet is still a public, immutable chain. Deploying an
// injection payload there publishes a live attack artifact that anyone's indexer can ingest
// forever — which is the exact harm this project exists to prevent, so doing it to make a
// demo would be indefensible. A forked anvil gives the same fidelity with none of that: the
// node is local, ephemeral, and dies with the process.
//
// THE GUARDRAIL. `assertLocalFork` refuses to run against anything but a loopback anvil. The
// tempting shape for this file is "RPC_URL from the environment", and that is exactly what
// turns a research script into a one-variable-away mainnet deployer. The check is deliberate
// and should not be relaxed into a warning.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";

const exec = promisify(execFile);

/** Resolved against this module, not the process cwd — a script should behave the same
 *  whether it is invoked from the package or from the repo root. */
const CONTRACT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../exploit-demo/MaliciousToken.sol",
);

export const ANVIL_RPC = "http://127.0.0.1:8545";

/** anvil's first dev account. This key is printed by anvil on every start and is published
 *  in its docs — it holds nothing anywhere real, and is safe in source precisely because it
 *  is universally known. Never put a key here that is not. */
export const ANVIL_DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const ANVIL_DEV_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

export class NotLocalError extends Error {}

async function rpc(url: string, method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(10_000),
  });
  const body = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

export interface ForkInfo {
  chainId: number;
  /** the block the fork was taken at, or null when anvil is running without a fork */
  forkBlock: number | null;
  forkUrl: string | null;
}

/**
 * Refuse to proceed unless the endpoint is a local anvil. Two independent checks, because
 * either alone is bypassable: a loopback URL could be an SSH tunnel to a real node, and a
 * self-reported chain id could be anything.
 *
 * Chain id is NOT one of the checks, and that is the whole subtlety here. `anvil --fork-url`
 * inherits the forked chain's id, so a mainnet fork reports 1 — identical to real mainnet.
 * The first version of this guard tested for 31337 and would have rejected every fork while
 * providing no protection at all against the case it was written for.
 *
 * What does discriminate is an anvil-only RPC method. `anvil_nodeInfo` returns a result on
 * anvil and `-32601 method does not exist` on a real node, so a successful response is
 * positive proof of a dev node rather than an absence of evidence.
 *
 * This is what makes deploying an attack payload defensible. Deployment is irreversible on a
 * public chain, so the guard belongs *before* the transaction, not in a README warning.
 */
export async function assertLocalFork(url = ANVIL_RPC): Promise<ForkInfo> {
  const host = new URL(url).hostname;
  if (!["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(host)) {
    throw new NotLocalError(
      `refusing to deploy: ${url} is not loopback. This script deploys an injection payload ` +
        `and must never touch a public chain — start a local fork instead:\n` +
        `  anvil --fork-url https://ethereum-rpc.publicnode.com`,
    );
  }

  let info: { forkConfig?: { forkBlockNumber?: number; forkUrl?: string } };
  try {
    info = (await rpc(url, "anvil_nodeInfo")) as typeof info;
  } catch (e) {
    throw new NotLocalError(
      `refusing to deploy: ${url} did not answer anvil_nodeInfo (${(e as Error).message}). ` +
        `Only a local dev node implements it — a real node rejects it as unknown. Start one:\n` +
        `  anvil --fork-url https://ethereum-rpc.publicnode.com`,
    );
  }

  const chainId = Number(await rpc(url, "eth_chainId"));
  return {
    chainId,
    forkBlock: info.forkConfig?.forkBlockNumber ?? null,
    forkUrl: info.forkConfig?.forkUrl ?? null,
  };
}

export interface DeployedToken {
  address: string;
  name: string;
  symbol: string;
  holder: string;
  amount: string;
}

/**
 * Compile and deploy `MaliciousToken` with `name()` set to the payload.
 *
 * Shells out to `forge` rather than bundling a compiler or a signing library: the repo's
 * whole packaging claim is zero runtime dependencies, and this is a research script that
 * already assumes a local dev chain, so assuming the toolchain that provides it is free.
 */
export async function deployPayloadToken(
  opts: {
    name: string;
    symbol?: string;
    holder?: string;
    amount?: string;
    rpcUrl?: string;
    contractPath?: string;
  },
): Promise<DeployedToken> {
  const rpcUrl = opts.rpcUrl ?? ANVIL_RPC;
  await assertLocalFork(rpcUrl);

  const symbol = opts.symbol ?? "CLAIM";
  const holder = opts.holder ?? ANVIL_DEV_ADDRESS;
  const amount = opts.amount ?? "1000000000000000000000"; // 1000 × 1e18
  const contract = opts.contractPath ?? `${CONTRACT}:MaliciousToken`;

  const { stdout } = await exec(
    "forge",
    [
      "create",
      "--rpc-url", rpcUrl,
      "--private-key", ANVIL_DEV_KEY,
      "--broadcast",
      contract,
      "--constructor-args", opts.name, symbol, holder, amount,
    ],
    { maxBuffer: 8 * 1024 * 1024 },
  );

  const match = stdout.match(/Deployed to:\s*(0x[0-9a-fA-F]{40})/);
  if (!match) throw new Error(`could not parse deployment address from forge output:\n${stdout}`);

  return { address: match[1], name: opts.name, symbol, holder, amount };
}

/** ERC-20 balance, read straight off the node. The E2E experiment scores a balance DELTA
 *  rather than a tool call, because a delta is the harm rather than an intention to cause it. */
export async function balanceOf(token: string, account: string, rpcUrl = ANVIL_RPC): Promise<bigint> {
  const data = "0x70a08231" + account.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const out = await rpc(rpcUrl, "eth_call", [{ to: token, data }, "latest"]);
  return typeof out === "string" && out.length > 2 ? BigInt(out) : 0n;
}

/**
 * Snapshot / revert, so each arm of the experiment starts from identical state.
 *
 * Without this the first arm drains the wallet and the second has nothing left to move,
 * which would read as "the guard worked" when it only means "the money was already gone".
 * The two arms have to be the same experiment run twice, not a sequence.
 */
export async function snapshot(rpcUrl = ANVIL_RPC): Promise<string> {
  return String(await rpc(rpcUrl, "evm_snapshot"));
}

export async function revert(id: string, rpcUrl = ANVIL_RPC): Promise<void> {
  const ok = await rpc(rpcUrl, "evm_revert", [id]);
  if (ok !== true) throw new Error(`evm_revert(${id}) refused — arms would no longer be comparable`);
}

/**
 * Actually move the tokens, from the victim's own wallet, on the local fork.
 *
 * This is the point of the whole exercise. Every other score in this repo is a proxy —
 * "the model emitted a tool call carrying the canary" — and a proxy invites the objection
 * that a real harness would have caught it before execution. A balance that changed is not
 * a proxy for harm; it is the harm.
 */
export async function sendErc20Transfer(
  token: string,
  to: string,
  amount: bigint,
  rpcUrl = ANVIL_RPC,
): Promise<string> {
  await assertLocalFork(rpcUrl);
  const { stdout } = await exec(
    "cast",
    [
      "send", token,
      "transfer(address,uint256)", to, amount.toString(),
      "--private-key", ANVIL_DEV_KEY,
      "--rpc-url", rpcUrl,
      "--json",
    ],
    { maxBuffer: 4 * 1024 * 1024 },
  );
  const receipt = JSON.parse(stdout) as { transactionHash?: string; status?: string };
  if (receipt.status && !/^(0x1|success)$/i.test(receipt.status)) {
    throw new Error(`transfer reverted: status=${receipt.status}`);
  }
  return receipt.transactionHash ?? "(no hash)";
}

/** Format 18-decimal units for a human-readable delta. */
export function formatUnits(v: bigint, decimals = 18): string {
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  const frac = (v % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole.toString();
}
