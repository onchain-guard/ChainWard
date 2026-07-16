// DATA SOURCE ADAPTER — where the on-chain text actually comes from.
//
// The demo uses MockOnchainDataSource (fixture-backed) so it runs offline and
// deterministically. The interface is real; the RPC adapter is written out (REAL IMPL)
// and drops in unchanged. This is the "substitutable but not vaporware" boundary:
// the scanner never knows or cares whether text came from a fixture or a live RPC.

import type { FieldKind } from "../../packages/core/src/core/types.ts";
import { MALICIOUS_TOKEN, HONEYPOT_TOKEN, MALICIOUS_NFT, MEMO_ATTACK, BENIGN_TOKEN, BENIGN_MEME } from "../demo/fixtures.ts";

export interface OnchainFields {
  fields: Array<{ kind: FieldKind; value: string }>;
}

export interface OnchainDataSource {
  readonly name: string;
  fetchToken(chain: string, address: string): Promise<OnchainFields>;
  fetchNft(chain: string, address: string, tokenId: string): Promise<OnchainFields>;
  fetchTx(chain: string, txHash: string): Promise<OnchainFields>;
}

/** Fixture-backed source. Address/hash keys map to the realistic sample payloads. */
export class MockOnchainDataSource implements OnchainDataSource {
  readonly name = "mock-fixtures";

  async fetchToken(_chain: string, address: string): Promise<OnchainFields> {
    const a = address.toLowerCase();
    const s =
      a === MALICIOUS_TOKEN.address ? MALICIOUS_TOKEN :
      a === HONEYPOT_TOKEN.address ? HONEYPOT_TOKEN :
      a === BENIGN_MEME.address ? BENIGN_MEME :
      BENIGN_TOKEN;
    return { fields: [
      { kind: "token_name", value: s.name },
      { kind: "token_symbol", value: s.symbol },
    ] };
  }

  async fetchNft(_chain: string, _address: string, _tokenId: string): Promise<OnchainFields> {
    return { fields: [
      { kind: "nft_name", value: MALICIOUS_NFT.name },
      { kind: "nft_description", value: MALICIOUS_NFT.description },
    ] };
  }

  async fetchTx(_chain: string, _txHash: string): Promise<OnchainFields> {
    return { fields: [{ kind: "tx_memo", value: MEMO_ATTACK.memo }] };
  }
}

/* REAL IMPL — live on-chain reads with viem. Same interface; the scanner is untouched.
 *
 *   import { createPublicClient, http, erc20Abi, hexToString } from "viem";
 *   import { base, mainnet } from "viem/chains";
 *
 *   export class RpcOnchainDataSource implements OnchainDataSource {
 *     readonly name = "viem-rpc";
 *     private client(chain: string) {
 *       return createPublicClient({ chain: chain === "base" ? base : mainnet, transport: http() });
 *     }
 *     async fetchToken(chain: string, address: `0x${string}`) {
 *       const c = this.client(chain);
 *       const [name, symbol] = await Promise.all([
 *         c.readContract({ address, abi: erc20Abi, functionName: "name" }),
 *         c.readContract({ address, abi: erc20Abi, functionName: "symbol" }),
 *       ]);
 *       return { fields: [
 *         { kind: "token_name",   value: String(name) },
 *         { kind: "token_symbol", value: String(symbol) },
 *       ] };
 *     }
 *     async fetchNft(chain: string, address: `0x${string}`, tokenId: string) {
 *       const c = this.client(chain);
 *       const uri = await c.readContract({ address, abi: erc721Abi, functionName: "tokenURI", args: [BigInt(tokenId)] });
 *       const json = await resolveTokenUri(String(uri)); // ipfs:// | data:base64 | https
 *       return { fields: [
 *         { kind: "nft_name",        value: String(json.name ?? "") },
 *         { kind: "nft_description", value: String(json.description ?? "") },
 *       ] };
 *     }
 *     async fetchTx(chain: string, hash: `0x${string}`) {
 *       const tx = await this.client(chain).getTransaction({ hash });
 *       // decode calldata / extract a memo field per your convention
 *       return { fields: [{ kind: "tx_memo", value: decodeMemo(tx.input) }] };
 *     }
 *   }
 */
