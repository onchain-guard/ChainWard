# @chainward/eliza

**ChainWard for ElizaOS** — guards the attacker-writable on-chain text an agent reads
before it reaches the model.

An ElizaOS agent with a wallet reads token names, NFT descriptions and memos. Anyone can
write those fields, and blockchain data is immutable, so a payload planted once stays
readable forever. This plugin puts ChainWard on the path.

```bash
npm install @chainward/eliza
```

## Two seams, and why you want both

```
receive ─▶ [PROVIDERS] ─▶ composeState ─▶ one flat prompt ─▶ [MODEL] ─▶ actions
                ▲                                              ▲
          guardProvider()                              model-boundary guard
          structured → sanitizes                       flattened → detects
```

| | Provider seam | Model seam |
| --- | --- | --- |
| Sees | one field at a time, with its chain and address | every generation, whatever produced it |
| Engine | full L1–L5, **including L3** | L1 + L4 only |
| Acts by | replacing the value with a safe rendering | appending a warning; prompt body untouched |
| Misses | anything from a provider you did not wrap | anything without a structural tell |

They are complements: the provider seam is precision, the model seam is coverage.

## Model seam — one line

```ts
import { createChainwardPlugin } from "@chainward/eliza";

export const character = {
  name: "wallet-agent",
  plugins: ["@elizaos/plugin-openai", createChainwardPlugin()],
};
```

The plugin registers a high-priority handler for every text model type, inspects the
assembled prompt, and hands off to the model provider that would otherwise have run.

**Why it only runs L1 and L4 here.** The pattern, classifier and deception layers assume
everything they read is attacker-written. An assembled prompt breaks that assumption: it
contains the agent's own instructions, and a healthy wallet agent says exactly the things
those rules look for — `You are a wallet assistant` is a role hijack by shape, and a
transfer policy is a crypto action directive by shape. Running the full engine there flags
a correct agent on its first turn. L1 and L4 key on form instead: invisible tag blocks,
bidi overrides, homoglyphs, base64 that decodes to prose, chat-template control tokens,
active markdown URIs. No author of a system prompt emits those, so their presence is
signal no matter which part of the prompt carries it.

**Why it never rewrites the prompt.** ChainWard's sanitizer replaces a *field* when that
field is malicious. A prompt is not a field — redacting it would delete the agent's own
instructions along with the payload. So this seam annotates and reports; it does not edit.

## Provider seam — where sanitization happens

Wrap whatever provider surfaces on-chain text:

```ts
import { guardProvider } from "@chainward/eliza";

plugins: [
  {
    name: "my-onchain",
    providers: [
      guardProvider(evmTokenProvider, {
        kind: "token_name",
        valueKinds: { symbol: "token_symbol", description: "nft_description" },
        chain: "base",
        address: (r) => r.data?.address as string,
      }),
    ],
  },
],
```

**Pass `chain` and `address` whenever you have them.** L3 is inert without an address, and
L3 is the only layer a general-purpose injection filter cannot replicate — it is what
catches a payload with no injection signal at all:

```
"Official USDC — issued by Circle."
```

Nothing there is imperative, forged or hidden. It is simply false, and only the chain can
say so. Given the address, ChainWard sees the token is not the real USDC and flags
impersonation. The same check catches "100% safe, audited, liquidity locked" on a contract
that cannot be sold.

`text` and string entries in `values` are sanitized. `data` is left untouched — it is
documented as structured data for programmatic access, and rewriting it would corrupt
components that parse it.

## Options

```ts
createChainwardPlugin({
  onFinding: (f) => log.warn(f),  // { source, severity, codes }
  annotate: true,                 // append the warning (default). false = detect only
  priority: 10_000,               // must exceed your model provider's priority
  providersOnly: false,           // true = skip the model seam entirely
});
```

## Behavior under failure

- **Scan throws** → the text passes through unchanged. A guard that takes the agent down
  is a worse failure than one that misses; findings surface through `onFinding` for your
  own alerting.
- **No model provider behind the guard** → throws with a clear message rather than
  returning something the agent would treat as a model answer.
- **Runtime exposes no model registry** → logs a warning and disables the model seam;
  `guardProvider` keeps working.

## Status

`0.x` — the API may still change. Requires `@elizaos/core >= 1.7.0` as a peer dependency.

## License

MIT
