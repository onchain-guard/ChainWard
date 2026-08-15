# chainward

**Scan and sanitize attacker-writable on-chain text before it reaches an LLM.**

A web3 AI agent reads token names, NFT descriptions and tx memos. Every one of those
fields is free text that **anyone can write** — and blockchain data is immutable, so a
payload planted once stays readable forever. ChainWard sits at the read boundary and
hands the model a sanitized rendering instead of the raw bytes.

Zero runtime dependencies. ESM + CJS. Fully typed.

```bash
npm install chainward
```

## Quick start

Put `guard()` between your agent harness and the model:

```ts
import { guard } from "chainward";

const { messages, findings } = await guard(rawMessages, {
  model: "claude-sonnet-5",          // selects the chat-template token set to check for
  targetContext: ["llm-chat"],       // where this data is about to be consumed
});

for (const f of findings) {
  console.warn(`message ${f.index} (${f.role}): ${f.severity} — ${f.codes.join(", ")}`);
}

const res = await llm.messages.create({ ...req, messages }); // sanitized
```

`guard()` understands both the plain-string (OpenAI) and block-array (Anthropic) message
shapes. It guards `text` and `tool_result` blocks — the actual injection vector — and
passes `tool_use`, `image` and unknown blocks through untouched.

## The proxy — when you don't own the calling code

`guard()` needs you to hold the code that calls the model. When you don't — Claude Code, a
vendor agent, a binary — the one thing you can still change is where requests go:

```bash
npx chainward proxy --upstream https://api.anthropic.com
```

```bash
export ANTHROPIC_BASE_URL=http://localhost:8787
```

That is the whole integration. Requests are guarded in flight, streamed responses are piped
through, and everything else is relayed untouched. See [PROXY.md](./PROXY.md).

Importing `chainward` does not pull the server in — the proxy lives behind its own subpath
(`chainward/proxy`) and only loads if you ask for it.

## Scanning individual on-chain fields

If you are the one reading the chain, scan each field directly. The field kind carries a
*shape prior*: a token symbol is expected to be a short ticker, so an imperative sentence
sitting in one is anomalous regardless of what it says.

```ts
import { defaultScanner } from "chainward";

const scanner = defaultScanner();

const scan = await scanner.scanField("token_name", tokenName, {
  chain: "base",
  address: tokenAddress,
  targetContexts: ["llm-chat", "markdown-ui"],
});

console.log(scan.severity);   // "CLEAN" | "SUSPICIOUS" | "MALICIOUS"
console.log(scan.signals);    // every detector hit, with an explanation
console.log(scan.sanitized);  // give THIS to the model
```

## What it detects

| Layer | Looks for |
| --- | --- |
| **L1 structural** | invisible/control chars, Unicode tag-block smuggling, bidi overrides, homoglyphs and mixed script, base64/hex blobs that decode to readable text |
| **L2a pattern** | instruction override, forged role turns, crypto action directives, approval lures, fake authority |
| **L2b classifier** | "does this read like instructions aimed at an AI rather than a label?" |
| **L3 deception** | text that claims safety while the contract behaves like a honeypot; text claiming to *be* a known token from an address that isn't it |
| **L4 differential** | chat-template control tokens and markdown constructs that are inert as stored data but become control once templated or rendered |
| **L5 verdict** | signal fusion → severity + a model-safe rendering |

Layer 3 is the part a general-purpose prompt-injection filter cannot do: a semantically
clean lie ("Official USDC, issued by Circle") carries no injection signal at all. Only
checking it against on-chain ground truth reveals it.

## Sanitization

`renderSafe` produces the string you actually pass to the model:

- **CLEAN** → normalized text (invisibles stripped, homoglyphs folded, NFKC)
- **SUSPICIOUS** → fenced as untrusted data, newlines flattened, truncated
- **MALICIOUS** → replaced with a redaction marker

Emoji survive: a ZWJ joining two pictographs is legitimate composition, not smuggling, so
`👨‍👩‍👧` is not torn into three separate people.

## Extending it

Detection is a plugin registry. A detector receives the raw text, the normalized text, the
field kind, and the signals earlier detectors already produced:

```ts
import { ChainWardScanner, defaultRegistry } from "chainward";

const registry = defaultRegistry().use({
  id: "my.detector",
  layer: "pattern",
  detect: ({ normalized }) =>
    normalized.includes("...") ? [{ layer: "pattern", code: "MY_RULE", detail: "...", weight: 0.6 }] : [],
});

const scanner = new ChainWardScanner({ registry });
```

The honeypot oracle and the injection classifier are interfaces too, so the built-in
deterministic implementations swap out for live GoPlus / Prompt Guard 2 without touching
anything downstream.

### Composing a narrower registry

You can also build a registry from scratch, and sometimes you must. Every layer above L1
and L4 assumes the text it reads is attacker-written in its entirety. That holds for an
on-chain field. It does **not** hold for an assembled prompt, where the agent's own system
instructions sit next to the untrusted data — there, `You are a wallet assistant` reads as
a role hijack and the agent's own transfer policy reads as a crypto action directive.

For text that mixes trusted and untrusted content, take only the layers that key on form
rather than intent:

```ts
import { ChainWardScanner, DetectorRegistry, structuralDetector, differentialDetector } from "chainward";

// invisible characters, homoglyphs, encoded blobs, chat-template tokens, active URIs —
// none of which an author of a system prompt has any reason to emit
const promptScanner = new ChainWardScanner({
  registry: new DetectorRegistry().use(structuralDetector).use(differentialDetector),
});
```

Note that `renderSafe` is defined over a *field*: for a non-CLEAN verdict it replaces the
whole input. Applying it to an assembled prompt would delete the agent's instructions along
with the payload, so at that level use the verdict to warn or reject, not to rewrite.

## Status

`0.x` — the API may still change. Detection layers and the sanitization contract are
stable enough to build on; the detector registry is the intended extension point.

## License

MIT
