# ChainWard in a real ElizaOS agent

A runnable agent that boots `@elizaos/core` for real — its own `AgentRuntime`, a pglite
database, its migrations, its `initialize()`, and its own plugin loader — with ChainWard
installed the way a project installs it.

```bash
pnpm --filter chainward-example-elizaos start
```

```
migrations                ✅
resolved from string      ✅ chainward
initialize()              ✅
handler order              chainward-guard(p=10000) → fake-llm(p=0)

=== what the guard did ===
  prompt body preserved    ✅ byte-for-byte
  warning appended         ✅
  verdict / signal         MALICIOUS / INVISIBLE_UNICODE_TAG
```

## Why it exists

Three things the README claimed were assumptions about someone else's code path until this
ran:

1. **`plugins: ["@chainwards/eliza"]` in a character file resolves.** `AgentRuntime` does not
   resolve strings itself — `@elizaos/core` exports the loader (`resolvePlugins`) and the CLI
   calls it. Verified here against the real loader.
2. **The guard registers ahead of the model provider.** The model seam rests entirely on
   `registerModel`'s priority ordering. The example registers the model provider *first*, at
   the priority a real model plugin ships with, because that is the ordering a real project
   produces.
3. **It survives a real `initialize()`** against a real database rather than a stub.

The model provider is a stand-in. What is under test is the guard's position in the chain and
what reaches the model — not what a model replies.

## In your own project

```bash
npm install @chainwards/eliza
```

`chainward` comes with it as a dependency; `@elizaos/core` is a peer your project already has.
Then either form works:

```jsonc
// character file
{ "name": "wallet-agent", "plugins": ["@chainwards/eliza"] }
```

```ts
// or programmatically, which also lets you sanitize at the provider seam
import { createChainwardPlugin, guardProvider } from "@chainwards/eliza";

plugins: [createChainwardPlugin()],
providers: [guardProvider(evmTokenProvider, { kind: "token_name", chain: "base", address })],
```

The provider seam is the one that can **sanitize**, because the field is still identifiable
there — which is also what lets the L3 on-chain truth check run at all. The model seam sees a
flattened prompt, so it detects and annotates and never rewrites. Use both.

## Booting programmatically? Run the migrations yourself

The `elizaos` CLI does this for you. Without it, `initialize()` dies on
`relation "agents" does not exist`:

```ts
const migrator = new DatabaseMigrationService();
await migrator.initializeWithDatabase(adapter.getDatabase());
migrator.discoverAndRegisterPluginSchemas([sqlPlugin]);
await migrator.runAllPluginMigrations();
```

## A known, unrelated failure

After the model call returns, ElizaOS writes a usage row and that insert fails on pglite with
a WASM-level error. It happens *after* the guard has run — the failing log body itself records
`provider: "chainward-guard", response: "ok"` — and it surfaces as an unhandled rejection, so
the example matches that one statement narrowly and reports it as a note.
