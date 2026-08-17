// Tests for the deployment guardrail.
//
// This file deploys an injection payload for real, which is only defensible because it can
// never reach a public chain. The guard is therefore the security-critical part of the
// module, and the failing directions are what must be pinned: a guard that wrongly ACCEPTS
// is an irreversible mainnet deployment, while one that wrongly rejects is an inconvenience.
//
// The accept path needs a running anvil, so it is not asserted here — CI has no node, and a
// test that fails for that reason trains people to ignore it. Everything below fails closed
// with no node at all.
//
// One premise is worth recording because the first version of the guard got it wrong: a
// mainnet fork reports chain id 1, exactly like real mainnet. Chain id cannot separate them,
// which is why the guard keys on an anvil-only RPC method instead.

import { test } from "node:test";
import assert from "node:assert/strict";
import { assertLocalFork, NotLocalError, ANVIL_DEV_ADDRESS, ANVIL_DEV_KEY, formatUnits } from "../src/anvil.ts";

// --- fail closed on anything that is not a loopback dev node -------------------------------

test("a public RPC is refused before any network call is made", async () => {
  await assert.rejects(
    () => assertLocalFork("https://ethereum-rpc.publicnode.com"),
    (e: Error) => e instanceof NotLocalError && /not loopback/.test(e.message),
    "the single most important rejection: this is the one-variable-away mainnet deploy",
  );
});

test("a hostname that merely contains 'localhost' is still refused", async () => {
  // `localhost.evil.example` is a real hostname that resolves wherever its owner points it.
  // A substring check would pass it; the guard compares the parsed hostname exactly.
  await assert.rejects(
    () => assertLocalFork("http://localhost.evil.example:8545"),
    (e: Error) => e instanceof NotLocalError && /not loopback/.test(e.message),
  );
});

test("loopback alone is not enough — a port with no anvil is refused", async () => {
  // Port 9 is discard; nothing answers anvil_nodeInfo there.
  await assert.rejects(
    () => assertLocalFork("http://127.0.0.1:9"),
    (e: Error) => e instanceof NotLocalError && /anvil_nodeInfo/.test(e.message),
    "the guard needs positive proof of a dev node, not just a friendly-looking host",
  );
});

test("the rejection explains how to start a fork rather than just failing", async () => {
  // A guard that blocks the obvious path without naming the correct one gets disabled.
  await assert.rejects(
    () => assertLocalFork("https://mainnet.example"),
    (e: Error) => /anvil --fork-url/.test(e.message),
  );
});

// --- the dev key is safe to ship, and that must stay true ----------------------------------

test("the committed key is anvil's published dev key, not a real one", () => {
  // Pinned so nobody can quietly swap in a funded key and have it look like it belongs here.
  assert.equal(ANVIL_DEV_KEY, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  assert.equal(ANVIL_DEV_ADDRESS, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
});

// --- balance formatting, since the E2E scores a delta ---------------------------------------

test("formatUnits renders whole and fractional balances", () => {
  assert.equal(formatUnits(1000n * 10n ** 18n), "1000");
  assert.equal(formatUnits(0n), "0");
  assert.equal(formatUnits(1n * 10n ** 17n), "0.1");
  assert.equal(formatUnits(1n), "0.000000000000000001", "wei must not round to zero");
});

test("formatUnits honours a non-18 decimals argument", () => {
  assert.equal(formatUnits(1_500_000n, 6), "1.5", "USDC-style 6 decimals");
});
