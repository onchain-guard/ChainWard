// Real unit tests over the engine. Run: npx tsx --test test/scanner.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultScanner } from "../src/core/scanner.ts";
import { normalizeText, analyzeStructure } from "../src/core/normalize.ts";
import {
  MALICIOUS_TOKEN, HONEYPOT_TOKEN, MALICIOUS_NFT, MEMO_ATTACK, BENIGN_TOKEN, BENIGN_MEME,
} from "../src/demo/fixtures.ts";

const scanner = defaultScanner();

test("injection in token name → MALICIOUS", async () => {
  const f = await scanner.scanField("token_name", MALICIOUS_TOKEN.name);
  assert.equal(f.severity, "MALICIOUS");
  assert.ok(f.signals.some((s) => s.code === "CRYPTO_ACTION_DIRECTIVE" || s.code === "INSTRUCTION_OVERRIDE"));
});

test("honeypot + safety claim → deception mismatch (MALICIOUS)", async () => {
  const f = await scanner.scanField("token_name", HONEYPOT_TOKEN.name, {
    chain: "base", address: HONEYPOT_TOKEN.address,
  });
  assert.equal(f.severity, "MALICIOUS");
  assert.ok(f.signals.some((s) => s.code === "CLAIM_BEHAVIOR_MISMATCH"));
});

test("NFT metadata with invisible tag chars → MALICIOUS (hard structural)", async () => {
  const f = await scanner.scanField("nft_description", MALICIOUS_NFT.description, {
    chain: "base", address: MALICIOUS_NFT.address,
  });
  assert.equal(f.severity, "MALICIOUS");
  assert.ok(f.signals.some((s) => s.code.startsWith("INVISIBLE_") && s.hard));
});

test("homoglyph NFT name is detected (mixed script)", async () => {
  const sigs = analyzeStructure(MALICIOUS_NFT.name);
  assert.ok(sigs.some((s) => s.code === "MIXED_SCRIPT"));
});

test("resolution-template memo → flagged (not CLEAN)", async () => {
  const f = await scanner.scanField("tx_memo", MEMO_ATTACK.memo);
  assert.notEqual(f.severity, "CLEAN");
});

test("benign USDC → CLEAN", async () => {
  const f = await scanner.scanField("token_name", BENIGN_TOKEN.name);
  assert.equal(f.severity, "CLEAN");
});

test("benign meme 'IGNORE' → not MALICIOUS (FP-avoidance)", async () => {
  const f = await scanner.scanField("token_name", BENIGN_MEME.name);
  assert.notEqual(f.severity, "MALICIOUS");
});

test("sanitizer strips invisible/tag chars", () => {
  const cleaned = normalizeText(MALICIOUS_NFT.description);
  // no codepoint in the Tag block should survive
  assert.ok(![...cleaned].some((ch) => { const c = ch.codePointAt(0)!; return c >= 0xe0000 && c <= 0xe007f; }));
});

test("homoglyph folds to ASCII on normalize", () => {
  assert.equal(normalizeText("Bored Аpe").includes("Аpe"), false); // Cyrillic А folded
});
