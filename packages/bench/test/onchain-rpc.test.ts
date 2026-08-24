// Offline tests for the ABI string decoder.
//
// These run in CI with no network, because the decoder is the part that can be wrong in a
// way that matters: its input is attacker-controlled return data from an arbitrary
// contract. A token whose `name()` is crafted to break the decoder either crashes the scan
// or — worse — decodes to something other than what the chain actually said, which would
// make every L3 verdict downstream a verdict on the wrong text.
//
// The live path (`src/live.ts`) is deliberately not tested here. It depends on a public RPC
// and on contracts staying deployed, so asserting on it would make CI fail for reasons that
// have nothing to do with this repo.

import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeAbiString } from "../src/onchain-rpc.ts";

/** Build a well-formed ABI `string` return: offset word, length word, padded payload. */
function encodeAbiString(s: string): string {
  const bytes = Buffer.from(s, "utf8");
  const offset = (32).toString(16).padStart(64, "0");
  const length = bytes.length.toString(16).padStart(64, "0");
  const padded = bytes.toString("hex").padEnd(Math.ceil(bytes.length / 32) * 64, "0");
  return `0x${offset}${length}${padded}`;
}

test("decodes an ordinary ERC-20 name", () => {
  assert.equal(decodeAbiString(encodeAbiString("USD Coin")), "USD Coin");
});

test("decodes a payload spanning more than one word", () => {
  const long = "Wrapped Ether Bridged From Somewhere Very Far Away Indeed";
  assert.equal(decodeAbiString(encodeAbiString(long)), long);
});

test("decodes multi-byte UTF-8 — a token name is not ASCII by contract", () => {
  assert.equal(decodeAbiString(encodeAbiString("도지코인 🐕")), "도지코인 🐕");
});

test("decodes the bytes32 form some early tokens return instead of string", () => {
  // MKR is the canonical example: a bare 32-byte word, NUL-padded, with no header.
  const bytes32 = "0x" + Buffer.from("MKR", "utf8").toString("hex").padEnd(64, "0");
  assert.equal(decodeAbiString(bytes32), "MKR");
});

test("a bytes32 word of binary junk decodes to empty, not mojibake", () => {
  const junk = "0x" + "de".repeat(32);
  assert.equal(
    decodeAbiString(junk),
    "",
    "returning garbage text would feed the scanner a string the chain never said",
  );
});

test("an oversized declared length is truncated, not trusted", () => {
  // Attacker-controlled: claims 0xffff bytes and supplies four. A decoder that believes the
  // header either over-reads or allocates on a hostile number.
  const offset = (32).toString(16).padStart(64, "0");
  const lying = "ffff".padStart(64, "0");
  const payload = Buffer.from("USDC", "utf8").toString("hex").padEnd(64, "0");
  assert.equal(decodeAbiString(`0x${offset}${lying}${payload}`), "USDC");
});

test("empty and malformed return data decode to empty string", () => {
  assert.equal(decodeAbiString(""), "");
  assert.equal(decodeAbiString("0x"), "");
  assert.equal(decodeAbiString("0xdeadbeef"), "", "shorter than a single word");
  assert.equal(decodeAbiString(encodeAbiString("")), "");
});

test("a zero-length string is empty, not a decode failure", () => {
  // An uninitialized proxy implementation returns exactly this, and it must read as
  // "makes no claim" rather than as an error.
  assert.equal(decodeAbiString(encodeAbiString("")), "");
});

test("the decoder never throws on hostile input", () => {
  for (const input of ["0xzz", "0x" + "f".repeat(200), "0x" + "0".repeat(64), "not hex at all"]) {
    assert.doesNotThrow(() => decodeAbiString(input), `threw on ${input.slice(0, 20)}`);
  }
});
