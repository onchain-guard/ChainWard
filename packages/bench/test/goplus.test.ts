// Tests for the GoPlus oracle mapping.
//
// Offline by construction: asserting against the live API would make CI depend on a third
// party's uptime and on specific contracts staying deployed.
//
// The thing under test is the absent-field handling, and it is worth spelling out why.
// GoPlus omits fields it has not determined — the real USDC record comes back with no
// `cannot_sell_all` at all. The obvious mapping, `sellable: t.cannot_sell_all !== "1"`,
// turns that silence into "sellable: true", and `Number(undefined) * 100` turns a missing
// sell tax into `NaN`, which fails every `>= 50` check. Both read as a clean bill of health
// for a contract nobody analysed. A security tool that says "safe" when it means "unknown"
// is worse than one that says nothing, because the caller stops looking.

import { test } from "node:test";
import assert from "node:assert/strict";
import { GoPlusHoneypotOracle } from "../src/goplus.ts";

const oracle = new GoPlusHoneypotOracle();

/** The shape GoPlus returns for a token it has fully analysed. */
const analysed = (over: Record<string, unknown> = {}) => ({
  is_honeypot: "0",
  cannot_sell_all: "0",
  buy_tax: "0",
  sell_tax: "0",
  is_open_source: "1",
  ...over,
});

// --- the absent-means-safe trap ---------------------------------------------------------

test("a record with none of the load-bearing fields yields no verdict, not a clean one", () => {
  assert.equal(
    oracle.map({ token_name: "Something", is_open_source: "1" }),
    null,
    "silence must not become sellable:true — that is an unanalysed contract passing as safe",
  );
});

test("a missing sell tax is unknown, never 0%", () => {
  const r = oracle.map(analysed({ sell_tax: undefined }))!;
  assert.equal(r.sellTaxPct, undefined, "0 would clear a 100%-sell-tax honeypot");
});

test("an unparseable tax is unknown, not NaN", () => {
  const r = oracle.map(analysed({ sell_tax: "not-a-number" }))!;
  assert.equal(r.sellTaxPct, undefined, "NaN >= 50 is false, so NaN silently reads as safe");
});

test("a partially-analysed record still yields a verdict when one key field is present", () => {
  // Real USDC arrives without `cannot_sell_all`; `is_honeypot` alone is enough to judge.
  const r = oracle.map({ is_honeypot: "0", buy_tax: "0", sell_tax: "0" });
  assert.ok(r, "dropping this would lose the verdict on the most-checked token there is");
  assert.equal(r.isHoneypot, false);
});

// --- the mapping itself -------------------------------------------------------------------

test("a flagged honeypot maps to isHoneypot and unsellable", () => {
  const r = oracle.map(analysed({ is_honeypot: "1", cannot_sell_all: "1", sell_tax: "1" }))!;
  assert.equal(r.isHoneypot, true);
  assert.equal(r.sellable, false);
  assert.equal(r.sellTaxPct, 100, "GoPlus taxes are fractions — 1 means 100%, not 1%");
  assert.ok(r.flags.includes("cannot_sell_all"));
});

test("fractional taxes are scaled to percent", () => {
  const r = oracle.map(analysed({ buy_tax: "0.05", sell_tax: "0.49" }))!;
  assert.equal(r.buyTaxPct, 5);
  assert.ok(Math.abs(r.sellTaxPct! - 49) < 1e-9);
});

test("risk flags are collected, and closed source is one of them", () => {
  const r = oracle.map(
    analysed({ hidden_owner: "1", is_proxy: "1", is_open_source: "0", transfer_pausable: "1" }),
  )!;
  for (const f of ["hidden_owner", "proxy_upgradeable", "closed_source", "transfer_pausable"]) {
    assert.ok(r.flags.includes(f), `missing flag ${f}: got [${r.flags.join(", ")}]`);
  }
});

test("a flag is not a verdict — a clean upgradeable proxy stays sellable", () => {
  // Real USDC is an upgradeable proxy. Reporting the flag is right; treating it as harm
  // would false-positive on the most legitimate token on the chain.
  const r = oracle.map(analysed({ is_proxy: "1" }))!;
  assert.equal(r.isHoneypot, false);
  assert.equal(r.sellable, true);
  assert.deepEqual(r.flags, ["proxy_upgradeable"]);
});

// --- failure paths must degrade to "no data", never to "clean" -----------------------------

const withFetch = (impl: () => Promise<Response>) =>
  new GoPlusHoneypotOracle({ fetchImpl: impl as unknown as typeof fetch, timeoutMs: 500 });

const jsonResponse = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

test("an unsupported chain returns no data", async () => {
  assert.equal(await oracle.check("dogecoin", "0xabc"), null);
});

test("a network failure returns no data rather than a clean verdict", async () => {
  const o = withFetch(() => Promise.reject(new Error("ECONNRESET")));
  assert.equal(await o.check("ethereum", "0xabc"), null);
});

test("a non-200 response returns no data", async () => {
  const o = withFetch(() => jsonResponse({}, 503));
  assert.equal(await o.check("ethereum", "0xabc"), null);
});

test("code != 1 means the analysis is not complete — no verdict", async () => {
  // code 2 is GoPlus for "still analysing". Reading its partial record as a result would
  // report a verdict the service explicitly declined to give.
  const o = withFetch(() => jsonResponse({ code: 2, result: { "0xabc": analysed() } }));
  assert.equal(await o.check("ethereum", "0xabc"), null);
});

test("a missing result entry returns no data", async () => {
  const o = withFetch(() => jsonResponse({ code: 1, result: {} }));
  assert.equal(await o.check("ethereum", "0xabc"), null);
});

test("the happy path maps and lowercases the address key", async () => {
  const o = withFetch(() =>
    jsonResponse({ code: 1, result: { "0xabc": analysed({ is_honeypot: "1" }) } }),
  );
  const r = await o.check("ethereum", "0xABC");
  assert.equal(r?.isHoneypot, true);
  assert.equal(r?.source, "goplus");
});
