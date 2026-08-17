// Tests for the usage/cost table.
//
// The cost figure exists to catch a budget surprise before the invoice does, which only
// works if the arithmetic is right and the caveats survive. So: the math, the intro-price
// boundary (a dated discount that silently expires is worse than no discount at all), the
// unknown-model path, and the stop_reason breakdown — which is the actionable half, because
// `max_tokens` and `refusal` land in the same discarded count and have opposite fixes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { usageTable } from "../src/report.ts";
import type { RunRow } from "../src/types.ts";

const run = (over: Partial<RunRow> = {}): RunRow => ({
  caseId: "A01",
  arm: "off",
  model: "claude-sonnet-5",
  provider: "anthropic",
  harmed: false,
  movedFunds: false,
  taskDone: false,
  invalid: false,
  stopReason: "end_turn",
  usage: { inputTokens: 1000, outputTokens: 1000 },
  toolCalls: [],
  text: "",
  ...over,
});

const DURING_INTRO = new Date("2026-08-17T00:00:00Z");
const AFTER_INTRO = new Date("2026-09-01T00:00:00Z");

test("no usage recorded → no table at all (the stub provider path)", () => {
  assert.equal(usageTable([run({ usage: undefined })]), "");
});

test("cost is input × in-rate + output × out-rate", () => {
  // 1M in + 1M out on Sonnet 5 intro ($2/$10) = $12.00
  const rows = Array.from({ length: 1000 }, () => run());
  const out = usageTable(rows, DURING_INTRO);
  assert.match(out, /\$12\.000/);
  assert.match(out, /인트로가/, "the discounted rate must be labelled, not applied silently");
});

test("the intro price expires — after the cutoff it bills at standard rate", () => {
  const rows = Array.from({ length: 1000 }, () => run());
  const out = usageTable(rows, AFTER_INTRO);
  assert.match(out, /\$18\.000/, "1M in + 1M out at standard $3/$15 = $18.00");
  assert.ok(!out.includes("인트로가"), "and the intro label must be gone with it");
});

test("an unpriced model reports tokens but never invents a cost", () => {
  const out = usageTable([run({ model: "some-future-model" })]);
  assert.match(out, /가격표 없음/);
  assert.ok(!out.includes("합계"), "a total that silently omits a model is worse than no total");
});

test("the cost is labelled an estimate, not a bill", () => {
  const out = usageTable([run()]);
  assert.match(out, /리스트가 추정/);
  assert.match(out, /실제 청구액이 아니다/);
});

test("stop_reason is broken out, and max_tokens says raise the budget", () => {
  const out = usageTable([run({ stopReason: "max_tokens", invalid: true }), run()]);
  assert.match(out, /`max_tokens` \| 1/);
  assert.match(out, /MAX_TOKENS`를 올려라/);
});

test("refusal gets the opposite advice — no budget fixes a classifier", () => {
  const out = usageTable([run({ stopReason: "refusal", invalid: true })]);
  assert.match(out, /예산으로는 해결되지 않는다/);
  assert.ok(!out.includes("MAX_TOKENS`를 올려라"), "the two fixes must not be confused");
});

test("per-model rows are separated, so one model cannot hide inside another's average", () => {
  const out = usageTable(
    [run({ model: "claude-sonnet-5" }), run({ model: "claude-haiku-4-5" })],
    DURING_INTRO,
  );
  assert.match(out, /`claude-sonnet-5` \| 1/);
  assert.match(out, /`claude-haiku-4-5` \| 1/);
  // sonnet intro (0.002 + 0.010) + haiku (0.001 + 0.005) = 0.018
  assert.match(out, /\$0\.02/, "and the total sums across them");
});
