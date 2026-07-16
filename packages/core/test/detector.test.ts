import { test } from "node:test";
import assert from "node:assert/strict";
import type { Detector } from "../src/core/detector.ts";
import { DetectorRegistry } from "../src/core/detector.ts";
import type { Signal } from "../src/core/types.ts";

const a: Detector = { id: "test.a", layer: "structural", detect: () => [{ layer: "structural", code: "A", detail: "", weight: 0.5 }] };
const b: Detector = { id: "test.b", layer: "pattern", detect: (i) => [{ layer: "pattern", code: "B", detail: `prior=${i.prior.length}`, weight: 0.4 }] };

test("registry runs detectors in registration order and accumulates prior", async () => {
  const reg = new DetectorRegistry().use(a).use(b);
  assert.equal(reg.list().length, 2);
  const signals: Signal[] = [];
  for (const d of reg.list()) signals.push(...await d.detect({ raw: "x", normalized: "x", kind: "token_name", ctx: {}, prior: [...signals] }));
  assert.deepEqual(signals.map((s) => s.code), ["A", "B"]);
  assert.equal(signals[1].detail, "prior=1");
});

test("use() is chainable and returns the registry", () => {
  const reg = new DetectorRegistry();
  assert.equal(reg.use(a), reg);
});
