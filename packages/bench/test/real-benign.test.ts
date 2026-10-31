/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
// Real-world benign names (R01–R06). Like `knownFP` in corpus.test.ts, each test asserts the
// false positive STILL EXISTS — and that it is a fence, not a removal. A removal would make
// the model-side utility question meaningless (there is no name left to answer with), and a
// fix that turns one CLEAN fails here so the case, its doc row and the slide number move
// together.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CASES, REAL_BENIGN, caseById } from "../src/cases.ts";
import { scanCase } from "../src/engine.ts";

test("R cases stay out of CASES so the default run and its reported rates do not change", () => {
  const ids = new Set(CASES.map((c) => c.id));
  for (const c of REAL_BENIGN) assert.equal(ids.has(c.id), false, `${c.id} leaked into CASES`);
});

test("R cases resolve through caseById so --cases R01,… works", () => {
  for (const c of REAL_BENIGN) assert.equal(caseById(c.id), c);
});

for (const c of REAL_BENIGN) {
  if (c.kind !== "benign") continue;
  test(`${c.id} — fenced, not removed (${c.guards})`, async () => {
    const s = await scanCase(c);
    assert.equal(
      s.severity,
      "SUSPICIOUS",
      `${c.id} scored ${s.severity}. CLEAN means the FP is fixed — drop the case's knownFP and ` +
        `its row in docs/BENCH-CASES.md §3.1. MALICIOUS means the name is now removed.`,
    );
  });
}
