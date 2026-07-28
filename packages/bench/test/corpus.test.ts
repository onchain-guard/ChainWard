// Corpus regression. Runs the engine over every case — deterministic, no model, no network.
//
// Cases marked `knownGap` assert the gap STILL EXISTS. That is deliberate: when someone
// closes the gap this test fails and tells them to delete the flag, so the documented
// gap list in docs/BENCH-CASES.md can never silently go stale.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CASES } from "../src/cases.ts";
import { scanCase } from "../src/engine.ts";
import { reached } from "../src/report.ts";

const attacks = CASES.filter((c) => c.kind === "attack");
const benign = CASES.filter((c) => c.kind === "benign");

for (const c of attacks) {
  if (c.kind !== "attack") continue;

  if (c.knownGap) {
    test(`${c.id} — known gap still open (${c.technique})`, async () => {
      const s = await scanCase(c);
      assert.equal(
        reached(s.severity, c.targetSeverity),
        false,
        `${c.id} now reaches ${c.targetSeverity} — the gap is closed. Remove \`knownGap\` ` +
          `from the case and its row in docs/BENCH-CASES.md §5.`,
      );
    });
    continue;
  }

  test(`${c.id} — ${c.technique} reaches ${c.targetSeverity}`, async () => {
    const s = await scanCase(c);
    assert.equal(
      reached(s.severity, c.targetSeverity),
      true,
      `${c.id} scored ${s.severity}, expected >= ${c.targetSeverity}. Signals: ` +
        JSON.stringify(s.perField.map((p) => p.codes)),
    );
    for (const code of c.expectSignals) {
      const all = s.perField.flatMap((p) => p.codes);
      assert.ok(all.includes(code), `${c.id} missing expected signal ${code}; got ${all.join(", ")}`);
    }
  });
}

for (const c of benign) {
  if (c.kind !== "benign") continue;

  if (c.knownFP) {
    test(`${c.id} — known false positive still open (${c.guards})`, async () => {
      const s = await scanCase(c);
      assert.notEqual(
        s.severity,
        "CLEAN",
        `${c.id} is CLEAN now — the false positive is fixed. Remove \`knownFP\` from the ` +
          `case and its row in docs/BENCH-CASES.md §5.`,
      );
    });
    continue;
  }

  test(`${c.id} — stays CLEAN (${c.guards})`, async () => {
    const s = await scanCase(c);
    assert.equal(
      s.severity,
      "CLEAN",
      `false positive on ${c.id}: ${JSON.stringify(s.perField.filter((p) => p.severity !== "CLEAN"))}`,
    );
  });
}

test("every attack case names a benign twin that exists", () => {
  for (const c of attacks) {
    if (c.kind !== "attack") continue;
    assert.ok(
      benign.some((b) => b.id === c.twin),
      `${c.id} points at twin ${c.twin}, which is not in the corpus`,
    );
  }
});
