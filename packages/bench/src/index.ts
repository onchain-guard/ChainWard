// ChainWard benchmark CLI.
//
//   npx tsx src/index.ts --guard-only            # engine verdicts only — no model, no key
//   npx tsx src/index.ts --provider stub         # plumbing smoke test (NOT results)
//   npx tsx src/index.ts --provider anthropic --models opus,sonnet --runs 30 --concurrency 6
//
// Reports the three harm families SEPARATELY (canary / passthrough / deception) alongside
// false-positive rate and utility retained. Reporting an attack rate without the last two is
// meaningless — a guard that redacts everything scores 0 harm and 0 utility.

import { CASES, caseById } from "./cases.ts";
import { buildToolResult, scanCase } from "./engine.ts";
import { SYSTEM_PROMPT, TOOLS, buildMessages } from "./prompt.ts";
import { aggregate, scoreRun } from "./score.ts";
import { guardTable, metricsTable, perCaseRuns, reached } from "./report.ts";
import { anthropicProvider } from "./providers/anthropic.ts";
import { stubProvider } from "./providers/stub.ts";
import type { Arm, BenchCase, GuardResultRow, Provider, RunRow } from "./types.ts";

interface Opts {
  provider: string;
  /** repeated runs are pooled ACROSS these — a guard that holds on one model only is a
   *  weaker claim than the same N spent on one model would suggest */
  models: string[];
  runs: number;
  /** max API calls in flight; the corpus is embarrassingly parallel */
  concurrency: number;
  guardOnly: boolean;
  only: string[];
}

function parseArgs(argv: string[]): Opts {
  const get = (flag: string, fallback: string) => {
    const i = argv.indexOf(flag);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
  };
  const list = (flag: string, fallback: string) =>
    get(flag, fallback).split(",").map((s) => s.trim()).filter(Boolean);
  return {
    provider: get("--provider", "stub"),
    models: list("--models", get("--model", "claude-sonnet-5")),
    runs: Number(get("--runs", "1")),
    concurrency: Number(get("--concurrency", "6")),
    guardOnly: argv.includes("--guard-only"),
    only: list("--cases", ""),
  };
}

function resolveProvider(id: string): Provider {
  if (id === "anthropic") {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) {
      console.error(
        "ANTHROPIC_API_KEY is not set.\n" +
          "  export ANTHROPIC_API_KEY=sk-ant-...   then re-run\n" +
          "  (or use --guard-only for engine metrics that need no model)",
      );
      process.exit(1);
    }
    return anthropicProvider(key);
  }
  if (id === "stub") return stubProvider();
  console.error(`unknown provider: ${id}`);
  process.exit(1);
}

/** Run `worker` over `items` with at most `limit` in flight. Results are collected as they
 *  land, so ordering is not preserved — aggregation groups by case/arm/model anyway. */
async function pool<T>(items: T[], limit: number, worker: (t: T) => Promise<void>): Promise<void> {
  let next = 0;
  const lanes = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (let i = next++; i < items.length; i = next++) await worker(items[i]);
  });
  await Promise.all(lanes);
}

async function runGuardOnly(cases: BenchCase[]): Promise<GuardResultRow[]> {
  const rows: GuardResultRow[] = [];
  for (const c of cases) {
    const s = await scanCase(c);
    rows.push({ caseId: s.caseId, severity: s.severity, perField: s.perField });
  }
  return rows;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const cases = opts.only.length
    ? opts.only.map((id) => caseById(id)).filter((c): c is BenchCase => Boolean(c))
    : CASES;

  const guardRows = await runGuardOnly(cases);

  console.log("# ChainWard 벤치마크\n");
  console.log("## 1. 엔진 판정 (결정적 — 모델 불필요)\n");
  console.log(guardTable(guardRows));

  const attacks = guardRows.filter((r) => r.caseId.startsWith("A"));
  const benign = guardRows.filter((r) => r.caseId.startsWith("B"));
  const detected = attacks.filter((r) => {
    const c = caseById(r.caseId);
    return c?.kind === "attack" && reached(r.severity, c.targetSeverity);
  }).length;
  const fpFlagged = benign.filter((r) => r.severity !== "CLEAN");

  console.log(
    `\n탐지: ${detected}/${attacks.length} · 오탐: ${fpFlagged.length}/${benign.length}` +
      (fpFlagged.length ? ` (${fpFlagged.map((r) => r.caseId).join(", ")})` : ""),
  );

  if (opts.guardOnly) return;

  const provider = resolveProvider(opts.provider);
  if (provider.id === "stub") {
    console.log("\n> ⚠️ provider=stub — 배관 점검용이며 결과로 보고할 수 없음. 실제 수치는 --provider anthropic.\n");
  }

  // Payloads are deterministic and identical across repeats and models, so build them all
  // up front — then every remaining unit of work is one independent API call.
  const tasks: Array<{ c: BenchCase; arm: Arm; model: string; messages: unknown[] }> = [];
  for (const c of cases) {
    for (const arm of ["off", "on"] as Arm[]) {
      const { json } = await buildToolResult(c, arm);
      const messages = buildMessages(c, json);
      for (const model of opts.models) {
        for (let i = 0; i < opts.runs; i++) tasks.push({ c, arm, model, messages });
      }
    }
  }

  process.stderr.write(
    `계획: ${cases.length}케이스 × 2 arm × ${opts.models.length}모델 × ${opts.runs}회 = ${tasks.length}콜 ` +
      `(동시 ${opts.concurrency})\n`,
  );

  const runs: RunRow[] = [];
  let failed = 0;
  let done = 0;
  await pool(tasks, opts.concurrency, async (t) => {
    try {
      const reply = await provider.complete({
        model: t.model,
        system: SYSTEM_PROMPT,
        messages: t.messages,
        tools: TOOLS,
      });
      runs.push(scoreRun(t.c, t.arm, t.model, provider.id, reply));
    } catch (e) {
      failed++;
      console.error(`  ${t.c.id}/${t.arm}/${t.model}: ${(e as Error).message}`);
    }
    done++;
    if (done % 25 === 0 || done === tasks.length) {
      process.stderr.write(`  ${done}/${tasks.length} (실패 ${failed})\n`);
    }
  });

  const metrics = aggregate(
    runs,
    benign.map((b) => ({ caseId: b.caseId, flagged: b.severity !== "CLEAN" })),
  );

  console.log("\n## 2. 모델 실행 결과\n");
  console.log(metricsTable(metrics, opts.models, provider.id));
  console.log("\n### 케이스별 (피해 발생 횟수 / 유효 실행 횟수)\n");
  console.log(perCaseRuns(runs));
  if (failed) {
    // a dropped call is not a safe run; saying so keeps the denominators honest
    console.log(`\n> ⚠️ ${failed}콜이 오류로 실행되지 못했고 어떤 분모에도 포함되지 않았다.`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
