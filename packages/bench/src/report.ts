// Markdown report generation — the table that goes into the contest write-up.

import type { GuardResultRow, RunRow } from "./types.ts";
import type { Metrics } from "./score.ts";
import { CASES } from "./cases.ts";

export function guardTable(rows: GuardResultRow[]): string {
  const out: string[] = [
    "| case | 목표 | 판정 | 결과 | 신호 |",
    "|---|---|---|---|---|",
  ];
  for (const r of rows) {
    const c = CASES.find((x) => x.id === r.caseId)!;
    const met = c.kind === "attack" ? reached(r.severity, c.targetSeverity) : r.severity === "CLEAN";
    const known = c.kind === "attack" ? c.knownGap : c.knownFP;
    const mark = met ? "✅" : known ? (c.kind === "attack" ? "🕳 gap" : "🕳 FP") : "❌";
    const codes = [...new Set(r.perField.flatMap((p) => p.codes))].slice(0, 3).join(", ") || "—";
    out.push(`| ${r.caseId} | ${c.targetSeverity} | ${r.severity} | ${mark} | ${codes} |`);
  }
  return out.join("\n");
}

const ORDER = { CLEAN: 0, SUSPICIOUS: 1, MALICIOUS: 2 } as const;
export function reached(actual: keyof typeof ORDER, target: keyof typeof ORDER): boolean {
  return ORDER[actual] >= ORDER[target];
}

export function metricsTable(m: Metrics, model: string, provider: string): string {
  return [
    `**model:** \`${model}\`  **provider:** \`${provider}\``,
    "",
    "| 지표 | 값 | 분모 |",
    "|---|---|---|",
    `| ASR (guard off) | **${m.asrOff.rate}%** | ${m.asrOff.hits}/${m.asrOff.runs} |`,
    `| ASR (guard on) | **${m.asrOn.rate}%** | ${m.asrOn.hits}/${m.asrOn.runs} |`,
    `| 오탐율 (정상 케이스) | **${m.falsePositive.rate}%** | ${m.falsePositive.flagged}/${m.falsePositive.benign} |`,
    `| 유용성 보존 (guard on) | **${m.utility.rate}%** | ${m.utility.done}/${m.utility.runs} |`,
  ].join("\n");
}

export function perCaseRuns(runs: RunRow[]): string {
  const ids = [...new Set(runs.map((r) => r.caseId))].sort();
  const out: string[] = ["| case | off 하이재킹 | on 하이재킹 |", "|---|---|---|"];
  for (const id of ids) {
    if (!id.startsWith("A")) continue;
    const off = runs.filter((r) => r.caseId === id && r.arm === "off");
    const on = runs.filter((r) => r.caseId === id && r.arm === "on");
    const f = (rs: RunRow[]) => `${rs.filter((r) => r.hijacked).length}/${rs.length}`;
    out.push(`| ${id} | ${f(off)} | ${f(on)} |`);
  }
  return out.join("\n");
}
