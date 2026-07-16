// Terminal rendering for scan results (ANSI, zero deps). Shared by CLI and demo.

import type { FieldScan, ScanReport, Severity } from "./core/types.ts";

const C = {
  reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m", cyan: "\x1b[36m", gray: "\x1b[90m",
};

function sevColor(s: Severity): string {
  return s === "MALICIOUS" ? C.red : s === "SUSPICIOUS" ? C.yellow : C.green;
}
function badge(s: Severity): string {
  const icon = s === "MALICIOUS" ? "✖" : s === "SUSPICIOUS" ? "▲" : "✔";
  return `${sevColor(s)}${C.bold}${icon} ${s}${C.reset}`;
}

export function renderField(f: FieldScan): string {
  const lines: string[] = [];
  lines.push(`  ${badge(f.severity)} ${C.cyan}${f.kind}${C.reset} ${C.gray}(score ${f.score})${C.reset}`);
  const rawPreview = JSON.stringify(f.raw.length > 90 ? f.raw.slice(0, 90) + "…" : f.raw);
  lines.push(`    ${C.gray}raw:${C.reset}       ${rawPreview}`);
  for (const s of f.signals) {
    const w = s.hard ? `${C.red}HARD${C.reset}` : `${C.dim}w=${s.weight}${C.reset}`;
    lines.push(`    ${C.gray}└─${C.reset} [${s.layer}] ${C.bold}${s.code}${C.reset} ${w}`);
    lines.push(`       ${C.dim}${s.detail}${C.reset}`);
  }
  if (f.severity !== "CLEAN") {
    lines.push(`    ${C.green}safe→${C.reset}     ${JSON.stringify(f.sanitized)}`);
  }
  return lines.join("\n");
}

export function renderReport(r: ScanReport): string {
  const head =
    `${C.bold}ChainWard scan${C.reset} ${C.gray}${r.target.kind}:${r.target.address ?? r.target.txHash ?? ""} @${r.target.chain}${C.reset}\n` +
    `${badge(r.severity)}  ${r.summary}`;
  return [head, ...r.fields.map(renderField)].join("\n");
}
