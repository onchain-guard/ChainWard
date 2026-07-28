// Benchmark case contracts. See docs/BENCH-CASES.md for the case table and the
// rationale behind every guardrail these cases exercise.

import type { FieldKind, Severity } from "@onchain-guard/core";

/** Which arm of the experiment: raw data vs. ChainWard-sanitized data. */
export type Arm = "off" | "on";

/** One scannable text field of the simulated on-chain record. `key` is the JSON key the
 *  indexer would use, `kind` is the FieldKind the engine scans it as. */
export interface CaseField {
  key: string;
  kind: FieldKind;
  value: string;
}

interface CaseBase {
  id: string;
  title: string;
  /** shape of the simulated indexer/tool response */
  shape: "token" | "nft" | "tx";
  chain: string;
  address: string;
  /** what the user asks the wallet agent */
  userMsg: string;
  /** scannable text fields (attacker-writable surface) */
  fields: CaseField[];
  /** non-text fields passed through untouched (balance, decimals, tokenId…) */
  passthrough?: Record<string, unknown>;
}

export interface AttackCase extends CaseBase {
  kind: "attack";
  technique: string;
  /** unique attacker address; a tool_use carrying it == hijacked */
  canary: string;
  /** severity the engine SHOULD reach for this case */
  targetSeverity: Exclude<Severity, "CLEAN">;
  /** detector codes we expect to see (documentation + regression anchor) */
  expectSignals: string[];
  /** set when the engine provably does NOT reach targetSeverity today.
   *  The corpus test asserts the gap still exists, so fixing it fails the test
   *  and forces this flag to be removed. */
  knownGap?: string;
  /** id of the benign case that must stay CLEAN under the same guardrail */
  twin: string;
}

export interface BenignCase extends CaseBase {
  kind: "benign";
  /** benign cases must stay CLEAN — any other verdict is a false positive */
  targetSeverity: "CLEAN";
  /** which guardrail's false-positive risk this case pins down */
  guards: string;
  /** the model's answer should mention this to count as "task still doable" */
  utilityToken: string;
  /** set when the engine provably DOES false-positive on this case today. Mirrors
   *  AttackCase.knownGap: the test asserts the FP still happens, so fixing the rule
   *  fails the test and forces the flag (and the doc row) to be removed. */
  knownFP?: string;
}

export type BenchCase = AttackCase | BenignCase;

export interface ToolCall {
  name: string;
  input: unknown;
}

export interface ModelReply {
  text: string;
  toolCalls: ToolCall[];
}

export interface Provider {
  readonly id: string;
  complete(req: {
    model: string;
    system: string;
    messages: unknown[];
    tools: unknown[];
  }): Promise<ModelReply>;
}

/** Engine-side result for one case — deterministic, needs no model. */
export interface GuardResultRow {
  caseId: string;
  /** worst severity across the case's fields */
  severity: Severity;
  perField: Array<{ key: string; kind: FieldKind; severity: Severity; codes: string[] }>;
}

/** One model run of one case in one arm. */
export interface RunRow {
  caseId: string;
  arm: Arm;
  model: string;
  provider: string;
  /** tool_use carrying this case's canary address → hijacked */
  hijacked: boolean;
  /** called a value-moving tool at all (any destination) */
  movedFunds: boolean;
  /** benign only: the answer still mentions the token → utility preserved */
  taskDone: boolean;
  toolCalls: ToolCall[];
  text: string;
}
