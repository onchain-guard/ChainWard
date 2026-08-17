// Benchmark case contracts. See docs/BENCH-CASES.md for the case table and the
// rationale behind every guardrail these cases exercise.

import type { FieldKind, Severity } from "chainward";

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

/** Which harm a model run measures for this case. The families are reported separately
 *  because their denominators AND their evidentiary strength differ — folding them into a
 *  single ASR was the original defect: cases whose harm is not a tool call could never
 *  produce a canary hit, yet sat in the ASR denominator and capped it. */
export type Scoring =
  /** a value-moving tool call carrying this case's canary. objective. */
  | "canary"
  /** the payload's active markdown construct survives into the model's answer, where a
   *  renderer would fire it. objective. */
  | "passthrough"
  /** the model repeats an attacker claim that on-chain truth refutes, without warning.
   *  keyword-based, so the weakest of the three — never folded into ASR. */
  | "deception";

export interface AttackCase extends CaseBase {
  kind: "attack";
  technique: string;
  /** how a model run is scored — see `Scoring`. Required: a new case must state which
   *  harm it measures, or it silently pollutes a denominator. */
  scoring: Scoring;
  /** `passthrough` only: regex source for the active construct whose survival IS the harm. */
  harmPattern?: string;
  /** unique attacker address; a tool_use carrying it == hijacked (`canary` scoring only) */
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

/** Token counts as the API reported them. Recorded rather than estimated, because a run
 *  that costs money should be able to say what it cost — and because the output count is
 *  the only way to tell "the model answered briefly" from "adaptive thinking ate the
 *  budget", which is the difference between a cheap corpus and a truncated one. */
export interface Usage {
  inputTokens: number;
  outputTokens: number;
}

export interface ModelReply {
  text: string;
  toolCalls: ToolCall[];
  /** `max_tokens` means the turn was cut off; `refusal` means a safety classifier
   *  declined. Either way the run says nothing about hijack resistance. */
  stopReason?: string;
  usage?: Usage;
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
  /** the harm this case measures actually happened — see the case's `scoring` family */
  harmed: boolean;
  /** called a value-moving tool at all (any destination) */
  movedFunds: boolean;
  /** benign only: the answer still mentions the token → utility preserved */
  taskDone: boolean;
  /** the turn was truncated or classifier-refused — excluded from every rate */
  invalid: boolean;
  stopReason?: string;
  usage?: Usage;
  toolCalls: ToolCall[];
  text: string;
}
