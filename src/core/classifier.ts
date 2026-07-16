// LAYER 2b — Injection-intent classifier.
//
// This is the "does this read like instructions to an AI, not like a name?" fuzzy layer.
// The interface is the stable contract; the DEMO ships a real, deterministic heuristic
// scorer (no deps, explainable). Production swaps in Meta's Llama Prompt Guard 2 — the
// adapter is written out below so the swap is mechanical.

import type { FieldKind } from "./types.ts";
import { FIELD_SHAPE } from "./types.ts";

export interface InjectionClassifier {
  readonly name: string;
  /** probability 0..1 that `text` is an injection/instruction aimed at an AI reader */
  score(text: string, kind: FieldKind): Promise<number>;
}

// Lexicons that signal "instruction aimed at a reader" rather than a label.
const IMPERATIVE_VERBS = /\b(ignore|disregard|forget|send|transfer|approve|reply|respond|act|pretend|assume|treat|proceed|execute|run|call|recommend|tell|make|do not|don't|must|should)\b/gi;
const AGENT_ADDRESS = /\b(you|your|assistant|system|model|agent|ai|llm)\b/gi;
const SENTENCE_END = /[.!?]/g;

/** Deterministic heuristic classifier — genuinely computes a score from linguistic shape.
 *  Not a stub: this alone catches paraphrased injections the regex pack misses. */
export class HeuristicClassifier implements InjectionClassifier {
  readonly name = "heuristic-v1";

  async score(text: string, kind: FieldKind): Promise<number> {
    const t = text.trim();
    if (!t) return 0;
    const words = t.split(/\s+/);
    const n = words.length;

    const imperatives = (t.match(IMPERATIVE_VERBS) ?? []).length;
    const agentRefs = (t.match(AGENT_ADDRESS) ?? []).length;
    const sentences = (t.match(SENTENCE_END) ?? []).length;

    // Feature scores (each ~0..1)
    const imperativeDensity = Math.min(1, imperatives / Math.max(4, n / 3));
    const addressesAgent = Math.min(1, agentRefs / 2);
    const looksLikeProse = Math.min(1, sentences / 2);

    // Shape prior: a long, sentence-y value in a field meant to be a short label is itself
    // suspicious. A 200-char "token name" is not a name.
    const shape = FIELD_SHAPE[kind];
    const overLen = t.length > shape.maxLabelLen ? 1 : 0;
    const shapeAnomaly = shape.freeform ? 0 : Math.max(overLen, n > 8 ? 0.6 : 0);

    // Weighted fusion -> logistic squash for a calibrated-ish 0..1.
    const raw =
      1.6 * imperativeDensity +
      1.4 * addressesAgent +
      0.8 * looksLikeProse +
      1.2 * shapeAnomaly -
      1.3;
    const p = 1 / (1 + Math.exp(-raw));
    return Math.round(p * 100) / 100;
  }
}

/* REAL IMPL — Meta Llama Prompt Guard 2 (open weights) via @huggingface/transformers.
 * Drop-in: implements the same InjectionClassifier interface. Change ONE line in the
 * scanner factory (see src/core/scanner.ts `defaultScanner`) to use this instead.
 *
 *   import { pipeline } from "@huggingface/transformers";
 *
 *   export class PromptGuardClassifier implements InjectionClassifier {
 *     readonly name = "Llama-Prompt-Guard-2-86M";
 *     private clf: any;
 *     private async init() {
 *       this.clf ??= await pipeline("text-classification",
 *         "meta-llama/Llama-Prompt-Guard-2-86M");
 *     }
 *     async score(text: string): Promise<number> {
 *       await this.init();
 *       const [out] = await this.clf(text);          // { label: "LABEL_1"|"LABEL_0", score }
 *       return out.label === "LABEL_1" ? out.score : 1 - out.score;
 *     }
 *   }
 *
 * Everything downstream (fusion, sanitization, CLI, MCP) is unchanged.
 */
