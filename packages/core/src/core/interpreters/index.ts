// L4 dispatch — run the parser-differential interpreters for the declared consuming
// environment(s). "plaintext" is the inert baseline (no interpreter → no control found),
// so a signal here means: this data is inert as text but becomes control in env B.

import type { Signal, TargetContext } from "../types.ts";
import { llmTemplateInterpret } from "./llm-template.ts";
import { markdownInterpret } from "./markdown.ts";

export function runInterpreters(text: string, contexts: TargetContext[], model?: string): Signal[] {
  const out: Signal[] = [];
  for (const c of contexts) {
    // Appended one at a time: the interpreters emit one signal per match, and `push(...)`
    // over an attacker-sized match list overflows the argument limit.
    if (c === "llm-chat") for (const s of llmTemplateInterpret(text, model)) out.push(s);
    else if (c === "markdown-ui") for (const s of markdownInterpret(text)) out.push(s);
    // "plaintext" → baseline, nothing to flag
  }
  return out;
}
