// L4 dispatch — run the parser-differential interpreters for the declared consuming
// environment(s). "plaintext" is the inert baseline (no interpreter → no control found),
// so a signal here means: this data is inert as text but becomes control in env B.

import type { Signal, TargetContext } from "../types.ts";
import { llmTemplateInterpret } from "./llm-template.ts";
import { markdownInterpret } from "./markdown.ts";

export function runInterpreters(text: string, contexts: TargetContext[], model?: string): Signal[] {
  const out: Signal[] = [];
  for (const c of contexts) {
    if (c === "llm-chat") out.push(...llmTemplateInterpret(text, model));
    else if (c === "markdown-ui") out.push(...markdownInterpret(text));
    // "plaintext" → baseline, nothing to flag
  }
  return out;
}
