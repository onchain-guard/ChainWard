// ChainWard SDK — library entry point.
//
//   import { guard } from "chainward";
//   const { messages } = await guard(rawMessages, { model, targetContext: ["llm-chat"] });
//   const res = await llm.chat(messages);   // messages are now sanitized
//
// Put this at the harness↔LLM boundary (in a harness you own — ElizaOS, custom agent).
// For harnesses you don't control (Claude Code), use the proxy instead: `chainward proxy`.

import type { Severity, TargetContext } from "./core/types.ts";
import { defaultScanner } from "./core/scanner.ts";

export * from "./core/types.ts";
export { ChainWardScanner, defaultScanner, fuse, renderSafe } from "./core/scanner.ts";

export interface ChatMessage {
  role: string;
  content: string | unknown;
  [k: string]: unknown;
}

export interface GuardFinding {
  index: number;
  role: string;
  severity: Severity;
  codes: string[];
}

export interface GuardOptions {
  /** target model id — selects the chat-template special-token set for the differential check */
  model?: string;
  /** consuming environments the data flows into (default: ["llm-chat"]) */
  targetContext?: TargetContext[];
  /** which message roles carry untrusted data (default: user, tool) */
  untrustedRoles?: string[];
  /** called for every non-CLEAN message */
  onFinding?: (f: GuardFinding) => void;
}

export interface GuardResult {
  messages: ChatMessage[];
  findings: GuardFinding[];
}

/** Scan+sanitize a chat-message array before it reaches the model. Non-string content
 *  (tool blocks, images) is passed through untouched. */
export async function guard(messages: ChatMessage[], opts: GuardOptions = {}): Promise<GuardResult> {
  const scanner = defaultScanner();
  const untrusted = new Set(opts.untrustedRoles ?? ["user", "tool"]);
  const targetContexts = opts.targetContext ?? (["llm-chat"] as TargetContext[]);
  const findings: GuardFinding[] = [];
  const out: ChatMessage[] = [];

  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (typeof m.content !== "string" || !untrusted.has(m.role)) {
      out.push(m);
      continue;
    }
    const scan = await scanner.scanField("agent_context", m.content, { targetContexts, model: opts.model });
    if (scan.severity !== "CLEAN") {
      const f: GuardFinding = { index: i, role: m.role, severity: scan.severity, codes: scan.signals.map((s) => s.code) };
      findings.push(f);
      opts.onFinding?.(f);
    }
    out.push({ ...m, content: scan.sanitized });
  }
  return { messages: out, findings };
}
