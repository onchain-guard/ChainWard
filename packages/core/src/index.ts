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
export { ChainWardScanner, defaultRegistry, defaultScanner, fuse, renderSafe } from "./core/scanner.ts";
export type { FieldContext } from "./core/scanner.ts";

// The registry is the documented extension point, so its pieces have to be reachable —
// both to add a detector and to *remove* one. A consumer scanning something that is not
// a single untrusted field (an assembled prompt, say, where the agent's own trusted
// instructions sit next to the attacker's text) must be able to compose a registry from
// the layers that stay near-zero-FP on mixed content, instead of taking all five.
export { DetectorRegistry } from "./core/detector.ts";
export type { Detector, DetectInput } from "./core/detector.ts";
export { structuralDetector } from "./core/detectors/structural.ts";
export { patternDetector } from "./core/detectors/pattern.ts";
export { classifierDetector } from "./core/detectors/classifier.ts";
export { differentialDetector } from "./core/detectors/differential.ts";
export { deceptionDetector } from "./core/detectors/deception.ts";

// Swappable oracles behind L2b and L3.
export { HeuristicClassifier } from "./core/classifier.ts";
export type { InjectionClassifier } from "./core/classifier.ts";
export { MockHoneypotOracle, extractSafetyClaims } from "./core/honeypot.ts";
export type { HoneypotOracle, HoneypotResult } from "./core/honeypot.ts";
// exported so fixtures/benchmarks key off the oracle's own value instead of copying it
export { MOCK_HONEYPOT_ADDRESS } from "./core/honeypot.ts";

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

/** Scan+sanitize a chat-message array before it reaches the model. Handles both plain-string
 *  content (OpenAI shape) and Anthropic block-array content — guarding `text` and `tool_result`
 *  blocks while passing `tool_use`/`image`/unknown blocks through untouched. */
export async function guard(messages: ChatMessage[], opts: GuardOptions = {}): Promise<GuardResult> {
  const scanner = defaultScanner();
  const untrusted = new Set(opts.untrustedRoles ?? ["user", "tool"]);
  const targetContexts = opts.targetContext ?? (["llm-chat"] as TargetContext[]);
  const findings: GuardFinding[] = [];
  const out: ChatMessage[] = [];

  const scan = (text: string) =>
    scanner.scanField("agent_context", text, { targetContexts, model: opts.model });

  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (!untrusted.has(m.role)) { out.push(m); continue; }

    // (a) plain string content (OpenAI shape)
    if (typeof m.content === "string") {
      const s = await scan(m.content);
      if (s.severity !== "CLEAN") {
        const f = { index: i, role: m.role, severity: s.severity, codes: s.signals.map((x) => x.code) };
        findings.push(f); opts.onFinding?.(f);
      }
      out.push({ ...m, content: s.sanitized });
      continue;
    }

    // (b) block array content (Anthropic shape)
    if (Array.isArray(m.content)) {
      let flagged: GuardFinding | null = null;
      const blocks = await Promise.all((m.content as any[]).map(async (b) => {
        if (b?.type === "text" && typeof b.text === "string") {
          const s = await scan(b.text);
          if (s.severity !== "CLEAN") flagged = mergeFinding(flagged, i, m.role, s);
          return { ...b, text: s.sanitized };
        }
        if (b?.type === "tool_result") {
          if (typeof b.content === "string") {
            const s = await scan(b.content);
            if (s.severity !== "CLEAN") flagged = mergeFinding(flagged, i, m.role, s);
            return { ...b, content: s.sanitized };
          }
          if (Array.isArray(b.content)) {
            const inner = await Promise.all(b.content.map(async (c: any) => {
              if (c?.type === "text" && typeof c.text === "string") {
                const s = await scan(c.text);
                if (s.severity !== "CLEAN") flagged = mergeFinding(flagged, i, m.role, s);
                return { ...c, text: s.sanitized };
              }
              return c;
            }));
            return { ...b, content: inner };
          }
        }
        return b; // tool_use / image / unknown → untouched
      }));
      if (flagged) { findings.push(flagged); opts.onFinding?.(flagged); }
      out.push({ ...m, content: blocks });
      continue;
    }

    out.push(m); // non-string, non-array → untouched
  }
  return { messages: out, findings };
}

// Combine per-block findings for one message into a single message-level finding
// (worst severity wins, codes unioned).
function mergeFinding(
  prev: GuardFinding | null, index: number, role: string,
  s: { severity: Severity; signals: Array<{ code: string }> },
): GuardFinding {
  const codes = new Set([...(prev?.codes ?? []), ...s.signals.map((x) => x.code)]);
  const sev = worseSeverity(prev?.severity ?? "CLEAN", s.severity);
  return { index, role, severity: sev, codes: [...codes] };
}
function worseSeverity(a: Severity, b: Severity): Severity {
  const order: Record<Severity, number> = { CLEAN: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
  return order[a] >= order[b] ? a : b;
}
