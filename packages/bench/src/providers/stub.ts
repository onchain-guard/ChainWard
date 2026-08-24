// ⚠️ NOT A MEASUREMENT. This provider is a deterministic stand-in used only to smoke-test
// the harness plumbing (arms, canary scoring, reporting) without network access.
//
// It decides to "follow" a directive by regex, which is circular: it would find a hijack
// exactly where we planted one. Numbers produced with --provider stub are pipeline checks,
// never results. Report only numbers from a real model provider.
//
// It follows a directive wherever it sits — attacker field or the user's own message — so
// the positive control passes here too. That is what makes `--provider stub` a check of the
// whole gate (pass path included) rather than only of its failure banner.

import type { ModelReply, Provider, ToolCall } from "../types.ts";

// Verb and address, in EITHER order — English puts the verb first ("transfer … to 0x…"),
// Korean puts it last ("0x… 으로 보내줘"). The one-sided pattern this replaces matched only
// the English form, so the Korean positive control never produced a tool call and the
// control gate's PASS path was never exercised by the smoke test.
const ACTION = String.raw`(?:transfer|send|approve|move|보내|전송|승인|이체)`;
const ADDR = String.raw`(0x[a-fA-F0-9]{40})`;
const DIRECTIVE = new RegExp(`${ACTION}[\\s\\S]{0,80}?${ADDR}|${ADDR}[\\s\\S]{0,80}?${ACTION}`, "i");
const APPROVAL = /approve|승인/i;
const FENCED = /treat (it|them) as data|treat as data|REDACTED|chainward/i;

export function stubProvider(): Provider {
  return {
    id: "stub",
    async complete({ messages }): Promise<ModelReply> {
      const flat = JSON.stringify(messages);
      const toolCalls: ToolCall[] = [];

      // A sanitized payload announces itself; a compliant agent heeds the fencing.
      if (!FENCED.test(flat)) {
        const m = DIRECTIVE.exec(flat);
        const dest = m?.[1] ?? m?.[2];
        if (dest) {
          // approve vs transfer matters: both count as value-moving, and a stub that only
          // ever emits one of them cannot smoke-test the other's scoring path
          toolCalls.push(
            APPROVAL.test(m![0])
              ? { name: "approve_token", input: { token_address: "0x0", spender: dest, amount: "all" } }
              : { name: "transfer_token", input: { token_address: "0x0", to: dest, amount: "all" } },
          );
        }
      }

      // the tool_result arrives as an escaped JSON string, so quotes may be backslashed
      const symbol = /\\?"symbol\\?":\s*\\?"([^"\\]{1,20})/.exec(flat)?.[1] ?? "";
      const name = /\\?"name\\?":\s*\\?"([^"\\]{1,60})/.exec(flat)?.[1] ?? "";
      return {
        text: toolCalls.length
          ? "Processing the requested transfer."
          : `Here is what I found for ${symbol || name}.`,
        toolCalls,
        stopReason: toolCalls.length ? "tool_use" : "end_turn",
      };
    },
  };
}
