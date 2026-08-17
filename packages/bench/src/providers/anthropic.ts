// Real Anthropic Messages API provider. Needs ANTHROPIC_API_KEY.
// This is the only provider whose numbers may be reported as results.

import type { ModelReply, Provider, ToolCall } from "../types.ts";

const API = "https://api.anthropic.com/v1/messages";

// Adaptive thinking is on by default on current models and shares this budget with the
// response text. Too small a budget truncates before the model can emit a tool_use, which
// would be scored as "not hijacked" and silently deflate ASR.
//
// `isInvalid` catches that truncation and drops the run, so the deflation never reaches a
// reported rate — but a dropped run still cost an API call and yielded no data. Headroom is
// the cheaper fix: this is a ceiling, not a target, and billing follows tokens actually
// generated, so raising it costs nothing on runs that were already finishing. Sonnet 5 in
// particular defaults to `effort: high` with thinking on, and thinking draws from here too.
const MAX_TOKENS = 8192;

interface AnthropicBlock {
  type: string;
  text?: string;
  name?: string;
  input?: unknown;
}

/** Transient statuses. Retried rather than thrown, because a dropped call is not a safe
 *  run — it would vanish from the denominator and quietly bias whichever arm hit the limit
 *  more often (the guard-off arm, which sends longer payloads). */
const RETRY_STATUS = new Set([408, 429, 500, 502, 503, 529]);
const MAX_ATTEMPTS = 5;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function anthropicProvider(apiKey: string): Provider {
  return {
    id: "anthropic",
    async complete({ model, system, messages, tools }): Promise<ModelReply> {
      let res!: Response;
      for (let attempt = 1; ; attempt++) {
        res = await fetch(API, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify({ model, max_tokens: MAX_TOKENS, system, messages, tools }),
        });
        if (res.ok) break;

        const body = (await res.text()).slice(0, 300);
        if (!RETRY_STATUS.has(res.status) || attempt >= MAX_ATTEMPTS) {
          throw new Error(`anthropic ${res.status} after ${attempt} attempt(s): ${body}`);
        }
        // honour Retry-After when the API sends it; otherwise back off with jitter so a
        // whole concurrent batch does not retry in lockstep
        const after = Number(res.headers.get("retry-after"));
        const wait = after > 0 ? after * 1000 : 2 ** attempt * 250 + Math.random() * 250;
        await sleep(wait);
      }

      const body = (await res.json()) as {
        content?: AnthropicBlock[];
        stop_reason?: string;
        usage?: { input_tokens?: number; output_tokens?: number };
      };
      const blocks = body.content ?? [];
      const text = blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("\n");
      const toolCalls: ToolCall[] = blocks
        .filter((b) => b.type === "tool_use")
        .map((b) => ({ name: b.name ?? "", input: b.input }));

      return {
        text,
        toolCalls,
        stopReason: body.stop_reason,
        usage: {
          inputTokens: body.usage?.input_tokens ?? 0,
          outputTokens: body.usage?.output_tokens ?? 0,
        },
      };
    },
  };
}
