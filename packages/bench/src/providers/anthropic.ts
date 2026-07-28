// Real Anthropic Messages API provider. Needs ANTHROPIC_API_KEY.
// This is the only provider whose numbers may be reported as results.

import type { ModelReply, Provider, ToolCall } from "../types.ts";

const API = "https://api.anthropic.com/v1/messages";

interface AnthropicBlock {
  type: string;
  text?: string;
  name?: string;
  input?: unknown;
}

export function anthropicProvider(apiKey: string): Provider {
  return {
    id: "anthropic",
    async complete({ model, system, messages, tools }): Promise<ModelReply> {
      const res = await fetch(API, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({ model, max_tokens: 1024, system, messages, tools }),
      });

      if (!res.ok) {
        throw new Error(`anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`);
      }

      const body = (await res.json()) as { content?: AnthropicBlock[] };
      const blocks = body.content ?? [];
      const text = blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("\n");
      const toolCalls: ToolCall[] = blocks
        .filter((b) => b.type === "tool_use")
        .map((b) => ({ name: b.name ?? "", input: b.input }));

      return { text, toolCalls };
    },
  };
}
