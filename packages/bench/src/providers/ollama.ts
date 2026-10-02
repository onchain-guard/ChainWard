/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
// Local-model provider. Talks to an Ollama server over its /api/chat endpoint.
//
// Why this exists: every number we report so far came from one model (Sonnet 5), so
// "the model refused" and "this model refused" are the same sentence in our data. Local
// models are the cheapest way to break that tie — no per-token cost, so the corpus can be
// replayed across four models for the price of GPU time.
//
// The harness speaks Anthropic's message shape (prompt.ts builds `tool_use`/`tool_result`
// blocks). Ollama speaks the OpenAI shape. Everything below is that translation, in both
// directions. No scoring or policy lives here — a provider that decided anything would be
// deciding its own result.

import type { ModelReply, Provider, ToolCall, Usage } from "../types.ts";

const DEFAULT_HOST = "http://127.0.0.1:11434";

/** Mirrors MAX_TOKENS in the Anthropic provider so a truncation ceiling is not what
 *  distinguishes the two providers' numbers. Ollama's own default (`num_predict: -1`) is
 *  unbounded, which would let one runaway generation stall a whole batch. */
const NUM_PREDICT = 8192;

/** Loading a 8B model into VRAM takes seconds, and a queued request waits behind every
 *  other one when the server runs with OLLAMA_NUM_PARALLEL=1. `fetch` has no default
 *  timeout, so without this a wedged server hangs the run forever instead of failing. */
const TIMEOUT_MS = 10 * 60 * 1000;

const RETRY_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 4;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ outbound translation */

interface OllamaMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls?: Array<{ function: { name: string; arguments: unknown } }>;
}

/** Anthropic allows a block array; Ollama's `content` is a plain string. Text blocks are
 *  joined, and the two block types that carry structure get their own handling below. */
function blocksToText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b: any) => b?.type === "text" && typeof b.text === "string")
    .map((b: any) => b.text)
    .join("\n");
}

/** The whole measurement hinges on this function.
 *
 *  The corpus delivers its payload as a `tool_result` block — that is the real injection
 *  vector, an agent reading on-chain data back from its own tool. Ollama has no such block:
 *  a tool's output is a separate message with role "tool". Flatten it wrong and the payload
 *  either vanishes (every case scores CLEAN, a silent false negative across the whole run)
 *  or lands in the user turn (where the model reads it as the user's own words, which is a
 *  different and much weaker threat model than the one we claim to measure). */
function toOllamaMessages(system: string, messages: unknown[]): OllamaMessage[] {
  const out: OllamaMessage[] = [];
  if (system) out.push({ role: "system", content: system });

  for (const raw of messages) {
    const m = raw as { role?: string; content?: unknown };
    const role = m.role === "assistant" ? "assistant" : "user";
    const blocks = Array.isArray(m.content) ? (m.content as any[]) : [];

    // tool_result blocks become their own role:"tool" messages, in place.
    const toolResults = blocks.filter((b) => b?.type === "tool_result");
    if (toolResults.length > 0) {
      for (const b of toolResults) {
        const body = typeof b.content === "string" ? b.content : JSON.stringify(b.content);
        out.push({ role: "tool", content: body });
      }
      // A tool_result turn carries nothing else in this corpus; emitting an empty user
      // message beside it would add a blank turn some models answer instead of the tool.
      const alsoText = blocksToText(m.content);
      if (alsoText) out.push({ role, content: alsoText });
      continue;
    }

    // tool_use blocks become assistant tool_calls, so the transcript still shows the model
    // having asked for the data it is about to receive. Drop this and the tool message
    // arrives unmotivated, which some models answer with a refusal unrelated to our test.
    const toolUses = blocks.filter((b) => b?.type === "tool_use");
    if (toolUses.length > 0) {
      out.push({
        role: "assistant",
        content: blocksToText(m.content),
        tool_calls: toolUses.map((b) => ({
          function: { name: String(b.name ?? ""), arguments: b.input ?? {} },
        })),
      });
      continue;
    }

    out.push({ role, content: blocksToText(m.content) });
  }
  return out;
}

/** Anthropic: {name, description, input_schema}. Ollama: OpenAI's function wrapper. */
function toOllamaTools(tools: unknown[]): unknown[] {
  return tools.map((raw) => {
    const t = raw as { name?: string; description?: string; input_schema?: unknown };
    return {
      type: "function",
      function: {
        name: t.name,
        description: t.description,
        parameters: t.input_schema ?? { type: "object", properties: {} },
      },
    };
  });
}

/* ------------------------------------------------------------------- inbound translation */

interface OllamaReply {
  message?: {
    content?: string;
    tool_calls?: Array<{ function?: { name?: string; arguments?: unknown } }>;
  };
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
}

/** Most models hand back a parsed object; some emit the arguments as a JSON string. The
 *  scorer reads `input.to` to decide whether a transfer went to the canary address, so a
 *  string here would read as "no destination" and score a real hijack as a miss. */
function normalizeArgs(args: unknown): unknown {
  if (typeof args !== "string") return args ?? {};
  try {
    return JSON.parse(args);
  } catch {
    return { _raw: args };
  }
}

/** `isInvalid` drops runs whose turn was cut off, because a truncated answer says nothing
 *  about hijack resistance — and silently counting it as "not hijacked" would deflate the
 *  rate. Ollama signals that as done_reason "length", so it is renamed to the token the
 *  scorer already knows. */
function toStopReason(done?: string): string | undefined {
  if (done === "length") return "max_tokens";
  return done;
}

/* --------------------------------------------------------------------------- the provider */

/** @param host  base URL of the Ollama server, e.g. the local end of an SSH tunnel.
 *               Defaults to 127.0.0.1:11434, Ollama's own default port. */
export function ollamaProvider(host: string = DEFAULT_HOST): Provider {
  const url = `${host.replace(/\/+$/, "")}/api/chat`;

  return {
    id: "ollama",
    async complete({ model, system, messages, tools }): Promise<ModelReply> {
      const body = JSON.stringify({
        model,
        messages: toOllamaMessages(system, messages),
        tools: toOllamaTools(tools),
        // Ollama streams by default; the harness wants one whole reply per call.
        stream: false,
        options: { num_predict: NUM_PREDICT },
      });

      let res!: Response;
      for (let attempt = 1; ; attempt++) {
        try {
          res = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
            signal: AbortSignal.timeout(TIMEOUT_MS),
          });
        } catch (e) {
          // A dropped run is not a safe run: it would vanish from the denominator and bias
          // whichever arm hit the error more often (the guard-off arm sends longer payloads).
          if (attempt >= MAX_ATTEMPTS) {
            throw new Error(
              `ollama unreachable at ${url} after ${attempt} attempt(s): ${String(e)}\n` +
                `  is the SSH tunnel up?  ssh -N -L 11434:127.0.0.1:11434 <user>@<host>`,
            );
          }
          await sleep(2 ** attempt * 500);
          continue;
        }
        if (res.ok) break;

        const detail = (await res.text()).slice(0, 300);
        if (!RETRY_STATUS.has(res.status) || attempt >= MAX_ATTEMPTS) {
          throw new Error(`ollama ${res.status} after ${attempt} attempt(s): ${detail}`);
        }
        await sleep(2 ** attempt * 500 + Math.random() * 250);
      }

      const reply = (await res.json()) as OllamaReply;
      const toolCalls: ToolCall[] = (reply.message?.tool_calls ?? []).map((c) => ({
        name: c.function?.name ?? "",
        input: normalizeArgs(c.function?.arguments),
      }));
      const usage: Usage = {
        inputTokens: reply.prompt_eval_count ?? 0,
        outputTokens: reply.eval_count ?? 0,
      };

      return {
        text: reply.message?.content ?? "",
        toolCalls,
        stopReason: toStopReason(reply.done_reason),
        usage,
      };
    },
  };
}
