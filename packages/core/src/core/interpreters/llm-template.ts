// L4 interpreter — LLM chat-template differential.
//
// The model's chat template is a DETERMINISTIC grammar: role turns are delimited by
// special tokens. Untrusted data that contains those tokens (or textual role headers)
// is inert as a stored string but forges a new system/assistant turn once the harness
// templates it into the prompt. We detect that emergent control construct.

import type { Signal } from "../types.ts";

// Special-token strings across the popular families. A production build narrows to the
// exact set for the resolved `model`; the union is a safe superset for detection.
const SPECIAL_TOKENS: Record<string, string[]> = {
  chatml: ["<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>"],
  llama2: ["[INST]", "[/INST]", "<<SYS>>", "<</SYS>>", "<s>", "</s>"],
  llama3: ["<|begin_of_text|>", "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>"],
  misc: ["<|endoftext|>", "<|end|>", "### Instruction:", "### Response:"],
};

function tokensFor(model?: string): string[] {
  const all = Object.values(SPECIAL_TOKENS).flat();
  if (!model) return all;
  const m = model.toLowerCase();
  if (m.includes("gpt") || m.includes("qwen") || m.includes("o1") || m.includes("o3")) return [...SPECIAL_TOKENS.chatml, ...SPECIAL_TOKENS.misc];
  if (m.includes("llama-3") || m.includes("llama3")) return [...SPECIAL_TOKENS.llama3, ...SPECIAL_TOKENS.misc];
  if (m.includes("llama")) return [...SPECIAL_TOKENS.llama2, ...SPECIAL_TOKENS.misc];
  return all; // claude/mistral/unknown → full superset
}

const ROLE_HEADER = /(^|\n)\s{0,3}(#{1,6}\s*)?(system|assistant|developer|tool)\s*[:：]/i;

export function llmTemplateInterpret(text: string, model?: string): Signal[] {
  const out: Signal[] = [];
  for (const tok of tokensFor(model)) {
    if (text.includes(tok)) {
      out.push({
        layer: "differential",
        code: "CHAT_TEMPLATE_TOKEN",
        detail: `Contains chat-template control token "${tok}" — inert as stored data, but forges a role turn once templated into the ${model ?? "target"} model prompt.`,
        weight: 1,
        evidence: tok,
        hard: true,
      });
    }
  }
  const m = ROLE_HEADER.exec(text);
  if (m) {
    out.push({
      layer: "differential",
      code: "ROLE_HEADER_INJECT",
      detail: `Mimics a role header ("${m[0].trim()}") — reads as a new conversation turn once inside the chat context, not as data.`,
      weight: 0.8,
      evidence: m[0].trim(),
    });
  }
  return out;
}
