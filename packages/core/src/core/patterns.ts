// LAYER 2a — Injection-intent pattern pack (fast, explainable, low-FP on obvious cases).
//
// Run AGAINST THE NORMALIZED TEXT (after Layer 1 folds homoglyphs / strips invisibles),
// so "ѕystem:" and "ｓystem:" are caught here too. Brittle to paraphrase on its own —
// that's what the classifier (Layer 2b) is for. Together they cover the space.

import type { Signal } from "./types.ts";
import { findForgedRoleHeader } from "./roles.ts";

interface Rule {
  code: string;
  re: RegExp;
  weight: number;
  detail: string;
  /** requires an address / crypto-primitive nearby to fire hard */
  needsAddress?: boolean;
}

const ADDRESS_RE = /0x[a-fA-F0-9]{40}\b/;

const RULES: Rule[] = [
  {
    code: "INSTRUCTION_OVERRIDE",
    re: /\b(ignore|disregard|forget|override|bypass)\b[\s\S]{0,25}\b(previous|prior|above|earlier|all|the)\b[\s\S]{0,15}\b(instruction|rule|prompt|message|context|direction)/i,
    weight: 0.85,
    detail: "Tells the reader to ignore prior instructions — classic prompt-injection opener.",
  },
  {
    // The `role:` form is handled separately (see roles.ts) — a bare colon also matches
    // ordinary metadata credit lines, so it needs turn-shaped content to count.
    code: "ROLE_HIJACK",
    re: /<\/?(system|assistant)>|\[(system|assistant|instructions?)\b|\byou are (now|a|an)\b/i,
    weight: 0.8,
    detail: "Impersonates a system/assistant turn or reassigns the model's role.",
  },
  {
    code: "FAKE_AUTHORITY",
    re: /\b(admin|root|elevated|executive|god)\s*(mode|access|terminal|privileges?)\b|\bnew session\b|\[new session\]|developer mode/i,
    weight: 0.7,
    detail: "Fabricates elevated authority / a fake session boundary.",
  },
  {
    code: "CRYPTO_ACTION_DIRECTIVE",
    re: /\b(send|transfer|approve|withdraw|drain|swap|bridge|sign)\b[\s\S]{0,50}(0x[a-fA-F0-9]{40}|to (my|this|the following) (wallet|address)|all (funds|tokens|balance))/i,
    weight: 0.9,
    detail: "Directs a value-moving action toward an attacker-chosen destination.",
    needsAddress: false,
  },
  {
    // A `## Status` heading is ordinary project prose; the template's teeth are the forged
    // VERDICT under it ("Status: VERIFIED"). Require the resolution framing or the verdict,
    // never a bare status heading.
    code: "RESOLUTION_TEMPLATE",
    re: /(^|\n)\s{0,3}#{1,6}\s*(?:transaction\s+)?resolution\b|\b(?:status|verdict|review|security (?:note|audit))\s*[:：]\s*(?:verified|approved|resolved|cleared|passed|completed?|safe)\b/i,
    weight: 0.55,
    detail: "Mimics a trusted resolution report and asserts a favorable verdict in attacker-written text.",
  },
  {
    code: "SAFETY_CLAIM_IMPERATIVE",
    re: /\b(this (token|contract|collection|wallet) is (verified|safe|audited|trusted|official))\b/i,
    weight: 0.55,
    detail: "Asserts its own safety in prose — cross-check against real contract behavior (Layer 3).",
  },
  {
    code: "APPROVAL_LURE",
    re: /\b(approve|grant|allowance|claim)\b[\s\S]{0,40}\b(airdrop|reward|unlimited|max|to claim)\b/i,
    weight: 0.65,
    detail: "Lures the agent into an approval — the approve-then-drain primitive.",
  },
];

export function analyzePatterns(normalized: string): Signal[] {
  const signals: Signal[] = [];
  const hasAddress = ADDRESS_RE.test(normalized);

  for (const rule of RULES) {
    const m = rule.re.exec(normalized);
    if (!m) continue;
    let weight = rule.weight;
    // a directive that actually carries an address is materially worse
    if (rule.code === "CRYPTO_ACTION_DIRECTIVE" && hasAddress) weight = Math.min(1, weight + 0.1);
    signals.push({
      layer: "pattern",
      code: rule.code,
      detail: rule.detail,
      weight,
      evidence: m[0].slice(0, 80),
    });
  }

  const role = findForgedRoleHeader(normalized);
  if (role) {
    signals.push({
      layer: "pattern",
      code: "ROLE_HIJACK",
      detail: `Opens a forged "${role.role}" turn — a role header followed by a sentence aimed at the model, not a metadata label.`,
      weight: 0.8,
      evidence: role.evidence,
    });
  }

  if (hasAddress) {
    signals.push({
      layer: "pattern",
      code: "ADDRESS_PRESENT",
      detail: "Contains a raw 0x address — context signal; strong when paired with an action directive.",
      weight: 0.25,
      evidence: ADDRESS_RE.exec(normalized)?.[0],
    });
  }

  return signals;
}
