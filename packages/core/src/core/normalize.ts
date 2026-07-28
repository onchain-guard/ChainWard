// LAYER 1 — Structural anomaly detection (highest reliability, near-zero FP).
//
// Why this layer is strong: legit on-chain labels ("USDC", "Bored Ape #1") do NOT
// contain invisible control chars, tag-block smuggling, bidi overrides, homoglyphs,
// or base64 blobs. Real-world agent-hijack payloads (per Zscaler / CSA / Embrace-the-Red
// research) rely exactly on these tricks. So their mere PRESENCE is high-signal, and we
// don't need to "understand" the text to flag it.
//
// This file is 100% real, dependency-free Unicode analysis.

import type { Signal } from "./types.ts";

export function codepoints(s: string): number[] {
  return Array.from(s, (c) => c.codePointAt(0)!);
}

function hex(cp: number): string {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

// Invisible / control / smuggling ranges. \t(09) \n(0A) \r(0D) are allowed (legit in
// freeform descriptions); everything else in these ranges is suspicious.
const INVISIBLE_RANGES: Array<[number, number, string, boolean]> = [
  // [start, end, code, hard?]  hard = forces MALICIOUS on its own
  [0x00, 0x08, "C0_CONTROL", true],
  [0x0b, 0x0c, "C0_CONTROL", true],
  [0x0e, 0x1f, "C0_CONTROL", true],
  [0x7f, 0x9f, "C1_CONTROL", true],
  [0x00ad, 0x00ad, "SOFT_HYPHEN", false],
  [0x200b, 0x200f, "ZERO_WIDTH", true],
  [0x202a, 0x202e, "BIDI_OVERRIDE", true],
  [0x2060, 0x2064, "INVISIBLE_FORMAT", true],
  [0x2066, 0x2069, "BIDI_ISOLATE", true],
  [0xfe00, 0xfe0f, "VARIATION_SELECTOR", false],
  [0xfeff, 0xfeff, "ZERO_WIDTH_NBSP", true],
  [0xe0000, 0xe007f, "UNICODE_TAG", true], // the classic invisible-instruction smuggling block
  [0xe0100, 0xe01ef, "VARIATION_SELECTOR_SUPP", true],
];

function classifyInvisible(cp: number): { code: string; hard: boolean } | null {
  for (const [lo, hi, code, hard] of INVISIBLE_RANGES) {
    if (cp >= lo && cp <= hi) return { code, hard };
  }
  return null;
}

// --- Emoji exemption ---
//
// The rule above is an empirical prior ("legit labels have no reason to carry invisible
// codepoints"), not something the chain enforces — and emoji break it. A ZWJ sequence is
// how composite emoji are *built*: 👨‍👩‍👧 is three pictographs joined by U+200D, and 🏳️‍🌈
// carries a U+FE0F presentation selector too. Flagging those redacts ordinary token names.
//
// So we exempt these two codepoints when they are doing their actual typographic job —
// a ZWJ *between pictographs*, a lone selector *modifying the character before it* — and
// keep flagging them everywhere else, which is where smuggling lives ("ig<ZWJ>nore").

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;

const isVariationSelector = (cp?: number) => cp !== undefined && cp >= 0xfe00 && cp <= 0xfe0f;
const isPictographic = (cp?: number) => cp !== undefined && PICTOGRAPHIC.test(String.fromCodePoint(cp));

/** Nearest neighbour, stepping over variation selectors (they sit between a pictograph and its ZWJ). */
function neighbour(cps: number[], i: number, step: -1 | 1): number | undefined {
  let j = i + step;
  while (isVariationSelector(cps[j])) j += step;
  return cps[j];
}

/** True when the codepoint at `i` is legitimate emoji composition rather than smuggling. */
export function isEmojiJoiner(cps: number[], i: number): boolean {
  const cp = cps[i];
  if (cp === 0x200d) {
    return isPictographic(neighbour(cps, i, -1)) && isPictographic(neighbour(cps, i, 1));
  }
  if (isVariationSelector(cp)) {
    // a selector modifies the single character before it; a RUN of them is a data channel
    if (isVariationSelector(cps[i - 1]) || isVariationSelector(cps[i + 1])) return false;
    const prev = cps[i - 1];
    return prev !== undefined && classifyInvisible(prev) === null;
  }
  return false;
}

// --- Script detection for homoglyph / mixed-script confusables ---
type Script = "latin" | "cyrillic" | "greek" | "fullwidth" | "other";

function scriptOf(cp: number): Script {
  if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) || (cp >= 0xc0 && cp <= 0x24f)) return "latin";
  if (cp >= 0x400 && cp <= 0x4ff) return "cyrillic";
  if (cp >= 0x370 && cp <= 0x3ff) return "greek";
  if (cp >= 0xff01 && cp <= 0xff5e) return "fullwidth";
  return "other";
}

// Minimal confusables map (Cyrillic/Greek/fullwidth -> canonical ASCII). A production
// build loads Unicode's confusables.txt; this hand-picked set covers the common attacks.
const CONFUSABLE: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", ѕ: "s", х: "x", і: "i", ԁ: "d", ɡ: "g",
  у: "y", к: "k", м: "m", н: "h", т: "t", в: "b", А: "A", Е: "E", О: "O", Р: "P",
  С: "C", Х: "X", І: "I", Ѕ: "S", Κ: "K", Μ: "M", Ν: "N", Ο: "O", Ρ: "P", Τ: "T",
};

function foldConfusables(s: string): string {
  let out = "";
  for (const ch of s) {
    if (CONFUSABLE[ch]) out += CONFUSABLE[ch];
    else if (ch.codePointAt(0)! >= 0xff01 && ch.codePointAt(0)! <= 0xff5e) {
      out += String.fromCodePoint(ch.codePointAt(0)! - 0xfee0); // fullwidth -> ASCII
    } else out += ch;
  }
  return out;
}

// --- Encoding smuggling: base64 / long-hex blobs that decode to readable text ---
function printableRatio(s: string): number {
  if (!s.length) return 0;
  let ok = 0;
  for (const cp of codepoints(s)) if (cp === 0x09 || cp === 0x0a || (cp >= 0x20 && cp <= 0x7e)) ok++;
  return ok / s.length;
}

function findEncodedBlobs(text: string): Array<{ type: string; raw: string; decoded: string }> {
  const out: Array<{ type: string; raw: string; decoded: string }> = [];
  // base64-ish runs
  for (const m of text.matchAll(/[A-Za-z0-9+/]{20,}={0,2}/g)) {
    try {
      const decoded = Buffer.from(m[0], "base64").toString("utf8");
      if (decoded.length >= 6 && printableRatio(decoded) > 0.85 && /[a-zA-Z]{3,}/.test(decoded)) {
        out.push({ type: "BASE64", raw: m[0], decoded });
      }
    } catch { /* not valid base64 */ }
  }
  // long hex runs that aren't a bare 40-hex address (address handled by the pattern layer)
  for (const m of text.matchAll(/(?:0x)?[0-9a-fA-F]{24,}/g)) {
    const bare = m[0].replace(/^0x/, "");
    if (bare.length === 40 || bare.length % 2 !== 0) continue;
    try {
      const decoded = Buffer.from(bare, "hex").toString("utf8");
      if (printableRatio(decoded) > 0.9 && /[a-zA-Z]{3,}/.test(decoded)) {
        out.push({ type: "HEX", raw: m[0], decoded });
      }
    } catch { /* ignore */ }
  }
  return out;
}

/** Run all structural checks. Returns raw Signals (no verdict yet). */
export function analyzeStructure(text: string): Signal[] {
  const signals: Signal[] = [];

  // 1) invisible / control / smuggling codepoints
  const seenInvisible = new Map<string, { count: number; hard: boolean; sample: number }>();
  const cps = codepoints(text);
  for (let i = 0; i < cps.length; i++) {
    const cls = classifyInvisible(cps[i]);
    if (cls && !isEmojiJoiner(cps, i)) {
      const rec = seenInvisible.get(cls.code) ?? { count: 0, hard: cls.hard, sample: cps[i] };
      rec.count++;
      seenInvisible.set(cls.code, rec);
    }
  }
  for (const [code, rec] of seenInvisible) {
    signals.push({
      layer: "structural",
      code: `INVISIBLE_${code}`,
      detail: `${rec.count} hidden ${code} char(s) (${hex(rec.sample)}) — legit labels never contain these; used to smuggle instructions past humans.`,
      weight: rec.hard ? 1.0 : 0.5,
      evidence: hex(rec.sample),
      hard: rec.hard,
    });
  }

  // 2) mixed-script / homoglyph
  const scripts = new Set<Script>();
  let hasConfusable = false;
  for (const ch of text) {
    const s = scriptOf(ch.codePointAt(0)!);
    if (s !== "other") scripts.add(s);
    if (CONFUSABLE[ch]) hasConfusable = true;
  }
  const alphaScripts = [...scripts].filter((s) => s === "latin" || s === "cyrillic" || s === "greek");
  if (alphaScripts.length > 1) {
    signals.push({
      layer: "structural",
      code: "MIXED_SCRIPT",
      detail: `Mixes scripts [${alphaScripts.join(", ")}] — homoglyph impersonation (e.g. Cyrillic 'а' inside a Latin word).`,
      weight: 0.7,
      evidence: alphaScripts.join("+"),
    });
  } else if (hasConfusable) {
    signals.push({
      layer: "structural",
      code: "CONFUSABLE_CHAR",
      detail: "Contains confusable look-alike characters folding to ASCII.",
      weight: 0.5,
    });
  }
  if (scripts.has("fullwidth")) {
    signals.push({
      layer: "structural",
      code: "FULLWIDTH_FORMS",
      detail: "Uses fullwidth forms (Ｕｎｉ…) that render like ASCII — evades naive keyword filters.",
      weight: 0.5,
    });
  }

  // 3) encoding smuggling
  for (const blob of findEncodedBlobs(text)) {
    signals.push({
      layer: "structural",
      code: `ENCODED_${blob.type}`,
      detail: `${blob.type} blob decodes to readable text: "${blob.decoded.slice(0, 60)}" — hidden payload.`,
      weight: 0.7,
      evidence: blob.raw.slice(0, 24) + (blob.raw.length > 24 ? "…" : ""),
    });
  }

  return signals;
}

/** Produce a model-safe rendering: strip invisibles, NFKC normalize, fold confusables.
 *  Emoji joiners are kept — stripping them would break 👨‍👩‍👧 into three separate people. */
export function normalizeText(text: string): string {
  const cps = codepoints(text);
  const kept: string[] = [];
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i];
    const drop = cp !== 0x09 && cp !== 0x0a && cp !== 0x0d
      && classifyInvisible(cp) !== null
      && !isEmojiJoiner(cps, i);
    if (!drop) kept.push(String.fromCodePoint(cp));
  }
  return foldConfusables(kept.join("")).normalize("NFKC");
}
