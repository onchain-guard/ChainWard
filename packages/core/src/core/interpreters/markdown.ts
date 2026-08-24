// L4 interpreter — markdown / browser-render differential.
//
// Every quantifier here is bounded and every class excludes newline. The unbounded
// originals (`[^\]]*`, `[^>]*?`) backtrack quadratically on text an attacker writes: 78KB
// of repeated `"!["` held the event loop for 5.4 seconds. Node runs one thread, so inside
// the proxy that is every other request stalled behind it — and a guard that stalls gets
// removed. 512 bounds a label or an attribute run; URLs keep 2048 so a long data: URI
// still gets read rather than silently skipped.
//
// Stored text is inert. But when a chat UI renders it as markdown, some constructs become
// ACTIVE: images auto-fetch (data-exfil), javascript:/data: URIs execute, raw <script>
// runs. Same bytes, but the RENDERING environment turns them into control. We flag the
// constructs that emerge only under markdown/HTML rendering.
//
// The bypass surface is the whole problem here. An earlier version matched only inline
// `![](…)` / `[](…)` plus `<script>`/`<iframe>`, which left five ways through that a real
// renderer honours: a raw `<img src>`, `srcset`, a raw `<a href="javascript:">`,
// reference-style `![x][ref]`, and an HTML-entity-encoded scheme (`javascript&#58;`). All
// five were verified CLEAN against the engine before this was written. Since passthrough is
// the one family whose harm actually reproduces on a real model, gaps here matter more than
// anywhere else in the engine.

import type { Signal } from "../types.ts";

/** Inline markdown: `![alt](url` or `[text](url`. */
const INLINE_RE = /(!?)\[[^\]\n]{0,512}\]\(([^)\s]{1,2048})/g;
/** Reference usage: `![alt][label]` or `[text][label]`. */
const REF_USE_RE = /(!?)\[[^\]\n]{0,512}\]\[([^\]\n]{1,512})\]/g;
/** Reference definition: a line of `[label]: url`. */
const REF_DEF_RE = /^[ \t]{0,3}\[([^\]\n]{1,512})\]:[ \t]*(\S{1,2048})/gm;
/** Raw HTML attributes that fetch or navigate. `srcset` takes a candidate list. */
const HTML_ATTR_RE = /<\s*(img|a|image)\b[^>\n]{0,512}?\b(src|srcset|href)\s*=\s*["']?([^"'>\s]{1,2048})/gi;

/**
 * Canonicalise a URL enough to test its scheme the way a browser would.
 *
 * Browsers decode HTML entities in attribute values and tolerate whitespace and control
 * characters inside a scheme, so `javascript&#58;`, `java\tscript:` and `JaVaScRiPt:` all
 * execute. Testing the raw string catches only the last of those.
 *
 * Deliberately narrow: this decodes numeric and named entities and strips characters a
 * scheme can never legitimately contain. It is not a general HTML unescaper, because the
 * value is attacker-controlled and a permissive decoder invites its own bypasses.
 */
function forSchemeTest(url: string): string {
  const decoded = url
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCharCode(Number.parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&colon;/gi, ":")
    .replace(/&Tab;|&NewLine;/gi, "");
  // Control characters and whitespace before the colon are ignored by browsers.
  return decoded.replace(/[\s\x00-\x1f]/g, "").toLowerCase();
}

const ACTIVE_SCHEME = /^(javascript|data|vbscript):/;
const HAS_QUERY = /[?&][^=&]+=/;
const IS_HTTP = /^https?:\/\//i;

interface Ref {
  /** true when the construct auto-fetches on render; false when it needs a click */
  fetches: boolean;
  url: string;
  /** how it was written, for the evidence string */
  via: string;
}

function classify(r: Ref, out: Signal[]): void {
  const probe = forSchemeTest(r.url);
  if (ACTIVE_SCHEME.test(probe)) {
    out.push({
      layer: "differential",
      code: "ACTIVE_URI",
      detail:
        `${r.via} uses a ${probe.split(":")[0]}: URI — executes when rendered. ` +
        `Detected after entity/whitespace decoding, which is what a browser does too.`,
      weight: 0.9,
      evidence: r.url.slice(0, 60),
      hard: true,
    });
    return;
  }
  if (!r.fetches || !IS_HTTP.test(r.url)) return;
  if (HAS_QUERY.test(r.url)) {
    out.push({
      layer: "differential",
      code: "IMAGE_EXFIL",
      detail:
        `${r.via} auto-fetches an external URL carrying query params on render — ` +
        `a data-exfiltration channel.`,
      weight: 0.9,
      evidence: r.url.slice(0, 60),
      hard: true,
    });
    return;
  }
  // A parameterless image URL carries nothing about the viewer — the host learns only that
  // someone rendered it, which is true of every image on the web. The exfiltration case is
  // the branch above, where query params carry the payload.
  //
  // Weight kept BELOW the SUSPICIOUS threshold (0.4) on purpose. At 0.5 this fired alone and
  // fenced the whole field, which over-triggers on the single most common thing in real NFT
  // metadata: an IPFS or Arweave thumbnail. A rule that flags the overwhelmingly legitimate
  // case is over-broad by this project's own standard, and the harm passthrough measures is
  // an ACTIVE construct surviving — a working thumbnail is the NFT behaving correctly.
  //
  // It still contributes through the noisy-OR, so an auto-fetch image alongside anything else
  // still reaches a verdict. What changed is that it no longer convicts on its own.
  out.push({
    layer: "differential",
    code: "AUTO_FETCH_IMAGE",
    detail:
      `${r.via} auto-fetches an external URL on render (SSRF/tracking surface). ` +
      `No query params, so nothing about the viewer is carried — reported, not convicting on its own.`,
    weight: 0.3,
    evidence: r.url.slice(0, 60),
  });
}

export function markdownInterpret(text: string): Signal[] {
  const out: Signal[] = [];
  const refs: Ref[] = [];

  // Reference definitions first, so usages can resolve against them.
  const defs = new Map<string, string>();
  REF_DEF_RE.lastIndex = 0;
  let d: RegExpExecArray | null;
  while ((d = REF_DEF_RE.exec(text))) defs.set(d[1].trim().toLowerCase(), d[2].trim());

  INLINE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INLINE_RE.exec(text))) {
    refs.push({ fetches: m[1] === "!", url: m[2].trim(), via: m[1] === "!" ? "Markdown image" : "Markdown link" });
  }

  REF_USE_RE.lastIndex = 0;
  while ((m = REF_USE_RE.exec(text))) {
    const url = defs.get(m[2].trim().toLowerCase());
    if (!url) continue; // a usage with no definition renders as literal text
    refs.push({
      fetches: m[1] === "!",
      url,
      via: `Reference-style markdown ${m[1] === "!" ? "image" : "link"}`,
    });
  }

  HTML_ATTR_RE.lastIndex = 0;
  while ((m = HTML_ATTR_RE.exec(text))) {
    const tag = m[1].toLowerCase();
    const attr = m[2].toLowerCase();
    // srcset is a candidate list — the first URL is enough to establish the fetch.
    const url = m[3].split(",")[0].trim();
    refs.push({
      // An <img> fetches on render whichever URL attribute carries it; an <a href> needs a
      // click, so it only matters when the scheme is active.
      fetches: tag !== "a",
      url,
      via: `Raw HTML <${tag} ${attr}>`,
    });
  }

  for (const r of refs) classify(r, out);

  if (/<script\b/i.test(text) || /<iframe\b/i.test(text)) {
    out.push({
      layer: "differential",
      code: "RAW_HTML_EXEC",
      detail: "Contains a raw <script>/<iframe> tag — executes if the data is rendered as HTML.",
      weight: 1,
      hard: true,
    });
  }
  if (/^\s*---\s*\r?\n/.test(text)) {
    out.push({
      layer: "differential",
      code: "FRONTMATTER_DELIM",
      detail: "Leading '---' opens YAML front-matter in generators that parse it — structural/config, not text.",
      weight: 0.4,
      evidence: "---",
    });
  }
  return out;
}
