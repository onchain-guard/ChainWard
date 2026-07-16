// L4 interpreter — markdown / browser-render differential.
//
// Stored text is inert. But when a chat UI renders it as markdown, some constructs become
// ACTIVE: images auto-fetch (data-exfil), javascript:/data: URIs execute, raw <script>
// runs. Same bytes, but the RENDERING environment turns them into control. We flag the
// constructs that emerge only under markdown/HTML rendering.

import type { Signal } from "../types.ts";

const LINK_RE = /(!?)\[[^\]]*\]\(([^)\s]+)/g; // ![alt](url  or  [text](url

export function markdownInterpret(text: string): Signal[] {
  const out: Signal[] = [];

  let m: RegExpExecArray | null;
  LINK_RE.lastIndex = 0;
  while ((m = LINK_RE.exec(text))) {
    const isImg = m[1] === "!";
    const url = m[2].trim();
    if (/^(javascript|data|vbscript):/i.test(url)) {
      out.push({ layer: "differential", code: "ACTIVE_URI",
        detail: `Markdown ${isImg ? "image" : "link"} uses a ${url.split(":")[0]}: URI — executes when rendered.`,
        weight: 0.9, evidence: url.slice(0, 60), hard: true });
    } else if (isImg && /^https?:\/\//i.test(url) && /[?&][^=&]+=/.test(url)) {
      out.push({ layer: "differential", code: "IMAGE_EXFIL",
        detail: "Markdown image auto-fetches an external URL carrying query params on render — a data-exfiltration channel.",
        weight: 0.9, evidence: url.slice(0, 60), hard: true });
    } else if (isImg && /^https?:\/\//i.test(url)) {
      out.push({ layer: "differential", code: "AUTO_FETCH_IMAGE",
        detail: "Markdown image auto-fetches an external URL on render (SSRF/tracking surface).",
        weight: 0.5, evidence: url.slice(0, 60) });
    }
  }

  if (/<script\b/i.test(text) || /<iframe\b/i.test(text)) {
    out.push({ layer: "differential", code: "RAW_HTML_EXEC",
      detail: "Contains a raw <script>/<iframe> tag — executes if the data is rendered as HTML.",
      weight: 1, hard: true });
  }
  if (/^\s*---\s*\r?\n/.test(text)) {
    out.push({ layer: "differential", code: "FRONTMATTER_DELIM",
      detail: "Leading '---' opens YAML front-matter in generators that parse it — structural/config, not text.",
      weight: 0.4, evidence: "---" });
  }
  return out;
}
