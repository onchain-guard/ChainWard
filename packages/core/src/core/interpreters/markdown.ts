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
      // A parameterless image URL carries nothing about the viewer — the host learns only
      // that someone rendered it, which is true of every image on the web. The exfiltration
      // case is the branch above, where query params carry the payload.
      //
      // Weight kept BELOW the SUSPICIOUS threshold (0.4) on purpose. At 0.5 this fired alone
      // and fenced the whole field, which over-triggers on the single most common thing in
      // real NFT metadata: an IPFS or Arweave thumbnail. A rule that flags the overwhelmingly
      // legitimate case is over-broad by this project's own standard, and the harm
      // passthrough measures is an ACTIVE construct surviving — a working thumbnail is the
      // NFT behaving correctly, not harm.
      //
      // It still contributes through the noisy-OR, so an auto-fetch image alongside anything
      // else (injection intent, an address, a role header) still reaches a verdict. The
      // signal is reported either way; what changed is that it no longer convicts on its own.
      out.push({ layer: "differential", code: "AUTO_FETCH_IMAGE",
        detail: "Markdown image auto-fetches an external URL on render (SSRF/tracking surface). " +
          "No query params, so nothing about the viewer is carried — reported, not convicting on its own.",
        weight: 0.3, evidence: url.slice(0, 60) });
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
