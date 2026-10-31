/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
// Put the console page inside the package so it ships to npm.
//
// The source lives in `frontend/` because that is where it is worked on — the design of the
// console is its own track, and moving it under the package would break every branch that
// touches it. Publishing needs a copy inside the package boundary regardless: `files` cannot
// reach above the package directory, so a path like "../../frontend/dashboard.html" is simply
// dropped from the tarball, silently, and the bin then serves nothing.
//
// The source keeps its styles in `frontend/css/`, but the copy cannot: the proxy serves the
// console as one page held in memory, not a static directory, so a linked stylesheet would
// be a 404. Each local `<link rel="stylesheet">` is folded back into a `<style>` block here,
// and the shipped page stays a single self-contained file.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = dirname(dirname(fileURLToPath(import.meta.url)));
const frontend = join(pkg, "..", "..", "frontend");
const src = join(frontend, "dashboard.html");
const dest = join(pkg, "console.html");

if (!existsSync(src)) {
  console.error(`copy-console: ${src} is missing — the bin will run without a console.`);
  process.exit(0); // not fatal: the proxy is the product, the console is a view of it
}

const LINK = /^([ \t]*)<link rel="stylesheet" href="([^"]+)">$/gm;
const page = readFileSync(src, "utf8").replace(LINK, (tag, indent, href) => {
  if (/^[a-z]+:|^\/\//i.test(href)) return tag; // remote stylesheet: leave it to the browser
  const css = join(frontend, href);
  if (!existsSync(css)) {
    // Fatal, unlike a missing page: an unstyled console looks broken, not absent.
    console.error(`copy-console: ${css} is linked from dashboard.html but missing.`);
    process.exit(1);
  }
  const body = readFileSync(css, "utf8").trimEnd().replace(/^(?=.)/gm, `${indent}  `);
  return `${indent}<style>\n${body}\n${indent}</style>`;
});

writeFileSync(dest, page);
console.log(`copy-console: frontend/dashboard.html (+ css) → packages/core/console.html`);
