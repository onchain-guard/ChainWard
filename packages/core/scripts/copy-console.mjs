// Put the console page inside the package so it ships to npm.
//
// The file lives at the repository root because that is where it is worked on — the design
// of the console is its own track, and moving it under the package would break every branch
// that touches it. Publishing needs a copy inside the package boundary regardless: `files`
// cannot reach above the package directory, so a path like "../../dashboard.html" is simply
// dropped from the tarball, silently, and the bin then serves nothing.

import { copyFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = dirname(dirname(fileURLToPath(import.meta.url)));
const src = join(pkg, "..", "..", "dashboard.html");
const dest = join(pkg, "console.html");

if (!existsSync(src)) {
  console.error(`copy-console: ${src} is missing — the bin will run without a console.`);
  process.exit(0); // not fatal: the proxy is the product, the console is a view of it
}

copyFileSync(src, dest);
console.log(`copy-console: dashboard.html → packages/core/console.html`);
