// Pack both packages the way `pnpm publish` will, and refuse the release if a tarball would
// break on install.
//
//   node scripts/release-check.mjs
//
// The failure this exists for is not hypothetical. `npm publish` does not substitute
// pnpm's `workspace:*` specifier, so it ships a manifest declaring a dependency npm cannot
// resolve — every consumer install fails. And a core version bumped without bumping the
// adapter leaves the adapter pinned to the previous core, which is how a fixed engine and a
// stale published one ended up under the same version string once already (commit 46cc377).

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const out = mkdtempSync(join(tmpdir(), "chainward-release-"));
const problems = [];

function manifestOf(pkgDir) {
  execFileSync("pnpm", ["pack", "--pack-destination", out], { cwd: join(root, pkgDir), stdio: "pipe" });
  const tgz = readdirSync(out).filter((f) => f.endsWith(".tgz")).map((f) => join(out, f)).pop();
  const raw = execFileSync("tar", ["-xzOf", tgz, "package/package.json"], { encoding: "utf8" });
  return { manifest: JSON.parse(raw), tgz };
}

const core = manifestOf("packages/core");
const eliza = manifestOf("packages/eliza");

console.log(`chainward          ${core.manifest.version}`);
console.log(`@chainwards/eliza  ${eliza.manifest.version}  → chainward ${eliza.manifest.dependencies?.chainward}`);

const pinned = eliza.manifest.dependencies?.chainward;
if (!pinned || pinned.includes("workspace:")) {
  problems.push(`@chainwards/eliza declares "chainward": "${pinned}" — packed with npm instead of pnpm. Every consumer install of this tarball fails.`);
} else if (pinned !== core.manifest.version) {
  problems.push(`@chainwards/eliza pins chainward ${pinned} but core is ${core.manifest.version} — publishing this ships the adapter against a different engine than the one in this tree.`);
}

for (const [name, m] of [["chainward", core.manifest], ["@chainwards/eliza", eliza.manifest]]) {
  if (!m.author) problems.push(`${name} has no author field`);
  if (!m.repository) problems.push(`${name} has no repository field — provenance needs it to match`);
  if (m.private) problems.push(`${name} is marked private and cannot publish`);
}

if (problems.length) {
  console.error(`\n${problems.length} problem(s) — do not publish:\n`);
  for (const p of problems) console.error(`  ✖ ${p}`);
  process.exit(1);
}
console.log("\n✅ 두 tarball 모두 설치 가능한 매니페스트를 담고 있다.");
