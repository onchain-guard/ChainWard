/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
// `chainward --version` must report the version that was actually installed.
//
// The flag exists so someone holding a working copy can say which build it is — a reviewer
// checking that the package matches a document, a bug report that needs to be reproducible.
// That only works if the number comes from the shipped manifest. A hardcoded constant is one
// forgotten edit away from naming the previous release, and a version that lies is worse
// than no flag at all, because nothing about the output looks wrong.
//
// So the assertion here is not "it prints something version-shaped" — it is "it prints the
// same string package.json holds". The test reads the manifest independently and compares.
//
// The lookup walks up from the module's own directory, because this file runs from two
// depths: `dist/cli.js` in an installed package and `src/proxy/cli.ts` under a dev runner.
// Running it through tsx covers the source path; the published path is covered by the same
// walk finding the same manifest, one level nearer the root.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkgRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(pkgRoot, "src", "proxy", "cli.ts");
const declared = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")).version as string;

const run = (...args: string[]) =>
  execFileSync("npx", ["tsx", cli, ...args], { encoding: "utf8", cwd: pkgRoot });

test("--version prints the version package.json declares", () => {
  assert.equal(run("--version"), `chainward ${declared}\n`);
});

test("-v and `version` are the same flag", () => {
  const expected = `chainward ${declared}\n`;
  assert.equal(run("-v"), expected);
  assert.equal(run("version"), expected);
});

test("the version is never invented when the manifest cannot be read", () => {
  // Not reachable from a published package, but the fallback is the whole reason the lookup
  // is allowed to fail quietly: it must say "unknown", never a plausible-looking number.
  const src = readFileSync(cli, "utf8");
  assert.match(src, /return "unknown";/, "packageVersion must fall back to an honest answer");
  assert.ok(
    !/chainward \d+\.\d+\.\d+/.test(src),
    "a literal version string in the CLI would drift from the manifest",
  );
});

test("--version is discoverable from the help text", () => {
  // A flag nobody is told about is a flag nobody uses; the functional spec points a reviewer
  // at this line.
  assert.match(run("--help"), /--version/);
});

test("adding the flag did not swallow the existing commands", () => {
  assert.match(run("--help"), /chainward proxy/);
  assert.match(run("--help"), /chainward text/);
  assert.match(run("text", "token_name", "USD Coin"), /CLEAN/);
});
