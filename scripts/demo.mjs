// `pnpm demo` — run the console against the copy of it in this repository.
//
// The product is `chainward proxy`, and it needs no wrapper: it binds its own default
// ports, prints its own console URL, reports a port collision with the flag that fixes it,
// and stops on Ctrl+C. This script exists for one reason the bin cannot cover.
//
// The console is edited here, at the repository root, and copied into the package at build
// time — `files` cannot reach above the package directory, so a path pointing outside it is
// dropped from the tarball without a word. That copy is what the bin serves. Run the bin
// directly after editing the page and you are served the copy from the last build: your
// change is absent, and nothing on screen distinguishes a stale file from a broken edit.
//
// So: refresh the copy, then hand over to the bin. Everything else this used to do — a port
// probe, a URL banner, a second web server for the page, a teardown handler — either moved
// into the bin or stopped being necessary when the bin started serving the console itself.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;

const cli = join(root, "packages/core/dist/cli.js");
if (!existsSync(cli)) {
  console.error(red("✖ 코어가 빌드되지 않았다.") + "  먼저: " + bold("pnpm -r build"));
  process.exit(1);
}

const copy = spawnSync(process.execPath, [join(root, "packages/core/scripts/copy-console.mjs")], {
  stdio: ["ignore", "ignore", "inherit"],
});
if (copy.status !== 0) {
  console.error(red("✖ 콘솔 페이지를 패키지로 복사하지 못했다."));
  process.exit(1);
}

// `--live` is sugar for the upstream flag, and nothing more. It deliberately does not check
// for an API key: this proxy holds no credentials of its own — it relays whatever the caller
// sent — so demanding a key here would refuse the case the proxy exists for, an agent that
// brings its own.
const argv = process.argv.slice(2);
const args = ["proxy", ...argv.filter((a) => a !== "--live")];
if (argv.includes("--live") && !argv.includes("--upstream")) {
  args.push("--upstream", "https://api.anthropic.com");
}

const run = spawnSync(process.execPath, [cli, ...args], { stdio: "inherit" });
process.exit(run.status ?? 0);
