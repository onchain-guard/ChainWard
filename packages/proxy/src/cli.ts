#!/usr/bin/env node
// `chainward-proxy` — the bin entry.

import { createProxy } from "./index.ts";

const USAGE = `chainward-proxy — guard on-chain text before it reaches an LLM

  chainward-proxy [options]

Options
  --upstream <url>     forward guarded requests here (e.g. https://api.anthropic.com)
                       omit for dry-run: guards and reports without calling a model
  --port <n>           guarded LLM endpoint          (default 8787)
  --events <n>         read-only event API           (default 8788, "off" to disable)
  --quiet              do not log findings to stderr
  -h, --help

Point your agent at the proxy and change nothing else:
  export ANTHROPIC_BASE_URL=http://localhost:8787
  export OPENAI_BASE_URL=http://localhost:8787/v1

Event API (for a dashboard or your own tooling)
  GET /events          server-sent events, replays the recent buffer on connect
  GET /events/recent   the buffer as JSON
  GET /health
`;

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("-h") || argv.includes("--help")) {
    process.stdout.write(USAGE);
    return;
  }

  const upstream = flag(argv, "--upstream") ?? process.env.CHAINWARD_UPSTREAM;
  const port = Number(flag(argv, "--port") ?? 8787);
  const rawEvents = flag(argv, "--events") ?? "8788";
  const eventPort = rawEvents === "off" ? undefined : Number(rawEvents);
  const quiet = argv.includes("--quiet");

  createProxy({
    port,
    upstream,
    eventPort,
    onEvent: quiet
      ? undefined
      : (e) => {
          if (!e.findings.length) return;
          const codes = [...new Set(e.findings.flatMap((f) => f.codes))].join(", ");
          process.stderr.write(`  ⚠ ${e.findings.length} message(s) guarded — ${codes}\n`);
        },
  });

  // stderr, so piping the proxy's stdout stays clean for tooling.
  process.stderr.write(
    `chainward proxy   :${port}   ${upstream ? `→ ${upstream}` : "dry-run (no upstream)"}\n`,
  );
  if (eventPort !== undefined) {
    process.stderr.write(`chainward events  :${eventPort}   /events · /events/recent · /health\n`);
  }
}

main();
