#!/usr/bin/env node
// `chainward` — the bin.

import { createProxy } from "./index.ts";

const USAGE = `chainward — guard the on-chain text an LLM reads

  chainward proxy [options]     run the guarding proxy

Proxy options
  --upstream <url>   forward guarded requests here (e.g. https://api.anthropic.com)
                     omit for dry-run: guard and report without calling a model
  --port <n>         guarded endpoint       (default 8787, env CHAINWARD_PORT)
  --events <n>       event API              (default 8788, env CHAINWARD_EVENTS_PORT,
                                             "off" to disable)
  --quiet            do not log findings to stderr

Point an agent you cannot modify at the proxy and change nothing else:
  chainward proxy --upstream https://api.anthropic.com
  export ANTHROPIC_BASE_URL=http://localhost:8787

Event API, for a dashboard or your own tooling
  GET /events          server-sent events; replays the recent buffer on connect
  GET /events/recent   the buffer as JSON
  GET /health

Library use lives in code, not here:
  import { guard } from "chainward"
`;

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

/** Resolve a port from flag, then env, then default — and reject nonsense early, because
 *  `listen(NaN)` silently binds a random port and the user is then told to connect to a
 *  number that is not the one serving them. */
function port(argv: string[], flagName: string, envName: string, fallback: number): number {
  const raw = flag(argv, flagName) ?? process.env[envName];
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    process.stderr.write(`chainward: ${flagName} expects a port number, got "${raw}"\n`);
    process.exit(2);
  }
  return n;
}

function runProxy(argv: string[]): void {
  const upstream = flag(argv, "--upstream") ?? process.env.CHAINWARD_UPSTREAM;
  const llmPort = port(argv, "--port", "CHAINWARD_PORT", 8787);
  const rawEvents = flag(argv, "--events") ?? process.env.CHAINWARD_EVENTS_PORT;
  const eventPort =
    rawEvents === "off" ? undefined : port(argv, "--events", "CHAINWARD_EVENTS_PORT", 8788);
  const quiet = argv.includes("--quiet");

  const proxy = createProxy({
    port: llmPort,
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

  // A port collision otherwise surfaces as an unhandled 'error' event and a stack trace,
  // which tells the user nothing about the one-flag fix.
  for (const [server, which, n] of [
    [proxy.llm, "--port", llmPort],
    [proxy.events, "--events", eventPort],
  ] as const) {
    server?.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        process.stderr.write(
          `chainward: port ${n} is already in use — rerun with ${which} <other port>\n`,
        );
        process.exit(1);
      }
      throw err;
    });
  }

  // stderr, so piping stdout stays clean for tooling.
  process.stderr.write(
    `chainward proxy   :${llmPort}   ${upstream ? `→ ${upstream}` : "dry-run (no upstream)"}\n`,
  );
  if (eventPort !== undefined) {
    process.stderr.write(`chainward events  :${eventPort}   /events · /events/recent · /health\n`);
  }
}

function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === "-h" || command === "--help" || command === "help") {
    process.stdout.write(USAGE);
    return;
  }
  if (command === "proxy") return runProxy(argv.slice(1));

  process.stderr.write(`chainward: unknown command "${command}"\n\n${USAGE}`);
  process.exit(2);
}

main();
