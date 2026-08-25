// One command to run the console demo, one Ctrl+C to stop it.
//
//   pnpm demo                 guard and report, without calling a model
//   pnpm demo --live          also forward to the real API (needs ANTHROPIC_API_KEY)
//
// Starting this by hand means three terminals, four commands, and two traps that cost real
// time: opening dashboard.html from the file system (the browser blocks a file:// page from
// reaching localhost, and the page sits on "Connecting…"), and forgetting --upstream (the
// proxy answers with a dry-run stub instead of a model). This starts everything, prints the
// one URL that works, and tears the whole tree down on exit.

import { spawn } from "node:child_process";
import { createReadStream, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const live = process.argv.includes("--live");

const PORT = { llm: 8787, events: 8788, page: 8899 };
const c = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
};

// ---- preflight --------------------------------------------------------------------
// Fail before starting anything rather than half-way through, so there is never a stray
// process left listening after a failed run.

const cli = join(root, "packages/core/dist/cli.js");
if (!existsSync(cli)) {
  console.error(c.red("✖ 코어가 빌드되지 않았다.") + "  먼저: " + c.bold("pnpm -r build"));
  process.exit(1);
}

const busy = [];
await Promise.all(
  Object.entries(PORT).map(
    ([name, port]) =>
      new Promise((done) => {
        const probe = createServer();
        probe.once("error", () => {
          busy.push(`${port} (${name})`);
          done();
        });
        probe.once("listening", () => probe.close(() => done()));
        // Bound without a host on purpose. Probing 127.0.0.1 while something else holds the
        // port on 0.0.0.0 succeeds — the two are different sockets — so the check passes and
        // the real listen fails afterwards, leaving half the tree running.
        probe.listen(port);
      }),
  ),
);
if (busy.length) {
  console.error(c.red(`✖ 포트가 이미 사용 중: ${busy.join(", ")}`));
  console.error("  이전 실행이 남아 있을 수 있다: " + c.bold(`pkill -f "chainward proxy"`));
  process.exit(1);
}

// `--live` without a key would start, look healthy, and fail on the first real request.
const key = process.env.ANTHROPIC_API_KEY ?? readEnvFile("ANTHROPIC_API_KEY");
if (live && !key) {
  console.error(c.red("✖ --live 에는 ANTHROPIC_API_KEY 가 필요하다.") + "  .env 에 넣거나 export 하라.");
  process.exit(1);
}

function readEnvFile(name) {
  const path = join(root, ".env");
  if (!existsSync(path)) return undefined;
  const line = readFileSync(path, "utf8").split(/\r?\n/).find((l) => l.startsWith(`${name}=`));
  return line?.slice(name.length + 1).trim() || undefined;
}

// ---- the proxy --------------------------------------------------------------------

const args = ["proxy", "--port", String(PORT.llm), "--events", String(PORT.events)];
if (live) args.push("--upstream", "https://api.anthropic.com");

const proxy = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"] });
proxy.stdout.on("data", (b) => process.stdout.write(c.dim(String(b))));
proxy.stderr.on("data", (b) => process.stdout.write(c.dim(String(b))));
proxy.on("exit", (code) => {
  if (code !== 0 && code !== null) {
    console.error(c.red(`✖ 프록시가 코드 ${code} 로 종료됐다.`));
    shutdown(1);
  }
});

// ---- the page ---------------------------------------------------------------------
//
// Served over HTTP on purpose. The dashboard reaches the event API with EventSource, and a
// page opened as file:// is blocked from doing that — which is the failure this whole script
// exists to make unreachable.

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".json": "application/json" };

const page = createServer((req, res) => {
  const rel = normalize(decodeURIComponent((req.url ?? "/").split("?")[0])).replace(/^(\.\.[/\\])+/, "");
  const file = join(root, rel === "/" || rel === "\\" ? "dashboard.html" : rel);
  if (!file.startsWith(root) || !existsSync(file)) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }
  res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
  createReadStream(file).pipe(res);
});
page.listen(PORT.page, () => {
  const url = `http://localhost:${PORT.page}/`;
  console.log();
  console.log(c.bold("  ChainWard 콘솔 데모"));
  console.log("  " + "─".repeat(58));
  console.log(`  ${c.bold("대시보드")}   ${c.green(url)}`);
  console.log(`  ${c.dim("LLM 엔드포인트")}  http://localhost:${PORT.llm}`);
  console.log(`  ${c.dim("이벤트 API")}      http://localhost:${PORT.events}`);
  console.log();
  if (live) {
    console.log("  " + c.green("실 모델 연결됨.") + " Claude Code 를 태우려면 새 터미널에서:");
    console.log(c.bold(`    export ANTHROPIC_BASE_URL=http://localhost:${PORT.llm} && claude`));
  } else {
    console.log("  " + c.yellow("dry-run") + " — 가드 판정만 보여주고 모델은 부르지 않는다.");
    console.log(c.dim("    실제 응답까지 보려면: pnpm demo --live"));
  }
  console.log();
  console.log(c.dim("  이벤트 하나 흘려보기:"));
  console.log(c.dim(`    curl -X POST http://localhost:${PORT.llm}/v1/messages -H 'content-type: application/json' \\`));
  console.log(c.dim(`      -d '{"model":"claude-sonnet-5","max_tokens":16,"messages":[{"role":"user",`));
  console.log(c.dim(`          "content":"![r](https://collector.invalid/p?w=0x5afe0000000000000000000000000000000000ab)"}]}'`));
  console.log();
  console.log(c.dim("  Ctrl+C 로 전부 종료"));
  console.log();
});

// ---- teardown ---------------------------------------------------------------------
//
// Both children die with the script, on every exit path. A demo that leaves a listener
// behind makes the next run fail on the port check above, which is a confusing way to
// discover that the last one is still running.

let closing = false;
function shutdown(code = 0) {
  if (closing) return;
  closing = true;
  proxy.kill("SIGTERM");
  page.closeAllConnections?.();
  page.close(() => process.exit(code));
  setTimeout(() => process.exit(code), 1500).unref();
}

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => shutdown(0));
process.on("uncaughtException", (e) => {
  console.error(c.red(`✖ ${e.message}`));
  shutdown(1);
});
