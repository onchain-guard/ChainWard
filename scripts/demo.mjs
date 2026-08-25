// One command to run the console demo, one Ctrl+C to stop it.
//
//   pnpm demo                 guard and report, without calling a model
//   pnpm demo --live          also forward to the real API (needs ANTHROPIC_API_KEY)
//
// This used to also run a static web server, because the console was a file on disk and a
// page opened as file:// is blocked from reaching localhost — it sat on "Connecting…" with
// no error to read. The proxy now serves the console itself, from the same origin as the
// events it reads, so that whole half is gone. What is left is the part a demo still wants:
// check the things that fail confusingly before starting, and take the tree down on exit.

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const live = process.argv.includes("--live");

const PORT = { llm: 8787, events: 8788 };
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
// Refresh the packaged copy of the console from the file people actually edit.
//
// The console is worked on at the repository root and copied into the package at build
// time. Without this line, editing it and running the demo serves the copy from the last
// build — the change is simply absent, with nothing on screen to suggest a stale file
// rather than a broken edit. Whoever is restyling the console would burn an afternoon on
// that before thinking to rebuild. It is one file copy; do it every start.
const copy = spawnSync(process.execPath, [join(root, "packages/core/scripts/copy-console.mjs")], {
  stdio: ["ignore", "ignore", "pipe"],
});
if (copy.status !== 0) {
  console.error(c.red("✖ 콘솔 페이지를 패키지로 복사하지 못했다."));
  console.error(c.dim(String(copy.stderr ?? "")));
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
function readEnvFile(name) {
  const path = join(root, ".env");
  if (!existsSync(path)) return undefined;
  const line = readFileSync(path, "utf8").split(/\r?\n/).find((l) => l.startsWith(`${name}=`));
  return line?.slice(name.length + 1).trim() || undefined;
}
if (live && !(process.env.ANTHROPIC_API_KEY ?? readEnvFile("ANTHROPIC_API_KEY"))) {
  console.error(c.red("✖ --live 에는 ANTHROPIC_API_KEY 가 필요하다.") + "  .env 에 넣거나 export 하라.");
  console.error(c.dim("  (Claude Code 를 태우는 경우에는 불필요하다 — 클라이언트가 자기 자격증명을 보낸다.)"));
  process.exit(1);
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

setTimeout(() => {
  const url = `http://localhost:${PORT.events}/`;
  console.log();
  console.log(c.bold("  ChainWard 콘솔 데모"));
  console.log("  " + "─".repeat(58));
  console.log(`  ${c.bold("콘솔")}          ${c.green(url)}`);
  console.log(`  ${c.dim("LLM 엔드포인트")}  http://localhost:${PORT.llm}`);
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
  console.log(c.dim("  Ctrl+C 로 종료"));
  console.log();
}, 400).unref();

// ---- teardown ---------------------------------------------------------------------

let closing = false;
function shutdown(code = 0) {
  if (closing) return;
  closing = true;
  proxy.kill("SIGTERM");
  setTimeout(() => process.exit(code), 800).unref();
  proxy.once("exit", () => process.exit(code));
}

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => shutdown(0));
process.on("uncaughtException", (e) => {
  console.error(c.red(`✖ ${e.message}`));
  shutdown(1);
});
