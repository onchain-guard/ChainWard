// The three arguments, run against the real engine. Free, offline, deterministic.
//
//   pnpm --filter @onchain-guard/bench proof
//
// Each argument is a PAIR: an attack and the benign case that must survive it. A guard that
// only shows what it blocks is indistinguishable from a guard that blocks everything, so the
// twin is not decoration — it is half the claim.
//
// Argument 3 is a miss. It is here on purpose: a corpus that reports only its wins has
// chosen its own denominator, and every other number it prints inherits that choice.

import { defaultScanner } from "chainward";
import type { FieldScan } from "chainward";
import { CASES, caseById } from "./cases.ts";
import { reached } from "./report.ts";
import type { AttackCase, BenchCase } from "./types.ts";

const scanner = defaultScanner();

/** Both interpreters apply: the answer lands in a chat UI that renders markdown. */
const TARGET_CONTEXTS = ["llm-chat", "markdown-ui"] as const;

const W = 92;
const rule = (ch = "─") => ch.repeat(W);

/** Truncate for the terminal, but say so — a silently cut payload reads as a short one. */
function clip(s: string, n: number): string {
  const flat = s.replace(/\r?\n/g, "⏎");
  return flat.length <= n ? flat : `${flat.slice(0, n - 1)}…`;
}

function signalLine(scan: FieldScan): string {
  if (!scan.signals.length) return "신호 없음";
  return scan.signals.map((s) => `${s.code}:${s.weight}${s.hard ? "!" : ""}`).join("  ");
}

async function showCase(c: BenchCase): Promise<void> {
  const tag = c.kind === "attack" ? "공격" : "정상";
  console.log(`\n  ${c.id} [${tag}] ${c.title}`);
  console.log(`     chain=${c.chain}  address=${c.address}`);
  console.log(`     유저 질문: "${c.userMsg}"`);

  for (const f of c.fields) {
    const scan = await scanner.scanField(f.kind, f.value, {
      chain: c.chain,
      address: c.address,
      targetContexts: [...TARGET_CONTEXTS],
    });
    const changed = scan.sanitized !== f.value;
    console.log(`\n     ${f.key} (${f.kind})`);
    console.log(`       들어온 값 │ ${clip(f.value, 68)}`);
    console.log(`       판정      │ ${scan.severity}  score=${scan.score}`);
    console.log(`       근거      │ ${signalLine(scan)}`);
    console.log(`       모델에게  │ ${clip(scan.sanitized, 68)}`);
    console.log(`                 │ ${changed ? "↑ 정화됨" : "↑ 원문 그대로 — 손대지 않음"}`);
  }
}

async function argument(n: number, title: string, claim: string, ids: string[]): Promise<void> {
  console.log(`\n${rule("═")}`);
  console.log(`  논증 ${n} — ${title}`);
  console.log(`${rule("═")}`);
  console.log(`\n  ${claim}`);
  for (const id of ids) {
    const c = caseById(id);
    if (!c) throw new Error(`proof: case ${id} is missing from the corpus`);
    await showCase(c);
  }
}

async function main(): Promise<void> {
  console.log(`\n${rule("═")}`);
  console.log("  ChainWard — 세 가지 논증");
  console.log("  모델 불필요 · 네트워크 불필요 · 결정적. 누구나 같은 결과를 얻는다.");
  console.log(rule("═"));

  await argument(
    1,
    "정화는 실제로 일어나고, 거의 똑같이 생긴 정상 데이터는 손대지 않는다",
    "두 케이스 모두 마크다운 이미지를 담은 텍스트다. 차이는 URL에 쿼리 파라미터가 붙었는지 하나뿐이다.\n" +
      "  파라미터 없는 이미지는 호스트가 \"누가 렌더했다\"만 알지만, 파라미터가 붙으면 뷰어의 컨텍스트가 실려 나간다.",
    ["A11", "B11"],
  );

  await argument(
    2,
    "텍스트가 완전히 같다. 갈리는 건 온체인 주소뿐이다",
    "name·symbol·balance가 바이트 단위로 동일하고 유저 질문도 같다. 다른 것은 컨트랙트 주소 하나다.\n" +
      "  텍스트만 읽는 필터는 무슨 짓을 해도 이 둘을 구분할 수 없다 — 거짓은 텍스트의 속성이 아니기 때문이다.\n" +
      "  B01의 주소는 이더리움 메인넷의 진짜 Circle USDC다. Etherscan에서 직접 확인할 수 있다.",
    ["A14", "B01"],
  );

  const gaps = CASES.filter((c): c is AttackCase => c.kind === "attack" && Boolean(c.knownGap));
  await argument(
    3,
    "우리가 못 잡는 것도 공개한다",
    `엔진이 목표 심각도에 도달하지 못하는 케이스가 ${gaps.length}건 있다. 아래는 그중 하나다.\n` +
      "  코퍼스 테스트가 이 미탐이 아직 열려 있음을 assert하므로, 누군가 고치면 테스트가 실패하면서\n" +
      "  문서의 미탐 목록을 갱신하라고 요구한다. 못 잡는 사실이 조용히 낡을 수 없다.",
    ["A07"],
  );

  for (const g of gaps) {
    console.log(`\n     ${g.id} 목표=${g.targetSeverity} · 미탐 사유: ${g.knownGap!.replace(/\s+/g, " ")}`);
  }

  // ---- corpus-wide, so the three arguments are not read as the whole picture ----
  console.log(`\n${rule("═")}`);
  console.log("  코퍼스 전체 (위 세 건은 이 안의 일부다)");
  console.log(rule("═"));

  const attacks = CASES.filter((c): c is AttackCase => c.kind === "attack");
  const benign = CASES.filter((c) => c.kind === "benign");
  let detected = 0;
  let falsePositive = 0;

  for (const c of attacks) {
    let worst: FieldScan["severity"] = "CLEAN";
    for (const f of c.fields) {
      const s = await scanner.scanField(f.kind, f.value, {
        chain: c.chain,
        address: c.address,
        targetContexts: [...TARGET_CONTEXTS],
      });
      if (reached(s.severity, worst)) worst = s.severity;
    }
    if (reached(worst, c.targetSeverity)) detected++;
  }

  for (const c of benign) {
    for (const f of c.fields) {
      const s = await scanner.scanField(f.kind, f.value, {
        chain: c.chain,
        address: c.address,
        targetContexts: [...TARGET_CONTEXTS],
      });
      if (s.severity !== "CLEAN") {
        falsePositive++;
        break;
      }
    }
  }

  console.log(`\n  탐지   ${detected}/${attacks.length}   공격 케이스가 목표 심각도에 도달`);
  console.log(`  오탐   ${falsePositive}/${benign.length}   정상 케이스가 잘못 걸림`);
  console.log(`\n  오탐 줄이 없는 탐지율은 의미가 없다 — 전부 차단하는 가드도 탐지 100%를 기록한다.`);
  console.log(`  두 숫자 모두 모델 없이 재현된다: pnpm --filter @onchain-guard/bench proof\n`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
