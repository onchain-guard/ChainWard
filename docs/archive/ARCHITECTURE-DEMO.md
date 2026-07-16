# ChainWard — 데모 아키텍처 (지금 만든 것)

목적: 실아키텍처(→ [ARCHITECTURE-REAL.md](./ARCHITECTURE-REAL.md))의 **각 부품이 실제로 구현 가능함을 증명**하는 축소 실행체. 최종 구현이 아니라, "이렇게 붙이면 실환경 개발로 이어진다"를 돌아가는 코드로 보이는 것.

핵심 원칙: **탐지 엔진은 실물 그대로**, 외부 의존만 *실인터페이스 뒤의 현실적 stand-in*. stand-in은 허무맹랑 모조가 아니라 **실컴포넌트의 충실한 대역**이라 교체가 기계적이다.

---

## 1. 데모가 돌리는 것

두 실행체:

| 실행 | 파일 | 보여주는 것 |
|---|---|---|
| **탐지 데모** | `src/demo/run-demo.ts` (`npm run demo`) | 6개 온체인 필드 스캔 → 판정·신호·정화. before/after 컨텍스트 |
| **에이전트 시뮬** | `src/demo/agent-sim.ts` (`npx tsx src/demo/agent-sim.ts`) | ElizaOS 지갑-어시스턴트 루프 재현: 가드 OFF→하이재킹 vs ON→차단 |
| **MCP 핸드셰이크** | `test/mcp.test.ts` | 실제 stdio JSON-RPC로 initialize/tools/call 왕복 |

에이전트 시뮬 흐름 = 실아키텍처와 동일 배선:
```
user → PROVIDER(read) → [ChainWard guard] → PROMPT → LLM → ACTION(wallet)
```

## 2. stand-in ↔ 실컴포넌트 매핑 (= 가능성 증명표)

**이 표가 요청 #1의 답이다:** 데모 각 부분이 실아키텍처의 어느 부품을 대역하고, 무엇을 증명하는가.

| 실아키텍처 부품 | 데모 stand-in | 왜 충실한 대역인가 (허무맹랑 아님) | 증명하는 것 |
|---|---|---|---|
| **Core 엔진** (C1) | **동일 코드** `src/core/*` | 대역 아님 — 프로덕션과 같은 코드가 데모서 실행 | 탐지·정화 로직이 실제로 동작함 |
| **온체인 데이터소스** (C2, viem RPC) | `MockOnchainDataSource` | `OnchainDataSource` 인터페이스 뒤. `RpcOnchainDataSource` REAL IMPL이 같은 파일에 완성 코드로 있음 | 엔진이 데이터 출처를 모름 → RPC 교체가 인터페이스 1줄 |
| **LLM** (C3, 실모델) | `mockLLM` | **문서화된 실패모드를 모델링**: LLM은 컨텍스트 속 명령을 따르고(Zscaler 4/26 결제, 2503.16248 55% ASR) in-band 안전주장을 신뢰함. 정확히 그걸 재현 | 실모델 붙이면 같은 하이재킹 발생함(리서치가 증명) → 가드 필요성이 실재 |
| **지갑 실행** (wallet, viem write) | `executeWallet` (로그) | 실제 이동 대신 "무슨 tx가 나갈지" 로그. 판정은 동일 | OFF=자금유출/ON=무이동의 인과가 실제 tx로 이어짐 |
| **기만 오라클** (C4, GoPlus) | `MockHoneypotOracle` | GoPlus 응답 스키마 그대로. `GoPlusHoneypotOracle` REAL IMPL 완성 코드 有 | honeypot 신호가 실 API로 교체 가능 |
| **분류기** (C3) | `HeuristicClassifier` | 실제 점수 계산(휴리스틱). `PromptGuardClassifier` REAL IMPL 완성 | 분류 계층이 존재·동작, 모델 교체 mechanical |
| **MCP 서버** (C5) | **실물** `src/mcp/server.ts` | 대역 아님 — 진짜 MCP 프로토콜(stdio JSON-RPC). 실 클라이언트 접속 가능(테스트가 증명) | ElizaOS/Claude가 실제로 붙을 수 있음 |
| **ElizaOS 플러그인** (C6) | `src/elizaos/plugin.ts` 스케치 + agent-sim의 provider→guard 흐름 | provider 감싸기 seam을 코드로 재현. 실 wiring은 REAL WIRING 주석 | 통합 지점이 실재하고 배선법이 확정됨 |

**정리:** 엔진·MCP는 데모=프로덕션(대역 아님). 나머지 4개는 각각 (a) 실인터페이스 뒤에 있고 (b) 완성된 REAL IMPL 코드가 동봉돼 있어 **교체가 증명된다**. LLM/wallet은 "결과가 실제로 이렇게 된다"를 문서화된 근거로 뒷받침.

## 3. mockLLM이 왜 페이크가 아닌가 (제일 민감한 부품)

가장 의심받을 부품. 정직하게:

- mockLLM은 랜덤·하드코딩 답이 아니라 **실 LLM의 문서화된 취약 행동을 규칙으로 인코딩**한다: ① 컨텍스트에 명령형+주소가 있으면 따른다(= 인젝션에 하이재킹), ② in-band "safe/verified" 주장을 믿는다(= honeypot에 속음), ③ ChainWard 경고가 컨텍스트에 있으면 따른다(= 가드 존중).
- ①②는 실측: Zscaler(26개 중 4개 실결제), arXiv 2503.16248(메모리주입 55% ASR), Freysa($47k), Grok/Bankr($150k).
- **교체 경로:** `mockLLM(context)` → `await realModel.chat(prompt)`. 프롬프트 조립·provider·가드는 불변. 실모델이 ①②대로 행동함이 리서치로 확인되므로, 데모의 인과(OFF 하이재킹 / ON 차단)는 실환경서 그대로 성립.

## 4. 실행

```bash
npm run demo                        # 탐지 6케이스
npx tsx src/demo/agent-sim.ts       # 에이전트 OFF vs ON
npm test                            # 엔진 유닛 + MCP 실핸드셰이크
```

agent-sim 결과(증명):
- A 인젝션 토큰: OFF → `TRANSFER → 공격자`(자금유출) / ON → `REFUSE`(차단)
- B 허니팟: OFF → `ADVISE_SAFE`(허니팟 추천) / ON → `REFUSE`
- C 정상 USDC: 양쪽 무경보(FP 없음)

## 5. 데모가 증명 못 하는 것 (정직한 경계)

- **실 LLM 미탑재:** mockLLM은 대역. 실모델의 정확한 ASR·FP는 실측 필요(→ 결과보고서용 미니 벤치마크에서 실모델로 측정 예정).
- **실 온체인 미연결:** mock fixtures 사용. 실 RPC/GoPlus 붙이면 네트워크·레이트리밋 변수 생김(코드는 준비됨).
- **실 ElizaOS 런타임 미기동:** provider seam은 스케치+시뮬로 증명, 실 `@elizaos/core` wiring은 별도 셋업 필요.
- **special-token 계층 미구현:** reader-aware 룰셋(REAL §6)의 chat-template 토큰 탐지는 아직 없음 → 다음 작업.

## 6. 데모 → 실아키텍처 전환 체크리스트

1. `MockOnchainDataSource` → `RpcOnchainDataSource` (viem)  ·  파일에 완성 코드
2. `MockHoneypotOracle` → `GoPlusHoneypotOracle`  ·  완성 코드
3. `HeuristicClassifier` → `PromptGuardClassifier`  ·  완성 코드
4. `mockLLM` → 실모델 호출 (agent-sim만; 프로덕션은 에이전트가 담당)
5. `executeWallet` → viem `writeContract`/signer (에이전트가 담당)
6. `src/elizaos/plugin.ts` REAL WIRING 주석대로 `@elizaos/core`에 배선
7. reader-aware `targetContext` + special-token 계층 추가 (신규)

1~3은 `core/scanner.ts`의 `defaultScanner()` 한 곳 교체. 엔진·CLI·MCP·판정은 불변.
