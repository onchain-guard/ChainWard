# ChainWard — 실제(프로덕션) 아키텍처

실환경에서 실제로 배포·운영될 아키텍처. 데모(→ [ARCHITECTURE-DEMO.md](./ARCHITECTURE-DEMO.md))는 이 문서의 각 부품이 **구현 가능함을 증명**하는 축소판이다.

---

## 1. 문제 (한 줄)

자율 AI 에이전트는 온체인 data(토큰명·NFT 메타·memo·컨트랙트 텍스트)를 읽어 판단하고 지갑을 굴린다. 그 data는 공격자가 심을 수 있는 자유 텍스트다. `system prompt + 신뢰불가 data`가 한 토큰 스트림으로 합쳐지면 — SQL 문자열 concat과 같은 구조 — **data가 명령으로 재해석**되어 에이전트가 하이재킹된다. ChainWard는 data가 모델에 닿기 전 그 지점에 끼어들어 스캔·정화한다.

## 2. 전체 데이터 흐름

```
                                  ┌───────────────── ChainWard (이 프로젝트) ─────────────────┐
 on-chain / 외부 소스              │                                                          │
 (토큰명, NFT tokenURI,   ──read──▶│  ┌─ Layer1 구조이상 ─┐                                    │
  memo, 컨트랙트 소스)             │  │  Layer2 패턴/분류기 │──▶ 판정(CLEAN/SUSP/MAL) ──▶ 정화 │
        ▲                         │  └─ Layer3 기만검증 ──┘        │            │             │
        │ Provider가 읽음          │        (GoPlus 등 외부 오라클)  │            │             │
        │                         └────────────────────────────────┼────────────┼────────────┘
   ┌────┴──────────────────────────┐                                │            │
   │ AI 에이전트 (ElizaOS 등)       │◀── sanitized text + verdict ───┘            │
   │  Provider → Prompt → LLM →     │                                             │
   │  Action → Wallet              │◀── (MALICIOUS면 provider가 차단/경고) ───────┘
   └───────────────────────────────┘
```

핵심: ChainWard는 **에이전트의 `Provider → Prompt` 경계**(data가 모델 컨텍스트로 들어가는 문)에 위치한다.

## 3. 구성요소 (프로덕션 실체)

| # | 컴포넌트 | 실제 기술 | 책임 |
|---|---|---|---|
| C1 | **Core 탐지 엔진** | 이 레포 `src/core/*` (그대로 프로덕션) | 정규화·구조분석·패턴·분류·기만검증·판정·정화 |
| C2 | **온체인 데이터소스** | `viem` RPC (Base·Ethereum), IPFS 게이트웨이(tokenURI), ABI 디코드(memo/calldata) | 토큰 `name()/symbol()`, NFT metadata JSON, tx memo 읽기 |
| C3 | **인젝션 분류기** | Meta **Llama Prompt Guard 2**(오픈웨이트) 또는 fine-tuned DeBERTa, 로컬 추론 | "지시문처럼 읽히나" 확률 |
| C4 | **기만 오라클** | **GoPlus** Token Security API (`api.gopluslabs.io`, 무료) | honeypot·sellable·tax·proxy 행동 |
| C5 | **MCP 서버** | `@modelcontextprotocol/sdk`, stdio/HTTP transport | `scan_onchain_data` 툴을 아무 MCP 클라이언트에 노출 |
| C6 | **ElizaOS 플러그인** | `@elizaos/core` `Plugin`(providers) | 온체인 provider를 감싸 컨텍스트 진입 전 자동 가드 |
| C7 | **reader-aware 룰셋** | 컨텍스트별 패턴 세트 (§6) | data가 흘러가는 소비 환경별로 위험 시퀀스 다르게 탐지 |

C1은 데모와 **동일 코드**. C2·C3·C4는 데모의 mock을 실어댑터로 교체(인터페이스 불변). C5는 데모에 이미 실동작. C6·C7은 프로덕션 확장.

## 4. 두 가지 통합 모드 (에이전트가 ChainWard를 쓰는 법)

MCP 툴은 "AI가 부르기로 결정"해야 실행된다 → 신뢰성 위해 두 모드 제공:

**모드 A — MCP 툴 (framework-agnostic, 느슨한 결합)**
- ChainWard MCP 서버를 에이전트 설정에 등록. 에이전트가 온체인 행동 전 `scan_onchain_data` 호출.
- 장점: Claude Desktop·Cursor·ElizaOS 등 아무 MCP 클라이언트. 단점: 에이전트가 "안 부르면" 안 걸림 → 시스템 프롬프트에 "행동 전 항상 스캔" 규칙 필요.

**모드 B — 네이티브 Provider 래퍼 (in-process, 강한 결합)**
- ElizaOS provider를 `guardProvider()`로 감싸 **data 통로 자체를 자동 통과**. 에이전트 판단 불필요.
- 장점: 우회 불가(모든 온체인 read가 가드 통과). 단점: 프레임워크별 어댑터 필요.

권장: **A를 기본 배포**(범용) + **B를 ElizaOS 고신뢰 옵션**으로.

## 5. 시퀀스 (모드 B, 지갑 어시스턴트)

```
User → Agent:      "이 토큰 0x… 사도 돼?"
Agent → Provider:  fetchToken(0x…)                    [C2 viem RPC]
Provider → Chain:  name()/symbol() 읽음
Provider → ChainWard: scanField(...)                  [C1 엔진 + C3/C4]
ChainWard → Provider: {severity, sanitized, verdict}
Provider → Prompt: sanitized text (+ MALICIOUS면 경고 배너)
Prompt → LLM:      결정                                [실모델]
LLM → Action:      (안전) "악성이다, 접근마" / (정상) 조언
Action → Wallet:   자금 이동 없음                       [C wallet]
```

## 6. reader-aware 룰셋 (Q2 리서치 산물 — 핵심 격상)

같은 필드라도 **어느 소비 환경으로 흘러가나**에 따라 위험 byte가 다르다(parser differential). `scanField(kind, text, {targetContext})`:

| targetContext | 추가 flag 시퀀스 |
|---|---|
| `llm-chat` | chat-template 토큰 `<\|im_start\|>` `[INST]` `<<SYS>>` `### System`, code fence ```` ``` ````, invisible/bidi/homoglyph |
| `markdown-ui` | 이미지 유출 `![](url?leak=)`, `[](javascript:)`, `---` |
| `sql-sink` | `--` `;` `${}` `{{}}` |
| `spreadsheet` | 셀 leader `= + - @` |

이것이 ChainWard를 "키워드 스캐너"에서 **"parser-differential 가드"**로 격상. (현재 엔진은 `llm-chat`의 일부만 — special-token 계층은 미구현, 다음 작업.)

## 7. 위협 모델 / 경계

- **막는 것:** 온체인 텍스트 필드에 심긴 인젝션·기만이 에이전트 판단을 오염시키는 것.
- **못 막는 것(정직):** 적응형 공격자 100%(자연어엔 신뢰경계 없음 — "No Silver Bullet"). ChainWard는 (a) 실측 기법(invisible Unicode·homoglyph·인코딩·template 토큰)엔 거의 완벽, (b) 명백 인젝션은 패턴+분류기, (c) 미탐지분도 정화로 "신뢰불가 data" 격리. **공격자 비용을 크게 올리는 계층**이지 은탄환 아님.
- **선제성:** 오염된 온체인 필드 실손실 사건은 아직 0(§ reachability≠impact). 입증된 인접기법(Zscaler·Bunq·boannews·ElizaOS 2503.16248)에 근거한 예방 계층.

## 8. 배포

- npm 패키지 3종: `chainward-core`(엔진), `chainward-mcp`(서버 bin), `@chainward/eliza-plugin`.
- MCP 서버: `npx chainward-mcp` → 에이전트 설정에 등록. 라이선스 MIT, 의존성 MIT/Apache.
