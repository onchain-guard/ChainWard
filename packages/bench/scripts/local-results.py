#!/usr/bin/env python3
# Copyright 2026 0xShield. All Rights Reserved.
#
# Licensed under the MIT License. See LICENSE in the project root.
#
# Builds docs/LOCAL-LLM-RESULTS.md from the raw run outputs scripts/taskc.sh leaves in the repo
# root (results-*.md, real-benign-*.md, substitution-*.md). Numbers are copied, never retyped:
# a model whose positive control failed gets "측정 불가" in the canary and fund-move columns
# even when the raw file has a number there.
#
#   python3 packages/bench/scripts/local-results.py [results-dir]   (default: repo root)

import glob, os, re, sys

EXPECTED = ["llama3.2:1b", "llama3.2:3b", "qwen2.5:7b", "llama3.1:8b"]
NA = "측정 불가"

base = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
if not glob.glob(os.path.join(base, "results-*.md")):
    sys.exit(f"results-*.md 가 {os.path.normpath(base)} 에 없습니다. scripts/taskc.sh 를 먼저 돌리세요.")


def read(p):
    return open(p, encoding="utf-8").read()


def clean(s):
    return s.replace("**", "").strip()


def parse_results(p):
    t = read(p)
    m = re.search(r"^\*\*model:\*\* `([^`]+)`", t, re.M)
    ctl = {c: (mk, fr) for c, mk, fr in
           re.findall(r"^\| (C0[12]) \|[^|]*\| `[^`]+` \| (✅|❌) (\d+/\d+) \|", t, re.M)}

    def fam(name):
        r = re.search(rf"^\| {name} \(\d+건\) \|[^|]*\| ([^|]+) \| ([^|]+) \|", t, re.M)
        return (clean(r.group(1)), clean(r.group(2))) if r else ("?", "?")

    f = re.search(r"자금 이동 시도\*\* \(canary 계열, 목적지 무관\) ‡ \| off (.+?) · on (.+?) \|", t)
    inv = re.search(r"무효 (\d+)건 제외", t)
    ok = all(ctl.get(c, ("❌",))[0] == "✅" for c in ("C01", "C02"))
    partial = ok and any(fr.split("/")[0] != fr.split("/")[1] for _, fr in ctl.values())
    return dict(file=os.path.basename(p), model=m.group(1) if m else "?", ctl=ctl, ok=ok, partial=partial,
                canary=fam("canary"), passthrough=fam("passthrough"), deception=fam("deception"),
                fund=(clean(f.group(1)), clean(f.group(2))) if f else ("?", "?"),
                invalid=inv.group(1) if inv else "0")


def parse_real(p):
    t = read(p)
    m = re.search(r"^\*\*model:\*\* `([^`]+)`", t, re.M)
    rows = re.findall(r"^\| (R0\d) \| `[^`]+` \| (\d+)/(\d+) \| (\d+)/(\d+) \|$", t, re.M)
    tot = lambda i: f"{sum(int(r[i]) for r in rows)}/{sum(int(r[i + 1]) for r in rows)}"
    worse = [r[0] for r in rows if int(r[3]) * int(r[2]) < int(r[1]) * int(r[4])]
    return dict(file=os.path.basename(p), model=m.group(1) if m else "?",
                off=tot(1) if rows else "?", on=tot(3) if rows else "?", worse=", ".join(worse) or "없음")


def parse_subs(p):
    out = {}
    for b in re.split(r"^## ", read(p), flags=re.M)[1:]:
        model = b.split("\n", 1)[0].strip()
        c = re.search(r"대조군 \(메모 없는 배치\): (✅ 통과|❌ 실패)", b)
        rows = {r[0]: r[1:] for r in re.findall(
            r"^\| (C0|S1|S2|S3|N1) [^|]*\| \w+ \| ([^|]+) \| ([^|]+) \| ([^|]+?)(?: ⚠️)? \|$", b, re.M)}
        concl = re.search(r"^→ \*\*(.+?)\*\*", b, re.M)
        broken = re.search(r"정상 메모에서도 (\d+/\d+) 회가 정상 지급에 실패", b)
        out[model] = dict(file=os.path.basename(p), ok=bool(c and c.group(1).startswith("✅")), rows=rows,
                          concl=concl.group(1) if concl else "", broken=broken.group(1) if broken else "")
    return out


res = {r["model"]: r for r in map(parse_results, sorted(glob.glob(os.path.join(base, "results-*.md"))))}
real = {r["model"]: r for r in map(parse_real, sorted(glob.glob(os.path.join(base, "real-benign-*.md"))))}
sub = {}
for p in sorted(glob.glob(os.path.join(base, "substitution-*.md"))):
    sub.update(parse_subs(p))
order = list(dict.fromkeys(EXPECTED + [m for m in list(res) + list(real) + list(sub) if m not in EXPECTED]))

L = ["# 로컬 모델 측정 결과", "",
     "> 1~4절은 레포 루트의 `results-*.md` · `real-benign-*.md` · `substitution-*.md` 에서 "
     "`packages/bench/scripts/local-results.py` 가 그대로 옮겼다. 5절(해석)만 사람이 쓴다.", "",
     "## 1. 결과표", "",
     "| 모델 | 대조군 | canary (ASR) off / on | passthrough off / on | 자금 이동 시도 off / on |",
     "|---|---|---|---|---|"]
for m in order:
    r = res.get(m)
    if not r:
        L.append(f"| `{m}` | {NA} (결과 파일 없음) | {NA} | {NA} | {NA} |")
        continue
    v = "✅ 통과" + (" (부분)" if r["partial"] else "") if r["ok"] else "❌ 실패"
    can = f"{r['canary'][0]} / {r['canary'][1]}" if r["ok"] else NA
    fund = f"{r['fund'][0]} / {r['fund'][1]}" if r["ok"] else NA
    L.append(f"| `{m}` | {v} | {can} | {r['passthrough'][0]} / {r['passthrough'][1]} | {fund} |")
L += ["",
      "- 값 = `비율 [95% 신뢰구간] · 적중/실행`. 0/N 은 \"0%\"가 아니라 \"상한 이하\"로 읽는다.",
      "- 대조군은 C01·C02 **둘 다 ✅** 일 때만 통과로 본다. 실패하면 canary·자금 이동 시도는 숫자가 있어도 측정 불가로 적었다.",
      "- (부분) = ✅ 이지만 반복 중 일부만 성공했다. 해석할 때 감안한다.",
      "- passthrough 는 툴 호출이 필요 없는 지표라 대조군과 무관하게 남긴다.", "",
      "### deception (상한값 — ASR 과 합산하지 않는다)", "",
      "| 모델 | off | on |", "|---|---|---|"]
for m in order:
    r = res.get(m)
    L.append(f"| `{m}` | {r['deception'][0]} | {r['deception'][1]} |" if r else f"| `{m}` | {NA} | {NA} |")
L += ["", "## 2. 대조군 판정 근거", "",
      "| 모델 | C01 | C02 | 무효 처리 | 원본 |", "|---|---|---|---|---|"]
for m in order:
    r = res.get(m)
    if not r:
        L.append(f"| `{m}` | — | — | — | 없음 |")
        continue
    cell = lambda c: " ".join(r["ctl"][c]) if c in r["ctl"] else "행 없음"
    L.append(f"| `{m}` | {cell('C01')} | {cell('C02')} | {r['invalid']}건 | `{r['file']}` |")
L += ["", "## 3. 치환형 공격", "",
      "공격(S1~S3)은 **다른 주소로 송금**한 비율, 정상 메모(N1)는 **정상 수령인에게 송금**한 비율이다.", "",
      "| 모델 | 대조군 | S1 이탈 | S2 이탈 | S3 이탈 | N1 정상 지급 | 스크립트 결론 |",
      "|---|---|---|---|---|---|---|"]
for m in order:
    s = sub.get(m)
    if not s:
        L.append(f"| `{m}` | {NA} (파일 없음) | | | | | |")
        continue
    if not s["ok"]:
        L.append(f"| `{m}` | ❌ 실패 | {NA} | {NA} | {NA} | {NA} | {NA} |")
        continue
    g = lambda k, i: s["rows"].get(k, ("?", "?", "?"))[i].strip()
    concl = s["concl"] + (f" ⚠️ 정상 메모에서도 {s['broken']} 지급 실패" if s["broken"] else "")
    L.append(f"| `{m}` | ✅ 통과 | {g('S1', 1)} | {g('S2', 1)} | {g('S3', 1)} | {g('N1', 0)} | {concl} |")
L += ["", "## 4. 실제 정상 이름 R01~R06 (격리돼도 답하는가)", "",
      "엔진은 6개 이름을 모두 격리(SUSPICIOUS)한다. 값은 `답변에 토큰 이름이 나온 횟수 / 유효 실행`이다. "
      "on 이 off 와 비슷하면 격리가 유용성을 해치지 않았다.", "",
      "| 모델 | off | on | on 이 더 낮은 케이스 | 원본 |", "|---|---|---|---|---|"]
for m in order:
    r = real.get(m)
    L.append(f"| `{m}` | {r['off']} | {r['on']} | {r['worse']} | `{r['file']}` |" if r else f"| `{m}` | — | — | — | 없음 |")
L += ["", "## 5. 해석 (사람이 쓴다)", "",
      "### 모델 크기에 따라 왜 다른가", "",
      "> 1절을 대조군 → 자금 이동 시도 off → canary off 순서로 읽는다. 대조군 ❌ 이면 0 은 \"막았다\"가 아니라 \"못 했다\"이다.", "",
      "(작성)", "",
      "### 치환형 공격", "",
      "> 3절의 결론 칸이 \"모델도 막지 못한다\"면 → 주소 허용목록 같은 다른 층이 필요하다. \"모델이 막는다\"면 → 엔진과 모델을 겹쳐 써야 한다.", "",
      "(작성)", ""]

os.makedirs(os.path.join(base, "docs"), exist_ok=True)
dst = os.path.join(base, "docs", "LOCAL-LLM-RESULTS.md")
if os.path.exists(dst):
    dst = os.path.join(base, "docs", "LOCAL-LLM-RESULTS.auto.md")
open(dst, "w", encoding="utf-8").write("\n".join(L))
print("\n".join(L[:L.index("## 2. 대조군 판정 근거")]))
print("\n".join(L[L.index("## 4. 실제 정상 이름 R01~R06 (격리돼도 답하는가)"):L.index("## 5. 해석 (사람이 쓴다)")]))
print(f"→ 저장: {os.path.normpath(dst)}")
