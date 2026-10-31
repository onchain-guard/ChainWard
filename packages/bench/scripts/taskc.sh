#!/usr/bin/env bash
# Task C — every local-model measurement in priority order, then the results table.
# Keep the SSH tunnel to the bench desktop open in another terminal first.
#
#   bash packages/bench/scripts/taskc.sh
#
# Order: per required model, the main bench then R01–R06; then substitution on all four
# models; then scripts/local-results.py writes docs/LOCAL-LLM-RESULTS.md. A failed step does
# not stop the run — the table marks what is missing.
set -u
cd "$(dirname "$0")/.."

PROVIDER=${PROVIDER:-ollama}
REQUIRED=${REQUIRED:-"qwen2.5:7b llama3.1:8b"}
ALL=${ALL:-"llama3.2:1b llama3.2:3b qwen2.5:7b llama3.1:8b"}
RUNS=${RUNS:-4}
OUT=${OUT:-../..}

# file-name tags match the ones already used in docs and the Notion page
tag() {
  case "$1" in
    qwen2.5:7b) echo qwen7b ;; llama3.1:8b) echo llama8b ;;
    llama3.2:3b) echo 3b ;; llama3.2:1b) echo 1b ;;
    *) echo "$1" | tr ':.' '--' ;;
  esac
}
step() { echo; echo "=== [$(date +%H:%M)] $* ==="; }
took() { echo "    → 끝 ($(( (SECONDS - $1) / 60 ))분 걸림)"; }

step "1. 사전 점검 — 모델마다 C01·C02 가 둘 다 ✅ 여야 송금 칸을 믿을 수 있다"
for m in $ALL; do
  echo "--- $m"
  npx tsx src/index.ts --provider "$PROVIDER" --models "$m" --runs 1 --cases C01,C02 --concurrency 1 2>&1 \
    | grep -E "^\| C0[12] |does not support|unreachable|ollama [0-9]{3}" || echo "    (결과 없음 — 터널을 확인하세요)"
done

for m in $REQUIRED; do
  t=$(tag "$m")
  step "2. 본 측정 $m → results-$t.md"
  s=$SECONDS
  npx tsx src/index.ts --provider "$PROVIDER" --models "$m" --runs "$RUNS" --concurrency 1 2>&1 | tee "$OUT/results-$t.md"
  took $s

  step "3. 실제 정상 이름 R01~R06 $m → real-benign-$t.md"
  s=$SECONDS
  npx tsx src/index.ts --provider "$PROVIDER" --models "$m" --runs "$RUNS" --concurrency 1 \
    --cases R01,R02,R03,R04,R05,R06 2>&1 | tee "$OUT/real-benign-$t.md"
  took $s
done

for m in $ALL; do
  t=$(tag "$m")
  step "4. 치환형 공격 $m → substitution-$t.md"
  npx tsx src/substitution.ts --provider "$PROVIDER" --models "$m" --runs 3 2>&1 | tee "$OUT/substitution-$t.md"
done

step "5. 결과표"
python3 scripts/local-results.py "$OUT"
