#!/usr/bin/env bash
set -euo pipefail

# Aegis Championship Mode: 본선 운영 증거 수집 명령.
# v0.3.1부터 기본 산출물은 실제 incident/action/AI ledger/nftables 기반
# Live Battle Evidence입니다. Synthetic AI Duel Demo는 리허설용으로만 선택 실행합니다.

INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG="${AEGIS_CONFIG:-/etc/aegis/agent.yaml}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
PY="${INSTALL_DIR}/.venv/bin/python"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${STATE_DIR}/championship_${TS}"
MODE="${AEGIS_CHAMPIONSHIP_CHECK_MODE:-live}" # live|full
RUN_SYNTHETIC_DEMO="${AEGIS_RUN_SYNTHETIC_DEMO:-0}"
mkdir -p "$OUT"
chmod 700 "$OUT" 2>/dev/null || true
export PYTHONPATH="${INSTALL_DIR}${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR"

echo "== Aegis Championship Mode v$(cat VERSION 2>/dev/null || echo unknown) =="
echo "mode=${MODE}"
echo "output=${OUT}"
echo "primary_engine=Live Battle Evidence"

if [[ -x "${INSTALL_DIR}/scripts/aegis_all_in_one_check.sh" ]]; then
  if [[ "$MODE" == "full" ]]; then
    AEGIS_RUN_DUEL_DEMO_CHECK=0 AEGIS_RUN_PROOF_CHECK=1 "${INSTALL_DIR}/scripts/aegis_all_in_one_check.sh" | tee "${OUT}/all_in_one_check.log" || true
  else
    AEGIS_RUN_DUEL_DEMO_CHECK=0 AEGIS_RUN_PROOF_CHECK=0 "${INSTALL_DIR}/scripts/aegis_all_in_one_check.sh" | tee "${OUT}/all_in_one_check_fast.log" || true
  fi
fi

"$PY" -m aegis_agent live-battle-evidence --config "$CONFIG" --limit 500 --summary | tee "${OUT}/live_battle_evidence_summary.json" || true
"$PY" -m aegis_agent live-battle-evidence --config "$CONFIG" --limit 500 | tee "${OUT}/live_battle_evidence_full.json" || true
"$PY" -m aegis_agent proof-report --config "$CONFIG" --output-dir "${OUT}/proof" --title "Aegis v$(cat VERSION) Live Battle Evidence Proof Report" | tee "${OUT}/proof_report_result.json" || true
"$PY" -m aegis_agent championship-status --config "$CONFIG" --limit 100 --summary | tee "${OUT}/championship_status.json" || true
"$PY" -m aegis_agent ai-quality --config "$CONFIG" --limit 100 | tee "${OUT}/ai_quality.json" || true

if [[ "$RUN_SYNTHETIC_DEMO" == "1" ]]; then
  echo "== Optional synthetic AI Duel rehearsal =="
  "$PY" -m aegis_agent duel-demo --config "$CONFIG" --output-dir "${OUT}/optional_ai_duel_demo" --execute | tee "${OUT}/optional_ai_duel_demo.json" || true
else
  echo "[Aegis] Optional synthetic AI Duel demo skipped. Set AEGIS_RUN_SYNTHETIC_DEMO=1 to run it."
fi

echo "== Championship artifacts =="
find "$OUT" -maxdepth 3 -type f | sort
