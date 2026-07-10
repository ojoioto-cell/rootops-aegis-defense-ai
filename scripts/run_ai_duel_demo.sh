#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
OUT_DIR="${AEGIS_DUEL_OUTPUT_DIR:-${STATE_DIR}/ai_duel_demo_$(date +%Y%m%d_%H%M%S)}"
PY="${INSTALL_DIR}/.venv/bin/python"

if [[ ! -x "$PY" ]]; then
  echo "[Aegis][ERROR] Python venv not found: $PY" >&2
  exit 1
fi

export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR"
mkdir -p "$OUT_DIR"

# Safe default: memory backend and synthetic telemetry. It does not run exploit tools.
"$PY" -m aegis_agent duel-demo \
  --config "${CONFIG_DIR}/agent.yaml" \
  --policy "${CONFIG_DIR}/policy.yaml" \
  --output-dir "$OUT_DIR"

echo "[Aegis] AI duel demo complete: $OUT_DIR"
echo "[Aegis] Proof report: $OUT_DIR/reports/proof_report.md"
echo "[Aegis] Proof summary: $OUT_DIR/reports/proof_summary.json"
