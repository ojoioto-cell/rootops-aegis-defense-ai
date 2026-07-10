#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
OUT_DIR="${AEGIS_PROOF_OUTPUT_DIR:-${STATE_DIR}/proof_$(date +%Y%m%d_%H%M%S)}"
PY="${INSTALL_DIR}/.venv/bin/python"

if [[ ! -x "$PY" ]]; then
  echo "[Aegis][ERROR] Python venv not found: $PY" >&2
  exit 1
fi

export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR"
mkdir -p "$OUT_DIR"
"$PY" -m aegis_agent proof-report \
  --config "${CONFIG_DIR}/agent.yaml" \
  --output-dir "$OUT_DIR" \
  --title "Aegis Competition Proof Report"

echo "[Aegis] Proof report generated: $OUT_DIR/proof_report.md"
echo "[Aegis] Proof summary generated: $OUT_DIR/proof_summary.json"
