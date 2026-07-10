#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG="${AEGIS_CONFIG:-/etc/aegis/agent.yaml}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
PY="${INSTALL_DIR}/.venv/bin/python"
export PYTHONPATH="${INSTALL_DIR}${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR"
"$PY" -m aegis_agent export-evidence --config "$CONFIG" --central-db "${STATE_DIR}/central.db" --proof-dir "${STATE_DIR}/proof" --output-dir "${STATE_DIR}/final_evidence"
