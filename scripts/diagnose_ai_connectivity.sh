#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
PY="${INSTALL_DIR}/.venv/bin/python"
CONFIG="${1:-${CONFIG_DIR}/agent.yaml}"

log(){ echo "[Aegis][AI-DIAG] $*"; }
warn(){ echo "[Aegis][AI-DIAG][WARN] $*" >&2; }

log "Checking system time and CA certificates"
date -u || true
if command -v timedatectl >/dev/null 2>&1; then timedatectl status || true; fi
if [[ -e /etc/ssl/certs/ca-certificates.crt || -e /etc/pki/tls/certs/ca-bundle.crt ]]; then
  log "CA certificate bundle appears present"
else
  warn "CA certificate bundle not found. Install ca-certificates."
fi

if [[ ! -x "$PY" ]]; then warn "Python venv not found: $PY"; exit 0; fi
export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR" 2>/dev/null || true
log "Running aegis-agent secrets-check"
"$PY" -m aegis_agent secrets-check --config "$CONFIG" || true
log "Running aegis-agent ai-test. If TLS fails, verify NTP time and ca-certificates."
"$PY" -m aegis_agent ai-test --config "$CONFIG" || true
