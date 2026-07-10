#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG="${AEGIS_CONFIG:-/etc/aegis/agent.yaml}"

echo "== Aegis services =="
systemctl --no-pager --full status aegis-central.service aegis-agent.service || true

echo
if command -v nft >/dev/null 2>&1; then
  echo "== nftables aegis_guard =="
  nft list ruleset | sed -n '/aegis_guard/,+160p' || true
  echo
  echo "== block_in_v4 =="
  nft list set inet aegis_guard block_in_v4 2>/dev/null || true
  echo
  echo "== rate_limit_v4 =="
  nft list set inet aegis_guard rate_limit_v4 2>/dev/null || true
else
  echo "nft command not found"
fi

echo
if [[ -x "$INSTALL_DIR/.venv/bin/python" ]]; then
  export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
  cd "$INSTALL_DIR"
  echo "== Recent actions =="
  "$INSTALL_DIR/.venv/bin/python" -m aegis_agent actions --config "$CONFIG" --limit 20 || true
  echo
  echo "== Recent incidents =="
  "$INSTALL_DIR/.venv/bin/python" -m aegis_agent incidents --config "$CONFIG" --limit 10 || true
else
  echo "Aegis venv python not found: $INSTALL_DIR/.venv/bin/python"
fi
