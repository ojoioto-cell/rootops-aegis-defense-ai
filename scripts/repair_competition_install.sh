#!/usr/bin/env bash
set -euo pipefail

# Repairs an existing Aegis competition install when systemd exits with
# status=226/NAMESPACE or scripts cannot import aegis_agent.
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[Aegis][ERROR] Run as root: sudo $0" >&2
  exit 1
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
  echo "[Aegis][ERROR] Install dir not found: $INSTALL_DIR" >&2
  exit 1
fi

echo "[Aegis] Installing package into venv for module discovery"
if [[ -x "$INSTALL_DIR/.venv/bin/pip" ]]; then
  if ! "$INSTALL_DIR/.venv/bin/pip" install -e "$INSTALL_DIR"; then
    echo "[Aegis][WARN] Editable package install failed; continuing with PYTHONPATH service fallback" >&2
  fi
else
  echo "[Aegis][ERROR] venv pip not found: $INSTALL_DIR/.venv/bin/pip" >&2
  exit 1
fi

echo "[Aegis] Writing namespace-compatible systemd services"
cat > /etc/systemd/system/aegis-agent.service <<'SERVICE'
[Unit]
Description=Aegis Linux Autonomous Defense Agent
Documentation=file:/opt/aegis-linux-defense-agent/docs/OPERATIONS_RUNBOOK.md
After=network-online.target nftables.service auditd.service aegis-central.service
Wants=network-online.target nftables.service auditd.service

[Service]
Type=simple
WorkingDirectory=/opt/aegis-linux-defense-agent
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/aegis-linux-defense-agent
ExecStart=/opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent daemon --config /etc/aegis/agent.yaml --policy /etc/aegis/policy.yaml --enable-enforcement --cleanup-expired
Restart=always
RestartSec=5
User=root
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
SERVICE

cat > /etc/systemd/system/aegis-central.service <<'SERVICE'
[Unit]
Description=Aegis Central Monitoring Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/aegis-linux-defense-agent
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/aegis-linux-defense-agent
Environment=AEGIS_CENTRAL_HOST=0.0.0.0
Environment=AEGIS_CENTRAL_PORT=8088
Environment=AEGIS_CENTRAL_TOKEN=
EnvironmentFile=-/etc/aegis/central.env
ExecStart=/opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_central.server --host ${AEGIS_CENTRAL_HOST} --port ${AEGIS_CENTRAL_PORT} --db /var/lib/aegis/central.db --token ${AEGIS_CENTRAL_TOKEN} --require-read-auth
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

echo "[Aegis] Rewriting status script to set PYTHONPATH"
cat > "$INSTALL_DIR/scripts/aegis_competition_status.sh" <<'STATUS'
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
STATUS
chmod +x "$INSTALL_DIR/scripts/aegis_competition_status.sh"

echo "[Aegis] Reloading and restarting services"

# Approved repair/update: refresh self-protection baseline before restarting.
PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}" "$INSTALL_DIR/.venv/bin/python" -m aegis_agent reset-self-baseline --config /etc/aegis/agent.yaml >/tmp/aegis_repair_reset_self_baseline.json 2>/tmp/aegis_repair_reset_self_baseline.err || \
  echo "[Aegis][WARN] self-protection baseline reset failed: $(cat /tmp/aegis_repair_reset_self_baseline.err 2>/dev/null)" >&2

systemctl daemon-reload
systemctl enable aegis-central.service aegis-agent.service >/dev/null
systemctl restart aegis-central.service
systemctl restart aegis-agent.service
sleep 2
systemctl --no-pager --full status aegis-agent.service aegis-central.service || true

echo "[Aegis] Repair complete. Run: sudo $INSTALL_DIR/scripts/aegis_competition_status.sh"
