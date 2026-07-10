#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${1:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${2:-/etc/aegis}"
STATE_DIR="${3:-/var/lib/aegis}"
SERVICE_NAME="aegis-agent.service"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" /var/log/aegis
cp -a . "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
if [[ ! -f "$CONFIG_DIR/agent.yaml" ]]; then
  cp "$INSTALL_DIR/config/agent_execute_example.yaml" "$CONFIG_DIR/agent.yaml"
  sed -i "s#audit_db: data/audit.db#audit_db: $STATE_DIR/audit.db#g" "$CONFIG_DIR/agent.yaml"
  sed -i "s#state_dir: data/state#state_dir: $STATE_DIR/state#g" "$CONFIG_DIR/agent.yaml"
  sed -i "s#quarantine_dir: data/quarantine#quarantine_dir: $STATE_DIR/quarantine#g" "$CONFIG_DIR/agent.yaml"
  sed -i "s#persistence_backup_dir: data/persistence_backup#persistence_backup_dir: $STATE_DIR/persistence_backup#g" "$CONFIG_DIR/agent.yaml"
fi
cp "$INSTALL_DIR/deploy/$SERVICE_NAME" "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "Installed $SERVICE_NAME. Review $CONFIG_DIR/agent.yaml, then run: systemctl start $SERVICE_NAME"
