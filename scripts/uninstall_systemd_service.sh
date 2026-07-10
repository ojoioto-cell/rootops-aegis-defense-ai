#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="aegis-agent.service"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
echo "Removed $SERVICE_NAME. Agent files/state were not deleted. Remove /opt/aegis-linux-defense-agent and /var/lib/aegis manually if desired."
