#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${1:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${2:-/etc/aegis}"
STATE_DIR="${3:-/var/lib/aegis}"
SERVICE_NAME="aegis-central.service"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
cp -a . "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
if [[ ! -f "$CONFIG_DIR/central.env" ]]; then
  cat > "$CONFIG_DIR/central.env" <<ENV
AEGIS_CENTRAL_HOST=127.0.0.1
AEGIS_CENTRAL_PORT=8088
AEGIS_CENTRAL_TOKEN=
ENV
fi
cp "$INSTALL_DIR/deploy/$SERVICE_NAME" "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "Installed $SERVICE_NAME. Review $CONFIG_DIR/central.env, then run: systemctl start $SERVICE_NAME"
