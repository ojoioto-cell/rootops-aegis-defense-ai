#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -eq 0 ]]; then
  ./scripts/uninstall_systemd_service.sh || true
  systemctl stop aegis-central.service 2>/dev/null || true
  systemctl disable aegis-central.service 2>/dev/null || true
  rm -f /etc/systemd/system/aegis-central.service
  systemctl daemon-reload || true
fi
echo "Uninstall completed for services. Project files and state are preserved unless manually deleted."
