#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi
systemctl stop aegis-agent.service 2>/dev/null || true
nft delete table inet aegis_guard 2>/dev/null || true
echo "Aegis agent stopped and inet aegis_guard removed if it existed."
