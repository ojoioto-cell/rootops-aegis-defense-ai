#!/usr/bin/env bash
set -euo pipefail
KEY_PATH="${1:-/etc/aegis/secrets/openai_api_key}"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo $0 ${KEY_PATH}" >&2
  exit 1
fi
install -d -m 700 -o root -g root "$(dirname "${KEY_PATH}")"
if [[ ! -f "${KEY_PATH}" ]]; then
  install -m 600 -o root -g root /dev/null "${KEY_PATH}"
fi
echo "Enter API key. Input will not be echoed."
read -r -s API_KEY
echo
printf "%s" "${API_KEY}" > "${KEY_PATH}"
chmod 600 "${KEY_PATH}"
chown root:root "${KEY_PATH}"
echo "Stored API key at ${KEY_PATH} with mode 600."
