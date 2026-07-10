#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
  echo "auditctl not found." >&2
  exit 1
fi

# Best-effort removal. auditctl does not support deleting by key everywhere,
# so this removes the same rules that install_auditd_rules.sh adds.
auditctl -d always,exit -F arch=b64 -S execve -k aegis_exec 2>/dev/null || true
auditctl -d always,exit -F arch=b32 -S execve -k aegis_exec 2>/dev/null || true
auditctl -W /tmp -p wa -k aegis_tmp 2>/dev/null || true
auditctl -W /dev/shm -p wa -k aegis_shm 2>/dev/null || true
for p in /var/www /srv/www /etc/cron.d /etc/crontab /var/spool/cron /etc/systemd/system /etc/rc.local; do
  [[ -e "$p" ]] && auditctl -W "$p" -p wa -k aegis_watch 2>/dev/null || true
done

echo "Aegis auditd rules removed where supported. Verify with: sudo auditctl -l | grep aegis"
