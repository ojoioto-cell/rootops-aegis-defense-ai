#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
  echo "auditctl not found. Install and start auditd first." >&2
  exit 1
fi

# Defensive audit rules for Aegis. These collect execve, suspicious temp/web writes,
# and persistence-path changes. They do not block anything.
auditctl -a always,exit -F arch=b64 -S execve -k aegis_exec || true
auditctl -a always,exit -F arch=b32 -S execve -k aegis_exec || true

auditctl -w /tmp -p wa -k aegis_tmp || true
auditctl -w /dev/shm -p wa -k aegis_shm || true
for p in /var/www /srv/www /etc/cron.d /etc/crontab /var/spool/cron /etc/systemd/system /etc/rc.local; do
  [[ -e "$p" ]] && auditctl -w "$p" -p wa -k aegis_watch || true
done

echo "Aegis auditd rules installed. Verify with: sudo auditctl -l | grep aegis"
