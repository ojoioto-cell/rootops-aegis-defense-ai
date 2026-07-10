from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})")
APACHE_TS_RE = re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+(?P<tz>[+-]\d{4})\]")
AUDIT_TS_RE = re.compile(r"audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\)")


def load_yaml(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def now_epoch() -> int:
    return int(time.time())


def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def run_command(cmd: List[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 999, "", str(exc)


def ip_in_allowlist(ip: str, ips: Iterable[str], cidrs: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if ip in set(ips or []):
        return True
    for cidr in cidrs or []:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def parse_syslog_timestamp(line: str, now: float | None = None) -> float:
    """Parse common syslog timestamps without a year. Falls back to current time."""
    m = SYSLOG_TS_RE.search(line or "")
    if not m:
        return now or time.time()
    base = datetime.fromtimestamp(now or time.time())
    candidate = f"{base.year} {m.group('mon')} {int(m.group('day')):02d} {m.group('hms')}"
    try:
        dt = datetime.strptime(candidate, "%Y %b %d %H:%M:%S")
        # Syslog has no year. If parsed date is far in the future, assume previous year.
        if dt.timestamp() - (now or time.time()) > 7 * 86400:
            dt = dt.replace(year=dt.year - 1)
        return dt.timestamp()
    except Exception:
        return now or time.time()


def parse_apache_timestamp(line: str, now: float | None = None) -> float:
    m = APACHE_TS_RE.search(line or "")
    if not m:
        return now or time.time()
    try:
        dt = datetime.strptime(m.group("ts") + " " + m.group("tz"), "%d/%b/%Y:%H:%M:%S %z")
        return dt.timestamp()
    except Exception:
        return now or time.time()


def parse_audit_timestamp(line: str, now: float | None = None) -> tuple[float, str | None]:
    m = AUDIT_TS_RE.search(line or "")
    if not m:
        return now or time.time(), None
    try:
        return float(m.group("epoch")), m.group("serial")
    except Exception:
        return now or time.time(), m.group("serial")


def event_within_window(ts: float, window_minutes: int | None, now: float | None = None) -> bool:
    if not window_minutes or window_minutes <= 0:
        return True
    ref = now or time.time()
    return (ref - ts) <= window_minutes * 60 and ts <= ref + 60


def safe_json_key(path: str) -> str:
    return str(Path(path).resolve())



def validate_enforcement_ip(ip: str | None) -> tuple[bool, str]:
    """Validate that an IP is safe to use as a firewall enforcement target.

    Competition networks may use RFC1918/private ranges, so private addresses are
    allowed. We reject wildcard, unspecified, loopback, multicast, link-local,
    and broadcast addresses because blocking them can create broad service impact
    or indicate a parser error rather than a real attacker/C2 target.
    """
    if not ip:
        return False, "missing_ip_target"
    try:
        obj = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False, f"invalid_ip:{ip}"
    if obj.is_unspecified:
        return False, f"unsafe_unspecified_ip:{ip}"
    if obj.is_loopback:
        return False, f"unsafe_loopback_ip:{ip}"
    if obj.is_multicast:
        return False, f"unsafe_multicast_ip:{ip}"
    if obj.is_link_local:
        return False, f"unsafe_link_local_ip:{ip}"
    if obj.version == 4 and str(obj) == "255.255.255.255":
        return False, f"unsafe_broadcast_ip:{ip}"
    return True, "v6" if obj.version == 6 else "v4"


def is_safe_remote_peer_ip(ip: str | None) -> bool:
    """Return True when an ss/netstat peer IP is meaningful remote evidence."""
    return validate_enforcement_ip(ip)[0]


def is_rfc1918_ipv4(ip: str | None) -> bool:
    try:
        obj = ipaddress.ip_address(str(ip))
    except Exception:
        return False
    if obj.version != 4:
        return False
    return any(obj in ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
