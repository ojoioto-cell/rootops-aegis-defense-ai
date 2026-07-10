from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Dict, List, Optional

from aegis_agent.collectors.tail_state import TailState
from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname, run_command, is_safe_remote_peer_ip, is_rfc1918_ipv4

SUSP_PROC_RE = re.compile(r"(/tmp/|/dev/shm/|\bsh\b|\bbash\b|\bcurl\b|\bwget\b|\bnc\b|python\s+-c|perl\s+-e|php\s+-r)", re.I)
IP_RE = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
URL_IP_RE = re.compile(r"https?://(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", re.I)
PID_USER_RE = re.compile(r"pid=(?P<pid>\d+)")
FILE_PATH_RE = re.compile(r"(?P<path>/(?:tmp|dev/shm|var/www|srv/www)[^\s\"']*)", re.I)
ABS_PATH_RE = re.compile(r"(?<!:)(?P<path>/(?:[^\s\"'<>]|\\ )+)")


def _extract_absolute_paths(raw: str) -> list[str]:
    """Extract filesystem-looking absolute paths from a telemetry line.

    Prefer the first real filesystem path instead of the last token. This fixes
    demo and live lines such as:
      /tmp/.x CREATE mode=755 sha256=...
      /etc/cron.d/job /tmp/.x

    Token-based extraction intentionally ignores URL paths such as
    http://1.2.3.4/x.sh while still accepting key=/tmp/x style fields.
    """
    paths: list[str] = []
    for token in re.split(r"\s+", raw or ""):
        candidates = [token]
        if "=" in token:
            candidates.append(token.split("=", 1)[1])
        for cand in candidates:
            path = cand.strip().strip("\"'`.,;)]}>")
            if not path.startswith("/") or path.startswith("//"):
                continue
            if "://" in path:
                continue
            if path not in paths:
                paths.append(path)
    return paths


def _first_absolute_path(raw: str) -> str | None:
    paths = _extract_absolute_paths(raw)
    return paths[0] if paths else None


def _parse_ps_line(line: str) -> dict:
    parts = line.strip().split(None, 4)
    meta: dict = {"cmdline": line.strip(), "source_kind": "process_snapshot"}
    if len(parts) >= 1:
        try:
            meta["pid"] = int(parts[0])
        except Exception:
            pass
    if len(parts) >= 2:
        try:
            meta["ppid"] = int(parts[1])
        except Exception:
            pass
    if len(parts) >= 3:
        meta["user"] = parts[2]
    if len(parts) >= 4:
        meta["comm"] = parts[3]
    if len(parts) >= 5:
        meta["args"] = parts[4]
    m = URL_IP_RE.search(line)
    if m:
        meta["embedded_ip"] = m.group("ip")
    fp = _first_absolute_path(line)
    if fp:
        meta["embedded_file_path"] = fp
    return meta


def collect_process_snapshot(path: str | None = None) -> List[Event]:
    host = hostname()
    lines: List[str] = []
    source = "process_snapshot"
    if path and Path(path).exists():
        source = path
        lines = Path(path).read_text(errors="ignore").splitlines()
    else:
        rc, out, _ = run_command(["ps", "-eo", "pid,ppid,user,comm,args"], timeout=5)
        if rc == 0:
            lines = out.splitlines()
    events: List[Event] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("PID"):
            continue
        if SUSP_PROC_RE.search(line):
            meta = _parse_ps_line(line)
            pid = meta.get("pid")
            dst_ip = meta.get("embedded_ip")
            file_path = meta.get("embedded_file_path")
            events.append(Event(
                new_id("E"), time.time(), source, "suspicious_process", host, "high", line.strip(),
                dst_ip=dst_ip,
                process=line.strip(),
                pid=pid if isinstance(pid, int) else None,
                file_path=file_path,
                user=meta.get("user"),
                metadata=meta,
            ))
    return events



def _extract_endpoint_ip(endpoint: str | None) -> str | None:
    """Extract IP from ss endpoint such as 1.2.3.4:443 or [2001:db8::1]:14550."""
    if not endpoint:
        return None
    ep = str(endpoint).strip()
    if ep in {"*", "*:*", "0.0.0.0:*", "[::]:*", ":::*"}:
        return None
    if ep.startswith("[") and "]" in ep:
        host = ep[1:ep.index("]")]
    else:
        # IPv4 host:port or wildcard. IPv6 without brackets is uncommon in ss -n output;
        # fall back to regex extraction below when split is ambiguous.
        if ep.count(":") == 1:
            host = ep.rsplit(":", 1)[0]
        else:
            host = ep.rsplit(":", 1)[0] if ep.rsplit(":", 1)[-1].isdigit() else ep
    host = host.strip("[]")
    if "%" in host:
        host = host.split("%", 1)[0]
    if host.startswith("::ffff:"):
        host = host.replace("::ffff:", "", 1)
    if host in {"", "*"}:
        return None
    if IP_RE.fullmatch(host):
        return host
    # Last resort for raw fields containing IPv4 somewhere.
    m = IP_RE.search(ep)
    return m.group("ip") if m else None


def _parse_ss_line(line: str) -> dict | None:
    parts = line.strip().split(None, 6)
    if len(parts) < 6 or parts[0].lower() in {"netid", "state"}:
        return None
    netid, state = parts[0].lower(), parts[1].upper()
    local_ep, peer_ep = parts[4], parts[5]
    peer_ip = _extract_endpoint_ip(peer_ep)
    local_ip = _extract_endpoint_ip(local_ep)
    return {"netid": netid, "state": state, "local_ip": local_ip, "peer_ip": peer_ip, "local_ep": local_ep, "peer_ep": peer_ep}

def collect_network_snapshot(path: str | None = None) -> List[Event]:
    host = hostname()
    lines: List[str] = []
    source = "network_snapshot"
    if path and Path(path).exists():
        source = path
        lines = Path(path).read_text(errors="ignore").splitlines()
    else:
        rc, out, _ = run_command(["ss", "-tunap"], timeout=5)
        if rc == 0:
            lines = out.splitlines()
    events: List[Event] = []
    ignored_process_markers = ("avahi-daemon", "systemd-resolve", "systemd-timesyncd")
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        lower = raw.lower()
        parsed = _parse_ss_line(raw)
        if not parsed:
            continue
        peer_ip = parsed.get("peer_ip")
        # Ignore wildcard/listener rows such as UDP UNCONN 0.0.0.0:* and local-only peers.
        if not peer_ip or not is_safe_remote_peer_ip(peer_ip):
            continue
        # Ignore common local discovery/resolver wildcard services unless they have a real remote peer.
        if any(marker in lower for marker in ignored_process_markers) and parsed.get("state") in {"UNCONN", "LISTEN"}:
            continue
        # Avoid treating passive listeners as external connections. UDP is only useful when ss exposes a real peer.
        state = parsed.get("state", "")
        if not ("ESTAB" in state or "SYN-RECV" in state or (parsed.get("netid") == "udp" and peer_ip)):
            continue
        pid = None
        m = PID_USER_RE.search(raw)
        if m:
            try:
                pid = int(m.group("pid"))
            except Exception:
                pass
        evtype = "network_connection"
        sev = "medium"
        if peer_ip and not is_rfc1918_ipv4(peer_ip):
            evtype = "external_network_connection"
            sev = "high"
        events.append(Event(
            new_id("E"), time.time(), source, evtype, host, sev, raw,
            dst_ip=peer_ip,
            pid=pid,
            metadata={
                "pid": pid,
                "peer_ip": peer_ip,
                "local_ip": parsed.get("local_ip"),
                "peer_ep": parsed.get("peer_ep"),
                "local_ep": parsed.get("local_ep"),
                "state": parsed.get("state"),
                "netid": parsed.get("netid"),
                "source_kind": "network_snapshot",
            },
        ))
    return events

def collect_file_events(path: str | None = None, *, state_dir: str | None = None, follow: bool = False, first_run: str = "full") -> List[Event]:
    host = hostname()
    events: List[Event] = []
    if not path or not Path(path).exists():
        return events
    p = Path(path)
    tailer = TailState(state_dir or "data/state") if follow else None
    lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        paths = _extract_absolute_paths(raw)
        file_path = paths[0] if paths else raw.split()[-1]
        evtype = "suspicious_file" if ("/tmp/" in raw or "/dev/shm/" in raw or "www" in raw) else "file_event"
        events.append(Event(new_id("E"), time.time(), str(p), evtype, host, "high" if evtype == "suspicious_file" else "low", raw, file_path=file_path, metadata={"path": file_path, "paths": paths}))
    return events


def collect_persistence_events(path: str | None = None, *, state_dir: str | None = None, follow: bool = False, first_run: str = "full") -> List[Event]:
    host = hostname()
    events: List[Event] = []
    if not path or not Path(path).exists():
        return events
    p = Path(path)
    tailer = TailState(state_dir or "data/state") if follow else None
    lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        if any(x in raw.lower() for x in ["cron", "systemd", "authorized_keys", "rc.local", ".service", ".timer"]):
            paths = _extract_absolute_paths(raw)
            target = paths[0] if paths else raw.split()[-1]
            events.append(Event(new_id("E"), time.time(), str(p), "persistence_modified", host, "critical", raw, file_path=target, metadata={"path": target, "paths": paths}))
    return events
