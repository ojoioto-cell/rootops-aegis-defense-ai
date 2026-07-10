from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List

from aegis_agent.collectors.tail_state import TailState
from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname, parse_syslog_timestamp

SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>[\w.\-]+) from (?P<src_ip>[0-9a-fA-F:.]+)")
SSH_ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>[\w.\-]+) from (?P<src_ip>[0-9a-fA-F:.]+)")
INVALID_USER = re.compile(r"Invalid user (?P<user>[\w.\-]+) from (?P<src_ip>[0-9a-fA-F:.]+)")
SUDO = re.compile(r"sudo:\s+(?P<user>[\w.\-]+)\s+:.*COMMAND=(?P<cmd>.+)$")
SSHD_PID = re.compile(r"sshd\[(?P<pid>\d+)\]")


def _pid(raw: str) -> int | None:
    m = SSHD_PID.search(raw)
    if not m:
        return None
    try:
        return int(m.group("pid"))
    except Exception:
        return None


def collect_auth_events(paths: List[str], *, state_dir: str | None = None, follow: bool = False, first_run: str = "full") -> List[Event]:
    events: List[Event] = []
    host = hostname()
    tailer = TailState(state_dir or "data/state") if follow else None
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            ts = parse_syslog_timestamp(raw, time.time())
            pid = _pid(raw)
            m = SSH_FAILED.search(raw)
            if m:
                events.append(Event(new_id("E"), ts, str(p), "ssh_failed_login", host, "medium", raw, src_ip=m.group("src_ip"), user=m.group("user"), process="sshd", pid=pid))
                continue
            m = SSH_ACCEPTED.search(raw)
            if m:
                events.append(Event(new_id("E"), ts, str(p), "ssh_success_login", host, "high", raw, src_ip=m.group("src_ip"), user=m.group("user"), process="sshd", pid=pid))
                continue
            m = INVALID_USER.search(raw)
            if m:
                events.append(Event(new_id("E"), ts, str(p), "ssh_invalid_user", host, "medium", raw, src_ip=m.group("src_ip"), user=m.group("user"), process="sshd", pid=pid))
                continue
            m = SUDO.search(raw)
            if m:
                events.append(Event(new_id("E"), ts, str(p), "sudo_execution", host, "high", raw, user=m.group("user"), process=m.group("cmd"), metadata={"command": m.group("cmd")}))
    return events
