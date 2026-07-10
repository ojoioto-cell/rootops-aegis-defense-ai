from __future__ import annotations

import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from aegis_agent.collectors.tail_state import TailState
from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname, parse_audit_timestamp

KV_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)=(?P<value>\"[^\"]*\"|[^\s]+)")
TYPE_RE = re.compile(r"type=(?P<type>[A-Z_]+)")
SUSP_EXEC_RE = re.compile(r"(/tmp/|/dev/shm/|/bin/sh|/bin/bash|\bcurl\b|\bwget\b|\bnc\b|python|perl|php)", re.I)
PERSIST_RE = re.compile(r"(/etc/cron|/var/spool/cron|crontab|systemd|authorized_keys|rc\.local|\.service|\.timer)", re.I)
SUSP_FILE_RE = re.compile(r"(/tmp/|/dev/shm/|/var/www|/srv/www)", re.I)


def _kv(line: str) -> dict:
    out: dict = {}
    for m in KV_RE.finditer(line or ""):
        value = m.group("value")
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        out[m.group("key")] = value
    return out


def _audit_type(line: str) -> str:
    m = TYPE_RE.search(line or "")
    return m.group("type") if m else "UNKNOWN"


def _serial(line: str) -> str | None:
    _, serial = parse_audit_timestamp(line, time.time())
    return serial


def _to_int(value) -> int | None:
    try:
        if value is None or value == "?":
            return None
        return int(str(value), 0)
    except Exception:
        return None


def collect_auditd_events(paths: List[str], *, state_dir: str | None = None, follow: bool = False, first_run: str = "full") -> List[Event]:
    """Parse auditd records into defensive Events.

    This parser is intentionally conservative. It emits high-signal events for
    suspicious command execution, suspicious file creation/modification, and
    persistence path modification. It does not execute anything and treats all
    audit text as data.
    """
    host = hostname()
    tailer = TailState(state_dir or "data/state") if follow else None
    lines: list[tuple[str, str]] = []
    for path in paths or []:
        p = Path(path)
        if not p.exists():
            continue
        file_lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
        for line in file_lines:
            if line.strip():
                lines.append((str(p), line.strip()))

    grouped: Dict[str, list[tuple[str, str]]] = defaultdict(list)
    for source, line in lines:
        serial = _serial(line) or f"single-{len(grouped)}"
        grouped[serial].append((source, line))

    events: List[Event] = []
    for serial, records in grouped.items():
        ts = time.time()
        merged: dict = {"audit_serial": serial, "records": [r for _, r in records], "source_kind": "auditd"}
        source = records[0][0]
        raw = " | ".join(r for _, r in records)
        exe = None
        comm = None
        pid = None
        ppid = None
        uid = None
        auid = None
        cwd = None
        paths_seen: list[str] = []
        nametypes: list[str] = []
        proctitle = None

        for _, line in records:
            this_ts, _ = parse_audit_timestamp(line, ts)
            ts = this_ts or ts
            kv = _kv(line)
            typ = _audit_type(line)
            if typ == "SYSCALL":
                exe = kv.get("exe") or exe
                comm = kv.get("comm") or comm
                pid = _to_int(kv.get("pid")) or pid
                ppid = _to_int(kv.get("ppid")) or ppid
                uid = kv.get("uid") or uid
                auid = kv.get("auid") or auid
            elif typ == "EXECVE":
                args = []
                for key, value in sorted(kv.items()):
                    if re.fullmatch(r"a\d+", key):
                        args.append(str(value))
                if args:
                    proctitle = " ".join(args)
            elif typ == "PROCTITLE":
                proctitle = kv.get("proctitle") or proctitle
            elif typ == "CWD":
                cwd = kv.get("cwd") or cwd
            elif typ == "PATH":
                name = kv.get("name")
                if name:
                    paths_seen.append(name)
                nt = kv.get("nametype")
                if nt:
                    nametypes.append(nt)

        merged.update({
            "exe": exe,
            "comm": comm,
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "auid": auid,
            "cwd": cwd,
            "paths": paths_seen,
            "nametypes": nametypes,
            "proctitle": proctitle,
        })

        cmd_blob = " ".join(x for x in [exe, comm, proctitle, " ".join(paths_seen)] if x)
        if SUSP_EXEC_RE.search(cmd_blob):
            file_path = next((p for p in paths_seen if SUSP_FILE_RE.search(p)), None)
            events.append(Event(
                new_id("E"), ts, source, "suspicious_process", host, "high", raw,
                process=proctitle or exe or comm or raw,
                pid=pid,
                file_path=file_path,
                metadata=merged,
            ))

        for path_seen in paths_seen:
            if PERSIST_RE.search(path_seen):
                events.append(Event(new_id("E"), ts, source, "persistence_modified", host, "critical", raw, pid=pid, file_path=path_seen, metadata=merged))
            elif SUSP_FILE_RE.search(path_seen) and any(nt in {"CREATE", "DELETE", "NORMAL", "UNKNOWN"} for nt in nametypes or ["NORMAL"]):
                events.append(Event(new_id("E"), ts, source, "suspicious_file", host, "high", raw, pid=pid, file_path=path_seen, metadata=merged))

    return events
