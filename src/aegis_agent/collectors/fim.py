from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Dict, Iterable, List

from aegis_agent.models import Event, new_id
from aegis_agent.utils import ensure_dir, hostname

SUSP_DIR_HINTS = ("/tmp", "/dev/shm", "/var/www", "/srv/www")
PERSIST_HINTS = ("/etc/cron", "/var/spool/cron", "authorized_keys", "systemd", "rc.local", ".service", ".timer")


def _state_path(state_dir: str | Path) -> Path:
    return ensure_dir(state_dir) / "fim_state.json"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _hash_small_file(path: Path, max_bytes: int = 1024 * 1024) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            h.update(f.read(max_bytes))
        return h.hexdigest()
    except Exception:
        return None


def _iter_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for raw in paths or []:
        root = Path(raw)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else root.rglob("*")
        for p in candidates:
            if count >= max_files:
                return
            try:
                if p.is_file() and not p.is_symlink():
                    count += 1
                    yield p
            except OSError:
                continue


def _classify(path: str, old: dict | None, new: dict) -> tuple[str, str]:
    lower = path.lower()
    executable_now = bool(new.get("mode", 0) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    executable_before = bool((old or {}).get("mode", 0) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    persistence = any(h in lower for h in PERSIST_HINTS)
    suspicious_dir = any(lower.startswith(h) or h in lower for h in SUSP_DIR_HINTS)
    if persistence:
        return "persistence_modified", "critical"
    if suspicious_dir or (executable_now and not executable_before):
        return "suspicious_file", "high"
    return "file_event", "low"


def collect_fim_events(paths: List[str], *, state_dir: str = "data/state", max_files: int = 10000, first_run_baseline: bool = True) -> List[Event]:
    """Polling FIM collector.

    It builds a baseline on the first run by default. Subsequent loops emit
    create/modify/delete events. This is intentionally dependency-free and can
    run where inotify/auditd is unavailable.
    """
    host = hostname()
    sp = _state_path(state_dir)
    state_exists = sp.exists()
    old_state = _load(sp)
    new_state: Dict[str, dict] = {}
    events: List[Event] = []
    now = time.time()

    for p in _iter_files(paths, max_files=max_files):
        try:
            st = p.stat()
        except OSError:
            continue
        key = str(p.resolve())
        rec = {
            "mtime": st.st_mtime,
            "size": st.st_size,
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "sha256": _hash_small_file(p),
        }
        new_state[key] = rec
        old = old_state.get(key)
        if not state_exists and not old_state and first_run_baseline:
            continue
        if old is None:
            evtype, sev = _classify(key, None, rec)
            events.append(Event(new_id("E"), now, "fim_poll", evtype, host, sev, f"FIM CREATE {key}", file_path=key, metadata={"fim_op": "create", "new": rec}))
        elif any(old.get(k) != rec.get(k) for k in ["mtime", "size", "mode", "sha256"]):
            evtype, sev = _classify(key, old, rec)
            events.append(Event(new_id("E"), now, "fim_poll", evtype, host, sev, f"FIM MODIFY {key}", file_path=key, metadata={"fim_op": "modify", "old": old, "new": rec}))

    if old_state:
        for key, old in old_state.items():
            if key not in new_state:
                evtype, sev = _classify(key, old, old)
                events.append(Event(new_id("E"), now, "fim_poll", evtype, host, sev, f"FIM DELETE {key}", file_path=key, metadata={"fim_op": "delete", "old": old}))

    _save(sp, new_state)
    return events
