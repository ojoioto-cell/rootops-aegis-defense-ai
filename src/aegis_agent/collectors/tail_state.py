from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, List

from aegis_agent.utils import ensure_dir, safe_json_key


class TailState:
    """Small file offset tracker for near-real-time log collection.

    The first run can either read the whole file (default) or baseline at EOF
    without emitting events. This keeps run-once behavior useful while letting
    continuous mode avoid reprocessing the same log lines.
    """

    def __init__(self, state_dir: str | Path = "data/state", state_file: str = "tail_offsets.json"):
        self.state_dir = ensure_dir(state_dir)
        self.path = self.state_dir / state_file
        self.offsets = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.offsets, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def read_lines(self, file_path: str | Path, *, follow: bool = False, first_run: str = "full", max_bytes: int = 2_000_000) -> List[str]:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return []
        key = safe_json_key(str(p))
        size = p.stat().st_size
        old = self.offsets.get(key)

        if not follow:
            return p.read_text(errors="ignore").splitlines()

        if old is None:
            if first_run == "eof":
                self.offsets[key] = size
                self.save()
                return []
            start = max(0, size - max_bytes) if first_run == "tail" else 0
        else:
            start = int(old)
            if start > size:
                start = 0  # rotated or truncated

        with p.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(start)
            data = f.read(max_bytes)
            self.offsets[key] = f.tell()
        self.save()
        return data.splitlines()


def read_lines(paths: Iterable[str], *, state_dir: str | Path = "data/state", follow: bool = False, first_run: str = "full") -> list[tuple[str, list[str]]]:
    state = TailState(state_dir)
    out: list[tuple[str, list[str]]] = []
    for path in paths or []:
        out.append((str(path), state.read_lines(path, follow=follow, first_run=first_run)))
    return out
