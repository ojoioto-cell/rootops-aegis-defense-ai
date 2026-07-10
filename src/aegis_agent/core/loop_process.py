from __future__ import annotations

import time
from typing import Any, Dict, List


class LoopProcessRecorder:
    """Small audit helper that records the autonomous defense loop phases."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._phases: List[Dict[str, Any]] = []
        self._seq = 0

    def add(self, phase: str, status: str = "ok", **data: Any) -> None:
        if not self.enabled:
            return
        self._seq += 1
        rec: Dict[str, Any] = {
            "seq": self._seq,
            "phase": phase,
            "status": status,
            "ts": time.time(),
        }
        rec.update(data)
        self._phases.append(rec)

    def snapshot(self) -> List[Dict[str, Any]]:
        return [dict(x) for x in self._phases]
