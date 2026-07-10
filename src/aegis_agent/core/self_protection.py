from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from aegis_agent.utils import ensure_dir


class SelfProtectionMonitor:
    """Lightweight integrity monitor for the agent package and policy files."""

    def __init__(self, state_dir: str = "data/state", enabled: bool = True, paths: Iterable[str] | None = None, baseline_on_first_run: bool = True):
        self.enabled = enabled
        self.state_dir = ensure_dir(state_dir)
        self.baseline_path = self.state_dir / "self_protection_baseline.json"
        self.paths = [Path(p) for p in (paths or [])]
        self.baseline_on_first_run = baseline_on_first_run

    def check(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "ok": True, "message": "self-protection disabled"}
        current = self._snapshot()
        if not self.baseline_path.exists():
            if self.baseline_on_first_run:
                self.baseline_path.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
                return {"enabled": True, "ok": True, "baseline_created": True, "message": "baseline created", "checked_files": len(current.get("files", {}))}
            return {"enabled": True, "ok": False, "message": "baseline missing", "checked_files": len(current.get("files", {}))}
        try:
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"enabled": True, "ok": False, "message": f"baseline unreadable: {exc}"}
        changes = []
        base_files = baseline.get("files", {})
        cur_files = current.get("files", {})
        for path, digest in cur_files.items():
            if path not in base_files:
                changes.append({"path": path, "change": "new"})
            elif base_files[path] != digest:
                changes.append({"path": path, "change": "modified"})
        for path in base_files:
            if path not in cur_files:
                changes.append({"path": path, "change": "missing"})
        return {
            "enabled": True,
            "ok": len(changes) == 0,
            "tamper_detected": len(changes) > 0,
            "changes": changes,
            "checked_files": len(cur_files),
            "message": "ok" if not changes else "agent_integrity_change_detected",
        }

    def reset_baseline(self) -> Dict[str, Any]:
        current = self._snapshot()
        self.baseline_path.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"ok": True, "baseline_path": str(self.baseline_path), "checked_files": len(current.get("files", {}))}

    def _snapshot(self) -> Dict[str, Any]:
        files: Dict[str, str] = {}
        for p in self.paths:
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file() and child.suffix in {".py", ".yaml", ".yml", ".service", ".sh"}:
                        files[str(child)] = self._sha256(child)
            elif p.is_file():
                files[str(p)] = self._sha256(p)
        return {"created_at": int(time.time()), "files": files}

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
