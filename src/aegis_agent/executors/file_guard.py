from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from aegis_agent.models import ActionPlan, ActionResult
from aegis_agent.utils import ensure_dir


class FileGuard:
    def __init__(self, dry_run: bool = True, quarantine_dir: str = "data/quarantine"):
        self.dry_run = dry_run
        self.quarantine_dir = ensure_dir(quarantine_dir)

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.action != "quarantine_file":
            return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, "Unsupported file action")
        target = Path(plan.target)
        rollback = {"type": "restore_file", "source": str(target)}
        if self.dry_run:
            return ActionResult(plan.action_id, plan.action, str(target), "planned", True, "Dry-run: file not moved", rollback)
        if not target.exists() or not target.is_file():
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, "Target file does not exist", rollback, error="file_not_found")
        try:
            digest = self._sha256(target)
            dest_name = f"{int(time.time())}_{target.name}.quarantine"
            dest = self.quarantine_dir / dest_name
            meta = {
                "original_path": str(target),
                "quarantine_path": str(dest),
                "sha256": digest,
                "created_at": int(time.time()),
            }
            shutil.move(str(target), str(dest))
            (self.quarantine_dir / f"{dest_name}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            rollback = {"type": "restore_file", "from": str(dest), "to": str(target), "sha256": digest}
            return ActionResult(plan.action_id, plan.action, str(target), "success", False, "File quarantined", rollback)
        except Exception as exc:
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, str(exc), rollback, error=str(exc))

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
