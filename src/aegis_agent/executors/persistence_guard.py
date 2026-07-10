from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Iterable, List

from aegis_agent.models import ActionPlan, ActionResult
from aegis_agent.utils import ensure_dir

SUSPICIOUS_LINE_RE = re.compile(
    r"(/tmp/|/dev/shm/|curl\b|wget\b|\bnc\b|python\s+-c|perl\s+-e|php\s+-r|/bin/sh|/bin/bash|base64\s+-d|authorized_keys)",
    re.I,
)
LINE_BASED_NAMES = {
    "crontab",
    "authorized_keys",
    "rc.local",
    ".bashrc",
    ".profile",
    "profile",
}
UNIT_SUFFIXES = {".service", ".timer"}


class PersistenceGuard:
    """Disable persistence artifacts with reversible, evidence-scoped mutations.

    Safety model:
    - Only exact evidence targets are handled.
    - Only configured persistence paths are eligible.
    - The full original file is backed up before mutation.
    - Line-based files are edited by commenting suspicious/evidence-linked lines.
    - systemd unit files are renamed to *.aegis-disabled-<action_id>.
    - Every successful change returns a rollback payload.
    """

    def __init__(self, dry_run: bool = True, config: dict[str, Any] | None = None):
        self.dry_run = dry_run
        cfg = config or {}
        self.backup_dir = ensure_dir(cfg.get("persistence_backup_dir", "data/persistence_backup"))
        self.allowed_paths = [Path(p) for p in cfg.get("persistence_allowed_paths", [
            "/etc/cron.d",
            "/etc/crontab",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
            "/etc/systemd/system",
            "/etc/rc.local",
            "/root/.ssh/authorized_keys",
            "/home",
        ])]
        self.max_file_size = int(cfg.get("persistence_max_file_size", 1024 * 1024))

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.action != "disable_persistence":
            return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, "Unsupported persistence action")

        target = Path(str(plan.target or "")).expanduser()
        rollback = {"type": "restore_persistence_file", "target": str(target)}
        if not str(target) or str(target) == "unknown":
            return ActionResult(plan.action_id, plan.action, str(target), "skipped", self.dry_run, "Persistence target is unknown", rollback)

        if self.dry_run:
            rollback.update({"backup_path": str(self.backup_dir / f"{plan.action_id}.bak")})
            return ActionResult(plan.action_id, plan.action, str(target), "planned", True, "Dry-run: persistence artifact not modified", rollback)

        if not self._allowed(target):
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, "Target path is outside configured persistence allowlist", rollback, error="persistence_path_not_allowed")
        if not target.exists():
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, "Persistence target does not exist", rollback, error="persistence_target_not_found")
        if target.is_dir():
            return ActionResult(plan.action_id, plan.action, str(target), "skipped", False, "Refusing to disable a directory target", rollback)
        try:
            if target.stat().st_size > self.max_file_size:
                return ActionResult(plan.action_id, plan.action, str(target), "failed", False, "Persistence target exceeds max safe edit size", rollback, error="persistence_target_too_large")
        except OSError as exc:
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, str(exc), rollback, error=str(exc))

        try:
            backup = self._backup(target, plan.action_id)
            if self._is_systemd_unit(target):
                return self._disable_unit_file(plan, target, backup)
            return self._disable_lines(plan, target, backup)
        except Exception as exc:
            return ActionResult(plan.action_id, plan.action, str(target), "failed", False, str(exc), rollback, error=str(exc))

    def _allowed(self, target: Path) -> bool:
        try:
            resolved = target.resolve(strict=False)
        except Exception:
            resolved = target.absolute()
        for base in self.allowed_paths:
            try:
                b = base.expanduser().resolve(strict=False)
                if resolved == b or b in resolved.parents:
                    return True
            except Exception:
                continue
        return False

    def _backup(self, target: Path, action_id: str) -> Path:
        ensure_dir(self.backup_dir)
        safe_name = str(target).strip("/").replace("/", "__") or target.name
        backup = self.backup_dir / f"{int(time.time())}_{action_id}_{safe_name}.bak"
        shutil.copy2(str(target), str(backup))
        meta = {
            "target": str(target),
            "backup": str(backup),
            "mode": oct(target.stat().st_mode),
            "uid": target.stat().st_uid,
            "gid": target.stat().st_gid,
            "created_at": int(time.time()),
        }
        backup.with_suffix(backup.suffix + ".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return backup

    @staticmethod
    def _is_systemd_unit(target: Path) -> bool:
        return target.suffix in UNIT_SUFFIXES or "/systemd/" in str(target)

    def _disable_unit_file(self, plan: ActionPlan, target: Path, backup: Path) -> ActionResult:
        disabled = target.with_name(f"{target.name}.aegis-disabled-{plan.action_id[-8:]}")
        if disabled.exists():
            disabled = target.with_name(f"{target.name}.aegis-disabled-{plan.action_id[-8:]}-{int(time.time())}")
        shutil.move(str(target), str(disabled))
        rollback = {
            "type": "restore_persistence_file",
            "target": str(target),
            "backup_path": str(backup),
            "disabled_path": str(disabled),
        }
        return ActionResult(plan.action_id, plan.action, str(target), "success", False, "systemd persistence unit disabled by reversible rename", rollback)

    def _disable_lines(self, plan: ActionPlan, target: Path, backup: Path) -> ActionResult:
        raw = target.read_text(errors="ignore")
        lines = raw.splitlines(keepends=True)
        tokens = self._tokens(plan)
        changed = 0
        out: List[str] = []
        for line in lines:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                out.append(line)
                continue
            if self._line_matches(line, tokens):
                out.append(f"# AEGIS_DISABLED {plan.action_id} {int(time.time())} :: {line}")
                changed += 1
            else:
                out.append(line)
        if changed == 0:
            # Do not blindly comment arbitrary persistence files. Evidence linkage is required.
            return ActionResult(
                plan.action_id,
                plan.action,
                str(target),
                "skipped",
                False,
                "No evidence-linked suspicious persistence line found; original backup retained but target unchanged",
                {"type": "restore_persistence_file", "target": str(target), "backup_path": str(backup)},
            )
        target.write_text("".join(out), encoding="utf-8")
        rollback = {
            "type": "restore_persistence_file",
            "target": str(target),
            "backup_path": str(backup),
            "changed_lines": changed,
        }
        return ActionResult(plan.action_id, plan.action, str(target), "success", False, f"Disabled {changed} evidence-linked persistence line(s)", rollback)

    def _tokens(self, plan: ActionPlan) -> list[str]:
        meta = plan.metadata or {}
        tokens: list[str] = []
        for key in ("linked_files", "linked_dst_ips", "linked_src_ips", "persistence_raw", "processes"):
            val = meta.get(key)
            if isinstance(val, list):
                tokens.extend(str(v) for v in val if v)
            elif val:
                tokens.append(str(val))
        if plan.target:
            tokens.append(str(plan.target))
        # Keep only useful, non-generic tokens.
        cleaned = []
        for t in tokens:
            for piece in re.split(r"\s+|,|;", t):
                p = piece.strip().strip('"\'')
                if len(p) >= 4 and p not in cleaned:
                    cleaned.append(p)
        return cleaned

    def _line_matches(self, line: str, tokens: Iterable[str]) -> bool:
        if SUSPICIOUS_LINE_RE.search(line):
            return True
        lower = line.lower()
        return any(tok.lower() in lower for tok in tokens if tok and len(tok) >= 4)
