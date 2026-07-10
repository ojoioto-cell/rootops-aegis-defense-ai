from __future__ import annotations

import os
import re
import signal
from pathlib import Path
from typing import Optional

from aegis_agent.models import ActionPlan, ActionResult

PID_RE = re.compile(r"^\s*(?P<pid>\d+)\b")
SUSPICIOUS_TOKENS = ("/tmp/", "/dev/shm/", " sh ", " bash ", "curl", "wget", " nc", "python -c", "perl -e")


class ProcessGuard:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.action != "suspend_process":
            return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, "Unsupported process action")
        pid = self._extract_pid(plan.target)
        rollback = {"type": "resume_process", "pid": pid}
        if not pid:
            return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, "PID not found in target string", rollback)
        if self.dry_run:
            return ActionResult(plan.action_id, plan.action, str(pid), "planned", True, "Dry-run: SIGSTOP not sent", rollback)
        safety_error = self._safety_check(pid, plan.target)
        if safety_error:
            return ActionResult(plan.action_id, plan.action, str(pid), "failed", False, safety_error, rollback, error="process_safety_check_failed")
        try:
            os.kill(pid, signal.SIGSTOP)
            return ActionResult(plan.action_id, plan.action, str(pid), "success", False, "Process suspended with SIGSTOP", rollback)
        except Exception as exc:
            return ActionResult(plan.action_id, plan.action, str(pid), "failed", False, str(exc), rollback, error=str(exc))

    @staticmethod
    def _extract_pid(target: str) -> Optional[int]:
        m = PID_RE.search(target or "")
        if not m:
            return None
        try:
            return int(m.group("pid"))
        except Exception:
            return None

    @staticmethod
    def _read_cmdline(pid: int) -> str:
        p = Path(f"/proc/{pid}/cmdline")
        if not p.exists():
            return ""
        raw = p.read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
        if raw:
            return raw
        stat = Path(f"/proc/{pid}/comm")
        return stat.read_text(errors="ignore").strip() if stat.exists() else ""

    def _safety_check(self, pid: int, target: str) -> str:
        if pid <= 2 or pid in {os.getpid(), os.getppid()}:
            return f"Refusing to suspend protected/current process PID {pid}"
        current_cmd = self._read_cmdline(pid)
        if not current_cmd:
            return f"PID {pid} is not present in /proc or command line is unavailable"
        target_l = f" {target.lower()} "
        current_l = f" {current_cmd.lower()} "
        # Require the live process command line to still look suspicious and to overlap with the evidence target.
        if not any(tok in current_l for tok in SUSPICIOUS_TOKENS):
            return f"Live PID {pid} command does not match suspicious-process safety pattern: {current_cmd}"
        target_tokens = [t for t in re.split(r"\s+", target_l.strip()) if len(t) >= 4 and not t.isdigit()]
        if target_tokens and not any(tok in current_l for tok in target_tokens):
            return f"Live PID {pid} command does not match evidence target. live={current_cmd} evidence={target}"
        return ""
