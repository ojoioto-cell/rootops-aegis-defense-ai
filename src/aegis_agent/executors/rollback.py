from __future__ import annotations

import os
import shutil
import signal
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.utils import is_root, run_command


class RollbackExecutor:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def execute(self, action_result: Dict[str, Any]) -> Dict[str, Any]:
        rollback = action_result.get("rollback") or {}
        rb_type = rollback.get("type", "")
        if not rollback:
            return self._result(action_result, "skipped", "No rollback payload")
        if rb_type == "network_rollback" or rollback.get("command"):
            return self._rollback_command(action_result, rollback)
        if rb_type == "resume_process":
            return self._resume_process(action_result, rollback)
        if rb_type == "restore_file":
            return self._restore_file(action_result, rollback)
        if rb_type == "restore_persistence_file":
            return self._restore_persistence_file(action_result, rollback)
        return self._result(action_result, "skipped", f"Unsupported rollback type: {rb_type}")

    def _rollback_command(self, action_result: Dict[str, Any], rollback: Dict[str, Any]) -> Dict[str, Any]:
        cmd = rollback.get("command") or []
        if not cmd:
            if rollback.get("backend") == "memory":
                return self._result(action_result, "success", "Memory backend rollback accepted; no OS firewall change existed", ["memory-backend", "rollback", str(rollback.get("target", ""))])
            return self._result(action_result, "skipped", "Rollback command missing")
        if cmd and cmd[0] == "memory-backend":
            return self._result(action_result, "success", "Memory backend rollback accepted; no OS firewall change existed", cmd)
        if self.dry_run:
            return self._result(action_result, "planned", "Dry-run: rollback command not executed", cmd)
        if cmd[0] in {"nft", "iptables", "ip6tables"} and not is_root():
            return self._result(action_result, "failed", "Rollback requires root privileges", cmd, "preflight_failed")
        rc, out, err = run_command(cmd, timeout=10)
        msg = out or err or f"rc={rc}"
        if rc == 0:
            return self._result(action_result, "success", "Rollback command executed", cmd)
        # nft timeout sets may auto-expire before explicit rollback. Treat absent elements as safely rolled back.
        err_l = msg.lower()
        if cmd[0] == "nft" and any(x in err_l for x in ["no such file", "not found", "does not exist"]):
            return self._result(action_result, "success", "Rollback target already absent", cmd)
        return self._result(action_result, "failed", msg, cmd, err or out)

    def _resume_process(self, action_result: Dict[str, Any], rollback: Dict[str, Any]) -> Dict[str, Any]:
        pid = rollback.get("pid")
        if not pid:
            return self._result(action_result, "skipped", "PID missing")
        if self.dry_run:
            return self._result(action_result, "planned", f"Dry-run: SIGCONT not sent to {pid}")
        try:
            os.kill(int(pid), signal.SIGCONT)
            return self._result(action_result, "success", f"Process {pid} resumed")
        except Exception as exc:
            return self._result(action_result, "failed", str(exc), error=str(exc))

    def _restore_file(self, action_result: Dict[str, Any], rollback: Dict[str, Any]) -> Dict[str, Any]:
        src = rollback.get("from")
        dst = rollback.get("to")
        if not src or not dst:
            return self._result(action_result, "skipped", "File rollback source/destination missing")
        if self.dry_run:
            return self._result(action_result, "planned", f"Dry-run: would restore {src} to {dst}")
        try:
            src_p = Path(src)
            dst_p = Path(dst)
            dst_p.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_p), str(dst_p))
            return self._result(action_result, "success", f"File restored to {dst}")
        except Exception as exc:
            return self._result(action_result, "failed", str(exc), error=str(exc))


    def _restore_persistence_file(self, action_result: Dict[str, Any], rollback: Dict[str, Any]) -> Dict[str, Any]:
        target = rollback.get("target")
        backup = rollback.get("backup_path")
        disabled = rollback.get("disabled_path")
        if not target:
            return self._result(action_result, "skipped", "Persistence rollback target missing")
        if self.dry_run:
            return self._result(action_result, "planned", f"Dry-run: would restore persistence target {target}")
        try:
            target_p = Path(target)
            target_p.parent.mkdir(parents=True, exist_ok=True)
            if disabled and Path(disabled).exists():
                if target_p.exists():
                    target_p.unlink()
                shutil.move(str(Path(disabled)), str(target_p))
                return self._result(action_result, "success", f"Persistence file restored from disabled path to {target}")
            if backup and Path(backup).exists():
                shutil.copy2(str(Path(backup)), str(target_p))
                return self._result(action_result, "success", f"Persistence file restored from backup to {target}")
            return self._result(action_result, "failed", "Persistence backup/disabled path not found", error="persistence_rollback_source_missing")
        except Exception as exc:
            return self._result(action_result, "failed", str(exc), error=str(exc))

    @staticmethod
    def _result(action_result: Dict[str, Any], status: str, message: str, command: List[str] | None = None, error: str | None = None) -> Dict[str, Any]:
        return {
            "action_id": action_result.get("action_id"),
            "action": action_result.get("action"),
            "target": action_result.get("target"),
            "rollback_status": status,
            "dry_run": status == "planned",
            "message": message,
            "command": command or [],
            "error": error,
        }
