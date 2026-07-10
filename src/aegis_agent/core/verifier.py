from __future__ import annotations

import socket
import time
from typing import Any, Dict, List

from aegis_agent.models import ActionResult
from aegis_agent.utils import run_command


class Verifier:
    def __init__(self, service_health_command: str = "", config: Dict[str, Any] | None = None):
        self.service_health_command = service_health_command
        self.config = config or {}
        self.verify_delay_seconds = float(self.config.get("verify_delay_seconds", 0) or 0)
        self.health_checks = self.config.get("health_checks", []) or []
        if service_health_command and not self.health_checks:
            self.health_checks = [{"type": "command", "name": "service_health_command", "command": service_health_command}]

    def check_health(self) -> dict:
        if not self.health_checks:
            return {"ok": True, "checks": [], "message": "No service health checks configured"}
        checks = []
        ok = True
        for chk in self.health_checks:
            typ = (chk.get("type") or "command").lower()
            if typ == "command":
                res = self._command_check(chk)
            elif typ == "tcp":
                res = self._tcp_check(chk)
            else:
                res = {"name": chk.get("name", typ), "type": typ, "ok": False, "message": f"Unsupported health check type: {typ}"}
            checks.append(res)
            ok = ok and bool(res.get("ok"))
        return {"ok": ok, "checks": checks, "message": "ok" if ok else "one_or_more_health_checks_failed"}

    def verify_actions(self, results: List[ActionResult], pre_health: dict | None = None) -> dict:
        if self.verify_delay_seconds > 0 and any(r.status == "success" for r in results):
            time.sleep(min(self.verify_delay_seconds, 10))
        failed = [r for r in results if r.status == "failed"]
        planned = [r for r in results if r.status == "planned"]
        post_health = self.check_health()
        service_ok = bool(post_health.get("ok"))
        health_message = post_health.get("message", "")
        return {
            "success": len(failed) == 0 and service_ok,
            "failed_actions": [r.to_dict() for r in failed],
            "planned_actions": [r.to_dict() for r in planned],
            "service_ok": service_ok,
            "health_message": health_message,
            "pre_health": pre_health or {},
            "post_health": post_health,
        }

    def _command_check(self, chk: Dict[str, Any]) -> dict:
        name = chk.get("name") or "command"
        cmd = chk.get("command") or ""
        if not cmd:
            return {"name": name, "type": "command", "ok": False, "message": "missing command"}
        timeout = int(chk.get("timeout", 10))
        rc, out, err = run_command(str(cmd).split(), timeout=timeout)
        return {"name": name, "type": "command", "ok": rc == 0, "rc": rc, "message": (out or err or f"rc={rc}").strip()}

    def _tcp_check(self, chk: Dict[str, Any]) -> dict:
        name = chk.get("name") or "tcp"
        host = chk.get("host", "127.0.0.1")
        port = int(chk.get("port", 0))
        timeout = float(chk.get("timeout", 2.0))
        if not port:
            return {"name": name, "type": "tcp", "ok": False, "message": "missing port"}
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return {"name": name, "type": "tcp", "ok": True, "message": f"connected {host}:{port}"}
        except Exception as exc:
            return {"name": name, "type": "tcp", "ok": False, "message": str(exc)}
