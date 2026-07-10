from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List


def _run(cmd: List[str], execute: bool = False) -> Dict[str, Any]:
    if not execute:
        return {"planned": True, "command": cmd}
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=10, check=False)
        return {"planned": False, "command": cmd, "returncode": p.returncode, "stdout": p.stdout[-1000:], "stderr": p.stderr[-1000:], "ok": p.returncode == 0}
    except Exception as exc:
        return {"planned": False, "command": cmd, "ok": False, "error": str(exc)}


class SelfHealingCheck:
    """Read-only by default self-healing planner for competition runtime prerequisites."""

    def __init__(self, nft_family: str = "inet", nft_table: str = "aegis_guard"):
        self.nft_family = nft_family
        self.nft_table = nft_table

    def check(self, execute: bool = False) -> Dict[str, Any]:
        results: Dict[str, Any] = {"execute": execute, "checks": [], "repairs": []}
        nft = shutil.which("nft")
        results["checks"].append({"name": "nft_command", "ok": bool(nft), "path": nft})
        if nft:
            exists = subprocess.run(["nft", "list", "table", self.nft_family, self.nft_table], text=True, capture_output=True, timeout=5, check=False)
            ok = exists.returncode == 0
            results["checks"].append({"name": "nft_aegis_table", "ok": ok, "stderr": exists.stderr[-500:]})
            if not ok:
                results["repairs"].append(_run(["/opt/aegis-linux-defense-agent/scripts/bootstrap_nftables.sh"], execute=execute))
        auditctl = shutil.which("auditctl")
        results["checks"].append({"name": "auditctl_command", "ok": bool(auditctl), "path": auditctl})
        if auditctl:
            p = subprocess.run(["auditctl", "-l"], text=True, capture_output=True, timeout=5, check=False)
            has = "aegis" in (p.stdout or "").lower()
            results["checks"].append({"name": "auditd_aegis_rules", "ok": has})
            if not has:
                results["repairs"].append(_run(["/opt/aegis-linux-defense-agent/scripts/install_auditd_rules.sh"], execute=execute))
        return results
