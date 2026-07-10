from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any, Dict

from aegis_agent.utils import ensure_dir
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine


class CompetitionEvidenceExporter:
    def __init__(self, output_dir: str = "/var/lib/aegis/final_evidence"):
        self.output_dir = Path(output_dir)

    def _run(self, cmd: list[str], out: Path) -> None:
        try:
            p = subprocess.run(cmd, text=True, capture_output=True, timeout=20, check=False)
            out.write_text(p.stdout + ("\nSTDERR:\n" + p.stderr if p.stderr else ""), encoding="utf-8")
        except Exception as exc:
            out.write_text(f"ERROR: {exc}\n", encoding="utf-8")

    def export(self, audit_db: str, central_db: str | None = None, proof_dir: str | None = None) -> Dict[str, Any]:
        ts = time.strftime("%Y%m%d_%H%M%S")
        root = self.output_dir / f"final_evidence_{ts}"
        ensure_dir(root)
        for src, name in [(audit_db, "audit.db"), (central_db, "central.db")]:
            if src and Path(src).exists():
                try:
                    shutil.copy2(src, root / name)
                except Exception as exc:
                    (root / f"{name}.copy_error.txt").write_text(str(exc), encoding="utf-8")
        if proof_dir and Path(proof_dir).exists():
            shutil.copytree(proof_dir, root / "proof", dirs_exist_ok=True)
        self._run(["systemctl", "status", "aegis-agent", "--no-pager"], root / "aegis-agent.status.txt")
        self._run(["systemctl", "status", "aegis-central", "--no-pager"], root / "aegis-central.status.txt")
        self._run(["journalctl", "-u", "aegis-agent", "-n", "500", "--no-pager"], root / "aegis-agent.journal.txt")
        self._run(["journalctl", "-u", "aegis-central", "-n", "300", "--no-pager"], root / "aegis-central.journal.txt")
        self._run(["nft", "list", "ruleset"], root / "nftables_ruleset.txt")
        try:
            live = LiveBattleEvidenceEngine(audit_db).compute(limit=1000)
            (root / "live_battle_evidence.json").write_text(json.dumps(live, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            (root / "live_battle_evidence.error.txt").write_text(str(exc), encoding="utf-8")
        summary = {"created_at": int(time.time()), "root": str(root), "files": sorted(p.name for p in root.iterdir())}
        (root / "manifest.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        tar_path = self.output_dir / f"final_evidence_{ts}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(root, arcname=root.name)
        return {"ok": True, "directory": str(root), "archive": str(tar_path), "manifest": str(root / "manifest.json")}
