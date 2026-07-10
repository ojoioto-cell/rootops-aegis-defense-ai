from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from aegis_agent.cli import cmd_battle_score, cmd_ai_quality
from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.battle_score import LiveBattleScoreEngine
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine
from aegis_agent.core.ai_quality import AIReasoningQualityGuard
from aegis_central.server import create_app, CENTRAL_VERSION


def test_version_0300():
    assert Path("VERSION").read_text().strip() == "0.3.1"
    assert CENTRAL_VERSION == "0.3.1"


def test_battle_score_engine_computes_metrics(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLogger(str(db))
    inc = {
        "incident_id": "INC-1",
        "host": "h1",
        "score": 90,
        "confidence": "critical",
        "attack_type": "ssh_bruteforce",
        "hypothesis": "test",
        "ai_provider": "rule_based",
        "ai_status": {"provider_used": "rule_based", "fallback": True},
        "loop_process": [
            {"phase": "collect_telemetry", "ts": 1.0},
            {"phase": "chain_selected", "ts": 2.0},
            {"phase": "ai_reasoning", "ts": 3.0},
            {"phase": "local_enforcement", "ts": 4.0},
            {"phase": "verify_actions", "ts": 5.0},
        ],
        "actions": [],
        "verification": {"service_ok": True},
        "policy_promotion": {"promotions": [{"stage": "promoted", "action": "block_ip_ttl", "recommended_ttl_seconds": 7200}]},
    }
    action = {"action_id": "ACT-1", "action": "block_ip_ttl", "target": "198.51.100.1", "status": "success", "dry_run": False}
    audit.save_incident(inc)
    audit.save_action("INC-1", action)
    score = LiveBattleScoreEngine(str(db)).compute()
    assert score["battle_metrics"]["enforcement_success_rate"] == 100.0
    assert score["battle_metrics"]["mean_response_time_seconds"] == 4.0
    assert score["blocked_or_limited_targets"] == ["198.51.100.1"]
    assert score["policy_promotion_stages"]["promoted"] == 1


def test_ai_quality_guard_detects_missing_evidence():
    guard = AIReasoningQualityGuard()
    result = guard.evaluate({"evidence_mapping": [{"claim": "x", "event_ids": []}], "recommended_actions": []}, ["E-1"])
    assert not result["ok"]
    assert result["issue_count"] >= 1


def test_central_battle_api(tmp_path):
    db = tmp_path / "central.db"
    app = create_app(str(db), auth_token="tok", require_read_auth=True)
    client = TestClient(app)
    assert client.get("/api/battle").status_code == 401
    r = client.get("/api/battle", headers={"Authorization": "Bearer tok"})
    assert r.status_code == 200
    assert r.json()["version"] == "0.3.1"

