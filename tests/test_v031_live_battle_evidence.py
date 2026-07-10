from __future__ import annotations

from pathlib import Path

from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine
from aegis_central.server import create_app, CENTRAL_VERSION
from fastapi.testclient import TestClient


def test_version_031():
    assert Path("VERSION").read_text().strip() == "0.3.1"
    assert CENTRAL_VERSION == "0.3.1"


def test_live_battle_evidence_excludes_synthetic_by_default(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLogger(str(db))
    live_inc = {
        "incident_id": "INC-LIVE",
        "agent_id": "real-agent",
        "host": "h1",
        "score": 90,
        "confidence": "critical",
        "attack_type": "ssh_bruteforce",
        "hypothesis": "test",
        "ai_provider": "rule_based",
        "ai_status": {"provider_used": "rule_based", "fallback": False},
        "loop_process": [
            {"phase": "collect_telemetry", "ts": 1.0},
            {"phase": "chain_selected", "ts": 2.0},
            {"phase": "ai_reasoning", "ts": 3.0},
            {"phase": "local_enforcement", "ts": 4.0},
            {"phase": "verify_actions", "ts": 5.0},
        ],
        "verification": {"service_ok": True},
    }
    synthetic_inc = {
        "incident_id": "INC-SYN",
        "agent_id": "aegis-ai-duel-demo",
        "host": "demo",
        "score": 100,
        "confidence": "critical",
        "attack_type": "drone_command_attempt",
        "hypothesis": "synthetic",
    }
    audit.save_incident(live_inc)
    audit.save_incident(synthetic_inc)
    audit.save_action("INC-LIVE", {"action_id": "ACT-LIVE", "action": "block_ip_ttl", "target": "198.51.100.1", "status": "success", "dry_run": False})
    audit.save_action("INC-SYN", {"action_id": "ACT-SYN", "action": "block_ip_ttl", "target": "198.51.100.2", "status": "success", "dry_run": False})

    evidence = LiveBattleEvidenceEngine(str(db)).compute()
    assert evidence["version"] == "0.3.1"
    assert evidence["source_scope"] == "live_only"
    assert evidence["live_incident_count"] == 1
    assert evidence["synthetic_incident_count"] == 1
    assert evidence["blocked_or_limited_targets"] == ["198.51.100.1"]
    assert evidence["battle_metrics"]["enforcement_success_rate"] == 100.0


def test_central_battle_api_live_evidence(tmp_path):
    db = tmp_path / "central.db"
    app = create_app(str(db), auth_token="tok", require_read_auth=True)
    client = TestClient(app)
    assert client.get("/api/battle").status_code == 401
    r = client.get("/api/battle", headers={"Authorization": "Bearer tok"})
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "0.3.1"
    assert body["engine"] == "live_battle_evidence"
