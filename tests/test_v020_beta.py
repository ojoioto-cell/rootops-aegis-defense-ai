from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from aegis_agent.ai.llm_client import AIReasoningClient
from aegis_agent.models import Event, EvidenceChain
from aegis_central.server import create_app


def _chain() -> EvidenceChain:
    e1 = Event("E-1", 1.0, "access.log", "web_attack_pattern", "host1", "medium", "GET /?cmd=id", src_ip="8.8.8.8", uri="/?cmd=id")
    e2 = Event("E-2", 2.0, "auditd", "suspicious_process", "host1", "high", "bash -c id", process="/bin/bash", pid=123)
    return EvidenceChain("C-1", "host1", [e1, e2], {"src_ip": ["8.8.8.8"]}, score=82, confidence="high", attack_type="rce_suspected", hypothesis="web rce suspected")


def test_ollama_strict_schema_accepts_defensive_json(monkeypatch):
    client = AIReasoningClient("ollama", "llama3.1", 3600, {"fallback_to_rule_based": False})

    def fake_call(chain):
        return json.dumps({
            "incident_likelihood": "high",
            "confidence_score": 84,
            "attack_type": "rce_suspected",
            "hypothesis": "web request followed by shell execution",
            "evidence_mapping": [{"claim": "attack request and shell execution", "event_ids": ["E-1", "E-2"]}],
            "recommended_actions": [{"action": "block_ip_ttl", "target": "8.8.8.8", "reason": "source of attack", "ttl_seconds": 600}],
            "limitations": []
        })

    monkeypatch.setattr(client, "_call_ollama", fake_call)
    result = client.analyze(_chain())
    assert result.confidence_score == 84
    assert result.recommended_actions[0]["action"] == "block_ip_ttl"
    assert result.evidence_mapping[0]["event_ids"] == ["E-1", "E-2"]


def test_ai_schema_rejects_shell_command_target_and_falls_back(monkeypatch):
    client = AIReasoningClient("ollama", "llama3.1", 3600, {"fallback_to_rule_based": True})

    def fake_call(chain):
        return json.dumps({
            "incident_likelihood": "critical",
            "confidence_score": 99,
            "attack_type": "bad_output",
            "hypothesis": "bad",
            "evidence_mapping": [{"claim": "bad", "event_ids": ["NOT-A-REAL-ID"]}],
            "recommended_actions": [{"action": "block_ip_ttl", "target": "1.2.3.4; rm -rf /", "reason": "bad"}],
            "limitations": []
        })

    monkeypatch.setattr(client, "_call_ollama", fake_call)
    result = client.analyze(_chain())
    assert result.attack_type == "rce_suspected"  # rule fallback preserved the chain classification
    assert any("fallback" in x.lower() for x in result.limitations)


def test_central_policy_deployment_and_heartbeat(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"))
    c = TestClient(app)
    hb = c.post("/api/agents/heartbeat", json={"agent_id": "agent-1", "hostname": "web01", "version": "0.2.0", "status": "online"})
    assert hb.status_code == 200
    pol = {"policy": {"thresholds": {"collect_more": 20}, "actions": {}}}
    created = c.post("/api/policies", json={"name": "beta", "version": "1", "policy": pol})
    assert created.status_code == 200
    policy_id = created.json()["policy_id"]
    assigned = c.post("/api/policy/assign", json={"agent_id": "agent-1", "policy_id": policy_id})
    assert assigned.status_code == 200
    fetched = c.get("/api/policy/agent-1")
    assert fetched.status_code == 200
    assert fetched.json()["policy_id"] == policy_id
    agents = c.get("/api/agents").json()
    assert agents[0]["agent_id"] == "agent-1"


def test_central_ioc_repository(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"))
    c = TestClient(app)
    r = c.post("/api/iocs", json={"indicator": "203.0.113.10", "type": "ip", "action": "block_ip_ttl", "confidence": 90, "ttl_seconds": 3600})
    assert r.status_code == 200
    iocs = c.get("/api/iocs").json()
    assert iocs[0]["indicator"] == "203.0.113.10"
