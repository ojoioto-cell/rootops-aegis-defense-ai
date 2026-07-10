from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aegis_central.server import create_app


def _incident_payload():
    return {
        "agent_id": "agent-1",
        "host": "web01",
        "incidents": [
            {
                "incident_id": "INC-1",
                "agent_id": "agent-1",
                "host": "web01",
                "score": 96,
                "confidence": "critical",
                "attack_type": "rce_or_post_exploitation_suspected",
                "hypothesis": "web request followed by shell and outbound C2",
                "actions": [
                    {"action_id": "ACT-1", "action": "block_ip_ttl", "target": "203.0.113.10", "status": "planned", "dry_run": True},
                    {"action_id": "ACT-2", "action": "block_outbound_ip", "target": "45.77.1.2", "status": "planned", "dry_run": True},
                ],
            }
        ],
    }


def test_central_ui_summary_and_action_index(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"))
    c = TestClient(app)
    assert c.get("/dashboard").status_code == 200
    assert "Aegis Central" in c.get("/dashboard").text

    hb = c.post("/api/agents/heartbeat", json={"agent_id": "agent-1", "hostname": "web01", "version": "0.2.1", "status": "online"})
    assert hb.status_code == 200
    ingest = c.post("/api/ingest", json=_incident_payload())
    assert ingest.status_code == 200
    assert ingest.json()["actions_indexed"] == 2

    summary = c.get("/api/summary").json()
    assert summary["agents"]["total"] == 1
    assert summary["incidents"]["critical"] == 1
    assert summary["actions"]["planned"] == 2

    actions = c.get("/api/actions").json()
    assert len(actions) == 2
    assert actions[0]["action_id"] in {"ACT-1", "ACT-2"}

    incident = c.get("/api/incidents/1").json()
    assert incident["row_id"] == 1
    assert len(incident["indexed_actions"]) == 2


def test_central_mutation_auth_and_approval_decision(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"), auth_token="secret")
    c = TestClient(app)
    denied = c.post("/api/iocs", json={"indicator": "203.0.113.10"})
    assert denied.status_code == 401
    headers = {"Authorization": "Bearer secret"}
    ioc = c.post("/api/iocs", json={"indicator": "203.0.113.10", "confidence": 95}, headers=headers)
    assert ioc.status_code == 200
    ioc_id = ioc.json()["ioc_id"]
    assert c.delete(f"/api/iocs/{ioc_id}", headers=headers).status_code == 200

    approval = c.post("/api/approvals", json={"agent_id": "agent-1", "requested_action": "restrict_account"}, headers=headers)
    assert approval.status_code == 200
    request_id = approval.json()["request_id"]
    decision = c.post(f"/api/approvals/{request_id}/decision", json={"status": "approved", "reason": "operator reviewed"}, headers=headers)
    assert decision.status_code == 200
    queue = c.get("/api/approvals").json()
    assert queue[0]["status"] == "approved"


def test_policy_delete_and_agent_fetch(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"))
    c = TestClient(app)
    c.post("/api/agents/heartbeat", json={"agent_id": "agent-1", "hostname": "web01", "version": "0.2.1", "status": "online"})
    created = c.post("/api/policies", json={"name": "ui-policy", "version": "2", "policy": {"thresholds": {"collect_more": 30}, "actions": {}}})
    assert created.status_code == 200
    policy_id = created.json()["policy_id"]
    assert c.post("/api/policy/assign", json={"agent_id": "agent-1", "policy_id": policy_id}).status_code == 200
    fetched = c.get("/api/policy/agent-1").json()
    assert fetched["policy_id"] == policy_id
    assert fetched["policy"]["thresholds"]["collect_more"] == 30
    agent = c.get("/api/agents/agent-1").json()
    assert agent["assigned_policy"]["policy_id"] == policy_id
    assert c.delete(f"/api/policies/{policy_id}").status_code == 200
