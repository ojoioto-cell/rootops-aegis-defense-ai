from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_agent.ai.llm_client import AIReasoningClient
from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.central_client import CentralClient
from aegis_agent.models import EvidenceChain, Event
from aegis_agent.security.secrets import resolve_api_key, secret_status
from aegis_central.server import create_app
from aegis_agent.ai.rule_engine import analyze_chain


def _chain() -> EvidenceChain:
    return EvidenceChain(
        chain_id="CHAIN-test",
        host="web01",
        events=[
            Event("E-ssh", 1.0, "auth", "ssh_failed_login", "web01", "high", src_ip="203.0.113.10", raw="failed"),
            Event("E-web", 2.0, "web", "web_attack_pattern", "web01", "high", src_ip="203.0.113.10", uri="/?cmd=id", raw="cmd=id"),
            Event("E-proc", 3.0, "proc", "suspicious_process", "web01", "critical", process="/bin/sh", raw="sh"),
            Event("E-net", 4.0, "net", "external_network_connection", "web01", "high", dst_ip="45.77.1.2", raw="c2"),
        ],
        entities={"src_ip": ["203.0.113.10"], "dst_ip": ["45.77.1.2"]},
        score=95,
        confidence="critical",
        attack_type="rce_or_post_exploitation_suspected",
        hypothesis="test",
        reasons=["SSH failed login burst", "Web attack pattern detected", "Suspicious process execution", "External C2 connection"],
    )


def test_dashboard_has_no_inline_onclick(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"))
    c = TestClient(app)
    body = c.get("/dashboard").text
    assert "onclick" not in body
    assert 'data-action="refresh-all"' in body


def test_read_api_auth_option_blocks_reads_and_dashboard(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"), auth_token="secret", require_read_auth=True)
    c = TestClient(app)
    assert c.get("/api/summary").status_code == 401
    assert c.get("/dashboard").status_code == 401
    headers = {"Authorization": "Bearer secret"}
    assert c.get("/api/summary", headers=headers).status_code == 200
    assert c.get("/dashboard", headers=headers).status_code == 200
    # health remains unauthenticated for liveness probes
    assert c.get("/api/health").status_code == 200


def test_central_enabled_default_token_refused():
    with pytest.raises(ValueError):
        CentralClient(enabled=True, url="http://127.0.0.1:8088", token="change-me")


def test_strict_secret_permissions_raise(tmp_path: Path):
    key = tmp_path / "openai_api_key"
    key.write_text("sk-test", encoding="utf-8")
    key.chmod(0o644)
    with pytest.raises(PermissionError):
        resolve_api_key({"api_key_file": str(key), "fail_on_insecure_secret_permissions": True})
    status = secret_status({"api_key_file": str(key), "fail_on_insecure_secret_permissions": True})
    assert status["loaded"] is False
    assert status["error"] == "insecure_secret_permissions"


def test_audit_and_central_db_permissions_0600(tmp_path: Path):
    audit_path = tmp_path / "audit.db"
    AuditLogger(str(audit_path))
    assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600
    central_path = tmp_path / "central.db"
    create_app(str(central_path))
    assert stat.S_IMODE(central_path.stat().st_mode) == 0o600


def test_rule_based_evidence_mapping_is_event_type_precise():
    analysis = analyze_chain(_chain())
    mapping = {m["claim"]: set(m["event_ids"]) for m in analysis.evidence_mapping}
    assert mapping["SSH failed login burst"] == {"E-ssh"}
    assert mapping["Web attack pattern detected"] == {"E-web"}
    assert mapping["Suspicious process execution"] == {"E-proc"}
    assert mapping["External C2 connection"] == {"E-net"}


def test_gpt_actual_call_mock_strict_schema(tmp_path: Path, monkeypatch):
    key = tmp_path / "openai_api_key"
    key.write_text("sk-mock", encoding="utf-8")
    key.chmod(0o600)
    chain = _chain()
    captured = {}

    def fake_post_json(self, url, body, headers=None):
        captured["url"] = url
        captured["auth"] = (headers or {}).get("Authorization")
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "incident_likelihood": "critical",
                                "confidence_score": 96,
                                "attack_type": "rce_or_post_exploitation_suspected",
                                "hypothesis": "Evidence-backed mocked GPT decision",
                                "evidence_mapping": [{"claim": "web request led to shell", "event_ids": ["E-web", "E-proc"]}],
                                "recommended_actions": [
                                    {"action": "block_ip_ttl", "target": "203.0.113.10", "reason": "source IP in chain", "ttl_seconds": 600}
                                ],
                                "limitations": [],
                            }
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(AIReasoningClient, "_post_json", fake_post_json)
    client = AIReasoningClient(provider="gpt", model="gpt-mock", config={"api_key_file": str(key), "fallback_to_rule_based": False})
    result = client.analyze(chain)
    assert captured["auth"] == "Bearer sk-mock"
    assert result.incident_likelihood == "critical"
    assert result.evidence_mapping[0]["event_ids"] == ["E-web", "E-proc"]
    assert result.recommended_actions[0]["action"] == "block_ip_ttl"
