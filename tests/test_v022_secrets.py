from __future__ import annotations

import os
import stat
from pathlib import Path

from fastapi.testclient import TestClient

from aegis_agent.ai.llm_client import AIReasoningClient
from aegis_agent.security.secrets import resolve_api_key, redact_secrets, secret_status
from aegis_central.server import create_app


def test_api_key_file_loads_and_warns_on_open_permissions(tmp_path: Path):
    key_file = tmp_path / "openai_api_key"
    key_file.write_text("sk-test-file-key\n", encoding="utf-8")
    key_file.chmod(0o644)

    result = resolve_api_key({"api_key_file": str(key_file), "api_key_env": "MISSING_AEGIS_TEST_KEY"})

    assert result.value == "sk-test-file-key"
    assert result.source == "api_key_file"
    assert any("permissions_too_open" in w for w in result.warnings)


def test_api_key_env_fallback(monkeypatch):
    monkeypatch.setenv("AEGIS_TEST_OPENAI_KEY", "sk-env-value")
    result = resolve_api_key({"api_key_env": "AEGIS_TEST_OPENAI_KEY"})
    assert result.value == "sk-env-value"
    assert result.source == "env:AEGIS_TEST_OPENAI_KEY"


def test_secret_status_masks_value(tmp_path: Path):
    key_file = tmp_path / "key"
    key_file.write_text("sk-abcdefghijklmnop\n", encoding="utf-8")
    key_file.chmod(0o600)
    status = secret_status({"api_key_file": str(key_file)})
    assert status["loaded"] is True
    assert status["source"] == "api_key_file"
    assert status["masked"].startswith("sk-a")
    assert "abcdefghijklmnop" not in str(status)


def test_redact_secrets_recursive():
    payload = {"ai": {"api_key": "sk-raw", "api_key_file": "/etc/aegis/secrets/openai_api_key"}, "central": {"token": "secret-token"}}
    redacted = redact_secrets(payload)
    assert redacted["ai"]["api_key"] == "***REDACTED***"
    assert redacted["central"]["token"] == "***REDACTED***"
    assert redacted["ai"]["api_key_file"].endswith("openai_api_key")


def test_llm_client_file_key_resolution_without_exposing_key(tmp_path: Path):
    key_file = tmp_path / "openai_api_key"
    key_file.write_text("sk-super-secret-value", encoding="utf-8")
    key_file.chmod(0o600)
    client = AIReasoningClient(provider="gpt", model="gpt-test", config={"api_key_file": str(key_file), "fallback_to_rule_based": True, "timeout_seconds": 1})
    # Resolve directly to avoid making an external network call in tests.
    result = resolve_api_key(client.config)
    assert result.value == "sk-super-secret-value"
    public_cfg = redact_secrets(client.config)
    assert "sk-super-secret-value" not in str(public_cfg)


def test_central_redacts_policy_and_agent_payloads(tmp_path: Path):
    app = create_app(str(tmp_path / "central.db"), auth_token="tok")
    c = TestClient(app)
    headers = {"Authorization": "Bearer tok"}

    policy = {
        "name": "gpt-policy",
        "version": "1",
        "policy": {"ai": {"provider": "gpt", "api_key": "sk-central-raw", "api_key_file": "/etc/aegis/secrets/openai_api_key"}},
    }
    r = c.post("/api/policies", json=policy, headers=headers)
    assert r.status_code == 200
    policy_id = r.json()["policy_id"]

    r = c.get(f"/api/policies/{policy_id}")
    body = r.json()
    dumped = str(body)
    assert "sk-central-raw" not in dumped
    assert "***REDACTED***" in dumped

    hb = {"agent_id": "agent-1", "hostname": "h", "token": "agent-secret-token", "version": "0.2.3"}
    assert c.post("/api/agents/heartbeat", json=hb, headers=headers).status_code == 200
    body = c.get("/api/agents/agent-1").json()
    assert "agent-secret-token" not in str(body)
    assert body["payload"]["token"] == "***REDACTED***"
