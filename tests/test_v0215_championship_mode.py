from pathlib import Path

from aegis_agent.ai.llm_client import AIReasoningClient
from aegis_agent.core.policy_promotion import PolicyPromotionEngine
from aegis_agent.models import Event, EvidenceChain


def _chain():
    e = Event("E-1", 1.0, "auth.log", "ssh_failed_login", "h", "high", "failed", src_ip="198.51.100.9")
    return EvidenceChain("CHAIN-1", "h", [e], {"src_ip": ["198.51.100.9"]}, attack_type="ssh_bruteforce", hypothesis="ssh brute force", score=70, confidence="high", reasons=["SSH brute force"])


def test_ai_priority_gpt_then_ollama_then_rule(monkeypatch):
    client = AIReasoningClient(
        provider="auto",
        model="gpt-5.5",
        default_ttl=3600,
        config={"provider": "auto", "provider_priority": ["gpt", "ollama", "rule_based"], "fallback_to_rule_based": True},
    )

    def fail_gpt(chain, cfg):
        raise RuntimeError("gpt_down")

    def ok_ollama(chain, cfg):
        return '{"incident_likelihood":"high","confidence_score":80,"attack_type":"ssh_bruteforce","hypothesis":"test","evidence_mapping":[{"claim":"ssh","event_ids":["E-1"]}],"recommended_actions":[{"action":"block_ip_ttl","target":"198.51.100.9","ttl_seconds":3600,"reason":"test"}],"limitations":[]}'

    monkeypatch.setattr(client, "_call_gpt", fail_gpt)
    monkeypatch.setattr(client, "_call_ollama", ok_ollama)
    result = client.analyze(_chain())
    assert result.attack_type == "ssh_bruteforce"
    assert client.last_status["provider_used"] == "ollama"
    assert client.last_status["attempts"][0]["provider"] == "gpt"
    assert client.last_status["attempts"][0]["ok"] is False


def test_ai_priority_falls_back_to_rule(monkeypatch):
    client = AIReasoningClient(provider="auto", config={"provider_priority": ["gpt", "ollama", "rule_based"]})
    monkeypatch.setattr(client, "_call_gpt", lambda chain, cfg: (_ for _ in ()).throw(RuntimeError("gpt_down")))
    monkeypatch.setattr(client, "_call_ollama", lambda chain, cfg: (_ for _ in ()).throw(RuntimeError("ollama_down")))
    result = client.analyze(_chain())
    assert result.recommended_actions
    assert client.last_status["provider_used"] == "rule_based"
    assert client.last_status["fallback"] is True


def test_policy_promotion_candidate_shadow_promoted(tmp_path: Path):
    engine = PolicyPromotionEngine(str(tmp_path), enabled=True, shadow_after=2, enforce_after=3, promote_after_success=3)
    incident = {
        "incident_id": "INC-1",
        "attack_type": "ssh_bruteforce",
        "score": 80,
        "actions": [{"action": "block_ip_ttl", "target": "198.51.100.9", "status": "success"}],
    }
    p1 = engine.observe_incident(incident, {"service_ok": True})
    assert p1["promotions"][0]["stage"] == "candidate"
    p2 = engine.observe_incident(incident, {"service_ok": True})
    assert p2["promotions"][0]["stage"] == "shadow"
    p3 = engine.observe_incident(incident, {"service_ok": True})
    assert p3["promotions"][0]["stage"] == "promoted"
    assert engine.summary()["stages"]["promoted"] == 1


def test_championship_scripts_present():
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "aegis_championship_mode.sh"
    assert script.exists()
    assert "championship-status" in script.read_text()
    install = (root / "scripts" / "all_in_one_competition_install.sh").read_text()
    assert "provider_priority" in install
    assert "policy_promotion" in install
