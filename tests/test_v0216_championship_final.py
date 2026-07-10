from pathlib import Path

from aegis_agent.core.policy_promotion import PolicyPromotionEngine
from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.proof import ProofReportGenerator


def test_installer_creates_fresh_runtime_state():
    root = Path(__file__).resolve().parents[1]
    install = (root / "scripts" / "all_in_one_competition_install.sh").read_text()
    assert "AEGIS_FRESH_STATE" in install
    assert "ai_reasoning_ledger.jsonl" in install
    assert "policy_promotions.json" in install
    assert "self_protection_baseline.json" in install
    assert (root / "data" / ".gitkeep").exists()
    assert (root / "data" / "state" / ".gitkeep").exists()


def test_policy_promotion_generates_ioc_shadow_and_approval_candidates(tmp_path):
    engine = PolicyPromotionEngine(str(tmp_path), enabled=True, shadow_after=2, enforce_after=3, promote_after_success=3)
    incident = {
        "incident_id": "INC-1",
        "attack_type": "ssh_bruteforce",
        "actions": [{"action": "block_ip_ttl", "target": "198.51.100.9", "status": "success"}],
    }
    engine.observe_incident(incident, {"service_ok": True})
    engine.observe_incident(incident, {"service_ok": True})
    result = engine.observe_incident(incident, {"service_ok": True})
    promo = result["promotions"][0]
    assert promo["stage"] == "promoted"
    assert promo["ioc_candidate"]["indicator"] == "198.51.100.9"
    assert promo["shadow_policy"]["approval_required"] is True
    assert promo["approval_request"]["requested_action"] == "promote_shadow_policy"
    assert promo["active_policy_status"] == "pending_operator_approval"
    summary = engine.summary()
    assert summary["ioc_candidate_count"] == 1
    assert summary["approval_pending_count"] == 1
    assert summary["ttl_recommendations"]["block_ip_ttl"] >= 3600


def test_proof_report_20_sections(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLogger(str(db))
    incident = {
        "incident_id": "INC-1",
        "host": "h",
        "score": 90,
        "confidence": "critical",
        "attack_type": "ssh_bruteforce",
        "hypothesis": "test",
        "actions": [{"action": "block_ip_ttl", "action_id": "ACT-1", "target": "198.51.100.9", "status": "success", "dry_run": False}],
        "ai_provider": "gpt",
        "ai_status": {"provider_used": "gpt", "fallback": False},
        "policy_promotion": {"promotions": [{"stage": "promoted", "action": "block_ip_ttl", "recommended_ttl_seconds": 7200, "ioc_candidate": {"indicator": "198.51.100.9"}, "shadow_policy": {"kind": "shadow_policy_patch"}, "active_policy_status": "pending_operator_approval"}]},
    }
    audit.save_incident(incident)
    audit.save_action("INC-1", incident["actions"][0])
    out = tmp_path / "proof"
    result = ProofReportGenerator(str(db), include_nftables=False).write(str(out))
    assert result["ok"] is True
    text = (out / "proof_report.md").read_text(encoding="utf-8")
    assert "Synthetic AI Duel Proof vs. Real Enforcement Proof" in text
    assert "AI Provider and Fallback Status" in text
    assert "Policy Promotion and Autonomous Growth" in text
    summary = (out / "proof_summary.json").read_text(encoding="utf-8")
    assert "policy_promotion_ioc_candidate_count" in summary
    assert "ttl_recommendations" in summary
