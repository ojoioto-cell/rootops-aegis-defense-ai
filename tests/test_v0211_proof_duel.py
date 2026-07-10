from pathlib import Path

import json

from aegis_agent.core.duel_demo import AIDuelDemoHarness
from aegis_agent.core.proof import ProofReportGenerator
from aegis_agent.core.reasoning_ledger import AIReasoningLedger


def test_ai_duel_demo_generates_ledger_and_proof(tmp_path: Path):
    out = tmp_path / "duel"
    result = AIDuelDemoHarness(
        "config/agent_linux_drone_competition_example.yaml",
        "config/policy_linux_drone_competition_example.yaml",
        str(out),
        execute=False,
    ).run()
    assert result["cycles"]
    assert (out / "ai_reasoning_ledger.jsonl").exists()
    assert (out / "reports" / "proof_report.md").exists()
    assert (out / "reports" / "proof_summary.json").exists()
    summary = json.loads((out / "reports" / "proof_summary.json").read_text())
    assert summary["incident_count"] >= 3
    assert summary["ledger_count"] >= 3
    md = (out / "reports" / "proof_report.md").read_text()
    assert "Defense Loop Architecture" in md
    assert "AI Reasoning Ledger" in md


def test_reasoning_ledger_redacts_and_reads_recent(tmp_path: Path):
    ledger = AIReasoningLedger(str(tmp_path / "ledger.jsonl"), enabled=True)
    incident = {
        "incident_id": "INC-1",
        "agent_id": "agent",
        "host": "h",
        "score": 90,
        "confidence": "critical",
        "attack_type": "test",
        "chain": {"events": []},
        "analysis": {"api_key": "sk-secret", "recommended_actions": []},
        "actions": [],
        "denied_actions": [],
        "verification": {},
        "loop_process": [],
    }
    ledger.append_incident(incident)
    rows = ledger.read_recent(1)
    assert rows[0]["analysis"]["api_key"] == "***REDACTED***"


def test_proof_report_from_empty_db(tmp_path: Path):
    audit = tmp_path / "audit.db"
    out = tmp_path / "proof"
    res = ProofReportGenerator(str(audit)).write(str(out))
    assert res["ok"] is True
    assert (out / "proof_report.md").exists()
    assert (out / "proof_summary.json").exists()
