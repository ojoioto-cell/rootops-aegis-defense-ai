from pathlib import Path

from aegis_agent.collectors.drone import collect_drone_events
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.ai.rule_engine import analyze_chain, build_action_plans
from aegis_agent.core.policy_gate import PolicyGate


def test_drone_unauthorized_gcs_generates_block_action(tmp_path: Path):
    log = tmp_path / "drone.log"
    log.write_text("SRC=192.168.13.50 DST=192.168.13.20 DPT=14550 MAVLINK MSG=COMMAND_LONG SYSID=255 COMPID=1\n", encoding="utf-8")
    events = collect_drone_events({
        "enabled": True,
        "logs": [str(log)],
        "collect_live_ss": False,
        "allowed_gcs_ips": ["192.168.13.10"],
        "allowed_drone_ips": ["192.168.13.20"],
        "allowed_sysids": [1],
        "mavlink_ports": [14550],
    })
    assert any(e.event_type == "drone_command_attempt" for e in events)
    chains = build_evidence_chains(events)
    assert chains
    chain = chains[0]
    assert chain.score >= 60
    analysis = analyze_chain(chain, default_ttl=600)
    plans = build_action_plans(analysis, [e.event_id for e in chain.events])
    assert any(p.action == "block_ip_ttl" and p.target == "192.168.13.50" for p in plans)


def test_drone_policy_allows_single_high_signal_event():
    from aegis_agent.models import ActionPlan, EvidenceChain, Event
    ev = Event("E-1", 0, "drone", "drone_unauthorized_gcs", "h", "critical", src_ip="192.168.13.50")
    chain = EvidenceChain("C-1", "h", [ev], {"src_ip": ["192.168.13.50"]}, score=65)
    plan = ActionPlan("A-1", "block_ip_ttl", "192.168.13.50", "drone_network_guard_source_block", ["E-1"], 65, ttl_seconds=600, metadata={"min_evidence_required": 1})
    policy = {
        "policy": {
            "evidence": {"min_events_for_response": 3},
            "allowlists": {"ips": ["127.0.0.1"], "cidrs": []},
            "actions": {"block_ip_ttl": {"enabled": True, "auto_allowed": True, "min_score": 50, "ttl_required": True, "rollback_required": True}},
        }
    }
    decision = PolicyGate(policy).check(plan, chain)
    assert decision.allowed, decision.reason
