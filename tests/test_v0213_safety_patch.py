from pathlib import Path

from aegis_agent.collectors.snapshot import collect_network_snapshot
from aegis_agent.executors.network_guard import NetworkGuard
from aegis_agent.models import ActionPlan, EvidenceChain, Event
from aegis_agent.core.policy_gate import PolicyGate
from aegis_agent.evidence.builder import build_evidence_chains
import time


def test_v0213_network_snapshot_ignores_wildcard_udp_listeners(tmp_path: Path):
    p = tmp_path / "network.txt"
    p.write_text(
        'udp   UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=687,fd=12))\n'
        'udp   UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=529,fd=16))\n'
        'tcp   ESTAB 0 0 192.168.13.20:44444 45.77.1.2:443 users:(("curl",pid=777,fd=3))\n',
        encoding="utf-8",
    )
    events = collect_network_snapshot(str(p))
    assert len(events) == 1
    assert events[0].dst_ip == "45.77.1.2"
    assert events[0].event_type == "external_network_connection"


def test_v0213_network_guard_rejects_unsafe_targets():
    guard = NetworkGuard(dry_run=False, backend="memory", config={"require_root": False})
    for ip in ["0.0.0.0", "::", "127.0.0.1", "224.0.0.1", "255.255.255.255"]:
        plan = ActionPlan("ACT-SAFE", "block_outbound_ip", ip, "test", ["E1"], 100, ttl_seconds=60)
        res = guard.execute(plan)
        assert res.status == "failed"
        assert res.error == "invalid_ip"


def test_v0213_policy_gate_rejects_unsafe_ip_before_enforcement():
    policy = {"policy": {"actions": {"block_outbound_ip": {"enabled": True, "auto_allowed": True, "min_score": 1, "ttl_required": True, "rollback_required": True}}, "allowlists": {"ips": [], "cidrs": []}, "evidence": {"min_events_for_response": 1}}}
    gate = PolicyGate(policy)
    chain = EvidenceChain("C1", "h", [], {}, score=100)
    plan = ActionPlan("ACT-1", "block_outbound_ip", "0.0.0.0", "test", ["E1"], 100, ttl_seconds=60)
    decision = gate.check(plan, chain)
    assert decision.allowed is False
    assert "Unsafe or invalid" in decision.reason


def test_v0213_self_protection_separated_from_network_context():
    now = time.time()
    events = [
        Event("E-SP", now, "self_protection", "agent_integrity_change", "h", "critical", "agent_integrity_change_detected"),
        Event("E-NET", now, "network_snapshot", "external_network_connection", "h", "high", "tcp ESTAB", dst_ip="45.77.1.2"),
    ]
    chains = build_evidence_chains(events)
    assert len(chains) == 2
    assert any([e.event_type for e in c.events] == ["agent_integrity_change"] for c in chains)
