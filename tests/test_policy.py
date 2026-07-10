from aegis_agent.core.policy_gate import PolicyGate
from aegis_agent.models import ActionPlan, EvidenceChain, Event
import time


def test_policy_blocks_allowlisted_ip():
    policy = {
        "policy": {
            "actions": {"block_ip_ttl": {"enabled": True, "auto_allowed": True, "min_score": 1, "ttl_required": True, "rollback_required": True}},
            "evidence": {"min_events_for_response": 1},
            "allowlists": {"ips": ["127.0.0.1"], "cidrs": [], "process_names": [], "accounts": []},
        }
    }
    gate = PolicyGate(policy)
    ev = Event("E1", time.time(), "test", "x", "h")
    ch = EvidenceChain("C1", "h", [ev], {"src_ip": ["127.0.0.1"]}, score=99)
    plan = ActionPlan("A1", "block_ip_ttl", "127.0.0.1", "test", ["E1"], 99, ttl_seconds=60)
    assert not gate.check(plan, ch).allowed
