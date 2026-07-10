from __future__ import annotations

import time
from pathlib import Path

from aegis_agent.ai.rule_engine import analyze_chain
from aegis_agent.core.security_growth import SecurityGrowthMemory
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.models import Event, new_id


def test_ssh_bruteforce_ten_failures_creates_block_and_rate_limit():
    now = time.time()
    events = [
        Event(new_id("E"), now + i, "auth.log", "ssh_failed_login", "host", "medium", "Failed password", src_ip="198.51.100.99", user="root", process="sshd")
        for i in range(10)
    ]
    chain = build_evidence_chains(events)[0]
    assert chain.score >= 60
    analysis = analyze_chain(chain)
    actions = {a["action"] for a in analysis.recommended_actions}
    assert "block_ip_ttl" in actions
    assert "rate_limit_ip" in actions


def test_security_growth_learns_and_adds_bounded_bonus(tmp_path: Path):
    mem = SecurityGrowthMemory(str(tmp_path), enabled=True, repeat_ip_score_bonus=15, auto_learn_min_score=60)
    incident = {
        "score": 80,
        "attack_type": "ssh_bruteforce",
        "chain": {"entities": {"src_ip": ["198.51.100.88"], "dst_ip": []}},
        "actions": [{"action": "block_ip_ttl", "target": "198.51.100.88", "status": "success"}],
    }
    learned = mem.learn_from_incident(incident)
    assert "198.51.100.88" in learned["learned"]

    ev = Event(new_id("E"), time.time(), "auth.log", "ssh_failed_login", "host", "medium", "Failed password", src_ip="198.51.100.88", user="root")
    chain = build_evidence_chains([ev])[0]
    observed = mem.observe_chain(chain)
    assert observed["score_bonus"] == 15
    assert "198.51.100.88" in observed["matched_ips"]
