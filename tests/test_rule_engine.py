from aegis_agent.ai.rule_engine import analyze_chain
from aegis_agent.models import EvidenceChain, Event


def ev(event_id, event_type, user=None):
    return Event(
        event_id=event_id,
        timestamp=1.0,
        source="test",
        event_type=event_type,
        host="host",
        severity="high",
        raw="raw",
        user=user,
    )


def test_restrict_account_prefers_successful_login_user():
    chain = EvidenceChain(
        chain_id="CHAIN-test",
        host="host",
        events=[
            ev("E1", "ssh_failed_login", "root"),
            ev("E2", "ssh_failed_login", "admin"),
            ev("E3", "ssh_success_login", "user01"),
            ev("E4", "sudo_execution", "user01"),
        ],
        entities={"user": ["admin", "root", "user01"]},
        score=100,
        confidence="critical",
        attack_type="account_compromise_suspected",
        hypothesis="possible_compromised_account_after_bruteforce",
        reasons=["test"],
    )
    analysis = analyze_chain(chain)
    restrict = [a for a in analysis.recommended_actions if a["action"] == "restrict_account"]
    assert restrict
    assert restrict[0]["target"] == "user01"
