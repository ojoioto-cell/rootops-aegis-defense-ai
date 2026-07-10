from aegis_agent.collectors.auth_log import collect_auth_events
from aegis_agent.collectors.web_log import collect_web_events
from aegis_agent.collectors.snapshot import collect_process_snapshot, collect_network_snapshot, collect_file_events, collect_persistence_events
from aegis_agent.evidence.builder import build_evidence_chains


def test_sample_chain_scores_high():
    events = []
    events += collect_auth_events(["sample_data/auth.log"])
    events += collect_web_events(["sample_data/access.log", "sample_data/error.log"])
    events += collect_process_snapshot("sample_data/processes.txt")
    events += collect_network_snapshot("sample_data/network.txt")
    events += collect_file_events("sample_data/file_events.log")
    events += collect_persistence_events("sample_data/persistence.log")
    chains = build_evidence_chains(events)
    assert chains
    assert max(c.score for c in chains) >= 90
