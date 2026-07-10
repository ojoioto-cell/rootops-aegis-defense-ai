from pathlib import Path
import json

from aegis_agent.collectors.snapshot import collect_file_events, collect_persistence_events
from aegis_agent.core.duel_demo import AIDuelDemoHarness
from aegis_agent.core.proof import ProofReportGenerator
from aegis_central import server as central_server


def test_v0212_event_path_parsers_use_first_absolute_path(tmp_path: Path):
    file_log = tmp_path / "file_events.log"
    file_log.write_text("/tmp/.x CREATE mode=755 sha256=demo\n", encoding="utf-8")
    ev = collect_file_events(str(file_log))[0]
    assert ev.file_path == "/tmp/.x"
    assert ev.metadata["paths"] == ["/tmp/.x"]

    persistence_log = tmp_path / "persistence.log"
    persistence_log.write_text("/etc/cron.d/aegis-demo /tmp/.x\n", encoding="utf-8")
    ev = collect_persistence_events(str(persistence_log))[0]
    assert ev.file_path == "/etc/cron.d/aegis-demo"
    assert ev.metadata["paths"][:2] == ["/etc/cron.d/aegis-demo", "/tmp/.x"]


def test_v0212_ai_duel_execute_successes_file_and_persistence(tmp_path: Path):
    out = tmp_path / "duel-exec"
    res = AIDuelDemoHarness(
        "config/agent_linux_drone_competition_example.yaml",
        "config/policy_linux_drone_competition_example.yaml",
        str(out),
        execute=True,
    ).run()
    assert res["cycles"]
    full = json.loads((out / "reports" / "proof_evidence_full.json").read_text())
    statuses = full["action_status"]
    assert statuses.get("failed", 0) == 0
    assert statuses.get("success", 0) >= 3
    actions = full["recent_actions"]
    assert any(a["action"] == "quarantine_file" and a["status"] == "success" for a in actions)
    assert any(a["action"] == "disable_persistence" and a["status"] == "success" for a in actions)
    assert (out / "reports" / "proof_evidence_full.json").exists()


def test_v0212_proof_summary_is_compact_and_full_is_separate(tmp_path: Path):
    out = tmp_path / "proof"
    res = ProofReportGenerator(str(tmp_path / "audit.db"), include_nftables=False).write(str(out))
    assert res["ok"] is True
    compact = json.loads((out / "proof_summary.json").read_text())
    full = json.loads((out / "proof_evidence_full.json").read_text())
    assert "recent_incidents" not in compact
    assert "recent_incidents" in full
    assert compact["nftables_proof"]["available"] is False


def test_v0212_central_version_matches_release():
    assert central_server.CENTRAL_VERSION == "0.3.1"
