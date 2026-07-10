from pathlib import Path

from aegis_agent.collectors.auth_log import collect_auth_events


def test_sudo_user_parser(tmp_path: Path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jul  4 13:20:10 web01 sudo:   user01 : TTY=pts/0 ; PWD=/home/user01 ; USER=root ; COMMAND=/bin/bash\n",
        encoding="utf-8",
    )
    events = collect_auth_events([str(log)])
    assert len(events) == 1
    assert events[0].event_type == "sudo_execution"
    assert events[0].user == "user01"
    assert events[0].process == "/bin/bash"
