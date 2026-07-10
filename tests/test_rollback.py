from aegis_agent.executors.rollback import RollbackExecutor


def test_rollback_dry_run_command_is_planned():
    action = {
        "action_id": "ACT-1",
        "action": "block_ip_ttl",
        "target": "203.0.113.10",
        "rollback": {
            "type": "network_rollback",
            "command": ["nft", "delete", "element", "inet", "aegis_guard", "block_in_v4", "{", "203.0.113.10", "}"],
        },
    }
    result = RollbackExecutor(dry_run=True).execute(action)
    assert result["rollback_status"] == "planned"
    assert result["command"][0] == "nft"


def test_memory_backend_network_rollback_is_success_without_command():
    action = {
        "action_id": "ACT-memory",
        "action": "block_ip_ttl",
        "target": "198.51.100.50",
        "rollback": {
            "type": "network_rollback",
            "backend": "memory",
            "target": "198.51.100.50",
            "mode": "block",
        },
    }
    result = RollbackExecutor(dry_run=False).execute(action)
    assert result["rollback_status"] == "success"
    assert result["command"][0] == "memory-backend"
