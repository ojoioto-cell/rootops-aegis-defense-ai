from aegis_agent.executors.network_guard import NetworkGuard
from aegis_agent.models import ActionPlan


def test_nftables_dry_run_block_builds_timeout_set_command():
    guard = NetworkGuard(dry_run=True, backend="nftables", config={"nft_table": "aegis_guard"})
    plan = ActionPlan("ACT-1", "block_ip_ttl", "203.0.113.10", "test", ["E1", "E2", "E3"], 90, ttl_seconds=120)
    result = guard.execute(plan)
    assert result.status == "planned"
    assert result.rollback["backend"] == "nftables"
    assert result.rollback["command"][:4] == ["nft", "delete", "element", "inet"]
    assert "timeout" in result.command
    assert "120s" in result.command


def test_memory_backend_real_enforcement_path_returns_success_without_os_change():
    guard = NetworkGuard(dry_run=False, backend="memory", config={"require_root": False})
    plan = ActionPlan("ACT-2", "block_ip_ttl", "203.0.113.20", "test", ["E1", "E2", "E3"], 90, ttl_seconds=60)
    result = guard.execute(plan)
    assert result.status == "success"
    assert result.dry_run is False
    assert result.rollback["backend"] == "memory"


def test_invalid_ip_is_rejected():
    guard = NetworkGuard(dry_run=True, backend="nftables")
    plan = ActionPlan("ACT-3", "block_ip_ttl", "not-an-ip", "test", ["E1", "E2", "E3"], 90, ttl_seconds=60)
    result = guard.execute(plan)
    assert result.status == "failed"
    assert result.error == "invalid_ip"


def test_rate_limit_dry_run_builds_rate_set_command():
    guard = NetworkGuard(dry_run=True, backend="nftables", config={"rate_limit": {"tcp_syn_per_second": 10}})
    plan = ActionPlan("ACT-4", "rate_limit_ip", "203.0.113.30", "test", ["E1", "E2", "E3"], 90, ttl_seconds=180)
    result = guard.execute(plan)
    assert result.status == "planned"
    assert "rate_limit_v4" in result.command
    assert "180s" in result.command
