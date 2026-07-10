from __future__ import annotations

from typing import Any, Dict

from aegis_agent.models import ActionPlan, ActionResult
from .network_guard import NetworkGuard
from .process_guard import ProcessGuard
from .file_guard import FileGuard
from .persistence_guard import PersistenceGuard
from .account_guard import AccountGuard


class LocalEnforcementLayer:
    def __init__(self, dry_run: bool = True, backend: str = "nftables", quarantine_dir: str = "data/quarantine", config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.network = NetworkGuard(dry_run, backend, self.config)
        self.process = ProcessGuard(dry_run)
        self.file = FileGuard(dry_run, quarantine_dir)
        self.persistence = PersistenceGuard(dry_run, self.config)
        self.account = AccountGuard(dry_run)
        self.dry_run = dry_run

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.action in {"block_ip_ttl", "block_outbound_ip", "rate_limit_ip"}:
            return self.network.execute(plan)
        if plan.action in {"suspend_process"}:
            return self.process.execute(plan)
        if plan.action in {"quarantine_file"}:
            return self.file.execute(plan)
        if plan.action in {"disable_persistence"}:
            return self.persistence.execute(plan)
        if plan.action in {"restrict_account"}:
            return self.account.execute(plan)
        return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, "No executor for action")
