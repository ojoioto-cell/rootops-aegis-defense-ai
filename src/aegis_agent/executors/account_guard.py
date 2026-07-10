from __future__ import annotations

from aegis_agent.models import ActionPlan, ActionResult


class AccountGuard:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def execute(self, plan: ActionPlan) -> ActionResult:
        # Disabled by default policy. Keep as placeholder for approval-based workflow.
        rollback = {"type": "unlock_account", "user": plan.target}
        return ActionResult(plan.action_id, plan.action, plan.target, "planned" if self.dry_run else "skipped", self.dry_run, "Account restriction requires explicit approval policy", rollback)
