from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from aegis_agent.models import ActionPlan, EvidenceChain
from aegis_agent.utils import ip_in_allowlist, validate_enforcement_ip


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyGate:
    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy.get("policy", policy)

    def check(self, plan: ActionPlan, chain: EvidenceChain) -> PolicyDecision:
        actions = self.policy.get("actions", {})
        action_policy = actions.get(plan.action)
        if not action_policy:
            return PolicyDecision(False, f"Action {plan.action} is not defined in policy")
        if not action_policy.get("enabled", False):
            return PolicyDecision(False, f"Action {plan.action} is disabled")
        if not action_policy.get("auto_allowed", False):
            return PolicyDecision(False, f"Action {plan.action} requires human approval")

        min_score = int(action_policy.get("min_score", 100))
        if plan.score < min_score:
            return PolicyDecision(False, f"Score {plan.score} below action minimum {min_score}")

        evidence_policy = self.policy.get("evidence", {})
        min_events = int(evidence_policy.get("min_events_for_response", 1))
        try:
            metadata_min = plan.metadata.get("min_evidence_required") if isinstance(plan.metadata, dict) else None
            if metadata_min is not None:
                min_events = min(min_events, max(1, int(metadata_min)))
        except Exception:
            pass
        if len(plan.evidence_ids) < min_events:
            return PolicyDecision(False, f"Evidence count {len(plan.evidence_ids)} below minimum {min_events}")

        if plan.action in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip", "isolate_host"}:
            ok, reason = validate_enforcement_ip(plan.target)
            if not ok:
                return PolicyDecision(False, f"Unsafe or invalid IP target: {reason}")
            if self._ip_is_protected(plan.target):
                return PolicyDecision(False, f"Target IP {plan.target} is protected by allowlist")

        if action_policy.get("ttl_required", False) and not plan.ttl_seconds:
            return PolicyDecision(False, "TTL is required but missing")

        if action_policy.get("rollback_required", False) and not plan.rollback_supported:
            return PolicyDecision(False, "Rollback is required but not supported")

        if plan.action == "suspend_process":
            if self._process_is_protected(plan.target):
                return PolicyDecision(False, f"Process target is protected: {plan.target}")
            if action_policy.get("require_auditd_pid_relation", True):
                meta = plan.metadata or {}
                if not meta.get("requires_auditd_pid_relation") or not meta.get("audit_serial"):
                    return PolicyDecision(False, "suspend_process requires verified auditd PID/PPID evidence")

        if plan.action == "restrict_account":
            if self._account_is_protected(plan.target):
                return PolicyDecision(False, f"Account target is protected: {plan.target}")

        return PolicyDecision(True, "Policy check passed")

    def _ip_is_protected(self, target: str) -> bool:
        allow = self.policy.get("allowlists", {})
        return ip_in_allowlist(target, allow.get("ips", []), allow.get("cidrs", []))

    def _process_is_protected(self, target: str) -> bool:
        names = self.policy.get("allowlists", {}).get("process_names", [])
        target_l = (target or "").lower()
        return any(name.lower() in target_l for name in names)

    def _account_is_protected(self, target: str) -> bool:
        accounts = set(self.policy.get("allowlists", {}).get("accounts", []))
        return target in accounts
