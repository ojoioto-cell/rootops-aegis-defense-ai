from __future__ import annotations

from typing import Any, Dict, List, Set

DANGEROUS_ACTIONS = {"kill_process", "isolate_host", "restrict_account", "suspend_process"}


class AIReasoningQualityGuard:
    """Validate AI output against evidence and competition safety constraints."""

    def evaluate(self, analysis: Dict[str, Any], evidence_ids: List[str], denied_actions: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        ids: Set[str] = set(evidence_ids)
        issues: List[Dict[str, Any]] = []
        if not isinstance(analysis, dict):
            return {"ok": False, "quality_score": 0, "issues": [{"type": "analysis_not_dict"}]}
        mappings = analysis.get("evidence_mapping") or []
        if not mappings:
            issues.append({"type": "missing_evidence_mapping"})
        for m in mappings:
            eids = m.get("event_ids") or []
            if not eids:
                issues.append({"type": "claim_without_evidence", "claim": m.get("claim", "")})
            for eid in eids:
                if eid not in ids:
                    issues.append({"type": "unknown_evidence_id", "event_id": eid, "claim": m.get("claim", "")})
        denied_dangerous = set()
        if denied_actions:
            for d in denied_actions:
                plan = d.get("plan") or {}
                if plan.get("action") in DANGEROUS_ACTIONS:
                    denied_dangerous.add(plan.get("action"))
                    issues.append({"type": "policy_gate_blocked_risky_recommendation", "action": plan.get("action"), "reason": d.get("reason"), "severity": "low"})
        recs = analysis.get("recommended_actions") or []
        for rec in recs:
            action = rec.get("action")
            if action in DANGEROUS_ACTIONS and action not in denied_dangerous:
                issues.append({"type": "dangerous_action_recommended_without_policy_denial", "action": action})
            if action in {"block_ip_ttl", "block_outbound_ip", "rate_limit_ip"} and not rec.get("target"):
                # Rule engine may fill target later; keep this as low severity rather than fatal.
                issues.append({"type": "network_action_without_explicit_target", "action": action, "severity": "low"})
        penalty = 0
        for issue in issues:
            if issue.get("severity") == "low":
                penalty += 3
            elif issue.get("type") == "policy_gate_blocked_risky_recommendation":
                penalty += 5
            else:
                penalty += 10
        score = max(0, 100 - penalty)
        blocking_issues = [i for i in issues if i.get("severity") != "low"]
        return {"ok": score >= 70 and not blocking_issues, "quality_score": score, "issue_count": len(issues), "blocking_issue_count": len(blocking_issues), "issues": issues[:50]}
