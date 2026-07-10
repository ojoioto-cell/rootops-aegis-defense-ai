from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.utils import ensure_dir


class PolicyPromotionEngine:
    """Evidence-driven candidate/shadow/enforce/promote tracker.

    v0.2.16 Championship Mode improvement:
      - Promotion no longer remains a label only.
      - A promoted record produces safe *candidates* for central IOC, TTL recommendation,
        and shadow policy/approval artifacts.
      - It still does not directly edit active policy or bypass Policy Gate. Active policy
        application is intentionally approval-based.
    """

    def __init__(self, state_dir: str = "data/state", enabled: bool = True, shadow_after: int = 2, enforce_after: int = 3, promote_after_success: int = 3):
        self.enabled = bool(enabled)
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "policy_promotions.json"
        self.shadow_after = int(shadow_after)
        self.enforce_after = int(enforce_after)
        self.promote_after_success = int(promote_after_success)
        ensure_dir(self.state_dir)
        self.data: Dict[str, Any] = {"version": 2, "candidates": {}}
        self._load()

    def _load(self) -> None:
        if not self.enabled or not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
                self.data.setdefault("candidates", {})
                self.data["version"] = max(int(self.data.get("version", 1)), 2)
        except Exception:
            self.data = {"version": 2, "candidates": {}}

    def _save(self) -> None:
        if not self.enabled:
            return
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _key(action: str, target: str, attack_type: str) -> str:
        return f"{action}|{attack_type or 'unknown'}"

    @staticmethod
    def _safe_ip(target: str) -> bool:
        try:
            ip = ipaddress.ip_address(str(target))
        except ValueError:
            return False
        return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved)

    @staticmethod
    def _recommended_ttl(action: str, observations: int, successes: int) -> int:
        base = {
            "rate_limit_ip": 1800,
            "block_ip_ttl": 3600,
            "block_outbound_ip": 7200,
            "quarantine_file": 0,
            "disable_persistence": 0,
        }.get(action, 3600)
        if base <= 0:
            return 0
        multiplier = 1
        if observations >= 3 or successes >= 2:
            multiplier = 2
        if observations >= 6 or successes >= 4:
            multiplier = 4
        return min(base * multiplier, 604800)

    def _build_shadow_policy(self, action: str, attack_type: str, ttl: int) -> Dict[str, Any]:
        patch: Dict[str, Any] = {
            "kind": "shadow_policy_patch",
            "attack_type": attack_type,
            "approval_required": True,
            "safe_application": "candidate_only_until_operator_approval",
            "policy_patch": {
                "actions": {
                    action: {
                        "enabled": True,
                        "auto_allowed": True,
                        "ttl_required": action in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"},
                        "rollback_required": True,
                    }
                }
            },
        }
        if ttl:
            patch["policy_patch"]["actions"][action]["recommended_ttl_seconds"] = ttl
        return patch

    def _build_ioc_candidate(self, action: str, target: str, attack_type: str, ttl: int, observations: int, successes: int) -> Dict[str, Any] | None:
        if action not in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"}:
            return None
        if not self._safe_ip(target):
            return None
        return {
            "indicator": target,
            "type": "ip",
            "action": "block_outbound_ip" if action == "block_outbound_ip" else "block_ip_ttl",
            "confidence": min(95, 70 + successes * 5 + observations * 2),
            "ttl_seconds": ttl or 86400,
            "source": "aegis_policy_promotion",
            "attack_type": attack_type,
            "promotion_stage": "promoted",
            "approval_required_for_active_policy": False,
        }

    def observe_incident(self, incident: Dict[str, Any], verification: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "promotions": []}
        now = int(time.time())
        attack_type = str(incident.get("attack_type") or "unknown")
        actions = incident.get("actions") or []
        service_ok = True if verification is None else bool(verification.get("service_ok", True))
        promotions: List[Dict[str, Any]] = []
        for a in actions:
            action = str(a.get("action") or "")
            target = str(a.get("target") or "")
            status = str(a.get("status") or "")
            if action not in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip", "quarantine_file", "disable_persistence"}:
                continue
            if status not in {"success", "planned"}:
                continue
            key = self._key(action, target, attack_type)
            rec = self.data.setdefault("candidates", {}).setdefault(key, {
                "action": action,
                "attack_type": attack_type,
                "first_seen": now,
                "observations": 0,
                "successes": 0,
                "stage": "candidate",
                "targets": [],
                "approval_required": True,
                "active_policy_status": "not_requested",
            })
            rec["last_seen"] = now
            rec["observations"] = int(rec.get("observations", 0)) + 1
            if service_ok and status == "success":
                rec["successes"] = int(rec.get("successes", 0)) + 1
            targets = rec.setdefault("targets", [])
            if target and target not in targets:
                targets.append(target)
                del targets[20:]
            obs = int(rec.get("observations", 0))
            succ = int(rec.get("successes", 0))
            stage = "candidate"
            if obs >= self.shadow_after:
                stage = "shadow"
            if obs >= self.enforce_after and succ >= 1:
                stage = "enforce_verified"
            if succ >= self.promote_after_success:
                stage = "promoted"
            rec["stage"] = stage
            rec["last_incident_id"] = incident.get("incident_id")
            rec["recommended_ttl_seconds"] = self._recommended_ttl(action, obs, succ)
            rec["shadow_policy"] = self._build_shadow_policy(action, attack_type, int(rec.get("recommended_ttl_seconds") or 0))
            if stage == "promoted":
                rec["ioc_candidate"] = self._build_ioc_candidate(action, target, attack_type, int(rec.get("recommended_ttl_seconds") or 0), obs, succ)
                rec["active_policy_status"] = "pending_operator_approval"
                rec["approval_request"] = {
                    "requested_action": "promote_shadow_policy",
                    "candidate_key": key,
                    "attack_type": attack_type,
                    "action": action,
                    "target": target,
                    "recommended_ttl_seconds": rec.get("recommended_ttl_seconds"),
                    "shadow_policy": rec.get("shadow_policy"),
                    "reason": "Repeated successful defensive response reached promoted stage; operator approval is required before active policy mutation.",
                }
            promotions.append({
                "key": key,
                "action": action,
                "target": target,
                "stage": stage,
                "observations": obs,
                "successes": succ,
                "recommended_ttl_seconds": rec.get("recommended_ttl_seconds", 0),
                "ioc_candidate": rec.get("ioc_candidate"),
                "shadow_policy": rec.get("shadow_policy"),
                "approval_request": rec.get("approval_request"),
                "active_policy_status": rec.get("active_policy_status", "not_requested"),
            })
        if promotions:
            self._save()
        return {"enabled": True, "promotions": promotions, "store": str(self.path)}

    def summary(self) -> Dict[str, Any]:
        candidates = list((self.data.get("candidates") or {}).values()) if self.enabled else []
        stages: Dict[str, int] = {}
        ioc_candidates = 0
        approval_pending = 0
        ttl_recommendations: Dict[str, int] = {}
        for c in candidates:
            stage = str(c.get("stage", "candidate"))
            stages[stage] = stages.get(stage, 0) + 1
            if c.get("ioc_candidate"):
                ioc_candidates += 1
            if c.get("active_policy_status") == "pending_operator_approval":
                approval_pending += 1
            action = str(c.get("action", "unknown"))
            ttl = int(c.get("recommended_ttl_seconds") or 0)
            if ttl:
                ttl_recommendations[action] = max(ttl_recommendations.get(action, 0), ttl)
        return {
            "enabled": self.enabled,
            "candidate_count": len(candidates),
            "stages": stages,
            "ioc_candidate_count": ioc_candidates,
            "approval_pending_count": approval_pending,
            "ttl_recommendations": ttl_recommendations,
            "store": str(self.path),
        }
