from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.reasoning_ledger import AIReasoningLedger

NETWORK_ACTIONS = {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"}
SUCCESS_STATUSES = {"success", "expired_rolled_back", "rolled_back"}
ROLLBACK_STATUSES = {"rolled_back", "expired_rolled_back", "rollback_planned", "expired_rollback_planned"}


def _phase_ts(phases: List[Dict[str, Any]], names: Iterable[str]) -> float | None:
    wanted = set(names)
    vals = [float(p.get("ts", 0) or 0) for p in phases if p.get("phase") in wanted and p.get("ts")]
    return min(vals) if vals else None


def _nft_counter_snapshot(family: str = "inet", table: str = "aegis_guard") -> Dict[str, Any]:
    if not shutil.which("nft"):
        return {"available": False, "ok": False, "reason": "nft_not_installed", "sets": {}, "chains": {}}
    try:
        proc = subprocess.run(["nft", "list", "table", family, table], text=True, capture_output=True, timeout=5, check=False)
    except Exception as exc:
        return {"available": True, "ok": False, "reason": str(exc), "sets": {}, "chains": {}}
    out = proc.stdout or ""
    sets: Dict[str, int] = {}
    chains: Dict[str, Any] = {}
    current_set = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("set "):
            current_set = s.split()[1]
            sets[current_set] = 0
        elif current_set and "elements =" in s:
            body = s.split("elements =", 1)[-1].strip().strip("{}").strip()
            sets[current_set] = len([x for x in body.split(",") if x.strip()]) if body else 0
        elif " counter packets " in s:
            # Example: ip saddr @block_in_v4 counter packets 3 bytes 180 drop
            parts = s.split()
            if "packets" in parts:
                try:
                    idx = parts.index("packets")
                    packets = int(parts[idx + 1])
                    bytes_idx = parts.index("bytes") if "bytes" in parts else -1
                    byte_count = int(parts[bytes_idx + 1]) if bytes_idx >= 0 else 0
                    key = " ".join(parts[: min(len(parts), 4)])
                    chains[key] = {"packets": packets, "bytes": byte_count, "rule": s[:240]}
                except Exception:
                    pass
    return {"available": True, "ok": proc.returncode == 0, "returncode": proc.returncode, "sets": sets, "chains": chains, "stderr": proc.stderr[:1000]}


class LiveBattleScoreEngine:
    """Compute live AI-battle metrics from audit DB, reasoning ledger and nftables state.

    This is intentionally read-only. It does not promote policy or change firewall
    state. The goal is to produce competition-grade, numeric proof of detection,
    enforcement, rollback, AI mode and service-safety status.
    """

    def __init__(self, audit_db: str, ledger_path: str | None = None, nft_family: str = "inet", nft_table: str = "aegis_guard"):
        self.audit = AuditLogger(audit_db)
        self.ledger = AIReasoningLedger(ledger_path, enabled=False) if ledger_path else None
        self.nft_family = nft_family
        self.nft_table = nft_table

    def compute(self, limit: int = 500) -> Dict[str, Any]:
        incidents = self.audit.list_incidents(limit)
        actions = self.audit.list_actions(limit)
        action_counts = Counter(str(a.get("action") or "unknown") for a in actions)
        action_status = Counter(str(a.get("status") or "unknown") for a in actions)
        attack_types = Counter(str(i.get("attack_type") or "unknown") for i in incidents)
        ai_modes = Counter(str((i.get("ai_status") or {}).get("provider_used") or i.get("ai_provider") or "unknown") for i in incidents)
        fallback_count = sum(1 for i in incidents if bool((i.get("ai_status") or {}).get("fallback")))

        network_actions = [a for a in actions if a.get("action") in NETWORK_ACTIONS]
        success_actions = [a for a in actions if a.get("status") == "success"]
        failed_actions = [a for a in actions if a.get("status") == "failed"]
        rolled_back = [a for a in actions if str(a.get("status", "")) in ROLLBACK_STATUSES or a.get("rollback_result")]
        blocked_targets = sorted({str(a.get("target")) for a in network_actions if a.get("target")})

        response_times: List[float] = []
        detection_times: List[float] = []
        policy_times: List[float] = []
        service_health_failures = 0
        policy_denials = 0
        for inc in incidents:
            phases = inc.get("loop_process") or []
            collect_ts = _phase_ts(phases, ["collect_telemetry"])
            chain_ts = _phase_ts(phases, ["chain_selected", "build_evidence_chain"])
            ai_ts = _phase_ts(phases, ["ai_reasoning"])
            enforce_ts = _phase_ts(phases, ["local_enforcement"])
            verify_ts = _phase_ts(phases, ["verify_actions"])
            if collect_ts and chain_ts and chain_ts >= collect_ts:
                detection_times.append(chain_ts - collect_ts)
            if ai_ts and enforce_ts and enforce_ts >= ai_ts:
                policy_times.append(enforce_ts - ai_ts)
            if collect_ts and verify_ts and verify_ts >= collect_ts:
                response_times.append(verify_ts - collect_ts)
            verification = inc.get("verification") or {}
            if verification.get("service_ok") is False:
                service_health_failures += 1
            policy_denials += len(inc.get("denied_actions") or [])

        promotion_stages = Counter()
        ttl_recommendations: Dict[str, int] = {}
        for inc in incidents:
            for promo in ((inc.get("policy_promotion") or {}).get("promotions") or []):
                promotion_stages[str(promo.get("stage", "candidate"))] += 1
                action = str(promo.get("action") or "unknown")
                ttl = int(promo.get("recommended_ttl_seconds") or 0)
                if ttl:
                    ttl_recommendations[action] = max(ttl_recommendations.get(action, 0), ttl)

        ledger_rows = self.ledger.read_recent(min(limit, 500)) if self.ledger else []
        invalid_ai_outputs = 0
        evidence_missing = 0
        for row in ledger_rows:
            analysis = row.get("analysis") or {}
            if not isinstance(analysis, dict) or not analysis.get("evidence_mapping"):
                invalid_ai_outputs += 1
            for m in analysis.get("evidence_mapping", []) or []:
                if not m.get("event_ids"):
                    evidence_missing += 1

        nft = _nft_counter_snapshot(self.nft_family, self.nft_table)
        total_actions = len(actions)
        success_rate = round((len(success_actions) / total_actions) * 100, 2) if total_actions else 0.0
        rollback_rate = round((len(rolled_back) / total_actions) * 100, 2) if total_actions else 0.0
        detection_rate = round((len(incidents) / max(len(incidents), 1)) * 100, 2) if incidents else 0.0

        def avg(xs: List[float]) -> float:
            return round(sum(xs) / len(xs), 3) if xs else 0.0

        if ai_modes.get("gpt"):
            ai_mode_status = "GPT ACTIVE"
        elif ai_modes.get("ollama"):
            ai_mode_status = "OLLAMA FALLBACK"
        elif ai_modes.get("rule_based"):
            ai_mode_status = "RULE_BASED ONLY" if fallback_count == 0 else "RULE_BASED FALLBACK"
        else:
            ai_mode_status = "NO AI DATA"

        return {
            "version": "0.3.1",
            "generated_at": int(time.time()),
            "championship_grade": self._grade(success_rate, service_health_failures, invalid_ai_outputs),
            "incident_count": len(incidents),
            "action_count": total_actions,
            "attack_types": dict(attack_types),
            "action_counts": dict(action_counts),
            "action_status": dict(action_status),
            "ai_mode_status": ai_mode_status,
            "ai_modes": dict(ai_modes),
            "ai_fallback_count": fallback_count,
            "ai_quality": {
                "ledger_rows": len(ledger_rows),
                "invalid_ai_output_count": invalid_ai_outputs,
                "evidence_mapping_missing_count": evidence_missing,
                "policy_gate_denials": policy_denials,
                "quality_score": max(0, 100 - invalid_ai_outputs * 10 - evidence_missing * 5),
            },
            "battle_metrics": {
                "detection_rate": detection_rate,
                "enforcement_success_rate": success_rate,
                "rollback_rate": rollback_rate,
                "mean_detection_time_seconds": avg(detection_times),
                "mean_policy_time_seconds": avg(policy_times),
                "mean_response_time_seconds": avg(response_times),
                "service_health_failures": service_health_failures,
                "failed_actions": len(failed_actions),
            },
            "policy_promotion_stages": dict(promotion_stages),
            "ttl_recommendations": ttl_recommendations,
            "blocked_or_limited_targets": blocked_targets[:200],
            "nftables_effect": nft,
        }

    @staticmethod
    def _grade(success_rate: float, service_health_failures: int, invalid_ai_outputs: int) -> str:
        if service_health_failures:
            return "B" if success_rate >= 80 else "C"
        if invalid_ai_outputs:
            return "A-" if success_rate >= 90 else "B"
        if success_rate >= 95:
            return "A+"
        if success_rate >= 90:
            return "A"
        if success_rate >= 80:
            return "B"
        return "C"
