from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.reasoning_ledger import AIReasoningLedger

NETWORK_ACTIONS = {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"}
SUCCESS_STATUSES = {"success", "expired_rolled_back", "rolled_back"}
ROLLBACK_STATUSES = {"rolled_back", "expired_rolled_back", "rollback_planned", "expired_rollback_planned"}
SYNTHETIC_AGENT_MARKERS = {"aegis-ai-duel-demo", "aegis-ai-duel-benchmark", "duel-demo", "duel-benchmark"}


def _phase_ts(phases: List[Dict[str, Any]], names: Iterable[str]) -> float | None:
    wanted = set(names)
    vals = [float(p.get("ts", 0) or 0) for p in phases if p.get("phase") in wanted and p.get("ts")]
    return min(vals) if vals else None


def _avg(xs: List[float]) -> float:
    return round(sum(xs) / len(xs), 3) if xs else 0.0


def _safe_payload(text: str | bytes | None, default: Any) -> Any:
    if text is None:
        return default
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except Exception:
        return default


def _is_synthetic_incident(incident: Dict[str, Any]) -> bool:
    """Return True for controlled demo/test incidents, not live battle evidence.

    Synthetic incidents are useful for proof rehearsals, but the 본선 운영 화면 should
    focus on actual incidents produced by the installed agent.  Detection is deliberately
    conservative: it checks explicit demo agent IDs, audit paths, and known demo telemetry
    paths without treating normal attack simulations in /var/log as synthetic.
    """
    agent_id = str(incident.get("agent_id") or "").lower()
    if any(m in agent_id for m in SYNTHETIC_AGENT_MARKERS):
        return True
    chain = incident.get("chain") or {}
    events = chain.get("events") or []
    for event in events:
        raw = str(event.get("raw") or "")
        source = str(event.get("source") or "")
        meta = event.get("metadata") or {}
        path_blob = " ".join([raw, source, json.dumps(meta, ensure_ascii=False, sort_keys=True)])
        lower = path_blob.lower()
        if "ai_duel_demo" in lower or "ai_duel_benchmark" in lower:
            return True
        if "/telemetry/" in lower and ("aegis-ai-duel" in lower or "duel" in lower):
            return True
    return False


def _action_rows_with_incident(audit: AuditLogger, limit: int = 1000) -> List[Dict[str, Any]]:
    """Read action payloads while preserving their incident_id DB column."""
    rows: List[Dict[str, Any]] = []
    try:
        with sqlite3.connect(audit.db_path) as con:
            cur = con.execute(
                "SELECT incident_id, created_at, payload FROM actions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            for incident_id, created_at, payload_text in cur.fetchall():
                payload = _safe_payload(payload_text, {})
                if not isinstance(payload, dict):
                    continue
                payload.setdefault("incident_id", incident_id)
                payload.setdefault("created_at", created_at)
                rows.append(payload)
    except Exception:
        # Older test DB or corrupted DB: fall back to public payload-only API.
        rows = audit.list_actions(limit)
    return rows


def _nft_table_snapshot(family: str = "inet", table: str = "aegis_guard") -> Dict[str, Any]:
    if not shutil.which("nft"):
        return {"available": False, "ok": False, "reason": "nft_not_installed", "sets": {}, "chains": {}, "real_enforcement_visible": False}
    try:
        proc = subprocess.run(["nft", "list", "table", family, table], text=True, capture_output=True, timeout=5, check=False)
    except Exception as exc:
        return {"available": True, "ok": False, "reason": str(exc), "sets": {}, "chains": {}, "real_enforcement_visible": False}
    out = proc.stdout or ""
    sets: Dict[str, int] = {}
    set_elements: Dict[str, List[str]] = {}
    chains: Dict[str, Any] = {}
    current_set: str | None = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("set "):
            current_set = s.split()[1]
            sets[current_set] = 0
            set_elements[current_set] = []
        elif current_set and "elements =" in s:
            body = s.split("elements =", 1)[-1].strip().strip("{}").strip()
            elems = [x.strip() for x in body.split(",") if x.strip()] if body else []
            sets[current_set] = len(elems)
            set_elements[current_set] = elems[:200]
        elif " counter packets " in s:
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
    return {
        "available": True,
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "sets": sets,
        "set_elements": set_elements,
        "chains": chains,
        "stderr": (proc.stderr or "")[:1000],
        "real_enforcement_visible": proc.returncode == 0,
        "table_excerpt": "\n".join(out.splitlines()[:80]) if proc.returncode == 0 else "",
    }


class LiveBattleEvidenceEngine:
    """Summarize actual battle evidence from runtime incidents/actions.

    Unlike the old AI Duel Benchmark, this engine does not create synthetic attack
    cycles. It reads the current audit database, reasoning ledger and nftables state,
    separates live evidence from optional demo/test proof, and produces operational
    metrics that can be displayed during 본선 AI 공방전.
    """

    def __init__(self, audit_db: str, ledger_path: str | None = None, nft_family: str = "inet", nft_table: str = "aegis_guard"):
        self.audit = AuditLogger(audit_db)
        self.ledger = AIReasoningLedger(ledger_path, enabled=False) if ledger_path else None
        self.nft_family = nft_family or "inet"
        self.nft_table = nft_table or "aegis_guard"

    def _split_incidents(self, incidents: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        synthetic: List[Dict[str, Any]] = []
        live: List[Dict[str, Any]] = []
        for inc in incidents:
            if _is_synthetic_incident(inc):
                synthetic.append(inc)
            else:
                live.append(inc)
        return live, synthetic

    def compute(self, limit: int = 500, include_synthetic: bool = False) -> Dict[str, Any]:
        all_incidents = self.audit.list_incidents(limit)
        live_incidents, synthetic_incidents = self._split_incidents(all_incidents)
        incidents = all_incidents if include_synthetic else live_incidents
        live_ids = {str(i.get("incident_id")) for i in incidents if i.get("incident_id")}
        all_actions = _action_rows_with_incident(self.audit, limit=max(limit * 2, 1000))
        actions = [a for a in all_actions if not live_ids or str(a.get("incident_id")) in live_ids]

        action_counts = Counter(str(a.get("action") or "unknown") for a in actions)
        action_status = Counter(str(a.get("status") or "unknown") for a in actions)
        attack_types = Counter(str(i.get("attack_type") or "unknown") for i in incidents)
        ai_modes = Counter(str((i.get("ai_status") or {}).get("provider_used") or i.get("ai_provider") or "unknown") for i in incidents)
        fallback_count = sum(1 for i in incidents if bool((i.get("ai_status") or {}).get("fallback")))
        policy_denials = sum(len(i.get("denied_actions") or []) for i in incidents)
        service_health_failures = sum(1 for i in incidents if (i.get("verification") or {}).get("service_ok") is False)

        network_actions = [a for a in actions if a.get("action") in NETWORK_ACTIONS]
        success_actions = [a for a in actions if a.get("status") == "success"]
        failed_actions = [a for a in actions if a.get("status") == "failed"]
        rolled_back = [a for a in actions if str(a.get("status", "")) in ROLLBACK_STATUSES or a.get("rollback_result")]
        blocked_targets = sorted({str(a.get("target")) for a in network_actions if a.get("target")})

        response_times: List[float] = []
        detection_times: List[float] = []
        policy_times: List[float] = []
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

        promotion_stages = Counter()
        ttl_recommendations: Dict[str, int] = {}
        promoted_iocs: List[Dict[str, Any]] = []
        shadow_policies: List[Dict[str, Any]] = []
        for inc in incidents:
            for promo in ((inc.get("policy_promotion") or {}).get("promotions") or []):
                stage = str(promo.get("stage", "candidate"))
                promotion_stages[stage] += 1
                action = str(promo.get("action") or "unknown")
                ttl = int(promo.get("recommended_ttl_seconds") or 0)
                if ttl:
                    ttl_recommendations[action] = max(ttl_recommendations.get(action, 0), ttl)
                if promo.get("ioc_candidate"):
                    promoted_iocs.append(promo.get("ioc_candidate"))
                if promo.get("shadow_policy"):
                    shadow_policies.append(promo.get("shadow_policy"))

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

        total_actions = len(actions)
        success_rate = round((len(success_actions) / total_actions) * 100, 2) if total_actions else 0.0
        rollback_rate = round((len(rolled_back) / total_actions) * 100, 2) if total_actions else 0.0
        detection_rate = 100.0 if incidents else 0.0
        nft = _nft_table_snapshot(self.nft_family, self.nft_table)

        if ai_modes.get("gpt"):
            ai_mode_status = "GPT ACTIVE"
        elif ai_modes.get("ollama"):
            ai_mode_status = "OLLAMA FALLBACK"
        elif ai_modes.get("rule_based"):
            ai_mode_status = "RULE_BASED ONLY" if fallback_count == 0 else "RULE_BASED FALLBACK"
        else:
            ai_mode_status = "NO LIVE AI DATA"

        return {
            "version": "0.3.1",
            "engine": "live_battle_evidence",
            "generated_at": int(time.time()),
            "source_scope": "live_only" if not include_synthetic else "live_plus_synthetic",
            "live_incident_count": len(live_incidents),
            "synthetic_incident_count": len(synthetic_incidents),
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
                "mean_detection_time_seconds": _avg(detection_times),
                "mean_policy_time_seconds": _avg(policy_times),
                "mean_response_time_seconds": _avg(response_times),
                "service_health_failures": service_health_failures,
                "failed_actions": len(failed_actions),
            },
            "policy_promotion_stages": dict(promotion_stages),
            "ttl_recommendations": ttl_recommendations,
            "promoted_ioc_candidates": promoted_iocs[:50],
            "shadow_policy_candidates": shadow_policies[:20],
            "blocked_or_limited_targets": blocked_targets[:200],
            "real_enforcement_proof": nft,
            "synthetic_proof_notice": "AI Duel Demo remains available for rehearsal, but this engine reports live audit/nftables evidence by default.",
        }

    @staticmethod
    def compact(evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "version": evidence.get("version"),
            "engine": evidence.get("engine"),
            "source_scope": evidence.get("source_scope"),
            "ai_mode_status": evidence.get("ai_mode_status"),
            "live_incident_count": evidence.get("live_incident_count"),
            "synthetic_incident_count": evidence.get("synthetic_incident_count"),
            "action_count": evidence.get("action_count"),
            "battle_metrics": evidence.get("battle_metrics"),
            "policy_promotion_stages": evidence.get("policy_promotion_stages"),
            "blocked_or_limited_targets": evidence.get("blocked_or_limited_targets"),
            "real_enforcement_proof": {
                "available": (evidence.get("real_enforcement_proof") or {}).get("available"),
                "ok": (evidence.get("real_enforcement_proof") or {}).get("ok"),
                "sets": (evidence.get("real_enforcement_proof") or {}).get("sets", {}),
            },
        }
