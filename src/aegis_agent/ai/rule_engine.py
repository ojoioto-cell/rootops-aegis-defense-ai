from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from aegis_agent.models import ActionPlan, AnalysisResult, EvidenceChain, new_id
from aegis_agent.utils import validate_enforcement_ip


def _claim_event_ids(chain: EvidenceChain, claim: str) -> List[str]:
    """Return the smallest event-id set that supports one rule-based claim.

    v0.2.3 narrows rule evidence mapping by event_type instead of attaching
    every event in the Evidence Chain to every claim. This keeps reports and
    downstream LLM validation evidence-first and auditable.
    """
    text = (claim or "").lower()
    candidates: set[str] = set()

    def add_by_type(types: set[str]) -> None:
        for e in chain.events:
            if e.event_type in types:
                candidates.add(e.event_id)

    if any(k in text for k in ["ssh", "brute", "failed login", "login burst"]):
        add_by_type({"ssh_failed_login"})
    if any(k in text for k in ["successful login", "success login", "sudo", "account", "credential"]):
        add_by_type({"ssh_success_login", "sudo_execution"})
    if any(k in text for k in ["web", "http", "uri", "url", "path traversal", "sqli", "rce", "command injection"]):
        add_by_type({"web_attack_pattern", "http_request", "app_error"})
    if any(k in text for k in ["process", "shell", "exec", "payload", "post-exploitation", "post exploitation"]):
        add_by_type({"suspicious_process"})
    if any(k in text for k in ["file", "webshell", "web shell", "tmp", "quarantine"]):
        add_by_type({"suspicious_file", "file_created", "file_modified", "fim_created", "fim_modified"})
    if any(k in text for k in ["c2", "outbound", "external", "network", "connection"]):
        add_by_type({"external_network_connection"})
    if any(k in text for k in ["persistence", "cron", "systemd", "authorized_keys", "startup"]):
        add_by_type({"persistence_modified"})
    if any(k in text for k in ["integrity", "self-protection", "self protection", "tamper"]):
        add_by_type({"agent_integrity_change"})
    if any(k in text for k in ["drone", "gcs", "mavlink", "heartbeat", "sysid", "component", "mission", "parameter", "ros2", "dds", "rtps", "telemetry"]):
        add_by_type({
            "drone_mavlink_access", "drone_unauthorized_gcs", "drone_command_attempt",
            "drone_mission_or_param_change_attempt", "drone_heartbeat_spoofing",
            "drone_mavlink_flood", "drone_ros2_dds_discovery", "drone_ros2_dds_access",
            "drone_ros2_dds_flood",
        })
    if any(k in text for k in ["signature", "pattern", "시그니처"]):
        add_by_type({"signature_match"})
    if any(k in text for k in ["attack loop", "mutating", "mutation", "repeated"]):
        for e in chain.events:
            if e.severity in {"high", "critical"} or e.event_type in {"web_attack_pattern", "suspicious_process", "external_network_connection", "signature_match"}:
                candidates.add(e.event_id)

    if not candidates:
        for e in chain.events:
            if e.severity in {"high", "critical"}:
                candidates.add(e.event_id)
    if not candidates and chain.events:
        candidates.add(chain.events[0].event_id)

    ordered = [e.event_id for e in chain.events if e.event_id in candidates]
    return ordered


def analyze_chain(chain: EvidenceChain, default_ttl: int = 3600) -> AnalysisResult:
    event_ids = [e.event_id for e in chain.events]
    types = Counter(e.event_type for e in chain.events)
    actions: List[Dict[str, Any]] = []

    src_ips = chain.entities.get("src_ip", [])
    users = chain.entities.get("user", [])
    # Prefer users tied to successful login or sudo activity for account response.
    # Avoid targeting invalid-user probes or alphabetically sorted entity values.
    account_candidates = []
    for e in chain.events:
        if e.event_type in {"ssh_success_login", "sudo_execution"} and e.user and e.user not in account_candidates:
            account_candidates.append(e.user)

    # Prefer precise targets from the event stream instead of alphabetically sorted entity values.
    dst_ips = [e.dst_ip for e in chain.events if e.event_type == "external_network_connection" and e.dst_ip and validate_enforcement_ip(e.dst_ip)[0]]
    files = [e.file_path for e in chain.events if e.event_type == "suspicious_file" and e.file_path]
    persistence_events = [e for e in chain.events if e.event_type == "persistence_modified" and e.file_path]
    persistence_targets = [e.file_path for e in persistence_events]
    persistence_raws = [e.raw for e in persistence_events if e.raw]
    processes = []
    for e in chain.events:
        if e.event_type == "suspicious_process" and e.process:
            target = f"{e.pid} {e.process}" if e.pid is not None else e.process
            if target not in processes:
                processes.append(target)

    drone_event_types = {
        "drone_mavlink_access", "drone_unauthorized_gcs", "drone_command_attempt",
        "drone_mission_or_param_change_attempt", "drone_heartbeat_spoofing",
        "drone_mavlink_flood", "drone_ros2_dds_discovery", "drone_ros2_dds_access",
        "drone_ros2_dds_flood",
    }
    is_drone_chain = any(types[t] for t in drone_event_types)
    drone_flood = bool(types["drone_mavlink_flood"] or types["drone_ros2_dds_flood"])

    ssh_bruteforce_chain = bool(types["ssh_failed_login"] or types["ssh_invalid_user"])

    signature_events = [e for e in chain.events if e.event_type == "signature_match"]

    def add_unique_action(action_dict: Dict[str, Any]) -> None:
        key = (action_dict.get("action"), action_dict.get("target"))
        if not key[1] or key[1] == "unknown":
            return
        if any((a.get("action"), a.get("target")) == key for a in actions):
            return
        actions.append(action_dict)

    def verified_audit_process_event(e) -> bool:
        meta = e.metadata or {}
        if meta.get("source_kind") != "auditd" or not meta.get("audit_serial") or e.pid is None:
            return False
        pid = int(e.pid)
        related = 0
        for other in chain.events:
            if other.event_id == e.event_id:
                continue
            om = other.metadata or {}
            vals = {other.pid, om.get("pid"), om.get("ppid")}
            if pid in {v for v in vals if isinstance(v, int)}:
                related += 1
        # A standalone auditd process is not enough for automatic suspension; require
        # at least one same-PID/PPID evidence item or a linked file/outbound context.
        return bool(related or e.file_path or e.dst_ip)

    for sig in signature_events:
        meta = sig.metadata or {}
        action = str(meta.get("recommended_action", "block_ip_ttl"))
        target = meta.get("target")
        if not target:
            if meta.get("target_from") == "dst_ip":
                target = sig.dst_ip
            elif meta.get("target_from") == "file_path":
                target = sig.file_path
            else:
                target = sig.src_ip
        if action in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"} and target:
            add_unique_action({
                "action": action,
                "target": target,
                "ttl_seconds": int(meta.get("ttl_seconds", default_ttl)),
                "reason": f"signature_pattern_{meta.get('signature_id', 'match')}",
                "min_evidence_required": 1,
                "signature_id": meta.get("signature_id"),
                "signature_category": meta.get("category"),
            })

    if chain.score >= 45 and src_ips and ssh_bruteforce_chain:
        add_unique_action({
            "action": "rate_limit_ip",
            "target": src_ips[0],
            "ttl_seconds": min(default_ttl, 1800),
            "reason": "ssh_bruteforce_rate_limit",
            "min_evidence_required": 1,
        })

    if chain.score >= 60 and src_ips:
        add_unique_action({
            "action": "block_ip_ttl",
            "target": src_ips[0],
            "ttl_seconds": default_ttl,
            "reason": "drone_network_guard_source_block" if is_drone_chain else ("ssh_bruteforce_source_block" if ssh_bruteforce_chain else "evidence_chain_source_ip_risk"),
            "min_evidence_required": 1 if (is_drone_chain or ssh_bruteforce_chain) else None,
        })

    if chain.score >= 60 and src_ips and drone_flood:
        add_unique_action({
            "action": "rate_limit_ip",
            "target": src_ips[0],
            "ttl_seconds": min(default_ttl, 1800),
            "reason": "drone_mavlink_or_ros2_flood_rate_limit",
            "min_evidence_required": 1,
        })

    if chain.score >= 70 and types["web_attack_pattern"]:
        add_unique_action({
            "action": "rate_limit_ip",
            "target": src_ips[0] if src_ips else "unknown",
            "ttl_seconds": min(default_ttl, 1800),
            "reason": "web_attack_or_http_flood_mitigation",
        })

    if chain.score >= 75 and dst_ips:
        add_unique_action({
            "action": "block_outbound_ip",
            "target": dst_ips[0],
            "ttl_seconds": default_ttl,
            "reason": "possible_c2_or_external_post_exploitation_connection",
        })

    trusted_processes = []
    for e in chain.events:
        if e.event_type == "suspicious_process" and e.process and verified_audit_process_event(e):
            target = f"{e.pid} {e.process}" if e.pid is not None else e.process
            trusted_processes.append((target, e))

    if chain.score >= 90 and trusted_processes:
        # v0.2.9: process suspension is intentionally conservative. It is only
        # proposed when auditd PID/PPID evidence directly supports the target.
        target, ev = trusted_processes[0]
        actions.append({
            "action": "suspend_process",
            "target": target,
            "reason": "auditd_verified_suspicious_process_in_evidence_chain",
            "requires_auditd_pid_relation": True,
            "audit_serial": (ev.metadata or {}).get("audit_serial"),
            "process_evidence_event_id": ev.event_id,
        })

    if chain.score >= 75 and files:
        actions.append({
            "action": "quarantine_file",
            "target": files[0],
            "reason": "suspicious_file_in_evidence_chain",
        })

    if chain.score >= 85 and types["persistence_modified"]:
        actions.append({
            "action": "disable_persistence",
            "target": persistence_targets[0] if persistence_targets else "unknown",
            "reason": "persistence_modified_in_evidence_chain",
            "linked_files": files,
            "linked_dst_ips": dst_ips,
            "linked_src_ips": src_ips,
            "persistence_raw": persistence_raws,
            "processes": processes,
        })

    # restrict_account intentionally remains disabled by default policy; recommend only for high score.
    if chain.score >= 90 and (account_candidates or users):
        actions.append({
            "action": "restrict_account",
            "target": (account_candidates or users)[0],
            "reason": "high_confidence_compromised_account_candidate",
        })

    mapping = []
    for r in chain.reasons:
        ids = _claim_event_ids(chain, r)
        mapping.append({"claim": r, "event_ids": ids})

    likelihood = "high" if chain.score >= 75 else "medium" if chain.score >= 30 else "low"
    if chain.score >= 90:
        likelihood = "critical"

    return AnalysisResult(
        incident_likelihood=likelihood,
        confidence_score=chain.score,
        attack_type=chain.attack_type,
        hypothesis=chain.hypothesis,
        evidence_mapping=mapping,
        recommended_actions=actions,
        limitations=["Rule-based MVP reasoning; connect Llama/GPT through ai/llm_client.py for advanced explanation."],
    )


def build_action_plans(analysis: AnalysisResult, evidence_ids: List[str]) -> List[ActionPlan]:
    plans: List[ActionPlan] = []
    for a in analysis.recommended_actions:
        plans.append(ActionPlan(
            action_id=new_id("ACT"),
            action=a["action"],
            target=a.get("target", "unknown"),
            reason=a.get("reason", analysis.hypothesis),
            evidence_ids=evidence_ids,
            score=analysis.confidence_score,
            ttl_seconds=a.get("ttl_seconds"),
            rollback_supported=True,
            metadata={k: v for k, v in a.items() if k not in {"action", "target", "reason", "ttl_seconds"}},
        ))
    return plans
