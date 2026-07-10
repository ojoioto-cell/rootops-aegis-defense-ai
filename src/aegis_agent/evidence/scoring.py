from __future__ import annotations

from collections import Counter
from typing import List

from aegis_agent.models import EvidenceChain


def score_chain(chain: EvidenceChain) -> EvidenceChain:
    types = [e.event_type for e in chain.events]
    c = Counter(types)
    score = 0
    reasons: List[str] = []
    attack_type = "unknown"
    hypothesis = "insufficient_evidence"

    # Competition-grade SSH brute-force scoring.
    # A repeated SSH failure burst is actionable even without later post-exploitation evidence.
    if c["ssh_failed_login"] >= 30:
        score += 75
        reasons.append("Severe SSH failed login burst")
        attack_type = "ssh_bruteforce"
        hypothesis = "ssh_bruteforce_attempt"
    elif c["ssh_failed_login"] >= 10:
        score += 60
        reasons.append("SSH failed login burst threshold exceeded")
        attack_type = "ssh_bruteforce"
        hypothesis = "ssh_bruteforce_attempt"
    elif c["ssh_failed_login"] >= 5:
        score += 45
        reasons.append("SSH failed login burst")
        attack_type = "ssh_bruteforce"
        hypothesis = "ssh_bruteforce_attempt"
    if c["ssh_invalid_user"] >= 10:
        score += 60
        reasons.append("Severe invalid SSH user enumeration")
        attack_type = "ssh_bruteforce"
        hypothesis = "ssh_invalid_user_bruteforce_or_enumeration"
    elif c["ssh_invalid_user"] >= 5:
        score += 45
        reasons.append("Invalid SSH user enumeration")
        attack_type = "ssh_bruteforce"
        hypothesis = "ssh_invalid_user_bruteforce_or_enumeration"
    elif c["ssh_invalid_user"] >= 3:
        score += 20
        reasons.append("Multiple invalid SSH users")
    if c["ssh_success_login"] >= 1 and c["ssh_failed_login"] >= 1:
        score += 30
        reasons.append("SSH success after failures")
        attack_type = "account_compromise_suspected"
        hypothesis = "possible_compromised_account_after_bruteforce"
    if c["sudo_execution"] >= 1:
        score += 20
        reasons.append("Sudo execution observed")
    if c["web_attack_pattern"] >= 1:
        score += 25
        reasons.append("Web vulnerability attack pattern observed")
        attack_type = "web_vulnerability_attack"
        hypothesis = "web_attack_attempt"
    if c["app_error"] >= 1 and c["web_attack_pattern"] >= 1:
        score += 15
        reasons.append("Application error after suspicious web request")
    if c["suspicious_process"] >= 1:
        score += 30
        reasons.append("Suspicious process execution")
        attack_type = "rce_or_post_exploitation_suspected"
        hypothesis = "possible_exploit_success_or_post_exploitation"
    if c["external_network_connection"] >= 1:
        score += 25
        reasons.append("External network connection observed")
    if c["suspicious_file"] >= 1:
        score += 25
        reasons.append("Suspicious file artifact observed")
    if c["persistence_modified"] >= 1:
        score += 30
        reasons.append("Persistence mechanism modified")
    if c["http_request"] >= 100:
        score += 25
        reasons.append("HTTP request volume spike")
        attack_type = "http_flood_suspected"
        hypothesis = "possible_application_dos"
    if c["agent_integrity_change"] >= 1:
        score += 90
        reasons.append("Agent integrity change detected")
        attack_type = "agent_tamper_suspected"
        hypothesis = "possible_agent_or_policy_tampering"

    if c["drone_unauthorized_gcs"] >= 1:
        score += 65
        reasons.append("Unauthorized drone network or GCS source observed")
        attack_type = "drone_unauthorized_gcs"
        hypothesis = "unauthorized_gcs_or_drone_network_access"
    if c["drone_command_attempt"] >= 1:
        score += 60
        reasons.append("Drone command-class MAVLink message from untrusted source")
        attack_type = "drone_command_attempt"
        hypothesis = "unauthorized_drone_command_attempt"
    if c["drone_mission_or_param_change_attempt"] >= 1:
        score += 65
        reasons.append("Drone mission or parameter change attempt from untrusted source")
        attack_type = "drone_mission_param_attempt"
        hypothesis = "unauthorized_mission_or_parameter_change_attempt"
    if c["drone_heartbeat_spoofing"] >= 1:
        score += 60
        reasons.append("Drone heartbeat spoofing or sysid/component anomaly")
        attack_type = "drone_heartbeat_spoofing"
        hypothesis = "possible_spoofed_drone_or_gcs_identity"
    if c["drone_mavlink_flood"] >= 1:
        score += 50
        reasons.append("MAVLink flood or telemetry abuse suspected")
        attack_type = "drone_mavlink_flood"
        hypothesis = "possible_mavlink_flood_or_command_abuse"
    if c["drone_ros2_dds_discovery"] >= 1:
        score += 50
        reasons.append("ROS2/DDS discovery from untrusted source")
        attack_type = "drone_ros2_dds_probe"
        hypothesis = "possible_ros2_dds_discovery_probe"
    if c["drone_ros2_dds_flood"] >= 1:
        score += 50
        reasons.append("ROS2/DDS discovery flood suspected")
        attack_type = "drone_ros2_dds_flood"
        hypothesis = "possible_ros2_dds_discovery_flood"

    signature_events = [e for e in chain.events if e.event_type == "signature_match"]
    if signature_events:
        max_sig_score = 0
        sig_ids = []
        for ev in signature_events:
            meta = ev.metadata or {}
            try:
                max_sig_score = max(max_sig_score, int(meta.get("risk_score", 60)))
            except Exception:
                max_sig_score = max(max_sig_score, 60)
            if meta.get("signature_id"):
                sig_ids.append(str(meta.get("signature_id")))
        score += max_sig_score
        reasons.append("Signature pattern matched: " + ",".join(sorted(set(sig_ids))[:5]))
        attack_type = "signature_pattern_match"
        hypothesis = "signature_pattern_based_attack_or_policy_violation"

    # Cross-source bonus.
    sources = {e.source for e in chain.events}
    if len(sources) >= 2 and score >= 40:
        score += 10
        reasons.append("Multiple evidence sources")

    score = max(0, min(score, 100))
    if score >= 90:
        conf = "critical"
    elif score >= 75:
        conf = "high"
    elif score >= 60:
        conf = "medium_high"
    elif score >= 30:
        conf = "medium"
    else:
        conf = "low"

    chain.score = score
    chain.confidence = conf
    chain.attack_type = attack_type
    chain.hypothesis = hypothesis
    chain.reasons = reasons
    return chain
