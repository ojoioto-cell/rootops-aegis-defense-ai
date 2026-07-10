from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import yaml

from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname


DEFAULT_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "sig-web-path-traversal",
        "name": "Web path traversal/LFI pattern",
        "category": "web_vulnerability",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|proc/self/environ)",
        "severity": "high",
        "score": 60,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 3600,
    },
    {
        "id": "sig-web-command-injection",
        "name": "Web command injection/RCE pattern",
        "category": "web_rce",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(;|%3b|\|\||\||%7c|`|\$\(|%24%28|/bin/(?:ba)?sh|(?:cmd|exec|shell|command|payload)=|(?:curl|wget)\s+(?:https?://|ftp://)|\bnc\s+-[A-Za-z]+)",
        "severity": "critical",
        "score": 75,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-web-sqli",
        "name": "SQL injection pattern",
        "category": "sql_injection",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(union\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\(|information_schema|extractvalue\s*\()",
        "severity": "high",
        "score": 60,
        "action": "rate_limit_ip",
        "target_from": "src_ip",
        "ttl_seconds": 1800,
    },
    {
        "id": "sig-vuln-log4shell-jndi",
        "name": "Known vulnerability exploit marker: Log4Shell/JNDI",
        "category": "known_vulnerability_exploit",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(\$\{[^\n]{0,80}jndi:|%24%7b[^\n]{0,120}jndi%3a|jndi:(?:ldap|rmi|dns|iiop)://)",
        "severity": "critical",
        "score": 85,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-vuln-spring4shell-binding",
        "name": "Known vulnerability exploit marker: Spring4Shell-style binding",
        "category": "known_vulnerability_exploit",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(class\.module\.class(?:Loader|loader)|class%2emodule%2eclass(?:loader|Loader)|spring\.cloud\.function\.routing-expression|spring%2ecloud%2efunction)",
        "severity": "critical",
        "score": 80,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-vuln-shellshock-cgi",
        "name": "Known vulnerability exploit marker: Shellshock CGI payload",
        "category": "known_vulnerability_exploit",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(\(\)\s*\{\s*:;\s*\};|%28%29\s*%7b\s*%3a%3b\s*%7d)",
        "severity": "critical",
        "score": 80,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-vuln-struts-ognl",
        "name": "Known vulnerability exploit marker: Struts/OGNL expression",
        "category": "known_vulnerability_exploit",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(%\{[^\n]{0,120}(?:#|@java|ognl|memberAccess|ServletActionContext)|redirect:(?:\$|%24)\{)",
        "severity": "critical",
        "score": 80,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-vuln-generic-exploit-surface",
        "name": "Generic exposed-vulnerability probe/exploit surface",
        "category": "generic_vulnerability_probe",
        "event_types": ["http_request", "web_attack_pattern"],
        "regex": r"(/(?:cgi-bin|vendor/phpunit|phpunit|solr/admin|actuator/(?:env|heapdump|jolokia)|jolokia|boaform|HNAP1|GponForm|_ignition/execute-solution|api/jsonws|manager/html|\.env|\.git/config|xmlrpc\.php|wp-json|wp-admin|owa/auth|ecp/|autodiscover))",
        "severity": "high",
        "score": 60,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 3600,
    },
    {
        "id": "sig-c2-outbound-tooling",
        "name": "Outbound C2/download tooling",
        "category": "c2_or_payload_download",
        "event_types": ["suspicious_process", "external_network_connection", "signature_match"],
        "regex": r"(curl\s+http|wget\s+http|/dev/tcp/|\bnc\s+-|bash\s+-i|python\s+-c)",
        "severity": "critical",
        "score": 80,
        "action": "block_outbound_ip",
        "target_from": "dst_ip",
        "ttl_seconds": 7200,
    },
    {
        "id": "sig-drone-command",
        "name": "Drone MAVLink command/mission/parameter message",
        "category": "drone_command_or_config_change",
        "event_types": [
            "drone_mavlink_access", "drone_unauthorized_gcs", "drone_command_attempt",
            "drone_mission_or_param_change_attempt", "drone_heartbeat_spoofing"
        ],
        "regex": r"(COMMAND_LONG|COMMAND_INT|MISSION_WRITE_PARTIAL_LIST|MISSION_CLEAR_ALL|PARAM_SET|PARAM_EXT_SET|RC_CHANNELS_OVERRIDE|SET_MODE)",
        "severity": "critical",
        "score": 70,
        "action": "block_ip_ttl",
        "target_from": "src_ip",
        "ttl_seconds": 3600,
        "defense_only": True,
    },
    {
        "id": "sig-ros2-dds-discovery",
        "name": "ROS2/DDS discovery/probe",
        "category": "drone_ros2_dds_probe",
        "event_types": ["drone_ros2_dds_discovery", "drone_ros2_dds_access"],
        "regex": r"(ros2|dds|rtps|discovery|11811|7400|7401|7402)",
        "severity": "high",
        "score": 55,
        "action": "rate_limit_ip",
        "target_from": "src_ip",
        "ttl_seconds": 1800,
        "defense_only": True,
    },
]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


class SignaturePatternEngine:
    """Evidence-first defensive signature matcher.

    The engine never executes commands and never bypasses Policy Gate. It turns
    signature matches into normal Evidence events. Rule/LLM reasoning, Policy
    Gate, Verifier, TTL and Rollback still control actual enforcement.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> list[dict[str, Any]]:
        patterns: list[dict[str, Any]] = []
        if bool(self.config.get("load_defaults", True)):
            patterns.extend(DEFAULT_SIGNATURES)
        for path in _as_list(self.config.get("files")):
            p = Path(str(path))
            if not p.exists():
                continue
            data = yaml.safe_load(p.read_text(errors="ignore")) or {}
            loaded = data.get("signatures", data if isinstance(data, list) else [])
            if isinstance(loaded, list):
                patterns.extend(x for x in loaded if isinstance(x, dict))
        patterns.extend(x for x in _as_list(self.config.get("inline")) if isinstance(x, dict))
        out = []
        for p in patterns:
            if p.get("enabled", True) is False:
                continue
            if not p.get("id") or not p.get("regex"):
                continue
            out.append(p)
        return out

    @staticmethod
    def _blob(ev: Event) -> str:
        meta = ev.metadata or {}
        parts = [ev.raw or "", ev.uri or "", ev.process or "", ev.file_path or ""]
        for key in ("decoded_uri", "command", "proctitle", "msg"):
            val = meta.get(key)
            if val:
                parts.append(str(val))
        if meta.get("paths"):
            parts.append(" ".join(str(x) for x in _as_list(meta.get("paths"))))
        return " \n ".join(parts)

    @staticmethod
    def _target(ev: Event, target_from: str) -> str | None:
        if target_from == "dst_ip":
            return ev.dst_ip or (ev.metadata or {}).get("embedded_ip")
        if target_from == "file_path":
            return ev.file_path or (ev.metadata or {}).get("embedded_file_path")
        if target_from == "process":
            return ev.process
        return ev.src_ip

    def evaluate(self, events: Sequence[Event]) -> List[Event]:
        if not self.enabled or not self.patterns:
            return []
        host = hostname()
        signature_events: list[Event] = []
        seen: set[tuple[str, str]] = set()
        for ev in events:
            if ev.event_type == "signature_match":
                continue
            blob = self._blob(ev)
            if not blob:
                continue
            for pattern in self.patterns:
                allowed_types = set(str(x) for x in _as_list(pattern.get("event_types")))
                if allowed_types and ev.event_type not in allowed_types:
                    continue
                try:
                    rx = re.compile(str(pattern["regex"]), re.I)
                except re.error:
                    continue
                req = pattern.get("require_regex")
                if req:
                    try:
                        if not re.search(str(req), blob, re.I):
                            continue
                    except re.error:
                        continue
                ex = pattern.get("exclude_regex")
                if ex:
                    try:
                        if re.search(str(ex), blob, re.I):
                            continue
                    except re.error:
                        continue
                match = rx.search(blob)
                if not match:
                    continue
                sig_id = str(pattern.get("id"))
                key = (sig_id, ev.event_id)
                if key in seen:
                    continue
                seen.add(key)
                target_from = str(pattern.get("target_from", "src_ip"))
                target = self._target(ev, target_from)
                meta = {
                    "signature_id": sig_id,
                    "signature_name": pattern.get("name", sig_id),
                    "category": pattern.get("category", "signature"),
                    "matched_text": match.group(0)[:200],
                    "original_event_id": ev.event_id,
                    "original_event_type": ev.event_type,
                    "recommended_action": pattern.get("action", "block_ip_ttl"),
                    "target_from": target_from,
                    "target": target,
                    "risk_score": int(pattern.get("score", 60)),
                    "ttl_seconds": int(pattern.get("ttl_seconds", 3600)),
                    "defense_only": bool(pattern.get("defense_only", False)),
                }
                signature_events.append(Event(
                    new_id("E"), ev.timestamp or time.time(), "signature_engine", "signature_match",
                    ev.host or host, str(pattern.get("severity", "high")),
                    f"Signature {sig_id} matched original_event={ev.event_id}: {ev.raw}",
                    src_ip=ev.src_ip,
                    dst_ip=ev.dst_ip,
                    user=ev.user,
                    process=ev.process,
                    pid=ev.pid,
                    file_path=ev.file_path,
                    uri=ev.uri,
                    metadata=meta,
                ))
        return signature_events
