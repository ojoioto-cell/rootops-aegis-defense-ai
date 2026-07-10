from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Set, Tuple

from aegis_agent.models import EvidenceChain, Event, new_id
from .scoring import score_chain

POST_AUTH_WINDOW_SECONDS = 15 * 60
POST_WEB_WINDOW_SECONDS = 10 * 60
DRONE_EVENT_TYPES = {
    "drone_mavlink_access", "drone_unauthorized_gcs", "drone_command_attempt",
    "drone_mission_or_param_change_attempt", "drone_heartbeat_spoofing",
    "drone_mavlink_flood", "drone_ros2_dds_discovery", "drone_ros2_dds_access",
    "drone_ros2_dds_flood",
}
HOST_EVENT_TYPES = {"sudo_execution", "suspicious_process", "external_network_connection", "network_connection", "suspicious_file", "persistence_modified", "app_error", "agent_integrity_change", "signature_match"} | DRONE_EVENT_TYPES
ANCHOR_TYPES = {"ssh_failed_login", "ssh_invalid_user", "ssh_success_login", "web_attack_pattern", "http_request"} | DRONE_EVENT_TYPES


def _add_entity(entities: Dict[str, Set[str]], key: str, value):
    if value is None:
        return
    value = str(value)
    if not value:
        return
    entities[key].add(value)


def _event_ips(ev: Event) -> set[str]:
    out = set()
    if ev.src_ip:
        out.add(ev.src_ip)
    if ev.dst_ip:
        out.add(ev.dst_ip)
    for key in ("embedded_ip",):
        val = ev.metadata.get(key) if ev.metadata else None
        if val:
            out.add(str(val))
    for key in ("ips",):
        vals = ev.metadata.get(key) if ev.metadata else None
        if isinstance(vals, list):
            out.update(str(v) for v in vals if v)
    return out


def _event_files(ev: Event) -> set[str]:
    out = set()
    if ev.file_path:
        out.add(ev.file_path)
    if ev.metadata:
        for key in ("embedded_file_path", "path"):
            val = ev.metadata.get(key)
            if val:
                out.add(str(val))
        for p in ev.metadata.get("paths", []) if isinstance(ev.metadata.get("paths", []), list) else []:
            out.add(str(p))
    return out


def _event_pids(ev: Event) -> set[int]:
    out = set()
    if ev.pid is not None:
        out.add(int(ev.pid))
    if ev.metadata:
        for key in ("pid", "ppid"):
            val = ev.metadata.get(key)
            if isinstance(val, int):
                out.add(val)
            else:
                try:
                    if val is not None:
                        out.add(int(val))
                except Exception:
                    pass
    return out


def _event_users(ev: Event) -> set[str]:
    return {ev.user} if ev.user else set()


def _within(a: Event, b: Event, seconds: int) -> bool:
    return abs(float(a.timestamp) - float(b.timestamp)) <= seconds


def _make_seed(ip_events: list[Event]) -> dict:
    seed = {
        "src_ips": set(e.src_ip for e in ip_events if e.src_ip),
        "users": set(e.user for e in ip_events if e.user and e.event_type == "ssh_success_login"),
        "all_users": set(e.user for e in ip_events if e.user),
        "dst_ips": set(),
        "file_paths": set(),
        "pids": set(),
        "web_attack_times": [e for e in ip_events if e.event_type == "web_attack_pattern"],
        "ssh_success_times": [e for e in ip_events if e.event_type == "ssh_success_login"],
        "anchor_events": list(ip_events),
    }
    for ev in ip_events:
        seed["dst_ips"].update(ip for ip in _event_ips(ev) if ip not in seed["src_ips"])
        seed["file_paths"].update(_event_files(ev))
        seed["pids"].update(_event_pids(ev))
    return seed


def _has_related_text(ev: Event, seed: dict) -> bool:
    raw = (ev.raw or "") + " " + (ev.process or "") + " " + (ev.file_path or "")
    for ip in seed["dst_ips"]:
        if ip and ip in raw:
            return True
    for path in seed["file_paths"]:
        if path and path in raw:
            return True
    return False


def _relation_reason(ev: Event, seed: dict, included: list[Event]) -> str | None:
    # Direct host context by user after SSH success.
    if ev.event_type == "sudo_execution":
        if ev.user and (ev.user in seed["users"] or ev.user in seed["all_users"]):
            if any(_within(ev, s, POST_AUTH_WINDOW_SECONDS) for s in seed["ssh_success_times"]):
                return "same_user_after_ssh_success"
        return None

    # Web/app errors without src_ip are only useful right after suspicious web requests.
    if ev.event_type == "app_error":
        if any(_within(ev, w, POST_WEB_WINDOW_SECONDS) for w in seed["web_attack_times"]):
            return "app_error_after_web_attack"
        return None

    ev_ips = _event_ips(ev)
    ev_files = _event_files(ev)
    ev_pids = _event_pids(ev)

    if seed["dst_ips"] and ev_ips.intersection(seed["dst_ips"]):
        return "shared_external_destination_ip"
    if seed["file_paths"] and ev_files.intersection(seed["file_paths"]):
        return "shared_file_path"
    if seed["pids"] and ev_pids.intersection(seed["pids"]):
        return "shared_pid_or_ppid"
    if _has_related_text(ev, seed):
        return "textual_target_match"

    # Process/network/file chain propagation: if this event relates to any already included context, include it.
    for inc in included:
        if inc is ev:
            continue
        if ev_ips and ev_ips.intersection(_event_ips(inc)):
            return "propagated_shared_ip"
        if ev_files and ev_files.intersection(_event_files(inc)):
            return "propagated_shared_file"
        if ev_pids and ev_pids.intersection(_event_pids(inc)):
            return "propagated_shared_pid"

    # RCE heuristic: suspicious process shortly after suspicious web request only if command contains
    # extracted URI target such as C2 IP or dropped file path. This prevents arbitrary shell processes
    # from attaching to a web attack chain.
    if ev.event_type == "suspicious_process" and seed["web_attack_times"]:
        if any(_within(ev, w, POST_WEB_WINDOW_SECONDS) for w in seed["web_attack_times"]):
            if _has_related_text(ev, seed):
                return "web_attack_related_process_artifact"

    return None


def _refresh_seed(seed: dict, ev: Event) -> None:
    seed["dst_ips"].update(ip for ip in _event_ips(ev) if ip not in seed["src_ips"])
    seed["file_paths"].update(_event_files(ev))
    seed["pids"].update(_event_pids(ev))
    if ev.user:
        seed["all_users"].add(ev.user)
        if ev.event_type in {"ssh_success_login", "sudo_execution"}:
            seed["users"].add(ev.user)


def build_evidence_chains(events: List[Event]) -> List[EvidenceChain]:
    if not events:
        return []

    by_ip: Dict[str, List[Event]] = defaultdict(list)
    context: List[Event] = []
    for ev in events:
        if ev.src_ip:
            by_ip[ev.src_ip].append(ev)
        else:
            context.append(ev)

    chains: List[EvidenceChain] = []
    for ip, ip_events in by_ip.items():
        seed = _make_seed(ip_events)
        included = list(ip_events)
        remaining = [e for e in context if e.event_type in HOST_EVENT_TYPES]

        changed = True
        while changed:
            changed = False
            for ev in list(remaining):
                reason = _relation_reason(ev, seed, included)
                if reason:
                    ev.metadata = dict(ev.metadata or {})
                    ev.metadata["chain_relation"] = reason
                    included.append(ev)
                    _refresh_seed(seed, ev)
                    remaining.remove(ev)
                    changed = True

        chain_events = sorted(included, key=lambda e: e.timestamp)
        chains.append(_make_chain(chain_events))

    if not chains and context:
        # Host-only incident chains. Keep self-protection/tamper evidence separate
        # from generic host network snapshots so installation/update drift does not
        # accidentally inherit unrelated outbound connection context.
        self_protection_events = [e for e in context if e.event_type == "agent_integrity_change"]
        high_signal = [e for e in context if e.event_type in HOST_EVENT_TYPES and e.event_type != "agent_integrity_change"]
        if self_protection_events:
            chains.append(_make_chain(sorted(self_protection_events, key=lambda e: e.timestamp)))
        if high_signal:
            chains.append(_make_chain(sorted(high_signal, key=lambda e: e.timestamp)))

    unique = []
    seen = set()
    for ch in chains:
        key = tuple(e.event_id for e in ch.events)
        if key not in seen:
            unique.append(ch)
            seen.add(key)
    return unique


def _make_chain(events: List[Event]) -> EvidenceChain:
    entities: Dict[str, Set[str]] = defaultdict(set)
    host = events[0].host if events else "unknown"
    for ev in events:
        _add_entity(entities, "src_ip", ev.src_ip)
        _add_entity(entities, "dst_ip", ev.dst_ip)
        embedded_ip = (ev.metadata or {}).get("embedded_ip")
        embedded_ips = embedded_ip if isinstance(embedded_ip, list) else [embedded_ip]
        for ip in embedded_ips:
            _add_entity(entities, "dst_ip", ip)
        _add_entity(entities, "user", ev.user)
        _add_entity(entities, "process", ev.process)
        _add_entity(entities, "pid", ev.pid)
        for p in _event_pids(ev):
            _add_entity(entities, "pid", p)
        _add_entity(entities, "file_path", ev.file_path)
        for f in _event_files(ev):
            _add_entity(entities, "file_path", f)
        _add_entity(entities, "uri", ev.uri)
    chain = EvidenceChain(
        chain_id=new_id("CHAIN"),
        host=host,
        events=events,
        entities={k: sorted(v) for k, v in entities.items()},
    )
    score_chain(chain)
    return chain
