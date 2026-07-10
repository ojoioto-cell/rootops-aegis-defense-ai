from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from aegis_agent.collectors.tail_state import TailState
from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname, run_command

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KEYVAL_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)\s*=\s*(?P<val>[^\s,;]+)")
PORT_RE = re.compile(r":(?P<port>\d{2,5})\b")
SYSID_RE = re.compile(r"\b(?:sysid|sys_id|system_id)\s*[:=]\s*(?P<id>\d+)\b", re.I)
COMPID_RE = re.compile(r"\b(?:compid|comp_id|component_id)\s*[:=]\s*(?P<id>\d+)\b", re.I)
MSG_RE = re.compile(r"\b(?:msg|message|mavlink_msg|type)\s*[:=]\s*(?P<msg>[A-Z0-9_]+)\b", re.I)

CONTROL_MESSAGES = {
    "COMMAND_LONG", "COMMAND_INT", "RC_CHANNELS_OVERRIDE", "MANUAL_CONTROL",
    "SET_MODE", "SET_POSITION_TARGET_LOCAL_NED", "SET_POSITION_TARGET_GLOBAL_INT",
}
MISSION_MESSAGES = {
    "MISSION_COUNT", "MISSION_ITEM", "MISSION_ITEM_INT", "MISSION_WRITE_PARTIAL_LIST",
    "MISSION_CLEAR_ALL", "MISSION_SET_CURRENT", "MISSION_REQUEST", "MISSION_REQUEST_INT",
}
PARAM_MESSAGES = {"PARAM_SET", "PARAM_EXT_SET", "PARAM_REQUEST_WRITE"}
HEARTBEAT_MESSAGES = {"HEARTBEAT"}

DEFAULT_MAVLINK_PORTS = [14550, 14551, 14552, 14553, 14554, 14555, 5760, 5761, 5762, 5763]
DEFAULT_ROS2_DDS_PORTS = [7400, 7401, 7402, 7403, 7410, 7411, 7412, 7413, 11811]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [value]


def _int_list(value: Any, default: Sequence[int]) -> List[int]:
    out: list[int] = []
    for item in _as_list(value):
        try:
            out.append(int(item))
        except Exception:
            continue
    return out or list(default)


def _str_set(value: Any) -> set[str]:
    return {str(x).strip() for x in _as_list(value) if str(x).strip()}


def _keyvals(line: str) -> Dict[str, str]:
    return {m.group("key").lower().replace("-", "_"): m.group("val").strip('"\'') for m in KEYVAL_RE.finditer(line)}


def _ports_in_line(line: str) -> set[int]:
    ports: set[int] = set()
    for m in PORT_RE.finditer(line):
        try:
            ports.add(int(m.group("port")))
        except Exception:
            pass
    kv = _keyvals(line)
    for key in ("dpt", "dport", "dst_port", "dstport", "port", "sport", "spt", "src_port"):
        val = kv.get(key)
        if val:
            try:
                ports.add(int(val))
            except Exception:
                pass
    return ports


def _msg_name(line: str) -> str:
    m = MSG_RE.search(line)
    if m:
        return m.group("msg").upper()
    upper = line.upper()
    for msg in CONTROL_MESSAGES | MISSION_MESSAGES | PARAM_MESSAGES | HEARTBEAT_MESSAGES:
        if msg in upper:
            return msg
    return ""


def _extract_id(pattern: re.Pattern[str], line: str) -> int | None:
    m = pattern.search(line)
    if not m:
        return None
    try:
        return int(m.group("id"))
    except Exception:
        return None


def _src_dst_from_line(line: str) -> tuple[str | None, str | None]:
    kv = _keyvals(line)
    src = kv.get("src") or kv.get("source") or kv.get("src_ip") or kv.get("saddr")
    dst = kv.get("dst") or kv.get("destination") or kv.get("dst_ip") or kv.get("daddr")
    ips = IP_RE.findall(line)
    if not src and ips:
        src = ips[0]
    if not dst and len(ips) >= 2:
        dst = ips[1]
    return src, dst


def _severity_for_event(event_type: str) -> str:
    if event_type in {"drone_unauthorized_gcs", "drone_heartbeat_spoofing", "drone_mission_or_param_change_attempt", "drone_command_attempt"}:
        return "critical"
    if event_type in {"drone_mavlink_flood", "drone_ros2_dds_flood"}:
        return "high"
    return "medium"


def _event_type_for_line(line: str, cfg: Dict[str, Any], src_ip: str | None, ports: set[int]) -> tuple[str | None, Dict[str, Any]]:
    lower = line.lower()
    mav_ports = set(_int_list(cfg.get("mavlink_ports"), DEFAULT_MAVLINK_PORTS))
    ros_ports = set(_int_list(cfg.get("ros2_dds_ports"), DEFAULT_ROS2_DDS_PORTS))
    allowed_gcs = _str_set(cfg.get("allowed_gcs_ips"))
    allowed_drone_ips = _str_set(cfg.get("allowed_drone_ips"))
    allowed_sysids = {int(x) for x in _int_list(cfg.get("allowed_sysids"), [])}
    allowed_compids = {int(x) for x in _int_list(cfg.get("allowed_component_ids"), [])}
    msg = _msg_name(line)
    sysid = _extract_id(SYSID_RE, line)
    compid = _extract_id(COMPID_RE, line)

    meta = {
        "msg": msg,
        "sysid": sysid,
        "compid": compid,
        "ports": sorted(ports),
        "allowed_gcs_ips": sorted(allowed_gcs),
        "allowed_drone_ips": sorted(allowed_drone_ips),
        "collector": "drone_passive",
        "defense_only": True,
    }

    is_mavlink = bool(ports.intersection(mav_ports)) or "mavlink" in lower or msg in (CONTROL_MESSAGES | MISSION_MESSAGES | PARAM_MESSAGES | HEARTBEAT_MESSAGES)
    is_ros = bool(ports.intersection(ros_ports)) or "ros2" in lower or "dds" in lower or "rtps" in lower or "discovery" in lower
    unauthorized_src = bool(src_ip) and src_ip not in allowed_gcs and src_ip not in allowed_drone_ips and src_ip not in {"127.0.0.1", "::1"}

    if is_mavlink:
        if msg in HEARTBEAT_MESSAGES:
            if unauthorized_src or (allowed_sysids and sysid is not None and sysid not in allowed_sysids) or (allowed_compids and compid is not None and compid not in allowed_compids):
                return "drone_heartbeat_spoofing", meta
            return "drone_mavlink_access", meta
        if msg in CONTROL_MESSAGES:
            return "drone_command_attempt" if unauthorized_src else "drone_mavlink_access", meta
        if msg in MISSION_MESSAGES or msg in PARAM_MESSAGES:
            return "drone_mission_or_param_change_attempt" if unauthorized_src else "drone_mavlink_access", meta
        if unauthorized_src:
            return "drone_unauthorized_gcs", meta
        return "drone_mavlink_access", meta

    if is_ros:
        return ("drone_ros2_dds_discovery" if unauthorized_src else "drone_ros2_dds_access"), meta

    return None, meta


def _events_from_lines(lines: Iterable[str], source: str, cfg: Dict[str, Any]) -> List[Event]:
    host = hostname()
    events: list[Event] = []
    src_counter: Counter[str] = Counter()
    mav_counter: Counter[str] = Counter()
    ros_counter: Counter[str] = Counter()
    flood_threshold = int(cfg.get("mavlink_flood_threshold_per_loop", 50))
    ros_threshold = int(cfg.get("ros2_dds_flood_threshold_per_loop", 80))

    for line in lines:
        raw = (line or "").strip()
        if not raw:
            continue
        src, dst = _src_dst_from_line(raw)
        ports = _ports_in_line(raw)
        ev_type, meta = _event_type_for_line(raw, cfg, src, ports)
        if not ev_type:
            continue
        if src:
            src_counter[src] += 1
            if ev_type.startswith("drone_mavlink") or "mavlink" in raw.lower() or meta.get("msg"):
                mav_counter[src] += 1
            if ev_type.startswith("drone_ros2"):
                ros_counter[src] += 1
        events.append(Event(
            new_id("E"), time.time(), source, ev_type, host,
            _severity_for_event(ev_type), raw, src_ip=src, dst_ip=dst, metadata=meta,
        ))

    # Synthetic flood events make repeated drone-network abuse visible even when
    # individual packets are low information. They remain passive evidence only.
    for src, count in mav_counter.items():
        if count >= flood_threshold:
            events.append(Event(
                new_id("E"), time.time(), source, "drone_mavlink_flood", host, "high",
                f"MAVLink flood suspected from {src}: {count} events in one collection window",
                src_ip=src, metadata={"count": count, "threshold": flood_threshold, "defense_only": True},
            ))
    for src, count in ros_counter.items():
        if count >= ros_threshold:
            events.append(Event(
                new_id("E"), time.time(), source, "drone_ros2_dds_flood", host, "high",
                f"ROS2/DDS discovery flood suspected from {src}: {count} events in one collection window",
                src_ip=src, metadata={"count": count, "threshold": ros_threshold, "defense_only": True},
            ))
    return events


def _live_drone_lines(cfg: Dict[str, Any]) -> list[str]:
    if not bool(cfg.get("collect_live_ss", True)):
        return []
    rc, out, _ = run_command(["ss", "-tunap"], timeout=5)
    if rc != 0:
        return []
    ports = set(_int_list(cfg.get("mavlink_ports"), DEFAULT_MAVLINK_PORTS) + _int_list(cfg.get("ros2_dds_ports"), DEFAULT_ROS2_DDS_PORTS))
    lines: list[str] = []
    for line in out.splitlines():
        if _ports_in_line(line).intersection(ports):
            lines.append(line)
    return lines


def collect_drone_events(cfg: Dict[str, Any], *, state_dir: str | None = None, follow: bool = False, first_run: str = "tail") -> List[Event]:
    """Collect passive drone-network evidence.

    This collector never sends MAVLink, ROS2, flight-control, mission, arming,
    disarming, takeoff, landing, parameter-write, or RC override traffic. It only
    parses logs/connection snapshots and returns evidence events for Policy Gate.
    """
    if not bool(cfg.get("enabled", False)):
        return []
    events: list[Event] = []
    tailer = TailState(state_dir or "data/state") if follow else None
    for path in _as_list(cfg.get("logs")):
        p = Path(str(path))
        if not p.exists():
            continue
        lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
        events += _events_from_lines(lines, str(p), cfg)
    snapshot_path = cfg.get("network_snapshot")
    if snapshot_path and Path(str(snapshot_path)).exists():
        lines = Path(str(snapshot_path)).read_text(errors="ignore").splitlines()
        events += _events_from_lines(lines, str(snapshot_path), cfg)
    live_lines = _live_drone_lines(cfg)
    if live_lines:
        events += _events_from_lines(live_lines, "drone_live_ss", cfg)
    return events
