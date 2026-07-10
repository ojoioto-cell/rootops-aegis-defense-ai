from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.models import EvidenceChain
from aegis_agent.utils import ensure_dir


class SecurityGrowthMemory:
    """Small local learning memory for competition defense.

    This is intentionally conservative: it does not invent shell commands or
    expand privileges. It only remembers previously observed high-confidence
    attacker IPs / C2 IPs and adds a bounded score bonus when they reappear.
    The actual action still passes through Policy Gate, TTL, rollback, and
    Verifier.
    """

    def __init__(self, state_dir: str = "data/state", enabled: bool = True, repeat_ip_score_bonus: int = 15, auto_learn_min_score: int = 60):
        self.enabled = bool(enabled)
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "learned_iocs.json"
        self.repeat_ip_score_bonus = int(repeat_ip_score_bonus)
        self.auto_learn_min_score = int(auto_learn_min_score)
        ensure_dir(self.state_dir)
        self.data: Dict[str, Any] = {"version": 1, "ips": {}, "dst_ips": {}}
        self._load()

    def _load(self) -> None:
        if not self.enabled or not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
                self.data.setdefault("ips", {})
                self.data.setdefault("dst_ips", {})
        except Exception:
            self.data = {"version": 1, "ips": {}, "dst_ips": {}}

    def _save(self) -> None:
        if not self.enabled:
            return
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def observe_chain(self, chain: EvidenceChain) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "score_bonus": 0, "matched_ips": []}
        matched: List[str] = []
        known_ips = self.data.get("ips", {})
        known_dst = self.data.get("dst_ips", {})
        for ip in chain.entities.get("src_ip", []):
            if ip in known_ips:
                matched.append(ip)
        for ip in chain.entities.get("dst_ip", []):
            if ip in known_dst:
                matched.append(ip)
        bonus = self.repeat_ip_score_bonus if matched else 0
        return {"enabled": True, "score_bonus": bonus, "matched_ips": sorted(set(matched))}

    def learn_from_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "learned": []}
        score = int(incident.get("score", 0) or 0)
        if score < self.auto_learn_min_score:
            return {"enabled": True, "learned": [], "reason": "score_below_learning_threshold"}
        now = int(time.time())
        learned: List[str] = []
        chain = incident.get("chain") or {}
        entities = chain.get("entities") or {}
        actions = incident.get("actions") or []
        action_targets = {str(a.get("target")) for a in actions if a.get("action") in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"} and a.get("status") in {"success", "planned"}}
        for ip in entities.get("src_ip", []) or []:
            ip = str(ip)
            if not ip or ip not in action_targets and score < 75:
                continue
            rec = self.data.setdefault("ips", {}).setdefault(ip, {"first_seen": now, "count": 0})
            rec.update({"last_seen": now, "last_score": score, "last_attack_type": incident.get("attack_type")})
            rec["count"] = int(rec.get("count", 0)) + 1
            learned.append(ip)
        for ip in entities.get("dst_ip", []) or []:
            ip = str(ip)
            if not ip or ip not in action_targets and score < 75:
                continue
            rec = self.data.setdefault("dst_ips", {}).setdefault(ip, {"first_seen": now, "count": 0})
            rec.update({"last_seen": now, "last_score": score, "last_attack_type": incident.get("attack_type")})
            rec["count"] = int(rec.get("count", 0)) + 1
            learned.append(ip)
        if learned:
            self._save()
        return {"enabled": True, "learned": sorted(set(learned)), "store": str(self.path)}
