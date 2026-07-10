from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable

from aegis_agent.models import EvidenceChain
from aegis_agent.utils import ensure_dir

URI_VALUE_RE = re.compile(r"(=)[^&\s]+")
DIGIT_RE = re.compile(r"\d+")


class AttackLoopTracker:
    """Track repeated/mutating attack attempts across monitoring loops.

    This is intentionally lightweight and file-backed. It groups attempts by
    source/target characteristics and adds a small score bonus when the same
    actor or same pattern keeps adapting.
    """

    def __init__(self, state_dir: str = "data/state", window_seconds: int = 3600, enabled: bool = True):
        self.enabled = enabled
        self.window_seconds = int(window_seconds or 3600)
        self.path = ensure_dir(state_dir) / "attack_loops.json"
        self.state = self._load()

    def observe(self, chain: EvidenceChain) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        now = int(time.time())
        self._gc(now)
        features = self._features(chain)
        key = self._key(features)
        rec = self.state.get(key) or {
            "loop_id": f"LOOP-{time.strftime('%Y%m%d%H%M%S')}-{key[:8]}",
            "first_seen": now,
            "attempts": 0,
            "variants": [],
            "src_ips": [],
            "dst_ips": [],
            "files": [],
            "attack_types": [],
        }
        rec["attempts"] = int(rec.get("attempts", 0)) + 1
        rec["last_seen"] = now
        for field in ("src_ips", "dst_ips", "files", "attack_types"):
            for value in features.get(field, []):
                if value and value not in rec[field]:
                    rec[field].append(value)
        variant = features.get("variant")
        if variant and variant not in rec["variants"]:
            rec["variants"].append(variant)
        mutation_detected = rec["attempts"] >= 2 and len(rec.get("variants", [])) >= 2
        score_bonus = 0
        if rec["attempts"] >= 2:
            score_bonus += min(10, 2 * rec["attempts"])
        if mutation_detected:
            score_bonus += 5
        rec["mutation_detected"] = mutation_detected
        self.state[key] = rec
        self._save()
        return {
            "enabled": True,
            "loop_key": key,
            "loop_id": rec["loop_id"],
            "attempts": rec["attempts"],
            "variant_count": len(rec.get("variants", [])),
            "mutation_detected": mutation_detected,
            "score_bonus": min(score_bonus, 15),
            "features": features,
        }

    def _features(self, chain: EvidenceChain) -> Dict[str, Any]:
        src_ips = chain.entities.get("src_ip", [])[:3]
        dst_ips = chain.entities.get("dst_ip", [])[:3]
        files = chain.entities.get("file_path", [])[:3]
        uris = []
        patterns = []
        for ev in chain.events:
            if ev.uri:
                uris.append(self._norm_uri(ev.uri))
            if ev.metadata and isinstance(ev.metadata.get("patterns"), list):
                patterns.extend(str(p) for p in ev.metadata["patterns"])
        variant_material = "|".join(sorted(set(uris + patterns + files + dst_ips))) or chain.attack_type
        variant = hashlib.sha256(variant_material.encode()).hexdigest()[:16]
        return {
            "src_ips": src_ips,
            "dst_ips": dst_ips,
            "files": files,
            "attack_types": [chain.attack_type],
            "patterns": sorted(set(patterns)),
            "uris": sorted(set(uris))[:5],
            "variant": variant,
        }

    def _key(self, features: Dict[str, Any]) -> str:
        # Prefer actor + attack class + pattern so payload mutations/C2 changes stay in one loop.
        # If the actor rotates, fall back to pattern + C2/file artifact grouping.
        if features.get("src_ips"):
            material_parts = ["src=" + ",".join(features["src_ips"][:2])]
            if features.get("attack_types"):
                material_parts.append("atype=" + features["attack_types"][0])
            if features.get("patterns"):
                material_parts.append("pat=" + ",".join(features["patterns"][:3]))
        else:
            material_parts = []
            if features.get("attack_types"):
                material_parts.append("atype=" + features["attack_types"][0])
            if features.get("patterns"):
                material_parts.append("pat=" + ",".join(features["patterns"][:3]))
            if features.get("dst_ips"):
                material_parts.append("dst=" + ",".join(features["dst_ips"][:2]))
            if features.get("files"):
                material_parts.append("file=" + ",".join(features["files"][:2]))
        material = "|".join(material_parts) or "host-only"
        return hashlib.sha256(material.encode()).hexdigest()

    @staticmethod
    def _norm_uri(uri: str) -> str:
        u = URI_VALUE_RE.sub(r"=VALUE", uri or "")
        u = DIGIT_RE.sub("N", u)
        return u[:200]

    def _gc(self, now: int) -> None:
        cutoff = now - self.window_seconds
        self.state = {k: v for k, v in self.state.items() if int(v.get("last_seen", v.get("first_seen", now))) >= cutoff}

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8")
