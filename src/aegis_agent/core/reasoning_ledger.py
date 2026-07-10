from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.security.secrets import redact_secrets
from aegis_agent.utils import ensure_dir


class AIReasoningLedger:
    """Append-only evidence/AI/policy/enforcement ledger for competition proof.

    The ledger is deliberately defensive-only and stores sanitized reasoning artifacts:
    Evidence Chain input, AI/Rule output, planned/denied/executed actions, verification,
    rollback status, and loop phases. Secrets are redacted before writing.
    """

    def __init__(self, path: str | None = None, enabled: bool = True, max_chain_events: int = 200):
        self.enabled = bool(enabled)
        self.path = Path(path or "data/ai_reasoning_ledger.jsonl")
        self.max_chain_events = int(max_chain_events or 200)
        if self.enabled:
            ensure_dir(self.path.parent)
            self.path.touch(exist_ok=True)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def _trim_chain(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        c = dict(chain or {})
        events = list(c.get("events") or [])
        if len(events) > self.max_chain_events:
            c["events"] = events[: self.max_chain_events]
            c["events_truncated"] = len(events) - self.max_chain_events
        return c

    def append_incident(self, incident: Dict[str, Any], extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        rec = {
            "ledger_version": 1,
            "ts": int(time.time()),
            "incident_id": incident.get("incident_id"),
            "agent_id": incident.get("agent_id"),
            "host": incident.get("host"),
            "score": incident.get("score"),
            "confidence": incident.get("confidence"),
            "attack_type": incident.get("attack_type"),
            "hypothesis": incident.get("hypothesis"),
            "ai_provider": incident.get("ai_provider"),
            "chain": self._trim_chain(incident.get("chain") or {}),
            "analysis": incident.get("analysis"),
            "actions": incident.get("actions"),
            "denied_actions": incident.get("denied_actions"),
            "verification": incident.get("verification"),
            "attack_loop": incident.get("attack_loop"),
            "security_growth": incident.get("security_growth"),
            "loop_process": incident.get("loop_process"),
        }
        if extra:
            rec["extra"] = extra
        rec = redact_secrets(rec)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        return {"enabled": True, "path": str(self.path), "incident_id": incident.get("incident_id")}

    def read_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
        return rows[-int(limit or 20):]
