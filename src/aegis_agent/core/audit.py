from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.utils import ensure_dir


class AuditLogger:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        ensure_dir(self.db_path.parent)
        self._init()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init(self):
        with self._connect() as con:
            con.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                host TEXT,
                score INTEGER,
                confidence TEXT,
                attack_type TEXT,
                hypothesis TEXT,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                action_id TEXT PRIMARY KEY,
                incident_id TEXT,
                created_at INTEGER NOT NULL,
                action TEXT,
                target TEXT,
                status TEXT,
                dry_run INTEGER,
                payload TEXT NOT NULL
            )
            """)
            con.commit()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def save_incident(self, incident: Dict[str, Any]):
        with self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    incident["incident_id"],
                    int(time.time()),
                    incident.get("host"),
                    int(incident.get("score", 0)),
                    incident.get("confidence"),
                    incident.get("attack_type"),
                    incident.get("hypothesis"),
                    json.dumps(incident, ensure_ascii=False),
                ),
            )
            con.commit()

    def save_action(self, incident_id: str, action_result: Dict[str, Any]):
        with self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO actions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    action_result["action_id"],
                    incident_id,
                    int(time.time()),
                    action_result.get("action"),
                    action_result.get("target"),
                    action_result.get("status"),
                    1 if action_result.get("dry_run") else 0,
                    json.dumps(action_result, ensure_ascii=False),
                ),
            )
            con.commit()

    def list_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute("SELECT payload FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def list_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute("SELECT payload FROM actions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_action(self, action_id: str) -> Dict[str, Any] | None:
        with self._connect() as con:
            row = con.execute("SELECT payload FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def update_action_payload(self, action_id: str, payload: Dict[str, Any]) -> None:
        with self._connect() as con:
            con.execute(
                "UPDATE actions SET status = ?, dry_run = ?, payload = ? WHERE action_id = ?",
                (
                    payload.get("status"),
                    1 if payload.get("dry_run") else 0,
                    json.dumps(payload, ensure_ascii=False),
                    action_id,
                ),
            )
            con.commit()

    def list_expired_actions(self, now_epoch: int, limit: int = 100) -> List[Dict[str, Any]]:
        candidates = self.list_actions(limit=10000)
        expired: List[Dict[str, Any]] = []
        for action in candidates:
            if action.get("status") not in {"success"}:
                continue
            if action.get("rollback_result"):
                continue
            rollback = action.get("rollback") or {}
            expires_at = int(rollback.get("expires_at") or 0)
            if expires_at and expires_at <= now_epoch:
                expired.append(action)
            if len(expired) >= limit:
                break
        return expired
