from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List


class CentralClient:
    def __init__(self, enabled: bool = False, url: str = "", token: str = "", timeout: int = 5):
        self.enabled = enabled
        self.url = (url or "").rstrip("/")
        self.token = token
        self.timeout = timeout
        if self.enabled and str(self.token).strip() == "change-me":
            raise ValueError("refusing_central_enabled_with_default_token_change_me")

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request_json(self, method: str, path_or_url: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if not self.enabled or not self.url:
            return {"ok": False, "reason": "central_disabled"}
        url = path_or_url if path_or_url.startswith("http") else self.url + path_or_url
        data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {"ok": True, "status": resp.status, "body": json.loads(body) if body else {}}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            return {"ok": False, "status": exc.code, "reason": detail[:1000]}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}

    def send_incidents(self, agent_id: str, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not incidents:
            return {"sent": False, "reason": "empty"}
        result = self._request_json("POST", "/api/ingest", {"agent_id": agent_id, "incidents": incidents})
        return {"sent": bool(result.get("ok")), **result}

    def send_heartbeat(self, agent_id: str, status: Dict[str, Any]) -> Dict[str, Any]:
        payload = {"agent_id": agent_id, **status}
        result = self._request_json("POST", "/api/agents/heartbeat", payload)
        return {"sent": bool(result.get("ok")), **result}

    def fetch_policy(self, agent_id: str) -> Dict[str, Any]:
        result = self._request_json("GET", f"/api/policy/{agent_id}")
        if not result.get("ok"):
            return result
        body = result.get("body", {})
        return {"ok": True, "policy": body.get("policy"), "policy_id": body.get("policy_id"), "version": body.get("version"), "body": body}

    def fetch_iocs(self, agent_id: str = "") -> Dict[str, Any]:
        suffix = f"?agent_id={agent_id}" if agent_id else ""
        return self._request_json("GET", f"/api/iocs{suffix}")

    def create_ioc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request_json("POST", "/api/iocs", payload)

    def create_approval(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request_json("POST", "/api/approvals", payload)
