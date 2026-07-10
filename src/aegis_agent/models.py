from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import time
import uuid


def new_id(prefix: str) -> str:
    return f"{prefix}-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


@dataclass
class Event:
    event_id: str
    timestamp: float
    source: str
    event_type: str
    host: str
    severity: str = "low"
    raw: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    file_path: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceChain:
    chain_id: str
    host: str
    events: List[Event]
    entities: Dict[str, List[str]]
    attack_type: str = "unknown"
    hypothesis: str = "insufficient_evidence"
    score: int = 0
    confidence: str = "low"
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["events"] = [e.to_dict() for e in self.events]
        return d


@dataclass
class AnalysisResult:
    incident_likelihood: str
    confidence_score: int
    attack_type: str
    hypothesis: str
    evidence_mapping: List[Dict[str, Any]]
    recommended_actions: List[Dict[str, Any]]
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionPlan:
    action_id: str
    action: str
    target: str
    reason: str
    evidence_ids: List[str]
    score: int
    ttl_seconds: Optional[int] = None
    rollback_supported: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionResult:
    action_id: str
    action: str
    target: str
    status: str
    dry_run: bool
    message: str = ""
    rollback: Dict[str, Any] = field(default_factory=dict)
    command: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
