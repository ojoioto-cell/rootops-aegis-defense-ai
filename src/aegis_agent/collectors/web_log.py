from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List
from urllib.parse import unquote

from aegis_agent.collectors.tail_state import TailState
from aegis_agent.models import Event, new_id
from aegis_agent.utils import hostname, parse_apache_timestamp

ACCESS_RE = re.compile(r'(?P<src_ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<uri>\S+)\s+[^\"]+"\s+(?P<status>\d{3})')

SUSPICIOUS_PATTERNS = [
    ("path_traversal", re.compile(r"(\.\./|%2e%2e%2f|%252e%252e%252f)", re.I)),
    ("command_injection", re.compile(r"(;|%3b|\|\||\||%7c|`|\$\(|%24%28|/bin/(?:ba)?sh|(?:cmd|exec|shell|command|payload)=|(?:curl|wget)\s+(?:https?://|ftp://)|\bnc\s+-[A-Za-z]+)", re.I)),
    ("sql_injection", re.compile(r"(union\s+select|or\s+1=1|sleep\(|benchmark\(|information_schema)", re.I)),
    ("lfi_rfi", re.compile(r"(etc/passwd|proc/self/environ|php://|file://|http://|https://)", re.I)),
    ("known_vulnerability_exploit", re.compile(r"(\$\{[^\n]{0,80}jndi:|jndi:(?:ldap|rmi|dns|iiop)://|class\.module\.class(?:loader|Loader)|\(\)\s*\{\s*:;\s*\};|%\{[^\n]{0,120}(?:#|@java|ognl|memberAccess)|_ignition/execute-solution|vendor/phpunit|eval-stdin\.php)", re.I)),
    ("generic_vulnerability_probe", re.compile(r"(/(?:cgi-bin|solr/admin|actuator/(?:env|heapdump|jolokia)|jolokia|boaform|HNAP1|GponForm|api/jsonws|manager/html|\.env|\.git/config|xmlrpc\.php|wp-json|wp-admin|owa/auth|ecp/|autodiscover))", re.I)),
    ("webshell_probe", re.compile(r"(cmd=|exec=|shell=|passthru|system\()", re.I)),
]
URL_IP_RE = re.compile(r"https?://(?P<host>(?:\d{1,3}\.){3}\d{1,3})", re.I)
FILE_PATH_RE = re.compile(r"(?:-O\s+|>|path=|file=)(?P<path>/(?:[^&\s\"']+))", re.I)


def _extract_uri_entities(uri: str) -> dict:
    decoded = unquote(uri or "")
    meta = {"decoded_uri": decoded}
    m = URL_IP_RE.search(decoded)
    if m:
        meta["embedded_ip"] = m.group("host")
    m = FILE_PATH_RE.search(decoded)
    if m:
        meta["embedded_file_path"] = m.group("path")
    return meta


def collect_web_events(paths: List[str], *, state_dir: str | None = None, follow: bool = False, first_run: str = "full") -> List[Event]:
    events: List[Event] = []
    host = hostname()
    tailer = TailState(state_dir or "data/state") if follow else None
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        lines = tailer.read_lines(p, follow=True, first_run=first_run) if tailer else p.read_text(errors="ignore").splitlines()
        for line in lines:
            raw = line.strip()
            ts = parse_apache_timestamp(raw, time.time())
            m = ACCESS_RE.search(raw)
            if m:
                src_ip = m.group("src_ip")
                uri = m.group("uri")
                status = int(m.group("status"))
                event_type = "http_request"
                sev = "low"
                matched = []
                decoded = unquote(uri)
                for name, rx in SUSPICIOUS_PATTERNS:
                    if rx.search(uri) or rx.search(decoded):
                        matched.append(name)
                metadata = _extract_uri_entities(uri)
                metadata["patterns"] = matched
                if matched:
                    event_type = "web_attack_pattern"
                    sev = "high"
                events.append(Event(new_id("E"), ts, str(p), event_type, host, sev, raw, src_ip=src_ip, uri=uri, status_code=status, metadata=metadata))
            else:
                lower = raw.lower()
                if "error" in lower or "exception" in lower or "segmentation" in lower:
                    events.append(Event(new_id("E"), ts, str(p), "app_error", host, "medium", raw))
    return events
