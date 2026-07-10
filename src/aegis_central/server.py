from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from aegis_agent.utils import ensure_dir
from aegis_agent.security.secrets import redact_secrets
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine

CENTRAL_VERSION = "0.3.1"


def _j(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def _policy_id(name: str, version: str, policy: Dict[str, Any]) -> str:
    digest = hashlib.sha256(_j(policy).encode("utf-8")).hexdigest()[:12]
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in name)[:40] or "policy"
    safe_ver = "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "-" for ch in version)[:20] or "v0"
    return f"{safe_name}-{safe_ver}-{digest}"


def _hash_id(prefix: str, payload: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_j(payload).encode('utf-8')).hexdigest()[:16]}"


def _json_loads_safe(raw: str | None, default: Any = None) -> Any:
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _safe_payload(raw: str | None, default: Any = None) -> Any:
    """Load payload and redact secret-like fields before returning to UI/API."""
    return redact_secrets(_json_loads_safe(raw, default))


def _safe_store(payload: Any) -> str:
    """Store redacted payload in central DB. Central never persists raw API keys."""
    return json.dumps(redact_secrets(payload), ensure_ascii=False)


def _now() -> int:
    return int(time.time())


def _age_label(epoch: int | None) -> str:
    if not epoch:
        return "unknown"
    delta = max(0, _now() - int(epoch))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _score_band(score: int | None) -> str:
    s = int(score or 0)
    if s >= 90:
        return "critical"
    if s >= 75:
        return "high"
    if s >= 60:
        return "medium"
    if s >= 30:
        return "low"
    return "info"


def _normalize_policy_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either full policy wrappers or raw policy documents from the UI/API."""
    if not isinstance(payload, dict):
        return {}
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else payload
    # If user pasted the whole central wrapper, unwrap one more level.
    if isinstance(policy, dict) and isinstance(policy.get("payload"), dict) and isinstance(policy["payload"].get("policy"), dict):
        policy = policy["payload"]["policy"]
    return policy if isinstance(policy, dict) else {}


def _dashboard_html() -> str:
    # Single-file SPA. No external dependencies so it works in isolated VM/offline environments.
    return r"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aegis Central Monitoring</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #111c33;
      --panel2: #16223d;
      --line: #263653;
      --text: #e5edf8;
      --muted: #9fb0c7;
      --accent: #38bdf8;
      --ok: #22c55e;
      --warn: #f59e0b;
      --bad: #ef4444;
      --critical: #fb7185;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #60a5fa;
      --info: #94a3b8;
      --white: #fff;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background: var(--bg); color: var(--text); }
    .layout { display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; }
    aside { background: #0b1220; border-right: 1px solid var(--line); padding: 22px 16px; position: sticky; top: 0; height: 100vh; overflow:auto; }
    main { padding: 22px; overflow: auto; }
    .brand { display:flex; gap:10px; align-items:center; margin-bottom: 18px; }
    .logo { width:36px; height:36px; border-radius:11px; background: linear-gradient(135deg, #38bdf8, #22c55e); box-shadow: 0 0 18px rgba(56,189,248,.35); }
    .brand h1 { font-size: 18px; margin:0; line-height:1.1; }
    .brand span { color: var(--muted); font-size:12px; }
    nav button { width:100%; display:flex; justify-content:space-between; align-items:center; border:0; color:var(--muted); background: transparent; padding:10px 12px; border-radius:10px; cursor:pointer; font-size:14px; text-align:left; }
    nav button:hover, nav button.active { color:var(--white); background: var(--panel2); }
    .small { font-size:12px; color:var(--muted); }
    .section { display:none; }
    .section.active { display:block; }
    .topbar { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom: 18px; }
    h2 { margin:0 0 6px; font-size:24px; }
    h3 { margin: 18px 0 10px; font-size:16px; }
    .toolbar { display:flex; gap:8px; flex-wrap: wrap; align-items:center; }
    button, input, select, textarea { font: inherit; }
    .btn { background: var(--accent); color:#06111f; border:0; padding:8px 12px; border-radius:10px; font-weight:700; cursor:pointer; }
    .btn.secondary { background: var(--panel2); color: var(--text); border:1px solid var(--line); }
    .btn.danger { background: #ef4444; color:white; }
    .btn.ghost { background: transparent; color: var(--accent); border:1px solid var(--line); }
    .input, textarea, select { background: #0b1220; color: var(--text); border:1px solid var(--line); border-radius:10px; padding:8px 10px; outline: none; }
    textarea { width:100%; min-height: 190px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; }
    .cards { display:grid; grid-template-columns: repeat(6, minmax(130px, 1fr)); gap:12px; margin-bottom: 16px; }
    .card { background: var(--panel); border:1px solid var(--line); border-radius:16px; padding:14px; min-height:80px; }
    .card .label { color: var(--muted); font-size:12px; }
    .card .value { font-size:28px; font-weight:800; margin-top:7px; }
    .grid2 { display:grid; grid-template-columns: 1fr 1fr; gap:14px; }
    .grid3 { display:grid; grid-template-columns: repeat(3, 1fr); gap:14px; }
    .panel { background: var(--panel); border:1px solid var(--line); border-radius:16px; padding:14px; margin-bottom: 14px; }
    table { width:100%; border-collapse: collapse; font-size:13px; }
    th, td { border-bottom:1px solid var(--line); padding:9px 8px; text-align:left; vertical-align:top; }
    th { color:#c9d8ef; font-size:12px; text-transform: uppercase; letter-spacing:.04em; background: rgba(255,255,255,.02); }
    tr:hover td { background: rgba(255,255,255,.025); }
    .badge { display:inline-flex; align-items:center; gap:5px; border-radius:999px; padding:3px 8px; font-size:12px; font-weight:700; border:1px solid transparent; }
    .badge.online, .badge.ok, .badge.success { background: rgba(34,197,94,.12); color:#86efac; border-color: rgba(34,197,94,.25); }
    .badge.offline, .badge.error, .badge.failed, .badge.denied { background: rgba(239,68,68,.12); color:#fca5a5; border-color: rgba(239,68,68,.25); }
    .badge.planned, .badge.pending { background: rgba(245,158,11,.12); color:#fcd34d; border-color: rgba(245,158,11,.25); }
    .badge.critical { background: rgba(251,113,133,.12); color:#fda4af; border-color: rgba(251,113,133,.25); }
    .badge.high { background: rgba(249,115,22,.12); color:#fdba74; border-color: rgba(249,115,22,.25); }
    .badge.medium { background: rgba(245,158,11,.12); color:#fcd34d; border-color: rgba(245,158,11,.25); }
    .badge.low, .badge.info { background: rgba(96,165,250,.12); color:#bfdbfe; border-color: rgba(96,165,250,.25); }
    .muted { color:var(--muted); }
    pre { white-space: pre-wrap; word-break: break-word; background:#0b1220; border:1px solid var(--line); border-radius:12px; padding:12px; max-height: 520px; overflow:auto; font-size:12px; }
    .modal { position: fixed; inset:0; display:none; background: rgba(0,0,0,.6); align-items:center; justify-content:center; padding:20px; z-index:20; }
    .modal.open { display:flex; }
    .modal-card { width:min(1100px, 96vw); max-height:90vh; overflow:auto; background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:18px; box-shadow: 0 25px 80px rgba(0,0,0,.45); }
    .modal-head { display:flex; justify-content:space-between; gap:12px; align-items:center; }
    .toast { position: fixed; right:20px; bottom:20px; background: #0b1220; border:1px solid var(--line); color:var(--text); padding:12px 14px; border-radius:12px; display:none; max-width:520px; z-index:30; }
    .toast.show { display:block; }
    .split { display:grid; grid-template-columns: 380px 1fr; gap:14px; }
    .kv { display:grid; grid-template-columns: 150px 1fr; gap:8px; font-size:13px; }
    @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } aside { position:static; height:auto; } .cards { grid-template-columns: repeat(2, 1fr); } .grid2, .grid3, .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<div class="layout">
  <aside>
    <div class="brand"><div class="logo"></div><div><h1>Aegis Central</h1><span>Control Plane UI</span></div></div>
    <nav id="nav">
      <button class="active" data-section="overview">Overview <span>⌘1</span></button>
      <button data-section="agents">Agents <span>⌘2</span></button>
      <button data-section="incidents">Incidents <span>⌘3</span></button>
      <button data-section="actions">Actions <span>⌘4</span></button>
      <button data-section="policies">Policies <span>⌘5</span></button>
      <button data-section="iocs">IOC <span>⌘6</span></button>
      <button data-section="approvals">Approvals <span>⌘7</span></button>
      <button data-section="championship">Championship <span>⌘8</span></button>
      <button data-section="battle">Live Evidence <span>⌘9</span></button>
    </nav>
    <div class="panel" style="margin-top:18px">
      <div class="small">Bearer token for write APIs</div>
      <input id="token" class="input" style="width:100%; margin-top:8px" placeholder="optional token" />
      <button class="btn secondary" style="width:100%; margin-top:8px" data-action="save-token">Save Token</button>
      <div class="small" style="margin-top:10px">Read APIs work without token unless server was started with auth policy for all endpoints. Write APIs require token when configured.</div>
    </div>
  </aside>
  <main>
    <section id="overview" class="section active">
      <div class="topbar"><div><h2>Overview</h2><div class="muted">서버별 Agent 상태, 침해 이벤트, 방어 액션, 정책/IOC/승인을 통합 관제합니다.</div></div><div class="toolbar"><button class="btn" data-action="refresh-all">Refresh</button></div></div>
      <div id="summaryCards" class="cards"></div>
      <div class="grid2">
        <div class="panel"><h3>Recent High Risk Incidents</h3><div id="recentHigh"></div></div>
        <div class="panel"><h3>Top Attack Types</h3><div id="topAttacks"></div></div>
      </div>
      <div class="grid2">
        <div class="panel"><h3>Agent Health</h3><div id="agentMini"></div></div>
        <div class="panel"><h3>Action Status</h3><div id="actionMini"></div></div>
      </div>
    </section>



    <section id="championship" class="section">
      <div class="topbar"><div><h2>Championship Mode</h2><div class="muted">AI 우선순위, fallback, 차단 성공률, 정책 승격, 차단 대상 지표를 한 화면에서 확인합니다.</div></div><button class="btn" data-action="load-championship">Refresh</button></div>
      <div id="championshipCards" class="cards"></div>
      <div class="grid2">
        <div class="panel"><h3>Policy Promotion Stage</h3><div id="championshipPromotion"></div></div>
        <div class="panel"><h3>Blocked / Limited Targets</h3><div id="championshipTargets"></div></div>
      </div>
      <div class="grid2">
        <div class="panel"><h3>Action Status</h3><div id="championshipActionStatus"></div></div>
        <div class="panel"><h3>AI Provider Modes</h3><div id="championshipAiModes"></div></div>
      </div>
      <div class="panel"><h3>Raw Championship Metrics</h3><pre id="championshipRaw"></pre></div>
    </section>

    <section id="battle" class="section">
      <div class="topbar"><div><h2>Live Battle Evidence</h2><div class="muted">본선 중 실제 incident/action/AI ledger/nftables 증거를 기준으로 탐지·차단·Rollback·AI 품질을 수치화합니다. Synthetic benchmark는 핵심 지표에서 제외됩니다.</div></div><button class="btn" data-action="load-battle">Refresh</button></div>
      <div id="battleCards" class="cards"></div>
      <div class="grid2">
        <div class="panel"><h3>Live Evidence Metrics</h3><div id="battleMetrics"></div></div>
        <div class="panel"><h3>AI Quality</h3><div id="battleAiQuality"></div></div>
      </div>
      <div class="grid2">
        <div class="panel"><h3>Blocked / Limited Targets</h3><div id="battleTargets"></div></div>
        <div class="panel"><h3>nftables Effect</h3><div id="battleNft"></div></div>
      </div>
      <div class="panel"><h3>Raw Live Battle Evidence</h3><pre id="battleRaw"></pre></div>
    </section>

    <section id="agents" class="section">
      <div class="topbar"><div><h2>Agents</h2><div class="muted">각 서버 Local Defense Agent의 heartbeat, 버전, 정책 상태를 확인합니다.</div></div><button class="btn" data-action="load-agents">Refresh</button></div>
      <div class="panel"><div id="agentsTable"></div></div>
    </section>

    <section id="incidents" class="section">
      <div class="topbar"><div><h2>Incidents</h2><div class="muted">Evidence Chain 기반 침해 판단 결과입니다.</div></div><div class="toolbar"><input id="incidentAgentFilter" class="input" placeholder="agent_id filter" /><button class="btn" data-action="load-incidents">Search</button></div></div>
      <div class="panel"><div id="incidentsTable"></div></div>
    </section>

    <section id="actions" class="section">
      <div class="topbar"><div><h2>Defense Actions</h2><div class="muted">Local Enforcement Layer에서 계획/실행한 방어 조치입니다.</div></div><div class="toolbar"><select id="actionStatusFilter" class="input"><option value="">all status</option><option>planned</option><option>success</option><option>failed</option><option>denied</option><option>rolled_back</option></select><button class="btn" data-action="load-actions">Search</button></div></div>
      <div class="panel"><div id="actionsTable"></div></div>
    </section>

    <section id="policies" class="section">
      <div class="topbar"><div><h2>Policies</h2><div class="muted">중앙 정책 저장소와 Agent별 정책 배포입니다.</div></div><button class="btn" data-action="load-policies">Refresh</button></div>
      <div class="split">
        <div class="panel"><h3>Create / Update Policy</h3>
          <input id="policyName" class="input" style="width:100%; margin-bottom:8px" placeholder="name" value="default-response-policy" />
          <input id="policyVersion" class="input" style="width:100%; margin-bottom:8px" placeholder="version" value="1" />
          <textarea id="policyJson">{
  "policy": {
    "thresholds": {"collect_more": 30, "soft_response": 60, "active_response": 80},
    "actions": {
      "block_ip_ttl": {"enabled": true, "min_score": 60, "ttl_required": true, "rollback_required": true},
      "block_outbound_ip": {"enabled": true, "min_score": 75, "ttl_required": true, "rollback_required": true},
      "suspend_process": {"enabled": false, "auto_allowed": false, "min_score": 95, "rollback_required": true, "require_auditd_pid_relation": true},
      "quarantine_file": {"enabled": true, "min_score": 80, "rollback_required": true}
    }
  }
}</textarea>
          <button class="btn" data-action="create-policy">Save Policy</button>
        </div>
        <div class="panel"><h3>Policy Repository</h3><div id="policiesTable"></div><h3>Assign Policy</h3><div class="toolbar"><input id="assignAgent" class="input" placeholder="agent_id" /><input id="assignPolicy" class="input" placeholder="policy_id" /><button class="btn" data-action="assign-policy">Assign</button></div></div>
      </div>
    </section>

    <section id="iocs" class="section">
      <div class="topbar"><div><h2>IOC Repository</h2><div class="muted">유해 IP/해시/URL 등 중앙 IOC를 관리합니다.</div></div><button class="btn" data-action="load-iocs">Refresh</button></div>
      <div class="split">
        <div class="panel"><h3>Add IOC</h3>
          <input id="iocIndicator" class="input" style="width:100%; margin-bottom:8px" placeholder="indicator: IP/hash/URL" />
          <select id="iocType" class="input" style="width:100%; margin-bottom:8px"><option value="ip">ip</option><option value="hash">hash</option><option value="url">url</option><option value="domain">domain</option></select>
          <select id="iocAction" class="input" style="width:100%; margin-bottom:8px"><option value="block_ip_ttl">block_ip_ttl</option><option value="block_outbound_ip">block_outbound_ip</option><option value="quarantine_file">quarantine_file</option><option value="watch_only">watch_only</option></select>
          <input id="iocConfidence" class="input" style="width:100%; margin-bottom:8px" placeholder="confidence" value="90" />
          <input id="iocTtl" class="input" style="width:100%; margin-bottom:8px" placeholder="ttl seconds" value="86400" />
          <button class="btn" data-action="create-ioc">Add IOC</button>
        </div>
        <div class="panel"><h3>Active IOC</h3><div id="iocsTable"></div></div>
      </div>
    </section>

    <section id="approvals" class="section">
      <div class="topbar"><div><h2>Approvals</h2><div class="muted">고위험 방어 액션 승인 요청을 관리합니다.</div></div><button class="btn" data-action="load-approvals">Refresh</button></div>
      <div class="split">
        <div class="panel"><h3>Create Approval Request</h3>
          <input id="approvalAgent" class="input" style="width:100%; margin-bottom:8px" placeholder="agent_id" />
          <input id="approvalAction" class="input" style="width:100%; margin-bottom:8px" placeholder="requested_action, e.g. restrict_account" />
          <textarea id="approvalPayload">{
  "risk": "critical",
  "reason": "High-risk action requires operator approval",
  "target": "user01"
}</textarea>
          <button class="btn" data-action="create-approval">Create Request</button>
        </div>
        <div class="panel"><h3>Approval Queue</h3><div id="approvalsTable"></div></div>
      </div>
    </section>
  </main>
</div>

<div class="modal" id="modal"><div class="modal-card"><div class="modal-head"><h3 id="modalTitle">Detail</h3><button class="btn secondary" data-action="close-modal">Close</button></div><pre id="modalBody"></pre></div></div>
<div id="toast" class="toast"></div>

<script>
const qs = (s) => document.querySelector(s);
const qsa = (s) => [...document.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const pretty = (o) => JSON.stringify(o, null, 2);
function token(){ return localStorage.getItem('aegis_token') || ''; }
function saveToken(){ localStorage.setItem('aegis_token', qs('#token').value.trim()); toast('Token saved'); }
function headers(){ const h = {'Content-Type':'application/json'}; const t=token(); if(t) h.Authorization='Bearer '+t; return h; }
async function api(path, options={}){ const res = await fetch(path, {...options, headers:{...headers(), ...(options.headers||{})}}); const txt = await res.text(); let body; try{ body = txt ? JSON.parse(txt) : {}; }catch(e){ body = txt; } if(!res.ok){ throw new Error(typeof body==='string'?body:JSON.stringify(body)); } return body; }
function toast(msg){ const t=qs('#toast'); t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 3400); }
function badge(value){ const v=String(value ?? 'info').toLowerCase(); return `<span class="badge ${esc(v)}">${esc(value ?? '')}</span>`; }
function scoreBadge(score){ let band='info'; const s=Number(score||0); if(s>=90) band='critical'; else if(s>=75) band='high'; else if(s>=60) band='medium'; else if(s>=30) band='low'; return `<span class="badge ${band}">${s}</span>`; }
function openModal(title, obj){ qs('#modalTitle').textContent=title; qs('#modalBody').textContent=pretty(obj); qs('#modal').classList.add('open'); }
function closeModal(){ qs('#modal').classList.remove('open'); }
function table(headers, rows){ if(!rows.length) return '<div class="muted">No data</div>'; return `<table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`; }
qsa('nav button').forEach(b=>b.addEventListener('click',()=>{ qsa('nav button').forEach(x=>x.classList.remove('active')); b.classList.add('active'); qsa('.section').forEach(s=>s.classList.remove('active')); qs('#'+b.dataset.section).classList.add('active'); const loaders={overview:refreshAll,championship:loadChampionship,battle:loadBattle,agents:loadAgents,incidents:loadIncidents,actions:loadActions,policies:loadPolicies,iocs:loadIocs,approvals:loadApprovals}; loaders[b.dataset.section]?.(); }));
window.addEventListener('keydown', e=>{ if((e.metaKey||e.ctrlKey) && /^[1-9]$/.test(e.key)){ e.preventDefault(); qsa('nav button')[Number(e.key)-1]?.click(); } if(e.key==='Escape') closeModal(); });
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const id = btn.dataset.id || '';
  try {
    if (action === 'save-token') return saveToken();
    if (action === 'refresh-all') return refreshAll();
    if (action === 'load-agents') return loadAgents();
    if (action === 'load-incidents') return loadIncidents();
    if (action === 'load-actions') return loadActions();
    if (action === 'load-policies') return loadPolicies();
    if (action === 'create-policy') return createPolicy();
    if (action === 'assign-policy') return assignPolicy();
    if (action === 'load-iocs') return loadIocs();
    if (action === 'create-ioc') return createIoc();
    if (action === 'load-approvals') return loadApprovals();
    if (action === 'load-championship') return loadChampionship();
    if (action === 'load-battle') return loadBattle();
    if (action === 'create-approval') return createApproval();
    if (action === 'close-modal') return closeModal();
    if (action === 'agent-detail') return agentDetail(id);
    if (action === 'incident-detail') return incidentDetail(id);
    if (action === 'action-detail') return actionDetail(id);
    if (action === 'policy-select') return setAssignPolicy(id);
    if (action === 'policy-delete') return deletePolicy(id);
    if (action === 'ioc-delete') return deleteIoc(id);
    if (action === 'approval-detail') return openModal('Approval '+id, approvalCache.get(String(id)) || {request_id:id, status:'not_loaded'});
    if (action === 'approval-decision') return decideApproval(id, btn.dataset.status || 'pending');
  } catch (err) {
    toast('Error: ' + err.message);
    console.error(err);
  }
});

async function loadSummary(){
  const s = await api('/api/summary');
  qs('#summaryCards').innerHTML = [
    ['Agents', `${s.agents.online}/${s.agents.total}`, 'online / total'],
    ['Incidents', s.incidents.total, `last24h ${s.incidents.last24h}`],
    ['Critical', s.incidents.critical, 'score ≥ 90'],
    ['Actions', s.actions.total, `${s.actions.success} success / ${s.actions.planned} planned`],
    ['IOC', s.iocs.active, 'active indicators'],
    ['Approvals', s.approvals.pending, 'pending']
  ].map(c=>`<div class="card"><div class="label">${c[0]}</div><div class="value">${c[1]}</div><div class="small">${c[2]}</div></div>`).join('');
  qs('#topAttacks').innerHTML = table(['Attack Type','Count'], (s.top_attack_types||[]).map(x=>`<tr><td>${esc(x.attack_type)}</td><td>${x.count}</td></tr>`));
  qs('#actionMini').innerHTML = table(['Status','Count'], Object.entries(s.actions.by_status||{}).map(([k,v])=>`<tr><td>${badge(k)}</td><td>${v}</td></tr>`));
}
async function loadChampionship(){
  const c = await api('/api/championship');
  const modes = c.ai_modes || {};
  const modeNames = Object.keys(modes);
  let active = 'no-data';
  if (modes.gpt) active = 'GPT ACTIVE';
  else if (modes.ollama) active = 'OLLAMA FALLBACK';
  else if (modes.rule_based) active = 'RULE BASED';
  else if ((c.ai_fallback_count||0) > 0) active = 'FALLBACK';
  const stages = c.policy_promotion_stages || {};
  const promoted = stages.promoted || 0;
  const targets = c.blocked_or_limited_targets || [];
  qs('#championshipCards').innerHTML = [
    ['AI MODE', active, 'priority: '+(c.ai_priority||[]).join(' > ')],
    ['Fallback', c.ai_fallback_count || 0, 'AI fallback count'],
    ['Success %', (c.enforcement_success_rate ?? 0)+'%', 'enforcement success rate'],
    ['Promoted', promoted, 'verified policy promotions'],
    ['Blocked', targets.length, 'blocked / limited targets'],
    ['Actions', Object.values(c.action_counts||{}).reduce((a,b)=>a+Number(b||0),0), 'indexed actions']
  ].map(x=>`<div class="card"><div class="label">${esc(x[0])}</div><div class="value">${esc(x[1])}</div><div class="small">${esc(x[2])}</div></div>`).join('');
  qs('#championshipPromotion').innerHTML = table(['Stage','Count'], Object.entries(stages).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`));
  qs('#championshipTargets').innerHTML = targets.length ? `<pre>${esc(targets.join('\n'))}</pre>` : '<div class="muted">No blocked targets</div>';
  qs('#championshipActionStatus').innerHTML = table(['Status','Count'], Object.entries(c.action_status||{}).map(([k,v])=>`<tr><td>${badge(k)}</td><td>${esc(v)}</td></tr>`));
  qs('#championshipAiModes').innerHTML = table(['AI Mode','Count'], Object.entries(modes).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`));
  qs('#championshipRaw').textContent = pretty(c);
}


async function loadBattle(){
  const b = await api('/api/battle');
  const m = b.battle_metrics || {};
  const q = b.ai_quality || {};
  qs('#battleCards').innerHTML = [
    ['Scope', b.source_scope || 'live_only', 'evidence source'],
    ['AI MODE', b.ai_mode_status || 'NO DATA', 'current reasoning mode'],
    ['Success %', (m.enforcement_success_rate ?? 0)+'%', 'enforcement success'],
    ['Response', (m.mean_response_time_seconds ?? 0)+'s', 'mean response time'],
    ['Quality', (q.quality_score ?? 0), 'AI reasoning score'],
    ['Targets', (b.blocked_or_limited_targets||[]).length, 'blocked / limited']
  ].map(x=>`<div class="card"><div class="label">${esc(x[0])}</div><div class="value">${esc(x[1])}</div><div class="small">${esc(x[2])}</div></div>`).join('');
  qs('#battleMetrics').innerHTML = table(['Metric','Value'], Object.entries(m).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`));
  qs('#battleAiQuality').innerHTML = table(['Metric','Value'], Object.entries(q).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`));
  qs('#battleTargets').innerHTML = (b.blocked_or_limited_targets||[]).length ? `<pre>${esc((b.blocked_or_limited_targets||[]).join('\n'))}</pre>` : '<div class="muted">No blocked targets</div>';
  const nft = b.real_enforcement_proof || b.nftables_effect || {};
  qs('#battleNft').innerHTML = `<pre>${esc(JSON.stringify(nft, null, 2))}</pre>`;
  qs('#battleRaw').textContent = pretty(b);
}

async function loadAgents(){ const ag=await api('/api/agents?limit=500'); qs('#agentsTable').innerHTML = table(['Agent','Host','Version','Status','Policy','Last Seen','Detail'], ag.map(a=>`<tr><td>${esc(a.agent_id)}</td><td>${esc(a.hostname)}</td><td>${esc(a.version)}</td><td>${badge(a.computed_status||a.status)}</td><td>${esc(a.policy_version||'')}</td><td>${esc(a.last_seen_age||a.last_seen)}</td><td><button class="btn ghost" data-action="agent-detail" data-id="${esc(a.agent_id)}">Open</button></td></tr>`)); qs('#agentMini').innerHTML = qs('#agentsTable').innerHTML; }
async function agentDetail(id){ const d=await api('/api/agents/'+encodeURIComponent(id)); openModal('Agent '+id, d); }
async function loadIncidents(){ const f=qs('#incidentAgentFilter')?.value.trim(); const inc=await api('/api/incidents?limit=200'+(f?'&agent_id='+encodeURIComponent(f):'')); qs('#incidentsTable').innerHTML = table(['Time','Agent','Host','Score','Type','Actions','Detail'], inc.map(i=>`<tr><td>${esc(i.created_at_age||i.created_at)}</td><td>${esc(i.agent_id)}</td><td>${esc(i.host)}</td><td>${scoreBadge(i.score)}</td><td>${esc(i.attack_type)}</td><td>${(i.action_count||0)}</td><td><button class="btn ghost" data-action="incident-detail" data-id="${esc(i.row_id)}">Open</button></td></tr>`)); qs('#recentHigh').innerHTML = table(['Time','Agent','Score','Type'], inc.filter(i=>Number(i.score)>=75).slice(0,8).map(i=>`<tr><td>${esc(i.created_at_age||i.created_at)}</td><td>${esc(i.agent_id)}</td><td>${scoreBadge(i.score)}</td><td>${esc(i.attack_type)}</td></tr>`)); }
async function incidentDetail(id){ const d=await api('/api/incidents/'+encodeURIComponent(id)); openModal('Incident '+id, d); }
async function loadActions(){ const st=qs('#actionStatusFilter')?.value; const actions=await api('/api/actions?limit=300'+(st?'&status='+encodeURIComponent(st):'')); qs('#actionsTable').innerHTML = table(['Time','Agent','Incident','Action','Target','Status','Dry-run','Detail'], actions.map(a=>`<tr><td>${esc(a.created_at_age||a.created_at)}</td><td>${esc(a.agent_id)}</td><td>${esc(a.incident_id||'')}</td><td>${esc(a.action)}</td><td>${esc(a.target)}</td><td>${badge(a.status)}</td><td>${a.dry_run?'yes':'no'}</td><td><button class="btn ghost" data-action="action-detail" data-id="${esc(a.action_id)}">Open</button></td></tr>`)); }
async function actionDetail(id){ const d=await api('/api/actions/'+encodeURIComponent(id)); openModal('Action '+id, d); }
async function loadPolicies(){ const p=await api('/api/policies?limit=200'); qs('#policiesTable').innerHTML = table(['Policy ID','Name','Version','Created','Use'], p.map(x=>`<tr><td>${esc(x.policy_id)}</td><td>${esc(x.name)}</td><td>${esc(x.version)}</td><td>${esc(x.created_at_age||x.created_at)}</td><td><button class="btn ghost" data-action="policy-select" data-id="${esc(x.policy_id)}">Select</button> <button class="btn danger" data-action="policy-delete" data-id="${esc(x.policy_id)}">Delete</button></td></tr>`)); }
function setAssignPolicy(id){ qs('#assignPolicy').value=id; toast('Policy selected'); }
async function createPolicy(){ const raw=qs('#policyJson').value; let data; try{ data=JSON.parse(raw); }catch(e){ return toast('Invalid JSON'); } data.name=qs('#policyName').value||'policy'; data.version=qs('#policyVersion').value||'1'; const r=await api('/api/policies',{method:'POST',body:JSON.stringify(data)}); toast('Policy saved: '+r.policy_id); await loadPolicies(); }
async function assignPolicy(){ const agent_id=qs('#assignAgent').value.trim(); const policy_id=qs('#assignPolicy').value.trim(); if(!agent_id||!policy_id) return toast('agent_id and policy_id required'); const r=await api('/api/policy/assign',{method:'POST',body:JSON.stringify({agent_id,policy_id})}); toast('Assigned '+r.policy_id+' to '+r.agent_id); }
async function deletePolicy(id){ if(!confirm('Delete policy '+id+'?')) return; await api('/api/policies/'+encodeURIComponent(id),{method:'DELETE'}); toast('Policy deleted'); await loadPolicies(); }
async function loadIocs(){ const i=await api('/api/iocs?limit=500'); qs('#iocsTable').innerHTML = table(['Indicator','Type','Action','Confidence','Expires','Delete'], i.map(x=>`<tr><td>${esc(x.indicator)}</td><td>${esc(x.type)}</td><td>${esc(x.action)}</td><td>${scoreBadge(x.confidence)}</td><td>${esc(x.expires_at_age||x.expires_at)}</td><td><button class="btn danger" data-action="ioc-delete" data-id="${esc(x.ioc_id)}">Delete</button></td></tr>`)); }
async function createIoc(){ const payload={indicator:qs('#iocIndicator').value.trim(),type:qs('#iocType').value,action:qs('#iocAction').value,confidence:Number(qs('#iocConfidence').value||80),ttl_seconds:Number(qs('#iocTtl').value||86400)}; if(!payload.indicator) return toast('indicator required'); const r=await api('/api/iocs',{method:'POST',body:JSON.stringify(payload)}); toast('IOC added: '+r.ioc_id); await loadIocs(); }
async function deleteIoc(id){ if(!confirm('Delete IOC '+id+'?')) return; await api('/api/iocs/'+encodeURIComponent(id),{method:'DELETE'}); toast('IOC deleted'); await loadIocs(); }
const approvalCache = new Map();
async function loadApprovals(){ const a=await api('/api/approvals?limit=200'); approvalCache.clear(); a.forEach(x=>approvalCache.set(String(x.request_id), x)); qs('#approvalsTable').innerHTML = table(['Request','Status','Updated','Action','Decision'], a.map(x=>`<tr><td>${esc(x.request_id)}</td><td>${badge(x.status)}</td><td>${esc(x.updated_at_age||x.updated_at)}</td><td>${esc(x.payload?.requested_action||x.payload?.action||'')}</td><td><button class="btn" data-action="approval-decision" data-id="${esc(x.request_id)}" data-status="approved">Approve</button> <button class="btn danger" data-action="approval-decision" data-id="${esc(x.request_id)}" data-status="rejected">Reject</button> <button class="btn ghost" data-action="approval-detail" data-id="${esc(x.request_id)}">Detail</button></td></tr>`)); }
async function createApproval(){ let extra={}; try{ extra=JSON.parse(qs('#approvalPayload').value||'{}'); }catch(e){ return toast('Invalid approval JSON'); } const payload={agent_id:qs('#approvalAgent').value.trim(),requested_action:qs('#approvalAction').value.trim(),status:'pending',...extra}; const r=await api('/api/approvals',{method:'POST',body:JSON.stringify(payload)}); toast('Approval created: '+r.request_id); await loadApprovals(); }
async function decideApproval(id,status){ const reason=prompt('Decision reason', status); if(reason===null) return; await api('/api/approvals/'+encodeURIComponent(id)+'/decision',{method:'POST',body:JSON.stringify({status,reviewer:'ui',reason})}); toast('Approval '+status); await loadApprovals(); }
async function refreshAll(){ try{ await loadSummary(); await loadChampionship(); await loadBattle(); await loadAgents(); await loadIncidents(); await loadActions(); await loadPolicies(); await loadIocs(); await loadApprovals(); } catch(e){ toast('Error: '+e.message); console.error(e); } }
qs('#token').value=token();
refreshAll();
setInterval(()=>{ if(qs('#overview').classList.contains('active')) refreshAll().catch(()=>{}); }, 30000);
</script>
</body>
</html>
"""


def create_app(db_path: str = "data/central.db", auth_token: str = "", require_read_auth: bool = False) -> FastAPI:
    app = FastAPI(title="Aegis Central Monitoring", version=CENTRAL_VERSION)
    db = Path(db_path)
    ensure_dir(db.parent)
    app.state.auth_token = auth_token
    app.state.require_read_auth = bool(require_read_auth)

    def init_db() -> None:
        with sqlite3.connect(db) as con:
            con.execute("""
            CREATE TABLE IF NOT EXISTS ingested_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                agent_id TEXT,
                host TEXT,
                score INTEGER,
                attack_type TEXT,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS action_index (
                action_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                incident_id TEXT,
                incident_row_id INTEGER,
                agent_id TEXT,
                host TEXT,
                action TEXT,
                target TEXT,
                status TEXT,
                dry_run INTEGER,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT,
                version TEXT,
                mode TEXT,
                status TEXT,
                policy_version TEXT,
                last_seen INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS policy_assignments (
                agent_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                assigned_at INTEGER NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                type TEXT NOT NULL,
                action TEXT NOT NULL,
                confidence INTEGER,
                ttl_seconds INTEGER,
                source TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                payload TEXT NOT NULL
            )
            """)
            con.execute("""
            CREATE TABLE IF NOT EXISTS approvals (
                request_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_incidents_agent ON ingested_incidents(agent_id, created_at)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_incidents_score ON ingested_incidents(score, created_at)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_actions_agent ON action_index(agent_id, created_at)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_actions_status ON action_index(status, created_at)")
            con.commit()
    init_db()
    try:
        os.chmod(db, 0o600)
    except OSError:
        pass

    def require_auth(request: Request) -> None:
        token = app.state.auth_token
        if not token:
            return
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="unauthorized")

    def require_read_auth_if_enabled(request: Request) -> None:
        if app.state.require_read_auth:
            if not app.state.auth_token:
                raise HTTPException(status_code=500, detail="read_auth_enabled_without_token")
            require_auth(request)

    def _agent_status(last_seen: int, raw_status: str | None, online_window_seconds: int = 120) -> str:
        if raw_status == "error":
            return "error"
        if _now() - int(last_seen or 0) <= online_window_seconds:
            return "online"
        return "offline"

    def _action_from_row(row: Iterable[Any]) -> Dict[str, Any]:
        r = list(row)
        payload = _safe_payload(r[10], {})
        return {
            "action_id": r[0], "created_at": r[1], "created_at_age": _age_label(r[1]), "incident_id": r[2],
            "incident_row_id": r[3], "agent_id": r[4], "host": r[5], "action": r[6], "target": r[7],
            "status": r[8], "dry_run": bool(r[9]), "payload": payload,
        }

    def _incident_from_row(row: Iterable[Any]) -> Dict[str, Any]:
        r = list(row)
        payload = _safe_payload(r[6], {})
        actions = payload.get("actions", []) if isinstance(payload, dict) else []
        return {
            "row_id": r[0], "created_at": r[1], "created_at_age": _age_label(r[1]), "agent_id": r[2],
            "host": r[3], "score": r[4], "score_band": _score_band(r[4]), "attack_type": r[5],
            "incident_id": payload.get("incident_id") if isinstance(payload, dict) else None,
            "action_count": len(actions), "payload": payload,
        }

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "aegis-central", "version": CENTRAL_VERSION}

    @app.get("/api/summary")
    def summary(request: Request, online_window_seconds: int = 120):
        require_read_auth_if_enabled(request)
        now = _now()
        day_ago = now - 86400
        with sqlite3.connect(db) as con:
            agent_rows = con.execute("SELECT status, last_seen FROM agents").fetchall()
            incident_total = con.execute("SELECT COUNT(*) FROM ingested_incidents").fetchone()[0]
            incident_24h = con.execute("SELECT COUNT(*) FROM ingested_incidents WHERE created_at >= ?", (day_ago,)).fetchone()[0]
            critical = con.execute("SELECT COUNT(*) FROM ingested_incidents WHERE score >= 90").fetchone()[0]
            high = con.execute("SELECT COUNT(*) FROM ingested_incidents WHERE score >= 75 AND score < 90").fetchone()[0]
            policies_count = con.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
            active_ioc = con.execute("SELECT COUNT(*) FROM iocs WHERE expires_at IS NULL OR expires_at > ?", (now,)).fetchone()[0]
            pending = con.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
            action_total = con.execute("SELECT COUNT(*) FROM action_index").fetchone()[0]
            status_rows = con.execute("SELECT COALESCE(status, 'unknown'), COUNT(*) FROM action_index GROUP BY status").fetchall()
            top_rows = con.execute("SELECT COALESCE(attack_type, 'unknown'), COUNT(*) FROM ingested_incidents GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 8").fetchall()
        online = sum(1 for st, last in agent_rows if _agent_status(last, st, online_window_seconds) == "online")
        offline = max(0, len(agent_rows) - online)
        by_status = {str(k): int(v) for k, v in status_rows}
        return {
            "version": CENTRAL_VERSION,
            "generated_at": now,
            "agents": {"total": len(agent_rows), "online": online, "offline": offline},
            "incidents": {"total": incident_total, "last24h": incident_24h, "critical": critical, "high": high},
            "actions": {"total": action_total, "planned": by_status.get("planned", 0), "success": by_status.get("success", 0), "failed": by_status.get("failed", 0), "by_status": by_status},
            "iocs": {"active": active_ioc},
            "policies": {"total": policies_count},
            "approvals": {"pending": pending},
            "top_attack_types": [{"attack_type": a, "count": c} for a, c in top_rows],
        }

    @app.get("/api/championship")
    def championship(request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            incidents = con.execute("SELECT payload FROM ingested_incidents ORDER BY created_at DESC LIMIT 300").fetchall()
            actions_rows = con.execute("SELECT action, status, target FROM action_index ORDER BY created_at DESC LIMIT 500").fetchall()
            active_iocs = con.execute("SELECT COUNT(*) FROM iocs WHERE expires_at IS NULL OR expires_at > ?", (_now(),)).fetchone()[0]
            pending_approvals = con.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
        ai_modes = {}
        fallback = 0
        promotion_stages = {}
        promotion_ioc_candidates = 0
        promotion_shadow_policies = 0
        ttl_recommendations: Dict[str, int] = {}
        for (payload_text,) in incidents:
            payload = _safe_payload(payload_text, {})
            if not isinstance(payload, dict):
                continue
            ai_status = payload.get("ai_status") or {}
            mode = str((ai_status or {}).get("provider_used") or payload.get("ai_provider") or "unknown")
            ai_modes[mode] = ai_modes.get(mode, 0) + 1
            if (ai_status or {}).get("fallback"):
                fallback += 1
            for promo in ((payload.get("policy_promotion") or {}).get("promotions") or []):
                st = str(promo.get("stage", "candidate"))
                promotion_stages[st] = promotion_stages.get(st, 0) + 1
                if promo.get("ioc_candidate"):
                    promotion_ioc_candidates += 1
                if promo.get("shadow_policy"):
                    promotion_shadow_policies += 1
                action = str(promo.get("action") or "unknown")
                ttl = int(promo.get("recommended_ttl_seconds") or 0)
                if ttl:
                    ttl_recommendations[action] = max(ttl_recommendations.get(action, 0), ttl)
        status_counts = {}
        action_counts = {}
        blocked = set()
        for action, status, target in actions_rows:
            action_counts[str(action)] = action_counts.get(str(action), 0) + 1
            status_counts[str(status)] = status_counts.get(str(status), 0) + 1
            if action in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"} and target:
                blocked.add(str(target))
        total_actions = sum(action_counts.values())
        success = status_counts.get("success", 0)
        if ai_modes.get("gpt"):
            ai_mode_status = "GPT ACTIVE"
        elif ai_modes.get("ollama"):
            ai_mode_status = "OLLAMA FALLBACK"
        elif ai_modes.get("rule_based"):
            ai_mode_status = "RULE_BASED ONLY" if not fallback else "RULE_BASED FALLBACK"
        else:
            ai_mode_status = "NO AI DATA"
        return {
            "version": CENTRAL_VERSION,
            "championship_mode": True,
            "ai_priority": ["gpt", "ollama", "rule_based"],
            "ai_mode_status": ai_mode_status,
            "ai_modes": ai_modes,
            "ai_fallback_count": fallback,
            "policy_promotion_stages": promotion_stages,
            "policy_promotion_ioc_candidate_count": promotion_ioc_candidates,
            "policy_promotion_shadow_policy_count": promotion_shadow_policies,
            "policy_promotion_approval_pending_count": pending_approvals,
            "ttl_recommendations": ttl_recommendations,
            "central_active_iocs": active_iocs,
            "central_pending_approvals": pending_approvals,
            "action_counts": action_counts,
            "action_status": status_counts,
            "enforcement_success_rate": round((success / total_actions) * 100, 2) if total_actions else 0.0,
            "blocked_or_limited_targets": sorted(blocked)[:100],
        }

    @app.get("/api/battle")
    def battle(request: Request, include_synthetic: bool = False):
        require_read_auth_if_enabled(request)
        # Central calculates live battle evidence from ingested incidents/actions.
        # It intentionally focuses on real runtime evidence and excludes optional
        # synthetic AI Duel demo/test records unless include_synthetic=true.
        tmp_audit = db.parent / "central_live_battle_evidence.db"
        try:
            from aegis_agent.core.audit import AuditLogger
            audit = AuditLogger(str(tmp_audit))
            with sqlite3.connect(db) as con:
                inc_rows = con.execute("SELECT payload FROM ingested_incidents ORDER BY created_at DESC LIMIT 500").fetchall()
                act_rows = con.execute("SELECT incident_id, payload FROM action_index ORDER BY created_at DESC LIMIT 1000").fetchall()
            for (payload_text,) in inc_rows:
                payload = _safe_payload(payload_text, {})
                if isinstance(payload, dict) and payload.get("incident_id"):
                    audit.save_incident(payload)
            for incident_id, payload_text in act_rows:
                payload = _safe_payload(payload_text, {})
                if isinstance(payload, dict) and payload.get("action_id"):
                    audit.save_action(incident_id or payload.get("incident_id") or "central", payload)
            return LiveBattleEvidenceEngine(str(tmp_audit)).compute(limit=500, include_synthetic=include_synthetic)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/agents/heartbeat")
    async def heartbeat(request: Request):
        require_auth(request)
        payload = await request.json()
        agent_id = payload.get("agent_id")
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id_required")
        now = _now()
        with sqlite3.connect(db) as con:
            con.execute(
                "INSERT OR REPLACE INTO agents(agent_id, hostname, version, mode, status, policy_version, last_seen, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    agent_id,
                    payload.get("hostname") or payload.get("host"),
                    payload.get("version"),
                    payload.get("mode"),
                    payload.get("status", "online"),
                    payload.get("policy_version"),
                    now,
                    _safe_store(payload),
                ),
            )
            con.commit()
        return {"status": "stored", "agent_id": agent_id, "last_seen": now}

    @app.get("/api/agents")
    def agents(request: Request, limit: int = 200, online_window_seconds: int = 120):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            rows = con.execute(
                "SELECT agent_id, hostname, version, mode, status, policy_version, last_seen, payload FROM agents ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            payload = _safe_payload(r[7], {})
            out.append({
                "agent_id": r[0], "hostname": r[1], "version": r[2], "mode": r[3], "status": r[4],
                "computed_status": _agent_status(r[6], r[4], online_window_seconds),
                "policy_version": r[5], "last_seen": r[6], "last_seen_age": _age_label(r[6]), "payload": payload,
            })
        return out

    @app.get("/api/agents/{agent_id}")
    def agent_detail(agent_id: str, request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            row = con.execute("SELECT agent_id, hostname, version, mode, status, policy_version, last_seen, payload FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="agent_not_found")
            incidents_count = con.execute("SELECT COUNT(*) FROM ingested_incidents WHERE agent_id = ?", (agent_id,)).fetchone()[0]
            actions_count = con.execute("SELECT COUNT(*) FROM action_index WHERE agent_id = ?", (agent_id,)).fetchone()[0]
            policy_row = con.execute("SELECT policy_id, assigned_at FROM policy_assignments WHERE agent_id = ?", (agent_id,)).fetchone()
        return {
            "agent_id": row[0], "hostname": row[1], "version": row[2], "mode": row[3], "status": row[4],
            "computed_status": _agent_status(row[6], row[4]), "policy_version": row[5], "last_seen": row[6], "last_seen_age": _age_label(row[6]),
            "incident_count": incidents_count, "action_count": actions_count,
            "assigned_policy": {"policy_id": policy_row[0], "assigned_at": policy_row[1]} if policy_row else None,
            "payload": _safe_payload(row[7], {}),
        }

    @app.post("/api/ingest")
    async def ingest(request: Request):
        require_auth(request)
        payload = await request.json()
        incidents = payload.get("incidents", []) if isinstance(payload, dict) else []
        agent_id = payload.get("agent_id") if isinstance(payload, dict) else None
        now = _now()
        stored_actions = 0
        with sqlite3.connect(db) as con:
            for inc in incidents:
                inc_agent = agent_id or inc.get("agent_id") or inc.get("host")
                cur = con.execute(
                    "INSERT INTO ingested_incidents(created_at, agent_id, host, score, attack_type, payload) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        now,
                        inc_agent,
                        inc.get("host"),
                        int(inc.get("score", 0)),
                        inc.get("attack_type"),
                        _safe_store(inc),
                    ),
                )
                row_id = cur.lastrowid
                incident_id = inc.get("incident_id") or _hash_id("INC", inc)
                for action in inc.get("actions", []) or []:
                    action_id = action.get("action_id") or _hash_id("ACT", {"incident_id": incident_id, "action": action})
                    con.execute(
                        "INSERT OR REPLACE INTO action_index(action_id, created_at, incident_id, incident_row_id, agent_id, host, action, target, status, dry_run, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            action_id,
                            now,
                            incident_id,
                            row_id,
                            inc_agent,
                            inc.get("host"),
                            action.get("action"),
                            str(action.get("target", "")),
                            action.get("status", "unknown"),
                            1 if action.get("dry_run") else 0,
                            _safe_store(action),
                        ),
                    )
                    stored_actions += 1
            con.commit()
        return {"status": "stored", "count": len(incidents), "actions_indexed": stored_actions}

    @app.get("/api/incidents")
    def incidents(request: Request, limit: int = 50, agent_id: str = "", min_score: int = 0):
        require_read_auth_if_enabled(request)
        query = "SELECT id, created_at, agent_id, host, score, attack_type, payload FROM ingested_incidents"
        params: list[Any] = []
        clauses = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if min_score:
            clauses.append("score >= ?")
            params.append(min_score)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(db) as con:
            rows = con.execute(query, tuple(params)).fetchall()
        return [_incident_from_row(r) for r in rows]

    @app.get("/api/incidents/{row_id}")
    def incident_detail(row_id: int, request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            row = con.execute("SELECT id, created_at, agent_id, host, score, attack_type, payload FROM ingested_incidents WHERE id = ?", (row_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="incident_not_found")
            actions = con.execute("SELECT action_id, created_at, incident_id, incident_row_id, agent_id, host, action, target, status, dry_run, payload FROM action_index WHERE incident_row_id = ? ORDER BY created_at DESC", (row_id,)).fetchall()
        inc = _incident_from_row(row)
        inc["indexed_actions"] = [_action_from_row(a) for a in actions]
        return inc

    @app.get("/api/actions")
    def actions(request: Request, limit: int = 200, agent_id: str = "", status: str = ""):
        require_read_auth_if_enabled(request)
        query = "SELECT action_id, created_at, incident_id, incident_row_id, agent_id, host, action, target, status, dry_run, payload FROM action_index"
        params: list[Any] = []
        clauses = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(db) as con:
            rows = con.execute(query, tuple(params)).fetchall()
        return [_action_from_row(r) for r in rows]

    @app.get("/api/actions/{action_id}")
    def action_detail(action_id: str, request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            row = con.execute("SELECT action_id, created_at, incident_id, incident_row_id, agent_id, host, action, target, status, dry_run, payload FROM action_index WHERE action_id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="action_not_found")
        return _action_from_row(row)

    @app.post("/api/policies")
    async def create_policy(request: Request):
        require_auth(request)
        payload = await request.json()
        name = payload.get("name", "default")
        version = payload.get("version", "v1")
        policy = redact_secrets(_normalize_policy_payload(payload))
        if not policy:
            raise HTTPException(status_code=400, detail="policy_required")
        policy_id = payload.get("policy_id") or _policy_id(name, version, policy)
        now = _now()
        stored = {"policy_id": policy_id, "name": name, "version": version, "policy": policy}
        with sqlite3.connect(db) as con:
            con.execute(
                "INSERT OR REPLACE INTO policies(policy_id, name, version, created_at, payload) VALUES (?, ?, ?, ?, ?)",
                (policy_id, name, version, now, _safe_store(stored)),
            )
            con.commit()
        return {"status": "stored", "policy_id": policy_id, "version": version}

    @app.get("/api/policies")
    def list_policies(request: Request, limit: int = 100):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            rows = con.execute("SELECT policy_id, name, version, created_at, payload FROM policies ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            assignments = dict(con.execute("SELECT policy_id, COUNT(*) FROM policy_assignments GROUP BY policy_id").fetchall())
        return [
            {
                "policy_id": r[0], "name": r[1], "version": r[2], "created_at": r[3], "created_at_age": _age_label(r[3]),
                "assigned_agents": int(assignments.get(r[0], 0)), "payload": _safe_payload(r[4], {}),
            }
            for r in rows
        ]

    @app.get("/api/policies/{policy_id}")
    def get_policy_by_id(policy_id: str, request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            row = con.execute("SELECT policy_id, name, version, created_at, payload FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="policy_not_found")
        return {"policy_id": row[0], "name": row[1], "version": row[2], "created_at": row[3], "created_at_age": _age_label(row[3]), "payload": _safe_payload(row[4], {})}

    @app.delete("/api/policies/{policy_id}")
    async def delete_policy(policy_id: str, request: Request):
        require_auth(request)
        with sqlite3.connect(db) as con:
            con.execute("DELETE FROM policy_assignments WHERE policy_id = ?", (policy_id,))
            cur = con.execute("DELETE FROM policies WHERE policy_id = ?", (policy_id,))
            con.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="policy_not_found")
        return {"status": "deleted", "policy_id": policy_id}

    @app.post("/api/policy/assign")
    async def assign_policy(request: Request):
        require_auth(request)
        payload = await request.json()
        agent_id = payload.get("agent_id")
        policy_id = payload.get("policy_id")
        if not agent_id or not policy_id:
            raise HTTPException(status_code=400, detail="agent_id_and_policy_id_required")
        with sqlite3.connect(db) as con:
            exists = con.execute("SELECT 1 FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
            if not exists:
                raise HTTPException(status_code=404, detail="policy_not_found")
            con.execute("INSERT OR REPLACE INTO policy_assignments(agent_id, policy_id, assigned_at) VALUES (?, ?, ?)", (agent_id, policy_id, _now()))
            con.commit()
        return {"status": "assigned", "agent_id": agent_id, "policy_id": policy_id}

    @app.get("/api/policy/{agent_id}")
    def get_policy(agent_id: str, request: Request):
        require_read_auth_if_enabled(request)
        with sqlite3.connect(db) as con:
            row = con.execute(
                "SELECT p.payload FROM policies p JOIN policy_assignments a ON p.policy_id = a.policy_id WHERE a.agent_id = ?",
                (agent_id,),
            ).fetchone()
            if not row:
                row = con.execute("SELECT payload FROM policies ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row:
            return {"policy_id": None, "version": None, "policy": None, "status": "no_policy"}
        payload = _safe_payload(row[0], {})
        return {"policy_id": payload.get("policy_id"), "version": payload.get("version"), "policy": payload.get("policy"), "status": "ok"}

    @app.post("/api/iocs")
    async def create_ioc(request: Request):
        require_auth(request)
        payload = await request.json()
        indicator = payload.get("indicator")
        ioc_type = payload.get("type", "ip")
        action = payload.get("action", "block_ip_ttl")
        if not indicator:
            raise HTTPException(status_code=400, detail="indicator_required")
        now = _now()
        ttl = int(payload.get("ttl_seconds", 86400) or 86400)
        ioc_id = payload.get("ioc_id") or hashlib.sha256(f"{indicator}:{ioc_type}:{action}".encode()).hexdigest()[:16]
        expires_at = payload.get("expires_at") or now + ttl
        with sqlite3.connect(db) as con:
            con.execute(
                "INSERT OR REPLACE INTO iocs(ioc_id, indicator, type, action, confidence, ttl_seconds, source, created_at, expires_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ioc_id,
                    indicator,
                    ioc_type,
                    action,
                    int(payload.get("confidence", 80)),
                    ttl,
                    payload.get("source", "central"),
                    now,
                    int(expires_at) if expires_at else None,
                    _safe_store(payload),
                ),
            )
            con.commit()
        return {"status": "stored", "ioc_id": ioc_id, "expires_at": expires_at}

    @app.get("/api/iocs")
    def list_iocs(request: Request, limit: int = 500, include_expired: bool = False, agent_id: str = ""):
        require_read_auth_if_enabled(request)
        now = _now()
        query = "SELECT ioc_id, indicator, type, action, confidence, ttl_seconds, source, created_at, expires_at, payload FROM iocs"
        params: list[Any] = []
        if not include_expired:
            query += " WHERE expires_at IS NULL OR expires_at > ?"
            params.append(now)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(db) as con:
            rows = con.execute(query, tuple(params)).fetchall()
        return [
            {
                "ioc_id": r[0], "indicator": r[1], "type": r[2], "action": r[3], "confidence": r[4], "ttl_seconds": r[5],
                "source": r[6], "created_at": r[7], "created_at_age": _age_label(r[7]), "expires_at": r[8], "expires_at_age": _age_label(r[8]),
                "payload": _safe_payload(r[9], {}),
            }
            for r in rows
        ]

    @app.delete("/api/iocs/{ioc_id}")
    async def delete_ioc(ioc_id: str, request: Request):
        require_auth(request)
        with sqlite3.connect(db) as con:
            cur = con.execute("DELETE FROM iocs WHERE ioc_id = ?", (ioc_id,))
            con.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="ioc_not_found")
        return {"status": "deleted", "ioc_id": ioc_id}

    @app.post("/api/approvals")
    async def create_approval(request: Request):
        require_auth(request)
        payload = await request.json()
        request_id = payload.get("request_id") or _hash_id("APR", payload)
        now = _now()
        stored = {"request_id": request_id, "status": payload.get("status", "pending"), **payload}
        with sqlite3.connect(db) as con:
            con.execute(
                "INSERT OR REPLACE INTO approvals(request_id, status, created_at, updated_at, payload) VALUES (?, ?, ?, ?, ?)",
                (request_id, stored["status"], now, now, _safe_store(stored)),
            )
            con.commit()
        return {"status": "stored", "request_id": request_id}

    @app.get("/api/approvals")
    def list_approvals(request: Request, limit: int = 100, status: str = ""):
        require_read_auth_if_enabled(request)
        query = "SELECT request_id, status, created_at, updated_at, payload FROM approvals"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(db) as con:
            rows = con.execute(query, tuple(params)).fetchall()
        return [
            {"request_id": r[0], "status": r[1], "created_at": r[2], "created_at_age": _age_label(r[2]), "updated_at": r[3], "updated_at_age": _age_label(r[3]), "payload": _safe_payload(r[4], {})}
            for r in rows
        ]

    @app.post("/api/approvals/{request_id}/decision")
    async def decide_approval(request_id: str, request: Request):
        require_auth(request)
        payload = await request.json()
        status = payload.get("status")
        if status not in {"approved", "rejected", "pending", "cancelled"}:
            raise HTTPException(status_code=400, detail="invalid_status")
        with sqlite3.connect(db) as con:
            row = con.execute("SELECT created_at, payload FROM approvals WHERE request_id = ?", (request_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="approval_not_found")
            stored = _safe_payload(row[1], {})
            stored.update({"status": status, "reviewer": payload.get("reviewer"), "decision_reason": payload.get("reason"), "decided_at": _now()})
            con.execute("UPDATE approvals SET status = ?, updated_at = ?, payload = ? WHERE request_id = ?", (status, _now(), _safe_store(stored), request_id))
            con.commit()
        return {"status": "updated", "request_id": request_id, "decision": status}

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        require_read_auth_if_enabled(request)
        return _dashboard_html()

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request):
        require_read_auth_if_enabled(request)
        return _dashboard_html()

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--db", default="data/central.db")
    parser.add_argument("--token", default="", help="Optional bearer token required for write APIs")
    parser.add_argument("--require-read-auth", action="store_true", help="Require bearer token for dashboard and read APIs as well as write APIs")
    args = parser.parse_args()
    uvicorn.run(create_app(args.db, auth_token=args.token, require_read_auth=args.require_read_auth), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
