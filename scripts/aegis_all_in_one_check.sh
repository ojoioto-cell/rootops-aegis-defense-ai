#!/usr/bin/env bash
set -uo pipefail

# Aegis All-in-One Competition Check
# Runs all essential post-install, runtime, AI, self-protection, proof, and defense-path checks.
# Designed for beginner operation after all_in_one_competition_install.sh.
#
# Optional env:
#   AEGIS_INSTALL_DIR=/opt/aegis-linux-defense-agent
#   AEGIS_CONFIG_DIR=/etc/aegis
#   AEGIS_STATE_DIR=/var/lib/aegis
#   AEGIS_LOG_DIR=/var/log/aegis
#   AEGIS_RUN_DUEL_DEMO_CHECK=1|0      # default 1
#   AEGIS_RUN_PROOF_CHECK=1|0          # default 1
#   AEGIS_AUTO_RESET_BASELINE=1|0      # default 0; installer may set 1 for approved fresh install
#   AEGIS_FAIL_ON_AI_FALLBACK=1|0      # default 0; rule fallback is allowed for offline competition
#   
INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
LOG_DIR="${AEGIS_LOG_DIR:-/var/log/aegis}"
AGENT_CONFIG="${AEGIS_CONFIG:-${CONFIG_DIR}/agent.yaml}"
POLICY_CONFIG="${AEGIS_POLICY:-${CONFIG_DIR}/policy.yaml}"
PY="${INSTALL_DIR}/.venv/bin/python"
CENTRAL_ENV="${CONFIG_DIR}/central.env"
RUN_DUEL="${AEGIS_RUN_DUEL_DEMO_CHECK:-1}"
RUN_PROOF="${AEGIS_RUN_PROOF_CHECK:-1}"
AUTO_RESET="${AEGIS_AUTO_RESET_BASELINE:-0}"
FAIL_ON_AI_FALLBACK="${AEGIS_FAIL_ON_AI_FALLBACK:-0}"
CHECK_ROOT="${STATE_DIR}/checks"
TS="$(date +%Y%m%d_%H%M%S)"
CHECK_DIR="${CHECK_ROOT}/all_in_one_${TS}"
SUMMARY_JSON="${CHECK_DIR}/summary.json"
FAIL=0
WARN=0
PASS=0

mkdir -p "$CHECK_DIR" "$LOG_DIR" 2>/dev/null || true
chmod 700 "$CHECK_ROOT" "$CHECK_DIR" 2>/dev/null || true

say(){ echo "$*"; }
pass(){ echo "[PASS] $*"; PASS=$((PASS+1)); }
warn(){ echo "[WARN] $*"; WARN=$((WARN+1)); }
fail(){ echo "[FAIL] $*"; FAIL=$((FAIL+1)); }

run_required(){
  local name="$1"; shift
  local log="${CHECK_DIR}/${name}.log"
  say "== ${name} =="
  if "$@" >"$log" 2>&1; then
    cat "$log"
    pass "${name} completed"
    return 0
  else
    cat "$log"
    fail "${name} failed; log=${log}"
    return 1
  fi
}

run_advisory(){
  local name="$1"; shift
  local log="${CHECK_DIR}/${name}.log"
  say "== ${name} =="
  if "$@" >"$log" 2>&1; then
    cat "$log"
    pass "${name} completed"
    return 0
  else
    cat "$log"
    warn "${name} reported issue; log=${log}"
    return 0
  fi
}

read_central_env(){
  if [[ -f "$CENTRAL_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$CENTRAL_ENV" || true
  fi
  AEGIS_CENTRAL_HOST="${AEGIS_CENTRAL_HOST:-127.0.0.1}"
  AEGIS_CENTRAL_PORT="${AEGIS_CENTRAL_PORT:-8088}"
  AEGIS_CENTRAL_TOKEN="${AEGIS_CENTRAL_TOKEN:-}"
}

json_escape(){ python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

say "============================================================"
say " Aegis All-in-One Competition Check"
say "============================================================"
say "install_dir=${INSTALL_DIR}"
say "config=${AGENT_CONFIG}"
say "policy=${POLICY_CONFIG}"
say "check_dir=${CHECK_DIR}"
say

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  warn "Not running as root. Some nftables/systemd checks may fail. Recommended: sudo ${INSTALL_DIR}/scripts/aegis_all_in_one_check.sh"
fi

export PYTHONPATH="${INSTALL_DIR}${PYTHONPATH:+:$PYTHONPATH}"
cd "$INSTALL_DIR" 2>/dev/null || warn "Cannot cd to ${INSTALL_DIR}; continuing"
read_central_env

# 1. Core post-install validation.
if [[ -x "${INSTALL_DIR}/scripts/post_install_competition_check.sh" ]]; then
  run_required "01_post_install_competition_check" env AEGIS_INSTALL_DIR="$INSTALL_DIR" AEGIS_CONFIG_DIR="$CONFIG_DIR" AEGIS_STATE_DIR="$STATE_DIR" AEGIS_LOG_DIR="$LOG_DIR" "${INSTALL_DIR}/scripts/post_install_competition_check.sh" || true
else
  fail "post_install_competition_check.sh missing"
fi

# 2. AI/GPT connectivity diagnosis. Advisory unless strict mode is requested.
if [[ -x "${INSTALL_DIR}/scripts/diagnose_ai_connectivity.sh" ]]; then
  run_advisory "02_diagnose_ai_connectivity" "${INSTALL_DIR}/scripts/diagnose_ai_connectivity.sh" "$AGENT_CONFIG"
  if grep -qiE "rule fallback used|certificate verify|missing_api_key|secret_file_missing|SSL" "${CHECK_DIR}/02_diagnose_ai_connectivity.log" 2>/dev/null; then
    if [[ "$FAIL_ON_AI_FALLBACK" == "1" ]]; then
      fail "AI/GPT diagnostic reported fallback/TLS/API-key issue and AEGIS_FAIL_ON_AI_FALLBACK=1"
    else
      warn "AI/GPT diagnostic reported fallback/TLS/API-key issue; rule_based fallback remains available"
    fi
  fi
else
  warn "diagnose_ai_connectivity.sh missing"
fi

# 3. Secrets check.
if [[ -x "$PY" ]]; then
  run_advisory "03_secrets_check" "$PY" -m aegis_agent secrets-check --config "$AGENT_CONFIG"
else
  fail "Aegis Python missing: $PY"
fi

# 4. Self-protection check, with optional approved baseline refresh.
if [[ -x "$PY" ]]; then
  SELF_LOG="${CHECK_DIR}/04_self_check.log"
  say "== 04_self_check =="
  if "$PY" -m aegis_agent self-check --config "$AGENT_CONFIG" >"$SELF_LOG" 2>&1; then
    cat "$SELF_LOG"
    if grep -q '"ok": true' "$SELF_LOG"; then
      pass "self-check ok"
    else
      if [[ "$AUTO_RESET" == "1" ]]; then
        warn "self-check reported change; refreshing approved install baseline and rechecking"
        "$PY" -m aegis_agent reset-self-baseline --config "$AGENT_CONFIG" >"${CHECK_DIR}/04_reset_self_baseline.log" 2>&1 || true
        cat "${CHECK_DIR}/04_reset_self_baseline.log" || true
        if "$PY" -m aegis_agent self-check --config "$AGENT_CONFIG" >"${CHECK_DIR}/04_self_check_after_reset.log" 2>&1 && grep -q '"ok": true' "${CHECK_DIR}/04_self_check_after_reset.log"; then
          cat "${CHECK_DIR}/04_self_check_after_reset.log"
          pass "self-check ok after approved baseline reset"
        else
          cat "${CHECK_DIR}/04_self_check_after_reset.log" 2>/dev/null || true
          fail "self-check still reports integrity issue after baseline reset"
        fi
      else
        cat "$SELF_LOG"
        fail "self-check reports integrity issue; run reset-self-baseline only after approved update"
      fi
    fi
  else
    cat "$SELF_LOG"
    fail "self-check command failed"
  fi
fi

# 5. Service status and basic recent logs.
say "== 05_service_status =="
{
  systemctl status aegis-agent --no-pager || true
  systemctl status aegis-central --no-pager || true
} >"${CHECK_DIR}/05_service_status.log" 2>&1
cat "${CHECK_DIR}/05_service_status.log"
if systemctl is-active --quiet aegis-agent && systemctl is-active --quiet aegis-central; then
  pass "aegis-agent and aegis-central active"
else
  fail "aegis-agent or aegis-central not active"
fi

# 6. Central health with token when present.
if command -v curl >/dev/null 2>&1; then
  HEALTH_URL="http://127.0.0.1:${AEGIS_CENTRAL_PORT}/api/health"
  if [[ -n "$AEGIS_CENTRAL_TOKEN" ]]; then
    if curl -fsS -H "Authorization: Bearer ${AEGIS_CENTRAL_TOKEN}" "$HEALTH_URL" >"${CHECK_DIR}/06_central_health.json" 2>"${CHECK_DIR}/06_central_health.err"; then
      cat "${CHECK_DIR}/06_central_health.json"
      pass "central health API reachable"
    else
      cat "${CHECK_DIR}/06_central_health.err" 2>/dev/null || true
      fail "central health API failed"
    fi
  else
    warn "central token unavailable; skipping authenticated central health"
  fi
else
  warn "curl missing; skipping central health"
fi

# 7. nftables state snapshot and invalid target guard.
if command -v nft >/dev/null 2>&1; then
  say "== 07_nftables_state =="
  nft list ruleset >"${CHECK_DIR}/07_nftables_ruleset.txt" 2>"${CHECK_DIR}/07_nftables.err" || true
  if nft list table inet aegis_guard >/dev/null 2>&1; then
    pass "nftables aegis_guard table exists"
  else
    fail "nftables aegis_guard table missing"
  fi
  for setname in block_in_v4 block_out_v4 rate_limit_v4 block_in_v6 block_out_v6 rate_limit_v6; do
    if nft list set inet aegis_guard "$setname" >"${CHECK_DIR}/07_${setname}.txt" 2>/dev/null; then
      pass "nftables set available: $setname"
    else
      fail "nftables set missing: $setname"
    fi
  done
  if grep -Eq '0\.0\.0\.0|::( |,|$)' "${CHECK_DIR}/07_block_out_v4.txt" "${CHECK_DIR}/07_block_out_v6.txt" 2>/dev/null; then
    fail "unsafe wildcard target found in outbound block set"
  else
    pass "no unsafe wildcard target found in outbound block sets"
  fi
else
  warn "nft command missing; skipping nftables state"
fi

# 8. Agent CLIs.
if [[ -x "$PY" ]]; then
  run_advisory "08_actions_cli" "$PY" -m aegis_agent actions --config "$AGENT_CONFIG" --limit 20
  run_advisory "09_incidents_cli" "$PY" -m aegis_agent incidents --config "$AGENT_CONFIG" --limit 20
  run_advisory "10_reasoning_ledger_cli" "$PY" -m aegis_agent reasoning-ledger --config "$AGENT_CONFIG" --limit 20
  run_advisory "10b_championship_status" "$PY" -m aegis_agent championship-status --config "$AGENT_CONFIG" --limit 20 --summary
  run_advisory "10c_live_battle_evidence" "$PY" -m aegis_agent live-battle-evidence --config "$AGENT_CONFIG" --limit 200 --summary
  run_advisory "10d_ai_quality" "$PY" -m aegis_agent ai-quality --config "$AGENT_CONFIG" --limit 50
  run_advisory "10e_self_heal_check" "$PY" -m aegis_agent self-heal-check --config "$AGENT_CONFIG"
fi

# 9. Safe proof/demo. This creates submission-grade proof artifacts but uses controlled telemetry.
if [[ "$RUN_DUEL" == "1" && -x "${INSTALL_DIR}/scripts/run_ai_duel_demo.sh" ]]; then
  run_advisory "11_run_ai_duel_demo" "${INSTALL_DIR}/scripts/run_ai_duel_demo.sh"
elif [[ "$RUN_DUEL" != "1" ]]; then
  warn "AI duel demo check skipped by AEGIS_RUN_DUEL_DEMO_CHECK=${RUN_DUEL}"
else
  warn "run_ai_duel_demo.sh missing"
fi

# AI Duel Benchmark was removed from the core 본선 workflow in v0.3.1.
# Live Battle Evidence is the primary performance evidence. Synthetic duel demo
# remains available for rehearsal through run_ai_duel_demo.sh when explicitly enabled.


if [[ "$RUN_PROOF" == "1" && -x "${INSTALL_DIR}/scripts/generate_proof_report.sh" ]]; then
  run_advisory "12_generate_proof_report" "${INSTALL_DIR}/scripts/generate_proof_report.sh"
elif [[ "$RUN_PROOF" != "1" ]]; then
  warn "Proof report generation skipped by AEGIS_RUN_PROOF_CHECK=${RUN_PROOF}"
else
  warn "generate_proof_report.sh missing"
fi

# 10. Expired TTL cleanup verification in dry mode by default. This is safe.
if [[ -x "$PY" ]]; then
  run_advisory "13_cleanup_expired_dryrun" "$PY" -m aegis_agent cleanup-expired --config "$AGENT_CONFIG" --limit 20
fi

cat >"$SUMMARY_JSON" <<EOFJSON
{
  "version": "$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo unknown)",
  "check_dir": "${CHECK_DIR}",
  "agent_config": "${AGENT_CONFIG}",
  "policy_config": "${POLICY_CONFIG}",
  "pass": ${PASS},
  "warn": ${WARN},
  "fail": ${FAIL},
  "result": "$(if [[ "$FAIL" -eq 0 ]]; then echo PASS; else echo FAIL; fi)",
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOFJSON

say
say "============================================================"
if [[ "$FAIL" -eq 0 ]]; then
  say "[Aegis] ALL-IN-ONE CHECK RESULT: PASS (${PASS} passed, ${WARN} warnings)"
  say "[Aegis] Summary: $SUMMARY_JSON"
  say "[Aegis] Check logs: $CHECK_DIR"
  exit 0
fi
say "[Aegis] ALL-IN-ONE CHECK RESULT: FAIL (${FAIL} failed, ${PASS} passed, ${WARN} warnings)"
say "[Aegis] Summary: $SUMMARY_JSON"
say "[Aegis] Check logs: $CHECK_DIR"
say "[Aegis] Emergency stop: sudo ${INSTALL_DIR}/scripts/aegis_competition_emergency_stop.sh"
exit 1
