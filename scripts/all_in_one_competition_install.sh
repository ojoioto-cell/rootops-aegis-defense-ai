#!/usr/bin/env bash
set -euo pipefail

# Aegis Linux + Drone Defense Agent - All-in-One Competition Installer + Validation
# One command installer for competition VMs. It installs missing OS packages,
# enables nftables/auditd, generates real-enforcement Linux+Drone configs,
# initializes nftables/auditd, installs services, and starts monitoring/defense.
#
# Optional env:
#   AEGIS_INSTALL_DIR=/opt/aegis-linux-defense-agent
#   AEGIS_CONFIG_DIR=/etc/aegis
#   AEGIS_STATE_DIR=/var/lib/aegis
#   AEGIS_LOG_DIR=/var/log/aegis
#   AEGIS_API_KEY_FILE=/etc/aegis/secrets/openai_api_key
#   AEGIS_OPENAI_API_KEY=<OPENAI_API_KEY>   # writes secret file chmod 600
#   AEGIS_AI_PROVIDER=auto|gpt|rule_based|ollama
#   AEGIS_GPT_MODEL=gpt-5.5
#   AEGIS_CENTRAL_HOST=0.0.0.0
#   AEGIS_CENTRAL_PORT=8088
#   AEGIS_CENTRAL_TOKEN=<token>              # generated if omitted
#   AEGIS_START_SERVICES=1|0                 # default 1
#   AEGIS_RUN_APT_UPDATE=auto|always|never   # default auto
#   AEGIS_LOOP_INTERVAL_SECONDS=5
#   AEGIS_ALLOWLIST_IPS=1.2.3.4,5.6.7.8     # extra admin IPs
#   AEGIS_DRONE_ENABLE=1|0                   # default 1
#   AEGIS_GCS_IPS=192.168.13.10             # authorized GCS IPs
#   AEGIS_DRONE_IPS=192.168.13.20           # drone/companion IPs
#   AEGIS_MAVLINK_PORTS=14550,14551,5760
#   AEGIS_ROS2_DDS_PORTS=7400,7401,11811
#   AEGIS_FRESH_STATE=1|0                  # default 1; remove runtime learning/ledger state at install

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[Aegis] Run as root: sudo $0" >&2
  exit 1
fi

INSTALL_DIR="${AEGIS_INSTALL_DIR:-/opt/aegis-linux-defense-agent}"
CONFIG_DIR="${AEGIS_CONFIG_DIR:-/etc/aegis}"
STATE_DIR="${AEGIS_STATE_DIR:-/var/lib/aegis}"
LOG_DIR="${AEGIS_LOG_DIR:-/var/log/aegis}"
API_KEY_FILE="${AEGIS_API_KEY_FILE:-${CONFIG_DIR}/secrets/openai_api_key}"
CENTRAL_HOST="${AEGIS_CENTRAL_HOST:-0.0.0.0}"
CENTRAL_PORT="${AEGIS_CENTRAL_PORT:-8088}"
START_SERVICES="${AEGIS_START_SERVICES:-1}"
RUN_APT_UPDATE="${AEGIS_RUN_APT_UPDATE:-auto}"
LOOP_INTERVAL="${AEGIS_LOOP_INTERVAL_SECONDS:-5}"
DRONE_ENABLE="${AEGIS_DRONE_ENABLE:-1}"
FRESH_STATE="${AEGIS_FRESH_STATE:-1}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { echo "[Aegis] $*"; }
warn() { echo "[Aegis][WARN] $*" >&2; }
fail() { echo "[Aegis][ERROR] $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1; }

install_packages() {
  log "Checking required OS packages"
  if require_cmd apt-get; then
    local pkgs=(python3 python3-venv python3-pip unzip curl nftables auditd iproute2)
    local missing=()
    for p in "${pkgs[@]}"; do
      if ! dpkg -s "$p" >/dev/null 2>&1; then
        missing+=("$p")
      fi
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
      log "Missing packages: ${missing[*]}"
      if [[ "$RUN_APT_UPDATE" == "always" || "$RUN_APT_UPDATE" == "auto" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get update
      fi
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    else
      log "Required packages already installed; skipping apt install"
    fi
    return 0
  fi

  if require_cmd dnf; then
    dnf install -y python3 python3-pip unzip curl nftables audit audit-libs iproute
    return 0
  fi
  if require_cmd yum; then
    yum install -y python3 python3-pip unzip curl nftables audit audit-libs iproute
    return 0
  fi
  fail "No supported package manager found. Install python3, python3-venv, python3-pip, unzip, curl, nftables, auditd manually."
}

enable_services() {
  log "Enabling nftables/auditd"
  if require_cmd systemctl; then
    systemctl enable --now nftables || warn "Failed to enable/start nftables; bootstrap will verify nft command"
    systemctl enable --now auditd || systemctl enable --now audit || warn "Failed to enable/start auditd; audit collector may be limited"
  else
    service nftables start || true
    service auditd start || true
  fi
}

prepare_dirs() {
  log "Preparing directories"
  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$STATE_DIR/state" "$LOG_DIR" "$(dirname "$API_KEY_FILE")"
  chmod 700 "$(dirname "$API_KEY_FILE")" "$CONFIG_DIR" "$STATE_DIR" "$STATE_DIR/state" || true

  if [[ "$FRESH_STATE" == "1" ]]; then
    log "Creating fresh runtime state for this installation"
    rm -f "$STATE_DIR/ai_reasoning_ledger.jsonl" \
          "$STATE_DIR/state/attack_loops.json" \
          "$STATE_DIR/state/learned_iocs.json" \
          "$STATE_DIR/state/policy_promotions.json" \
          "$STATE_DIR/state/self_protection_baseline.json" 2>/dev/null || true
  fi

  touch "$LOG_DIR/drone_mavlink.log"
  chmod 640 "$LOG_DIR/drone_mavlink.log" || true
}

copy_source() {
  log "Installing source to $INSTALL_DIR"
  if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
    find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    tar --exclude='.venv' --exclude='data' --exclude='.pytest_cache' --exclude='*.pyc' -C "$SRC_DIR" -cf - . | tar -C "$INSTALL_DIR" -xf -
  fi
  chown -R root:root "$INSTALL_DIR"
}

setup_python() {
  log "Creating Python virtual environment"
  python3 -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
  "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
  if ! "$INSTALL_DIR/.venv/bin/pip" install -e "$INSTALL_DIR"; then
    warn "Editable package install failed; continuing with PYTHONPATH service fallback"
  fi
}

prepare_api_key() {
  log "Preparing OpenAI API key file"
  install -d -m 700 -o root -g root "$(dirname "$API_KEY_FILE")"

  if [[ -n "${AEGIS_OPENAI_API_KEY:-}" ]]; then
    umask 077
    printf '%s' "$AEGIS_OPENAI_API_KEY" > "$API_KEY_FILE"
    log "OpenAI API key stored from AEGIS_OPENAI_API_KEY"
  elif [[ -s "$API_KEY_FILE" ]]; then
    log "Existing API key file found; keeping $API_KEY_FILE"
  elif [[ -s "$SRC_DIR/secrets/openai_api_key" ]]; then
    cp "$SRC_DIR/secrets/openai_api_key" "$API_KEY_FILE"
    log "Copied API key file from package secrets directory"
  else
    umask 077
    : > "$API_KEY_FILE"
    echo
    echo "[Aegis] GPT/OpenAI API key setup"
    echo "[Aegis] Key file will be created at: $API_KEY_FILE"
    echo "[Aegis] Paste API key now. Press Enter with blank input to use rule_based mode."
    if [[ -t 0 ]]; then
      read -r -s -p "OpenAI API key: " entered_key || true
      echo
      if [[ -n "${entered_key:-}" ]]; then
        printf '%s' "$entered_key" > "$API_KEY_FILE"
        log "OpenAI API key stored at $API_KEY_FILE"
      else
        warn "No API key entered. Agent will use rule_based reasoning until a key is stored."
      fi
    else
      warn "No interactive terminal available. Created empty API key file; Agent will use rule_based reasoning."
    fi
  fi

  chmod 600 "$API_KEY_FILE" || true
  chown root:root "$API_KEY_FILE" || true
}

generate_token() {
  if [[ -n "${AEGIS_CENTRAL_TOKEN:-}" ]]; then
    printf '%s' "$AEGIS_CENTRAL_TOKEN"; return
  fi
  if [[ -f "$CONFIG_DIR/central.env" ]]; then
    local old
    old="$(grep -E '^AEGIS_CENTRAL_TOKEN=' "$CONFIG_DIR/central.env" | tail -1 | cut -d= -f2- || true)"
    if [[ -n "$old" && "$old" != "change-me" ]]; then
      printf '%s' "$old"; return
    fi
  fi
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

detect_allowlist_ips() {
  local values=()
  values+=("127.0.0.1" "::1")
  if [[ -n "${SSH_CONNECTION:-}" ]]; then values+=("$(awk '{print $1}' <<<"$SSH_CONNECTION")"); fi
  if [[ -n "${SSH_CLIENT:-}" ]]; then values+=("$(awk '{print $1}' <<<"$SSH_CLIENT")"); fi
  if require_cmd who; then
    local who_ip
    who_ip="$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p' | head -1 || true)"
    [[ -n "$who_ip" ]] && values+=("$who_ip")
  fi
  if require_cmd ip; then
    local src_ip
    src_ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)"
    [[ -n "$src_ip" ]] && values+=("$src_ip")
  fi
  if [[ -n "${AEGIS_ALLOWLIST_IPS:-}" ]]; then
    IFS=',' read -r -a extra <<< "$AEGIS_ALLOWLIST_IPS"
    values+=("${extra[@]}")
  fi
  printf '%s\n' "${values[@]}" | awk 'NF && !seen[$0]++'
}

comma_or_default() {
  local value="$1" default="$2"
  if [[ -n "$value" ]]; then printf '%s' "$value"; else printf '%s' "$default"; fi
}

generate_configs() {
  log "Generating Linux+Drone competition config with real enforcement enabled"
  local token="$1"
  local api_key_exists=0
  [[ -s "$API_KEY_FILE" ]] && api_key_exists=1
  mapfile -t allow_ips < <(detect_allowlist_ips)

  local ai_provider="${AEGIS_AI_PROVIDER:-auto}"
  # v0.2.15 Championship Mode keeps provider=auto by default:
  # priority is GPT -> local Ollama/Llama -> rule_based fallback.

  local gcs_ips drone_ips mav_ports ros_ports
  gcs_ips="$(comma_or_default "${AEGIS_GCS_IPS:-}" "$(IFS=','; echo "${allow_ips[*]}")")"
  drone_ips="${AEGIS_DRONE_IPS:-}"
  mav_ports="$(comma_or_default "${AEGIS_MAVLINK_PORTS:-}" "14550,14551,14552,14553,14554,14555,5760,5761,5762,5763")"
  ros_ports="$(comma_or_default "${AEGIS_ROS2_DDS_PORTS:-}" "7400,7401,7402,7403,7410,7411,7412,7413,11811")"

  AEGIS_INSTALL_DIR="$INSTALL_DIR" \
  AEGIS_CONFIG_DIR="$CONFIG_DIR" \
  AEGIS_STATE_DIR="$STATE_DIR" \
  AEGIS_LOG_DIR="$LOG_DIR" \
  AEGIS_API_KEY_FILE="$API_KEY_FILE" \
  AEGIS_CENTRAL_TOKEN_VALUE="$token" \
  AEGIS_CENTRAL_HOST_VALUE="$CENTRAL_HOST" \
  AEGIS_CENTRAL_PORT_VALUE="$CENTRAL_PORT" \
  AEGIS_AI_PROVIDER_VALUE="$ai_provider" \
  AEGIS_GPT_MODEL_VALUE="${AEGIS_GPT_MODEL:-gpt-5.5}" \
  AEGIS_LOOP_INTERVAL_SECONDS_VALUE="$LOOP_INTERVAL" \
  AEGIS_ALLOWLIST_IPS_VALUE="$(IFS=','; echo "${allow_ips[*]}")" \
  AEGIS_DRONE_ENABLE_VALUE="$DRONE_ENABLE" \
  AEGIS_GCS_IPS_VALUE="$gcs_ips" \
  AEGIS_DRONE_IPS_VALUE="$drone_ips" \
  AEGIS_MAVLINK_PORTS_VALUE="$mav_ports" \
  AEGIS_ROS2_DDS_PORTS_VALUE="$ros_ports" \
  "$INSTALL_DIR/.venv/bin/python" - <<'PY'
import os, socket
from pathlib import Path
import yaml


def csv(v):
    return [x.strip() for x in str(v or '').split(',') if x.strip()]


def csv_int(v):
    out = []
    for x in csv(v):
        try:
            out.append(int(x))
        except Exception:
            pass
    return out

install_dir = Path(os.environ['AEGIS_INSTALL_DIR'])
config_dir = Path(os.environ['AEGIS_CONFIG_DIR'])
state_dir = Path(os.environ['AEGIS_STATE_DIR'])
log_dir = Path(os.environ['AEGIS_LOG_DIR'])
api_key_file = os.environ['AEGIS_API_KEY_FILE']
central_token = os.environ['AEGIS_CENTRAL_TOKEN_VALUE']
central_host = os.environ['AEGIS_CENTRAL_HOST_VALUE']
central_port = os.environ['AEGIS_CENTRAL_PORT_VALUE']
ai_provider = os.environ['AEGIS_AI_PROVIDER_VALUE']
gpt_model = os.environ['AEGIS_GPT_MODEL_VALUE']
loop_interval = int(os.environ.get('AEGIS_LOOP_INTERVAL_SECONDS_VALUE', '5'))
allow_ips = csv(os.environ.get('AEGIS_ALLOWLIST_IPS_VALUE', '')) or ['127.0.0.1', '::1']
drone_enable = os.environ.get('AEGIS_DRONE_ENABLE_VALUE', '1') not in {'0','false','False','no'}
gcs_ips = csv(os.environ.get('AEGIS_GCS_IPS_VALUE', '')) or allow_ips
drone_ips = csv(os.environ.get('AEGIS_DRONE_IPS_VALUE', ''))
mav_ports = csv_int(os.environ.get('AEGIS_MAVLINK_PORTS_VALUE', '14550,14551,14552,14553,14554,14555,5760,5761,5762,5763'))
ros_ports = csv_int(os.environ.get('AEGIS_ROS2_DDS_PORTS_VALUE', '7400,7401,7402,7403,7410,7411,7412,7413,11811'))
hostname = socket.gethostname()

agent = yaml.safe_load((install_dir / 'config/agent_execute_example.yaml').read_text()) or {}
policy = yaml.safe_load((install_dir / 'config/policy_linux_drone_competition_example.yaml').read_text()) or yaml.safe_load((install_dir / 'config/policy.yaml').read_text()) or {}

agent.setdefault('agent', {})
agent['agent'].update({
    'id': hostname,
    'hostname': hostname,
    'mode': 'autonomous_linux_drone_competition',
    'max_iterations': 3,
    'loop_interval_seconds': loop_interval,
    'audit_db': str(state_dir / 'audit.db'),
    'state_dir': str(state_dir / 'state'),
})

agent.setdefault('ai', {})
agent['ai'].update({
    'provider': ai_provider,
    'provider_priority': ['gpt', 'ollama', 'rule_based'] if ai_provider == 'auto' else [ai_provider, 'rule_based'],
    'model': gpt_model if ai_provider in {'auto','gpt'} else ('llama3.1' if ai_provider == 'ollama' else 'local-rule-engine'),
    'require_evidence_ids': True,
    'strict_json': True,
    'fallback_to_rule_based': True,
    'api_key_file': api_key_file,
    'api_key_env': 'OPENAI_API_KEY',
    'fail_on_insecure_secret_permissions': True if ai_provider in {'auto','gpt'} else False,
    'gpt': {
        'model': gpt_model,
        'endpoint': 'https://api.openai.com/v1/chat/completions',
        'api_key_file': api_key_file,
        'api_key_env': 'OPENAI_API_KEY',
        'timeout_seconds': 15,
    },
    'ollama': {
        'model': os.environ.get('AEGIS_OLLAMA_MODEL', 'llama3.1'),
        'endpoint': os.environ.get('AEGIS_OLLAMA_ENDPOINT', 'http://127.0.0.1:11434/api/generate'),
        'timeout_seconds': 5,
    },
    'rule_based': {'model': 'local-rule-engine'},
})

agent.setdefault('central', {})
agent['central'].update({
    'enabled': True,
    'url': f'http://127.0.0.1:{central_port}/api/ingest',
    'token': central_token,
    'timeout_seconds': 5,
    'policy_sync': {'enabled': False, 'save_to': str(state_dir / 'central_policy.yaml')},
})

agent.setdefault('telemetry', {})
agent['telemetry'].update({
    'auth_logs': ['/var/log/auth.log', '/var/log/secure'],
    'web_logs': [
        '/var/log/nginx/access.log', '/var/log/nginx/error.log',
        '/var/log/httpd/access_log', '/var/log/httpd/error_log',
        '/var/log/apache2/access.log', '/var/log/apache2/error.log',
    ],
    'app_logs': [],
    'auditd_logs': ['/var/log/audit/audit.log'],
    'process_snapshot': None,
    'network_snapshot': None,
    'file_events': None,
    'persistence_events': None,
    'time_window_minutes': 30,
    'ignore_time_window_for_sample_data': False,
    'realtime': {'enabled': True, 'tail_first_run': 'tail'},
    'fim': {
        'enabled': True,
        'paths': ['/tmp', '/dev/shm', '/var/www', '/srv/www', '/etc/cron.d', '/etc/systemd/system'],
        'state_dir': str(state_dir / 'state'),
        'first_run_baseline': True,
        'max_files': 20000,
    },
})

agent['drone'] = {
    'enabled': drone_enable,
    'defense_only': True,
    'collect_live_ss': True,
    'logs': [str(log_dir / 'drone_mavlink.log')],
    'network_snapshot': None,
    'allowed_gcs_ips': gcs_ips,
    'allowed_drone_ips': drone_ips,
    'allowed_sysids': [1],
    'allowed_component_ids': [],
    'mavlink_ports': mav_ports,
    'ros2_dds_ports': ros_ports,
    'mavlink_flood_threshold_per_loop': 20,
    'ros2_dds_flood_threshold_per_loop': 50,
}

agent['enforcement'] = {
    'dry_run': False,
    'require_cli_enable_flag': False,
    'require_root': True,
    'prefer_backend': 'nftables',
    'nft_family': 'inet',
    'nft_table': 'aegis_guard',
    'quarantine_dir': str(state_dir / 'quarantine'),
    'persistence_backup_dir': str(state_dir / 'persistence_backup'),
    'persistence_max_file_size': 1048576,
    'persistence_allowed_paths': [
        '/etc/cron.d', '/etc/crontab', '/var/spool/cron', '/var/spool/cron/crontabs',
        '/etc/systemd/system', '/etc/rc.local', '/root/.ssh/authorized_keys', '/home',
    ],
    'action_ttl_seconds_default': 3600,
    'allow_sample_data_enforcement': False,
    'rate_limit': {'tcp_syn_per_second': 20, 'burst': 40},
}
agent['verifier'] = {'service_health_command': '', 'verify_delay_seconds': 1, 'health_checks': []}
agent['rollback'] = {'auto_on_health_failure': True}
agent['attack_loop'] = {'enabled': True, 'state_dir': str(state_dir / 'state'), 'window_seconds': 3600}
agent['self_protection'] = {
    'enabled': True,
    'state_dir': str(state_dir / 'state'),
    'baseline_on_first_run': True,
    'paths': [str(install_dir / 'src' / 'aegis_agent'), str(config_dir), str(install_dir / 'VERSION'), str(install_dir / 'deploy')],
}
agent['loop_process'] = {
    'enabled': True,
    'description': 'Loop-process audit trail: collect -> signature -> evidence -> reason -> plan -> policy -> enforce -> verify -> rollback -> learn',
}
agent['signature_patterns'] = {
    'enabled': True,
    'load_defaults': True,
    'files': [str(install_dir / 'config/signatures.yaml')],
    'description': 'Signature matches become Evidence events and still pass Policy Gate, TTL, Verifier, Rollback.',
}
agent['vulnerability_guard'] = {
    'enabled': True,
    'aggregate_threshold': 3,
    'aggregate_min_events': 3,
    'block_ttl_seconds': 3600,
    'critical_ttl_seconds': 7200,
    'description': 'Generic known/new vulnerability attack guard. It creates Evidence events only; Policy Gate and Rollback still control enforcement.',
}

agent['security_growth'] = {
    'enabled': True,
    'state_dir': str(state_dir / 'state'),
    'repeat_ip_score_bonus': 15,
    'auto_learn_min_score': 60,
    'description': 'Local evidence-driven learning: remembered hostile IP/C2 indicators add bounded score bonus but still pass Policy Gate, TTL, Verifier, and Rollback.',
}
agent['policy_promotion'] = {
    'enabled': True,
    'state_dir': str(state_dir / 'state'),
    'shadow_after_observations': 2,
    'enforce_after_observations': 3,
    'promote_after_successes': 3,
    'description': 'Championship Mode: candidate -> shadow -> enforce_verified -> promoted policy evidence; no unsafe action bypasses Policy Gate.',
}
agent['reasoning_ledger'] = {
    'enabled': True,
    'path': str(state_dir / 'ai_reasoning_ledger.jsonl'),
    'max_chain_events': 200,
    'description': 'Append-only sanitized AI/Rule reasoning ledger for proof reports and competition evidence.',
}
agent['proof_generator'] = {
    'enabled': True,
    'output_dir': str(state_dir / 'proof'),
}

p = policy.get('policy', policy)
p.setdefault('thresholds', {})
p['thresholds'].update({'collect_more': 20, 'soft_response': 50, 'active_response': 70})
p.setdefault('evidence', {})
p['evidence'].update({'min_events_for_response': 1, 'min_sources_for_active_response': 1, 'require_event_id_mapping': True})
p.setdefault('safety', {})
p['safety']['dry_run_default'] = False
p.setdefault('allowlists', {})
p['allowlists']['ips'] = allow_ips
p['allowlists']['cidrs'] = []
p['allowlists'].setdefault('accounts', ['root'])
p['allowlists'].setdefault('process_names', ['systemd','sshd','nginx','apache2','httpd','mysqld','postgresql','dockerd','containerd'])
p.setdefault('drone', {})
p['drone'].update({
    'defense_only': True,
    'allowed_gcs_ips': gcs_ips,
    'allowed_drone_ips': drone_ips,
    'forbidden_agent_actions': ['arm','disarm','takeoff','land','mission_upload','parameter_write','rc_override','mavlink_command_send'],
})
p.setdefault('actions', {})
for name, min_score in {'block_ip_ttl': 50, 'rate_limit_ip': 40, 'block_outbound_ip': 70}.items():
    p['actions'].setdefault(name, {})
    p['actions'][name].update({'enabled': True, 'auto_allowed': True, 'min_score': min_score, 'ttl_required': True, 'rollback_required': True})
p['actions'].setdefault('suspend_process', {})
p['actions']['suspend_process'].update({
    'enabled': False,
    'auto_allowed': False,
    'min_score': 95,
    'risk': 'high_guarded',
    'ttl_required': False,
    'rollback_required': True,
    'require_auditd_pid_relation': True,
})
policy = {'policy': p}

config_dir.mkdir(parents=True, exist_ok=True)
state_dir.mkdir(parents=True, exist_ok=True)
log_dir.mkdir(parents=True, exist_ok=True)
(config_dir / 'agent.yaml').write_text(yaml.safe_dump(agent, sort_keys=False, allow_unicode=True), encoding='utf-8')
(config_dir / 'policy.yaml').write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding='utf-8')
central_env = config_dir / 'central.env'
central_env.write_text('\n'.join([
    f'AEGIS_CENTRAL_HOST={central_host}',
    f'AEGIS_CENTRAL_PORT={central_port}',
    f'AEGIS_CENTRAL_TOKEN={central_token}',
    '',
]), encoding='utf-8')
for path in [config_dir / 'agent.yaml', config_dir / 'policy.yaml', central_env]:
    path.chmod(0o600)
print('agent_config=' + str(config_dir / 'agent.yaml'))
print('policy_config=' + str(config_dir / 'policy.yaml'))
print('central_env=' + str(central_env))
print('ai_provider=' + ai_provider)
print('allowlist_ips=' + ','.join(allow_ips))
print('drone_enabled=' + str(drone_enable))
print('allowed_gcs_ips=' + ','.join(gcs_ips))
print('allowed_drone_ips=' + ','.join(drone_ips))
PY
}

install_services() {
  log "Installing systemd services"
  cp "$INSTALL_DIR/deploy/aegis-agent.service" /etc/systemd/system/aegis-agent.service
  cp "$INSTALL_DIR/deploy/aegis-central.service" /etc/systemd/system/aegis-central.service
  systemctl daemon-reload
  systemctl enable aegis-central.service
  systemctl enable aegis-agent.service
}

bootstrap_defense() {
  log "Bootstrapping nftables and auditd rules"
  "$INSTALL_DIR/scripts/bootstrap_nftables.sh"
  "$INSTALL_DIR/scripts/install_auditd_rules.sh" || warn "auditd rules were not fully installed"
}


reset_self_baseline() {
  log "Resetting approved self-protection baseline after installation/config generation"
  if [[ -x "$INSTALL_DIR/.venv/bin/python" && -f "$CONFIG_DIR/agent.yaml" ]]; then
    PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}" "$INSTALL_DIR/.venv/bin/python" -m aegis_agent reset-self-baseline --config "$CONFIG_DIR/agent.yaml" >/tmp/aegis_reset_self_baseline.json 2>/tmp/aegis_reset_self_baseline.err \
      && log "Self-protection baseline reset" \
      || warn "Self-protection baseline reset failed: $(cat /tmp/aegis_reset_self_baseline.err 2>/dev/null)"
  else
    warn "Skipping self-protection baseline reset; python/config not ready"
  fi
}

start_services() {
  if [[ "$START_SERVICES" != "1" ]]; then
    log "Service start skipped by AEGIS_START_SERVICES=$START_SERVICES"
    return
  fi
  log "Starting central monitoring and defense agent"
  systemctl restart aegis-central.service
  systemctl restart aegis-agent.service
}

run_post_install_check() {
  log "Running all-in-one post-install, AI, self-protection, proof, and rollback checks"
  if [[ -x "$INSTALL_DIR/scripts/aegis_all_in_one_check.sh" ]]; then
    AEGIS_INSTALL_DIR="$INSTALL_DIR" AEGIS_CONFIG_DIR="$CONFIG_DIR" AEGIS_STATE_DIR="$STATE_DIR" AEGIS_LOG_DIR="$LOG_DIR" AEGIS_AUTO_RESET_BASELINE=1 \
      "$INSTALL_DIR/scripts/aegis_all_in_one_check.sh" || warn "All-in-one check reported failures. Review output above."
  elif [[ -x "$INSTALL_DIR/scripts/post_install_competition_check.sh" ]]; then
    AEGIS_INSTALL_DIR="$INSTALL_DIR" AEGIS_CONFIG_DIR="$CONFIG_DIR" AEGIS_STATE_DIR="$STATE_DIR" AEGIS_LOG_DIR="$LOG_DIR" \
      "$INSTALL_DIR/scripts/post_install_competition_check.sh" || warn "Post-install check reported failures. Review output above."
  else
    warn "No post-install check script found"
  fi
}

post_install_summary() {
  local token="$1"
  cat <<EOF

[Aegis] Linux + Drone All-in-One competition installation complete.

Central UI:
  http://<SERVER_IP>:${CENTRAL_PORT}/dashboard
  token: ${token}

Post-install check:
  automatically executed by scripts/aegis_all_in_one_check.sh

Agent:
  service: aegis-agent.service
  config:  ${CONFIG_DIR}/agent.yaml
  policy:  ${CONFIG_DIR}/policy.yaml
  Linux defense: enabled
  Drone network defense: ${DRONE_ENABLE}
  real enforcement: enabled by default
  security growth loop: enabled
  policy promotion loop: enabled
  AI priority: GPT -> local Ollama/Llama -> rule_based fallback
  API key file: ${API_KEY_FILE}
  firewall backend: nftables

Drone network input:
  passive log: ${LOG_DIR}/drone_mavlink.log
  GCS IPs: ${AEGIS_GCS_IPS:-auto/admin allowlist}
  Drone IPs: ${AEGIS_DRONE_IPS:-unset}

Useful commands:
  sudo systemctl status aegis-agent --no-pager
  sudo journalctl -u aegis-agent -f
  sudo nft list ruleset | sed -n '/aegis_guard/,+160p'
  ${INSTALL_DIR}/.venv/bin/python -m aegis_agent actions --config ${CONFIG_DIR}/agent.yaml
  ${INSTALL_DIR}/.venv/bin/python -m aegis_agent incidents --config ${CONFIG_DIR}/agent.yaml
  ${INSTALL_DIR}/.venv/bin/python -m aegis_agent reasoning-ledger --config ${CONFIG_DIR}/agent.yaml
  ${INSTALL_DIR}/.venv/bin/python -m aegis_agent proof-report --config ${CONFIG_DIR}/agent.yaml --output-dir ${STATE_DIR}/proof
  sudo ${INSTALL_DIR}/scripts/run_ai_duel_demo.sh
  sudo ${INSTALL_DIR}/scripts/aegis_competition_status.sh
  sudo ${INSTALL_DIR}/scripts/aegis_all_in_one_check.sh

Emergency rollback:
  sudo ${INSTALL_DIR}/scripts/aegis_competition_emergency_stop.sh

EOF
}

main() {
  install_packages
  enable_services
  prepare_dirs
  prepare_api_key
  copy_source
  setup_python
  local token
  token="$(generate_token)"
  generate_configs "$token"
  install_services
  bootstrap_defense
  reset_self_baseline
  start_services
  run_post_install_check
  post_install_summary "$token"
}

main "$@"
