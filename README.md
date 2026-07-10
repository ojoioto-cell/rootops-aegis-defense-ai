# Aegis Linux·Drone Defense AI v0.3.1

**RootOps Aegis** is a host-based autonomous defense AI agent for DAH 2026 style AI cyber defense scenarios. It protects Linux servers, drone network gateways, GCS/companion-computer nodes, and mission support systems by combining Evidence Chain analysis, AI/Rule reasoning, Policy Gate enforcement, nftables-based blocking, rollback, and Live Battle Evidence reporting.

> Defensive use only. Aegis does not generate exploits, does not send flight-control commands, and does not allow an LLM to execute shell commands directly.

---

## Repository information

- **Project:** Aegis Linux·Drone Defense AI
- **Version:** v0.3.1 Live Battle Evidence Edition
- **Team:** RootOps
- **Purpose:** DAH 2026 preliminary artifact and final-round rehearsal platform
- **Primary runtime:** Linux VM, GCS Linux node, Companion Computer, Linux Gateway, or control server

---

## Key features

### Linux Host Defense

- SSH brute-force detection and TTL-based IP blocking
- Vulnerability probing and RCE-attempt detection
- Known and generic exploit markers: JNDI/Log4Shell style, Shellshock style, Spring/Struts-style indicators, exposed endpoint probing
- Outbound C2 blocking
- File quarantine and persistence guard
- nftables-based `block_ip_ttl`, `rate_limit_ip`, `block_outbound_ip`
- Rollback and TTL expiration support

### Drone Network Guard

- Passive MAVLink/ROS2 event observation
- Unauthorized GCS/source detection
- MAVLink command/mission/parameter attempt detection
- Heartbeat/sysid anomaly tracking
- ROS2/DDS discovery/flood indicators
- Network blocking only; no `arm`, `disarm`, `takeoff`, `land`, `mission_upload`, `parameter_write`, or RC override actions

### AI Reasoning and Safe Enforcement

Aegis uses a layered reasoning model:

1. **GPT API** when available
2. **Local Ollama/Llama** when GPT is unavailable
3. **Rule-based fallback** when no AI provider is reachable

All outputs must pass schema, Evidence ID, target validation, and Policy Gate checks before any action is executed.

### Live Battle Evidence Engine

v0.3.1 centers the final-round workflow on **real runtime evidence**, not synthetic benchmarking:

- live incident count
- action count and status
- enforcement success rate
- mean response time
- AI mode and fallback count
- blocked/limited targets
- nftables state
- rollback evidence
- final evidence export package

Synthetic AI Duel Demo remains available only for rehearsal and report screenshots.

---

## Repository layout

```text
.
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── pyproject.toml
├── VERSION
├── src/
│   ├── aegis_agent/
│   └── aegis_central/
├── config/
├── scripts/
├── docs/
├── tests/
├── sample_data/
├── secrets/
│   ├── README.md
│   └── .gitignore
└── data/
    ├── .gitkeep
    └── state/.gitkeep
```

Runtime state such as `audit.db`, reasoning ledgers, learned IOCs, policy-promotion state, and API keys must not be committed.

---

## Requirements

For Ubuntu/Debian competition VMs, the all-in-one installer checks and installs required packages automatically:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip curl nftables auditd iproute2
```

Core Python requirements are listed in `requirements.txt`.

---

## Quick start: competition install

```bash
git clone https://github.com/<YOUR_ORG>/rootops-aegis-defense-ai.git
cd rootops-aegis-defense-ai
sudo ./scripts/all_in_one_competition_install.sh
```

During installation, Aegis creates:

```text
/etc/aegis/secrets/openai_api_key
```

Paste the OpenAI API key when prompted. If left blank, Aegis falls back to local Ollama/Llama if available, then rule-based reasoning.

---

## Important environment variables

| Variable | Purpose | Example |
|---|---|---|
| `AEGIS_OPENAI_API_KEY` | Write API key non-interactively during install | `sk-...` |
| `AEGIS_AI_PROVIDER` | Provider mode | `auto`, `gpt`, `ollama`, `rule_based` |
| `AEGIS_GCS_IPS` | Authorized GCS IP allowlist | `192.168.13.10` |
| `AEGIS_DRONE_IPS` | Drone/companion IP baseline | `192.168.13.20` |
| `AEGIS_ALLOWLIST_IPS` | Extra admin IPs | `1.2.3.4,5.6.7.8` |
| `AEGIS_CENTRAL_PORT` | Central dashboard port | `8088` |
| `AEGIS_FRESH_STATE` | Reset runtime state at install | `1` |

Non-interactive example:

```bash
sudo AEGIS_OPENAI_API_KEY="<OPENAI_API_KEY>" \
     AEGIS_GCS_IPS="192.168.13.10" \
     AEGIS_DRONE_IPS="192.168.13.20" \
     ./scripts/all_in_one_competition_install.sh
```

Do **not** commit real API keys, central tokens, or internal IP evidence.

---

## Verification commands

Run the full all-in-one check:

```bash
sudo /opt/aegis-linux-defense-agent/scripts/aegis_all_in_one_check.sh
```

Check services:

```bash
sudo systemctl status aegis-agent --no-pager
sudo systemctl status aegis-central --no-pager
```

Check nftables sets:

```bash
sudo nft list set inet aegis_guard block_in_v4
sudo nft list set inet aegis_guard rate_limit_v4
sudo nft list set inet aegis_guard block_out_v4
```

Check live battle evidence:

```bash
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent live-battle-evidence \
  --config /etc/aegis/agent.yaml \
  --summary
```

Check AI quality:

```bash
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent ai-quality \
  --config /etc/aegis/agent.yaml
```

Export final evidence package:

```bash
sudo /opt/aegis-linux-defense-agent/scripts/export_competition_evidence.sh
```

---

## Central monitoring

After installation, the dashboard runs on:

```text
http://<SERVER_IP>:8088/dashboard
```

The dashboard provides incident/action status, AI mode, blocked targets, live battle evidence, and proof artifacts. Read APIs can be protected with a bearer token.

---

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
python -m aegis_agent --version
python -m aegis_agent run-once --config config/agent.yaml
pytest -q
```

Expected version:

```text
0.3.1
```

---

## Safety boundaries

Aegis is a defensive agent. It does not perform the following:

- exploit generation
- unauthorized scanning
- arbitrary LLM-generated shell execution
- drone flight-control command transmission
- `arm`, `disarm`, `takeoff`, `land`, `mission_upload`, `parameter_write`, or RC override
- unrestricted host isolation or account lockout

High-risk actions such as process suspension, account restriction, or host isolation are disabled by default and require explicit policy changes.

---

## Emergency stop

If a false positive or operational issue occurs:

```bash
sudo /opt/aegis-linux-defense-agent/scripts/aegis_competition_emergency_stop.sh
```

Prefer individual rollback first when possible:

```bash
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent rollback-action <ACTION_ID> \
  --config /etc/aegis/agent.yaml \
  --execute
```

---

## Evidence package for submission or after-action review

```bash
sudo /opt/aegis-linux-defense-agent/scripts/export_competition_evidence.sh
```

Typical artifacts:

```text
proof_report.md
proof_summary.json
proof_evidence_full.json
live_battle_evidence.json
ai_reasoning_ledger.jsonl
incidents.json
actions.json
nftables_ruleset.txt
service_status.txt
championship_status.json
```

Review artifacts before sharing to ensure API keys, tokens, private IPs, or competition-sensitive values are not exposed.

---

## License

This project is released under the Apache License 2.0. See [`LICENSE`](LICENSE).

---

## Disclaimer

Aegis is provided for defensive research, competition, and authorized security operations. Use it only on systems and networks that you own or are explicitly authorized to protect.
