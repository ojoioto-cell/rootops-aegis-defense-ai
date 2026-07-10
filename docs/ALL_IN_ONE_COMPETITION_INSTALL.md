# Aegis v0.2.13 All-in-One Competition Install

Run one command on the competition VM:

```bash
unzip aegis_linux_defense_agent_v0_2_13.zip
cd aegis_linux_defense_agent_v0_2_13
sudo ./scripts/all_in_one_competition_install.sh
```

The installer automatically:

1. Installs missing packages: `python3`, `python3-venv`, `python3-pip`, `unzip`, `curl`, `nftables`, `auditd`, `iproute2`.
2. Enables and starts `nftables` and `auditd`.
3. Creates `/etc/aegis/secrets/openai_api_key` before service deployment and prompts only for the API key.
4. Installs Aegis into `/opt/aegis-linux-defense-agent`.
5. Creates the Python virtual environment and installs requirements.
6. Generates `/etc/aegis/agent.yaml` and `/etc/aegis/policy.yaml` with real enforcement enabled.
7. Adds `127.0.0.1`, `::1`, the SSH client IP, and detected host IP to allowlist.
8. Removes broad private CIDR allowlists so competition private-network attackers can still be blocked.
9. Bootstraps `inet aegis_guard` nftables table and timeout sets.
10. Installs auditd rules.
11. Resets the approved self-protection baseline after installation/configuration.
12. Starts `aegis-central` and `aegis-agent`.
13. Runs `post_install_competition_check.sh` automatically.

## Useful commands

```bash
sudo /opt/aegis-linux-defense-agent/scripts/post_install_competition_check.sh
sudo /opt/aegis-linux-defense-agent/scripts/aegis_competition_status.sh
sudo /opt/aegis-linux-defense-agent/scripts/run_ai_duel_demo.sh
sudo /opt/aegis-linux-defense-agent/scripts/generate_proof_report.sh
sudo /opt/aegis-linux-defense-agent/scripts/diagnose_ai_connectivity.sh
```

## Emergency stop

```bash
sudo /opt/aegis-linux-defense-agent/scripts/aegis_competition_emergency_stop.sh
```

v0.2.13 safety patch rejects invalid firewall targets such as `0.0.0.0`, `::`, loopback, multicast, link-local, and broadcast before nftables enforcement.
