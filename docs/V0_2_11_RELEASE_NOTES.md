# Aegis Linux Defense Agent v0.2.11 Release Notes

v0.2.11 includes v0.2.10 and adds the final competition proof layer for AI attack/defense demonstrations.

## New capabilities

- **AI Duel Demo Harness**: safe, synthetic AI-offense-vs-Aegis-defense demo. It generates controlled SSH brute-force, vulnerability probing/RCE mutation, and Drone/MAVLink unauthorized command telemetry, then runs the normal Aegis defense loop.
- **AI Reasoning Ledger**: append-only sanitized JSONL proof log containing Evidence Chain, AI/Rule reasoning output, Policy Gate decisions, enforcement results, verification, rollback, attack loop, security growth, and loop phases.
- **Proof Report Generator**: produces `proof_report.md` and `proof_summary.json` from the local audit DB and reasoning ledger.
- **Post-install validation expansion**: validates the AI duel demo/proof generator path automatically.
- **Installer integration**: generated `/etc/aegis/agent.yaml` enables reasoning ledger and proof output paths by default.

## Safety boundary

The AI Duel Demo does not run exploit tools, brute-force tools, MAVLink control commands, or ROS2 control commands. It only writes controlled synthetic telemetry to prove the defense loop.

## Useful commands

```bash
sudo /opt/aegis-linux-defense-agent/scripts/run_ai_duel_demo.sh
sudo /opt/aegis-linux-defense-agent/scripts/generate_proof_report.sh
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent reasoning-ledger --config /etc/aegis/agent.yaml
```

## Proof artifacts

Default generated artifacts:

```text
/var/lib/aegis/ai_reasoning_ledger.jsonl
/var/lib/aegis/proof/proof_report.md
/var/lib/aegis/proof/proof_summary.json
/var/lib/aegis/ai_duel_demo_*/reports/proof_report.md
```
