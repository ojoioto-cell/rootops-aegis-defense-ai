# Aegis Linux Defense Agent v0.2.12 Release Notes

v0.2.12 includes v0.2.11 and focuses on final proof reliability for competition review and rehearsal.

## Fixes

- Central Monitoring `CENTRAL_VERSION` now reports `0.2.12`.
- File event parsing now selects the first filesystem path in a telemetry line, avoiding trailing metadata such as `sha256=...`.
- Persistence event parsing now selects the persistence artifact path, avoiding payload paths such as `/tmp/.x` when the artifact is `/etc/cron.d/job`.
- AI Duel Demo `--execute` now uses demo-owned files and persistence artifacts under the output directory so quarantine/disable actions can succeed safely.
- Proof generator now writes compact and full outputs:
  - `proof_summary.json`
  - `proof_evidence_full.json`
  - `proof_report.md`
  - `proof_nftables_state.txt` when available
- Proof report now records nftables availability, `inet aegis_guard` table visibility, and set element counts.

## Proof commands

```bash
sudo /opt/aegis-linux-defense-agent/scripts/run_ai_duel_demo.sh
sudo /opt/aegis-linux-defense-agent/scripts/generate_proof_report.sh
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent duel-demo \
  --config /etc/aegis/agent.yaml \
  --policy /etc/aegis/policy.yaml \
  --output-dir /var/lib/aegis/ai_duel_execute_proof \
  --execute
```
