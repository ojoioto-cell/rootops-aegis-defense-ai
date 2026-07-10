# Aegis v0.3.0 Final Competition Edition

Aegis v0.3.0 includes all v0.2.16 Championship Reliability features and adds final competition capabilities focused on measurable autonomous defense performance, not just more signatures.

## Major Additions

1. **Live Battle Score Engine**
   - Calculates detection rate, enforcement success rate, rollback rate, mean detection time, mean policy time, mean response time, service-health failures, AI quality score, blocked targets, and nftables counter snapshots.
   - CLI: `aegis-agent live-battle-evidence --config /etc/aegis/agent.yaml --summary`

2. **AI Reasoning Quality Guard**
   - Validates evidence mappings, missing evidence IDs, risky recommendations, and Policy Gate denials.
   - CLI: `aegis-agent ai-quality --config /etc/aegis/agent.yaml`

3. **Self-Healing Check**
   - Plans or executes repair for missing `aegis_guard` nftables table and missing auditd rules.
   - CLI: `aegis-agent self-heal-check --config /etc/aegis/agent.yaml`

4. **Evidence Exporter**
   - Exports audit DB, central DB, Proof Report, journal excerpts, nftables ruleset, and manifest into a final evidence archive.
   - CLI: `aegis-agent export-evidence --config /etc/aegis/agent.yaml`

5. **Central Live Battle Dashboard/API**
   - Adds `/api/battle` and a Live Battle dashboard section.
   - Shows AI mode, response time, enforcement success, AI quality, blocked targets, and nftables effect.

6. **Championship Scripts Updated**
   - `aegis_all_in_one_check.sh` includes Live Battle Evidence, AI Quality, and Self-Heal Check.
   - From v0.3.1, AI Duel Benchmark is not a core 본선 metric; synthetic demo is optional rehearsal only.

## AI Provider Priority

The intended reasoning priority remains:

1. GPT API
2. Local Ollama/Llama
3. Rule-based fallback

Aegis records provider mode and fallback count so competition reports can prove whether GPT/Ollama/rule paths were used.

## Safety Boundary

Aegis remains defensive only. It does not generate exploit code, does not send drone control commands, and does not allow LLMs to execute shell commands. Enforcement remains Policy Gate, TTL, verifier, and rollback controlled.
