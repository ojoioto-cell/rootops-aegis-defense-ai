# Aegis v0.3.1 Live Battle Evidence Edition

Aegis v0.3.1 includes v0.3.0 and reorganizes the final competition workflow around **Live Battle Evidence Engine**.

## Why this changed

AI Duel Benchmark is useful for development rehearsals, but the actual final round does not repeatedly run a synthetic AI-duel benchmark. The important proof is produced from real runtime telemetry: incidents, actions, AI reasoning ledger rows, nftables state, policy-gate decisions, rollback status, and service-health evidence.

## Primary workflow

```text
Actual attack event
→ Aegis telemetry and Evidence Chain
→ GPT/Ollama/rule reasoning
→ Policy Gate
→ nftables/quarantine/persistence action
→ Verifier/Rollback/TTL
→ Live Battle Evidence metrics
→ Proof Report and Evidence Export
```

## New / changed commands

```bash
aegis-agent live-battle-evidence --config /etc/aegis/agent.yaml --summary
```

`battle-score` remains as a backward-compatible alias, but `live-battle-evidence` is the primary command.

## What is no longer core

- `duel-benchmark` CLI and `run_ai_duel_benchmark.sh` were removed from the core workflow.
- AI Duel Demo remains available as an optional rehearsal/proof screenshot tool.
- Championship Mode does not run synthetic benchmarks by default.

## Dashboard

The central `/api/battle` endpoint and Live Evidence UI now emphasize:

- live incident count
- synthetic incident count
- AI mode status
- enforcement success rate
- rollback rate
- service health failures
- policy promotion stages
- blocked or limited targets
- real nftables table/set proof

## Safety

No LLM can execute shell commands. Promotion, enforcement, rollback, and TTL remain Policy Gate controlled.
