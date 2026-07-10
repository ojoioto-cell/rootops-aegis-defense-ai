# Aegis v0.2.15 Championship Mode

v0.2.15 is a competition-focused reliability and proof upgrade over v0.2.14.

## Features

1. GPT-first reasoning with Ollama/Llama fallback and rule_based final fallback.
2. Policy Promotion Engine records candidate → shadow → enforce_verified → promoted states.
3. Proof Report includes AI provider mode, fallback count, enforcement success rate and policy promotion stage counts.
4. Central API `/api/championship` exposes current competition metrics.
5. CLI `championship-status` summarizes AI, enforcement and promotion status.
6. Script `aegis_championship_mode.sh` runs final proof generation.

## Safety

Policy promotion does not bypass Policy Gate. It records and proves policy maturation while retaining TTL, rollback and allowlist protections.
