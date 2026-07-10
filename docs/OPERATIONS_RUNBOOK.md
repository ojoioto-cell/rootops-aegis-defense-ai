# Aegis Operations Runbook

## Recommended deployment flow

1. Install in a disposable Linux VM.
2. Run dry-run mode with sample logs.
3. Configure live telemetry paths.
4. Enable auditd/FIM with conservative path scope.
5. Configure service health checks.
6. Run live dry-run for at least one full maintenance window.
7. Validate allowlists for management IPs, service accounts, and critical processes.
8. Enable enforcement only for low-risk actions first: `block_ip_ttl`, `rate_limit_ip`, `block_outbound_ip`.
9. Validate rollback with `cleanup-expired` and `rollback-action`.
10. Add high-risk actions only after service owner approval.

## Important commands

```bash
python -m aegis_agent run-once --config config/agent.yaml
python -m aegis_agent daemon --config config/agent.yaml --loops 3
python -m aegis_agent actions --config config/agent.yaml
python -m aegis_agent cleanup-expired --config config/agent.yaml
python -m aegis_agent self-check --config config/agent.yaml
python -m aegis_agent sync-policy --config config/agent.yaml --output data/central_policy.yaml
```

## Real enforcement guardrails

Real enforcement is blocked unless `dry_run: false` and `--enable-enforcement` are both present. Never enable real enforcement with `sample_data` telemetry.

## AI provider guidance

Use `rule_based` for closed-network baseline. Use `ollama` for offline Llama testing. Use `gpt` only when policy permits external API calls. LLM output is advisory and must pass schema validation before any action can be planned.
