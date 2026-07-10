# Aegis v0.2.3 Beta Release Notes

## v0.1.5 AI Reasoning Engine

- Added `rule_based`, `ollama`, and `gpt/openai-compatible` providers.
- Added strict JSON-only defensive schema.
- Added evidence ID validation.
- Added action allowlist validation.
- Rejected shell-command-like targets.
- Added safe fallback to deterministic rule engine.

## v0.1.6 Central Monitoring + Policy Deployment

- Added agent heartbeat endpoint.
- Added agent inventory endpoint.
- Added policy repository.
- Added policy assignment endpoint.
- Added agent policy fetch endpoint.
- Added IOC repository.
- Added approval request repository.
- Hardened dashboard rendering with HTML escaping.

## v0.1.7 Daemon + Install Scripts

- Added `aegis_agent daemon` CLI.
- Added SIGTERM/SIGINT-aware service loop.
- Added optional expired-action cleanup in daemon mode.
- Updated systemd unit to use daemon mode.
- Added central systemd unit.
- Added install/uninstall/verify scripts.

## v0.2.0 Beta

- Combined v0.1.4 operational hardening with v0.1.5-v0.1.7 features.
- Intended for isolated VM operational testing, not unsupervised production use.


## v0.2.3 Central Monitoring UI Edition

- Replaced the static central dashboard with an offline SPA-style UI.
- Added `/api/summary` for dashboard metrics.
- Added action indexing from ingested incident payloads.
- Added `/api/actions` and `/api/actions/{action_id}`.
- Added `/api/incidents/{row_id}` detail API.
- Added `/api/agents/{agent_id}` detail API.
- Added policy detail/delete APIs.
- Added IOC delete API.
- Added approval decision API.
- Fixed central policy sync in the local agent so it accepts raw policy documents and older wrapped policy payloads.
- Kept safety boundary: Central UI manages monitoring/policy/IOC/approval records only; local agents still perform defense actions through Policy Gate and Local Enforcement.


## v0.2.3 Secrets Manager

- Added `api_key_file` support for GPT/OpenAI-compatible providers.
- Kept `api_key_env` environment-variable fallback.
- Added read-only local secret-file loading; the agent never writes or changes the key file.
- Added permission warnings for group/other readable or writable secret files.
- Added recursive secret redaction for Central Monitoring storage and UI/API responses.
- Added `python -m aegis_agent secrets-check --config ...` validation command.
