# Aegis v0.2.3 Secrets Manager

v0.2.3 supports local read-only GPT/OpenAI-compatible API key files while keeping the previous environment-variable mode.

## Recommended config

```yaml
ai:
  provider: gpt
  model: gpt-5.5
  endpoint: https://api.openai.com/v1/chat/completions
  api_key_file: /etc/aegis/secrets/openai_api_key
  api_key_env: OPENAI_API_KEY
  strict_json: true
  fallback_to_rule_based: true
```

Resolution order:

1. `api_key_file` local file, preferred for service deployments.
2. legacy inline `api_key`, supported but warned.
3. `api_key_env`, environment variable fallback.

## File permissions

Recommended:

```bash
sudo mkdir -p /etc/aegis/secrets
sudo nano /etc/aegis/secrets/openai_api_key
sudo chmod 600 /etc/aegis/secrets/openai_api_key
sudo chown root:root /etc/aegis/secrets/openai_api_key
```

Helper script:

```bash
sudo ./scripts/create_openai_key_file.sh
```

The agent warns when group/other permissions are open. It does not modify secret-file permissions automatically.

## Validation

```bash
python -m aegis_agent secrets-check --config config/agent_gpt_file_example.yaml
```

The output shows only `loaded`, `source`, warning messages, and a masked key preview. The raw API key is never printed.

## Central UI/API behavior

Central Monitoring redacts secret-like fields before storing or returning payloads. Fields such as `api_key`, `token`, `password`, `secret`, and `client_secret` are shown as `***REDACTED***`. Central policy deployment should not be used to distribute raw API keys; keep keys local on each protected server via `api_key_file` or environment variables.
