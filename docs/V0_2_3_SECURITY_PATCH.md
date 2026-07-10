# Aegis Linux Defense Agent v0.2.3 Security Patch

## Scope

v0.2.3 is a security and quality stabilization release built on v0.2.2.

## Key Fixes

1. Central UI inline handlers removed.
2. Optional read API and dashboard authentication added.
3. Version metadata aligned.
4. Rule-based evidence mapping narrowed by event type.
5. `central.enabled=true` with `token=change-me` refused.
6. Strict secret file permission mode added.
7. Audit and central DB files are chmod `0600` after creation.
8. GPT mocked call test added for strict JSON and API key handling.
9. nftables VM validation script added.

## Operational Recommendation

Use `--require-read-auth` whenever Central is reachable beyond localhost. Keep the Central token out of source control and do not leave it as `change-me`.

## Secret File Strict Mode

```yaml
ai:
  provider: gpt
  api_key_file: /etc/aegis/secrets/openai_api_key
  fail_on_insecure_secret_permissions: true
```

Recommended permission:

```bash
sudo chmod 600 /etc/aegis/secrets/openai_api_key
sudo chown root:root /etc/aegis/secrets/openai_api_key
```
