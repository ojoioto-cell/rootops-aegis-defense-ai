# Secrets directory

Do not commit real API keys.

The v0.3.1 all-in-one installer creates the runtime key file automatically:

```text
/etc/aegis/secrets/openai_api_key
```

During install, the user can paste the API key once. The file is written as `root:root` with mode `600`. If the key is left blank, Aegis uses offline `rule_based` reasoning.

Manual setup:

```bash
sudo mkdir -p /etc/aegis/secrets
sudo sh -c 'printf "%s" "<OPENAI_API_KEY>" > /etc/aegis/secrets/openai_api_key'
sudo chmod 600 /etc/aegis/secrets/openai_api_key
sudo chown root:root /etc/aegis/secrets/openai_api_key
```

The central UI/API redacts secrets before display.
