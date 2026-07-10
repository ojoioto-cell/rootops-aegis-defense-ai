#!/usr/bin/env bash
set -euo pipefail
CONFIG="${1:-config/agent.yaml}"
python -m compileall src/aegis_agent src/aegis_central >/dev/null
python -m pytest -q
python -m aegis_agent run-once --config "$CONFIG" >/tmp/aegis_verify_run.json
python -m aegis_agent ai-test --config "$CONFIG" >/tmp/aegis_verify_ai.json
echo "Verification PASS. Outputs: /tmp/aegis_verify_run.json /tmp/aegis_verify_ai.json"
