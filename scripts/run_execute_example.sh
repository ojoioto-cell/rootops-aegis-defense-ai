#!/usr/bin/env bash
set -euo pipefail

echo "This runs REAL local enforcement. Review config/agent_execute_example.yaml and config/policy.yaml first."
echo "Use only in an isolated test VM. Press Ctrl+C to abort, or wait 5 seconds to continue."
sleep 5
sudo python -m aegis_agent run-once --config config/agent_execute_example.yaml --enable-enforcement
