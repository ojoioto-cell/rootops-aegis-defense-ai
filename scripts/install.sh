#!/usr/bin/env bash
set -euo pipefail
cat <<'MSG'
[Aegis] Default installer notice:
  - For competition real-enforcement all-in-one setup, run:
      sudo ./scripts/all_in_one_competition_install.sh
  - For local developer venv only, this script will continue now.
MSG
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m aegis_agent self-check --config config/agent.yaml >/dev/null || true
echo "Installed local venv. Dry-run: source .venv/bin/activate && python -m aegis_agent run-once --config config/agent.yaml"
