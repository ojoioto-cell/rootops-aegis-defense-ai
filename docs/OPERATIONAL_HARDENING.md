# v0.1.4 Operational Hardening

## Goals

v0.1.4 stabilizes real defense execution before adding LLM/Ollama reasoning.

Implemented:

1. Persistence Guard real reversible disable
2. Health checks before/after action execution
3. Auto rollback on health failure
4. Agent self-protection integrity baseline
5. Attack Loop Tracker for repeated/mutating attacks
6. Hardened systemd service example

## Persistence Guard safety model

The guard only mutates exact evidence-linked targets under configured allowed paths. It backs up the original file first and returns a rollback payload.

Line-based files are modified by adding an `AEGIS_DISABLED` comment prefix to evidence-linked suspicious lines. Unit files are renamed to `.aegis-disabled-*`.

It refuses:

- unknown targets
- directory targets
- paths outside allowlist
- files larger than configured max size
- broad line edits without suspicious/evidence-linked content

## Auto rollback

When `rollback.auto_on_health_failure: true`, successful reversible actions are rolled back if post-action health checks fail.

## Self-protection

The monitor hashes configured package/config paths and stores `data/state/self_protection_baseline.json` on first run. A modified/missing/new file creates an `agent_integrity_change` host event.

## Attack Loop Tracker

Repeated or mutating attempts are grouped by source IP, attack type, and pattern. If attempts repeat, the chain receives a small score bonus. If payload/artifact variants change, mutation is flagged.
