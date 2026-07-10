# Aegis v0.2.16 Championship Reliability Patch

v0.2.16 includes v0.2.15 and focuses on competition reliability, evidence clarity and safe autonomous policy growth.

## Key fixes

1. Runtime state cleanup
   - Removed packaged `data/ai_reasoning_ledger.jsonl`.
   - Removed packaged `data/state/*.json`.
   - Installer creates fresh state in `/var/lib/aegis`.

2. Championship Dashboard UI
   - AI MODE card.
   - fallback count.
   - enforcement success rate.
   - policy promotion stage.
   - blocked/limited targets.

3. Proof Report 2.0
   - Separates Synthetic AI Duel Proof from Real Enforcement Proof.
   - Shows GPT/Ollama/rule_based usage and fallback count.
   - Adds policy promotion growth metrics and TTL recommendations.

4. Policy Promotion implementation
   - promoted IOC candidate generation.
   - TTL recommendation.
   - shadow-policy patch generation.
   - approval request generation.
   - no direct active policy mutation without approval.

5. CLI quality
   - `championship-status --summary`.
   - BrokenPipeError safe handling.
