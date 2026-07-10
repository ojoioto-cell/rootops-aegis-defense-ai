# Aegis Linux Defense Agent v0.2.10 Release Notes

## Purpose

v0.2.10 is the practical competition patch over v0.2.8. It keeps the All-in-One installer, Linux defense, Drone Network Guard, OpenAI key-file creation, and post-install validation, while making the whole detection/response path explicitly loop-based.

## Major changes

- Added `SignaturePatternEngine`.
- Added `signature_match` evidence events.
- Added signature-based `block_ip_ttl`, `rate_limit_ip`, and `block_outbound_ip` recommendations.
- Added `LoopProcessRecorder` for per-incident loop audit trail.
- Updated post-install validation to test signature-based blocking path.
- Disabled `suspend_process` by default for competition safety.
- Added Policy Gate requirement for auditd PID/PPID evidence before any process suspension can be allowed.
- Added `config/signatures.yaml` for competition signatures.

## Default safe enforcement posture

Automatic actions enabled:

- `block_ip_ttl`
- `rate_limit_ip`
- `block_outbound_ip`
- `quarantine_file`
- `disable_persistence`

Automatic actions disabled by default:

- `suspend_process`
- `kill_process`
- `restrict_account`
- `isolate_host`

## One-command install

```bash
unzip aegis_linux_defense_agent_v0_2_12.zip
cd aegis_linux_defense_agent_v0_2_12
sudo ./scripts/all_in_one_competition_install.sh
```

The installer creates `/etc/aegis/secrets/openai_api_key`; the user only enters the key when prompted.

## v0.2.10 Competition Safety + Vulnerability Guard Patch

This release includes all v0.2.9 loop-process and signature blocking capabilities and adds three competition-safety improvements:

1. `suspend_process` is disabled not only in local competition policies but also in the central policy example files. Even if a central policy is deployed from the bundled example, process suspension remains disabled by default and still requires auditd PID/PPID relation evidence when explicitly enabled.
2. Web RCE signatures no longer match bare `curl`, `wget`, or `nc` strings by themselves. This avoids overmatching normal User-Agent values such as `curl/8.0`. The RCE signature now requires command context, shell separators, shell syntax, or downloader invocation with an actual URL.
3. A new `VulnerabilityAttackGuard` detects known and generic vulnerability attack attempts, including Log4Shell/JNDI markers, Spring-style binding probes, Shellshock CGI payloads, Struts/OGNL expressions, phpunit/Ignition probes, exposed admin surfaces, and aggregate new/variant vulnerability probing from the same source IP. The guard creates evidence events only; all enforcement still passes through Evidence Chain, AI/Rule reasoning, Policy Gate, Local Enforcement, Verifier, Rollback, and Security Growth.

The loop is now:

```text
collect_telemetry
→ signature_pattern_scan
→ vulnerability_guard_scan
→ build_evidence_chain
→ attack_loop_track
→ security_growth_observe
→ ai_reasoning
→ plan_actions
→ pre_action_health_check
→ policy_gate
→ local_enforcement
→ verify_actions
→ rollback if needed
→ security_growth_learn
```

### Defensive scope

The vulnerability guard can block or rate-limit vulnerability attempts when evidence supports the source IP risk. It cannot guarantee detection of every zero-day exploit. Unknown vulnerability handling is behavior/signature-hybrid: exposed vulnerable endpoints, exploit syntax, encoded payloads, repeated probing categories, and post-exploitation artifacts raise evidence score and trigger TTL-based blocking.

### Safety

The agent still does not generate offensive payloads, does not run exploit code, and does not send drone control commands. It only performs defensive observation, IP/rate limiting, outbound block, file quarantine, persistence disabling, and rollback-controlled local enforcement.
