# Aegis v0.2.9 Signature Pattern Loop

v0.2.9 adds a signature-pattern blocking engine while preserving the autonomous loop safety model.

The flow is:

```text
collect telemetry
  -> signature pattern scan
  -> evidence chain build
  -> attack/security-growth loop scoring
  -> AI/rule reasoning
  -> action planning
  -> Policy Gate
  -> Local Enforcement
  -> Verifier
  -> rollback if needed
  -> learn bounded hostile indicators
```

Signature matches never execute actions directly. They are converted into `signature_match` Evidence events. Any resulting `block_ip_ttl`, `rate_limit_ip`, or `block_outbound_ip` action must still pass allowlist, score, TTL, rollback, and Policy Gate checks.

Default pattern groups include:

- SSH brute-force log markers
- Web path traversal/LFI
- Web command injection/RCE
- SQL injection
- Outbound C2/download tooling
- Drone MAVLink command/mission/parameter attempts
- ROS2/DDS discovery probes

Competition default safety change:

- `suspend_process` is disabled by default.
- If manually enabled, it requires verified auditd PID/PPID evidence.
- Network blocking remains the primary automatic response path.
