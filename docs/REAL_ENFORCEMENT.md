# Real Enforcement Notes

## Real network blocking

v0.1.3 includes the v0.1.2 host-level network enforcement path and adds precision Evidence Chain gating before actions are planned.

### nftables backend

The agent creates a dedicated table:

```text
inet aegis_guard
```

It does not modify existing firewall tables directly. It creates input/output chains with priority `-10` and policy `accept`, plus timeout sets for Aegis actions.

Inbound source IP block:

```text
nft add element inet aegis_guard block_in_v4 { 185.10.10.5 timeout 3600s }
```

Outbound destination IP block:

```text
nft add element inet aegis_guard block_out_v4 { 45.77.1.2 timeout 3600s }
```

Suspicious IP TCP SYN rate limit:

```text
nft add element inet aegis_guard rate_limit_v4 { 185.10.10.5 timeout 1800s }
```

The chain rule drops TCP SYN packets over the configured rate.

### iptables backend

The iptables backend inserts reversible INPUT/OUTPUT rules with Aegis comments. Use `cleanup-expired --execute` for TTL cleanup because iptables has no native timeout sets in this MVP.

## Safety requirements

Real enforcement requires:

1. `enforcement.dry_run: false`
2. CLI flag `--enable-enforcement`
3. root privileges for nftables/iptables
4. telemetry not pointing to `sample_data`, unless `allow_sample_data_enforcement: true`
5. policy action enabled and `auto_allowed: true`
6. target not allowlisted
7. evidence count and score threshold satisfied

## Process suspension safety

`SIGSTOP` is sent only after the live `/proc/<pid>/cmdline` still matches the evidence target and suspicious pattern. This reduces the risk of stale snapshot PIDs causing the wrong process to be suspended.
