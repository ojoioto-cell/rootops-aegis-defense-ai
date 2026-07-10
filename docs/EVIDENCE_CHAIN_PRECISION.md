# Evidence Chain Precision Design

v0.1.3 replaces broad host-context attachment with relationship-based correlation.

## Problem fixed

v0.1.2 could attach unrelated host-level suspicious processes to an IP chain when that IP had suspicious events. This was safe in dry-run and partially mitigated by process safety checks, but it was not precise enough for autonomous defense.

## v0.1.3 correlation rules

A host event is added to an IP-anchored Evidence Chain only when at least one relation is present:

| Relation | Example |
|---|---|
| direct source IP | same attacker IP in auth/web logs |
| same user after SSH success | `ssh_success_login(user01)` then `sudo_execution(user01)` |
| shared external destination IP | web payload references `45.77.1.2`, process/network connects to `45.77.1.2` |
| shared file path | URI/process/FIM/auditd all reference `/tmp/.x` |
| shared PID/PPID | auditd process, network socket, file event share PID |
| app error after web attack | app error occurs shortly after suspicious web request |
| propagated relation | process creates file, network socket belongs to same PID |

## Result

The Agent can still connect a realistic exploit chain:

```text
web attack URI → shell/wget process → dropped /tmp file → outbound C2 → cron persistence
```

But it will not attach an unrelated shell process just because it exists on the same host.
