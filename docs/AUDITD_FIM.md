# auditd and FIM Collection

## auditd collector

The auditd collector parses records such as:

- `SYSCALL`
- `EXECVE`
- `PATH`
- `CWD`
- `PROCTITLE`

It groups records by audit serial, then emits defensive events:

| Event | Trigger |
|---|---|
| `suspicious_process` | temp/web shell/downloader execution indicators |
| `suspicious_file` | `/tmp`, `/dev/shm`, web directory file artifacts |
| `persistence_modified` | cron/systemd/authorized_keys/rc.local changes |

Suggested rules:

```bash
sudo ./scripts/install_auditd_rules.sh
```

## FIM collector

The polling FIM collector stores a baseline under `data/state/fim_state.json`. First run can baseline without emitting events. Later loops compare mtime, size, mode, and small-file SHA256.

| Operation | Event |
|---|---|
| create in suspicious path | `suspicious_file` |
| executable bit added | `suspicious_file` |
| cron/systemd/auth key path changed | `persistence_modified` |
| ordinary file change | `file_event` |

## Real-time mode

`telemetry.realtime.enabled: true` enables tail offsets for log files. `tail_first_run: eof` is recommended for production so historical logs do not trigger actions.
