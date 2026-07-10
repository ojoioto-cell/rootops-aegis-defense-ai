# Architecture

## Design goal

외부 IPS/WAF 없이 Unix/Linux 서버 내부에 설치되는 Host-based Autonomous Defense AI Agent.

## Control/Data plane separation

- Local Defense Agent: telemetry, evidence chain, reasoning, response, verification, rollback.
- Central Monitoring: dashboard, incident view, policy management, report, approval workflow.

Central 장애 시에도 Local Defense Agent는 계속 동작한다.

## Defense loop

```text
Collect → Normalize → Build Evidence Chain → Analyze → Plan Response
→ Policy Gate → Local Enforcement → Verify → Audit → Sync Central
```

## Safety controls

- dry-run default
- action allowlist
- TTL requirement
- rollback metadata
- protected IP/account/process allowlist
- evidence threshold
- audit log
- no direct LLM shell execution

## Production hardening roadmap

1. journalctl/auditd real-time tailing
2. eBPF/XDP optional fast path for high-volume network events
3. robust nftables table/bootstrap and TTL cleanup scheduler
4. local reverse-proxy guard for HTTP request pre-filtering
5. Ollama/Llama structured reasoning integration
6. central policy signing and mTLS
7. approval workflow for critical actions
8. SIEM export format
