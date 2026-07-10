from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

import yaml

from aegis_agent import __version__
from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.central_client import CentralClient
from aegis_agent.core.loop_controller import LoopController
from aegis_agent.core.duel_demo import AIDuelDemoHarness
from aegis_agent.core.proof import ProofReportGenerator
from aegis_agent.core.reasoning_ledger import AIReasoningLedger
from aegis_agent.core.self_protection import SelfProtectionMonitor
from aegis_agent.core.policy_promotion import PolicyPromotionEngine
from aegis_agent.core.battle_score import LiveBattleScoreEngine
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine
from aegis_agent.core.ai_quality import AIReasoningQualityGuard
from aegis_agent.core.self_heal import SelfHealingCheck
from aegis_agent.core.evidence_exporter import CompetitionEvidenceExporter
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.executors.rollback import RollbackExecutor
from aegis_agent.utils import load_yaml, now_epoch
from aegis_agent.security.secrets import secret_status, redact_secrets


_STOP = False


def _signal_stop(signum, frame):  # pragma: no cover - signal behavior is integration-tested manually
    global _STOP
    _STOP = True


def _build_controller(args):
    cfg = load_yaml(args.config)
    policy_path = args.policy or str(Path(args.config).parent / "policy.yaml")
    policy = load_yaml(policy_path)
    return cfg, LoopController(cfg, policy, enable_enforcement=args.enable_enforcement)


def cmd_run_once(args):
    cfg, controller = _build_controller(args)
    incidents = controller.run_once()
    print(json.dumps({"version": __version__, "incident_count": len(incidents), "incidents": incidents}, indent=2, ensure_ascii=False))


def cmd_run(args):
    cfg, controller = _build_controller(args)
    interval = int(cfg.get("agent", {}).get("loop_interval_seconds", 10))
    loops = args.loops
    count = 0
    while True:
        count += 1
        incidents = controller.run_once()
        print(json.dumps({"version": __version__, "loop": count, "incident_count": len(incidents), "incidents": incidents}, indent=2, ensure_ascii=False))
        if loops and count >= loops:
            break
        time.sleep(interval)


def cmd_daemon(args):
    signal.signal(signal.SIGTERM, _signal_stop)
    signal.signal(signal.SIGINT, _signal_stop)
    cfg, controller = _build_controller(args)
    interval = int(args.interval or cfg.get("agent", {}).get("loop_interval_seconds", 10))
    count = 0
    controller.heartbeat(status="daemon_starting")
    while not _STOP:
        count += 1
        started = time.time()
        try:
            incidents = controller.run_once()
            cleanup = None
            if args.cleanup_expired:
                cleanup = _cleanup_expired_internal(controller.audit, controller.rollback_executor, args.cleanup_limit)
            line = {"version": __version__, "mode": "daemon", "loop": count, "incident_count": len(incidents), "cleanup": cleanup}
            print(json.dumps(line, ensure_ascii=False), flush=True)
        except Exception as exc:
            controller.heartbeat(status="error", extra={"error": str(exc)})
            print(json.dumps({"version": __version__, "mode": "daemon", "loop": count, "error": str(exc)}, ensure_ascii=False), file=sys.stderr, flush=True)
        if args.loops and count >= args.loops:
            break
        sleep_for = max(1, interval - int(time.time() - started))
        for _ in range(sleep_for):
            if _STOP:
                break
            time.sleep(1)
    controller.heartbeat(status="daemon_stopped")


def _resolve_audit_db(args):
    if getattr(args, "db", None):
        return args.db
    if getattr(args, "config", None):
        cfg = load_yaml(args.config)
        return cfg.get("agent", {}).get("audit_db", "data/audit.db")
    return "data/audit.db"


def cmd_incidents(args):
    audit = AuditLogger(_resolve_audit_db(args))
    print(json.dumps(audit.list_incidents(args.limit), indent=2, ensure_ascii=False))


def cmd_actions(args):
    audit = AuditLogger(_resolve_audit_db(args))
    print(json.dumps(audit.list_actions(args.limit), indent=2, ensure_ascii=False))


def cmd_rollback_action(args):
    audit = AuditLogger(_resolve_audit_db(args))
    action = audit.get_action(args.action_id)
    if not action:
        print(json.dumps({"ok": False, "error": "action_not_found", "action_id": args.action_id}, indent=2, ensure_ascii=False))
        return
    executor = RollbackExecutor(dry_run=not args.execute)
    result = executor.execute(action)
    action["rollback_result"] = result
    if result.get("rollback_status") == "success":
        action["status"] = "rolled_back"
    elif result.get("rollback_status") == "planned":
        action["status"] = "rollback_planned"
    audit.update_action_payload(args.action_id, action)
    print(json.dumps({"ok": result.get("rollback_status") in {"success", "planned"}, "result": result}, indent=2, ensure_ascii=False))


def _cleanup_expired_internal(audit: AuditLogger, executor: RollbackExecutor, limit: int = 100):
    expired = audit.list_expired_actions(now_epoch(), limit=limit)
    results = []
    for action in expired:
        result = executor.execute(action)
        action["rollback_result"] = result
        if result.get("rollback_status") == "success":
            action["status"] = "expired_rolled_back"
        elif result.get("rollback_status") == "planned":
            action["status"] = "expired_rollback_planned"
        audit.update_action_payload(action["action_id"], action)
        results.append(result)
    return {"expired_count": len(expired), "results": results}


def cmd_cleanup_expired(args):
    audit = AuditLogger(_resolve_audit_db(args))
    executor = RollbackExecutor(dry_run=not args.execute)
    result = _cleanup_expired_internal(audit, executor, args.limit)
    result["execute"] = bool(args.execute)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _build_self_monitor(args):
    cfg = load_yaml(args.config)
    agent = cfg.get("agent", {})
    sp = cfg.get("self_protection", {})
    default_paths = ["aegis_agent", "config", "VERSION", "deploy"]
    return SelfProtectionMonitor(
        state_dir=sp.get("state_dir", agent.get("state_dir", "data/state")),
        enabled=bool(sp.get("enabled", True)),
        paths=sp.get("paths", default_paths),
        baseline_on_first_run=bool(sp.get("baseline_on_first_run", True)),
    )


def cmd_self_check(args):
    mon = _build_self_monitor(args)
    print(json.dumps(mon.check(), indent=2, ensure_ascii=False))


def cmd_reset_self_baseline(args):
    mon = _build_self_monitor(args)
    print(json.dumps(mon.reset_baseline(), indent=2, ensure_ascii=False))


def _central_from_config(config_path: str) -> tuple[dict, CentralClient]:
    cfg = load_yaml(config_path)
    central = cfg.get("central", {})
    url = central.get("url", "").replace("/api/ingest", "")
    client = CentralClient(bool(central.get("enabled", False)), url, central.get("token", ""), int(central.get("timeout_seconds", 5)))
    return cfg, client


def cmd_sync_policy(args):
    cfg, client = _central_from_config(args.config)
    agent_id = args.agent_id or cfg.get("agent", {}).get("id", "unknown-agent")
    result = client.fetch_policy(agent_id)
    if result.get("ok") and result.get("policy") and args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            yaml.safe_dump(result["policy"], f, allow_unicode=True, sort_keys=False)
    print(json.dumps({"agent_id": agent_id, **result}, indent=2, ensure_ascii=False))


def cmd_heartbeat(args):
    cfg, client = _central_from_config(args.config)
    agent_id = args.agent_id or cfg.get("agent", {}).get("id", "unknown-agent")
    payload = {
        "hostname": cfg.get("agent", {}).get("hostname"),
        "version": __version__,
        "mode": cfg.get("agent", {}).get("mode", "autonomous"),
        "status": args.status,
    }
    print(json.dumps(client.send_heartbeat(agent_id, payload), indent=2, ensure_ascii=False))


def cmd_secrets_check(args):
    cfg = load_yaml(args.config)
    ai_cfg = cfg.get("ai", {})
    status = secret_status(ai_cfg, default_env="OPENAI_API_KEY")
    public_ai_cfg = redact_secrets(ai_cfg)
    print(json.dumps({"ok": bool(status.get("loaded")) or ai_cfg.get("provider", "rule_based") != "gpt", "provider": ai_cfg.get("provider", "rule_based"), "secret_status": status, "sanitized_ai_config": public_ai_cfg}, indent=2, ensure_ascii=False))


def cmd_ai_test(args):
    cfg, controller = _build_controller(args)
    events = controller.collect_telemetry()
    chains = build_evidence_chains(events)
    if not chains:
        print(json.dumps({"ok": False, "error": "no_evidence_chain"}, indent=2, ensure_ascii=False))
        return
    chain = chains[0]
    result = controller.ai.analyze(chain)
    print(json.dumps({"ok": True, "provider": controller.ai.provider, "ai_status": getattr(controller.ai, "last_status", {}), "chain_id": chain.chain_id, "analysis": result.to_dict()}, indent=2, ensure_ascii=False))



def cmd_reasoning_ledger(args):
    cfg = load_yaml(args.config) if args.config else {}
    ledger_cfg = cfg.get("reasoning_ledger", {})
    path = args.ledger or ledger_cfg.get("path") or cfg.get("agent", {}).get("reasoning_ledger") or "data/ai_reasoning_ledger.jsonl"
    ledger = AIReasoningLedger(path, enabled=False)
    print(json.dumps({"ledger": str(path), "entries": ledger.read_recent(args.limit)}, indent=2, ensure_ascii=False))



def cmd_championship_status(args):
    cfg = load_yaml(args.config)
    audit = AuditLogger(_resolve_audit_db(args))
    incidents = audit.list_incidents(args.limit)
    actions = audit.list_actions(args.limit)
    ledger_cfg = cfg.get("reasoning_ledger", {})
    ledger_path = args.ledger or ledger_cfg.get("path") or cfg.get("agent", {}).get("reasoning_ledger") or "data/ai_reasoning_ledger.jsonl"
    ledger = AIReasoningLedger(ledger_path, enabled=False)
    state_dir = cfg.get("agent", {}).get("state_dir", "data/state")
    promo_cfg = cfg.get("policy_promotion", {})
    promo = PolicyPromotionEngine(
        state_dir=promo_cfg.get("state_dir", state_dir),
        enabled=bool(promo_cfg.get("enabled", True)),
        shadow_after=int(promo_cfg.get("shadow_after_observations", 2)),
        enforce_after=int(promo_cfg.get("enforce_after_observations", 3)),
        promote_after_success=int(promo_cfg.get("promote_after_successes", 3)),
    )
    ai_modes = {}
    fallback_count = 0
    for i in incidents:
        st = i.get("ai_status") or {}
        ai = str(i.get("ai_provider") or st.get("provider_used") or "unknown")
        ai_modes[ai] = ai_modes.get(ai, 0) + 1
        if st.get("fallback"):
            fallback_count += 1
    action_status = {}
    action_counts = {}
    blocked_targets = set()
    for a in actions:
        action_counts[str(a.get("action"))] = action_counts.get(str(a.get("action")), 0) + 1
        action_status[str(a.get("status"))] = action_status.get(str(a.get("status")), 0) + 1
        if a.get("action") in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"} and a.get("target"):
            blocked_targets.add(str(a.get("target")))
    success = action_status.get("success", 0)
    total = len(actions)
    summary = promo.summary()
    output = {
        "version": __version__,
        "championship_mode": True,
        "ai_priority": cfg.get("ai", {}).get("provider_priority", ["gpt", "ollama", "rule_based"]),
        "incident_count": len(incidents),
        "action_count": len(actions),
        "ai_modes": ai_modes,
        "ai_fallback_count": fallback_count,
        "action_counts": action_counts,
        "action_status": action_status,
        "enforcement_success_rate": round((success / total) * 100, 2) if total else 0.0,
        "blocked_or_limited_targets": sorted(blocked_targets)[:100],
        "policy_promotion": summary,
        "reasoning_ledger_path": str(ledger_path),
    }
    if not getattr(args, "summary", False):
        output["recent_reasoning_entries"] = ledger.read_recent(min(args.limit, 10))
    print(json.dumps(output, indent=2, ensure_ascii=False))

def cmd_proof_report(args):
    audit_db = args.db or _resolve_audit_db(args)
    cfg = load_yaml(args.config) if args.config else {}
    ledger = args.ledger or cfg.get("reasoning_ledger", {}).get("path") or cfg.get("agent", {}).get("reasoning_ledger") or "data/ai_reasoning_ledger.jsonl"
    enf = cfg.get("enforcement", {}) if isinstance(cfg, dict) else {}
    result = ProofReportGenerator(
        audit_db,
        ledger,
        nft_family=enf.get("nft_family", "inet"),
        nft_table=enf.get("nft_table", "aegis_guard"),
        include_nftables=not args.no_nftables,
    ).write(args.output_dir, title=args.title)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_duel_demo(args):
    harness = AIDuelDemoHarness(args.config, args.policy, args.output_dir, execute=args.execute, use_config_ai=args.use_config_ai)
    result = harness.run()
    print(json.dumps({"version": __version__, "ok": True, **result}, indent=2, ensure_ascii=False))


def _resolve_ledger_path_from_config(config_path: str | None) -> str:
    if config_path:
        cfg = load_yaml(config_path)
        return cfg.get("reasoning_ledger", {}).get("path") or cfg.get("agent", {}).get("reasoning_ledger") or "data/ai_reasoning_ledger.jsonl"
    return "data/ai_reasoning_ledger.jsonl"


def _compute_live_battle_evidence(args):
    cfg = load_yaml(args.config) if args.config else {}
    audit_db = args.db or cfg.get("agent", {}).get("audit_db", "data/audit.db")
    ledger = args.ledger or cfg.get("reasoning_ledger", {}).get("path") or cfg.get("agent", {}).get("reasoning_ledger") or "data/ai_reasoning_ledger.jsonl"
    enf = cfg.get("enforcement", {}) if isinstance(cfg, dict) else {}
    return LiveBattleEvidenceEngine(
        audit_db,
        ledger,
        nft_family=enf.get("nft_family", "inet"),
        nft_table=enf.get("nft_table", "aegis_guard"),
    ).compute(limit=args.limit, include_synthetic=getattr(args, "include_synthetic", False))


def cmd_live_battle_evidence(args):
    evidence = _compute_live_battle_evidence(args)
    if args.summary:
        evidence = LiveBattleEvidenceEngine.compact(evidence)
    print(json.dumps(evidence, indent=2, ensure_ascii=False))


def cmd_battle_score(args):
    # Backward-compatible alias.  v0.3.1 centers this output on actual runtime
    # evidence instead of synthetic AI Duel Benchmark metrics.
    cmd_live_battle_evidence(args)


def cmd_ai_quality(args):
    audit = AuditLogger(_resolve_audit_db(args))
    guard = AIReasoningQualityGuard()
    rows = []
    for inc in audit.list_incidents(args.limit):
        chain = inc.get("chain") or {}
        events = chain.get("events") or []
        evidence_ids = [e.get("event_id") for e in events if e.get("event_id")]
        result = guard.evaluate(inc.get("analysis") or {}, evidence_ids, inc.get("denied_actions") or [])
        rows.append({"incident_id": inc.get("incident_id"), "attack_type": inc.get("attack_type"), **result})
    ok_count = sum(1 for r in rows if r.get("ok"))
    print(json.dumps({"ok": ok_count == len(rows), "checked": len(rows), "ok_count": ok_count, "results": rows}, indent=2, ensure_ascii=False))


def cmd_self_heal_check(args):
    cfg = load_yaml(args.config) if args.config else {}
    enf = cfg.get("enforcement", {}) if isinstance(cfg, dict) else {}
    result = SelfHealingCheck(enf.get("nft_family", "inet"), enf.get("nft_table", "aegis_guard")).check(execute=args.execute)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_export_evidence(args):
    cfg = load_yaml(args.config) if args.config else {}
    audit_db = args.db or cfg.get("agent", {}).get("audit_db", "data/audit.db")
    result = CompetitionEvidenceExporter(args.output_dir).export(audit_db, central_db=args.central_db, proof_dir=args.proof_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(prog="aegis-agent", description="Aegis Linux Defense Agent")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("run-once", help="Collect telemetry, build evidence chain, plan and execute allowed defense actions once")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--policy", default=None)
    p.add_argument("--enable-enforcement", action="store_true", help="Allow real enforcement only if config dry_run is false")
    p.set_defaults(func=cmd_run_once)

    p = sub.add_parser("run", help="Run continuous monitoring loop")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--policy", default=None)
    p.add_argument("--enable-enforcement", action="store_true", help="Allow real enforcement only if config dry_run is false")
    p.add_argument("--loops", type=int, default=0, help="Number of loops; 0 means infinite")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("daemon", help="Run service-friendly realtime daemon loop with signal handling")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--policy", default=None)
    p.add_argument("--enable-enforcement", action="store_true")
    p.add_argument("--interval", type=int, default=0)
    p.add_argument("--loops", type=int, default=0, help="Testing only; 0 means infinite")
    p.add_argument("--cleanup-expired", action="store_true")
    p.add_argument("--cleanup-limit", type=int, default=100)
    p.set_defaults(func=cmd_daemon)

    p = sub.add_parser("ai-test", help="Run AI reasoning against the first current evidence chain without executing actions")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--policy", default=None)
    p.set_defaults(func=cmd_ai_test, enable_enforcement=False)

    p = sub.add_parser("sync-policy", help="Fetch assigned central policy for this agent and optionally save it")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--agent-id", default="")
    p.add_argument("--output", default="")
    p.set_defaults(func=cmd_sync_policy)

    p = sub.add_parser("heartbeat", help="Send one central heartbeat")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--agent-id", default="")
    p.add_argument("--status", default="manual")
    p.set_defaults(func=cmd_heartbeat)

    p = sub.add_parser("incidents", help="List local audit incidents")
    p.add_argument("--config", default=None, help="Optional agent config used to resolve audit_db")
    p.add_argument("--db", default=None, help="Audit DB path; overrides --config")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_incidents)

    p = sub.add_parser("actions", help="List local audit actions")
    p.add_argument("--config", default=None, help="Optional agent config used to resolve audit_db")
    p.add_argument("--db", default=None, help="Audit DB path; overrides --config")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_actions)

    p = sub.add_parser("rollback-action", help="Rollback one saved action by action_id; dry-run unless --execute is set")
    p.add_argument("action_id")
    p.add_argument("--config", default=None, help="Optional agent config used to resolve audit_db")
    p.add_argument("--db", default=None, help="Audit DB path; overrides --config")
    p.add_argument("--execute", action="store_true", help="Actually execute rollback; otherwise prints planned rollback")
    p.set_defaults(func=cmd_rollback_action)

    p = sub.add_parser("cleanup-expired", help="Rollback expired successful actions from audit DB; dry-run unless --execute is set")
    p.add_argument("--config", default=None, help="Optional agent config used to resolve audit_db")
    p.add_argument("--db", default=None, help="Audit DB path; overrides --config")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--execute", action="store_true", help="Actually execute cleanup rollback; otherwise prints planned cleanup")
    p.set_defaults(func=cmd_cleanup_expired)


    p = sub.add_parser("secrets-check", help="Validate GPT/OpenAI API key loading and secret-file permissions without exposing the key")
    p.add_argument("--config", default="config/agent.yaml")
    p.set_defaults(func=cmd_secrets_check)

    p = sub.add_parser("self-check", help="Check agent/policy integrity against the self-protection baseline")
    p.add_argument("--config", default="config/agent.yaml")
    p.set_defaults(func=cmd_self_check)

    p = sub.add_parser("reset-self-baseline", help="Reset the self-protection integrity baseline after an approved update")
    p.add_argument("--config", default="config/agent.yaml")
    p.set_defaults(func=cmd_reset_self_baseline)

    p = sub.add_parser("reasoning-ledger", help="Show recent AI reasoning ledger entries")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--ledger", default="")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_reasoning_ledger)


    p = sub.add_parser("championship-status", help="Show Championship Mode AI/provider, promotion, action and proof status")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--db", default=None)
    p.add_argument("--ledger", default="")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--summary", action="store_true", help="Print compact status without recent reasoning rows")
    p.set_defaults(func=cmd_championship_status)

    p = sub.add_parser("proof-report", help="Generate a competition proof report from audit DB and AI reasoning ledger")
    p.add_argument("--config", default="config/agent.yaml")
    p.add_argument("--db", default=None)
    p.add_argument("--ledger", default="")
    p.add_argument("--output-dir", default="data/proof")
    p.add_argument("--title", default="Aegis Competition Proof Report")
    p.add_argument("--no-nftables", action="store_true", help="Skip nftables proof collection in generated report")
    p.set_defaults(func=cmd_proof_report)

    p = sub.add_parser("duel-demo", help="Run a safe AI-attack vs Aegis-defense duel demo and generate proof artifacts")
    p.add_argument("--config", default="config/agent_linux_drone_competition_example.yaml")
    p.add_argument("--policy", default="config/policy_linux_drone_competition_example.yaml")
    p.add_argument("--output-dir", default="data/ai_duel_demo")
    p.add_argument("--execute", action="store_true", help="Use configured enforcement instead of safe default dry/memory behavior")
    p.add_argument("--use-config-ai", action="store_true", help="Use AI provider from config; default demo uses rule_based to avoid external calls")
    p.set_defaults(func=cmd_duel_demo)


    p = sub.add_parser("live-battle-evidence", help="Compute actual live battle evidence metrics from incidents, actions, ledger and nftables")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--db", default=None)
    p.add_argument("--ledger", default="")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--summary", action="store_true")
    p.add_argument("--include-synthetic", action="store_true", help="Include optional AI Duel demo/test incidents; default is live-only")
    p.set_defaults(func=cmd_live_battle_evidence)

    p = sub.add_parser("battle-score", help="Backward-compatible alias for live-battle-evidence")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--db", default=None)
    p.add_argument("--ledger", default="")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--summary", action="store_true")
    p.add_argument("--include-synthetic", action="store_true")
    p.set_defaults(func=cmd_battle_score)

    p = sub.add_parser("ai-quality", help="Validate recent AI reasoning outputs against evidence IDs and policy safety")
    p.add_argument("--config", default=None)
    p.add_argument("--db", default=None)
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_ai_quality)

    p = sub.add_parser("self-heal-check", help="Plan or execute repair of runtime prerequisites such as nftables table and auditd rules")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--execute", action="store_true")
    p.set_defaults(func=cmd_self_heal_check)

    p = sub.add_parser("export-evidence", help="Export final competition evidence bundle as tar.gz")
    p.add_argument("--config", default="/etc/aegis/agent.yaml")
    p.add_argument("--db", default=None)
    p.add_argument("--central-db", default="/var/lib/aegis/central.db")
    p.add_argument("--proof-dir", default="/var/lib/aegis/proof")
    p.add_argument("--output-dir", default="/var/lib/aegis/final_evidence")
    p.set_defaults(func=cmd_export_evidence)

    args = parser.parse_args()
    try:
        args.func(args)
    except BrokenPipeError:  # allow piping to head/grep without noisy tracebacks
        try:
            sys.stdout.close()
        except Exception:
            pass
        return


if __name__ == "__main__":
    main()
