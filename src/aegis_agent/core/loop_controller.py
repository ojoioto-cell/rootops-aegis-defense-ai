from __future__ import annotations

import time
from typing import Any, Dict, List

from aegis_agent import __version__
from aegis_agent.ai.llm_client import AIReasoningClient
from aegis_agent.ai.rule_engine import build_action_plans
from aegis_agent.collectors.auth_log import collect_auth_events
from aegis_agent.collectors.web_log import collect_web_events
from aegis_agent.collectors.snapshot import collect_file_events, collect_network_snapshot, collect_persistence_events, collect_process_snapshot
from aegis_agent.collectors.auditd import collect_auditd_events
from aegis_agent.collectors.fim import collect_fim_events
from aegis_agent.collectors.drone import collect_drone_events
from aegis_agent.core.attack_loop import AttackLoopTracker
from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.central_client import CentralClient
from aegis_agent.core.policy_gate import PolicyGate
from aegis_agent.core.self_protection import SelfProtectionMonitor
from aegis_agent.core.security_growth import SecurityGrowthMemory
from aegis_agent.core.policy_promotion import PolicyPromotionEngine
from aegis_agent.core.signature_engine import SignaturePatternEngine
from aegis_agent.core.vulnerability_guard import VulnerabilityAttackGuard
from aegis_agent.core.loop_process import LoopProcessRecorder
from aegis_agent.core.reasoning_ledger import AIReasoningLedger
from aegis_agent.core.ai_quality import AIReasoningQualityGuard
from aegis_agent.core.verifier import Verifier
from aegis_agent.evidence.builder import build_evidence_chains
from aegis_agent.executors.local_enforcement import LocalEnforcementLayer
from aegis_agent.executors.rollback import RollbackExecutor
from aegis_agent.models import Event, new_id
from aegis_agent.utils import event_within_window, hostname


class LoopController:
    def __init__(self, agent_config: Dict[str, Any], policy_config: Dict[str, Any], enable_enforcement: bool = False):
        self.cfg = agent_config
        agent = self.cfg.get("agent", {})
        enforcement = self.cfg.get("enforcement", {})
        self.agent_id = agent.get("id", agent.get("hostname", "unknown-agent"))
        self.max_iterations = int(agent.get("max_iterations", 3))
        self.audit = AuditLogger(agent.get("audit_db", "data/audit.db"))

        central = self.cfg.get("central", {})
        self.central = CentralClient(
            enabled=bool(central.get("enabled", False)),
            url=central.get("url", "").replace("/api/ingest", ""),
            token=central.get("token", ""),
            timeout=int(central.get("timeout_seconds", 5)),
        )
        self.policy_sync_status: Dict[str, Any] = {"enabled": False}
        self.policy = self._maybe_apply_central_policy(policy_config)
        self.policy_gate = PolicyGate(self.policy)

        ai_cfg = self.cfg.get("ai", {})
        default_ttl = int(enforcement.get("action_ttl_seconds_default", 3600))
        self.ai = AIReasoningClient(
            ai_cfg.get("provider", "rule_based"),
            ai_cfg.get("model", "local-rule-engine"),
            default_ttl,
            config=ai_cfg,
        )

        dry_run_cfg = bool(enforcement.get("dry_run", True))
        require_flag = bool(enforcement.get("require_cli_enable_flag", True))
        dry_run = dry_run_cfg or (require_flag and not enable_enforcement)
        if not dry_run and self._uses_sample_telemetry() and not bool(enforcement.get("allow_sample_data_enforcement", False)):
            raise RuntimeError(
                "Refusing real enforcement with sample_data telemetry. "
                "Use config/agent.yaml for dry-run, or point telemetry to live logs and keep allow_sample_data_enforcement=false."
            )
        self.dry_run = dry_run
        self.enforcer = LocalEnforcementLayer(
            dry_run=dry_run,
            backend=enforcement.get("prefer_backend", "nftables"),
            quarantine_dir=enforcement.get("quarantine_dir", "data/quarantine"),
            config=enforcement,
        )
        verifier_cfg = self.cfg.get("verifier", {})
        self.verifier = Verifier(verifier_cfg.get("service_health_command", ""), verifier_cfg)
        self.rollback_policy = self.cfg.get("rollback", {})
        self.rollback_executor = RollbackExecutor(dry_run=dry_run)
        state_dir = agent.get("state_dir", "data/state")
        loop_cfg = self.cfg.get("attack_loop", {})
        self.attack_loop = AttackLoopTracker(
            state_dir=loop_cfg.get("state_dir", state_dir),
            window_seconds=int(loop_cfg.get("window_seconds", 3600)),
            enabled=bool(loop_cfg.get("enabled", True)),
        )
        sp_cfg = self.cfg.get("self_protection", {})
        default_sp_paths = ["aegis_agent", "config", "VERSION", "deploy"]
        self.self_protection = SelfProtectionMonitor(
            state_dir=sp_cfg.get("state_dir", state_dir),
            enabled=bool(sp_cfg.get("enabled", True)),
            paths=sp_cfg.get("paths", default_sp_paths),
            baseline_on_first_run=bool(sp_cfg.get("baseline_on_first_run", True)),
        )
        growth_cfg = self.cfg.get("security_growth", {})
        self.security_growth = SecurityGrowthMemory(
            state_dir=growth_cfg.get("state_dir", state_dir),
            enabled=bool(growth_cfg.get("enabled", True)),
            repeat_ip_score_bonus=int(growth_cfg.get("repeat_ip_score_bonus", 15)),
            auto_learn_min_score=int(growth_cfg.get("auto_learn_min_score", 60)),
        )
        promo_cfg = self.cfg.get("policy_promotion", {})
        self.policy_promotion = PolicyPromotionEngine(
            state_dir=promo_cfg.get("state_dir", state_dir),
            enabled=bool(promo_cfg.get("enabled", True)),
            shadow_after=int(promo_cfg.get("shadow_after_observations", 2)),
            enforce_after=int(promo_cfg.get("enforce_after_observations", 3)),
            promote_after_success=int(promo_cfg.get("promote_after_successes", 3)),
        )
        self.signature_engine = SignaturePatternEngine(self.cfg.get("signature_patterns", self.cfg.get("signatures", {})))
        self.vulnerability_guard = VulnerabilityAttackGuard(self.cfg.get("vulnerability_guard", {}))
        self.loop_process_cfg = self.cfg.get("loop_process", {})
        ledger_cfg = self.cfg.get("reasoning_ledger", {})
        self.ai_quality_guard = AIReasoningQualityGuard()
        self.reasoning_ledger = AIReasoningLedger(
            path=ledger_cfg.get("path", self.cfg.get("agent", {}).get("reasoning_ledger", "data/ai_reasoning_ledger.jsonl")),
            enabled=bool(ledger_cfg.get("enabled", True)),
            max_chain_events=int(ledger_cfg.get("max_chain_events", 200)),
        )

    def _maybe_apply_central_policy(self, local_policy: Dict[str, Any]) -> Dict[str, Any]:
        central_cfg = self.cfg.get("central", {})
        sync_cfg = central_cfg.get("policy_sync", {})
        if not bool(sync_cfg.get("enabled", False)):
            return local_policy
        result = self.central.fetch_policy(self.agent_id)
        self.policy_sync_status = {"enabled": True, **result}
        remote_policy = result.get("policy")
        if result.get("ok") and isinstance(remote_policy, dict):
            # v0.2.1 accepts both raw policy documents and older wrapped {policy: {...}} payloads.
            if isinstance(remote_policy.get("policy"), dict):
                return remote_policy["policy"]
            return remote_policy
        return local_policy

    def _uses_sample_telemetry(self) -> bool:
        def flatten(value):
            if isinstance(value, dict):
                for v in value.values():
                    yield from flatten(v)
            elif isinstance(value, list):
                for v in value:
                    yield from flatten(v)
            elif value is not None:
                yield str(value)

        values = list(flatten(self.cfg.get("telemetry", {}))) + list(flatten(self.cfg.get("drone", {})))
        return any("sample_data" in v.replace("\\", "/") for v in values)

    def collect_telemetry(self):
        t = self.cfg.get("telemetry", {})
        agent = self.cfg.get("agent", {})
        realtime = t.get("realtime", {})
        state_dir = agent.get("state_dir", "data/state")
        follow = bool(realtime.get("enabled", False))
        first_run = realtime.get("tail_first_run", "full")

        events = []
        events += collect_auth_events(t.get("auth_logs", []), state_dir=state_dir, follow=follow, first_run=first_run)
        events += collect_web_events(t.get("web_logs", []) + t.get("app_logs", []), state_dir=state_dir, follow=follow, first_run=first_run)
        events += collect_auditd_events(t.get("auditd_logs", []), state_dir=state_dir, follow=follow, first_run=first_run)
        events += collect_process_snapshot(t.get("process_snapshot"))
        events += collect_network_snapshot(t.get("network_snapshot"))
        events += collect_file_events(t.get("file_events"), state_dir=state_dir, follow=follow, first_run=first_run)
        events += collect_persistence_events(t.get("persistence_events"), state_dir=state_dir, follow=follow, first_run=first_run)
        drone_cfg = self.cfg.get("drone", {})
        if drone_cfg.get("enabled", False):
            events += collect_drone_events(drone_cfg, state_dir=state_dir, follow=follow, first_run=first_run)
        fim = t.get("fim", {})
        if fim.get("enabled", False):
            events += collect_fim_events(
                fim.get("paths", t.get("scan_paths", [])),
                state_dir=fim.get("state_dir", state_dir),
                max_files=int(fim.get("max_files", 10000)),
                first_run_baseline=bool(fim.get("first_run_baseline", True)),
            )
        return self._filter_time_window(events)

    def _filter_time_window(self, events):
        t = self.cfg.get("telemetry", {})
        window = int(t.get("time_window_minutes", 0) or 0)
        if not window:
            return events
        if self._uses_sample_telemetry() and bool(t.get("ignore_time_window_for_sample_data", True)):
            return events
        return [e for e in events if event_within_window(e.timestamp, window)]

    def _self_protection_event(self, status: Dict[str, Any]) -> Event | None:
        if not status.get("enabled") or status.get("ok", True):
            return None
        return Event(
            new_id("E"),
            time.time(),
            "self_protection",
            "agent_integrity_change",
            hostname(),
            "critical",
            status.get("message", "agent integrity changed"),
            metadata=status,
        )

    def heartbeat(self, status: str = "online", extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        agent = self.cfg.get("agent", {})
        payload = {
            "hostname": agent.get("hostname") or hostname(),
            "host": hostname(),
            "version": __version__,
            "mode": agent.get("mode", "autonomous"),
            "status": status,
            "dry_run": self.dry_run,
            "policy_version": self.policy_sync_status.get("version") or self.policy.get("version") or "local",
            "policy_sync": self.policy_sync_status,
        }
        if extra:
            payload.update(extra)
        return self.central.send_heartbeat(self.agent_id, payload)

    def run_once(self) -> List[Dict[str, Any]]:
        loop = LoopProcessRecorder(enabled=bool(self.loop_process_cfg.get("enabled", True)))
        loop.add("heartbeat_start", status="ok", agent_id=self.agent_id, dry_run=self.dry_run)
        self.heartbeat(status="running")

        self_protection_status = self.self_protection.check()
        loop.add("self_protection_check", status="ok" if self_protection_status.get("ok", True) else "alert", ok=self_protection_status.get("ok", True))

        events = self.collect_telemetry()
        loop.add("collect_telemetry", status="ok", event_count=len(events))

        sp_event = self._self_protection_event(self_protection_status)
        if sp_event:
            events.append(sp_event)
            loop.add("self_protection_event_added", status="alert", event_id=sp_event.event_id)

        signature_events = self.signature_engine.evaluate(events)
        if signature_events:
            events.extend(signature_events)
        loop.add("signature_pattern_scan", status="ok", signature_event_count=len(signature_events))

        vulnerability_events = self.vulnerability_guard.evaluate(events)
        if vulnerability_events:
            events.extend(vulnerability_events)
        loop.add("vulnerability_guard_scan", status="ok", vulnerability_event_count=len(vulnerability_events))

        chains = build_evidence_chains(events)
        loop.add("build_evidence_chain", status="ok", chain_count=len(chains))

        incidents: List[Dict[str, Any]] = []
        for chain in chains:
            chain_loop_base = loop.snapshot()
            chain_phases: List[Dict[str, Any]] = []

            def cphase(phase: str, status: str = "ok", **data: Any) -> None:
                rec = {"seq": len(chain_loop_base) + len(chain_phases) + 1, "phase": phase, "status": status, "ts": time.time()}
                rec.update(data)
                chain_phases.append(rec)

            cphase("chain_selected", chain_id=chain.chain_id, score=chain.score, event_count=len(chain.events), attack_type=chain.attack_type)
            attack_loop_info = self.attack_loop.observe(chain)
            cphase("attack_loop_track", score_bonus=attack_loop_info.get("score_bonus", 0), mutation_detected=attack_loop_info.get("mutation_detected", False))
            bonus = int(attack_loop_info.get("score_bonus", 0) or 0)
            if bonus:
                chain.score = min(100, chain.score + bonus)
                chain.reasons.append(f"Attack loop repeated/mutating attempt bonus +{bonus}")
                if attack_loop_info.get("mutation_detected"):
                    chain.reasons.append("Payload or artifact mutation detected across attempts")
            security_growth_info = self.security_growth.observe_chain(chain)
            cphase("security_growth_observe", score_bonus=security_growth_info.get("score_bonus", 0), matched_ips=security_growth_info.get("matched_ips", []))
            growth_bonus = int(security_growth_info.get("score_bonus", 0) or 0)
            if growth_bonus:
                chain.score = min(100, chain.score + growth_bonus)
                chain.reasons.append(f"Previously learned hostile indicator bonus +{growth_bonus}")
            if chain.score < int(self.policy.get("policy", {}).get("thresholds", {}).get("collect_more", 30)):
                cphase("collect_more_stop", status="skipped", score=chain.score)
                continue
            analysis = self.ai.analyze(chain)
            ai_status = getattr(self.ai, "last_status", {"provider_requested": self.ai.provider, "provider_used": self.ai.provider})
            cphase("ai_reasoning", provider=ai_status.get("provider_used", self.ai.provider), provider_requested=ai_status.get("provider_requested", self.ai.provider), fallback=ai_status.get("fallback", False), confidence_score=analysis.confidence_score, recommended_actions=len(analysis.recommended_actions))
            evidence_ids = [e.event_id for e in chain.events]
            plans = build_action_plans(analysis, evidence_ids)
            cphase("plan_actions", planned_count=len(plans), actions=[p.action for p in plans])
            pre_health = self.verifier.check_health()
            cphase("pre_action_health_check", service_ok=pre_health.get("service_ok", True))
            action_results = []
            denied = []
            for plan in plans:
                decision = self.policy_gate.check(plan, chain)
                cphase("policy_gate", action=plan.action, target=plan.target, allowed=decision.allowed, reason=decision.reason)
                if not decision.allowed:
                    denied.append({"plan": plan.to_dict(), "reason": decision.reason})
                    continue
                result = self.enforcer.execute(plan)
                cphase("local_enforcement", action=plan.action, target=plan.target, result=result.status, dry_run=result.dry_run)
                action_results.append(result)
            ai_quality = self.ai_quality_guard.evaluate(analysis.to_dict(), evidence_ids, denied)
            cphase("ai_quality_guard", status="ok" if ai_quality.get("ok") else "warning", quality_score=ai_quality.get("quality_score"), issue_count=ai_quality.get("issue_count", 0))
            verification = self.verifier.verify_actions(action_results, pre_health)
            cphase("verify_actions", service_ok=verification.get("service_ok", True), action_count=len(action_results))
            action_dicts = [r.to_dict() for r in action_results]
            auto_rollback = self._auto_rollback_if_needed(verification, action_dicts)
            if auto_rollback:
                verification["auto_rollback"] = auto_rollback
                cphase("auto_rollback", status="executed", rolled_back_count=auto_rollback.get("rolled_back_count", 0))
            incident = {
                "incident_id": new_id("INC"),
                "agent_id": self.agent_id,
                "host": chain.host,
                "chain": chain.to_dict(),
                "analysis": analysis.to_dict(),
                "score": chain.score,
                "confidence": chain.confidence,
                "attack_type": chain.attack_type,
                "hypothesis": chain.hypothesis,
                "attack_loop": attack_loop_info,
                "security_growth": security_growth_info,
                "self_protection": self_protection_status,
                "policy_sync": self.policy_sync_status,
                "ai_provider": ai_status.get("provider_used", self.ai.provider),
                "ai_status": ai_status,
                "actions": action_dicts,
                "denied_actions": denied,
                "ai_quality": ai_quality,
                "verification": verification,
                "loop_process": chain_loop_base + chain_phases,
            }
            promotion = self.policy_promotion.observe_incident(incident, verification)
            promotion_sync = self._sync_policy_promotion_candidates(promotion)
            cphase("policy_promotion", promotions=promotion.get("promotions", []), enabled=promotion.get("enabled", False), central_sync=promotion_sync)
            incident["policy_promotion"] = promotion
            incident["policy_promotion_central_sync"] = promotion_sync
            growth_learn = self.security_growth.learn_from_incident(incident)
            cphase("security_growth_learn", learned=growth_learn.get("learned", []))
            incident["security_growth_learning"] = growth_learn
            cphase("ai_reasoning_ledger", status="pending")
            incident["loop_process"] = chain_loop_base + chain_phases
            ledger_status = self.reasoning_ledger.append_incident(incident)
            chain_phases[-1].update({"status": "ok" if ledger_status.get("enabled") else "disabled", "path": ledger_status.get("path")})
            incident["reasoning_ledger"] = ledger_status
            incident["loop_process"] = chain_loop_base + chain_phases
            self.audit.save_incident(incident)
            for r in action_dicts:
                self.audit.save_action(incident["incident_id"], r)
            incidents.append(incident)
        central_result = self.central.send_incidents(self.agent_id, incidents)
        for incident in incidents:
            incident["central_sync"] = central_result
        self.heartbeat(status="online", extra={"last_incident_count": len(incidents)})
        return incidents

    def _sync_policy_promotion_candidates(self, promotion: Dict[str, Any]) -> Dict[str, Any]:
        """Send promoted IOC and shadow-policy approval candidates to Central, if enabled.

        This never changes local active policy directly. Central stores IOC candidates and
        pending approval requests so an operator can approve active policy changes.
        """
        if not getattr(self.central, "enabled", False):
            return {"enabled": False, "reason": "central_disabled"}
        results: List[Dict[str, Any]] = []
        for item in promotion.get("promotions", []) or []:
            if item.get("stage") != "promoted":
                continue
            ioc = item.get("ioc_candidate")
            if isinstance(ioc, dict) and ioc.get("indicator"):
                payload = {**ioc, "source": ioc.get("source") or "aegis_policy_promotion", "candidate_key": item.get("key")}
                res = self.central.create_ioc(payload)
                results.append({"type": "ioc_candidate", "indicator": ioc.get("indicator"), "result": res})
            approval = item.get("approval_request")
            if isinstance(approval, dict):
                payload = {
                    "agent_id": self.agent_id,
                    "requested_action": "promote_shadow_policy",
                    "status": "pending",
                    "risk": "controlled_policy_mutation",
                    **approval,
                }
                res = self.central.create_approval(payload)
                results.append({"type": "policy_promotion_approval", "candidate_key": item.get("key"), "result": res})
        return {"enabled": True, "results": results}

    def _auto_rollback_if_needed(self, verification: Dict[str, Any], action_dicts: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        if not bool(self.rollback_policy.get("auto_on_health_failure", True)):
            return None
        if verification.get("service_ok", True):
            return None
        results = []
        for action in action_dicts:
            if action.get("status") != "success":
                continue
            rb = self.rollback_executor.execute(action)
            action["rollback_result"] = rb
            if rb.get("rollback_status") == "success":
                action["status"] = "rolled_back"
            results.append(rb)
        return {"trigger": "health_check_failed", "rolled_back_count": sum(1 for r in results if r.get("rollback_status") == "success"), "results": results}
