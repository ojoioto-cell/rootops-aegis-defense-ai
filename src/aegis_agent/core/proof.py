from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from aegis_agent.core.audit import AuditLogger
from aegis_agent.core.reasoning_ledger import AIReasoningLedger
from aegis_agent.core.live_battle_evidence import LiveBattleEvidenceEngine
from aegis_agent.utils import ensure_dir


def _safe_table(rows: List[List[Any]]) -> str:
    if not rows:
        return ""
    out = []
    out.append("| " + " | ".join(str(x) for x in rows[0]) + " |")
    out.append("|" + "|".join("---" for _ in rows[0]) + "|")
    for r in rows[1:]:
        out.append("| " + " | ".join(str(x).replace("\n", " ") for x in r) + " |")
    return "\n".join(out)


def _count_elements(nft_output: str) -> int:
    if "elements" not in nft_output:
        return 0
    start = nft_output.find("{")
    end = nft_output.rfind("}")
    if start < 0 or end <= start:
        return 0
    body = nft_output[start + 1:end]
    # nft set elements are comma separated, e.g. { 1.2.3.4 timeout 1h, 5.6.7.8 }
    chunks = [x.strip() for x in body.split(",") if x.strip()]
    # Ignore table/set headers if a list-ruleset fragment is passed accidentally.
    return len([c for c in chunks if not c.startswith("type ") and not c.startswith("flags ")])


class ProofReportGenerator:
    """Generate a competition-ready proof report from audit DB and reasoning ledger.

    v0.2.12 splits compact summary and full evidence. It also records whether
    nftables proof could be collected from the current host, so AI-duel proof and
    real kernel blocking proof can be distinguished in reports.
    """

    def __init__(
        self,
        audit_db: str,
        ledger_path: str | None = None,
        *,
        nft_family: str = "inet",
        nft_table: str = "aegis_guard",
        include_nftables: bool = True,
    ):
        self.audit = AuditLogger(audit_db)
        self.ledger = AIReasoningLedger(ledger_path, enabled=False) if ledger_path else None
        if self.ledger and ledger_path:
            self.ledger.path = Path(ledger_path)
        self.nft_family = nft_family or "inet"
        self.nft_table = nft_table or "aegis_guard"
        self.include_nftables = include_nftables

    def _run_nft(self, args: list[str]) -> dict[str, Any]:
        if not shutil.which("nft"):
            return {"ok": False, "available": False, "command": ["nft", *args], "error": "nft_not_installed", "stdout": "", "stderr": ""}
        try:
            proc = subprocess.run(["nft", *args], text=True, capture_output=True, timeout=5, check=False)
            return {
                "ok": proc.returncode == 0,
                "available": True,
                "command": ["nft", *args],
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except Exception as exc:
            return {"ok": False, "available": True, "command": ["nft", *args], "error": str(exc), "stdout": "", "stderr": ""}

    def collect_nftables_proof(self) -> Dict[str, Any]:
        if not self.include_nftables:
            return {"enabled": False, "available": False, "message": "nftables proof disabled"}
        proof: dict[str, Any] = {
            "enabled": True,
            "family": self.nft_family,
            "table": self.nft_table,
            "available": bool(shutil.which("nft")),
            "sets": {},
        }
        table = self._run_nft(["list", "table", self.nft_family, self.nft_table])
        proof["table_check"] = {k: v for k, v in table.items() if k not in {"stdout"}}
        proof["table_exists"] = bool(table.get("ok"))
        if table.get("ok"):
            proof["table_excerpt"] = "\n".join((table.get("stdout") or "").splitlines()[:80])
        for set_name in ["block_in_v4", "rate_limit_v4", "block_out_v4", "block_in_v6", "rate_limit_v6", "block_out_v6"]:
            res = self._run_nft(["list", "set", self.nft_family, self.nft_table, set_name])
            proof["sets"][set_name] = {
                "ok": bool(res.get("ok")),
                "available": bool(res.get("available")),
                "element_count": _count_elements(res.get("stdout") or "") if res.get("ok") else 0,
                "error": res.get("error") or res.get("stderr", ""),
                "stdout_excerpt": "\n".join((res.get("stdout") or "").splitlines()[:40]),
            }
        proof["real_blocking_proof"] = bool(proof.get("table_exists"))
        return proof

    def build_full_summary(self, limit: int = 200) -> Dict[str, Any]:
        incidents = self.audit.list_incidents(limit)
        actions = self.audit.list_actions(limit)
        action_counts = Counter(a.get("action") for a in actions)
        action_status = Counter(a.get("status") for a in actions)
        attack_types = Counter(i.get("attack_type") for i in incidents)
        ai_modes = Counter((i.get("ai_status") or {}).get("provider_used") or i.get("ai_provider") or "unknown" for i in incidents)
        ai_fallback_count = sum(1 for i in incidents if bool((i.get("ai_status") or {}).get("fallback")))
        policy_stages = Counter()
        ioc_candidates: List[Dict[str, Any]] = []
        shadow_policies: List[Dict[str, Any]] = []
        ttl_recommendations: Dict[str, int] = {}
        approval_pending_count = 0
        for i in incidents:
            for promo in ((i.get("policy_promotion") or {}).get("promotions") or []):
                stage = promo.get("stage", "candidate")
                policy_stages[stage] += 1
                if promo.get("ioc_candidate"):
                    ioc_candidates.append(promo.get("ioc_candidate"))
                if promo.get("shadow_policy"):
                    shadow_policies.append(promo.get("shadow_policy"))
                if promo.get("active_policy_status") == "pending_operator_approval":
                    approval_pending_count += 1
                action = str(promo.get("action") or "unknown")
                ttl = int(promo.get("recommended_ttl_seconds") or 0)
                if ttl:
                    ttl_recommendations[action] = max(ttl_recommendations.get(action, 0), ttl)
        blocked_targets = sorted({str(a.get("target")) for a in actions if a.get("action") in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"} and a.get("target")})
        rolled_back = [a for a in actions if str(a.get("status", "")).startswith("rolled") or a.get("rollback_result")]
        success_actions = [a for a in actions if a.get("status") == "success"]
        enforcement_success_rate = round((len(success_actions) / len(actions)) * 100, 2) if actions else 0.0
        ledger_rows = []
        if self.ledger:
            ledger_rows = self.ledger.read_recent(limit)
        battle_score = LiveBattleEvidenceEngine(str(self.audit.db_path), str(self.ledger.path) if self.ledger else None, self.nft_family, self.nft_table).compute(limit)
        return {
            "generated_at": int(time.time()),
            "incident_count": len(incidents),
            "action_count": len(actions),
            "attack_types": dict(attack_types),
            "action_counts": dict(action_counts),
            "action_status": dict(action_status),
            "ai_modes": dict(ai_modes),
            "ai_fallback_count": ai_fallback_count,
            "policy_promotion_stages": dict(policy_stages),
            "policy_promotion_ioc_candidate_count": len(ioc_candidates),
            "policy_promotion_shadow_policy_count": len(shadow_policies),
            "policy_promotion_approval_pending_count": approval_pending_count,
            "ttl_recommendations": ttl_recommendations,
            "ioc_candidates": ioc_candidates[:50],
            "shadow_policies": shadow_policies[:20],
            "blocked_targets": blocked_targets,
            "rollback_count": len(rolled_back),
            "enforcement_success_rate": enforcement_success_rate,
            "ledger_count": len(ledger_rows),
            "recent_incidents": incidents[:20],
            "recent_actions": actions[:50],
            "recent_ledger": ledger_rows[-20:],
            "nftables_proof": self.collect_nftables_proof(),
            "live_battle_evidence": battle_score,
            "live_battle_score": battle_score,  # backward-compatible alias
        }

    def build_summary(self, limit: int = 200) -> Dict[str, Any]:
        full = self.build_full_summary(limit)
        # Compact summary suitable for report attachments and quick review.
        return {
            "generated_at": full["generated_at"],
            "incident_count": full["incident_count"],
            "action_count": full["action_count"],
            "attack_types": full["attack_types"],
            "action_counts": full["action_counts"],
            "action_status": full["action_status"],
            "ai_modes": full.get("ai_modes", {}),
            "ai_fallback_count": full.get("ai_fallback_count", 0),
            "policy_promotion_stages": full.get("policy_promotion_stages", {}),
            "policy_promotion_ioc_candidate_count": full.get("policy_promotion_ioc_candidate_count", 0),
            "policy_promotion_shadow_policy_count": full.get("policy_promotion_shadow_policy_count", 0),
            "policy_promotion_approval_pending_count": full.get("policy_promotion_approval_pending_count", 0),
            "ttl_recommendations": full.get("ttl_recommendations", {}),
            "blocked_targets": full["blocked_targets"],
            "rollback_count": full["rollback_count"],
            "enforcement_success_rate": full.get("enforcement_success_rate", 0.0),
            "ledger_count": full["ledger_count"],
            "live_battle_evidence": full.get("live_battle_evidence", full.get("live_battle_score", {})),
            "nftables_proof": {
                "available": full.get("nftables_proof", {}).get("available", False),
                "table_exists": full.get("nftables_proof", {}).get("table_exists", False),
                "real_blocking_proof": full.get("nftables_proof", {}).get("real_blocking_proof", False),
                "sets": {k: {"ok": v.get("ok"), "element_count": v.get("element_count", 0)} for k, v in full.get("nftables_proof", {}).get("sets", {}).items()},
            },
        }

    def write(self, output_dir: str, title: str = "Aegis Competition Proof Report") -> Dict[str, Any]:
        out = Path(output_dir)
        ensure_dir(out)
        full_summary = self.build_full_summary()
        compact_summary = {
            "generated_at": full_summary["generated_at"],
            "incident_count": full_summary["incident_count"],
            "action_count": full_summary["action_count"],
            "attack_types": full_summary["attack_types"],
            "action_counts": full_summary["action_counts"],
            "action_status": full_summary["action_status"],
            "ai_modes": full_summary.get("ai_modes", {}),
            "ai_fallback_count": full_summary.get("ai_fallback_count", 0),
            "policy_promotion_stages": full_summary.get("policy_promotion_stages", {}),
            "policy_promotion_ioc_candidate_count": full_summary.get("policy_promotion_ioc_candidate_count", 0),
            "policy_promotion_shadow_policy_count": full_summary.get("policy_promotion_shadow_policy_count", 0),
            "policy_promotion_approval_pending_count": full_summary.get("policy_promotion_approval_pending_count", 0),
            "ttl_recommendations": full_summary.get("ttl_recommendations", {}),
            "blocked_targets": full_summary["blocked_targets"],
            "rollback_count": full_summary["rollback_count"],
            "enforcement_success_rate": full_summary.get("enforcement_success_rate", 0.0),
            "ledger_count": full_summary["ledger_count"],
            "live_battle_evidence": full_summary.get("live_battle_evidence", full_summary.get("live_battle_score", {})),
            "nftables_proof": {
                "available": full_summary.get("nftables_proof", {}).get("available", False),
                "table_exists": full_summary.get("nftables_proof", {}).get("table_exists", False),
                "real_blocking_proof": full_summary.get("nftables_proof", {}).get("real_blocking_proof", False),
                "sets": {k: {"ok": v.get("ok"), "element_count": v.get("element_count", 0)} for k, v in full_summary.get("nftables_proof", {}).get("sets", {}).items()},
            },
        }

        (out / "proof_summary.json").write_text(json.dumps(compact_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        (out / "proof_evidence_full.json").write_text(json.dumps(full_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            (out / "proof_summary.json").chmod(0o600)
            (out / "proof_evidence_full.json").chmod(0o600)
        except OSError:
            pass

        nft = full_summary.get("nftables_proof", {})
        if nft.get("table_excerpt"):
            (out / "proof_nftables_state.txt").write_text(str(nft.get("table_excerpt", "")), encoding="utf-8")

        md = []
        md.append(f"# {title}\n")
        md.append("## Executive Summary\n")
        md.append(_safe_table([
            ["Metric", "Value"],
            ["Incidents", full_summary["incident_count"]],
            ["Actions", full_summary["action_count"]],
            ["Rollback records", full_summary["rollback_count"]],
            ["Enforcement success rate", str(full_summary.get("enforcement_success_rate", 0.0)) + "%"],
            ["AI reasoning ledger rows", full_summary["ledger_count"]],
            ["AI provider modes", json.dumps(full_summary.get("ai_modes", {}), ensure_ascii=False)],
            ["AI fallback count", full_summary.get("ai_fallback_count", 0)],
            ["Policy promotion stages", json.dumps(full_summary.get("policy_promotion_stages", {}), ensure_ascii=False)],
            ["Promotion IOC candidates", full_summary.get("policy_promotion_ioc_candidate_count", 0)],
            ["Shadow policies", full_summary.get("policy_promotion_shadow_policy_count", 0)],
            ["Approval-pending promotions", full_summary.get("policy_promotion_approval_pending_count", 0)],
            ["TTL recommendations", json.dumps(full_summary.get("ttl_recommendations", {}), ensure_ascii=False)],
            ["nftables available", nft.get("available", False)],
            ["aegis_guard table exists", nft.get("table_exists", False)],
        ]))
        battle = full_summary.get("live_battle_evidence", full_summary.get("live_battle_score", {}))
        bm = battle.get("battle_metrics", {})
        aq = battle.get("ai_quality", {})
        md.append("\n\n## Live Battle Evidence and AI Quality\n")
        md.append(_safe_table([
            ["Metric", "Value"],
            ["Championship grade", battle.get("championship_grade", "N/A")],
            ["AI mode status", battle.get("ai_mode_status", "N/A")],
            ["Detection rate", str(bm.get("detection_rate", 0.0)) + "%"],
            ["Enforcement success rate", str(bm.get("enforcement_success_rate", 0.0)) + "%"],
            ["Rollback rate", str(bm.get("rollback_rate", 0.0)) + "%"],
            ["Mean response time", str(bm.get("mean_response_time_seconds", 0.0)) + "s"],
            ["AI quality score", aq.get("quality_score", 0)],
            ["Service health failures", bm.get("service_health_failures", 0)],
        ]))

        md.append("\n\n## Attack Type Distribution\n")
        md.append(_safe_table([["Attack type", "Count"], *full_summary["attack_types"].items()]) or "No incidents recorded.")
        md.append("\n\n## Defensive Actions\n")
        md.append(_safe_table([["Action", "Count"], *full_summary["action_counts"].items()]) or "No actions recorded.")
        md.append("\n\n## Action Status\n")
        md.append(_safe_table([["Status", "Count"], *full_summary["action_status"].items()]) or "No action status recorded.")
        md.append("\n\n## Blocked / Limited Targets\n")
        if full_summary["blocked_targets"]:
            md.extend([f"- `{t}`" for t in full_summary["blocked_targets"]])
        else:
            md.append("No blocked targets recorded.")

        md.append("\n\n## Synthetic AI Duel Proof vs. Real Enforcement Proof\n")
        md.append("Live Battle Evidence is based on actual runtime incidents, actions, AI reasoning ledger rows and nftables state. Synthetic AI Duel proof remains optional for rehearsal, but 본선 운영 판단은 live evidence and real enforcement proof를 기준으로 합니다.\n")
        md.append(_safe_table([
            ["Proof Layer", "Evidence", "Meaning"],
            ["Synthetic AI Duel", "AI reasoning ledger + incidents/actions", "Shows the autonomous defense loop against simulated AI attack behavior"],
            ["Real Enforcement", "nftables table/set state + add/delete validation", "Shows that the host can actually enforce and roll back network blocking"],
        ]))

        md.append("\n\n## AI Provider and Fallback Status\n")
        md.append(_safe_table([
            ["Metric", "Value"],
            ["AI provider modes", json.dumps(full_summary.get("ai_modes", {}), ensure_ascii=False)],
            ["AI fallback count", full_summary.get("ai_fallback_count", 0)],
            ["Expected priority", "GPT API -> local Ollama/Llama -> rule_based fallback"],
        ]))

        md.append("\n\n## Policy Promotion and Autonomous Growth\n")
        md.append(_safe_table([
            ["Metric", "Value"],
            ["Stages", json.dumps(full_summary.get("policy_promotion_stages", {}), ensure_ascii=False)],
            ["IOC candidates", full_summary.get("policy_promotion_ioc_candidate_count", 0)],
            ["Shadow policies", full_summary.get("policy_promotion_shadow_policy_count", 0)],
            ["Approval-pending active policies", full_summary.get("policy_promotion_approval_pending_count", 0)],
            ["TTL recommendations", json.dumps(full_summary.get("ttl_recommendations", {}), ensure_ascii=False)],
        ]))

        md.append("\n\n## nftables Blocking Proof\n")
        if nft.get("available"):
            rows = [["Set", "Exists", "Elements"]]
            for name, data in nft.get("sets", {}).items():
                rows.append([name, data.get("ok", False), data.get("element_count", 0)])
            md.append(_safe_table(rows))
            if nft.get("table_exists"):
                md.append("\n`inet aegis_guard` table was visible to the proof generator. See `proof_nftables_state.txt` for a ruleset excerpt when available.")
            else:
                md.append("\n`nft` is installed, but `inet aegis_guard` was not visible at report generation time.")
        else:
            md.append("nftables proof unavailable on this host. Run `post_install_competition_check.sh` on the competition VM for real kernel add/delete validation.")

        md.append("\n\n## Defense Loop Architecture\n")
        md.append("```mermaid\nflowchart TD\n  A[Collect telemetry] --> B[Signature and Vulnerability scan]\n  B --> C[Evidence Chain]\n  C --> D[AI/Rule Reasoning]\n  D --> E[Policy Gate]\n  E --> F[Local Enforcement]\n  F --> G[Verifier]\n  G --> H[Rollback or TTL expiry]\n  G --> I[Security Growth Memory]\n```\n")

        md.append("\n## Recent Incidents\n")
        rows = [["Incident", "Attack type", "Score", "Confidence", "Actions"]]
        for inc in full_summary["recent_incidents"][:10]:
            rows.append([
                inc.get("incident_id", ""),
                inc.get("attack_type", ""),
                inc.get("score", ""),
                inc.get("confidence", ""),
                ", ".join(a.get("action", "") for a in inc.get("actions", []) or []),
            ])
        md.append(_safe_table(rows) if len(rows) > 1 else "No incidents recorded.")

        md.append("\n\n## Recent AI Reasoning Ledger Rows\n")
        rows = [["Incident", "Provider", "Attack type", "Score", "Recommended actions"]]
        for rec in full_summary["recent_ledger"][-10:]:
            analysis = rec.get("analysis") or {}
            rows.append([
                rec.get("incident_id", ""),
                rec.get("ai_provider", ""),
                analysis.get("attack_type", rec.get("attack_type", "")),
                analysis.get("confidence_score", rec.get("score", "")),
                ", ".join(a.get("action", "") for a in analysis.get("recommended_actions", []) or []),
            ])
        md.append(_safe_table(rows) if len(rows) > 1 else "No AI reasoning ledger rows recorded.")

        md.append("\n\n## Defensive Safety Boundary\n")
        md.append("Aegis does not generate exploit code, does not send drone control commands, and does not allow LLMs to execute shell commands. All defensive actions must pass Policy Gate and remain rollback/TTL controlled.\n")

        (out / "proof_report.md").write_text("\n".join(md), encoding="utf-8")
        return {
            "ok": True,
            "output_dir": str(out),
            "files": [
                str(out / "proof_report.md"),
                str(out / "proof_summary.json"),
                str(out / "proof_evidence_full.json"),
            ] + ([str(out / "proof_nftables_state.txt")] if (out / "proof_nftables_state.txt").exists() else []),
        }
