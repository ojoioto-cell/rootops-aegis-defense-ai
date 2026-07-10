from __future__ import annotations

import ipaddress
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

from aegis_agent.models import ActionPlan, ActionResult
from aegis_agent.utils import is_root, run_command, validate_enforcement_ip


class NetworkGuard:
    """Local network enforcement for host-based autonomous defense.

    v0.1.2 implements real blocking with safety rails:
    - nftables backend uses a dedicated inet table and timeout sets.
    - iptables/ip6tables backend inserts reversible rules with comments.
    - memory backend is useful for tests and isolated demos only.
    """

    def __init__(self, dry_run: bool = True, backend: str = "nftables", config: Optional[Dict[str, Any]] = None):
        self.dry_run = dry_run
        self.backend = backend
        self.config = config or {}
        self.nft_table = self.config.get("nft_table", "aegis_guard")
        self.nft_family = self.config.get("nft_family", "inet")
        self.rate_limit = self.config.get("rate_limit", {}) or {}
        self.rate_limit_per_second = int(self.rate_limit.get("tcp_syn_per_second", 20))
        self.rate_limit_burst = int(self.rate_limit.get("burst", 40))
        self.require_root = bool(self.config.get("require_root", True))

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.action == "block_ip_ttl":
            return self.block_ip_ttl(plan, direction="inbound")
        if plan.action == "block_outbound_ip":
            return self.block_ip_ttl(plan, direction="outbound")
        if plan.action == "rate_limit_ip":
            return self.rate_limit_ip(plan)
        return ActionResult(plan.action_id, plan.action, plan.target, "skipped", self.dry_run, f"Unsupported network action {plan.action}")

    def block_ip_ttl(self, plan: ActionPlan, direction: str) -> ActionResult:
        valid, version_or_error = self._validate_ip(plan.target)
        if not valid:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", self.dry_run, version_or_error, error="invalid_ip")

        ttl = self._ttl(plan)
        expires_at = int(time.time()) + ttl
        rollback = self._rollback_payload(plan, direction, version_or_error, ttl, expires_at, mode="block")

        if self.dry_run:
            commands = self._build_block_commands(plan.target, direction, version_or_error, plan.action_id, ttl, include_ensure=True)
            return ActionResult(plan.action_id, plan.action, plan.target, "planned", True, "Dry-run: firewall block not applied", rollback, commands[-1] if commands else [])

        guard = self._preflight()
        if guard:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, guard, rollback, error="preflight_failed")

        if self.backend == "nftables":
            ok, ensure_msg = self._ensure_nftables_actual()
            if not ok:
                return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, ensure_msg, rollback, error="nftables_setup_failed")
        commands = self._build_block_commands(plan.target, direction, version_or_error, plan.action_id, ttl, include_ensure=False)
        if not commands:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, "No supported firewall backend found", rollback, error="backend_not_found")

        ok, message, failed_cmd, err = self._run_commands(commands)
        status = "success" if ok else "failed"
        return ActionResult(plan.action_id, plan.action, plan.target, status, False, message, rollback, failed_cmd or commands[-1], None if ok else err)

    def rate_limit_ip(self, plan: ActionPlan) -> ActionResult:
        valid, version_or_error = self._validate_ip(plan.target)
        if not valid:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", self.dry_run, version_or_error, error="invalid_ip")

        ttl = self._ttl(plan)
        expires_at = int(time.time()) + ttl
        rollback = self._rollback_payload(plan, "inbound", version_or_error, ttl, expires_at, mode="rate_limit")

        if self.dry_run:
            commands = self._build_rate_limit_commands(plan.target, version_or_error, plan.action_id, ttl, include_ensure=True)
            return ActionResult(plan.action_id, plan.action, plan.target, "planned", True, "Dry-run: TCP SYN rate limit not applied", rollback, commands[-1] if commands else [])

        guard = self._preflight()
        if guard:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, guard, rollback, error="preflight_failed")

        if self.backend == "nftables":
            ok, ensure_msg = self._ensure_nftables_actual()
            if not ok:
                return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, ensure_msg, rollback, error="nftables_setup_failed")
        commands = self._build_rate_limit_commands(plan.target, version_or_error, plan.action_id, ttl, include_ensure=False)
        if not commands:
            return ActionResult(plan.action_id, plan.action, plan.target, "failed", False, "No supported rate-limit backend found", rollback, error="backend_not_found")

        ok, message, failed_cmd, err = self._run_commands(commands)
        status = "success" if ok else "failed"
        return ActionResult(plan.action_id, plan.action, plan.target, status, False, message, rollback, failed_cmd or commands[-1], None if ok else err)

    def _preflight(self) -> str:
        if self.backend == "memory":
            return ""
        if self.require_root and not is_root():
            return "Real network enforcement requires root privileges. Re-run with sudo or keep dry_run=true."
        if self.backend == "nftables" and not shutil.which("nft"):
            return "nft executable not found"
        if self.backend == "iptables" and not (shutil.which("iptables") or shutil.which("ip6tables")):
            return "iptables/ip6tables executable not found"
        return ""

    @staticmethod
    def _validate_ip(ip: str) -> Tuple[bool, str]:
        ok, detail = validate_enforcement_ip(ip)
        if not ok:
            return False, f"Unsafe or invalid firewall target: {detail}"
        return True, detail

    @staticmethod
    def _ttl(plan: ActionPlan) -> int:
        try:
            ttl = int(plan.ttl_seconds or 3600)
        except Exception:
            ttl = 3600
        return max(60, min(ttl, 604800))

    def _set_name(self, direction: str, version: str, mode: str) -> str:
        if mode == "rate_limit":
            return f"rate_limit_{version}"
        return f"block_{'in' if direction == 'inbound' else 'out'}_{version}"

    def _chain_name(self, direction: str) -> str:
        return "input" if direction == "inbound" else "output"

    def _nft_set_type(self, version: str) -> str:
        return "ipv6_addr" if version == "v6" else "ipv4_addr"

    def _nft_ip_keyword(self, version: str) -> str:
        return "ip6" if version == "v6" else "ip"

    def _nft_direction_field(self, direction: str) -> str:
        return "saddr" if direction == "inbound" else "daddr"

    def _build_block_commands(self, ip: str, direction: str, version: str, action_id: str, ttl: int, include_ensure: bool = False) -> List[List[str]]:
        if self.backend == "memory":
            return [["memory-backend", "block", direction, ip, str(ttl)]]
        if self.backend == "nftables":
            set_name = self._set_name(direction, version, "block")
            cmds = self._build_nft_ensure_commands() if include_ensure else []
            cmds.append(["nft", "add", "element", self.nft_family, self.nft_table, set_name, "{", ip, "timeout", f"{ttl}s", "}"])
            return cmds
        if self.backend == "iptables":
            tool = "ip6tables" if version == "v6" else "iptables"
            if not shutil.which(tool):
                return []
            chain = "INPUT" if direction == "inbound" else "OUTPUT"
            flag = "-s" if direction == "inbound" else "-d"
            comment = self._iptables_comment(action_id, ttl)
            return [[tool, "-I", chain, flag, ip, "-m", "comment", "--comment", comment, "-j", "DROP"]]
        return []

    def _build_rate_limit_commands(self, ip: str, version: str, action_id: str, ttl: int, include_ensure: bool = False) -> List[List[str]]:
        if self.backend == "memory":
            return [["memory-backend", "rate-limit", ip, str(ttl), str(self.rate_limit_per_second)]]
        if self.backend == "nftables":
            set_name = self._set_name("inbound", version, "rate_limit")
            cmds = self._build_nft_ensure_commands() if include_ensure else []
            cmds.append(["nft", "add", "element", self.nft_family, self.nft_table, set_name, "{", ip, "timeout", f"{ttl}s", "}"])
            return cmds
        if self.backend == "iptables":
            tool = "ip6tables" if version == "v6" else "iptables"
            if not shutil.which(tool):
                return []
            name = f"aegis_{action_id[-8:]}"
            comment = self._iptables_comment(action_id, ttl)
            return [[
                tool, "-I", "INPUT", "-s", ip, "-p", "tcp", "--syn",
                "-m", "hashlimit",
                "--hashlimit-above", f"{self.rate_limit_per_second}/second",
                "--hashlimit-burst", str(self.rate_limit_burst),
                "--hashlimit-mode", "srcip",
                "--hashlimit-name", name,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ]]
        return []

    def _ensure_nftables_actual(self) -> Tuple[bool, str]:
        """Create the dedicated nftables table/chains/sets/rules once.

        This method checks before adding rules to avoid duplicate drop/rate-limit rules.
        """
        setup_cmds = [
            (["nft", "list", "table", self.nft_family, self.nft_table], ["nft", "add", "table", self.nft_family, self.nft_table]),
            (["nft", "list", "chain", self.nft_family, self.nft_table, "input"], ["nft", "add", "chain", self.nft_family, self.nft_table, "input", "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"]),
            (["nft", "list", "chain", self.nft_family, self.nft_table, "output"], ["nft", "add", "chain", self.nft_family, self.nft_table, "output", "{", "type", "filter", "hook", "output", "priority", "-10", ";", "policy", "accept", ";", "}"]),
        ]
        for check_cmd, add_cmd in setup_cmds:
            rc, _, _ = run_command(check_cmd, timeout=10)
            if rc != 0:
                rc2, out2, err2 = run_command(add_cmd, timeout=10)
                if rc2 != 0 and "file exists" not in (err2 or out2).lower():
                    return False, err2 or out2 or f"Failed: {' '.join(add_cmd)}"

        for version in ("v4", "v6"):
            set_type = self._nft_set_type(version)
            for set_name in (f"block_in_{version}", f"block_out_{version}", f"rate_limit_{version}"):
                check = ["nft", "list", "set", self.nft_family, self.nft_table, set_name]
                add = ["nft", "add", "set", self.nft_family, self.nft_table, set_name, "{", "type", set_type, ";", "flags", "timeout", ";", "}"]
                rc, _, _ = run_command(check, timeout=10)
                if rc != 0:
                    rc2, out2, err2 = run_command(add, timeout=10)
                    if rc2 != 0 and "file exists" not in (err2 or out2).lower():
                        return False, err2 or out2 or f"Failed: {' '.join(add)}"

        for version in ("v4", "v6"):
            ip_kw = self._nft_ip_keyword(version)
            rules = [
                ("input", f"aegis_block_in_{version}", ["nft", "add", "rule", self.nft_family, self.nft_table, "input", ip_kw, "saddr", f"@block_in_{version}", "counter", "drop", "comment", f"aegis_block_in_{version}"]),
                ("output", f"aegis_block_out_{version}", ["nft", "add", "rule", self.nft_family, self.nft_table, "output", ip_kw, "daddr", f"@block_out_{version}", "counter", "drop", "comment", f"aegis_block_out_{version}"]),
                ("input", f"aegis_rate_limit_{version}", ["nft", "add", "rule", self.nft_family, self.nft_table, "input", ip_kw, "saddr", f"@rate_limit_{version}", "tcp", "flags", "syn", "limit", "rate", "over", f"{self.rate_limit_per_second}/second", "counter", "drop", "comment", f"aegis_rate_limit_{version}"]),
            ]
            for chain, marker, add in rules:
                rc, out, err = run_command(["nft", "list", "chain", self.nft_family, self.nft_table, chain], timeout=10)
                if rc != 0:
                    return False, err or out or f"Failed to inspect chain {chain}"
                if marker not in out:
                    rc2, out2, err2 = run_command(add, timeout=10)
                    if rc2 != 0:
                        return False, err2 or out2 or f"Failed: {' '.join(add)}"
        return True, "nftables guard objects ready"

    def _build_nft_ensure_commands(self) -> List[List[str]]:
        table = ["nft", "add", "table", self.nft_family, self.nft_table]
        input_chain = ["nft", "add", "chain", self.nft_family, self.nft_table, "input", "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"]
        output_chain = ["nft", "add", "chain", self.nft_family, self.nft_table, "output", "{", "type", "filter", "hook", "output", "priority", "-10", ";", "policy", "accept", ";", "}"]
        cmds = [table, input_chain, output_chain]
        for version in ("v4", "v6"):
            set_type = self._nft_set_type(version)
            for set_name in (f"block_in_{version}", f"block_out_{version}", f"rate_limit_{version}"):
                cmds.append(["nft", "add", "set", self.nft_family, self.nft_table, set_name, "{", "type", set_type, ";", "flags", "timeout", ";", "}"])
        # Drop rules for timeout sets.
        for version in ("v4", "v6"):
            ip_kw = self._nft_ip_keyword(version)
            cmds.append(["nft", "add", "rule", self.nft_family, self.nft_table, "input", ip_kw, "saddr", f"@block_in_{version}", "counter", "drop", "comment", f"aegis_block_in_{version}"])
            cmds.append(["nft", "add", "rule", self.nft_family, self.nft_table, "output", ip_kw, "daddr", f"@block_out_{version}", "counter", "drop", "comment", f"aegis_block_out_{version}"])
            cmds.append([
                "nft", "add", "rule", self.nft_family, self.nft_table, "input",
                ip_kw, "saddr", f"@rate_limit_{version}", "tcp", "flags", "syn",
                "limit", "rate", "over", f"{self.rate_limit_per_second}/second", "counter", "drop",
                "comment", f"aegis_rate_limit_{version}",
            ])
        return cmds

    def _run_commands(self, commands: List[List[str]]) -> Tuple[bool, str, List[str], str]:
        if self.backend == "memory":
            return True, "Memory backend accepted action; no OS firewall change applied", [], ""
        for cmd in commands:
            rc, out, err = run_command(cmd, timeout=10)
            if rc == 0:
                continue
            # nft add table/chain/set/rule may return "File exists" on repeat executions. Treat ensure steps as idempotent.
            err_l = (err or out or "").lower()
            if self.backend == "nftables" and ("file exists" in err_l or "already exists" in err_l):
                continue
            return False, out or err or f"Command failed with rc={rc}", cmd, err or out
        return True, "Network enforcement applied", [], ""

    def _rollback_payload(self, plan: ActionPlan, direction: str, version: str, ttl: int, expires_at: int, mode: str) -> Dict[str, Any]:
        set_name = self._set_name(direction, version, mode)
        payload: Dict[str, Any] = {
            "type": "network_rollback",
            "backend": self.backend,
            "target": plan.target,
            "direction": direction,
            "version": version,
            "mode": mode,
            "ttl_seconds": ttl,
            "expires_at": expires_at,
        }
        if self.backend == "nftables":
            payload["command"] = ["nft", "delete", "element", self.nft_family, self.nft_table, set_name, "{", plan.target, "}"]
        elif self.backend == "iptables":
            tool = "ip6tables" if version == "v6" else "iptables"
            chain = "INPUT" if direction == "inbound" else "OUTPUT"
            flag = "-s" if direction == "inbound" else "-d"
            comment = self._iptables_comment(plan.action_id, ttl)
            if mode == "rate_limit":
                payload["command"] = [tool, "-D", "INPUT", "-s", plan.target, "-p", "tcp", "--syn", "-m", "hashlimit", "--hashlimit-above", f"{self.rate_limit_per_second}/second", "--hashlimit-burst", str(self.rate_limit_burst), "--hashlimit-mode", "srcip", "--hashlimit-name", f"aegis_{plan.action_id[-8:]}", "-m", "comment", "--comment", comment, "-j", "DROP"]
            else:
                payload["command"] = [tool, "-D", chain, flag, plan.target, "-m", "comment", "--comment", comment, "-j", "DROP"]
        return payload

    @staticmethod
    def _iptables_comment(action_id: str, ttl: int) -> str:
        expires_at = int(time.time()) + ttl
        return f"aegis:{action_id}:expires:{expires_at}"
