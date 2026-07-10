from __future__ import annotations

import os
import stat
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

SECRET_MARKER = "***REDACTED***"
SENSITIVE_KEYS = {
    "api_key",
    "apiKey",
    "openai_api_key",
    "gpt_api_key",
    "authorization",
    "Authorization",
    "bearer",
    "token",
    "secret",
    "password",
    "client_secret",
}
MASK_ONLY_KEYS = {"api_key_file", "api_key_env", "fail_on_insecure_secret_permissions"}


@dataclass
class SecretLoadResult:
    value: str
    source: str
    warnings: List[str]

    def public_dict(self) -> Dict[str, Any]:
        return {"loaded": bool(self.value), "source": self.source, "warnings": list(self.warnings)}


def mask_secret(value: Any, keep: int = 4) -> Any:
    """Return a non-sensitive representation of a secret-like value."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    if len(text) <= keep * 2:
        return SECRET_MARKER
    return f"{text[:keep]}...{text[-keep:]}"


def _key_is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(token.lower() == k for token in SENSITIVE_KEYS) or any(token in k for token in ["api_key", "secret", "password", "token"])


def redact_secrets(obj: Any) -> Any:
    """Recursively redact sensitive values before logging, storing, or returning via UI/API."""
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for key, value in obj.items():
            key_text = str(key)
            if key_text in MASK_ONLY_KEYS:
                # These are references/options for where/how the key is loaded, not the key itself.
                out[key] = value
            elif _key_is_sensitive(key_text):
                out[key] = SECRET_MARKER if value not in (None, "") else value
            else:
                out[key] = redact_secrets(value)
        return out
    if isinstance(obj, list):
        return [redact_secrets(v) for v in obj]
    return obj


def check_secret_file_permissions(path: str | Path) -> List[str]:
    """Warn when the secret file is readable/writable/executable by group or others.

    Recommended production permission is 0600 owned by the service account or root.
    This function warns instead of failing so dry-run/testing remains easy.
    """
    warnings: List[str] = []
    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError:
        return [f"secret_file_missing:{p}"]
    except PermissionError:
        return [f"secret_file_permission_denied:{p}"]
    except OSError as exc:
        return [f"secret_file_stat_failed:{p}:{exc}"]

    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.append(f"secret_file_permissions_too_open:{p}:mode={oct(mode)}:recommended=0o600")
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        warnings.append(f"secret_file_executable:{p}:mode={oct(mode)}")
    if not stat.S_ISREG(st.st_mode):
        warnings.append(f"secret_file_not_regular:{p}")
    return warnings


def _strict_permission_violations(warnings: Iterable[str]) -> List[str]:
    return [
        w for w in warnings
        if "permissions_too_open" in w
        or "secret_file_executable" in w
        or "secret_file_not_regular" in w
        or "secret_file_permission_denied" in w
    ]


def read_secret_file(path: str | Path) -> tuple[str, List[str]]:
    warnings = check_secret_file_permissions(path)
    p = Path(path)
    if any(w.startswith("secret_file_missing") or w.startswith("secret_file_permission_denied") for w in warnings):
        return "", warnings
    try:
        # Read only; never write, chmod, or mutate the secret from the agent.
        value = p.read_text(encoding="utf-8").strip()
    except Exception as exc:
        return "", [*warnings, f"secret_file_read_failed:{p}:{exc}"]
    if not value:
        warnings.append(f"secret_file_empty:{p}")
    return value, warnings


def resolve_api_key(config: Dict[str, Any], default_env: str = "OPENAI_API_KEY") -> SecretLoadResult:
    """Resolve API key in backward-compatible order.

    Priority:
      1. api_key_file: preferred production mode. Read-only local file.
      2. api_key: legacy inline config support; warned and masked in outputs.
      3. api_key_env: environment variable mode, still supported.
    """
    cfg = config or {}
    warnings: List[str] = []

    api_key_file = cfg.get("api_key_file")
    if api_key_file:
        value, file_warnings = read_secret_file(str(api_key_file))
        warnings.extend(file_warnings)
        strict = bool(cfg.get("fail_on_insecure_secret_permissions", False))
        violations = _strict_permission_violations(file_warnings)
        if strict and violations:
            raise PermissionError("insecure_secret_file_permissions:" + ";".join(violations))
        if value:
            return SecretLoadResult(value=value, source="api_key_file", warnings=warnings)

    inline = cfg.get("api_key")
    if inline:
        warnings.append("inline_api_key_in_config_is_supported_but_not_recommended; use api_key_file or api_key_env")
        return SecretLoadResult(value=str(inline), source="api_key", warnings=warnings)

    env_name = str(cfg.get("api_key_env") or default_env)
    env_value = os.getenv(env_name, "")
    if env_value:
        return SecretLoadResult(value=env_value, source=f"env:{env_name}", warnings=warnings)
    warnings.append(f"missing_api_key: checked api_key_file, api_key, env:{env_name}")
    return SecretLoadResult(value="", source="missing", warnings=warnings)


def secret_status(config: Dict[str, Any], default_env: str = "OPENAI_API_KEY") -> Dict[str, Any]:
    try:
        result = resolve_api_key(config, default_env=default_env)
    except PermissionError as exc:
        return {"loaded": False, "source": "permission_error", "warnings": [str(exc)], "error": "insecure_secret_permissions"}
    status = result.public_dict()
    if result.value:
        status["masked"] = mask_secret(result.value)
    return status
