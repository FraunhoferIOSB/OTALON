"""Public wiring contracts checked against the tracked env sample."""

from __future__ import annotations

import hmac
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_ENV_REFERENCE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_PLACEHOLDER = re.compile(r"<SET_([A-Z0-9_]+)>")


def _parse_sample_env(path: Path) -> dict[str, str]:
    """Parse assignments and expand references with deterministic fake keys."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        value = _PLACEHOLDER.sub(lambda match: f"synthetic-{match.group(1).lower()}", value)
        while True:
            expanded = _ENV_REFERENCE.sub(lambda match: values[match.group(1)], value)
            if expanded == value:
                break
            value = expanded
        values[name] = value
    return values


def _has_key_entry(entries: list[str], prefix: str, token: str) -> bool:
    """Match an allow-list entry without exposing credential values on failure."""
    return any(hmac.compare_digest(entry, f"{prefix}:{token}") for entry in entries)


def test_sample_public_service_and_key_contracts() -> None:
    """The documented public aliases resolve without consulting host env."""
    env = _parse_sample_env(ROOT / ".env.compose.sample")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^  otalon-capture-pcap-import:\s*$", compose)
    assert env["PCAP_IMPORT_WORKER_HOST"] == "otalon-capture-pcap-import"

    ui_operator_expr = re.search(r"(?m)^      OTALON_OPERATOR_KEY: (.+)$", compose)
    assert ui_operator_expr is not None
    ui_operator_key = _ENV_REFERENCE.sub(lambda match: env[match.group(1)], ui_operator_expr.group(1))
    assert hmac.compare_digest(ui_operator_key, env["ADMIN_API_KEY"])
    assert _has_key_entry(env["OTALON_API_ALLOWED_KEYS"].split(","), "ui:operator", env["ADMIN_API_KEY"])

    assert int(env["RETRAIN_COOLDOWN_MINUTES"]) > 0
    assert env["NVD_API_KEY"] == ""
    assert env["PASSIVE_SEEDER_INFLUX_TOKEN"] == env["INFLUX_TOKEN"]

    aliases = {
        "OTALON_API_KEY": ("OTALON_API_ALLOWED_KEYS", "mcp:operator"),
        "OTALON_AI_UI_KEY": ("OTALON_AI_ALLOWED_KEYS", "ui:viewer"),
        "OTALON_AI_INTERNAL_KEY": ("OTALON_AI_ALLOWED_KEYS", "internal:operator"),
        "OTALON_SCAN_API_KEY": ("OTALON_SCAN_ALLOWED_KEYS", "mcp-prod:operator"),
        "OTALON_MCP_API_KEY": ("OTALON_MCP_ALLOWED_KEYS", "otalon-ai:operator"),
    }
    for key_name, (allowlist_name, entry_name) in aliases.items():
        assert _has_key_entry(env[allowlist_name].split(","), entry_name, env[key_name])
