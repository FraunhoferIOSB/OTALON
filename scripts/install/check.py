#!/usr/bin/env python3
"""Validate local configuration shapes without contacting services."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:
    from ._common import (
        InstallError,
        absolute_workspace,
        checked_path,
        has_placeholder,
        parse_env,
        read_env,
        read_regular,
        reject_unresolved,
        sample_required_keys,
    )
except ImportError:
    from _common import (
        InstallError,
        absolute_workspace,
        checked_path,
        has_placeholder,
        parse_env,
        read_env,
        read_regular,
        reject_unresolved,
        sample_required_keys,
    )


HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
ALLOWLISTS = {
    "OTALON_API_ALLOWED_KEYS": (
        ("ui", "operator", "ADMIN_API_KEY"),
        ("mcp", "operator", "OTALON_API_KEY"),
        ("scan-ui", "viewer", "OTALON_API_SCAN_UI_KEY"),
    ),
    "OTALON_SCAN_ALLOWED_KEYS": (
        ("ui-prod", "viewer", "OTALON_SCAN_VIEWER_KEY"),
        ("mcp-prod", "operator", "OTALON_SCAN_API_KEY"),
    ),
    "OTALON_MCP_ALLOWED_KEYS": (("otalon-ai", "operator", "OTALON_MCP_API_KEY"),),
    "OTALON_AI_ALLOWED_KEYS": (
        ("ui", "viewer", "OTALON_AI_UI_KEY"),
        ("internal", "operator", "OTALON_AI_INTERNAL_KEY"),
    ),
}
EXTERNAL_KEYS = (
    "LITELLM_BASE_URL",
    "LITELLM_API_KEY",
    "CHAT_LLM_MODEL",
    "JOBS_LLM_MODEL",
)
MODEL_ALIAS_KEYS = ("CHAT_LLM_MODEL", "JOBS_LLM_MODEL")
MODEL_ALIAS_RE = re.compile(r"[A-Za-z0-9._:/+-]{1,200}")
SERVICE_KEYS = (
    "ADMIN_API_KEY",
    "OTALON_API_KEY",
    "OTALON_SCAN_API_KEY",
    "OTALON_API_SCAN_UI_KEY",
    "OTALON_SCAN_VIEWER_KEY",
    "OTALON_MCP_API_KEY",
    "OTALON_AI_UI_KEY",
    "OTALON_AI_INTERNAL_KEY",
    "PCAP_IMPORT_WORKER_TOKEN",
)
# Internal Compose DNS name used by the derived DSNs in the sample environment.
POSTGRES_BRIDGE_HOST = "postgres"
DSN_KEYS = ("POSTGRES_DSN", "CHAT_DB_DSN")


def _validate_model_aliases(document) -> None:
    """Reject served-model aliases outside the accepted ASCII shape without echoing them."""
    for key in MODEL_ALIAS_KEYS:
        if not MODEL_ALIAS_RE.fullmatch(document.resolved.get(key, "")):
            raise InstallError(f"{key}: expected 1-200 ASCII characters from A-Z a-z 0-9 . _ : / + -")


def _validate_service_key_shapes(document) -> None:
    """Allow opaque service keys, but reject characters that break registries or headers."""
    for key in SERVICE_KEYS:
        value = document.resolved.get(key, "")
        if any(character.isspace() or not character.isprintable() or character in ",:" for character in value):
            raise InstallError(f"{key}: must not contain whitespace, control characters, comma, or colon")


def _validate_postgres_dsn(document, variable: str) -> None:
    """Compare one expanded DSN with the resolved PostgreSQL settings, reporting field names only."""
    value = document.resolved.get(variable, "")
    if not value or has_placeholder(value) or any(c.isspace() or not c.isprintable() for c in value):
        raise InstallError(f"{variable}: DSN is missing or malformed")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InstallError(f"{variable}: DSN is malformed") from exc
    if parsed.scheme not in ("postgresql", "postgresql+psycopg") or parsed.query or parsed.fragment:
        raise InstallError(f"{variable}: expected a PostgreSQL DSN without query or fragment")

    settings = document.resolved
    expected_user = settings.get("POSTGRES_USER", "")
    expected_password = settings.get("POSTGRES_PASSWORD", "")
    expected_port = settings.get("POSTGRES_PORT", "")
    expected_database = settings.get("POSTGRES_DATABASE", "")
    path = parsed.path
    mismatches = []
    if not expected_user or parsed.username is None or unquote(parsed.username) != expected_user:
        mismatches.append("user")
    if not expected_password or parsed.password is None or unquote(parsed.password) != expected_password:
        mismatches.append("password")
    if hostname != POSTGRES_BRIDGE_HOST:
        mismatches.append("host")
    if not expected_port or port is None or str(port) != expected_port:
        mismatches.append("port")
    if not expected_database or not path.startswith("/") or "/" in path[1:] or unquote(path[1:]) != expected_database:
        mismatches.append("database")
    if mismatches:
        raise InstallError(
            f"{variable}: mismatched fields against resolved PostgreSQL settings: {', '.join(mismatches)}"
        )


def _validate_allowlists(document) -> None:
    for variable, expected in ALLOWLISTS.items():
        value = document.resolved.get(variable, "")
        if not value or has_placeholder(value):
            raise InstallError(f"{variable}: allow-list is missing or unresolved")
        fields = value.split(",")
        actual = []
        for field in fields:
            parts = field.split(":", 2)
            if len(parts) != 3 or not all(parts):
                raise InstallError(f"{variable}: expected name:role:key entries")
            actual.append(tuple(parts))
        if len(actual) != len(expected):
            raise InstallError(f"{variable}: entries do not match configured callers")
        for item, (caller, role, key_name) in zip(actual, expected):
            if item[:2] != (caller, role) or item[2] != document.resolved.get(key_name, ""):
                raise InstallError(f"{variable}: entries do not match configured callers")


def _validate_url(value: str, *, allow_offline_marker: bool = False) -> None:
    if not value or has_placeholder(value) or any(character.isspace() for character in value):
        raise InstallError("LITELLM_BASE_URL: endpoint is not configured")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise InstallError("LITELLM_BASE_URL: URL is malformed") from exc
    if (
        parsed.scheme not in ("http", "https")
        or not hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InstallError("LITELLM_BASE_URL: expected an HTTP(S) URL without user information")
    if parsed.query or parsed.fragment or not parsed.path.endswith("/v1"):
        raise InstallError("LITELLM_BASE_URL: URL must end in /v1 without query or fragment")
    if not allow_offline_marker and (".invalid" in value.lower() or "offline-unconfigured" in value.lower()):
        raise InstallError("LITELLM_BASE_URL: offline or invalid marker is not ready for deployment")


def check(
    workspace_arg: str, env_arg: str | None, syntax_only: bool, without_ai: bool = False, desktop: bool = False
) -> int:
    workspace = absolute_workspace(workspace_arg)
    env_path = checked_path(workspace, env_arg or ".env.compose")
    sample_path = checked_path(workspace, ".env.compose.sample")
    try:
        _, document = read_env(env_path)
        sample_raw = read_regular(sample_path)
        sample = parse_env(sample_raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InstallError("Sample environment file is not valid UTF-8") from exc

    required = sample_required_keys(sample)
    if without_ai:
        required.difference_update(EXTERNAL_KEYS)
    if desktop:
        required.difference_update({"CAPTURE_SOURCE", "SCAN_SOURCE"})
    unresolved_required = reject_unresolved(document, required)
    if unresolved_required:
        raise InstallError("Required values missing or unresolved: " + ", ".join(unresolved_required))
    if not without_ai:
        _validate_url(
            document.resolved.get("LITELLM_BASE_URL", ""),
            allow_offline_marker=syntax_only,
        )
        for key in EXTERNAL_KEYS:
            if key not in document.resolved or not document.resolved[key] or has_placeholder(document.resolved[key]):
                raise InstallError(f"{key}: external endpoint or served model alias is not configured")
        _validate_model_aliases(document)
    for key in document.resolved:
        if without_ai and key in EXTERNAL_KEYS:
            continue
        if has_placeholder(document.resolved[key]):
            raise InstallError(f"{key}: unresolved placeholder")

    password = document.resolved.get("POSTGRES_PASSWORD", "")
    if not HEX64_RE.fullmatch(password):
        raise InstallError("POSTGRES_PASSWORD: expected 64 hexadecimal characters")
    influx = document.resolved.get("INFLUX_TOKEN", "")
    if not influx.startswith("apiv3_") or not HEX64_RE.fullmatch(influx[6:]):
        raise InstallError("INFLUX_TOKEN: expected apiv3_ plus 64 hexadecimal characters")
    for dsn_key in DSN_KEYS:
        _validate_postgres_dsn(document, dsn_key)

    configured_workspace = document.resolved.get("WORKSPACE_DIR", "")
    if not Path(configured_workspace).is_absolute() or configured_workspace != str(workspace):
        raise InstallError("WORKSPACE_DIR: must match the selected absolute workspace")

    unresolved_services = reject_unresolved(document, SERVICE_KEYS)
    if unresolved_services:
        raise InstallError("Service keys missing or unresolved: " + ", ".join(unresolved_services))
    _validate_service_key_shapes(document)
    _validate_allowlists(document)

    build_ref = document.resolved.get("OTALON_BUILD_REF", "")
    if not build_ref or has_placeholder(build_ref):
        raise InstallError("OTALON_BUILD_REF: checkout reference is missing")

    if desktop:
        print("Desktop local shape check only; Windows collector/Npcap capture must be verified separately.")
    if without_ai:
        prefix = "Syntax-only: " if syntax_only else ""
        print(prefix + "local core configuration passed; LLM features unavailable (--without-ai).")
        return 0

    if syntax_only:
        print("Syntax-only checks passed; offline markers, endpoint reachability, and served models were NOT checked.")
        return 0

    for key in ("LITELLM_API_KEY", "CHAT_LLM_MODEL", "JOBS_LLM_MODEL"):
        value = document.resolved.get(key, "")
        if not value or has_placeholder(value):
            raise InstallError(f"{key}: external credential or served model alias is not configured")
    for key in EXTERNAL_KEYS:
        value = document.resolved.get(key, "")
        if ".invalid" in value.lower() or "offline-unconfigured" in value.lower():
            raise InstallError(f"{key}: offline or invalid marker is not ready for deployment")
    print("Configuration shapes passed; endpoint reachability and served-model availability were NOT verified.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=str(Path(__file__).absolute().parents[2]))
    parser.add_argument("--env-file")
    parser.add_argument(
        "--syntax-only",
        action="store_true",
        help="check local syntax/shapes only; this does not establish external readiness",
    )
    parser.add_argument(
        "--without-ai",
        action="store_true",
        help="validate core installation only; retain external LLM values and exclude the AI service at startup",
    )
    parser.add_argument(
        "--desktop", action="store_true", help="validate Desktop mode; Linux capture/scan interfaces are not used"
    )
    args = parser.parse_args()
    try:
        return check(args.workspace, args.env_file, args.syntax_only, args.without_ai, args.desktop)
    except OSError:
        print("Filesystem operation failed", file=sys.stderr)
        return 1
    except InstallError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
