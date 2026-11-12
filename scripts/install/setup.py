#!/usr/bin/env python3
"""Create and fill the local .env.compose file without rotating configured keys."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

try:
    from ._common import (
        EnvDocument,
        InstallError,
        absolute_workspace,
        checked_path,
        create_exclusive,
        decode_value,
        has_placeholder,
        parse_env,
        read_env_with_info,
        read_regular,
        render_updated,
        write_existing_in_place,
    )
except ImportError:
    from _common import (
        EnvDocument,
        InstallError,
        absolute_workspace,
        checked_path,
        create_exclusive,
        decode_value,
        has_placeholder,
        parse_env,
        read_env_with_info,
        read_regular,
        render_updated,
        write_existing_in_place,
    )


GENERATED_KEYS = (
    "POSTGRES_PASSWORD",
    "INFLUX_TOKEN",
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
EXTERNAL_KEYS = (
    "LITELLM_BASE_URL",
    "LITELLM_API_KEY",
    "CHAT_LLM_MODEL",
    "JOBS_LLM_MODEL",
)
HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def _git_output(workspace: Path, *args: str) -> str:
    """Run a bounded, shell-free git query in the workspace and return stripped stdout."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise InstallError("OTALON_BUILD_REF: git revision is unavailable") from exc
    return result.stdout.strip()


def _git_revision(workspace: Path) -> str:
    # Git searches parent directories, so a workspace without its own repository
    # metadata could silently resolve to an enclosing repository. Require the
    # discovered top level to be the selected workspace itself. A regular ``.git``
    # file (a linked worktree) is accepted because git resolves it to the same top level.
    toplevel = _git_output(workspace, "rev-parse", "--show-toplevel")
    if not toplevel or os.path.realpath(toplevel) != os.path.realpath(workspace):
        raise InstallError(
            "OTALON_BUILD_REF: workspace is not the root of a git repository"
        )
    revision = _git_output(workspace, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision) or has_placeholder(revision):
        raise InstallError("OTALON_BUILD_REF: git revision is invalid")
    return revision


def _external_missing(document: EnvDocument) -> list[str]:
    missing: list[str] = []
    for key in EXTERNAL_KEYS:
        value = document.resolved.get(key, "")
        if (
            not value
            or has_placeholder(value)
            or ".invalid" in value.lower()
            or "offline-unconfigured" in value.lower()
        ):
            missing.append(key)
    return missing


def setup(workspace_arg: str, env_arg: str | None, without_ai: bool = False) -> int:
    workspace = absolute_workspace(workspace_arg)
    env_path = checked_path(workspace, env_arg or ".env.compose")
    sample_path = checked_path(workspace, ".env.compose.sample")
    sample_raw = read_regular(sample_path)
    try:
        sample_document = parse_env(sample_raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InstallError("Sample environment file is not valid UTF-8") from exc

    created = False
    try:
        original, document, original_info = read_env_with_info(env_path)
    except FileNotFoundError:
        original = sample_raw
        document = sample_document
        original_info = None
        created = True

    updates: dict[str, str] = {}
    used = {
        value
        for value in document.resolved.values()
        if value and not has_placeholder(value)
    }
    for key in GENERATED_KEYS:
        if (
            key not in document.values
            or not decode_value(document.values[key])
            or has_placeholder(decode_value(document.values[key]))
        ):
            if key == "INFLUX_TOKEN":
                value = "apiv3_" + secrets.token_hex(32)
            else:
                value = secrets.token_hex(32)
            while value in used:
                value = secrets.token_hex(32)
            used.add(value)
            updates[key] = value

    workspace_value = document.resolved.get("WORKSPACE_DIR", "")
    if "WORKSPACE_DIR" not in document.values or not decode_value(
        document.values.get("WORKSPACE_DIR", "")
    ):
        updates["WORKSPACE_DIR"] = str(workspace)
    elif created and workspace_value == "/home/user/otalon":
        updates["WORKSPACE_DIR"] = str(workspace)
    else:
        configured = workspace_value
        if not Path(configured).is_absolute() or configured != str(workspace):
            raise InstallError(
                "WORKSPACE_DIR: configured workspace does not match selected workspace"
            )

    if (
        "OTALON_BUILD_REF" not in document.values
        or not decode_value(document.values.get("OTALON_BUILD_REF", ""))
        or has_placeholder(decode_value(document.values.get("OTALON_BUILD_REF", "")))
    ):
        updates["OTALON_BUILD_REF"] = _git_revision(workspace)

    candidate_bytes = render_updated(document, updates, sample_document.values)
    try:
        candidate = parse_env(candidate_bytes.decode("utf-8"))
    except (UnicodeDecodeError, InstallError):
        raise
    # Generated fields must have their promised formats and every reference must resolve in order.
    for key in GENERATED_KEYS:
        value = candidate.resolved.get(key, "")
        if not value or has_placeholder(value):
            raise InstallError(f"{key}: generated value is unresolved")
    if not HEX64_RE.fullmatch(candidate.resolved["POSTGRES_PASSWORD"]):
        raise InstallError("POSTGRES_PASSWORD: expected 64 hexadecimal characters")
    influx = candidate.resolved["INFLUX_TOKEN"]
    if not influx.startswith("apiv3_") or not HEX64_RE.fullmatch(influx[6:]):
        raise InstallError(
            "INFLUX_TOKEN: expected apiv3_ plus 64 hexadecimal characters"
        )
    if candidate.resolved.get("WORKSPACE_DIR") != str(workspace):
        raise InstallError(
            "WORKSPACE_DIR: configured workspace does not match selected workspace"
        )

    if created:
        create_exclusive(env_path, candidate_bytes, 0o660, env_path.parent.lstat())
    else:
        write_existing_in_place(env_path, original, candidate_bytes, original_info)

    changed = [key for key in updates]
    if changed:
        print(f"Updated {len(changed)} keys: {', '.join(changed)}")
    else:
        print("Updated 0 keys")
    if without_ai:
        print(
            "LLM configuration is optional in this mode; AI features unavailable (--without-ai)."
        )
    else:
        missing = _external_missing(candidate)
        if missing:
            print("External configuration missing: " + ", ".join(missing))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace", default=str(Path(__file__).absolute().parents[2])
    )
    parser.add_argument("--env-file")
    parser.add_argument(
        "--without-ai",
        action="store_true",
        help="prepare core installation only; preserve optional external LLM configuration",
    )
    args = parser.parse_args()
    try:
        return setup(args.workspace, args.env_file, args.without_ai)
    except OSError:
        print("Filesystem operation failed", file=sys.stderr)
        return 1
    except InstallError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
