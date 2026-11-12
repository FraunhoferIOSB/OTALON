#!/usr/bin/env python3
"""Provision a separate capture-source credential and stdlib Windows package.

Never rotates an existing source key or exports suite/database credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import zipfile
from pathlib import Path


def checked(path):
    path = Path(path).absolute()
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError("symlink path refused")
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("hardlinked file refused")
    return path


def prepare(workspace, destination, receiver_uid):
    workspace = checked(workspace)
    if destination is not None:
        destination = checked(destination)
    key = checked(workspace / "shared/continuous-source.key")
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_hex(32) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        if receiver_uid is not None:
            os.chown(key, receiver_uid, receiver_uid)
    value = key.read_bytes()
    if not re.fullmatch(rb"[0-9a-f]{64}\n?", value):
        raise ValueError("existing source key invalid; not rotated")
    if destination is None:
        print("Capture source key ready; configured value preserved.")
        return 0
    cert = checked(workspace / "shared/tls/tls.crt")
    if not cert.is_file():
        raise ValueError("Start the TLS proxy first; certificate missing")
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in [("source.key", value), ("otalon.crt", cert.read_bytes())]:
        target = checked(destination / name)
        if target.exists() and target.read_bytes() != content:
            raise ValueError("existing Windows export differs; not overwritten")
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(content)
            os.chmod(target, 0o600)
    config = {
        "dumpcap": r"C:\Program Files\Wireshark\dumpcap.exe",
        "interface": "<SELECT_NPCAP_INTERFACE>",
        "spool": r"C:\OTALON\spool",
        "url": "https://localhost:9493",
        "key_file": r"C:\OTALON\source.key",
        "ca_file": r"C:\OTALON\otalon.crt",
        "chunk_seconds": 2,
        "chunk_kb": 8192,
        "min_free_bytes": 1000000000,
        "max_spool_bytes": 2000000000,
    }
    cfg = checked(destination / "collector.sample.json")
    if not cfg.exists():
        cfg.write_text(json.dumps(config, indent=2) + "\n")
    package = checked(destination / "collector.zip")
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("__main__.py", "from windows_collector.collector import main\nmain()\n")
        for name in [
            "windows_collector/__init__.py",
            "windows_collector/collector.py",
            "desktop_ingest/__init__.py",
            "desktop_ingest/pcap.py",
        ]:
            archive.write(checked(workspace / "otalon-capture/src" / name), name)
    print("Windows collector package ready. Source key preserved; no suite secrets exported.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--export")
    parser.add_argument("--receiver-uid", type=int)
    args = parser.parse_args()
    try:
        return prepare(Path(args.workspace), Path(args.export) if args.export else None, args.receiver_uid)
    except (ValueError, OSError):
        print(
            "Windows preparation failed; inspect paths, existing export and certificate. No key rotation performed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
