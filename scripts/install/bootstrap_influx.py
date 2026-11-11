#!/usr/bin/env python3
"""Create InfluxDB's local administrator-token bootstrap file once."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

try:
    from ._common import (
        InstallError,
        absolute_workspace,
        checked_path,
        open_directory,
        read_env,
    )
except ImportError:
    from _common import (
        InstallError,
        absolute_workspace,
        checked_path,
        open_directory,
        read_env,
    )


BOOTSTRAP_UID = 1500
BOOTSTRAP_GID = 1500
BOOTSTRAP_MODE = 0o600
MAX_BOOTSTRAP_BYTES = 1024 * 1024


def _safe_existing_target(
    directory_fd: int, name: str
) -> tuple[bool, os.stat_result | None]:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False, None
    except OSError as exc:
        raise InstallError("Bootstrap target cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode):
        raise InstallError("Bootstrap target must not be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise InstallError("Bootstrap target must be a regular file")
    return True, info


def _validate_token(value: str) -> None:
    if (
        len(value) != 70
        or not value.startswith("apiv3_")
        or not re.fullmatch(r"[0-9a-fA-F]{64}", value[6:])
    ):
        raise InstallError(
            "INFLUX_TOKEN: expected apiv3_ plus 64 hexadecimal characters"
        )


def _open_existing(directory_fd: int, name: str) -> int:
    """Open an existing bootstrap file read-only without following symlinks.

    ``O_NOATIME`` is requested to avoid disturbing access times, but the kernel
    refuses it with ``EPERM`` for callers that do not own the file. That refusal
    says nothing about the file being exposed or unsafe, so the open is retried
    once without the flag; every other error is reported as an unsafe open.
    """
    base = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    try:
        try:
            return os.open(name, base | noatime, dir_fd=directory_fd)
        except PermissionError:
            if not noatime:
                raise
            return os.open(name, base, dir_fd=directory_fd)
    except OSError as exc:
        raise InstallError("Bootstrap target cannot be opened safely") from exc


def _read_existing(
    directory_fd: int, name: str, expected_info: os.stat_result
) -> tuple[int, bytes, os.stat_result]:
    """Open and read an existing bootstrap file, returning ``(fd, bytes, fstat)``.

    The file must be the already-inspected regular file with exactly one hard
    link and at most ``MAX_BOOTSTRAP_BYTES`` bytes; the size is checked from
    ``fstat`` before any read buffer is allocated and the read loop is capped.
    The descriptor is closed on every failure path and is handed to the caller
    (who must close it) only on success.
    """
    fd = _open_existing(directory_fd, name)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (
            expected_info.st_dev,
            expected_info.st_ino,
        ):
            raise InstallError("Bootstrap target changed while being opened")
        if info.st_nlink != 1:
            raise InstallError("Bootstrap target must not have additional hard links")
        if info.st_size > MAX_BOOTSTRAP_BYTES:
            raise InstallError("Existing bootstrap file exceeds the size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            part = os.read(fd, min(65536, MAX_BOOTSTRAP_BYTES + 1 - total))
            if not part:
                break
            total += len(part)
            if total > MAX_BOOTSTRAP_BYTES:
                raise InstallError("Existing bootstrap file exceeds the size limit")
            chunks.append(part)
        if total != info.st_size or os.fstat(fd).st_size != info.st_size:
            raise InstallError("Bootstrap target changed while being read")
        return fd, b"".join(chunks), info
    except OSError as exc:
        os.close(fd)
        raise InstallError("Bootstrap target cannot be read") from exc
    except BaseException:
        os.close(fd)
        raise


def _validate_existing(raw: bytes, token: str) -> None:
    """Validate the content of an existing bootstrap file without modifying anything.

    The file must be UTF-8 JSON without duplicate keys at any depth, an object
    with string ``token`` and ``name`` members, ``name == "_admin"`` and a token
    equal to ``token``. Additional members and original formatting are allowed
    and left untouched. Errors never include file contents.
    """

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InstallError("Existing bootstrap file is invalid JSON") from exc
    if not isinstance(value, dict) or "token" not in value or "name" not in value:
        raise InstallError("Existing bootstrap file has an invalid schema")
    if not isinstance(value["token"], str) or not isinstance(value["name"], str):
        raise InstallError("Existing bootstrap file has an invalid schema")
    if value["name"] != "_admin":
        raise InstallError("Existing bootstrap file name must be _admin")
    if not secrets.compare_digest(
        value["token"].encode("utf-8"), token.encode("utf-8")
    ):
        raise InstallError(
            "Existing bootstrap token differs; explicit rotation is required"
        )


def _require_expected_metadata(info: os.stat_result) -> None:
    """Fail unless the opened existing file is owned by 1500:1500 with mode 0600.

    This is a read-only check: the installer never changes the ownership or
    permissions of an existing file, so an operator must correct them.
    """
    if (info.st_uid, info.st_gid) != (BOOTSTRAP_UID, BOOTSTRAP_GID) or stat.S_IMODE(
        info.st_mode
    ) != BOOTSTRAP_MODE:
        raise InstallError(
            "Existing bootstrap file must be owned by 1500:1500 with mode 0600; no changes were made"
        )


def _create_new(directory_fd: int, name: str, token: str) -> None:
    temp_name = ".influx-token-" + secrets.token_hex(12)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise InstallError("Temporary bootstrap file could not be created") from exc
    try:
        payload = json.dumps(
            {"token": token, "name": "_admin"}, separators=(",", ":")
        ).encode("utf-8")
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise InstallError(
                    "Temporary bootstrap file could not be fully written"
                )
            view = view[written:]
        os.fchown(fd, BOOTSTRAP_UID, BOOTSTRAP_GID)
        os.fchmod(fd, BOOTSTRAP_MODE)
        os.fsync(fd)
    except (OSError, InstallError) as exc:
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except OSError:
            pass
        if isinstance(exc, InstallError):
            raise
        raise InstallError("Bootstrap file could not be secured") from exc
    finally:
        os.close(fd)

    try:
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except AttributeError:
            renameat2 = None
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                directory_fd, os.fsencode(temp_name), directory_fd, os.fsencode(name), 1
            )
            if result != 0:
                error = ctypes.get_errno()
                if error == errno.EEXIST:
                    raise InstallError("Bootstrap target appeared during creation")
                if error not in (errno.ENOSYS, errno.EINVAL):
                    raise OSError(error, "atomic bootstrap rename failed")
                renameat2 = None
        if renameat2 is None:
            # Atomic no-replace publication fallback for C libraries without renameat2.
            os.link(
                temp_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temp_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise InstallError("Bootstrap target appeared during creation") from exc
    except OSError as exc:
        raise InstallError("Bootstrap target could not be installed") from exc
    finally:
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def bootstrap(workspace_arg: str, env_arg: str | None) -> int:
    workspace = absolute_workspace(workspace_arg)
    env_path = checked_path(workspace, env_arg or ".env.compose")
    _, document = read_env(env_path)
    token = document.resolved.get("INFLUX_TOKEN", "")
    _validate_token(token)

    shared = checked_path(workspace, "shared")
    try:
        shared_info = shared.lstat()
    except OSError as exc:
        raise InstallError("shared directory must exist") from exc
    if stat.S_ISLNK(shared_info.st_mode) or not stat.S_ISDIR(shared_info.st_mode):
        raise InstallError("shared path must be a real directory")
    target_name = "influx-admin-token.json"
    directory_fd = open_directory(shared)
    try:
        directory_info = os.fstat(directory_fd)
        if (directory_info.st_dev, directory_info.st_ino) != (
            shared_info.st_dev,
            shared_info.st_ino,
        ):
            raise InstallError("shared directory changed during bootstrap")
        exists, info = _safe_existing_target(directory_fd, target_name)
        if exists:
            fd, raw, opened = _read_existing(directory_fd, target_name, info)
            try:
                _validate_existing(raw, token)
                _require_expected_metadata(opened)
            finally:
                os.close(fd)
            print("InfluxDB bootstrap token file already matches; no content change")
            return 0

        _create_new(directory_fd, target_name, token)
        print("Created InfluxDB bootstrap token file")
        return 0
    finally:
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace", default=str(Path(__file__).absolute().parents[2])
    )
    parser.add_argument("--env-file")
    args = parser.parse_args()
    try:
        return bootstrap(args.workspace, args.env_file)
    except OSError:
        print("Filesystem operation failed", file=sys.stderr)
        return 1
    except InstallError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
