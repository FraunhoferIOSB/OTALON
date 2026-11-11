"""Shared, dependency-free helpers for the local installation utilities.

Environment-file grammar accepted by :func:`parse_env` (deliberately a small
subset of the full Docker Compose grammar):

* UTF-8 text of at most 1 MiB; the only control characters allowed are the
  line endings ``\\n`` and ``\\r\\n`` (tabs, NUL, lone ``\\r``, Unicode line
  separators and other controls are rejected, including inside comments).
* Blank lines, whitespace-only lines and lines starting with ``#`` are kept
  verbatim and ignored. Every other line is ``NAME=value`` with
  ``NAME`` matching ``[A-Z][A-Z0-9_]*``, no ``export`` prefix, no spaces around
  ``=`` and no leading or trailing whitespace in the value. Duplicates fail.
* ``'single quoted'`` values are literal: no expansion and no reference
  checks happen inside them (``$``, backticks and backslashes are data).
* Bare and ``"double quoted"`` values expand ``${NAME}`` only, and ``NAME``
  must be assigned on an earlier line. Self, forward, unknown, malformed or
  dangling references fail; the process environment is never consulted.
  Bare ``$NAME``, ``$(command)``, ``$$``, backticks, ``${NAME:-x}`` forms and
  backslashes are rejected rather than guessed.
* The resolved (expanded) values may total at most 1 MiB, checked before the
  expanded strings are built, so reference chains cannot grow without bound.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

KEY_RE = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)\Z")
REFERENCE_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
PLACEHOLDER_RE = re.compile(r"<SET_[^>]*>|<git-sha-or-release-ref>", re.IGNORECASE)
# Every C0/C1 control and Unicode line separator except LF (0x0a) and CR (0x0d).
CONTROL_RE = re.compile("[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]")
MAX_ENV_BYTES = 1024 * 1024
MAX_RESOLVED_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 65536


class InstallError(Exception):
    """A safe-to-display validation or filesystem error."""


@dataclass(frozen=True)
class EnvDocument:
    """A parsed environment file.

    ``lines`` are the original lines including their line endings, ``values``
    maps each name to its raw (still quoted, unexpanded) text and ``resolved``
    maps each name to its decoded and expanded value.
    """

    lines: tuple[str, ...]
    values: dict[str, str]
    resolved: dict[str, str]


def absolute_workspace(raw: str | os.PathLike[str]) -> Path:
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise InstallError(
            "WORKSPACE_DIR: workspace must be an absolute path without traversal"
        )
    check_path_ancestors(path, include_target=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError("WORKSPACE_DIR: workspace is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise InstallError("WORKSPACE_DIR: workspace is not a directory")
    return path


def checked_path(base: Path, raw: str | os.PathLike[str]) -> Path:
    supplied = Path(raw)
    if ".." in supplied.parts:
        raise InstallError("Path traversal is not allowed")
    path = supplied if supplied.is_absolute() else base / supplied
    if not path.is_absolute():
        raise InstallError("Path must be absolute or relative to the workspace")
    check_path_ancestors(path, include_target=False)
    return path


def check_path_ancestors(path: Path, *, include_target: bool) -> None:
    """Reject symlink components and non-directory path ancestors."""
    path = Path(os.path.abspath(path))
    components = path.parts
    current = Path(components[0])
    stop = len(components) if include_target else len(components) - 1
    for component in components[1:stop]:
        current = current / component
        try:
            info = current.lstat()
        except OSError as exc:
            raise InstallError("Path ancestor is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise InstallError("Symlink paths are not allowed")
        if not stat.S_ISDIR(info.st_mode):
            raise InstallError("Path ancestor is not a directory")
    if include_target:
        try:
            info = path.lstat()
        except OSError as exc:
            raise InstallError("Path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise InstallError("Symlink paths are not allowed")


def open_directory(path: Path) -> int:
    """Open an absolute directory one no-follow component at a time."""
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        try:
            os.close(current_fd)
        except (OSError, UnboundLocalError):
            pass
        raise InstallError("Directory path cannot be opened safely") from exc


def _open_regular(path: Path, flags: int) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise InstallError("File cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode):
        raise InstallError("Symlink files are not allowed")
    if not stat.S_ISREG(before.st_mode):
        raise InstallError("File must be a regular file")
    parent_fd = open_directory(path.parent)
    try:
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise InstallError("File changed while being opened")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path.name, flags | nofollow, dir_fd=parent_fd)
    except OSError as exc:
        raise InstallError("File cannot be opened safely") from exc
    finally:
        os.close(parent_fd)
    try:
        after = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise InstallError("File cannot be inspected") from exc
    try:
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise InstallError("File changed while being opened")
        reject_extra_links(after)
    except InstallError:
        os.close(fd)
        raise
    return fd, after


def reject_extra_links(info: os.stat_result) -> None:
    """Raise :class:`InstallError` unless the file has exactly one directory entry.

    A file with additional hard links could alias operator data or be an
    attacker-planted alias, so installer inputs and in-place targets must not
    have one. Nothing is repaired automatically.
    """
    if info.st_nlink != 1:
        raise InstallError("File must not have additional hard links")


def read_regular(path: Path, max_bytes: int = MAX_ENV_BYTES) -> bytes:
    """Return the bytes of a regular, single-link file of at most ``max_bytes``."""
    return read_regular_with_info(path, max_bytes)[0]


def read_regular_with_info(
    path: Path, max_bytes: int = MAX_ENV_BYTES
) -> tuple[bytes, os.stat_result]:
    """Read a no-follow regular file and return its bytes and opened-file metadata.

    The reported size is checked against ``max_bytes`` before any allocation and
    the read loop never requests more than ``max_bytes + 1`` bytes in total, so a
    growing file cannot cause an unbounded read. The descriptor is closed on
    every success and failure path.
    """
    fd, info = _open_regular(path, os.O_RDONLY)
    try:
        if info.st_size > max_bytes:
            raise InstallError(f"File exceeds the {max_bytes}-byte size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise InstallError(f"File exceeds the {max_bytes}-byte size limit")
            chunks.append(chunk)
        if os.fstat(fd).st_size != info.st_size or total != info.st_size:
            raise InstallError("File changed while being read")
        return b"".join(chunks), info
    except OSError as exc:
        raise InstallError("File cannot be read") from exc
    finally:
        os.close(fd)


def read_env(path: Path) -> tuple[bytes, EnvDocument]:
    """Read and parse an environment file, returning its bytes and document."""
    raw, document, _ = read_env_with_info(path)
    return raw, document


def read_env_with_info(path: Path) -> tuple[bytes, EnvDocument, os.stat_result]:
    """Read and parse an environment file, also returning its opened-file metadata."""
    raw, info = read_regular_with_info(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("Environment file is not valid UTF-8") from exc
    return raw, parse_env(text), info


_EXPANSION_TOKEN_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}|[$`\\]")
_LINE_RE = re.compile(r"[^\n]*\n|[^\n]+")


def _byte_length(text: str) -> int:
    """Return the UTF-8 length of ``text`` (lone surrogates count as three bytes)."""
    return len(text.encode("utf-8", "surrogatepass"))


def _unquote(key: str, value: str) -> tuple[str, bool]:
    """Split a raw value into its payload and whether ``${NAME}`` expansion applies.

    Single-quoted values are literal (``False``); bare and double-quoted values
    expand (``True``). A quote that is unmatched or repeated inside the quoted
    payload is rejected.
    """
    first = value[:1]
    if first in ("'", '"'):
        if len(value) < 2 or value[-1] != first or first in value[1:-1]:
            raise InstallError(f"{key}: unmatched quote")
        return value[1:-1], first == '"'
    if value[-1:] in ("'", '"'):
        raise InstallError(f"{key}: unmatched quote")
    return value, True


def _expand(
    key: str,
    text: str,
    resolved: dict[str, str],
    sizes: dict[str, int],
    used: int,
) -> tuple[str, int]:
    """Expand ``${NAME}`` references in ``text`` using earlier assignments only.

    Returns the expanded text and its UTF-8 size. Any other ``$`` form, a
    backtick or a backslash is rejected, as is a self, forward or unknown
    reference. ``used`` is the resolved size already consumed by earlier values;
    the running total is checked before each piece is appended so no oversized
    string is ever built.
    """
    pieces: list[str] = []
    size = 0
    position = 0

    def add(piece: str, piece_size: int) -> None:
        nonlocal size
        size += piece_size
        if used + size > MAX_RESOLVED_BYTES:
            raise InstallError(f"{key}: resolved environment exceeds the size limit")
        pieces.append(piece)

    for token in _EXPANSION_TOKEN_RE.finditer(text):
        literal = text[position : token.start()]
        add(literal, _byte_length(literal))
        name = token.group(1)
        if name is None:
            raise InstallError(f"{key}: unsupported or malformed variable syntax")
        if name == key:
            raise InstallError(f"{key}: self reference is not allowed")
        if name not in resolved:
            raise InstallError(f"{key}: reference must follow {name}")
        add(resolved[name], sizes[name])
        position = token.end()
    tail = text[position:]
    add(tail, _byte_length(tail))
    return "".join(pieces), size


def parse_env(text: str) -> EnvDocument:
    """Parse ``text`` using the restricted grammar described in the module docstring.

    Raises :class:`InstallError` (never echoing values) for oversized input,
    control characters, malformed or duplicate assignments, unmatched quotes and
    unsupported or unresolvable references. Lines are split only on ``\\n`` so the
    original bytes of every line, including its ending, are preserved in
    ``EnvDocument.lines``.
    """
    if len(text) > MAX_ENV_BYTES or _byte_length(text) > MAX_ENV_BYTES:
        raise InstallError("Environment file exceeds the size limit")
    if CONTROL_RE.search(text):
        for index, line in enumerate(_LINE_RE.findall(text), start=1):
            if CONTROL_RE.search(line):
                assignment = KEY_RE.match(line.rstrip("\r\n"))
                label = (
                    assignment.group(1) if assignment else f"Environment line {index}"
                )
                raise InstallError(f"{label}: invalid control character")
    lines = tuple(_LINE_RE.findall(text))
    values: dict[str, str] = {}
    resolved: dict[str, str] = {}
    sizes: dict[str, int] = {}
    used = 0
    for index, line in enumerate(lines, start=1):
        body = (
            line[:-2]
            if line.endswith("\r\n")
            else line[:-1] if line.endswith("\n") else line
        )
        if "\r" in body:
            assignment = KEY_RE.match(body)
            label = assignment.group(1) if assignment else f"Environment line {index}"
            raise InstallError(f"{label}: invalid line ending")
        if not body.strip() or body.lstrip().startswith("#"):
            continue
        match = KEY_RE.fullmatch(body)
        if not match:
            raise InstallError(f"Environment line {index} is malformed")
        key, value = match.groups()
        if key in values:
            raise InstallError(f"{key}: duplicate assignment")
        if value.startswith("export ") or value != value.strip():
            raise InstallError(f"{key}: assignment formatting is invalid")
        payload, expands = _unquote(key, value)
        if expands:
            expanded, size = _expand(key, payload, resolved, sizes, used)
        else:
            expanded, size = payload, _byte_length(payload)
            if used + size > MAX_RESOLVED_BYTES:
                raise InstallError(
                    f"{key}: resolved environment exceeds the size limit"
                )
        values[key] = value
        resolved[key] = expanded
        sizes[key] = size
        used += size
    return EnvDocument(lines=lines, values=values, resolved=resolved)


def decode_value(value: str) -> str:
    """Return ``value`` without surrounding whitespace and one matching quote pair.

    No expansion is performed; use :attr:`EnvDocument.resolved` for expanded values.
    """
    decoded = value.strip()
    if len(decoded) >= 2 and decoded[0] == decoded[-1] and decoded[0] in "\"'":
        return decoded[1:-1]
    return decoded


def has_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value))


def missing_or_placeholder(document: EnvDocument, key: str) -> bool:
    return (
        key not in document.values
        or not decode_value(document.values[key])
        or has_placeholder(decode_value(document.values[key]))
    )


def sample_required_keys(sample: EnvDocument) -> set[str]:
    return {
        key
        for key, value in sample.values.items()
        if "<SET_" in value or "<git-sha-or-release-ref>" in value
    }


def render_updated(
    document: EnvDocument, updates: dict[str, str], order: Iterable[str] = ()
) -> bytes:
    if not updates:
        return "".join(document.lines).encode("utf-8")
    newline = "\r\n" if any(line.endswith("\r\n") for line in document.lines) else "\n"
    output: list[str] = []
    seen: set[str] = set()
    for line in document.lines:
        body = (
            line[:-2]
            if line.endswith("\r\n")
            else line[:-1] if line.endswith("\n") else line
        )
        match = KEY_RE.fullmatch(body)
        if match and match.group(1) in updates:
            key = match.group(1)
            ending = line[len(body) :]
            output.append(f"{key}={updates[key]}{ending}")
            seen.add(key)
        else:
            output.append(line)
    rank = {key: index for index, key in enumerate(order)}
    missing = [key for key in updates if key not in seen]
    missing.sort(key=lambda key: rank.get(key, len(rank)))
    for key in missing:
        key_rank = rank.get(key, len(rank))
        insert_at = len(output)
        for index, rendered in enumerate(output):
            body = (
                rendered[:-2]
                if rendered.endswith("\r\n")
                else rendered[:-1] if rendered.endswith("\n") else rendered
            )
            match = KEY_RE.fullmatch(body)
            if match and rank.get(match.group(1), len(rank)) > key_rank:
                insert_at = index
                break
        if (
            insert_at == len(output)
            and output
            and not output[-1].endswith(("\n", "\r"))
        ):
            output[-1] += newline
        output.insert(insert_at, f"{key}={updates[key]}{newline}")
    return "".join(output).encode("utf-8")


def write_existing_in_place(
    path: Path, expected: bytes, content: bytes, expected_info: os.stat_result
) -> None:
    fd, info = _open_regular(path, os.O_RDWR)
    try:
        if (info.st_dev, info.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise InstallError("Environment file changed during setup")
        if os.fstat(fd).st_size != info.st_size:
            raise InstallError("Environment file changed during setup")
        current = os.read(fd, max(info.st_size, 1) + 1)
        if current != expected:
            raise InstallError("Environment file changed during setup")
        if current == content:
            return
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise InstallError("Environment file could not be fully written")
            view = view[written:]
        os.ftruncate(fd, len(content))
        os.fsync(fd)
    except OSError as exc:
        raise InstallError("Environment file could not be updated") from exc
    finally:
        os.close(fd)


def create_exclusive(
    path: Path,
    content: bytes,
    mode: int,
    expected_parent: os.stat_result | None = None,
) -> None:
    parent_fd = open_directory(path.parent)
    if expected_parent is not None:
        actual_parent = os.fstat(parent_fd)
        if (actual_parent.st_dev, actual_parent.st_ino) != (
            expected_parent.st_dev,
            expected_parent.st_ino,
        ):
            os.close(parent_fd)
            raise InstallError("Target directory changed during setup")
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            mode,
            dir_fd=parent_fd,
        )
    except FileExistsError as exc:
        os.close(parent_fd)
        raise InstallError("Target appeared during setup") from exc
    except OSError as exc:
        os.close(parent_fd)
        raise InstallError("Target could not be created") from exc
    except InstallError:
        os.close(parent_fd)
        raise
    try:
        os.fchmod(fd, mode)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise InstallError("Target could not be fully written")
            view = view[written:]
        os.fsync(fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise InstallError("Target could not be written") from exc
    except InstallError:
        raise
    finally:
        os.close(fd)
        os.close(parent_fd)


def reject_unresolved(
    document: EnvDocument, keys: Iterable[str], *, allow: set[str] = frozenset()
) -> list[str]:
    return sorted(
        key
        for key in keys
        if key not in allow
        and (
            key not in document.resolved
            or not document.resolved[key]
            or has_placeholder(document.resolved[key])
        )
    )
