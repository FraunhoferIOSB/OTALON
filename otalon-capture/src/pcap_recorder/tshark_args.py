"""Allow-list validation for caller-supplied ``tshark`` arguments.

The recorder exposes ``format=detail`` to two internal consumers
(``otalon-api``, ``otalon-mcp``). Those consumers need display filters and
statistics modes (``-Y``, ``-z io,phs``, ``-T fields -e ...``) to get usable
packet evidence out of a 30-second chunk; without them the response is a full
verbose decode of ~37 000 packets that no downstream consumer can process.

Free-form pass-through is what audit finding HC1 rejected: ``tshark`` accepts
``-w`` (write anywhere), ``-X lua_script:`` (execute Lua), ``-o`` (override
preferences) and ``-r`` (read a different file), so an unfiltered string is an
arbitrary file read/write and code-execution primitive.

This module therefore implements the middle position the audit asked for: a
strict allow-list of read-only rendering flags, each with its own value
validator. Anything not explicitly listed is rejected before a subprocess is
built. No shell is ever involved — :func:`parse_tshark_args` returns an argv
list that is spliced into a fixed ``["tshark", "-r", <path>, ...]`` command.
"""

from __future__ import annotations

import re
import shlex
from typing import Dict, List, Pattern

MAX_RAW_LENGTH = 512
"""Ceiling on the raw argument string; the longest legitimate call is ~200."""

MAX_TOKENS = 40
"""Ceiling on the token count after splitting; ``-T fields`` calls use ~16."""


class TsharkArgError(ValueError):
    """Raised when a caller-supplied ``tshark`` argument string is rejected."""


FLAGS_WITHOUT_VALUE = frozenset(
    {
        "-q",
        "-V",
        "-n",
        "-x",
    }
)
"""Standalone read-only flags: quiet, verbose decode, no name resolution, hex."""

_FIELD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
_COUNT_RE = re.compile(r"^[0-9]{1,7}$")
_TIME_FORMAT_RE = re.compile(r"^(?:a|ad|adoy|d|dd|e|r|u|ud|udoy)$")
_OUTPUT_FORMAT_RE = re.compile(r"^(?:fields|text|json|jsonraw|pdml|ps|psml|tabs|ek)$")
_DISPLAY_FILTER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,400}$")
_STAT_RE = re.compile(
    r"^(?:io,phs"
    r"|io,stat,[0-9]{1,5}(?:,[^\x00-\x1f\x7f]{1,200})?"
    r"|conv,(?:eth|ip|ipv6|tcp|udp)"
    r"|endpoints,(?:eth|ip|ipv6|tcp|udp)"
    r"|plen,tree"
    r"|expert"
    r"|dns,tree"
    r"|http,tree"
    r"|http_req,tree"
    r")$"
)

VALUE_FLAG_PATTERNS: Dict[str, Pattern[str]] = {
    "-Y": _DISPLAY_FILTER_RE,
    "-T": _OUTPUT_FORMAT_RE,
    "-e": _FIELD_RE,
    "-c": _COUNT_RE,
    "-z": _STAT_RE,
    "-t": _TIME_FORMAT_RE,
}
"""Allow-listed flags that consume a value, each with its value validator."""


def _split(raw: str) -> List[str]:
    """Split ``raw`` into tokens using POSIX quoting rules, never a shell.

    Args:
        raw: The caller-supplied argument string.

    Returns:
        The token list.

    Raises:
        TsharkArgError: If the string is over-long or unbalanced-quoted.
    """

    if len(raw) > MAX_RAW_LENGTH:
        raise TsharkArgError(f"tshark_args exceeds {MAX_RAW_LENGTH} characters")
    try:
        tokens = shlex.split(raw)
    except ValueError as error:
        raise TsharkArgError(f"tshark_args is not parsable: {error}") from error
    if len(tokens) > MAX_TOKENS:
        raise TsharkArgError(f"tshark_args exceeds {MAX_TOKENS} tokens")
    return tokens


def _validate_value(flag: str, value: str) -> None:
    """Validate the value belonging to ``flag`` against its own pattern.

    A value that itself looks like an option is always rejected: it would be
    consumed by ``tshark`` as a flag if the preceding flag were ever dropped.

    Args:
        flag: The allow-listed flag the value belongs to.
        value: The candidate value.

    Raises:
        TsharkArgError: If the value is empty, option-shaped or malformed.
    """

    if not value or value.startswith("-"):
        raise TsharkArgError(f"tshark_args: missing value for '{flag}'")
    if not VALUE_FLAG_PATTERNS[flag].match(value):
        raise TsharkArgError(f"tshark_args: value for '{flag}' is not allowed")


def parse_tshark_args(raw: str) -> List[str]:
    """Return the validated argv list for a caller-supplied argument string.

    Args:
        raw: The ``tshark_args`` query value; empty means "no extra arguments".

    Returns:
        A validated argv list, safe to splice into a fixed ``tshark`` command.

    Raises:
        TsharkArgError: If any token is outside the allow-list or malformed.
    """

    if not raw or not raw.strip():
        return []
    tokens = _split(raw)
    argv: List[str] = []
    index = 0
    while index < len(tokens):
        flag = tokens[index]
        if flag in FLAGS_WITHOUT_VALUE:
            argv.append(flag)
            index += 1
            continue
        if flag not in VALUE_FLAG_PATTERNS:
            raise TsharkArgError(f"tshark_args: flag '{flag}' is not allowed")
        if index + 1 >= len(tokens):
            raise TsharkArgError(f"tshark_args: missing value for '{flag}'")
        value = tokens[index + 1]
        _validate_value(flag, value)
        argv.extend((flag, value))
        index += 2
    return argv
