"""InfluxDB SQL helper functions for time-bucketing, quoting, and query building."""

import re

SQL_IDENTIFIER_PATTERN = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
"""Strict pattern for unqualified SQL identifiers (columns, tags, measurements).

ASCII letters, digits and underscores only, never starting with a digit. Deliberately
narrower than the SQL standard so that no quoting, escaping or Unicode-confusable
character can alter the surrounding statement.
"""

SQL_IDENTIFIER_MAX_LENGTH = 255
"""Maximum accepted identifier length in characters."""

NICE_BUCKETS: tuple[int, ...] = (
    1,
    2,
    5,
    10,
    15,
    30,
    60,
    120,
    300,
    600,
    900,
    1800,
    3600,
)
"""Sorted bucket sizes in seconds suitable for InfluxDB DATE_BIN aggregation.

Represents human-friendly time intervals: 1s, 2s, 5s, 10s, 15s, 30s,
1m, 2m, 5m, 10m, 15m, 30m, 1h.
"""


def nice_bucket_seconds(total_seconds: int | float, max_points: int) -> int:
    """Return the smallest bucket size from NICE_BUCKETS producing at most max_points data points.

    Args:
        total_seconds: Total time range in seconds.
        max_points: Maximum number of data points allowed.

    Returns:
        The smallest suitable bucket size in seconds.
    """
    for bucket in NICE_BUCKETS:
        points = total_seconds / bucket
        if points <= max_points:
            return bucket
    return NICE_BUCKETS[-1]


def to_sql_interval_literal(seconds: int) -> str:
    """Convert seconds to an InfluxDB SQL interval literal string.

    Args:
        seconds: Number of seconds.

    Returns:
        An interval string like ``"5 seconds"``, ``"1 minute"``, or ``"1 hour"``.
    """
    if seconds >= 3600 and seconds % 3600 == 0:
        hours = seconds // 3600
        unit = "hour" if hours == 1 else "hours"
        return f"{hours} {unit}"
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"
    unit = "second" if seconds == 1 else "seconds"
    return f"{seconds} {unit}"


def sql_quote(value: str) -> str:
    """Quote and escape a string value for safe use in InfluxDB SQL WHERE clauses.

    Escapes single quotes to prevent SQL injection.

    Args:
        value: The string value to quote.

    Returns:
        The quoted string (e.g., ``"'O''Brien'"``).
    """
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def sql_identifier(name: str) -> str:
    """Validate and double-quote a SQL identifier such as a column or tag name.

    Fails closed: only names matching :data:`SQL_IDENTIFIER_PATTERN` are accepted, so
    the returned fragment can never terminate the identifier quoting or inject
    additional SQL. Unlike :func:`sql_quote`, which escapes string *values*, this
    function is for the identifier position.

    Args:
        name: The identifier to validate.

    Returns:
        The double-quoted identifier (e.g., ``'"uci"'``).

    Raises:
        TypeError: If name is not a string.
        ValueError: If name is empty, too long, or contains characters outside
            ``[A-Za-z0-9_]`` or starts with a digit.
    """
    if not isinstance(name, str):
        raise TypeError(f"SQL identifier must be a string, got {type(name).__name__}")
    if len(name) > SQL_IDENTIFIER_MAX_LENGTH:
        raise ValueError(
            f"invalid SQL identifier: exceeds {SQL_IDENTIFIER_MAX_LENGTH} characters"
        )
    if not SQL_IDENTIFIER_PATTERN.match(name):
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return f'"{name}"'


def distinct_values(column: str) -> str:
    """Generate a DISTINCT SQL expression fragment for a given column name.

    The column name is validated and quoted by :func:`sql_identifier`.

    Args:
        column: The column name.

    Returns:
        A SQL fragment like ``'DISTINCT "uci"'``.

    Raises:
        TypeError: If column is not a string.
        ValueError: If column is not a valid SQL identifier.
    """
    return f"DISTINCT {sql_identifier(column)}"
