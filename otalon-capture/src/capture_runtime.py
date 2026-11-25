"""Small automatic-capture contracts, independent of acquisition and credentials.

Coordinators supply observed state; these definitions do not start producers,
load environment files, schedule retries, or infer readiness from a child PID.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Self, get_args


class CaptureIntent(str, Enum):
    NONE = "NONE"
    LIVE = "LIVE"


def resolve_capture_intent() -> CaptureIntent:
    """Read boot intent after the caller's existing explicit env-loading policy."""
    # This is boot selection only, not the adapter's internal PCAP/LIVE enum.
    value = os.environ.get("CAPTURE_TYPE", "NONE").strip()
    if value == "PCAP":
        raise ValueError(
            "CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE "
            "and import PCAP/PCAPNG through Operations / Data Sources."
        )
    if value not in ("NONE", "LIVE"):
        raise ValueError("CAPTURE_TYPE must be NONE or LIVE for service startup.")
    return CaptureIntent(value)


class CaptureBackend(str, Enum):
    NATIVE = "native"
    WSL = "wsl"


class SourceState(str, Enum):
    DISABLED = "disabled"
    WAITING = "waiting"
    RECORDING = "recording"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


ReasonCode = Literal[
    "none_selected",
    "source_absent",
    "collector_stale",
    "retry_exhausted",
    "privilege_denied",
    "dependency_unavailable",
    "custody_invalid",
    "checkpoint_incompatible",
    "upstream_unavailable",
]


@dataclass(frozen=True)
class RetryBudget:
    """Fixed episode policy; lifecycle owners track attempts and stable uptime."""

    retry_limit: int = field(default=5, init=False)
    readiness_timeout_seconds: int = field(default=5, init=False)
    stable_reset_seconds: int = field(default=60, init=False)

    def delay_before(self, attempt: int) -> int:
        """Return the delay before a one-based attempt, rejecting extra attempts."""
        if type(attempt) is not int or not 1 <= attempt <= self.retry_limit:
            raise ValueError("Capture retry attempt must be an integer from 1 to 5.")
        return (0, 2, 4, 8, 16)[attempt - 1]


@dataclass(frozen=True)
class CaptureSnapshot:
    """Additive status values only; defaults convey unknown, not running truth."""

    capture_type: CaptureIntent | None = None
    backend: CaptureBackend | None = None
    source_state: SourceState = SourceState.DEGRADED
    reason_code: ReasonCode | None = None
    retry_attempt: int | None = None
    retry_limit: int | None = None
    retry_in_seconds: float | None = None
    retry_exhausted: bool | None = None
    observation_age_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.capture_type is not None:
            object.__setattr__(self, "capture_type", CaptureIntent(self.capture_type))
        if self.backend is not None:
            object.__setattr__(self, "backend", CaptureBackend(self.backend))
        object.__setattr__(self, "source_state", SourceState(self.source_state))
        if self.reason_code is not None and self.reason_code not in get_args(ReasonCode):
            raise ValueError("Capture reason_code must be an allowlisted code.")
        if self.retry_attempt is not None and (type(self.retry_attempt) is not int or not 0 <= self.retry_attempt <= 5):
            raise ValueError("Capture retry_attempt must be an integer from 0 to 5.")
        if self.retry_limit is not None and (type(self.retry_limit) is not int or self.retry_limit != 5):
            raise ValueError("Capture retry_limit must be 5.")
        for name in ("retry_in_seconds", "observation_age_seconds"):
            value = getattr(self, name)
            if value is not None and (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value < 0
                or (name == "retry_in_seconds" and value > 16)
            ):
                raise ValueError(f"Capture {name} is outside its finite nonnegative domain.")
        if self.retry_exhausted is not None and type(self.retry_exhausted) is not bool:
            raise ValueError("Capture retry_exhausted must be a boolean or null.")


ADAPTER_SNAPSHOT_PATH = "/tmp/otalon-capture-adapter-state.json"
ADAPTER_SNAPSHOT_MAX_BYTES = 4096
ADAPTER_SNAPSHOT_FRESHNESS_SECONDS = 6


@dataclass(frozen=True)
class AdapterSnapshot:
    """Ephemeral child evidence, not custody, publication proof, or public status."""

    state: SourceState
    generation: str
    child_pid: int
    updated_monotonic: float
    reason_code: ReasonCode | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", SourceState(self.state))
        if not isinstance(self.generation, str) or not 1 <= len(self.generation) <= 128:
            raise ValueError("Adapter snapshot generation must be bounded and nonempty.")
        if type(self.child_pid) is not int or self.child_pid <= 0:
            raise ValueError("Adapter snapshot child_pid must be positive.")
        if (
            type(self.updated_monotonic) not in (int, float)
            or not math.isfinite(self.updated_monotonic)
            or self.updated_monotonic < 0
        ):
            raise ValueError("Adapter snapshot instant must be finite and nonnegative.")
        if self.reason_code is not None and self.reason_code not in get_args(ReasonCode):
            raise ValueError("Adapter snapshot reason_code must be allowlisted.")

    @classmethod
    def from_bytes(cls, data: bytes, *, generation: str, child_pid: int, now: float) -> Self | None:
        """Ignore oversized, malformed, mismatched, future, or stale evidence.

        The coordinator must cap the file read itself at MAX_BYTES + 1. Atomic
        replacement and heartbeat production belong to the lifecycle owner.
        """
        if len(data) > ADAPTER_SNAPSHOT_MAX_BYTES or not math.isfinite(now):
            return None
        try:
            snapshot = cls(**json.loads(data))
        except (ValueError, TypeError, RecursionError):
            return None
        if snapshot.generation != generation or snapshot.child_pid != child_pid:
            return None
        if not 0 <= now - snapshot.updated_monotonic < ADAPTER_SNAPSHOT_FRESHNESS_SECONDS:
            return None
        return snapshot
