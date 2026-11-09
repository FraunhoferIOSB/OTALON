"""SNMP single-target scan module.

Startup-time side effect (Phase 4 of ``harden-otalon-scan-security``):
when the environment variable ``CS_SNMP_LOG_COMMUNITY`` is set to the
exact string ``"1"`` at the moment this package is first imported, a
single WARNING-level log line is emitted to make the operational risk
(SNMP community strings logged in cleartext) visible during routine log
review.

Placement rationale: the warning lives here — at package import time —
rather than in the FastAPI service's lifespan startup, because

1. The snmp_scan module is also runnable as a standalone CLI
   (``python -m otalon_scan.modules.snmp_scan.start``) and as a unit-test target;
   the service lifespan does not cover those entry points.
2. Importing this package is the necessary precondition for any code
   path that could log the community, so an import-time warning cannot
   be bypassed by a code path that skips the FastAPI lifespan.
3. Module import happens exactly once per process; the
   ``_warned_once`` guard below makes the "exactly one WARNING line"
   guarantee robust against pytest's import-cache shenanigans
   (``importlib.reload``).

The warning text is matched by the unit test in
``otalon-scan/tests/unit/test_snmp_redaction.py`` — keep both in sync.
"""

from __future__ import annotations

import os

from loguru import logger

_ENV_FLAG_NAME = "CS_SNMP_LOG_COMMUNITY"
_STARTUP_WARNING = "CS_SNMP_LOG_COMMUNITY=1 active: SNMP community strings will be logged in cleartext"

# Module-level guard so the warning is emitted exactly once per process,
# even across ``importlib.reload`` (which resets module globals — the
# guard then correctly fires once for the new module instance).
_warned_once = False


def _emit_startup_warning_if_enabled() -> None:
    """Emit the cleartext-logging warning at most once when the override is set."""
    global _warned_once
    if _warned_once:
        return
    if os.environ.get(_ENV_FLAG_NAME) == "1":
        logger.warning(_STARTUP_WARNING)
        _warned_once = True


_emit_startup_warning_if_enabled()
