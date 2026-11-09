"""ScanModule Protocol and related error type.

Defines the contract every scan module MUST implement (capability
``scan--module-contract``). Modules are pure scanners: their input is a
validated :class:`ScanConfig`, their output is an asynchronous iterator
of :class:`ScanProgress` events followed by exactly one terminal
:class:`ScanResult`.

Modules MUST NOT:

- open database connections (persistence is owned by the orchestrator,
  see capability ``scan--persistence-ownership``)
- mutate :data:`sys.path`
- call :func:`asyncio.run` (HC8 invariant)
- silently swallow exceptions

Conformance is enforced at orchestrator load time via a runtime
``isinstance(mod_class, ScanModule)`` check (decision D2).
"""

from __future__ import annotations

from typing import AsyncIterator, Protocol, runtime_checkable

from .models import ScanConfig, ScanProgress, ScanResult


class ScanModuleError(Exception):
    """Raised when a scan module fails internally.

    Modules MUST wrap underlying scanner exceptions (``nmap`` subprocess,
    ``pysnmp`` queries, raw-socket I/O, ...) in :class:`ScanModuleError` and
    re-raise; the original cause SHALL be preserved as ``__cause__`` via
    ``raise ScanModuleError(...) from exc``.

    The orchestrator catches this exception, marks the owning scan
    ``FAILED``, writes the message to ``scans.error_message`` and stops
    iteration.
    """


@runtime_checkable
class ScanModule(Protocol):
    """Contract every scan module MUST implement.

    Attributes:
        name: MITRE ATT&CK ICS technique ID + technique key, e.g.
            ``"T0846/arp_scan"``. Used by the orchestrator for logging,
            SSE event correlation and scan-record tagging.
    """

    name: str

    def scan(
        self,
        config: ScanConfig,
    ) -> AsyncIterator[ScanProgress | ScanResult]:
        """Run the scan and yield progress / result events.

        Args:
            config: Pre-validated module configuration. The orchestrator
                rejects malformed configs with HTTP 422 before invoking
                this method; implementations MUST NOT re-validate.

        Yields:
            Zero or more :class:`ScanProgress` events describing
            intermediate findings (one per host, per port-observation,
            or per scanner-specific checkpoint), followed by exactly one
            terminal :class:`ScanResult` whose ``findings`` field carries
            the full discovered device set.

        Raises:
            ScanModuleError: any module-internal failure. Modules MUST
                NOT use bare ``except Exception: pass``.
            asyncio.CancelledError: the orchestrator may cancel a scan
                in flight. Modules MUST clean up resources (subprocess
                children, sockets, file handles) and re-raise.
        """
        ...
