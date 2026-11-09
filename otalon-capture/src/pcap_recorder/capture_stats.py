"""Read-only capture-loss observability for the PCAP recorder.

The recorder runs ``tcpdump`` as a long-lived subprocess, so tcpdump's own
"N packets dropped by kernel" summary is only emitted on termination and is
therefore never observed during normal operation. Until now no drop counter
was recorded anywhere, which left capture loss undetectable (PCAP-005).

This module closes that gap by polling ``/proc/net/dev``. It is strictly
observational: nothing here starts, stops, reconfigures or signals the capture
process, and no tcpdump command-line flag is altered.

Counter semantics differ sharply and must not be conflated:

``rx_drop``
    Frames the kernel discarded *after* the NIC handed them over. On a mirror
    or SPAN port this is normally huge and benign: the network stack drops
    frames that are not addressed to the host, while the ``AF_PACKET`` tap
    still receives a full copy. It is therefore NOT a capture-loss indicator,
    and is deliberately never used to raise an alert here.

``rx_fifo`` (a.k.a. ``rx_missed_errors``)
    Frames the NIC could not deliver into host memory at all, typically
    because the ring buffer overran. These never reach any capture socket and
    are genuine capture loss.

Scope limitation (deliberate): the per-socket ``AF_PACKET`` ring-buffer drop
counter (``tp_drops``) is NOT exposed by the kernel to other processes.
``/proc/net/packet`` publishes only ``sk``/``RefCnt``/``Type``/``Proto``/
``Iface``/``R``/``Rmem``/``User``/``Inode`` — there is no drops column. That
counter is readable exclusively by the socket owner via
``getsockopt(PACKET_STATISTICS)``, i.e. by tcpdump itself, and reading it
resets it. Surfacing it would therefore require changing how the capture
process is invoked or signalled, which is a capture-behaviour change and is
explicitly out of scope for this observability-only module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

PROC_NET_DEV = Path("/proc/net/dev")

_DEV_RX_PACKETS_FIELD = 1
_DEV_RX_DROP_FIELD = 3
_DEV_RX_FIFO_FIELD = 4


@dataclass(frozen=True)
class InterfaceCounters:
    """Kernel receive counters for a single network interface.

    Attributes:
        rx_packets: Frames handed to the host stack by the NIC.
        rx_drop: Frames dropped by the stack after reception. Expected to be
            large and benign on a mirror port; not capture loss on its own.
        rx_fifo: Frames the NIC could not deliver into host memory. Genuine
            capture loss.
    """

    rx_packets: int
    rx_drop: int
    rx_fifo: int


@dataclass(frozen=True)
class CaptureLossSnapshot:
    """Deltas observed between two consecutive polls.

    Attributes:
        interface: Capture interface the counters belong to.
        rx_packets: Frames received since the previous poll.
        rx_drop: Stack-level drops since the previous poll (benign on a mirror
            port; reported for context only).
        rx_fifo: NIC-level misses since the previous poll. Genuine capture
            loss.
    """

    interface: str
    rx_packets: int
    rx_drop: int
    rx_fifo: int

    @property
    def has_capture_loss(self) -> bool:
        """Return whether counters indicate genuine loss of captured frames."""

        return self.rx_fifo > 0


def read_interface_counters(interface: str, proc_net_dev: Path = PROC_NET_DEV) -> Optional[InterfaceCounters]:
    """Return receive counters for ``interface`` from ``/proc/net/dev``.

    Args:
        interface: Interface name to look up, e.g. ``enp5s0``.
        proc_net_dev: Override for the procfs path, used by tests.

    Returns:
        The parsed counters, or ``None`` when the interface or the procfs
        entry is unavailable or malformed.
    """

    try:
        content = proc_net_dev.read_text(encoding="utf-8")
    except OSError as error:
        logger.debug("Cannot read {path}: {error}", path=proc_net_dev, error=error)
        return None

    for line in content.splitlines():
        name, separator, remainder = line.partition(":")
        if not separator or name.strip() != interface:
            continue
        fields = remainder.split()
        if len(fields) <= _DEV_RX_FIFO_FIELD:
            logger.debug("Malformed {path} row for {iface}.", path=proc_net_dev, iface=interface)
            return None
        try:
            return InterfaceCounters(
                rx_packets=int(fields[_DEV_RX_PACKETS_FIELD]),
                rx_drop=int(fields[_DEV_RX_DROP_FIELD]),
                rx_fifo=int(fields[_DEV_RX_FIFO_FIELD]),
            )
        except ValueError:
            logger.debug("Non-numeric counters for {iface} in {path}.", iface=interface, path=proc_net_dev)
            return None
    return None


class CaptureLossMonitor:
    """Poll kernel counters and log capture loss for one interface.

    The monitor is purely observational: it never touches the capture process
    and only reports deltas between consecutive :meth:`poll` calls. The first
    poll establishes the baseline and reports nothing.
    """

    def __init__(self, interface: str) -> None:
        """Initialise the monitor for ``interface``.

        Args:
            interface: Capture interface to observe.
        """

        self._interface = interface
        self._previous: Optional[InterfaceCounters] = None

    @property
    def interface(self) -> str:
        """Return the observed interface name."""

        return self._interface

    def poll(self) -> Optional[CaptureLossSnapshot]:
        """Sample counters once and return the delta since the previous call.

        Returns:
            The observed deltas, or ``None`` on the first call or when the
            counters are unavailable.
        """

        current = read_interface_counters(self._interface)
        if current is None:
            return None

        previous, self._previous = self._previous, current
        if previous is None:
            logger.info(
                "Capture-loss baseline for {iface}: rx_packets={packets} rx_drop={drop} rx_fifo={fifo}.",
                iface=self._interface,
                packets=current.rx_packets,
                drop=current.rx_drop,
                fifo=current.rx_fifo,
            )
            return None

        return CaptureLossSnapshot(
            interface=self._interface,
            rx_packets=max(0, current.rx_packets - previous.rx_packets),
            rx_drop=max(0, current.rx_drop - previous.rx_drop),
            rx_fifo=max(0, current.rx_fifo - previous.rx_fifo),
        )

    def poll_and_log(self) -> Optional[CaptureLossSnapshot]:
        """Poll once and emit a log line describing the result.

        Genuine capture loss is logged at ``WARNING``; benign mirror-port stack
        drops are logged at ``DEBUG`` so they cannot mask real incidents.

        Returns:
            The snapshot returned by :meth:`poll`.
        """

        snapshot = self.poll()
        if snapshot is None:
            return None

        if snapshot.has_capture_loss:
            logger.warning(
                "Capture loss on {iface}: rx_fifo={fifo} frames missed by the NIC "
                "(rx_packets={packets}, rx_drop={drop} stack-level/benign on a mirror port).",
                iface=snapshot.interface,
                fifo=snapshot.rx_fifo,
                packets=snapshot.rx_packets,
                drop=snapshot.rx_drop,
            )
        else:
            logger.debug(
                "Capture healthy on {iface}: rx_packets={packets} rx_fifo=0 "
                "(rx_drop={drop} stack-level, benign on a mirror port).",
                iface=snapshot.interface,
                packets=snapshot.rx_packets,
                drop=snapshot.rx_drop,
            )
        return snapshot


def describe_counters(snapshots: List[CaptureLossSnapshot]) -> Dict[str, int]:
    """Aggregate snapshots into a flat mapping for status endpoints.

    Args:
        snapshots: Snapshots to aggregate.

    Returns:
        Summed counters keyed by counter name.
    """

    return {
        "rx_packets": sum(item.rx_packets for item in snapshots),
        "rx_drop": sum(item.rx_drop for item in snapshots),
        "rx_fifo": sum(item.rx_fifo for item in snapshots),
    }
