"""Subprocess management for the tcpdump based PCAP recorder."""

from __future__ import annotations

import shlex
import subprocess
import threading
from pathlib import Path
from typing import IO, List, Optional

from loguru import logger

from .settings import PcapConfig


class TcpdumpRecorder:
    """Manage the lifecycle of a tcpdump subprocess."""

    def __init__(self, config: PcapConfig) -> None:
        self._config = config
        self._ringbuffer_path = Path(config.ringbuffer.directory)
        self._ringbuffer_path.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._process: Optional[subprocess.Popen[str]] = None
        self._stderr_thread: Optional[threading.Thread] = None

    @property
    def interface(self) -> str:
        """Return the configured capture interface name.

        The value is sourced from :class:`PcapConfig`; it is never derived
        from a host scan.
        """

        return self._config.interface

    @property
    def is_running(self) -> bool:
        """Return whether the tcpdump subprocess is currently alive.

        This is a read-only poll of the managed subprocess handle; it does
        not start, stop or otherwise mutate the recorder. ``poll()`` returns
        ``None`` while the child is still running.
        """

        with self._lock:
            return self._process is not None and self._process.poll() is None

    def build_command(self) -> List[str]:
        """Return the tcpdump command derived from ``PcapConfig``."""

        output_pattern = self._ringbuffer_path / "%Y%m%d_%H%M%S.pcap"
        command = [
            "tcpdump",
            "-i",
            self._config.interface,
            "-G",
            str(self._config.chunk_duration_sec),
            "-w",
            str(output_pattern),
            "-nn",
            "-s",
            "0",
            "-Z",
            "root",
        ]
        if self._config.bpf_filter:
            command.extend(shlex.split(self._config.bpf_filter))
        return command

    def start(self) -> None:
        """Start tcpdump if it is not already running."""

        with self._lock:
            if self._process is not None and self._process.poll() is None:
                raise RuntimeError("TcpdumpRecorder is already running.")
            command = self.build_command()
            logger.info("Starting tcpdump recorder: {command}", command=" ".join(command))
            try:
                self._process = subprocess.Popen(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError as error:
                raise RuntimeError("tcpdump executable not found on PATH.") from error
            except Exception as error:  # noqa: BLE001 - propagate meaningful message
                raise RuntimeError("Failed to start tcpdump process.") from error
            # PCAP-014: stderr must reach the log instead of vanishing into
            # DEVNULL. A bad interface ("no such device") otherwise dies
            # silently while the recorder looks healthy.
            stream = self._process.stderr
            if stream is not None:
                self._stderr_thread = threading.Thread(
                    target=self._drain_stderr,
                    args=(stream,),
                    daemon=True,
                    name="tcpdump-stderr",
                )
                self._stderr_thread.start()

    def _drain_stderr(self, stream: IO[str]) -> None:
        """Log every line the tcpdump subprocess writes to stderr (PCAP-014).

        Reads until EOF (subprocess exit) so startup failures such as
        ``no such device`` and runtime warnings both become visible log
        lines. Runs as a daemon thread; it never takes the instance lock.
        """
        try:
            for line in stream:
                stripped = line.rstrip()
                if stripped:
                    logger.error("tcpdump stderr: {line}", line=stripped)
        finally:
            stream.close()

    def stop(self, timeout_s: float = 5.0) -> None:
        """Stop tcpdump gracefully and ensure the subprocess is cleaned up."""

        with self._lock:
            if self._process is None:
                return
            logger.info("Stopping tcpdump recorder.")
            self._process.terminate()
            try:
                self._process.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "tcpdump did not exit within {timeout}s. Sending SIGKILL.",
                    timeout=timeout_s,
                )
                self._process.kill()
                self._process.wait(timeout=timeout_s)
            finally:
                # PCAP-014: the drain thread ends at pipe EOF once the child
                # is gone; join briefly so a straggler line still gets logged.
                thread = self._stderr_thread
                if thread is not None and thread.is_alive():
                    thread.join(timeout=2.0)
                self._stderr_thread = None
                self._process = None
