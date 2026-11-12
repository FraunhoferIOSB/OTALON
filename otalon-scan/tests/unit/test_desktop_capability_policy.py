"""Desktop must reject raw-L2 scans before allocating a process or run UUID."""

import pytest

from otalon_scan.core.module_manager import ModuleManager


def test_desktop_rejects_raw_discovery_before_cleanup_or_process(monkeypatch):
    monkeypatch.setenv("OTALON_PLATFORM", "desktop")
    manager = ModuleManager.__new__(ModuleManager)

    def forbidden():
        raise AssertionError("raw-L2 must refuse before runtime bookkeeping")

    manager._clean_up_finished_modules = forbidden
    for name in ["arp_scan", "pn_discovery"]:
        with pytest.raises(ValueError, match="Desktop"):
            manager.start_module(name)
