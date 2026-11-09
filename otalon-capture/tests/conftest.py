"""Pytest configuration for the capture module and subpackages."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

# Ensure both otalon_capture and pcap_recorder packages are importable in tests
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

NETCAP_PKG = SRC_ROOT / "otalon_capture"
PCAP_PKG = SRC_ROOT / "pcap_recorder"

for package_path in (NETCAP_PKG, PCAP_PKG):
    if package_path.exists() and str(package_path.parent) not in sys.path:
        sys.path.insert(0, str(package_path.parent))
