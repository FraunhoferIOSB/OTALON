"""Fixtures for installer utility subprocess tests."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALL_DIR = REPO_ROOT / "scripts" / "install"
TEST_ROOT = Path(os.environ.get("INSTALL_TEST_ROOT", REPO_ROOT)).resolve()


class InstallerFixture(unittest.TestCase):
    def setUp(self) -> None:
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(
            prefix="install-test-", dir=TEST_ROOT
        )
        self.workspace = Path(self._temporary.name) / "workspace"
        self.workspace.mkdir()
        sample = REPO_ROOT / ".env.compose.sample"
        if not sample.is_file():
            raise RuntimeError(
                "The repository environment sample is required for installer tests"
            )
        (self.workspace / ".env.compose.sample").write_bytes(sample.read_bytes())
        self.initialize_git()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def initialize_git(self) -> None:
        subprocess.run(
            ["git", "init", "-q", str(self.workspace)], check=True, capture_output=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.workspace),
                "-c",
                "user.name=Installer Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "test",
            ],
            check=True,
            capture_output=True,
        )

    def replace_assignment(self, text: str, key: str, value: str) -> str:
        """Replace the value of one ``KEY=`` line, asserting that exactly one line matches."""
        pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
        self.assertEqual(
            len(pattern.findall(text)), 1, f"{key} must be assigned exactly once"
        )
        return pattern.sub(lambda _match: f"{key}={value}", text, count=1)

    def replace_exact_once(self, text: str, old: str, new: str) -> str:
        """Replace a literal fragment, asserting that it occurs exactly once."""
        self.assertEqual(text.count(old), 1, "fixture fragment must occur exactly once")
        return text.replace(old, new, 1)

    def run_script(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(INSTALL_DIR / script),
                "--workspace",
                str(self.workspace),
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def setup_env(self) -> bytes:
        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.workspace / ".env.compose").read_bytes()
