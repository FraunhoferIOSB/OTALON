"""Subprocess coverage for setup.py using disposable local workspaces."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

try:
    from .test_helpers import INSTALL_DIR, InstallerFixture
except ImportError:
    from test_helpers import INSTALL_DIR, InstallerFixture


class SetupTests(InstallerFixture):
    def test_first_creation_generates_distinct_keys_and_rerun_is_identical(
        self,
    ) -> None:
        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LITELLM_API_KEY", result.stdout)
        self.assertNotIn("apiv3_", result.stdout)
        env_path = self.workspace / ".env.compose"
        first = env_path.read_bytes()
        info = env_path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o660)
        values = dict(
            line.split("=", 1)
            for line in first.decode("utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        self.assertEqual(values["WORKSPACE_DIR"], str(self.workspace))
        self.assertRegex(values["POSTGRES_PASSWORD"], re.compile(r"^[0-9a-f]{64}$"))
        self.assertRegex(values["INFLUX_TOKEN"], re.compile(r"^apiv3_[0-9a-f]{64}$"))
        generated_names = (
            "ADMIN_API_KEY",
            "OTALON_API_KEY",
            "OTALON_SCAN_API_KEY",
            "OTALON_API_SCAN_UI_KEY",
            "OTALON_SCAN_VIEWER_KEY",
            "OTALON_MCP_API_KEY",
            "OTALON_AI_UI_KEY",
            "OTALON_AI_INTERNAL_KEY",
            "PCAP_IMPORT_WORKER_TOKEN",
        )
        generated = [values["POSTGRES_PASSWORD"], values["INFLUX_TOKEN"]]
        generated.extend(values[name] for name in generated_names)
        self.assertEqual(len(generated), len(set(generated)))
        self.assertNotEqual(values["PCAP_IMPORT_WORKER_TOKEN"], values["ADMIN_API_KEY"])
        self.assertTrue(values["OTALON_BUILD_REF"])
        self.assertTrue(values["LITELLM_API_KEY"].startswith("<SET_"))

        rerun = self.run_script("setup.py")
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("Updated 0 keys", rerun.stdout)
        self.assertEqual(env_path.read_bytes(), first)
        after = env_path.stat()
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
        )

    def test_custom_env_file_is_created_only_at_requested_path(self) -> None:
        requested = self.workspace / "local" / "installer.env"
        requested.parent.mkdir()
        result = self.run_script("setup.py", "--env-file", str(requested))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(requested.is_file())
        self.assertFalse((self.workspace / ".env.compose").exists())
        self.assertEqual(stat.S_IMODE(requested.stat().st_mode), 0o660)

    def test_repository_sample_variable_order_and_count_are_preserved(self) -> None:
        repository_sample = (
            Path(__file__).resolve().parents[3] / ".env.compose.sample"
        ).read_bytes()
        (self.workspace / ".env.compose.sample").write_bytes(repository_sample)
        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        sample_keys = [
            line.split("=", 1)[0]
            for line in repository_sample.decode("utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        ]
        configured_keys = [
            line.split("=", 1)[0]
            for line in (self.workspace / ".env.compose")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#") and "=" in line
        ]
        self.assertEqual(configured_keys, sample_keys)
        self.assertEqual(len(configured_keys), len(sample_keys))

    def test_existing_values_comments_order_inode_mode_and_owner_are_preserved(
        self,
    ) -> None:
        source = Path(__file__).resolve().parents[3] / ".env.compose.sample"
        source = source.read_text(encoding="utf-8")
        source = self.replace_assignment(
            source, "ADMIN_API_KEY", "operator-value-kept-exactly"
        )
        source = self.replace_assignment(source, "WORKSPACE_DIR", str(self.workspace))
        source = self.replace_assignment(
            source, "OTALON_BUILD_REF", self.expected_revision()
        )
        source = self.replace_exact_once(
            source, "# Host and platform\n", "# Operator comment stays here.\n"
        )
        env_path = self.workspace / ".env.compose"
        env_path.write_bytes(source.encode("utf-8"))
        env_path.chmod(0o660)
        before = env_path.stat()

        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        after_bytes = env_path.read_bytes()
        after = env_path.stat()
        self.assertIn(b"# Operator comment stays here.\n", after_bytes)
        self.assertIn(b"ADMIN_API_KEY=operator-value-kept-exactly\n", after_bytes)
        self.assertLess(
            after_bytes.index(b"POSTGRES_USER="),
            after_bytes.index(b"POSTGRES_PASSWORD="),
        )
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )

    def test_group_writable_service_owned_env_keeps_owner_and_mode(self) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.skipTest(
                "assigning the service owner requires root; parent rootful fixture covers this"
            )
        source = Path(__file__).resolve().parents[3] / ".env.compose.sample"
        source = source.read_text(encoding="utf-8")
        source = self.replace_assignment(source, "WORKSPACE_DIR", str(self.workspace))
        env_path = self.workspace / ".env.compose"
        env_path.write_text(source, encoding="utf-8")
        os.chown(env_path, 10001, 10000)
        env_path.chmod(0o660)
        before = env_path.stat()
        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        after = env_path.stat()
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, 10001, 10000, 0o660),
        )

    def test_empty_and_placeholder_local_values_are_filled(self) -> None:
        source = Path(__file__).resolve().parents[3] / ".env.compose.sample"
        source = source.read_text(encoding="utf-8")
        source = self.replace_assignment(source, "ADMIN_API_KEY", "")
        source = self.replace_assignment(source, "OTALON_API_KEY", "<SET_OLD>")
        source = self.replace_assignment(source, "WORKSPACE_DIR", "")
        source = self.replace_assignment(
            source, "OTALON_BUILD_REF", self.expected_revision()
        )
        (self.workspace / ".env.compose").write_text(source, encoding="utf-8")
        result = self.run_script("setup.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        content = (self.workspace / ".env.compose").read_text(encoding="utf-8")
        self.assertRegex(content, r"(?m)^ADMIN_API_KEY=[0-9a-f]{64}$")
        self.assertRegex(content, r"(?m)^OTALON_API_KEY=[0-9a-f]{64}$")
        self.assertIn(f"WORKSPACE_DIR={self.workspace}", content)

    def test_existing_different_workspace_is_rejected_without_mutation(self) -> None:
        (self.workspace / ".env.compose").write_text(
            "WORKSPACE_DIR=/different/absolute/path\nPOSTGRES_PASSWORD=kept\n",
            encoding="utf-8",
        )
        path = self.workspace / ".env.compose"
        original = path.read_bytes()
        inode = path.stat().st_ino
        result = self.run_script("setup.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WORKSPACE_DIR", result.stderr)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.stat().st_ino, inode)

    def test_invalid_environment_files_fail_before_mutation(self) -> None:
        cases = {
            "duplicate": "POSTGRES_PASSWORD=one\nPOSTGRES_PASSWORD=two\n",
            "malformed": "not an assignment\n",
            "forward-reference": "EARLY=${LATER}\nLATER=value\n",
            "path-traversal-reference": "EARLY=${../LATER}\n",
            "unmatched-quote": "VALUE='incomplete\n",
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.workspace / ".env.compose"
                original = content.encode("utf-8")
                path.write_bytes(original)
                inode = path.stat().st_ino
                result = self.run_script("setup.py")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(path.stat().st_ino, inode)
                path.unlink()

    def test_symlink_file_ancestor_and_nonregular_target_fail_closed(self) -> None:
        env = self.workspace / ".env.compose"
        target = self.workspace / "operator-file"
        target.write_bytes(b"operator bytes\n")
        env.symlink_to(target)
        result = self.run_script("setup.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"operator bytes\n")
        env.unlink()

        directory = self.workspace / "env-dir"
        directory.mkdir()
        nested = self.workspace / "nested"
        nested.symlink_to(directory, target_is_directory=True)
        result = self.run_script("setup.py", "--env-file", "nested/.env.compose")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((directory / ".env.compose").exists())
        nested.unlink()

        env.mkdir()
        result = self.run_script("setup.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(env.is_dir())

    def test_invalid_git_reference_does_not_create_configuration(self) -> None:
        git_dir = self.workspace / ".git"
        for path in git_dir.iterdir():
            if path.is_dir():
                import shutil

                shutil.rmtree(path)
            else:
                path.unlink()
        git_dir.rmdir()
        result = self.run_script("setup.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OTALON_BUILD_REF", result.stderr)
        self.assertFalse((self.workspace / ".env.compose").exists())

    def test_nested_workspace_without_git_does_not_use_outer_repository(self) -> None:
        outer = Path(self._temporary.name) / "outer"
        nested = outer / "nested"
        nested.mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-q", str(outer)], check=True, capture_output=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(outer),
                "-c",
                "user.name=Installer Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "outer",
            ],
            check=True,
            capture_output=True,
        )
        outer_revision = self.expected_revision_for(outer)
        (nested / ".env.compose.sample").write_bytes(
            (self.workspace / ".env.compose.sample").read_bytes()
        )
        self.assertFalse((nested / ".git").exists())

        result = subprocess.run(
            [sys.executable, str(INSTALL_DIR / "setup.py"), "--workspace", str(nested)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OTALON_BUILD_REF", result.stderr)
        self.assertNotIn(outer_revision, result.stdout + result.stderr)
        self.assertFalse((nested / ".env.compose").exists())

    def test_git_worktree_file_workspace_is_accepted(self) -> None:
        linked = Path(self._temporary.name) / "linked"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.workspace),
                "worktree",
                "add",
                "-q",
                "--detach",
                str(linked),
            ],
            check=True,
            capture_output=True,
        )
        self.assertTrue((linked / ".git").is_file())
        (linked / ".env.compose.sample").write_bytes(
            (self.workspace / ".env.compose.sample").read_bytes()
        )
        result = subprocess.run(
            [sys.executable, str(INSTALL_DIR / "setup.py"), "--workspace", str(linked)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        content = (linked / ".env.compose").read_text(encoding="utf-8")
        self.assertIn(
            f"OTALON_BUILD_REF={self.expected_revision_for(linked)}\n", content
        )

    def expected_revision_for(self, path: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def expected_revision(self) -> str:
        import subprocess

        return subprocess.run(
            ["git", "-C", str(self.workspace), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()


if __name__ == "__main__":
    import unittest

    unittest.main()
