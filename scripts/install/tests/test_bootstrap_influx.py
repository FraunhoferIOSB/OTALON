"""Subprocess coverage for safe local InfluxDB bootstrap-file creation."""

from __future__ import annotations

import json
import os
import stat

try:
    from .test_helpers import InstallerFixture
except ImportError:
    from test_helpers import InstallerFixture


ROOT_CAN_SET_INFLUX_OWNER = hasattr(os, "geteuid") and os.geteuid() == 0


class BootstrapInfluxTests(InstallerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.shared = self.workspace / "shared"
        self.shared.mkdir()
        self.token = "apiv3_" + "a" * 64
        (self.workspace / ".env.compose").write_text(
            f"INFLUX_TOKEN={self.token}\n", encoding="utf-8"
        )
        self.target = self.shared / "influx-admin-token.json"

    def test_first_bootstrap_creates_exact_schema_with_required_metadata(self) -> None:
        if not ROOT_CAN_SET_INFLUX_OWNER:
            self.skipTest("creating a uid 1500:1500 bootstrap file requires root")
        result = self.run_script("bootstrap_influx.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = self.target.read_bytes()
        self.assertEqual(json.loads(raw), {"token": self.token, "name": "_admin"})
        info = self.target.stat()
        self.assertEqual(
            (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (1500, 1500, 0o600)
        )
        self.assertNotIn(self.token, result.stdout + result.stderr)
        self.assertEqual(set(self.shared.iterdir()), {self.target})

    def test_matching_bootstrap_preserves_bytes_inode_and_correct_metadata(
        self,
    ) -> None:
        if not ROOT_CAN_SET_INFLUX_OWNER:
            self.skipTest("preserving uid 1500:1500 metadata requires root")
        original = (
            b'{ "token" : "'
            + self.token.encode()
            + b'", "name" : "_admin", "metadata" : { "enabled" : true } }\n'
        )
        self.target.write_bytes(original)
        os.chown(self.target, 1500, 1500)
        self.target.chmod(0o600)
        before = self.target.stat()
        result = self.run_script("bootstrap_influx.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )
        self.assertEqual(
            (after.st_atime_ns, after.st_mtime_ns),
            (before.st_atime_ns, before.st_mtime_ns),
        )

    def test_matching_token_with_wrong_mode_is_rejected_without_mutation(self) -> None:
        raw = json.dumps({"token": self.token, "name": "_admin"}).encode("utf-8")
        self.target.write_bytes(raw)
        self.target.chmod(0o640)
        before = self.target.stat()

        result = self.run_script("bootstrap_influx.py")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode 0600", result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), raw)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )

    def test_matching_token_with_wrong_owner_is_rejected_without_mutation(self) -> None:
        if not ROOT_CAN_SET_INFLUX_OWNER:
            self.skipTest("checking a wrong owner requires root")
        raw = json.dumps({"token": self.token, "name": "_admin"}).encode("utf-8")
        self.target.write_bytes(raw)
        os.chown(self.target, 1501, 1500)
        self.target.chmod(0o600)
        before = self.target.stat()

        result = self.run_script("bootstrap_influx.py")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1500:1500", result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), raw)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )

    def test_duplicate_json_keys_at_any_depth_are_rejected_without_mutation(
        self,
    ) -> None:
        invalid = (
            b'{"token":"'
            + self.token.encode()
            + b'","token":"'
            + self.token.encode()
            + b'","name":"_admin"}',
            b'{"token":"'
            + self.token.encode()
            + b'","name":"_admin","extra":{"key":1,"key":2}}',
        )
        for raw in invalid:
            with self.subTest(length=len(raw)):
                self.target.write_bytes(raw)
                before = self.target.stat()
                result = self.run_script("bootstrap_influx.py")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid JSON", result.stderr)
                self.assertNotIn(self.token, result.stdout + result.stderr)
                after = self.target.stat()
                self.assertEqual(self.target.read_bytes(), raw)
                self.assertEqual(
                    (
                        after.st_ino,
                        after.st_uid,
                        after.st_gid,
                        stat.S_IMODE(after.st_mode),
                    ),
                    (
                        before.st_ino,
                        before.st_uid,
                        before.st_gid,
                        stat.S_IMODE(before.st_mode),
                    ),
                )
                self.target.unlink()

    def test_invalid_json_field_types_are_rejected_without_mutation(self) -> None:
        invalid = (
            b'{"token":null,"name":"_admin"}',
            b'{"token":"' + self.token.encode() + b'","name":42}',
        )
        for raw in invalid:
            with self.subTest(length=len(raw)):
                self.target.write_bytes(raw)
                before = self.target.stat()
                result = self.run_script("bootstrap_influx.py")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("schema", result.stderr)
                self.assertNotIn(self.token, result.stdout + result.stderr)
                after = self.target.stat()
                self.assertEqual(self.target.read_bytes(), raw)
                self.assertEqual(
                    (
                        after.st_ino,
                        after.st_uid,
                        after.st_gid,
                        stat.S_IMODE(after.st_mode),
                    ),
                    (
                        before.st_ino,
                        before.st_uid,
                        before.st_gid,
                        stat.S_IMODE(before.st_mode),
                    ),
                )
                self.target.unlink()

    def test_oversized_and_hardlinked_targets_are_rejected_without_mutation(
        self,
    ) -> None:
        oversized = (
            b'{"token":"'
            + self.token.encode()
            + b'","name":"_admin","extra":"'
            + (b"x" * (1024 * 1024))
            + b'"}'
        )
        self.target.write_bytes(oversized)
        before = self.target.stat()
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("size limit", result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), oversized)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )
        self.target.unlink()

        raw = json.dumps({"token": self.token, "name": "_admin"}).encode("utf-8")
        self.target.write_bytes(raw)
        alias = self.shared / "bootstrap-alias.json"
        os.link(self.target, alias)
        before = self.target.stat()
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hard links", result.stderr)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        after = self.target.stat()
        self.assertEqual(self.target.read_bytes(), raw)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )

    def test_mismatched_existing_token_is_rejected_without_mutation(self) -> None:
        raw = b'{"token":"apiv3_' + b"b" * 64 + b'","name":"_admin"}'
        self.target.write_bytes(raw)
        before = self.target.stat()
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs", result.stderr)
        self.assertNotIn("apiv3_", result.stderr)
        after = self.target.stat()
        self.assertEqual(
            (
                after.st_ino,
                after.st_uid,
                after.st_gid,
                after.st_mode,
                after.st_atime_ns,
            ),
            (
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_mode,
                before.st_atime_ns,
            ),
        )
        self.assertEqual(self.target.read_bytes(), raw)

    def test_invalid_json_wrong_name_and_invalid_token_fail_without_mutation(
        self,
    ) -> None:
        for content, expected in (
            (b"not json", "invalid JSON"),
            (json.dumps({"token": self.token, "name": "operator"}).encode(), "name"),
        ):
            with self.subTest(expected=expected):
                self.target.write_bytes(content)
                before = self.target.stat()
                result = self.run_script("bootstrap_influx.py")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                after = self.target.stat()
                self.assertEqual(
                    (
                        after.st_ino,
                        after.st_uid,
                        after.st_gid,
                        after.st_mode,
                        after.st_atime_ns,
                    ),
                    (
                        before.st_ino,
                        before.st_uid,
                        before.st_gid,
                        before.st_mode,
                        before.st_atime_ns,
                    ),
                )
                self.assertEqual(self.target.read_bytes(), content)
                self.target.unlink()

        (self.workspace / ".env.compose").write_text(
            "INFLUX_TOKEN=bad-token\n", encoding="utf-8"
        )
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("INFLUX_TOKEN", result.stderr)
        self.assertFalse(self.target.exists())

    def test_target_and_shared_symlinks_or_directories_are_rejected(self) -> None:
        other = self.workspace / "other.json"
        other.write_bytes(b"operator bytes")
        self.target.symlink_to(other)
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(other.read_bytes(), b"operator bytes")
        self.assertTrue(self.target.is_symlink())
        self.target.unlink()

        self.target.mkdir()
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.target.is_dir())
        self.target.rmdir()

        self.shared.rename(self.workspace / "shared-real")
        self.shared.symlink_to(self.workspace / "shared-real", target_is_directory=True)
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            (self.workspace / "shared-real" / "influx-admin-token.json").exists()
        )

    def test_missing_shared_and_symlink_environment_inputs_are_rejected(self) -> None:
        self.shared.rmdir()
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shared", result.stderr)

        self.shared.mkdir()
        env_path = self.workspace / ".env.compose"
        actual_env = self.workspace / "operator-env"
        actual_env.write_text(f"INFLUX_TOKEN={self.token}\n", encoding="utf-8")
        env_path.unlink()
        env_path.symlink_to(actual_env)
        result = self.run_script("bootstrap_influx.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Symlink", result.stderr)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    import unittest

    unittest.main()
