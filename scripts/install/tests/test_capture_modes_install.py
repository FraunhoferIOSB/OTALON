"""Capture-intent/default contracts through real, disposable installer subprocesses."""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

from scripts.install._common import parse_env

try:
    from .test_helpers import InstallerFixture
except ImportError:
    from test_helpers import InstallerFixture


RETIRED_DIAGNOSTIC = (
    "CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE "
    "and import PCAP/PCAPNG through Operations / Data Sources."
)
EXTERNALS = {
    "LITELLM_BASE_URL": "https://capture-test.example.net/v1",
    "LITELLM_API_KEY": "synthetic-capture-external-key",
    "CHAT_LLM_MODEL": "capture-test-chat",
    "JOBS_LLM_MODEL": "capture-test-jobs",
}


class CaptureModesInstallTests(InstallerFixture):
    def setUp(self) -> None:
        super().setUp()
        result = subprocess.run(
            ["git", "-C", str(self.workspace), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(
            Path(result.stdout.strip()).resolve(), self.workspace.resolve()
        )

    @property
    def env_path(self) -> Path:
        return self.workspace / ".env.compose"

    def snapshot(self, path: Path) -> tuple[bytes, tuple[int, ...]]:
        info = path.stat()
        return path.read_bytes(), (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
            info.st_mtime_ns,
        )

    def run_preserved(
        self, script: str, *args: str, expected: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Check bytes/metadata without exposing generated fixture credentials on failure."""
        sample_path = self.workspace / ".env.compose.sample"
        sample_before = self.snapshot(sample_path)
        before = self.snapshot(self.env_path) if self.env_path.exists() else None
        names = {path.name for path in self.workspace.iterdir()}
        result = self.run_script(script, *args)
        self.assertTrue(self.snapshot(sample_path) == sample_before, "sample changed")
        after = self.snapshot(self.env_path) if self.env_path.exists() else None
        if before is None:
            self.assertEqual(
                {path.name for path in self.workspace.iterdir()},
                names | {".env.compose"},
            )
            self.assertIsNotNone(after)
            self.assertEqual(after[1][4], 0o660)
        else:
            self.assertEqual({path.name for path in self.workspace.iterdir()}, names)
            self.assertIsNotNone(after)
            if expected is None:
                self.assertTrue(after == before, "configured bytes/metadata changed")
            else:
                self.assertTrue(after[0] == expected, "unexpected rendered bytes")
                self.assertEqual(after[1][:-1], before[1][:-1])
        output = result.stdout + result.stderr
        if after is not None:
            for line in after[0].decode("utf-8").splitlines():
                if line.startswith(
                    ("POSTGRES_PASSWORD=", "INFLUX_TOKEN=", "ADMIN_API_KEY=")
                ):
                    value = line.split("=", 1)[1]
                    if value and not value.startswith("<SET_"):
                        self.assertTrue(value not in output, "credential echoed")
        return result

    def configured(self) -> str:
        result = self.run_preserved("setup.py", "--without-ai")
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.env_path.read_text(encoding="utf-8")

    def change(self, text: str, assignments: dict[str, str]) -> str:
        for key, value in assignments.items():
            text = self.replace_assignment(text, key, value)
        return text

    def remove(self, text: str, key: str) -> str:
        document = parse_env(text)
        line = f"{key}={document.values[key]}\n"
        return self.replace_exact_once(text, line, "")

    def write_case(self, text: str, expected_values: dict[str, str]) -> None:
        self.env_path.write_text(text, encoding="utf-8")
        document = parse_env(text)
        for key, expected in expected_values.items():
            self.assertEqual(document.resolved[key], expected)

    def assert_check(
        self, expected_key: str | None, *args: str
    ) -> subprocess.CompletedProcess[str]:
        result = self.run_preserved("check.py", *args)
        self.assertEqual(
            result.returncode, 0 if expected_key is None else 1, result.stderr
        )
        if expected_key is not None:
            self.assertIn(expected_key, result.stderr)
        self.assertNotIn("postgresql://", result.stdout + result.stderr)
        self.assertNotIn("<SET_", result.stdout + result.stderr)
        return result

    def test_new_setup_defaults_and_identical_rerun(self) -> None:
        text = self.configured()
        document = parse_env(text)
        self.assertEqual(document.resolved["CAPTURE_TYPE"], "NONE")
        self.assertEqual(document.resolved["CAPTURE_SOURCE"], "")
        self.assertEqual(
            int(document.resolved["PCAP_IMPORT_MAX_UPLOAD_BYTES"]), 1024 * 1024 * 1024
        )
        sample = parse_env((self.workspace / ".env.compose.sample").read_text())
        self.assertEqual(list(document.values), list(sample.values))
        self.assertIn("# Host and platform\n", text)
        self.assert_check(None, "--without-ai")
        rerun = self.run_preserved("setup.py", "--without-ai")
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("Updated 0 keys", rerun.stdout)

    def test_existing_live_source_limit_key_comments_and_metadata_preserved(
        self,
    ) -> None:
        original = self.configured()
        configured = {
            "CAPTURE_TYPE": "LIVE",
            "CAPTURE_SOURCE": "owned-test0",
            "PCAP_IMPORT_MAX_UPLOAD_BYTES": "8388608",
            "ADMIN_API_KEY": "synthetic-existing-key-kept",
        }
        for key, value in configured.items():
            self.assertTrue(
                parse_env(original).resolved[key] != value, f"{key} is not nondefault"
            )
        text = self.change(original, configured)
        text = self.replace_exact_once(
            text, "# Host and platform\n", "# Operator capture choices stay.\n"
        )
        text = text.replace("\n", "\r\n").rstrip("\r\n")
        self.write_case(text, configured)
        self.env_path.chmod(0o640)
        for args in ((), ("--without-ai",)):
            result = self.run_preserved("setup.py", *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Updated 0 keys", result.stdout)
        self.assert_check(None, "--without-ai")

    def test_missing_capture_defaults_render_sample_values_only(self) -> None:
        original = self.configured()
        missing = ("CAPTURE_TYPE", "CAPTURE_SOURCE", "PCAP_IMPORT_MAX_UPLOAD_BYTES")
        text = original
        for key in missing:
            text = self.remove(text, key)
        self.write_case(text, {})
        self.assertTrue(all(key not in parse_env(text).resolved for key in missing))
        expected = self.replace_exact_once(
            text,
            "SCAN_SOURCE=enp4s0\n",
            "CAPTURE_TYPE=NONE\nCAPTURE_SOURCE=\nSCAN_SOURCE=enp4s0\n",
        )
        expected = self.replace_exact_once(
            expected,
            "PCAP_IMPORT_WORKER_HOST=otalon-capture-pcap-import\n",
            "PCAP_IMPORT_MAX_UPLOAD_BYTES=1073741824\n"
            "PCAP_IMPORT_WORKER_HOST=otalon-capture-pcap-import\n",
        )
        result = self.run_preserved(
            "setup.py", "--without-ai", expected=expected.encode()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = parse_env(self.env_path.read_text())
        self.assertEqual(document.resolved["CAPTURE_TYPE"], "NONE")
        self.assertEqual(document.resolved["CAPTURE_SOURCE"], "")
        self.assertEqual(
            document.resolved["PCAP_IMPORT_MAX_UPLOAD_BYTES"], "1073741824"
        )
        rerun = self.run_preserved("setup.py", "--without-ai")
        self.assertEqual(rerun.returncode, 0, rerun.stderr)

    def test_missing_intent_defaults_none_even_if_sample_marks_it_required(
        self,
    ) -> None:
        text = self.change(
            self.configured(), {"CAPTURE_SOURCE": "<SET_UNUSED_CAPTURE>"}
        )
        text = self.remove(text, "CAPTURE_TYPE")
        self.write_case(text, {"CAPTURE_SOURCE": "<SET_UNUSED_CAPTURE>"})
        sample_path = self.workspace / ".env.compose.sample"
        sample = self.change(
            sample_path.read_text(), {"CAPTURE_TYPE": "<SET_CAPTURE_TYPE>"}
        )
        sample_path.write_text(sample)
        self.assert_check(None, "--without-ai")
        self.assert_check(None, "--without-ai", "--desktop")

    def test_none_unused_sources_work_without_generation_or_preparation(self) -> None:
        original = self.change(self.configured(), {"CAPTURE_TYPE": "NONE"})
        for label, source in (
            ("missing", None),
            ("empty", ""),
            ("placeholder", "<SET_UNUSED_CAPTURE>"),
        ):
            with self.subTest(case=label):
                text = (
                    self.remove(original, "CAPTURE_SOURCE")
                    if source is None
                    else self.change(original, {"CAPTURE_SOURCE": source})
                )
                self.write_case(text, {"CAPTURE_TYPE": "NONE"})
                for args in (("--without-ai",), ("--without-ai", "--desktop")):
                    self.assert_check(None, *args)
                expected = (
                    self.replace_exact_once(
                        text,
                        "SCAN_SOURCE=enp4s0\n",
                        "CAPTURE_SOURCE=\nSCAN_SOURCE=enp4s0\n",
                    ).encode()
                    if source is None
                    else None
                )
                result = self.run_preserved(
                    "setup.py", "--without-ai", expected=expected
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_required_and_global_source_exemptions_are_consistent(self) -> None:
        original = self.configured()
        sample_path = self.workspace / ".env.compose.sample"
        sample = self.change(
            sample_path.read_text(),
            {
                "CAPTURE_SOURCE": "<SET_CAPTURE_SOURCE>",
                "SCAN_SOURCE": "<SET_SCAN_SOURCE>",
            },
        )
        sample_path.write_text(sample)
        for mode in ("NONE", "LIVE"):
            with self.subTest(mode=mode):
                text = self.change(
                    original,
                    {
                        "CAPTURE_TYPE": mode,
                        "CAPTURE_SOURCE": "<SET_UNUSED_CAPTURE>",
                        "SCAN_SOURCE": "",
                    },
                )
                self.write_case(text, {"CAPTURE_TYPE": mode})
                self.assert_check(None, "--without-ai", "--desktop")
                native = self.assert_check(
                    "SCAN_SOURCE" if mode == "NONE" else "CAPTURE_SOURCE",
                    "--without-ai",
                )
                if mode == "NONE":
                    self.assertNotIn("CAPTURE_SOURCE", native.stderr)
                text = self.change(text, {"SCAN_SOURCE": "<SET_UNUSED_SCAN>"})
                self.write_case(text, {"SCAN_SOURCE": "<SET_UNUSED_SCAN>"})
                self.assert_check("SCAN_SOURCE", "--without-ai", "--desktop")

    def test_live_native_missing_empty_and_unsafe_sources_fail_key_only(self) -> None:
        original = self.change(self.configured(), {"CAPTURE_TYPE": "LIVE"})
        sources = (
            None,
            "",
            "<SET_LIVE_SOURCE>",
            "'bad source'",
            "-option",
            ".hidden",
            "bad/name",
            "bad;name",
            "a" * 16,
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index):
                text = (
                    self.remove(original, "CAPTURE_SOURCE")
                    if source is None
                    else self.change(original, {"CAPTURE_SOURCE": source})
                )
                self.write_case(text, {"CAPTURE_TYPE": "LIVE"})
                native = self.assert_check("CAPTURE_SOURCE", "--without-ai")
                if source:
                    self.assertNotIn(source.strip("'"), native.stdout + native.stderr)
                self.assert_check(None, "--without-ai", "--desktop")

    def test_syntactically_absent_interfaces_are_locally_valid(self) -> None:
        original = self.configured()
        for source in ("0", "_", "absent0", "a" * 15, "owned.1:2-test"):
            with self.subTest(source=source):
                self.write_case(
                    self.change(
                        original, {"CAPTURE_TYPE": "LIVE", "CAPTURE_SOURCE": source}
                    ),
                    {"CAPTURE_SOURCE": source},
                )
                result = self.assert_check(None, "--without-ai")
                self.assertNotIn("recording", result.stdout.lower())

    def test_trimmed_quoted_and_resolved_intents(self) -> None:
        original = self.configured()
        for mode in ("' NONE '", '" LIVE "', '"${TZ}"'):
            with self.subTest(mode=mode):
                text = self.change(
                    original, {"CAPTURE_TYPE": mode, "CAPTURE_SOURCE": "absent0"}
                )
                if "${TZ}" in mode:
                    text = self.change(text, {"TZ": "' NONE '"})
                self.write_case(text, {})
                self.assertIn(
                    parse_env(text).resolved["CAPTURE_TYPE"].strip(), ("NONE", "LIVE")
                )
                self.assert_check(None, "--without-ai")
                self.assert_check(None, "--without-ai", "--desktop")

    def test_invalid_and_retired_intent_precedes_required_values(self) -> None:
        original = self.configured()
        for value in (
            "",
            "none",
            "live",
            "AUTO",
            "'LIVE NONE'",
            "unknown-intent",
            "PCAP",
            "' PCAP '",
        ):
            with self.subTest(case=value):
                text = self.change(
                    original,
                    {
                        "CAPTURE_TYPE": value,
                        "CAPTURE_SOURCE": "source-do-not-echo",
                        "ADMIN_API_KEY": "<SET_MISSING_AUTH>",
                    },
                )
                self.write_case(text, {})
                for args in (
                    (),
                    ("--syntax-only",),
                    ("--without-ai",),
                    ("--without-ai", "--desktop"),
                ):
                    result = self.assert_check("CAPTURE_TYPE", *args)
                    expected = (
                        RETIRED_DIAGNOSTIC
                        if parse_env(text).resolved["CAPTURE_TYPE"].strip() == "PCAP"
                        else "CAPTURE_TYPE must be NONE or LIVE for service startup."
                    )
                    self.assertEqual(result.stderr.strip(), expected)
                    self.assertNotIn(
                        "source-do-not-echo", result.stdout + result.stderr
                    )

    def test_none_retains_db_auth_registry_build_and_active_ai_checks(self) -> None:
        original = self.change(self.configured(), {"CAPTURE_TYPE": "NONE", **EXTERNALS})
        cases = (
            ("POSTGRES_PASSWORD", "not-a-hex-password"),
            ("INFLUX_TOKEN", "not-an-influx-token"),
            ("POSTGRES_DSN", "mysql://synthetic.invalid/db"),
            ("CHAT_DB_DSN", "postgresql://user:synthetic@wrong-host:5432/db"),
            ("ADMIN_API_KEY", ""),
            ("PCAP_IMPORT_WORKER_TOKEN", ""),
            ("OTALON_API_ALLOWED_KEYS", "unexpected:operator:synthetic"),
            ("OTALON_SCAN_ALLOWED_KEYS", "unexpected:viewer:synthetic"),
            ("WORKSPACE_DIR", "/different/absolute/workspace"),
            ("OTALON_BUILD_REF", "<SET_BUILD_REF>"),
            ("PCAP_BUFFER_DIR", "<SET_EVIDENCE_PATH>"),
            ("PCAP_LOG_FILE", "<SET_CAPTURE_LOG>"),
            ("SCAN_SOURCE", "<SET_SCAN_SOURCE>"),
            ("CHAT_LLM_MODEL", "'bad alias'"),
            ("LITELLM_BASE_URL", "https://offline.invalid/v1"),
            ("LITELLM_API_KEY", "<SET_EXTERNAL_KEY>"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                self.write_case(self.change(original, {key: value}), {})
                self.assert_check(key)
                if key not in EXTERNALS:
                    self.assert_check(key, "--without-ai")
                else:
                    self.assert_check(None, "--without-ai")

    def test_inactive_capture_grammar_remains_strict_and_single_quotes_literal(
        self,
    ) -> None:
        original = self.change(self.configured(), {"CAPTURE_TYPE": "NONE"})
        for value in (
            "${UNASSIGNED_CAPTURE}",
            "${",
            "${BROKEN",
            "$NAME",
            "'unmatched",
        ):
            with self.subTest(case=value):
                text = self.change(original, {"CAPTURE_SOURCE": value})
                self.env_path.write_text(text)
                for args in (("--without-ai",), ("--without-ai", "--desktop")):
                    self.assert_check("CAPTURE_SOURCE", *args)
                result = self.run_preserved("setup.py", "--without-ai")
                self.assertEqual(result.returncode, 1)
                self.assertIn("CAPTURE_SOURCE", result.stderr)
                self.assertNotIn(value, result.stderr)
        literal = "'${UNASSIGNED_CAPTURE}'"
        self.write_case(
            self.change(original, {"CAPTURE_SOURCE": literal}),
            {"CAPTURE_SOURCE": "${UNASSIGNED_CAPTURE}"},
        )
        self.assert_check(None, "--without-ai")
