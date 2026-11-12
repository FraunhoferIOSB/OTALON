"""Subprocess coverage for the explicit optional-AI installer mode."""

from __future__ import annotations

import re
import stat
from pathlib import Path

try:
    from .test_helpers import InstallerFixture
except ImportError:
    from test_helpers import InstallerFixture


EXTERNAL_KEYS = (
    "LITELLM_BASE_URL",
    "LITELLM_API_KEY",
    "CHAT_LLM_MODEL",
    "JOBS_LLM_MODEL",
)
CONFIGURED_EXTERNALS = {
    "LITELLM_BASE_URL": "http://host.docker.internal:4000/v1",
    "LITELLM_API_KEY": "optional-ai-test-key-do-not-print",
    "CHAT_LLM_MODEL": "optional-chat-model",
    "JOBS_LLM_MODEL": "optional-jobs-model",
}


class OptionalAITests(InstallerFixture):
    @property
    def env_path(self) -> Path:
        return self.workspace / ".env.compose"

    def replace_assignments(self, values: dict[str, str]) -> None:
        content = self.env_path.read_text(encoding="utf-8")
        for key, value in values.items():
            content = self.replace_assignment(content, key, value)
        self.env_path.write_text(content, encoding="utf-8")

    def assignment_values(self) -> dict[str, str]:
        return dict(
            re.findall(
                r"(?m)^([A-Z][A-Z0-9_]*)=(.*)$",
                self.env_path.read_text(encoding="utf-8"),
            )
        )

    def test_check_without_ai_accepts_sample_external_placeholders_without_writing(
        self,
    ) -> None:
        self.setup_env()
        before = self.env_path.read_bytes()

        result = self.run_script("check.py", "--without-ai")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LLM features unavailable", result.stdout)
        self.assertIn("local core configuration passed", result.stdout)
        self.assertNotIn("endpoint reachability", result.stdout.lower())
        self.assertNotIn("served-model availability", result.stdout.lower())
        self.assertNotIn("<SET_", result.stdout + result.stderr)
        self.assertEqual(self.env_path.read_bytes(), before)

    def test_check_without_ai_accepts_empty_and_missing_external_assignments(
        self,
    ) -> None:
        self.setup_env()
        self.replace_assignments({key: "" for key in EXTERNAL_KEYS})
        empty_before = self.env_path.read_bytes()
        empty_result = self.run_script("check.py", "--without-ai")
        self.assertEqual(empty_result.returncode, 0, empty_result.stderr)
        self.assertEqual(self.env_path.read_bytes(), empty_before)

        content = self.env_path.read_text(encoding="utf-8")
        content = re.sub(r"(?m)^CHAT_LLM_MODEL=.*\n", "", content)
        self.env_path.write_text(content, encoding="utf-8")
        missing_before = self.env_path.read_bytes()
        missing_result = self.run_script("check.py", "--without-ai")
        self.assertEqual(missing_result.returncode, 0, missing_result.stderr)
        self.assertEqual(self.env_path.read_bytes(), missing_before)

    def test_check_without_ai_still_rejects_malformed_inactive_field_grammar(
        self,
    ) -> None:
        self.setup_env()
        self.replace_assignments({"CHAT_LLM_MODEL": "${UNASSIGNED_MODEL}"})

        result = self.run_script("check.py", "--without-ai")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CHAT_LLM_MODEL", result.stderr)
        self.assertNotIn("${UNASSIGNED_MODEL}", result.stderr)

    def test_check_without_ai_keeps_local_secret_registry_dsn_and_workspace_checks(
        self,
    ) -> None:
        failures = (
            ({"ADMIN_API_KEY": ""}, "ADMIN_API_KEY"),
            (
                {"OTALON_API_ALLOWED_KEYS": "unexpected:operator:opaque"},
                "OTALON_API_ALLOWED_KEYS",
            ),
            ({"POSTGRES_DSN": "mysql://invalid/local"}, "POSTGRES_DSN"),
            ({"WORKSPACE_DIR": "/different/absolute/workspace"}, "WORKSPACE_DIR"),
        )
        for overrides, expected_error in failures:
            with self.subTest(expected_error=expected_error):
                self.setup_env_once()
                self.replace_assignments(overrides)
                result = self.run_script("check.py", "--without-ai")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)

    def test_configured_ai_remains_strict_by_default_and_accepts_desktop_url(
        self,
    ) -> None:
        self.setup_env()
        default_result = self.run_script("check.py")
        self.assertNotEqual(default_result.returncode, 0)
        self.assertIn("LITELLM_API_KEY", default_result.stderr)

        self.replace_assignments(CONFIGURED_EXTERNALS)
        result = self.run_script("check.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NOT verified", result.stdout)
        self.assertNotIn(CONFIGURED_EXTERNALS["LITELLM_API_KEY"], result.stdout)

    def test_syntax_only_and_without_ai_is_explicit_and_default_stays_strict(
        self,
    ) -> None:
        self.setup_env()

        result = self.run_script("check.py", "--syntax-only", "--without-ai")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("syntax-only", result.stdout.lower())
        self.assertIn("LLM features unavailable", result.stdout)
        self.assertIn("local core configuration passed", result.stdout)
        strict = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn("LITELLM_API_KEY", strict.stderr)

    def test_optional_setup_preserves_sample_external_values_and_file_metadata(
        self,
    ) -> None:
        sample = (self.workspace / ".env.compose.sample").read_text(encoding="utf-8")
        sample_values = dict(re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=(.*)$", sample))

        result = self.run_script("setup.py", "--without-ai")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("optional", result.stdout.lower())
        self.assertIn("AI features unavailable", result.stdout)
        self.assertNotIn("External configuration missing", result.stdout)
        values = self.assignment_values()
        for key in EXTERNAL_KEYS:
            self.assertEqual(values[key], sample_values[key])
        first = self.env_path.read_bytes()
        before = self.env_path.stat()
        rerun = self.run_script("setup.py", "--without-ai")
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertEqual(self.env_path.read_bytes(), first)
        after = self.env_path.stat()
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )

    def test_optional_setup_leaves_empty_and_missing_externals_untouched(self) -> None:
        self.setup_env()
        self.replace_assignments({key: "" for key in EXTERNAL_KEYS})
        first = self.run_script("setup.py", "--without-ai")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("AI features unavailable", first.stdout)
        self.assertNotIn("External configuration missing", first.stdout)
        empty_values = self.assignment_values()
        self.assertTrue(all(empty_values[key] == "" for key in EXTERNAL_KEYS))

        content = self.env_path.read_text(encoding="utf-8")
        content = re.sub(r"(?m)^JOBS_LLM_MODEL=.*\n", "", content)
        self.env_path.write_text(content, encoding="utf-8")
        before = self.env_path.read_bytes()
        missing = self.run_script("setup.py", "--without-ai")
        self.assertEqual(missing.returncode, 0, missing.stderr)
        self.assertNotIn("JOBS_LLM_MODEL=", self.env_path.read_text(encoding="utf-8"))
        self.assertEqual(self.env_path.read_bytes(), before)

    def test_optional_setup_preserves_configured_values_without_printing_them(
        self,
    ) -> None:
        self.setup_env()
        self.replace_assignments(CONFIGURED_EXTERNALS)
        before_values = self.assignment_values()
        result = self.run_script("setup.py", "--without-ai")
        self.assertEqual(result.returncode, 0, result.stderr)
        after_values = self.assignment_values()
        for key in EXTERNAL_KEYS:
            self.assertEqual(after_values[key], before_values[key])
        self.assertNotIn(CONFIGURED_EXTERNALS["LITELLM_API_KEY"], result.stdout)
        self.assertIn("AI features unavailable", result.stdout)

    def test_default_setup_accepts_desktop_gateway_url_as_configured(self) -> None:
        self.setup_env()
        self.replace_assignments(CONFIGURED_EXTERNALS)

        result = self.run_script("setup.py")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("External configuration missing", result.stdout)
        self.assertNotIn("LITELLM_BASE_URL", result.stdout)

    def setup_env_once(self) -> None:
        if self.env_path.exists():
            self.env_path.unlink()
        self.setup_env()
