"""Regression tests for the legitimate Desktop gateway URL, using the real CLI."""

from __future__ import annotations

try:
    from .test_check import (
        CHAT_ALIAS,
        JOBS_ALIAS,
        SAMPLE_GATEWAY_URL,
        SYNTHETIC_API_KEY,
    )
    from .test_helpers import InstallerFixture
except ImportError:
    from test_check import (
        CHAT_ALIAS,
        JOBS_ALIAS,
        SAMPLE_GATEWAY_URL,
        SYNTHETIC_API_KEY,
    )
    from test_helpers import InstallerFixture


class DesktopGatewayTests(InstallerFixture):
    def configure_external(self) -> None:
        content = (self.workspace / ".env.compose").read_text(encoding="utf-8")
        for key, value in (
            ("LITELLM_API_KEY", SYNTHETIC_API_KEY),
            ("CHAT_LLM_MODEL", CHAT_ALIAS),
            ("JOBS_LLM_MODEL", JOBS_ALIAS),
        ):
            content = self.replace_assignment(content, key, value)
        (self.workspace / ".env.compose").write_text(content, encoding="utf-8")

    def test_normal_check_accepts_default_desktop_gateway_with_configured_external_inputs(
        self,
    ) -> None:
        self.setup_env()
        self.configure_external()
        before = (self.workspace / ".env.compose").read_bytes()
        self.assertIn(("LITELLM_BASE_URL=" + SAMPLE_GATEWAY_URL).encode(), before)
        result = self.run_script("check.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NOT verified", result.stdout)
        self.assertNotIn(SAMPLE_GATEWAY_URL, result.stdout + result.stderr)
        self.assertNotIn(SYNTHETIC_API_KEY, result.stdout + result.stderr)
        self.assertEqual((self.workspace / ".env.compose").read_bytes(), before)

    def test_default_url_does_not_supply_missing_key_or_model_aliases(self) -> None:
        self.setup_env()
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        for key in ("LITELLM_API_KEY", "CHAT_LLM_MODEL", "JOBS_LLM_MODEL"):
            self.assertIn(key, result.stderr)
        self.assertNotIn(SAMPLE_GATEWAY_URL, result.stdout + result.stderr)

    def test_literal_chat_markup_is_not_silently_repaired(self) -> None:
        self.setup_env()
        self.configure_external()
        original = (self.workspace / ".env.compose").read_text(encoding="utf-8")
        for value in (
            "@url:`" + SAMPLE_GATEWAY_URL + "`",
            "`" + SAMPLE_GATEWAY_URL + "`",
            "@url:" + SAMPLE_GATEWAY_URL,
        ):
            with self.subTest(wrapper=value.split(":", 1)[0]):
                content = self.replace_assignment(original, "LITELLM_BASE_URL", value)
                (self.workspace / ".env.compose").write_text(content, encoding="utf-8")
                for args in ((), ("--syntax-only",)):
                    result = self.run_script("check.py", *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("LITELLM_BASE_URL", result.stderr)
                    self.assertNotIn(value, result.stdout + result.stderr)
                    self.assertEqual(
                        (self.workspace / ".env.compose").read_text(encoding="utf-8"),
                        content,
                    )
