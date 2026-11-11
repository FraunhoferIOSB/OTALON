"""Subprocess coverage for the non-networking configuration checker."""

from __future__ import annotations

import re
from pathlib import Path

try:
    from .test_helpers import InstallerFixture
except ImportError:
    from test_helpers import InstallerFixture


SAMPLE_GATEWAY_URL = "http://host.docker.internal:4000/v1"
VALID_GATEWAY_URL = "https://proxy.example.net/v1"
SYNTHETIC_API_KEY = "synthetic-opaque-key-0001"
CHAT_ALIAS = "configured-chat-alias"
JOBS_ALIAS = "configured-jobs-alias"


class CheckTests(InstallerFixture):
    @property
    def env_path(self) -> Path:
        return self.workspace / ".env.compose"

    def read_assignment(self, text: str, key: str) -> str:
        """Return the value of the single ``KEY=`` line in ``text``."""
        matches = re.findall(rf"(?m)^{re.escape(key)}=(.*)$", text)
        self.assertEqual(len(matches), 1, f"{key} must be assigned exactly once")
        return matches[0]

    def configure(
        self, overrides: dict[str, str] | None = None, *, gateway: bool = True
    ) -> None:
        """Write explicit non-default external values (and optional overrides) into the local env file.

        The sample gateway URL is kept unless ``gateway`` is true, in which case a
        valid synthetic gateway URL replaces it. Every assignment must occur exactly
        once and must differ from its generated value.
        """
        assignments = {
            "LITELLM_API_KEY": SYNTHETIC_API_KEY,
            "CHAT_LLM_MODEL": CHAT_ALIAS,
            "JOBS_LLM_MODEL": JOBS_ALIAS,
        }
        if gateway:
            assignments["LITELLM_BASE_URL"] = VALID_GATEWAY_URL
        assignments.update(overrides or {})
        content = self.env_path.read_text(encoding="utf-8")
        for key, value in assignments.items():
            self.assertNotEqual(
                self.read_assignment(content, key),
                value,
                f"{key} must change from its generated value",
            )
            content = self.replace_assignment(content, key, value)
        self.env_path.write_text(content, encoding="utf-8")

    def set_assignments(self, assignments: dict[str, str]) -> None:
        """Replace already-configured assignments without the nondefault assertion."""
        content = self.env_path.read_text(encoding="utf-8")
        for key, value in assignments.items():
            content = self.replace_assignment(content, key, value)
        self.env_path.write_text(content, encoding="utf-8")

    def test_syntax_only_does_not_treat_placeholders_as_configuration(self) -> None:
        self.setup_env()
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        for name in ("LITELLM_API_KEY", "CHAT_LLM_MODEL", "JOBS_LLM_MODEL"):
            self.assertIn(name, result.stderr)
        self.assertNotIn("<SET_", result.stderr)

    def test_syntax_only_passes_shapes_with_offline_marker_but_is_explicit(
        self,
    ) -> None:
        self.setup_env()
        self.configure(gateway=False)
        content = self.env_path.read_text(encoding="utf-8")
        self.assertEqual(
            self.read_assignment(content, "LITELLM_BASE_URL"), SAMPLE_GATEWAY_URL
        )
        result = self.run_script("check.py", "--syntax-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NOT checked", result.stdout)
        self.assertIn("syntax-only", result.stdout.lower())

    def test_syntax_only_rejects_unconfigured_gateway_sample_marker(self) -> None:
        self.setup_env()
        self.configure({"LITELLM_BASE_URL": "<SET_LITELLM_BASE_URL>"}, gateway=False)
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LITELLM_BASE_URL", result.stderr)
        self.assertNotIn("<SET_", result.stderr)

    def test_full_check_rejects_missing_external_values_without_exposing_values(
        self,
    ) -> None:
        self.setup_env()
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        for name in ("LITELLM_API_KEY", "CHAT_LLM_MODEL", "JOBS_LLM_MODEL"):
            self.assertIn(name, result.stderr)
        self.assertNotIn("<SET_", result.stderr)
        self.assertNotIn("apiv3_", result.stderr)

    def test_full_check_accepts_shapes_but_disclaims_reachability(self) -> None:
        self.setup_env()
        self.configure()
        result = self.run_script("check.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NOT verified", result.stdout)
        self.assertNotIn("https://proxy.example.net", result.stdout)

    def test_full_check_rejects_default_markers_and_userinfo_urls(self) -> None:
        self.setup_env()
        self.configure({"LITELLM_BASE_URL": "https://gateway.invalid/v1"})
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LITELLM_BASE_URL", result.stderr)

        self.set_assignments(
            {"LITELLM_BASE_URL": "https://user:pass@gateway.example/v1"}
        )
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LITELLM_BASE_URL", result.stderr)
        self.assertNotIn("user:pass", result.stderr)

        self.set_assignments({"LITELLM_BASE_URL": SAMPLE_GATEWAY_URL})
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LITELLM_BASE_URL", result.stderr)

        self.set_assignments(
            {
                "LITELLM_BASE_URL": "https://gateway.example/v1",
                "CHAT_LLM_MODEL": "offline-unconfigured",
            }
        )
        result = self.run_script("check.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CHAT_LLM_MODEL", result.stderr)

    def test_allowlist_must_match_expanded_configured_credentials(self) -> None:
        self.setup_env()
        self.configure()
        content = self.env_path.read_text(encoding="utf-8")
        content = self.replace_exact_once(
            content,
            "ui:operator:${ADMIN_API_KEY}",
            "unexpected:operator:${ADMIN_API_KEY}",
        )
        self.env_path.write_text(content, encoding="utf-8")
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OTALON_API_ALLOWED_KEYS", result.stderr)

    def test_same_environment_grammar_rejects_duplicates_and_bad_shapes(self) -> None:
        self.setup_env()
        self.configure()
        path = self.env_path
        original = path.read_text(encoding="utf-8")
        path.write_text(original + "POSTGRES_PASSWORD=duplicate\n", encoding="utf-8")
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("POSTGRES_PASSWORD", result.stderr)

        forward = self.replace_exact_once(
            original,
            "POSTGRES_USER=postgres\n",
            "EARLY=${POSTGRES_DATABASE}\nPOSTGRES_USER=postgres\n",
        )
        path.write_text(forward, encoding="utf-8")
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EARLY", result.stderr)

        malformed = original.replace(
            "POSTGRES_PASSWORD=", "POSTGRES_PASSWORD=bad\nPOSTGRES_PASSWORD=", 1
        )
        path.write_text(malformed, encoding="utf-8")
        result = self.run_script("check.py", "--syntax-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("POSTGRES_PASSWORD", result.stderr)

    def test_repository_sample_syntax_passes_and_full_check_refuses_default_gateway(
        self,
    ) -> None:
        self.setup_env()
        self.configure(gateway=False)
        content = self.env_path.read_text(encoding="utf-8")
        self.assertEqual(
            self.read_assignment(content, "LITELLM_BASE_URL"), SAMPLE_GATEWAY_URL
        )
        syntax = self.run_script("check.py", "--syntax-only")
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn("NOT checked", syntax.stdout)
        full = self.run_script("check.py")
        self.assertNotEqual(full.returncode, 0)
        self.assertIn("LITELLM_BASE_URL", full.stderr)
        self.assertNotIn("host.docker.internal", full.stderr)

    def test_model_aliases_accept_allowed_ascii_up_to_200_characters(self) -> None:
        for alias in ("provider/model-name_v1.2:tag+x", "a" * 200):
            with self.subTest(length=len(alias)):
                self.setup_env_once()
                self.configure({"CHAT_LLM_MODEL": alias, "JOBS_LLM_MODEL": alias})
                for args in (("--syntax-only",), ()):
                    result = self.run_script("check.py", *args)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_model_aliases_reject_malformed_values_by_name_only(self) -> None:
        invalid = {
            "empty": "",
            "space": "bad alias",
            "control": "bad\x07alias",
            "non_ascii": "bad-\u00e9-alias",
            "disallowed_character": "bad@alias",
            "oversize": "a" * 201,
        }
        for key in ("CHAT_LLM_MODEL", "JOBS_LLM_MODEL"):
            for label, value in invalid.items():
                with self.subTest(key=key, case=label):
                    self.setup_env_once()
                    self.configure()
                    self.set_assignments({key: value})
                    for args in (("--syntax-only",), ()):
                        result = self.run_script("check.py", *args)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(key, result.stderr)
                        if value:
                            self.assertNotIn(value, result.stderr)
                            self.assertNotIn(value, result.stdout)

    def test_service_keys_may_be_opaque_but_not_registry_or_header_unsafe(self) -> None:
        self.setup_env()
        self.configure()
        self.set_assignments({"ADMIN_API_KEY": "opaque-key.v1+/_~"})
        for args in (("--syntax-only",), ()):
            result = self.run_script("check.py", *args)
            self.assertEqual(result.returncode, 0, result.stderr)

        for label, value in (
            ("space", "unsafe key"),
            ("comma", "unsafe,key"),
            ("colon", "unsafe:key"),
            ("control", "unsafe\x07key"),
        ):
            with self.subTest(case=label):
                self.set_assignments({"ADMIN_API_KEY": value})
                for args in (("--syntax-only",), ()):
                    result = self.run_script("check.py", *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("ADMIN_API_KEY", result.stderr)
                    self.assertNotIn(value, result.stderr)
                    self.assertNotIn(value, result.stdout)

    def test_dsn_fields_must_match_resolved_postgres_settings(self) -> None:
        self.setup_env()
        self.configure()
        original = self.env_path.read_text(encoding="utf-8")
        user = self.read_assignment(original, "POSTGRES_USER")
        password = self.read_assignment(original, "POSTGRES_PASSWORD")
        port = self.read_assignment(original, "POSTGRES_PORT")
        database = self.read_assignment(original, "POSTGRES_DATABASE")
        other_password = ("0" if password[0] != "0" else "1") * 64
        mismatches = {
            "user": f"postgresql://other_user:{password}@postgres:{port}/{database}",
            "password": f"postgresql://{user}:{other_password}@postgres:{port}/{database}",
            "host": f"postgresql://{user}:{password}@db.example.net:{port}/{database}",
            "port": f"postgresql://{user}:{password}@postgres:6543/{database}",
            "database": f"postgresql://{user}:{password}@postgres:{port}/other_database",
        }
        for variable in ("POSTGRES_DSN", "CHAT_DB_DSN"):
            for field, dsn in mismatches.items():
                with self.subTest(variable=variable, field=field):
                    self.env_path.write_text(original, encoding="utf-8")
                    self.set_assignments({variable: dsn})
                    for args in (("--syntax-only",), ()):
                        result = self.run_script("check.py", *args)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(variable, result.stderr)
                        self.assertIn(field, result.stderr)
                        self.assertNotIn(password, result.stderr)
                        self.assertNotIn(other_password, result.stderr)
                        self.assertNotIn("postgresql://", result.stderr)

    def test_dsn_validation_accepts_bridge_sample_and_nondefault_settings(self) -> None:
        self.setup_env()
        self.configure()
        content = self.env_path.read_text(encoding="utf-8")
        for variable in ("POSTGRES_DSN", "CHAT_DB_DSN"):
            self.assertIn(
                "@postgres:${POSTGRES_PORT}/${POSTGRES_DATABASE}",
                self.read_assignment(content, variable),
            )
        for args in (("--syntax-only",), ()):
            result = self.run_script("check.py", *args)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_dsn_rejects_non_postgresql_scheme_query_and_fragment(self) -> None:
        self.setup_env()
        self.configure()
        original = self.env_path.read_text(encoding="utf-8")
        user = self.read_assignment(original, "POSTGRES_USER")
        password = self.read_assignment(original, "POSTGRES_PASSWORD")
        port = self.read_assignment(original, "POSTGRES_PORT")
        database = self.read_assignment(original, "POSTGRES_DATABASE")
        self.assertTrue(port.isdecimal())
        suffix = f"{user}:{password}@postgres:{port}/{database}"
        invalid_dsns = (
            f"mysql://{suffix}",
            f"postgresql://{suffix}?sslmode=disable",
            f"postgresql://{suffix}#fragment",
        )

        for variable in ("POSTGRES_DSN", "CHAT_DB_DSN"):
            for dsn in invalid_dsns:
                with self.subTest(variable=variable, dsn_shape=dsn.split(":", 1)[0]):
                    content = self.replace_assignment(original, variable, dsn)
                    self.env_path.write_text(content, encoding="utf-8")
                    for args in (("--syntax-only",), ()):
                        result = self.run_script("check.py", *args)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(variable, result.stderr)
                        self.assertNotIn(dsn, result.stdout + result.stderr)

        self.env_path.write_text(original, encoding="utf-8")
        self.set_assignments(
            {
                "POSTGRES_USER": "otalon_user",
                "POSTGRES_PORT": "6543",
                "POSTGRES_DATABASE": "custom_db",
            }
        )
        for args in (("--syntax-only",), ()):
            result = self.run_script("check.py", *args)
            self.assertEqual(result.returncode, 0, result.stderr)

    def setup_env_once(self) -> None:
        """Regenerate the local env file from the sample for a fresh sub-case."""
        if self.env_path.exists():
            self.env_path.unlink()
        self.setup_env()


if __name__ == "__main__":
    import unittest

    unittest.main()
