"""Regression coverage for the installer's restricted environment parser."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

try:
    from .test_helpers import INSTALL_DIR, InstallerFixture
except ImportError:
    from test_helpers import INSTALL_DIR, InstallerFixture


COMMON_MODULE_NAME = "installer_common_parser_tests"
COMMON_SPEC = importlib.util.spec_from_file_location(
    COMMON_MODULE_NAME, INSTALL_DIR / "_common.py"
)
if COMMON_SPEC is None or COMMON_SPEC.loader is None:
    raise ImportError("Unable to load installer _common.py")
COMMON_MODULE = importlib.util.module_from_spec(COMMON_SPEC)
sys.modules[COMMON_MODULE_NAME] = COMMON_MODULE
COMMON_SPEC.loader.exec_module(COMMON_MODULE)
common: ModuleType = COMMON_MODULE


class ParserTests(InstallerFixture):
    def test_quote_and_expansion_contract(self) -> None:
        document = common.parse_env(
            "FIRST=alpha\n"
            "SINGLE='${FIRST} $FIRST `tick` \\\\ path'\n"
            'DOUBLE="${FIRST}-double"\n'
            "BARE=${FIRST}-bare\n"
        )

        self.assertEqual(
            document.resolved["SINGLE"], "${FIRST} $FIRST `tick` \\\\ path"
        )
        self.assertEqual(document.resolved["DOUBLE"], "alpha-double")
        self.assertEqual(document.resolved["BARE"], "alpha-bare")

    def test_references_and_unsupported_syntax_are_rejected_without_values(
        self,
    ) -> None:
        invalid = (
            ("UNKNOWN=private-unknown-${MISSING}", "UNKNOWN"),
            ("SELF=private-self-${SELF}", "SELF"),
            ("EARLY=${LATER}\nLATER=value", "EARLY"),
            ("BAD=private-malformed-${BROKEN", "BAD"),
            ("BAD=private-dangling-${", "BAD"),
            ("BAD=private-dollar-$", "BAD"),
            ("BAD=private-name-$NAME", "BAD"),
            ("BAD=private-command-$(command)", "BAD"),
            ("BAD=private-backtick-`command`", "BAD"),
            (r"BAD=private-backslash-left\right", "BAD"),
        )
        for text, name in invalid:
            with self.subTest(text=text):
                with self.assertRaises(common.InstallError) as caught:
                    common.parse_env(text)
                self.assertIn(name, str(caught.exception))
                self.assertNotIn("private-", str(caught.exception))
                self.assertNotIn("command", str(caught.exception))

    def test_process_environment_is_not_an_expansion_source(self) -> None:
        with self.subTest("ambient value is not used"):
            previous = os.environ.get("INSTALL_PARSER_EXTERNAL")
            os.environ["INSTALL_PARSER_EXTERNAL"] = "ambient-value"
            try:
                with self.assertRaises(common.InstallError) as caught:
                    common.parse_env("RESULT=${INSTALL_PARSER_EXTERNAL}\n")
            finally:
                if previous is None:
                    os.environ.pop("INSTALL_PARSER_EXTERNAL", None)
                else:
                    os.environ["INSTALL_PARSER_EXTERNAL"] = previous
            self.assertIn("RESULT", str(caught.exception))
            self.assertNotIn("ambient-value", str(caught.exception))

    def test_duplicate_assignments_quotes_and_controls_are_rejected(self) -> None:
        invalid = (
            "NAME=first\nNAME=second\n",
            "NAME='unmatched\n",
            'NAME="unmatched\n',
            "NAME=bad\x00value\n",
            "NAME=bad\tvalue\n",
            "NAME=bad\x85value\n",
            "NAME=bad\u2028value\n",
            "NAME=bad\u2029value\n",
            "NAME=bad\rvalue\n",
        )
        for text in invalid:
            with self.subTest(text=repr(text)):
                with self.assertRaises(common.InstallError) as caught:
                    common.parse_env(text)
                if "\r" not in text:
                    self.assertIn("NAME", str(caught.exception))
                self.assertNotIn("value", str(caught.exception))

    def test_comment_control_errors_report_only_line_numbers(self) -> None:
        with self.assertRaises(common.InstallError) as caught:
            common.parse_env("# first\n# bad\tcomment\n")

        message = str(caught.exception)
        self.assertIn("Environment line 2", message)
        self.assertNotIn("comment", message)
        self.assertNotIn("bad", message)

    def test_noop_render_preserves_line_endings_and_final_newline(self) -> None:
        for raw in (b"NAME=value\n", b"# note\r\nNAME=value", b"NAME=value"):
            with self.subTest(raw=raw):
                document = common.parse_env(raw.decode("utf-8"))
                self.assertEqual(common.render_updated(document, {}), raw)

    def test_setup_rerun_preserves_environment_bytes_and_metadata(self) -> None:
        self.setup_env()
        env_path = self.workspace / ".env.compose"
        original = env_path.read_bytes()
        before = env_path.stat()

        result = self.run_script("setup.py")

        self.assertEqual(result.returncode, 0, result.stderr)
        after = env_path.stat()
        self.assertEqual(env_path.read_bytes(), original)
        self.assertEqual(
            (after.st_ino, after.st_uid, after.st_gid, after.st_mode),
            (before.st_ino, before.st_uid, before.st_gid, before.st_mode),
        )

    def test_input_and_cumulative_expansion_limits_are_enforced(self) -> None:
        with self.assertRaises(common.InstallError):
            common.parse_env("X=" + ("x" * (common.MAX_ENV_BYTES + 1)))

        chain = ["V0=x"]
        for index in range(1, 22):
            previous = f"V{index - 1}"
            chain.append(f"V{index}=${{{previous}}}${{{previous}}}")
        self.assertLess(len("\n".join(chain).encode("utf-8")), common.MAX_ENV_BYTES)
        with self.assertRaises(common.InstallError):
            common.parse_env("\n".join(chain))

    def test_read_regular_rejects_oversized_and_hardlinked_inputs(self) -> None:
        oversized = self.workspace / "oversized.env"
        oversized.write_bytes(b"too large")
        with self.assertRaises(common.InstallError):
            common.read_regular(oversized, max_bytes=2)

        linked = self.workspace / "linked.env"
        linked.write_bytes(b"NAME=value\n")
        alias = self.workspace / "linked-alias.env"
        os.link(linked, alias)
        with self.assertRaises(common.InstallError):
            common.read_regular(linked)

    def test_repeated_failed_reads_do_not_leak_descriptors(self) -> None:
        fd_directory = Path("/proc/self/fd")
        if not fd_directory.is_dir():
            self.skipTest("descriptor-count regression is Linux-specific")

        oversized = self.workspace / "oversized.env"
        oversized.write_bytes(b"too large")
        before = len(os.listdir(fd_directory))
        for _ in range(20):
            with self.assertRaises(common.InstallError):
                common.read_regular(oversized, max_bytes=2)
        after = len(os.listdir(fd_directory))
        self.assertEqual(after, before)

    def test_invalid_environment_cli_inputs_fail_without_mutation(self) -> None:
        shared = self.workspace / "shared"
        shared.mkdir()
        env_path = self.workspace / ".env.compose"
        target = shared / "influx-admin-token.json"
        valid_token = "apiv3_" + "a" * 64
        invalid_inputs = (
            ("malformed", b"INFLUX_TOKEN=${UNKNOWN}\n", False),
            (
                "oversized",
                b"INFLUX_TOKEN=" + (b"a" * common.MAX_ENV_BYTES) + b"\n",
                False,
            ),
            ("hardlinked", f"INFLUX_TOKEN={valid_token}\n".encode("ascii"), True),
        )

        for label, content, make_link in invalid_inputs:
            with self.subTest(case=label):
                env_path.write_bytes(content)
                alias = self.workspace / "env-alias"
                if make_link:
                    os.link(env_path, alias)
                before = env_path.stat()
                original_names = {
                    path.relative_to(self.workspace)
                    for path in self.workspace.rglob("*")
                }

                for script in ("setup.py", "check.py", "bootstrap_influx.py"):
                    result = self.run_script(script)
                    self.assertNotEqual(result.returncode, 0, script)
                    after = env_path.stat()
                    self.assertEqual(env_path.read_bytes(), content)
                    self.assertEqual(
                        (after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                        (before.st_ino, before.st_uid, before.st_gid, before.st_mode),
                    )
                    self.assertFalse(target.exists())
                    self.assertEqual(
                        {
                            path.relative_to(self.workspace)
                            for path in self.workspace.rglob("*")
                        },
                        original_names,
                    )

                if make_link:
                    alias.unlink()
