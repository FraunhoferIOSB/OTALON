"""Desktop validation accepts no Linux NIC, but preserves local auth checks."""

import os
import re
import subprocess

try:
    from .test_helpers import InstallerFixture, REPO_ROOT
except ImportError:
    from test_helpers import InstallerFixture, REPO_ROOT


class DesktopCheckTests(InstallerFixture):
    def test_documented_platform_selection_keeps_wsl_overlay(self):
        section = (REPO_ROOT / "INSTALL.md").read_text().split("## 3. ", 1)[1].split("## 4. ", 1)[0]
        script = re.search(r"```sh\n(.*?)\n```", section, re.S).group(1)
        for kernel_match, platform, files in [
            (0, "desktop", "docker-compose.yml:docker-compose.wsl.yml"),
            (1, "native", "docker-compose.yml"),
        ]:
            with self.subTest(platform=platform):
                result = subprocess.run(
                    [
                        "bash", "-c",
                        f"grep() {{ return {kernel_match}; }}\n" + script
                        + '\nprintf "%s\\n" "$INSTALL_PLATFORM" "$COMPOSE_FILE" "$INSTALL_AI_ARGS" "$OTALON_SERVICES"',
                    ],
                    cwd=self.workspace,
                    env={**os.environ, "WORKSPACE_DIR": "stale-workspace", "COMPOSE_FILE": "stale-overlay"},
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = result.stdout.splitlines()
                expected_files = ":".join(str(self.workspace / name) for name in files.split(":"))
                self.assertEqual(lines[:3], [platform, expected_files, "--without-ai"])
                self.assertEqual(len(lines[3].split()), 12)
                self.assertNotIn("otalon-ai", lines[3].split())

    def test_desktop_without_linux_capture_interface(self):
        self.setup_env()
        p = self.workspace / ".env.compose"
        text = p.read_text()
        text = self.replace_assignment(text, "CAPTURE_SOURCE", "")
        text = self.replace_assignment(text, "SCAN_SOURCE", "")
        p.write_text(text)
        before = p.read_bytes()
        result = self.run_script("check.py", "--without-ai", "--desktop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Windows collector", result.stdout)
        self.assertEqual(p.read_bytes(), before)
        text = self.replace_assignment(text, "ADMIN_API_KEY", "")
        p.write_text(text)
        rejected = self.run_script("check.py", "--without-ai", "--desktop")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("ADMIN_API_KEY", rejected.stderr)
