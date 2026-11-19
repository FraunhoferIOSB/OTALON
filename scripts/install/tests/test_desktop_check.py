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
        for document, platform, files in [
            ("INSTALL-WSL.md", "desktop", "docker-compose.yml:docker-compose.wsl.yml"),
            ("INSTALL.md", "native", "docker-compose.yml"),
        ]:
            section = (REPO_ROOT / document).read_text().split("## 3. ", 1)[1].split("## 4. ", 1)[0]
            match = re.search(r"```sh\n(.*?)\n```", section, re.S)
            if match is None:
                self.fail(f"{document} has no executable platform selection")
            script = match.group(1)
            with self.subTest(document=document, platform=platform):
                result = subprocess.run(
                    [
                        "bash", "-c",
                        script
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

    def test_split_guides_keep_platform_steps_and_order(self):
        native = (REPO_ROOT / "INSTALL.md").read_text()
        desktop = (REPO_ROOT / "INSTALL-WSL.md").read_text()
        for document, text, step_count in [
            ("INSTALL.md", native, 13),
            ("INSTALL-WSL.md", desktop, 14),
        ]:
            with self.subTest(document=document):
                steps = [int(value) for value in re.findall(r"(?m)^## (\d+)\. ", text)]
                self.assertEqual(steps, list(range(1, step_count + 1)))
                self.assertIn("--branch wsl-compatible", text)
                self.assertIn("--without-ai", text)
                self.assertLess(text.index("setup.py"), text.index("config --quiet"))
                self.assertLess(text.index("bootstrap_influx.py"), text.index("## 7. "))
                self.assertLess(text.index("upgrade head"), text.index("## 11. "))
                self.assertIn("${OTALON_SERVICES:?Repeat step 3}", text)
                self.assertIn("Preserve", text)
        self.assertIn("[INSTALL-WSL.md](INSTALL-WSL.md)", native)
        self.assertIn("[INSTALL.md](INSTALL.md)", desktop)
        for desktop_only in ["prepare_wsl.py", "--desktop", "```powershell", "docker-compose.wsl.yml"]:
            self.assertNotIn(desktop_only, native)
        for required in ["--desktop", "--receiver-uid 10006", "--root /app/continuous --uid 10006", "--root /app/recovery --uid 10004", "--cap-add CHOWN --cap-add FOWNER", "py -3 C:\\OTALON\\collector.zip", "--cacert", "not release-qualified"]:
            self.assertIn(required, desktop)
        self.assertLess(desktop.index("prepare_wsl.py"), desktop.index("## 6. "))
        self.assertLess(desktop.index("icacls"), desktop.index("--export /mnt/c/OTALON"))

    def test_split_guides_shell_syntax(self):
        for document in ["INSTALL.md", "INSTALL-WSL.md"]:
            text = (REPO_ROOT / document).read_text()
            blocks = re.findall(r"```sh\n(.*?)\n```", text, re.S)
            self.assertGreater(len(blocks), 0)
            for index, block in enumerate(blocks):
                with self.subTest(document=document, block=index):
                    result = subprocess.run(
                        ["bash", "-n"], input=block, capture_output=True, text=True, timeout=10
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

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
