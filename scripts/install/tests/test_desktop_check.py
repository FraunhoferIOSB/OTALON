"""Desktop validation accepts no Linux NIC, but preserves local auth checks."""

try:
    from .test_helpers import InstallerFixture
except ImportError:
    from test_helpers import InstallerFixture


class DesktopCheckTests(InstallerFixture):
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
