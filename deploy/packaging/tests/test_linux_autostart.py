import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/packaging/linux/install-autostart.sh"
DESKTOP_TEMPLATE = ROOT / "deploy/packaging/linux/localscale-agent.desktop.in"
START_AGENT = ROOT / "deploy/packaging/linux/start-agent-linux.py"


class LinuxAutostartPackagingTests(unittest.TestCase):
    def test_template_is_xfce_desktop_entry_with_safe_placeholders(self):
        text = DESKTOP_TEMPLATE.read_text()
        self.assertIn("[Desktop Entry]", text)
        self.assertIn("Type=Application", text)
        self.assertIn("X-GNOME-Autostart-enabled=true", text)
        self.assertIn("--no-open", text)
        self.assertIn("@START_AGENT@", text)
        self.assertNotIn("$HOME", text)
        self.assertNotRegex(text, r"(?i)(password|secret|token|client_secret)\\s*=")

    def test_install_is_absolute_idempotent_and_uninstall_is_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            bundle = Path(tmp) / "bundle"
            home.mkdir()
            bundle.mkdir()
            (bundle / "start-agent-linux.py").write_text("#!/usr/bin/env python3\n")
            (bundle / "localscaled").write_text("#!/bin/sh\n")
            env = {**os.environ, "HOME": str(home)}
            first = subprocess.run([str(SCRIPT), "install", str(bundle)], env=env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            entry = home / ".config/autostart/localscale-agent.desktop"
            content = entry.read_text()
            self.assertIn(f"Exec=/usr/bin/python3 {bundle.resolve()}/start-agent-linux.py --no-open", content)
            self.assertIn(f"Path={bundle.resolve()}", content)
            self.assertNotIn("password", content.lower())
            before = entry.stat().st_mtime_ns
            second = subprocess.run([str(SCRIPT), "install", str(bundle)], env=env, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(before, entry.stat().st_mtime_ns)
            removed = subprocess.run([str(SCRIPT), "uninstall"], env=env, text=True, capture_output=True)
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(entry.exists())
            again = subprocess.run([str(SCRIPT), "uninstall"], env=env, text=True, capture_output=True)
            self.assertEqual(again.returncode, 0, again.stderr)

    def test_launcher_has_no_credentials_and_is_python_syntax_valid(self):
        text = START_AGENT.read_text()
        self.assertNotRegex(text, r"(?i)(password|secret|token|client_secret)")
        result = subprocess.run(["python3", "-m", "py_compile", str(START_AGENT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
