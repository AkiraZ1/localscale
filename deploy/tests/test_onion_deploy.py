#!/usr/bin/env python3
"""Contract tests for the LocalScale Onion deployment templates."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
VALIDATOR = ROOT / "scripts" / "validate-onion.sh"


class OnionDeploymentContractTests(unittest.TestCase):
    def test_templates_exist_and_contain_no_private_key_material(self):
        expected = {"host.env.example", "client.env.example", "torrc.onion-v3.example"}
        self.assertEqual(expected, {p.name for p in TEMPLATES.iterdir()})
        for path in TEMPLATES.iterdir():
            text = path.read_text()
            self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", text)
            self.assertNotIn("BEGIN RSA PRIVATE KEY", text)
            self.assertNotIn("hs_ed25519_secret_key", text)
            self.assertNotIn("PRIVATE_KEY=", text)

    def test_host_and_client_mode_rules(self):
        host = (TEMPLATES / "host.env.example").read_text()
        client = (TEMPLATES / "client.env.example").read_text()
        self.assertIn("LOCALSCALE_ONION_MODE=host", host)
        self.assertIn("LOCALSCALE_ONION_MODE=client", client)
        self.assertIn("LOCALSCALE_ONION_SERVICE_DIR=", host)
        self.assertIn("LOCALSCALE_ONION_SERVICE_DIR=", client)
        self.assertIn("LOCALSCALE_ONION_HOSTNAME=", client)
        self.assertNotIn("LOCALSCALE_ONION_HOSTNAME=", host)

    def test_validator_accepts_templates_and_rejects_invalid_modes(self):
        result = subprocess.run([str(VALIDATOR), "--templates"], text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        result = subprocess.run([str(VALIDATOR), "--mode", "sideways"], text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("hs_ed25519_secret_key", result.stdout + result.stderr)

    def test_env_mode_rules_are_enforced_without_reading_service_dirs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = root / "host.env"
            host.write_text("LOCALSCALE_ONION_MODE=host\nLOCALSCALE_ONION_HOSTNAME=bad.onion\n")
            result = subprocess.run([str(VALIDATOR), "--env", str(host)], text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            client = root / "client.env"
            client.write_text("LOCALSCALE_ONION_MODE=client\\n")
            result = subprocess.run([str(VALIDATOR), "--env", str(client)], text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)

    def test_env_file_must_not_be_group_or_world_readable(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "client.env"
            env_file.write_text("LOCALSCALE_ONION_MODE=client\nLOCALSCALE_ONION_HOSTNAME=replace-with-host-v3-onion-address.onion\n")
            os.chmod(env_file, 0o644)
            result = subprocess.run([str(VALIDATOR), "--env", str(env_file)], text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            os.chmod(env_file, 0o600)
            result = subprocess.run([str(VALIDATOR), "--env", str(env_file)], text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_validator_uses_portable_permission_metadata(self):
        text = VALIDATOR.read_text()
        self.assertIn("stat -c '%a'", text)
        self.assertIn("stat -f '%Lp'", text)

    def test_torrc_is_v3_and_local_only(self):
        text = (TEMPLATES / "torrc.onion-v3.example").read_text()
        self.assertIn("HiddenServiceDir", text)
        self.assertIn("HiddenServicePort 80 127.0.0.1:8080", text)
        self.assertIn("ClientOnionAuthDir", text)
        self.assertNotIn("HiddenServiceVersion 2", text)


if __name__ == "__main__":
    unittest.main()
