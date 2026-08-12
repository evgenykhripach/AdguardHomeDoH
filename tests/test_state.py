import json
import os
import tempfile
import unittest
from pathlib import Path

from deploy.lib.state import (
    load_enabled_services,
    load_install_state,
    save_enabled_services,
    save_install_state,
)


class StateTests(unittest.TestCase):
    def test_install_state_round_trip_is_strict_json_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            value = save_install_state(
                path,
                domain="dns.example.com",
                public_ip="203.0.113.10",
                email="admin@example.com",
                version="1.0.0",
                repository="evgenykhripach/AdguardHomeDoH",
            )
            self.assertEqual("dns.example.com", value["domain"])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(
                {
                    "domain": "dns.example.com",
                    "public_ip": "203.0.113.10",
                    "email": "admin@example.com",
                    "version": "1.0.0",
                    "repository": "evgenykhripach/AdguardHomeDoH",
                },
                load_install_state(path),
            )

    def test_enabled_services_are_json_string_array_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enabled-services.json"
            save_enabled_services(path, ["chatgpt", "claude"])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(["chatgpt", "claude"], load_enabled_services(path))
            self.assertEqual(["chatgpt", "claude"], json.loads(path.read_text()))

    def test_state_loader_rejects_extra_or_wrong_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            path.write_text(
                json.dumps(
                    {
                        "domain": "dns.example.com",
                        "public_ip": "203.0.113.10",
                        "email": "admin@example.com",
                        "version": "1.0.0",
                        "repository": "repo",
                        "unexpected": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_install_state(path)

    def test_enabled_services_loader_rejects_non_string_items(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enabled-services.json"
            path.write_text("[\"chatgpt\", 1]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_enabled_services(path)


if __name__ == "__main__":
    unittest.main()
