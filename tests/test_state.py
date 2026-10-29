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

    def test_install_state_keeps_an_optional_relay_exit_host(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            save_install_state(path, **common)
            self.assertNotIn("relay", load_install_state(path))
            save_install_state(path, relay="203.0.113.99", **common)
            self.assertEqual("203.0.113.99", load_install_state(path)["relay"])
            # Forwarding to ourselves would loop every routed connection.
            with self.assertRaises(ValueError):
                save_install_state(path, relay="203.0.113.10", **common)
            for bad in ("2001:db8::1", "relay.example.com", ""):
                if bad:
                    with self.assertRaises(ValueError):
                        save_install_state(path, relay=bad, **common)

    def test_install_state_keeps_local_sites_served_behind_the_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            save_install_state(path, local_sites=["app.example.org=127.0.0.1:9443", "*=127.0.0.1:9443"], **common)
            self.assertEqual(
                ["app.example.org=127.0.0.1:9443", "*=127.0.0.1:9443"],
                load_install_state(path)["local_sites"],
            )
            save_install_state(path, local_sites=[], **common)
            self.assertNotIn("local_sites", load_install_state(path))
            for bad in ("app.example.org", "app.example.org=127.0.0.1:443", "app=::1:9443"):
                with self.assertRaises(ValueError):
                    save_install_state(path, local_sites=[bad], **common)

    def test_install_state_keeps_only_the_managed_compatibility_policy_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            save_install_state(path, policy="/etc/adguardhome-doh/compat-policy.csv", **common)
            self.assertEqual("/etc/adguardhome-doh/compat-policy.csv", load_install_state(path)["policy"])
            with self.assertRaises(ValueError):
                save_install_state(path, policy="/tmp/other.csv", **common)

    def test_legacy_install_without_front_is_read_without_inserting_a_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            legacy = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            path.write_text(json.dumps(legacy), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(legacy, load_install_state(path))
            save_install_state(path, **legacy)
            self.assertNotIn("front", json.loads(path.read_text(encoding="utf-8")))

    def test_mtproxyl_front_round_trips_with_other_install_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            written = save_install_state(
                path, **common, front="mtproxyl", relay="203.0.113.99",
                local_sites=["app.example.org=127.0.0.1:9443"],
                policy="/etc/adguardhome-doh/compat-policy.csv",
            )
            self.assertEqual("mtproxyl", written["front"])
            self.assertEqual(written, load_install_state(path))
            self.assertEqual("mtproxyl", json.loads(path.read_text(encoding="utf-8"))["front"])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_front_rejects_any_other_value_on_load_and_save(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="repo")
            save_install_state(path, **common, front="mtproxyl")
            before = path.read_bytes()
            for invalid in ("", "standard", "MTProxyL", "mtproxyl ", "/tmp/proxy",
                            "mtproxyl; touch /tmp/file", False, 0, [], {}):
                with self.subTest(value=invalid):
                    with self.assertRaises(ValueError):
                        save_install_state(path, **common, front=invalid)
                    self.assertEqual(before, path.read_bytes())
                    path.write_text(json.dumps({**common, "front": invalid}), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_install_state(path)
                    path.write_bytes(before)
            path.write_text(json.dumps({**common, "front": None}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_install_state(path)

    def test_install_domain_matches_renderer_hostname_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "install.json"
            common = dict(public_ip="203.0.113.10", email="admin@example.com",
                          version="1.0.0", repository="repo")
            save_install_state(path, domain="dns.example.xn--p1ai", **common)
            self.assertEqual("dns.example.xn--p1ai", load_install_state(path)["domain"])
            for domain in ("dns.example.123", "dns.example.xn--x", "dns_.example.com"):
                with self.subTest(domain=domain), self.assertRaises(ValueError):
                    save_install_state(path, domain=domain, **common)

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
