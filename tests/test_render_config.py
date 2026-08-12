import csv
import json
import tempfile
import unittest
from pathlib import Path

from tools.render_config import (
    Catalog,
    load_policy,
    render,
    render_adguard_yaml,
    render_nginx_http,
    render_nginx_stream,
    render_rewrites,
)


class RenderConfigTests(unittest.TestCase):
    def write_policy(self, rows):
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", delete=False)
        with handle:
            writer = csv.writer(handle)
            writer.writerow(("domain", "kind", "probe"))
            writer.writerows(rows)
        return Path(handle.name)

    def test_load_policy_normalizes_and_preserves_probe(self):
        path = self.write_policy([
            ("Example.COM", "suffix", ""),
            ("files.oaiusercontent.com", "fqdn", "files.oaiusercontent.com"),
        ])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        self.assertEqual("example.com", rows[0].domain)
        self.assertEqual("files.oaiusercontent.com", rows[1].probe)

    def test_duplicate_and_invalid_rows_are_rejected(self):
        for rows in (
            [("example.com", "suffix", ""), ("example.com", "suffix", "")],
            [("example.com.", "suffix", "")],
            [("example.com", "wildcard", "")],
        ):
            path = self.write_policy(rows)
            try:
                with self.assertRaises(ValueError):
                    load_policy(path)
            finally:
                path.unlink()

    def test_suffix_expands_to_apex_and_wildcard(self):
        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        self.assertEqual(
            [
                {"domain": "example.com", "answer": "203.0.113.10", "enabled": True},
                {"domain": "*.example.com", "answer": "203.0.113.10", "enabled": True},
            ],
            render_rewrites(rows, "203.0.113.10"),
        )

    def test_fqdn_does_not_expand_and_oai_probe_is_rendered(self):
        path = self.write_policy([
            ("oaiusercontent.com", "suffix", "files.oaiusercontent.com"),
            ("api.fitbit.com", "fqdn", "api.fitbit.com"),
        ])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        nginx = render_nginx_stream(rows, "dns.example.com")
        self.assertIn(".oaiusercontent.com $ssl_preread_server_name:443;", nginx)
        self.assertIn("api.fitbit.com $ssl_preread_server_name:443;", nginx)
        self.assertNotIn("*.api.fitbit.com", nginx)
        self.assertEqual(
            "files.oaiusercontent.com",
            next(row.probe for row in rows if row.domain == "oaiusercontent.com"),
        )

    def test_runtime_renderers_escape_only_validated_values(self):
        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        adguard = render_adguard_yaml(rows, "$2a$10$hash")
        http = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com", "/var/www/html"
        )
        self.assertIn("password: $2a$10$hash", adguard)
        self.assertIn("domain: 'example.com'", adguard)
        self.assertIn("location = /doh/" + "a" * 48, http)
        self.assertIn("location = /" + "a" * 48 + ".mobileconfig {", http)
        self.assertNotIn("listen 443 ssl", http)

    def test_catalog_rows_render_deterministically_for_selected_services(self):
        root = Path(__file__).resolve().parents[1]
        catalog = Catalog.load(root / "config")
        rows = catalog.enabled_policy(["chatgpt"])
        first = render_nginx_stream(rows, "dns.example.com")
        second = render_nginx_stream(list(reversed(rows)), "dns.example.com")
        self.assertEqual(first, second)
        self.assertIn("chatgpt.com $ssl_preread_server_name:443;", first)

    def test_render_accepts_catalog_and_selected_services(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            render(
                output,
                public_ip="203.0.113.10",
                doh_host="dns.example.com",
                config_dir=root / "config",
                service_ids=["chatgpt"],
            )
            health = json.loads(
                (output / "health-policy.json").read_text(encoding="utf-8")
            )
            self.assertTrue(health)
            self.assertEqual(
                "files.oaiusercontent.com",
                next(row["probe"] for row in health if row["domain"] == "oaiusercontent.com"),
            )
            self.assertNotIn("anthropic.com", (output / "nginx-stream.conf").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
