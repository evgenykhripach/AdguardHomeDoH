import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.render_config import Catalog


ROOT = Path(__file__).resolve().parents[1]


class CatalogTests(unittest.TestCase):
    def test_repository_catalog_has_expected_domain_union_and_defaults(self):
        catalog = Catalog.load(ROOT / "config")

        self.assertEqual(206, len(catalog.domains))
        self.assertEqual(
            {
                "chatgpt",
                "claude",
                "gemini",
                "microsoft_copilot",
                "github_copilot",
                "grok",
            },
            set(catalog.default_service_ids),
        )
        self.assertTrue(all(service.name_ru for service in catalog.services))
        self.assertTrue(
            all(
                not service.default_enabled
                for service in catalog.services
                if service.risk_level == "experimental"
            )
        )

    def test_catalog_foreign_keys_and_domain_coverage_are_strict(self):
        catalog = Catalog.load(ROOT / "config")
        service_ids = {service.id for service in catalog.services}
        domains = {domain.domain for domain in catalog.domains}
        self.assertTrue(service_ids)
        self.assertTrue(domains)
        self.assertTrue(all(row.service_id in service_ids for row in catalog.service_domains))
        self.assertTrue(all(row.domain in domains for row in catalog.service_domains))
        self.assertTrue(all(row.service_id in service_ids for row in catalog.service_probes))
        self.assertEqual(domains, set(catalog.associations))
        self.assertEqual(
            service_ids,
            {row.service_id for row in catalog.service_probes},
            "every service must have at least one mandatory TLS probe",
        )

    def test_shared_domain_union_respects_selected_and_healthy_services(self):
        catalog = Catalog.load(ROOT / "config")
        shared = catalog.enabled_policy(["chatgpt", "google_shared"])
        chatgpt_only = catalog.enabled_policy(["chatgpt"])
        unhealthy_shared = catalog.enabled_policy(
            ["chatgpt", "google_shared"], healthy_service_ids=["chatgpt"]
        )

        shared_domains = {row.domain for row in shared}
        chatgpt_domains = {row.domain for row in chatgpt_only}
        unhealthy_domains = {row.domain for row in unhealthy_shared}
        self.assertLess(len(chatgpt_domains), len(shared_domains))
        self.assertEqual(chatgpt_domains, unhealthy_domains)
        self.assertIn("oaiusercontent.com", shared_domains)

    def test_chatgpt_upload_probe_is_preserved(self):
        catalog = Catalog.load(ROOT / "config")
        row = next(
            row for row in catalog.enabled_policy(["chatgpt"])
            if row.domain == "oaiusercontent.com"
        )
        self.assertEqual("files.oaiusercontent.com", row.probe)

    def test_gemini_service_routes_consumer_app_backends(self):
        catalog = Catalog.load(ROOT / "config")
        backends = {
            "alkalicore-pa.clients6.google.com",
            "alkalimakersuite-pa.clients6.google.com",
            "cloudaicompanion.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "geller-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "proactivebackend-pa.googleapis.com",
            "robinfrontend-pa.googleapis.com",
            "signaler-pa.clients6.google.com",
            "waa-pa.clients6.google.com",
            "webchannel-alkalimakersuite-pa.clients6.google.com",
        }
        routed = {row.domain for row in catalog.enabled_policy(["gemini"])}
        self.assertTrue(backends <= routed)
        for domain in backends:
            self.assertIn("gemini", catalog.associations[domain])
            self.assertIn("developer_infrastructure", catalog.associations[domain])

    def test_context7_service_covers_official_web_and_mcp_hosts(self):
        catalog = Catalog.load(ROOT / "config")
        service = next(service for service in catalog.services if service.id == "context7")
        self.assertEqual("Context7", service.name_ru)
        self.assertEqual("Разработка", service.category)
        self.assertFalse(service.default_enabled)
        self.assertEqual("standard", service.risk_level)

        self.assertIn("context7.com", catalog.associations)
        self.assertEqual(("context7",), catalog.associations["context7.com"])
        self.assertEqual(
            {"context7.com", "mcp.context7.com"},
            set(catalog._probes["context7"]),
        )
        policy = catalog.enabled_policy(["context7"])
        self.assertEqual(1, len(policy))
        self.assertEqual("context7.com", policy[0].domain)
        self.assertEqual("context7.com", policy[0].probe)

    def test_sensitive_and_infrastructure_domains_are_not_default_chatgpt(self):
        catalog = Catalog.load(ROOT / "config")
        default_rows = {row.domain for row in catalog.enabled_policy(catalog.default_service_ids)}
        self.assertNotIn("crixet.com", default_rows)
        self.assertNotIn("gpt3-openai.com", default_rows)
        self.assertNotIn("openaiapi-site.azureedge.net", default_rows)
        self.assertNotIn("openaipublic.blob.core.windows.net", default_rows)
        for domain in (
            "crixet.com",
            "gpt3-openai.com",
            "openaiapi-site.azureedge.net",
            "openaipublic.blob.core.windows.net",
        ):
            service_ids = catalog.associations[domain]
            self.assertTrue(service_ids)
            self.assertTrue(
                all(
                    service.risk_level == "experimental"
                    for service in catalog.services
                    if service.id in service_ids
                )
            )

    def test_policy_is_deterministic_full_catalog_projection(self):
        catalog = Catalog.load(ROOT / "config")
        with (ROOT / "config/policy.csv").open(
            "r", encoding="utf-8", newline=""
        ) as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(
            [(entry.domain, entry.kind) for entry in catalog.domains],
            [(row["domain"], row["kind"]) for row in rows],
        )
        self.assertEqual(
            "files.oaiusercontent.com",
            next(row["probe"] for row in rows if row["domain"] == "oaiusercontent.com"),
        )
        self.assertTrue(all(row["probe"] == "" for row in rows if row["domain"] != "oaiusercontent.com"))

    def test_catalog_rejects_orphan_service_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            for name in (
                "services.csv",
                "domains.csv",
                "service-domains.csv",
                "service-probes.csv",
            ):
                (config_dir / name).write_text(
                    (ROOT / "config" / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            service_domains = config_dir / "service-domains.csv"
            with service_domains.open("a", encoding="utf-8") as stream:
                stream.write("missing_service,example.com\n")
            with self.assertRaises(ValueError):
                Catalog.load(config_dir)

    def test_catalog_rejects_probe_outside_associated_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            for name in (
                "services.csv",
                "domains.csv",
                "service-domains.csv",
                "service-probes.csv",
            ):
                (config_dir / name).write_text(
                    (ROOT / "config" / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            with (config_dir / "service-probes.csv").open("a", encoding="utf-8") as stream:
                stream.write("chatgpt,probe.unrelated.example\n")
            with self.assertRaises(ValueError):
                Catalog.load(config_dir)


class ActivationSeedingTests(unittest.TestCase):
    def test_mtproxyl_map_contains_catalog_and_compatibility_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.csv"
            policy.write_text("domain,kind,probe\nlegacy.example,suffix,\napi.example,fqdn,\n", encoding="utf-8")
            def run(output, extra):
                result = subprocess.run([
                    sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                    "--front", "mtproxyl", "--config-dir", str(ROOT / "config"), *extra,
                    "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                    "--doh-token", "a" * 48, "--password-hash", "secret-hash",
                    "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
                ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, result.returncode, result.stderr)
                return (output / "mtproxyl-sni.map").read_text(encoding="utf-8")
            first = run(root / "one", ["--services", "chatgpt"])
            second = run(root / "two", ["--services", "claude"])
            compat = run(root / "three", ["--policy", str(policy)])
            self.assertEqual(first, second)
            self.assertIn(".chatgpt.com adguardhome_doh;", first)
            self.assertIn(".anthropic.com adguardhome_doh;", first)
            self.assertIn(".legacy.example adguardhome_doh;", compat)
            self.assertIn("api.example adguardhome_doh;", compat)
            self.assertIn(".chatgpt.com adguardhome_doh;", compat)
            self.assertNotIn("secret-hash", compat)
            self.assertNotIn("a" * 48, compat)
            self.assertNotIn("anthropic.com", (root / "one/nginx-stream.conf").read_text(encoding="utf-8"))
            self.assertNotIn("chatgpt.com", (root / "three/nginx-stream.conf").read_text(encoding="utf-8"))

    def test_compatibility_policy_seeds_previously_healthy_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.csv"
            policy.write_text("domain,kind,probe\nexample.com,suffix,\n", encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--policy", str(policy), "--healthy-services", "example.com",
                "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                "--doh-token", "a" * 48, "--password-hash", "hash",
                "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            output_yaml = (output / "AdGuardHome.yaml").read_text(encoding="utf-8")
            self.assertIn("domain: 'example.com'", output_yaml)
            self.assertIn("domain: '*.example.com'", output_yaml)

    def test_activation_reads_token_and_password_hash_from_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "token").write_text("a" * 48, encoding="utf-8")
            (root / "hash").write_text("$2a$10$fixture", encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--config-dir", str(ROOT / "config"), "--services", "chatgpt",
                "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                "--doh-token-file", str(root / "token"),
                "--password-hash-file", str(root / "hash"),
                "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("$2a$10$fixture", (output / "AdGuardHome.yaml").read_text(encoding="utf-8"))
            self.assertIn("/doh/" + "a" * 48, (output / "nginx-http.conf").read_text(encoding="utf-8"))

    def test_activation_preserves_custom_settings_and_unmanaged_rewrites(self):
        import yaml

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "existing.yaml"
            previous.write_text(
                "http:\n  address: 0.0.0.0:3001\n"
                "users:\n  - name: operator\n    password: operator-hash\n"
                "  - name: admin\n    password: admin-hash\n"
                "dns:\n  bind_hosts: [0.0.0.0]\n  upstream_dns: [192.0.2.53]\n"
                "user_rules: ['||custom.example^']\n"
                "filtering:\n  rewrites_enabled: false\n  rewrites:\n"
                "  - {domain: old.example.com, answer: 203.0.113.9, enabled: true}\n"
                "  - {domain: chatgpt.com, answer: 203.0.113.9, enabled: true}\n"
                "  - {domain: custom.example.com, answer: 192.0.2.55, enabled: true}\n",
                encoding="utf-8",
            )
            previous_policy = root / "policy.json"
            previous_policy.write_text(json.dumps({"domains": [
                {"domain": "old.example.com", "kind": "fqdn"},
                {"domain": "chatgpt.com", "kind": "suffix"},
            ]}), encoding="utf-8")
            token = root / "token"
            token.write_text("a" * 48, encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--config-dir", str(ROOT / "config"), "--services", "chatgpt",
                "--healthy-services", "chatgpt", "--public-ip", "203.0.113.10",
                "--existing-config", str(previous), "--existing-policy", str(previous_policy),
                "--existing-public-ip", "203.0.113.9",
                "--doh-host", "dns.example.com", "--doh-token-file", str(token),
                "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            config = yaml.safe_load((output / "AdGuardHome.yaml").read_text(encoding="utf-8"))

        self.assertEqual(["192.0.2.53"], config["dns"]["upstream_dns"])
        self.assertEqual(["||custom.example^"], config["user_rules"])
        self.assertEqual(["operator", "admin"], [user["name"] for user in config["users"]])
        self.assertEqual("admin-hash", config["users"][1]["password"])
        self.assertEqual("127.0.0.1:3001", config["http"]["address"])
        self.assertEqual(["127.0.0.1"], config["dns"]["bind_hosts"])
        self.assertTrue(config["filtering"]["rewrites_enabled"])
        rules = {(item["domain"], item["answer"]) for item in config["filtering"]["rewrites"]}
        self.assertIn(("custom.example.com", "192.0.2.55"), rules)
        self.assertIn(("chatgpt.com", "203.0.113.10"), rules)
        self.assertNotIn(("old.example.com", "203.0.113.9"), rules)
        self.assertNotIn(("chatgpt.com", "203.0.113.9"), rules)

    def test_activation_rejects_ambiguous_existing_configuration_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "existing.yaml"
            previous.write_text("users: []\nusers: []\n", encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--config-dir", str(ROOT / "config"), "--services", "chatgpt",
                "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                "--doh-token", "a" * 48, "--existing-config", str(previous),
                "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((output / "AdGuardHome.yaml").exists())

    def test_activation_rejects_existing_config_without_an_admin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "existing.yaml"
            previous.write_text("users:\n  - name: other\n    password: hash\n", encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--config-dir", str(ROOT / "config"), "--services", "chatgpt",
                "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                "--doh-token", "a" * 48, "--existing-config", str(previous),
                "--certificate-root", "/cert", "--webroot", "/web", "--output", str(output),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("exactly one admin", result.stderr)
            self.assertFalse((output / "AdGuardHome.yaml").exists())

    def test_only_healthy_services_are_seeded_while_nginx_keeps_the_union(self):
        """A restart must not send clients to the real addresses in between."""

        root = Path(__file__).resolve().parents[1]
        runtime = root / "deploy" / "lib" / "render_runtime.py"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "stage"
            result = subprocess.run(
                [
                    sys.executable, str(runtime),
                    "--config-dir", str(root / "config"),
                    "--services", "chatgpt,claude",
                    "--healthy-services", "chatgpt",
                    "--public-ip", "203.0.113.10",
                    "--doh-host", "dns.example.com",
                    "--doh-token", "a" * 48,
                    "--password-hash", "$2a$10$hash",
                    "--certificate-root", "/etc/letsencrypt/live/dns.example.com",
                    "--webroot", "/var/www/adguardhome-doh",
                    "--output", str(output),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            adguard = (output / "AdGuardHome.yaml").read_text(encoding="utf-8")
            stream = (output / "nginx-stream.conf").read_text(encoding="utf-8")

        self.assertIn("    - domain: 'chatgpt.com'", adguard)
        self.assertIn("      answer: 203.0.113.10", adguard)
        # A service that has not proven itself yet stays for the gate to enable.
        self.assertNotIn("claude.ai", adguard)
        # SNI routing always covers the full selected union.
        self.assertIn(".claude.ai $ssl_preread_server_name:443;", stream)
        self.assertIn(".chatgpt.com $ssl_preread_server_name:443;", stream)

    def test_activation_without_health_state_stays_gated(self):
        root = Path(__file__).resolve().parents[1]
        runtime = root / "deploy" / "lib" / "render_runtime.py"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "stage"
            result = subprocess.run(
                [
                    sys.executable, str(runtime),
                    "--config-dir", str(root / "config"),
                    "--services", "chatgpt",
                    "--public-ip", "203.0.113.10",
                    "--doh-host", "dns.example.com",
                    "--doh-token", "a" * 48,
                    "--password-hash", "$2a$10$hash",
                    "--certificate-root", "/etc/letsencrypt/live/dns.example.com",
                    "--webroot", "/var/www/adguardhome-doh",
                    "--output", str(output),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(
                "  rewrites: []",
                (output / "AdGuardHome.yaml").read_text(encoding="utf-8"),
            )

    def test_installer_passes_the_persisted_health_state_to_the_renderer(self):
        source = (Path(__file__).resolve().parents[1] / "deploy" / "install.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("adguardhome_doh_healthy_services", source)
        self.assertIn('"$STATE_DIR/health-state.json"', source)
        self.assertIn("--healthy-services", source)


if __name__ == "__main__":
    unittest.main()
