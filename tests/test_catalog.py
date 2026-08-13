import csv
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


if __name__ == "__main__":
    unittest.main()
