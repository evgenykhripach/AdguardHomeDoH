"""Acceptance tests for domain policy, Apple profile, and operator docs."""

from __future__ import annotations

import json
import plistlib
import re
import unittest
from pathlib import Path

from tools.validator import validate_domain_csv, validate_inventory, validate_mobileconfig


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_DIR = ROOT / "domains"
PROFILE = ROOT / "profiles" / "dns.pressroll.ru.mobileconfig"
PRODUCTION_INVENTORY = ROOT / "inventory.production.json"


class PolicyAndDocumentationTests(unittest.TestCase):
    def test_grouped_and_combined_domain_lists_are_normalized_and_unique(self) -> None:
        grouped = [DOMAIN_DIR / name for name in ("ai.csv", "work.csv", "gaming.csv")]
        combined_rows: list[str] = []
        for path in grouped:
            text = path.read_text(encoding="utf-8")
            self.assertEqual([], validate_domain_csv(text), path.name)
            combined_rows.extend(text.splitlines())

        combined = (DOMAIN_DIR / "domains.csv").read_text(encoding="utf-8")
        self.assertEqual([], validate_domain_csv(combined))
        self.assertEqual(combined_rows, combined.splitlines())

    def test_required_service_families_have_representative_routes(self) -> None:
        rows = set((DOMAIN_DIR / "domains.csv").read_text(encoding="utf-8").splitlines())
        required = {
            "OpenAI/ChatGPT/API": {"openai.com.,suffix", "chatgpt.com.,suffix"},
            "Claude/Anthropic": {"api.anthropic.com.,fqdn", "claude.ai.,suffix"},
            "Gemini": {"gemini.google.com.,fqdn", "generativelanguage.googleapis.com.,fqdn"},
            "Microsoft/GitHub Copilot": {"githubcopilot.com.,suffix", "copilot.microsoft.com.,fqdn"},
            "Perplexity": {"perplexity.ai.,suffix"},
            "Grok/xAI": {"grok.com.,suffix", "auth.x.ai.,fqdn", "api.x.ai.,fqdn"},
            "Midjourney": {"midjourney.com.,suffix"},
            "GitHub": {"github.com.,suffix", "githubusercontent.com.,suffix"},
            "Notion": {"notion.com.,suffix", "notion.site.,suffix"},
            "JetBrains": {"jetbrains.com.,suffix"},
            "Framer": {"framer.com.,suffix"},
            "Spotify": {"spotify.com.,suffix", "accounts.spotify.com.,fqdn", "api.spotify.com.,fqdn"},
            "Twitch": {"twitch.tv.,suffix", "api.twitch.tv.,fqdn", "static-cdn.jtvnw.net.,fqdn"},
            "Xbox": {"xbox.com.,suffix", "xboxlive.com.,suffix"},
            "PlayStation": {"playstation.com.,suffix", "playstationnetwork.com.,suffix"},
            "Supercell": {"supercell.com.,suffix", "supercellid.com.,suffix"},
            "Destiny 2": {"bungie.net.,suffix"},
        }
        for service, expected in required.items():
            with self.subTest(service=service):
                self.assertTrue(expected <= rows, f"missing {service}: {sorted(expected - rows)}")
        forbidden = {
            "google.com.,suffix",
            "googleapis.com.,suffix",
            "microsoft.com.,suffix",
            "x.ai.,suffix",
            "notion-static.com.,suffix",
            "jtvnw.net.,suffix",
            "ttvnw.net.,suffix",
            "supercell.net.,suffix",
        }
        self.assertTrue(rows.isdisjoint(forbidden), f"risky broad routes: {sorted(rows & forbidden)}")

    def test_production_inventory_is_ipv4_only_and_uses_combined_policy(self) -> None:
        inventory = json.loads(PRODUCTION_INVENTORY.read_text(encoding="utf-8"))
        self.assertEqual([], validate_inventory(inventory))
        self.assertEqual("89.125.113.107", inventory["ipv4"])
        self.assertEqual(["89.125.113.107"], inventory["publication"]["A"])
        self.assertEqual([], inventory["publication"]["AAAA"])
        self.assertEqual("domains/domains.csv", inventory["domain_csv"])
        self.assertEqual("", inventory["acme"]["email"])

    def test_apple_profile_is_global_doh_and_contains_no_matching_domains(self) -> None:
        profile_bytes = PROFILE.read_bytes()
        self.assertEqual([], validate_mobileconfig(profile_bytes, expected_ipv4="89.125.113.107"))
        profile = plistlib.loads(profile_bytes)
        self.assertIs(profile["PayloadRemovalDisallowed"], False)
        settings = profile["PayloadContent"][0]["DNSSettings"]
        self.assertEqual("HTTPS", settings["DNSProtocol"])
        self.assertEqual("https://dns.pressroll.ru/dns-query", settings["ServerURL"])
        self.assertEqual(["89.125.113.107"], settings["ServerAddresses"])
        self.assertNotIn("MatchingDomains", settings)
        self.assertNotIn("MatchingDomains", profile["PayloadContent"][0])

    def test_docs_cover_install_removal_verification_privacy_and_limitations(self) -> None:
        required = {
            "README.md": ("dns.pressroll.ru", "DoH", "DoT", "Smart DNS"),
            "docs/client-setup.md": ("Apple", "Android", "Windows", "роутер", "консол", "удал"),
            "docs/runbook.md": ("install.sh", "verify", "rollback.sh", "certbot renew --dry-run"),
            "docs/service-discovery.md": ("SNI", "domains.csv", "провер"),
            "docs/privacy-and-limitations.md": ("TLS", "query", "QUIC", "ECH", "UDP", "аккаунт"),
        }
        for relative, markers in required.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(file=relative, marker=marker):
                    self.assertIn(marker.lower(), text.lower())

    def test_repository_artifacts_contain_no_supplied_or_private_credentials(self) -> None:
        candidates = [
            *ROOT.glob("*.json"),
            *DOMAIN_DIR.glob("*.csv"),
            PROFILE,
            *ROOT.joinpath("docs").glob("*.md"),
            ROOT / "README.md",
        ]
        forbidden = re.compile(r"(?i)(srwseaa|root\s*password|password\s*[:=]\s*\S+|private[_ -]?key)")
        for path in candidates:
            with self.subTest(path=path.name):
                self.assertIsNone(forbidden.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
