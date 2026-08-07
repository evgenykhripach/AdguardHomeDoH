import copy
import contextlib
import io
import json
import plistlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.validator import (
    EXPECTED_DOH_URL,
    EXPECTED_INNER_PAYLOAD_IDENTIFIER,
    EXPECTED_OUTER_PAYLOAD_IDENTIFIER,
    validate_artifacts,
    validate_deployment_ports,
    validate_domain_csv,
    validate_inventory,
    validate_mobileconfig,
    validate_sniproxy,
    render_template,
    main,
)


INVENTORY = {
    "hostname": "dns.pressroll.ru",
    "ipv4": "203.0.113.10",
    "publication": {"A": ["203.0.113.10"], "AAAA": []},
}

DOMAIN_CSV = "openai.com.,suffix\nexample.com.,prefix\nexample.net.,fqdn\n"

SNIPROXY = {
    "listeners": [
        {"name": "dns-udp", "protocol": "udp", "port": 53, "interface": "0.0.0.0"},
        {"name": "dns-tcp", "protocol": "tcp", "port": 53, "interface": "0.0.0.0"},
        {"name": "dot", "protocol": "tcp", "port": 853, "interface": "0.0.0.0"},
        {"name": "sni-proxy", "protocol": "tcp", "port": 443, "interface": "0.0.0.0"},
        {"name": "prometheus", "protocol": "tcp", "port": 9090, "interface": "127.0.0.1"},
    ],
    "closed": [
        {"protocol": "udp", "port": 443},
        {"protocol": "udp", "port": 853},
    ],
}

NGINX = {
    "listeners": [
        {"name": "acme-http", "protocol": "tcp", "port": 80, "interface": "0.0.0.0"},
    ],
}

EXPECTED_OUTER_UUID = "00000000-0000-4000-8000-000000000001"
EXPECTED_INNER_UUID = "00000000-0000-4000-8000-000000000002"


def make_mobileconfig(**overrides):
    inner = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadIdentifier": EXPECTED_INNER_PAYLOAD_IDENTIFIER,
        "DNSSettings": {
            "DNSProtocol": "HTTPS",
            "ServerURL": EXPECTED_DOH_URL,
            "ServerAddresses": [INVENTORY["ipv4"]],
        },
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadIdentifier": EXPECTED_OUTER_PAYLOAD_IDENTIFIER,
        "PayloadVersion": 1,
        "PayloadUUID": EXPECTED_OUTER_UUID,
        "PayloadContent": [inner],
    }
    inner["PayloadVersion"] = 1
    inner["PayloadUUID"] = EXPECTED_INNER_UUID
    for key, value in overrides.items():
        if key.startswith("inner_"):
            inner[key.removeprefix("inner_")] = value
        else:
            profile[key] = value
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML).decode("utf-8")


class ValidatorTests(unittest.TestCase):
    def test_documentation_sample_is_valid(self):
        self.assertEqual([], validate_inventory(INVENTORY))
        self.assertEqual([], validate_domain_csv(DOMAIN_CSV))
        self.assertEqual([], validate_sniproxy(SNIPROXY))
        self.assertEqual([], validate_deployment_ports({"sniproxy": SNIPROXY, "nginx": NGINX}))
        self.assertEqual([], validate_mobileconfig(make_mobileconfig(), expected_ipv4=INVENTORY["ipv4"]))
        self.assertEqual(
            [],
            validate_artifacts(
                inventory=INVENTORY,
                domain_csv=DOMAIN_CSV,
                sniproxy=SNIPROXY,
                nginx=NGINX,
                mobileconfig=make_mobileconfig(),
            ),
        )
        self.assertEqual(
            "server_name dns.pressroll.ru; listen 203.0.113.10;",
            render_template("server_name {{ inventory.hostname }}; listen ${ipv4};", INVENTORY),
        )

    def test_fixed_deployment_hostname_is_required_by_default(self):
        invalid = copy.deepcopy(INVENTORY)
        invalid["hostname"] = "evil.example"
        self.assertTrue(any("dns.pressroll.ru" in error for error in validate_inventory(invalid)))
        self.assertTrue(any("dns.pressroll.ru" in error for error in validate_artifacts(
            inventory=invalid,
            domain_csv=DOMAIN_CSV,
            sniproxy=SNIPROXY,
            nginx=NGINX,
            mobileconfig=make_mobileconfig(),
        )))
        with self.assertRaises(ValueError):
            render_template("server_name {{ inventory.hostname }};", invalid)

    def test_inventory_rejects_missing_or_invalid_ipv4(self):
        missing = copy.deepcopy(INVENTORY)
        del missing["ipv4"]
        self.assertTrue(any("ipv4" in error.lower() for error in validate_inventory(missing)))

        ipv6 = copy.deepcopy(INVENTORY)
        ipv6["ipv4"] = "2001:db8::10"
        self.assertTrue(any("ipv4" in error.lower() for error in validate_inventory(ipv6)))

    def test_inventory_rejects_non_fqdn_and_aaaa_publication(self):
        invalid = copy.deepcopy(INVENTORY)
        invalid["hostname"] = "dns_pressroll"
        invalid["publication"]["AAAA"] = ["2001:db8::10"]
        errors = validate_inventory(invalid)
        self.assertTrue(any("hostname" in error.lower() for error in errors))
        self.assertTrue(any("aaaa" in error.lower() or "ipv6" in error.lower() for error in errors))

    def test_domain_csv_rejects_non_normalized_and_duplicate_domains(self):
        errors = validate_domain_csv("Example.com.,suffix\nexample.com.,fqdn\n")
        self.assertTrue(any("normal" in error.lower() for error in errors))
        self.assertTrue(any("duplicate" in error.lower() for error in errors))

    def test_domain_csv_rejects_missing_or_extra_trailing_dot_and_invalid_mode(self):
        errors = validate_domain_csv("example.com,suffix\nservice.example.com..,exact\n")
        self.assertTrue(any("line 1" in error and ("normal" in error.lower() or "trailing" in error.lower()) for error in errors))
        self.assertTrue(any("line 2" in error and ("normal" in error.lower() or "trailing" in error.lower()) for error in errors))
        self.assertTrue(any("mode" in error.lower() for error in errors))

    def test_validate_artifacts_requires_nginx_tcp80(self):
        errors = validate_artifacts(
            inventory=INVENTORY,
            domain_csv=DOMAIN_CSV,
            sniproxy=SNIPROXY,
            nginx={"listeners": []},
            mobileconfig=make_mobileconfig(),
        )
        self.assertTrue(any("nginx" in error.lower() and "80" in error for error in errors))

    def test_sniproxy_rejects_public_prometheus_and_udp_tls_ports(self):
        invalid = copy.deepcopy(SNIPROXY)
        invalid["listeners"][-1]["interface"] = "0.0.0.0"
        invalid["listeners"].append(
            {"name": "unexpected-udp-443", "protocol": "udp", "port": 443, "interface": "0.0.0.0"}
        )
        errors = validate_sniproxy(invalid)
        self.assertTrue(any("prometheus" in error.lower() and "loopback" in error.lower() for error in errors))
        self.assertTrue(any("udp" in error.lower() and "443" in error for error in errors))

    def test_sniproxy_rejects_missing_required_listener(self):
        invalid = copy.deepcopy(SNIPROXY)
        invalid["listeners"] = [entry for entry in invalid["listeners"] if entry["port"] != 853]
        errors = validate_sniproxy(invalid)
        self.assertTrue(any("853" in error for error in errors))

    def test_deployment_rejects_missing_nginx_tcp80(self):
        errors = validate_deployment_ports({"sniproxy": SNIPROXY, "nginx": {"listeners": []}})
        self.assertTrue(any("nginx" in error.lower() and "80" in error for error in errors))

    def test_deployment_rejects_sniproxy_owning_nginx_tcp80(self):
        sniproxy = copy.deepcopy(SNIPROXY)
        sniproxy["listeners"].append(
            {"name": "conflicting-http", "protocol": "tcp", "port": 80, "interface": "0.0.0.0"}
        )
        errors = validate_deployment_ports({"sniproxy": sniproxy, "nginx": NGINX})
        self.assertTrue(any("sniproxy" in error.lower() and "tcp 80" in error.lower() for error in errors))

    def test_sniproxy_rejects_loopback_public_listener(self):
        invalid = copy.deepcopy(SNIPROXY)
        invalid["listeners"][0]["interface"] = "127.0.0.1"
        errors = validate_sniproxy(invalid)
        self.assertTrue(any("udp" in error.lower() and "53" in error and "public" in error.lower() for error in errors))

    def test_sniproxy_rejects_private_required_listener_interface(self):
        invalid = copy.deepcopy(SNIPROXY)
        invalid["listeners"][0]["interface"] = "10.0.0.1"
        errors = validate_sniproxy(invalid, expected_ipv4=INVENTORY["ipv4"])
        self.assertTrue(any("udp" in error.lower() and "53" in error and "public" in error.lower() for error in errors))

    def test_mobileconfig_rejects_wrong_identifiers_protocol_and_url(self):
        wrong_outer = validate_mobileconfig(
            make_mobileconfig(PayloadIdentifier="ru.pressroll.wrong"),
            expected_ipv4=INVENTORY["ipv4"],
        )
        self.assertTrue(any("identifier" in error.lower() for error in wrong_outer))

        wrong_inner = validate_mobileconfig(
            make_mobileconfig(inner_PayloadIdentifier="ru.pressroll.wrong.settings"),
            expected_ipv4=INVENTORY["ipv4"],
        )
        self.assertTrue(any("identifier" in error.lower() for error in wrong_inner))

        wrong_protocol = validate_mobileconfig(
            make_mobileconfig(inner_DNSSettings={"DNSProtocol": "TLS", "ServerURL": EXPECTED_DOH_URL}),
            expected_ipv4=INVENTORY["ipv4"],
        )
        self.assertTrue(any("protocol" in error.lower() for error in wrong_protocol))

        wrong_url = validate_mobileconfig(
            make_mobileconfig(inner_DNSSettings={"DNSProtocol": "HTTPS", "ServerURL": "https://wrong.invalid/dns-query"}),
            expected_ipv4=INVENTORY["ipv4"],
        )
        self.assertTrue(any("url" in error.lower() for error in wrong_url))

    def test_mobileconfig_requires_versions_uuids_and_exact_payload_content(self):
        invalid = make_mobileconfig(PayloadVersion=2, PayloadUUID="", inner_PayloadVersion=2, inner_PayloadUUID="")
        errors = validate_mobileconfig(invalid, expected_ipv4=INVENTORY["ipv4"])
        self.assertTrue(any("version" in error.lower() for error in errors))
        self.assertTrue(any("uuid" in error.lower() for error in errors))

        invalid_content = make_mobileconfig(PayloadContent=[make_mobileconfig()])
        errors = validate_mobileconfig(invalid_content, expected_ipv4=INVENTORY["ipv4"])
        self.assertTrue(any("exactly one" in error.lower() for error in errors))

    def test_render_template_rejects_unresolved_brace_markers(self):
        for malformed in (
            "server_name {{ inventory.hostname;",
            "server_name inventory.hostname }};",
            "server_name ${hostname;",
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    render_template(malformed, INVENTORY)

    def test_cli_validates_real_files_and_fixed_hostname(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inventory.json").write_text(json.dumps(INVENTORY), encoding="utf-8")
            (root / "domains.csv").write_text(DOMAIN_CSV, encoding="utf-8")
            (root / "sniproxy.json").write_text(json.dumps(SNIPROXY), encoding="utf-8")
            (root / "nginx.json").write_text(json.dumps(NGINX), encoding="utf-8")
            (root / "profile.mobileconfig").write_text(make_mobileconfig(), encoding="utf-8")
            args = [
                "--inventory", str(root / "inventory.json"),
                "--domains", str(root / "domains.csv"),
                "--sniproxy", str(root / "sniproxy.json"),
                "--nginx", str(root / "nginx.json"),
                "--mobileconfig", str(root / "profile.mobileconfig"),
            ]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, main(args))

            (root / "nginx.json").write_text(json.dumps({"listeners": []}), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(args))

            (root / "nginx.json").write_text(json.dumps(NGINX), encoding="utf-8")
            invalid_inventory = copy.deepcopy(INVENTORY)
            invalid_inventory["hostname"] = "evil.example"
            (root / "inventory.json").write_text(json.dumps(invalid_inventory), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(args))

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(args + ["--expected-hostname", "evil.example"])


if __name__ == "__main__":
    unittest.main()
