"""Behaviour tests for the native deployment bundle.

These tests deliberately exercise the renderer and shell entry points through
their public command lines.  They do not inspect implementation source to
decide whether an operation happened.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.render_deployment import render_deployment
from tools.validator import validate_inventory, validate_nginx, validate_sniproxy


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "inventory.example.json"
INSTALL = ROOT / "deploy" / "bin" / "install.sh"
BUILD = ROOT / "deploy" / "bin" / "build-sniproxy.sh"
ROLLBACK = ROOT / "deploy" / "bin" / "rollback.sh"
APPLY_NFT = ROOT / "deploy" / "bin" / "apply-nftables.sh"
GEOIP_UPDATE = ROOT / "deploy" / "bin" / "update-geoip.sh"
VALIDATE_MMDB = ROOT / "deploy" / "bin" / "validate-mmdb.sh"


def run(*args: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class DeploymentBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    def test_example_inventory_and_rendered_listeners_validate(self) -> None:
        self.assertEqual([], validate_inventory(self.inventory))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            manifest = render_deployment(self.inventory, output)
            self.assertEqual("dns.pressroll.ru", manifest["hostname"])
            sniproxy = json.loads((output / "sniproxy-listeners.json").read_text())
            nginx = json.loads((output / "nginx-listeners.json").read_text())
            self.assertEqual([], validate_sniproxy(sniproxy, expected_ipv4="203.0.113.10"))
            self.assertEqual([], validate_nginx(nginx, expected_ipv4="203.0.113.10"))
            self.assertTrue((output / "manifest.json").is_file())
            self.assertTrue((output / "etc/sniproxy/sniproxy.yaml").is_file())

    def test_sniproxy_v230_schema_uses_exact_general_and_acl_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            render_deployment(self.inventory, output)
            config = (output / "etc/sniproxy/sniproxy.yaml").read_text(encoding="utf-8")
            for expected in (
                "  upstream_dns: https://cloudflare-dns.com/dns-query",
                '  bind_dns_over_udp: "0.0.0.0:53"',
                '  bind_dns_over_tcp: "0.0.0.0:53"',
                '  bind_dns_over_tls: "0.0.0.0:853"',
                '  bind_dns_over_quic: ""',
                "  tls_cert: /etc/sniproxy/tls/fullchain.pem",
                "  tls_key: /etc/sniproxy/tls/privkey.pem",
                '  bind_http: "127.0.0.1:8081"',
                '  bind_https: "0.0.0.0:443"',
                '  prometheus: "127.0.0.1:9090"',
                '  public_ipv4: "203.0.113.10"',
                '  public_ipv6: ""',
                "  preferred_version: ipv4only",
                "  allow_conn_to_local: false",
                "  log_level: warn",
                "  domain:\n    enabled: true\n    priority: 10",
                "  override:\n    enabled: true\n    priority: 20",
                "  geoip:\n    enabled: true\n    priority: 100",
                "    allowed: [RU, PRIVATE]",
                "    path: /var/lib/dohdns/geoip/Country-without-asn.mmdb",
                "    path: /etc/sniproxy/current/domains.csv",
                "    rules: {}",
                '    doh_sni: "dns.pressroll.ru"',
            ):
                self.assertIn(expected, config)
            for obsolete in (
                "bind_prometheus",
                "  upstream:",
                "geoip_allowed:",
                "domain_list:",
                "tls_certificate:",
                "tls_private_key:",
                "bind_dns:",
                "bind_dns_tcp:",
            ):
                self.assertNotIn(obsolete, config)
            self.assertIn("PRIVATE is only for the internal loopback DoH-to-DNS path", config)

    def test_pinned_inputs_and_build_target_are_explicit(self) -> None:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb",
            inventory["geoip"]["database_url"],
        )
        self.assertEqual(
            "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb.sha256sum",
            inventory["geoip"]["sha256_url"],
        )
        build = (ROOT / "deploy/bin/build-sniproxy.sh").read_text(encoding="utf-8")
        self.assertRegex(build, re.compile(r'build -trimpath \\\n\s+-ldflags'))
        self.assertIn('"$go_root/go/bin/go"', build)
        self.assertIn('./cmd/sniproxy', build)

    def test_verified_prebuilt_binary_avoids_sandbox_source_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sandbox"
            binary = Path(directory) / "sniproxy-linux-amd64"
            binary.write_bytes(b"verified-prebuilt-fixture")
            checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
            result = run(
                str(BUILD),
                "--root", str(root),
                "--prebuilt-binary", str(binary),
                "--prebuilt-sha256", checksum,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            installed = root / "usr/local/libexec/sniproxy/v2.3.0/sniproxy"
            self.assertEqual(binary.read_bytes(), installed.read_bytes())
            self.assertTrue(os.access(installed, os.X_OK))

            bad_root = Path(directory) / "bad-sandbox"
            bad = run(
                str(BUILD),
                "--root", str(bad_root),
                "--prebuilt-binary", str(binary),
                "--prebuilt-sha256", "0" * 64,
            )
            self.assertNotEqual(0, bad.returncode)
            self.assertFalse((bad_root / "usr/local/libexec/sniproxy/v2.3.0/sniproxy").exists())

    def test_install_forwards_verified_prebuilt_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sandbox"
            binary = Path(directory) / "sniproxy-linux-amd64"
            binary.write_bytes(b"install-prebuilt-fixture")
            checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
            result = run(
                str(INSTALL),
                "--inventory", str(INVENTORY_PATH),
                "--root", str(root),
                "--prebuilt-binary", str(binary),
                "--prebuilt-sha256", checksum,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            installed = root / "usr/local/libexec/sniproxy/current/sniproxy"
            self.assertEqual(binary.read_bytes(), installed.read_bytes())

    def test_tls_permissions_and_hook_check_order_are_restrictive(self) -> None:
        sync = (ROOT / "deploy/bin/sync-cert.sh").read_text(encoding="utf-8")
        self.assertIn('dohdns_mkdir "$DEST_DIR" 0750', sync)
        self.assertIn('install -m 0640', sync)
        self.assertNotIn('chown root:sniproxy -- "$DEST_CERT"', sync)
        self.assertIn('if ((CHECK_ONLY)); then', sync)
        self.assertLess(sync.index('if ((CHECK_ONLY)); then'), sync.index('CERT="$(dohdns_under_root'))
        hook = (ROOT / "deploy/templates/certbot-deploy-hook.sh.tmpl").read_text(encoding="utf-8")
        self.assertLess(hook.index("sync-cert.sh"), hook.index("try-restart"))
        self.assertIn("RuntimeDirectory=sniproxy", (ROOT / "deploy/templates/sniproxy.service.tmpl").read_text())

    def test_nft_rate_limits_have_terminal_drops_and_persistent_unit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            render_deployment(self.inventory, output)
            nft = (output / "etc/nftables.d/dohdns.nft").read_text(encoding="utf-8")
            self.assertIn("set dohdns_dns_rate", nft)
            self.assertIn("set dohdns_tcp_rate", nft)
            self.assertGreaterEqual(nft.count("flags dynamic"), 2)
            self.assertRegex(nft, re.compile(r"update @dohdns_dns_rate \{\s+ip saddr limit rate"))
            self.assertRegex(nft, re.compile(r"update @dohdns_tcp_rate \{\s+ip saddr limit rate"))
            self.assertNotIn("meter dohdns_", nft)
            established = nft.index("ct state established,related accept")
            self.assertLess(nft.index("udp dport { 53 } update"), established)
            self.assertLess(nft.index("udp dport { 443, 853 } drop"), established)
            self.assertRegex(nft, re.compile(r"udp dport \{ 53 \}.*?accept.*?udp dport \{ 53 \} drop", re.S))
            self.assertRegex(nft, re.compile(r"tcp dport \{ 53, 80, 443, 853 \}.*?accept.*?tcp dport \{ 53, 80, 443, 853 \} (?:ct state new )?drop", re.S))
            service = output / "etc/systemd/system/dohdns-nftables.service"
            self.assertTrue(service.is_file())
            text = service.read_text(encoding="utf-8")
            self.assertIn("ExecStart=/usr/local/libexec/dohdns/apply-nftables.sh --root /", text)
            self.assertIn("Before=sniproxy.service", text)
            self.assertIn("RemainAfterExit=true", text)

    def test_renderer_rejects_unsafe_output_root_and_unknown_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            bad = dict(self.inventory)
            bad["hostname"] = "evil.example"
            with self.assertRaises(ValueError):
                render_deployment(bad, output)
            with self.assertRaises(ValueError):
                render_deployment(self.inventory, Path("/tmp"))
            output.mkdir()
            sentinel = output / "user-data"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaises(ValueError):
                render_deployment(self.inventory, output)
            self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))

    def test_dry_run_is_root_and_network_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory) / "sandbox"
            result = run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox), "--dry-run")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(sandbox.exists())
            self.assertIn("DRY-RUN", result.stdout)
            for forbidden in ("apt", "systemctl", "curl", "certbot", "nft"):
                self.assertNotIn(forbidden, result.stdout)

    def test_sandbox_install_is_idempotent_and_uses_generation_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory) / "sandbox"
            first = run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox))
            self.assertEqual(0, first.returncode, first.stderr)
            first_manifest = (sandbox / "var/lib/dohdns/manifest.json").read_bytes()
            first_binary = os.readlink(sandbox / "usr/local/libexec/sniproxy/current")
            second = run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox))
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertEqual(first_manifest, (sandbox / "var/lib/dohdns/manifest.json").read_bytes())
            self.assertEqual(first_binary, os.readlink(sandbox / "usr/local/libexec/sniproxy/current"))
            self.assertTrue((sandbox / "etc/sniproxy/current").is_symlink())

    def test_rollback_restores_previous_generation_and_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory) / "sandbox"
            run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox))
            current = sandbox / "usr/local/libexec/sniproxy/current"
            generation_a = os.readlink(current)
            marker = sandbox / "var/lib/dohdns/generations" / generation_a / "marker"
            marker.write_text("A", encoding="utf-8")
            run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox), "--force-new-generation")
            generation_b = os.readlink(current)
            self.assertNotEqual(generation_a, generation_b)
            rolled = run(str(ROLLBACK), "--root", str(sandbox))
            self.assertEqual(0, rolled.returncode, rolled.stderr)
            self.assertEqual(generation_a, os.readlink(current))

    def test_failed_post_activation_install_restores_previous_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory) / "sandbox"
            first = run(str(INSTALL), "--inventory", str(INVENTORY_PATH), "--root", str(sandbox))
            self.assertEqual(0, first.returncode, first.stderr)
            current = sandbox / "usr/local/libexec/sniproxy/current"
            generation_a = os.readlink(current)
            failed = run(
                str(INSTALL),
                "--inventory", str(INVENTORY_PATH), "--root", str(sandbox), "--force-new-generation",
                env={**os.environ, "DOHDNS_TEST_FAIL_AFTER_ACTIVATION": "1"},
            )
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual(generation_a, os.readlink(current))
            self.assertEqual("gen-" + generation_a.split("generations/gen-", 1)[1].split("/", 1)[0], (sandbox / "var/lib/dohdns/active-generation").read_text().strip())
            rolled_again = run(str(ROLLBACK), "--root", str(sandbox))
            self.assertEqual(0, rolled_again.returncode, rolled_again.stderr)
            self.assertEqual(generation_a, os.readlink(current))

    def test_nftables_render_and_apply_are_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            render_deployment(self.inventory, output)
            nft = (output / "etc/nftables.d/dohdns.nft").read_text(encoding="utf-8")
            self.assertIn("table inet dohdns", nft)
            self.assertNotIn("flush ruleset", nft)
            self.assertIn("udp dport { 53 }", nft)
            self.assertIn("tcp dport { 53, 80, 443, 853 }", nft)
            self.assertIn("udp dport { 443, 853 } drop", nft)
            result = run(str(APPLY_NFT), "--root", str(Path(directory) / "sandbox"), "--rules", str(output / "etc/nftables.d/dohdns.nft"))
            self.assertEqual(0, result.returncode, result.stderr)

    def test_resolver_has_no_loop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "staging"
            render_deployment(self.inventory, output)
            resolved = (output / "etc/systemd/resolved.conf.d/dohdns.conf").read_text()
            self.assertIn("DNSStubListener=no", resolved)
            self.assertIn("DNS=1.1.1.1 1.0.0.1", resolved)
            self.assertNotIn("dns.pressroll.ru", resolved)
            self.assertNotIn("127.0.0.1", resolved)

    def test_geoip_update_is_atomic_on_success_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sandbox"
            db = root / "var/lib/dohdns/geoip/Country-without-asn.mmdb"
            db.parent.mkdir(parents=True)
            db.write_bytes(b"old-valid-mmdb")
            source = Path(directory) / "Country-without-asn.mmdb"
            source.write_bytes(b"new-valid-mmdb")
            checksum = hashlib.sha256(source.read_bytes()).hexdigest()
            result = run(
                str(GEOIP_UPDATE), "--root", str(root), "--input", str(source), "--sha256", checksum,
                env={**os.environ, "DOHDNS_SKIP_MMDBLOOKUP": "1"},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(source.read_bytes(), db.read_bytes())
            self.assertEqual(b"old-valid-mmdb", (db.with_suffix(db.suffix + ".previous")).read_bytes())
            source.write_bytes(b"bad")
            bad = run(
                str(GEOIP_UPDATE), "--root", str(root), "--input", str(source), "--sha256", checksum,
                env={**os.environ, "DOHDNS_SKIP_MMDBLOOKUP": "1"},
            )
            self.assertNotEqual(0, bad.returncode)
            self.assertEqual(b"new-valid-mmdb", db.read_bytes())

    def test_validate_mmdb_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run(str(VALIDATE_MMDB), "--path", str(Path(directory) / "missing.mmdb"))
            self.assertNotEqual(0, result.returncode)


if __name__ == "__main__":
    unittest.main()
