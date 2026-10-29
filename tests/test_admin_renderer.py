import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.render_config import (
    PolicyRow,
    render_mtproxyl_sni_map,
    render_nginx_http,
    render_nginx_stream,
)


ROOT = Path(__file__).resolve().parents[1]
DOH_HOST = "dns.example.com"
ADMIN_HOST = "admin.dns.example.com"
TOKEN = "a" * 48
CERTIFICATE = "/etc/letsencrypt/live/dns.example.com"
ADMIN_CERTIFICATE = "/etc/letsencrypt/live/admin.dns.example.com"
WEBROOT = "/var/www/adguardhome-doh"
ROWS = [PolicyRow("example.org", "suffix", ""), PolicyRow("api.other.org", "fqdn", "")]


class AdminRendererTests(unittest.TestCase):
    def render_http(self, **kwargs):
        return render_nginx_http(
            DOH_HOST, TOKEN, CERTIFICATE, WEBROOT, http2_directive=False,
            front="mtproxyl", **kwargs,
        )

    def test_admin_is_one_exact_sni_route_without_changing_other_routes(self):
        before = render_mtproxyl_sni_map(ROWS, DOH_HOST)
        after = render_mtproxyl_sni_map(ROWS, DOH_HOST, admin_host=ADMIN_HOST)
        self.assertEqual(before + ADMIN_HOST + " adguardhome_doh;\n", after)
        self.assertNotIn(DOH_HOST + " adguardhome_doh;", after.splitlines())
        self.assertNotIn("web." + DOH_HOST + " adguardhome_doh;", after.splitlines())
        self.assertNotIn("default ", after)

        before_stream = render_nginx_stream(ROWS, DOH_HOST, front="mtproxyl")
        after_stream = render_nginx_stream(ROWS, DOH_HOST, front="mtproxyl", admin_host=ADMIN_HOST)
        self.assertEqual(
            before_stream,
            after_stream.replace("        %s 127.0.0.1:4443;\n" % ADMIN_HOST, ""),
        )
        self.assertEqual(1, after_stream.count("        %s 127.0.0.1:4443;" % ADMIN_HOST))

    def test_admin_server_has_own_certificate_and_blocks_all_doh_paths(self):
        before = self.render_http()
        after = self.render_http(admin_host=ADMIN_HOST, admin_certificate_root=ADMIN_CERTIFICATE)
        self.assertEqual(1, after.count("server_name " + DOH_HOST + ";"))
        self.assertEqual(1, after.count("server_name " + ADMIN_HOST + ";"))
        main_server, admin_server = after.split("server {\n")[1:]
        self.assertIn("ssl_certificate %s/fullchain.pem;" % CERTIFICATE, main_server)
        self.assertIn("location = /doh/%s {" % TOKEN, main_server)
        self.assertIn("proxy_pass http://127.0.0.1:3001/dns-query;", main_server)
        self.assertIn("listen 127.0.0.1:4443 ssl http2;", admin_server)
        self.assertIn("ssl_certificate %s/fullchain.pem;" % ADMIN_CERTIFICATE, admin_server)
        self.assertIn("ssl_certificate_key %s/privkey.pem;" % ADMIN_CERTIFICATE, admin_server)
        self.assertIn("location ^~ /dns-query { return 404; }", admin_server)
        self.assertIn("location ^~ /doh { return 404; }", admin_server)
        self.assertNotIn(TOKEN, admin_server)
        self.assertNotIn("proxy_pass http://127.0.0.1:3001/dns-query;", admin_server)
        self.assertIn("location / {\n        proxy_pass http://127.0.0.1:3001;", admin_server)
        for server in (main_server, admin_server):
            login = server.split("location = /control/login {", 1)[1].split("    }", 1)[0]
            self.assertIn("limit_req zone=adguardhome_doh_login burst=5 nodelay;", login)
            self.assertIn("limit_req_status 429;", login)
        self.assertEqual(1, after.count("limit_req_zone $binary_remote_addr"))
        self.assertIn("if ($adguardhome_doh_admin_sni) { return 421; }", main_server)
        self.assertIn("if ($adguardhome_doh_admin_sni = 0) { return 421; }", admin_server)
        self.assertIn("map $ssl_server_name $adguardhome_doh_admin_sni {", after)
        self.assertIn("        %s 1;" % ADMIN_HOST, after)
        self.assertNotIn("adguardhome_doh_admin_sni", before)
        modern = render_nginx_http(
            DOH_HOST, TOKEN, CERTIFICATE, WEBROOT, http2_directive=True, front="mtproxyl",
            admin_host=ADMIN_HOST, admin_certificate_root=ADMIN_CERTIFICATE,
        )
        self.assertEqual(2, modern.count("    http2 on;"))
        self.assertNotIn("ssl http2;", modern)

    def test_admin_hostname_is_normalized_and_exact_catalog_parent_is_allowed(self):
        rows = [PolicyRow(DOH_HOST, "fqdn", "")]
        mapping = render_mtproxyl_sni_map(rows, DOH_HOST, admin_host="ADMIN.DNS.EXAMPLE.COM")
        self.assertEqual(ADMIN_HOST + " adguardhome_doh;\n", mapping)
        stream = render_nginx_stream(rows, DOH_HOST, front="mtproxyl", admin_host="ADMIN.DNS.EXAMPLE.COM")
        self.assertIn(ADMIN_HOST + " 127.0.0.1:4443;", stream)

    def test_admin_routes_reject_conflicts_and_invalid_hosts(self):
        conflicts = [
            (DOH_HOST, ROWS),
            ("web." + DOH_HOST, ROWS),
            (ADMIN_HOST, [PolicyRow(ADMIN_HOST, "fqdn", "")]),
            (ADMIN_HOST, [PolicyRow(ADMIN_HOST, "suffix", "")]),
            (ADMIN_HOST, [PolicyRow("dns.example.com", "suffix", "")]),
            (ADMIN_HOST, [PolicyRow("example.com", "suffix", "")]),
        ]
        for host, rows in conflicts:
            with self.subTest(host=host, rows=rows):
                with self.assertRaises(ValueError):
                    render_mtproxyl_sni_map(rows, DOH_HOST, admin_host=host)
                with self.assertRaises(ValueError):
                    render_nginx_stream(rows, DOH_HOST, front="mtproxyl", admin_host=host)
        for host in ("", "bad host", "admin.example.com; return 200", "*.example.com", "admin.example.com."):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.render_http(admin_host=host, admin_certificate_root=ADMIN_CERTIFICATE)
        for host in (DOH_HOST, "web." + DOH_HOST):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.render_http(admin_host=host, admin_certificate_root=ADMIN_CERTIFICATE)

    def test_admin_requires_pair_mtproxyl_and_safe_paths(self):
        for kwargs in (
            {"admin_host": ADMIN_HOST},
            {"admin_certificate_root": ADMIN_CERTIFICATE},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": ""},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": "relative/cert"},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": "/cert/../other"},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": "/cert; return 200"},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": "/cert\nserver {"},
            {"admin_host": ADMIN_HOST, "admin_certificate_root": "/cert/$host"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.render_http(**kwargs)
        with self.assertRaises(ValueError):
            render_nginx_http(DOH_HOST, TOKEN, CERTIFICATE, WEBROOT, front="standard",
                              admin_host=ADMIN_HOST, admin_certificate_root=ADMIN_CERTIFICATE)
        with self.assertRaises(ValueError):
            render_nginx_stream(ROWS, DOH_HOST, admin_host=ADMIN_HOST)
        for certificate, webroot in (("/cert; return 200", WEBROOT), (CERTIFICATE, "/web; return 200")):
            with self.subTest(certificate=certificate, webroot=webroot), self.assertRaises(ValueError):
                render_nginx_http(DOH_HOST, TOKEN, certificate, webroot, front="mtproxyl",
                                  admin_host=ADMIN_HOST, admin_certificate_root=ADMIN_CERTIFICATE)


class AdminRuntimeRendererTests(unittest.TestCase):
    def run_renderer(self, output, *extra):
        return subprocess.run([
            sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
            "--config-dir", str(ROOT / "config"), "--front", "mtproxyl", "--services", "chatgpt",
            "--public-ip", "203.0.113.10", "--doh-host", DOH_HOST, "--doh-token", TOKEN,
            "--password-hash", "hash", "--certificate-root", CERTIFICATE,
            "--webroot", WEBROOT, "--output", str(output), *extra,
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_cli_stages_admin_and_remains_compatible_without_options(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stage"
            result = self.run_renderer(stage, "--admin-host", ADMIN_HOST,
                                       "--admin-certificate-root", ADMIN_CERTIFICATE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(ADMIN_HOST + " adguardhome_doh;", (stage / "mtproxyl-sni.map").read_text())
            self.assertIn(ADMIN_HOST + " 127.0.0.1:4443;", (stage / "nginx-stream.conf").read_text())
            self.assertIn("server_name " + ADMIN_HOST + ";", (stage / "nginx-http.conf").read_text())
            previous = Path(directory) / "previous"
            result = self.run_renderer(previous)
            self.assertEqual(0, result.returncode, result.stderr)
            for name in ("mtproxyl-sni.map", "nginx-stream.conf", "nginx-http.conf"):
                self.assertNotIn(ADMIN_HOST, (previous / name).read_text())

    def test_cli_fails_before_staging_for_incomplete_or_conflicting_inputs(self):
        cases = (
            ("--admin-host", ADMIN_HOST),
            ("--admin-certificate-root", ADMIN_CERTIFICATE),
            ("--admin-host", "web." + DOH_HOST, "--admin-certificate-root", ADMIN_CERTIFICATE),
            ("--admin-host", "admin.spotify.com", "--admin-certificate-root", ADMIN_CERTIFICATE),
            ("--admin-host", ADMIN_HOST, "--admin-certificate-root", "/cert; return 200"),
            ("--front", "standard", "--admin-host", ADMIN_HOST, "--admin-certificate-root", ADMIN_CERTIFICATE),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, case in enumerate(cases):
                with self.subTest(case=case):
                    stage = Path(directory) / str(index)
                    result = self.run_renderer(stage, *case)
                    self.assertNotEqual(0, result.returncode)
                    self.assertFalse(stage.exists(), result.stderr)


if __name__ == "__main__":
    unittest.main()
