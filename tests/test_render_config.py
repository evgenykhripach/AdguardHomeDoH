import csv
import json
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.render_config import (
    Catalog,
    load_policy,
    nginx_version,
    render,
    render_adguard_yaml,
    render_nginx_http,
    render_nginx_stream,
    render_rewrites,
    render_mobileconfig,
    use_http2_directive,
)


class RenderConfigTests(unittest.TestCase):
    def test_mobileconfig_uses_system_scope_for_macos_dns_settings(self):
        token = "a" * 48
        payload = plistlib.loads(
            render_mobileconfig(
                "dns.example.com", token, "203.0.113.10",
                match_domains=["openai.com", "chatgpt.com", "OpenAI.com"],
            ).encode("utf-8")
        )

        self.assertEqual("System", payload["PayloadScope"])
        dns_settings = payload["PayloadContent"][0]["DNSSettings"]
        self.assertEqual("HTTPS", dns_settings["DNSProtocol"])
        # Scoped to the routed domains, an unreachable server costs exactly
        # those domains instead of every lookup on the device.
        self.assertEqual(["chatgpt.com", "openai.com"], dns_settings["SupplementalMatchDomains"])
        self.assertIs(True, dns_settings["AllowFailover"])
        self.assertEqual(
            "https://dns.example.com/doh/" + token,
            dns_settings["ServerURL"],
        )
        self.assertEqual(["203.0.113.10"], dns_settings["ServerAddresses"])
        self.assertEqual(
            "com.apple.dnsSettings.managed",
            payload["PayloadContent"][0]["PayloadType"],
        )
        self.assertNotIn(
            "com.apple.vpn.managed",
            [item["PayloadType"] for item in payload["PayloadContent"]],
        )

    def test_mobileconfig_rejects_invalid_or_ipv6_public_ip(self):
        for public_ip in ("not-an-ip", "2001:db8::10"):
            with self.assertRaises(ValueError):
                render_mobileconfig("dns.example.com", "a" * 48, public_ip)

    def test_mobileconfig_without_match_domains_keeps_the_device_wide_scope(self):
        payload = plistlib.loads(
            render_mobileconfig("dns.example.com", "a" * 48, "203.0.113.10").encode("utf-8")
        )
        self.assertNotIn("SupplementalMatchDomains", payload["PayloadContent"][0]["DNSSettings"])
        with self.assertRaises(ValueError):
            render_mobileconfig(
                "dns.example.com", "a" * 48, "203.0.113.10", match_domains=["bad host"]
            )

    def test_runtime_renderer_imports_when_installed_next_to_renderer(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            runtime_dir = Path(directory)
            shutil.copy2(root / "deploy/lib/render_runtime.py", runtime_dir / "render_runtime.py")
            shutil.copy2(root / "tools/render_config.py", runtime_dir / "render_config.py")
            result = subprocess.run(
                ["python3", str(runtime_dir / "render_runtime.py"), "--help"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--config-dir", result.stdout)

    def test_runtime_renderer_stages_domain_named_mobileconfig(self):
        root = Path(__file__).resolve().parents[1]
        token = "a" * 48
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run(
                [
                    "python3", str(root / "deploy/lib/render_runtime.py"),
                    "--config-dir", str(root / "config"),
                    "--services", "chatgpt",
                    "--public-ip", "203.0.113.10",
                    "--doh-host", "dns.example.com",
                    "--doh-token", token,
                    "--password-hash", "hash",
                    "--certificate-root", "/etc/letsencrypt/live/dns.example.com",
                    "--webroot", "/var/www/adguardhome-doh",
                    "--output", str(output),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            profile = output / "dns.example.com.mobileconfig"
            self.assertTrue(profile.is_file())
            contents = profile.read_text(encoding="utf-8")
            payload = plistlib.loads(profile.read_bytes())
        self.assertIn("https://dns.example.com/doh/" + token, contents)
        self.assertEqual("dns.example.com", payload["PayloadDisplayName"])
        self.assertEqual(
            "dns.example.com", payload["PayloadContent"][0]["PayloadDisplayName"]
        )
        self.assertEqual(
            ["203.0.113.10"],
            payload["PayloadContent"][0]["DNSSettings"]["ServerAddresses"],
        )
        with (root / "config" / "domains.csv").open(encoding="utf-8", newline="") as stream:
            catalog_domains = sorted(row["domain"] for row in csv.DictReader(stream))
        # The whole catalog is listed even though only ChatGPT is selected, so
        # a later service change never requires reinstalling the profile.
        self.assertEqual(
            catalog_domains,
            payload["PayloadContent"][0]["DNSSettings"]["SupplementalMatchDomains"],
        )
        self.assertIn("spotify.com", catalog_domains)
        self.assertIs(True, payload["PayloadContent"][0]["DNSSettings"]["AllowFailover"])

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
        self.assertIn(
            "resolver 9.9.9.10 149.112.112.10 1.1.1.1 8.8.8.8 valid=60s ipv4=on ipv6=off;",
            nginx,
        )
        self.assertIn("resolver_timeout 5s;", nginx)
        self.assertIn("proxy_timeout 1h;", nginx)
        self.assertIn(".oaiusercontent.com $ssl_preread_server_name:443;", nginx)
        self.assertIn("api.fitbit.com $ssl_preread_server_name:443;", nginx)
        self.assertNotIn("*.api.fitbit.com", nginx)
        self.assertEqual(
            "files.oaiusercontent.com",
            next(row.probe for row in rows if row.domain == "oaiusercontent.com"),
        )

    def test_resolver_survives_a_single_upstream_operator_failing(self):
        """A DoH client has no plain-DNS fallback, so the server must have one."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        adguard = render_adguard_yaml(rows, "$2a$10$hash")

        self.assertIn("  fallback_dns:\n    - tls://1.1.1.1", adguard)
        self.assertNotIn("  fallback_dns: []", adguard)
        # Bootstrap must not depend on one operator: without it no DoH
        # upstream hostname resolves and the server answers nothing at all.
        for server in ("9.9.9.10", "149.112.112.10", "1.1.1.1", "8.8.8.8"):
            self.assertIn("    - %s" % server, adguard)
        self.assertIn("  upstream_timeout: 4s", adguard)
        self.assertNotIn("  upstream_timeout: 10s", adguard)
        self.assertIn("  cache_optimistic: true", adguard)
        self.assertIn("  cache_ttl_min: 60", adguard)

    def test_panel_lockout_is_delegated_to_nginx_rate_limiting(self):
        """AdGuard keys its lockout on the proxy address shared by everyone."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        adguard = render_adguard_yaml(rows, "$2a$10$hash")
        http = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com",
            "/var/www/html", http2_directive=False,
        )

        self.assertIn("auth_attempts: 0", adguard)
        self.assertNotIn("auth_attempts: 5", adguard)
        self.assertIn(
            "limit_req_zone $binary_remote_addr zone=adguardhome_doh_login:1m rate=30r/m;",
            http,
        )
        login_block = http.split("    location = /control/login {", 1)[1].split("    }", 1)[0]
        self.assertIn("limit_req zone=adguardhome_doh_login burst=5 nodelay;", login_block)
        # DNS resolution itself must never be throttled.
        doh_block = http.split("    location = /doh/" + "a" * 48 + " {", 1)[1].split("    }", 1)[0]
        self.assertNotIn("limit_req", doh_block)

    def test_http2_syntax_follows_the_installed_nginx_release(self):
        legacy = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com",
            "/var/www/html", http2_directive=False,
        )
        modern = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com",
            "/var/www/html", http2_directive=True,
        )

        # Ubuntu 24.04 ships nginx 1.24, which rejects the directive outright.
        self.assertIn("    listen 127.0.0.1:4443 ssl http2;", legacy)
        self.assertNotIn("http2 on;", legacy)
        # nginx 1.25.1+ deprecated the listen parameter in favour of it.
        self.assertIn("    listen 127.0.0.1:4443 ssl;", modern)
        self.assertIn("    http2 on;", modern)
        self.assertIn("ssl_session_cache shared:adguardhome_doh:10m;", legacy)

    def test_http2_style_detection_reads_the_nginx_version_banner(self):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        self.assertEqual(
            (1, 24, 0),
            nginx_version(lambda *a, **k: Result(b"nginx version: nginx/1.24.0 (Ubuntu)")),
        )
        self.assertFalse(use_http2_directive(runner=lambda *a, **k: Result(b"nginx/1.24.0")))
        self.assertFalse(use_http2_directive(runner=lambda *a, **k: Result(b"nginx/1.25.0")))
        self.assertTrue(use_http2_directive(runner=lambda *a, **k: Result(b"nginx/1.25.1")))
        self.assertTrue(use_http2_directive(runner=lambda *a, **k: Result(b"nginx/1.28.0")))

        def missing(*args, **kwargs):
            raise OSError("nginx is not installed")

        # An unknown version must render what every supported release accepts.
        self.assertIsNone(nginx_version(missing))
        self.assertFalse(use_http2_directive(runner=missing))

    def test_healthy_rewrites_are_seeded_into_the_activated_configuration(self):
        """An update restarts AdGuard and drops the gate's API rewrites."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()

        empty = render_adguard_yaml(rows, "$2a$10$hash")
        seeded = render_adguard_yaml(
            rows, "$2a$10$hash",
            rewrites=render_rewrites(rows, "203.0.113.10"),
        )

        self.assertIn("  rewrites: []", empty)
        self.assertNotIn("  rewrites: []", seeded)
        self.assertIn("    - domain: 'example.com'", seeded)
        self.assertIn("    - domain: '*.example.com'", seeded)
        self.assertIn("      answer: 203.0.113.10", seeded)
        self.assertIn("      enabled: true", seeded)
        self.assertIn("  rewrites_enabled: true", seeded)

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
        self.assertIn("  ratelimit: 0", adguard)
        self.assertNotIn("  ratelimit: 20", adguard)
        self.assertIn("  rewrites: []", adguard)
        self.assertNotIn("answer: 127.0.0.1", adguard)
        self.assertIn("location = /doh/" + "a" * 48, http)
        self.assertIn("location = /" + "a" * 48 + ".mobileconfig {", http)
        self.assertIn("try_files /dns.example.com.mobileconfig =404;", http)
        self.assertIn(
            'Content-Disposition "attachment; filename=dns.example.com.mobileconfig"',
            http,
        )
        mobileconfig_block = http.split(
            "    location = /" + "a" * 48 + ".mobileconfig {", 1
        )[1].split("    }", 1)[0]
        doh_block = http.split("    location = /doh/" + "a" * 48 + " {", 1)[1].split(
            "    }", 1
        )[0]
        self.assertIn("        access_log off;", mobileconfig_block)
        self.assertIn("        access_log off;", doh_block)
        self.assertNotIn(
            "access_log off;",
            http.rsplit("    location / {", 1)[1].split("    }", 1)[0],
        )
        self.assertNotIn("listen 443 ssl", http)

    def test_routed_answers_outlive_a_cellular_stall(self):
        """Ten-second answers make a phone re-ask six times a minute."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        adguard = render_adguard_yaml(rows, "$2a$10$hash")

        self.assertIn("  blocked_response_ttl: 300", adguard)

    def test_untokenized_doh_paths_are_closed(self):
        """AdGuard also answers on /dns-query/<ClientID>, which no token guards."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        adguard = render_adguard_yaml(rows, "$2a$10$hash")
        http = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com",
            "/var/www/html", http2_directive=False,
        )

        self.assertIn("    location ^~ /dns-query { return 404; }", http)
        self.assertNotIn("location = /dns-query {", http)
        self.assertIn("      - POST /dns-query", adguard)
        self.assertNotIn("{ClientID}", adguard)

    def test_listeners_keep_carrier_nat_mappings_alive(self):
        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        stream = render_nginx_stream(rows, "dns.example.com")
        http = render_nginx_http(
            "dns.example.com", "a" * 48, "/etc/letsencrypt/live/dns.example.com",
            "/var/www/html", http2_directive=False,
        )

        self.assertIn("        listen 443 so_keepalive=30s:10s:3;", stream)
        self.assertIn("        listen [::]:443 so_keepalive=30s:10s:3;", stream)
        self.assertIn("        proxy_socket_keepalive on;", stream)
        self.assertIn("    keepalive_requests 100000;", http)

    def test_stream_connections_are_logged_with_truncated_client_addresses(self):
        """A stall report needs to say whether the ClientHello ever arrived."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        stream = render_nginx_stream(rows, "dns.example.com")

        self.assertNotIn("access_log off;", stream)
        self.assertIn(
            "        access_log /var/log/adguardhome-doh/nginx-stream.access.log"
            " adguardhome_doh_stream buffer=32k flush=5s;",
            stream,
        )
        self.assertIn("    map $remote_addr $adguardhome_doh_client {", stream)
        self.assertIn("        default anon;", stream)
        self.assertIn("$adguardhome_doh_net.0;", stream)
        for variable in ("$ssl_preread_server_name", "$status", "$session_time",
                         "$bytes_received", "$upstream_addr", "$upstream_connect_time"):
            self.assertIn(variable, stream)
        # The raw address must never reach the log.
        self.assertNotIn("client=$remote_addr", stream)

    def test_relay_hands_routed_services_to_one_exit_host(self):
        """Clients reach the relay; only the exit host can reach the sites."""

        path = self.write_policy([("example.com", "suffix", ""), ("api.fitbit.com", "fqdn", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        stream = render_nginx_stream(rows, "dns.example.com", relay="203.0.113.99")

        self.assertIn("        .example.com 203.0.113.99:443;", stream)
        self.assertIn("        api.fitbit.com 203.0.113.99:443;", stream)
        self.assertNotIn("$ssl_preread_server_name:443", stream)
        # DoH stays local and unknown names are still dropped on the relay.
        self.assertIn("        dns.example.com 127.0.0.1:4443;", stream)
        self.assertIn("        default 127.0.0.1:9;", stream)
        self.assertIn("$ssl_preread_server_name:443", render_nginx_stream(rows, "dns.example.com"))
        for bad in ("2001:db8::1", "not-an-ip"):
            with self.assertRaises(ValueError):
                render_nginx_stream(rows, "dns.example.com", relay=bad)

    def test_local_sites_are_served_behind_the_stream_listener(self):
        """An existing site keeps its name; unknown SNI can keep reaching it."""

        path = self.write_policy([("example.com", "suffix", "")])
        try:
            rows = load_policy(path)
        finally:
            path.unlink()
        stream = render_nginx_stream(
            rows, "dns.example.com",
            local_sites=["App.Example.org=127.0.0.1:9443", "*=127.0.0.1:9443"],
        )

        self.assertIn("        app.example.org 127.0.0.1:9443;", stream)
        self.assertIn("        default 127.0.0.1:9443;", stream)
        self.assertNotIn("default 127.0.0.1:9;", stream)
        self.assertIn("        dns.example.com 127.0.0.1:4443;", stream)
        self.assertIn("        default 127.0.0.1:9;", render_nginx_stream(rows, "dns.example.com"))
        for bad in (
            "app.example.org",                    # no address
            "app.example.org=127.0.0.1",          # no port
            "app.example.org=127.0.0.1:443",      # the listener owns 443
            "app.example.org=::1:9443",           # IPv6
            "dns.example.com=127.0.0.1:9443",     # the DoH host itself
            "example.com=127.0.0.1:9443",         # a routed domain
        ):
            with self.assertRaises(ValueError):
                render_nginx_stream(rows, "dns.example.com", local_sites=[bad])
        with self.assertRaises(ValueError):
            render_nginx_stream(rows, "dns.example.com",
                                local_sites=["a.example.org=127.0.0.1:1", "a.example.org=127.0.0.1:2"])

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
