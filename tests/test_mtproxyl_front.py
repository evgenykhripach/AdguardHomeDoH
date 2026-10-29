from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.lib.mtproxyl_front import check_admin_sni, patch, unpatch, render_http, render_admin_http, _strip

DOMAIN = 'dns.example.com'
ADMIN = 'admin.dns.example.com'
SOURCE = '''worker_processes 1;
events { worker_connections 1024; }
stream {
    map $ssl_preread_server_name $mtproxyl_upstream {
        web.dns.example.com mtproxyl_web;
        default mtproxyl_faketls;
    }
    upstream mtproxyl_web { server 127.0.0.1:15444; }
    upstream mtproxyl_faketls { server 127.0.0.1:15443; }
    server { listen 443; ssl_preread on; proxy_pass $mtproxyl_upstream; proxy_protocol on; }
}
http {
    server {
        listen 127.0.0.1:8444 ssl;
        server_name dns.example.com;
        ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
        location / { try_files $uri $uri/ =404; }
    }
}
'''


# Synthetic version of the six-server layout, with no production data.
REALISTIC = SOURCE.replace('http {\n', """http {
    include /opt/mtproxyl-nginx/conf/mime.types;
    server { listen 80 default_server; server_name _; return 444; }
    server { listen 80; server_name dns.example.com; return 301 https://dns.example.com$request_uri; }
    server { listen 127.0.0.1:8444 ssl default_server; server_name _; return 444; }
    server { listen 127.0.0.1:15444 ssl proxy_protocol default_server; server_name _; return 444; }
    server { listen 127.0.0.1:15444 ssl proxy_protocol; server_name web.dns.example.com; location / { return 200; } }
""").replace('        location / { try_files', r'''        error_page 404 /404.html;
        location ~* "(wget|curl|chmod|/tmp/|eval\\(|base64)" { return 403; }
        location / { try_files''')


class AdminSniPreflightTest(unittest.TestCase):
    @staticmethod
    def with_entries(entries, *, hostnames=False):
        extra = ('hostnames;\n        ' if hostnames else '') + entries
        return SOURCE.replace('web.dns.example.com mtproxyl_web;',
                              extra + '\n        web.dns.example.com mtproxyl_web;')

    def test_typical_vendor_maps_and_unrelated_routes_are_safe(self):
        candidates = (
            SOURCE,
            REALISTIC,
            self.with_entries('other.example.com mtproxyl_web;\n        "" mtproxyl_faketls;'),
            self.with_entries('*.other.example.com mtproxyl_web;\n'
                              '        .another.example.com mtproxyl_web;\n'
                              '        mail.* mtproxyl_faketls;', hostnames=True),
            self.with_entries('volatile; other.example.com mtproxyl_web;', hostnames=True),
            self.with_entries('"*.other.example.com" mtproxyl_web; # benign mask\n'
                              '        \'MAIL.*\' mtproxyl_faketls; # benign suffix', hostnames=True)
            .replace('web.dns.example.com mtproxyl_web;',
                     '"WEB.DNS.EXAMPLE.COM" "mtproxyl_web"; # web route'),
        )
        for source in candidates:
            with self.subTest(source=source):
                self.assertIsNone(check_admin_sni(source, DOMAIN, ADMIN))

    def test_reserved_hosts_and_exact_matches_ignore_case_and_final_dot(self):
        for admin in (DOMAIN, DOMAIN.upper() + '.', 'web.' + DOMAIN,
                      'WEB.' + DOMAIN.upper() + '.'):
            with self.subTest(admin=admin), self.assertRaisesRegex(ValueError, 'reserved'):
                check_admin_sni(SOURCE, DOMAIN, admin)
        for key in (ADMIN, ADMIN.upper(), ADMIN + '.', '"' + ADMIN.upper() + '."'):
            source = self.with_entries(key + ' mtproxyl_web;')
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'existing SNI route'):
                check_admin_sni(source, DOMAIN.upper() + '.', ADMIN.upper() + '.')

    def test_applicable_hostname_masks_are_rejected(self):
        for key in ('*.dns.example.com', '*.EXAMPLE.COM.', '.dns.example.com',
                    '.admin.dns.example.com', 'admin.*', 'ADMIN.DNS.*'):
            source = self.with_entries(key + ' mtproxyl_web;', hostnames=True)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'existing SNI route'):
                check_admin_sni(source, DOMAIN, ADMIN)

    def test_existing_root_faketls_and_web_routes_remain_unambiguous(self):
        cases = (
            self.with_entries('dns.example.com mtproxyl_web;'),
            self.with_entries('dns.* mtproxyl_web;', hostnames=True),
            SOURCE.replace('web.dns.example.com mtproxyl_web;',
                           'web.dns.example.com. mtproxyl_web;'),
            self.with_entries('hostnames;').replace('web.dns.example.com mtproxyl_web;',
                                                   'web.dns.example.com. mtproxyl_web;'),
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                check_admin_sni(source, DOMAIN, ADMIN)

    def test_regex_is_rejected_even_when_it_looks_harmless(self):
        for key in ('~^admin',
                    '"~*^other\\.example\\.com$"', '"~^(?P<name>.*)$"'):
            source = self.with_entries(key + ' mtproxyl_web;')
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'regex'):
                check_admin_sni(source, DOMAIN, ADMIN)

    def test_duplicate_exact_and_mask_entries_are_rejected(self):
        cases = (
            'WEB.DNS.EXAMPLE.COM mtproxyl_web;',
            'other.example.com mtproxyl_web; OTHER.EXAMPLE.COM. mtproxyl_web;',
            '.other.example.com mtproxyl_web; other.example.com mtproxyl_web;',
            '.other.example.com mtproxyl_web; *.other.example.com mtproxyl_web;',
            'mail.* mtproxyl_web; MAIL.* mtproxyl_web;',
            '"" mtproxyl_web; \'\' mtproxyl_web;',
        )
        for entries in cases:
            source = self.with_entries(entries, hostnames=True)
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, 'duplicate'):
                check_admin_sni(source, DOMAIN, ADMIN)

    def test_unknown_or_invalid_map_forms_fail_closed(self):
        cases = (
            self.with_entries('hostnames; hostnames;'),
            self.with_entries('other.example.com mtproxyl_web; hostnames;'),
            self.with_entries('volatile; volatile;'),
            self.with_entries('include /tmp/unknown;'),
            self.with_entries('other.example.com;'),
            self.with_entries('other.example.com mtproxyl_web extra;'),
            self.with_entries('other.example.com { }'),
            self.with_entries('*.other.example.com mtproxyl_web;'),
            self.with_entries('bad.*.example.com mtproxyl_web;', hostnames=True),
            self.with_entries('*.* mtproxyl_web;', hostnames=True),
            self.with_entries('"other\\.example.com" mtproxyl_web;'),
            SOURCE.replace('default mtproxyl_faketls;', 'default mtproxyl_web;'),
            SOURCE.replace('default mtproxyl_faketls;', 'default mtproxyl_faketls; default mtproxyl_faketls;'),
            SOURCE.replace('default mtproxyl_faketls;', ''),
            SOURCE.replace('web.dns.example.com mtproxyl_web;', 'web.dns.example.com mtproxyl_faketls;'),
            SOURCE.replace('web.dns.example.com mtproxyl_web;', ''),
            SOURCE.replace('stream {', 'include /tmp/unknown;\nstream {'),
            SOURCE.replace('stream {', 'stream { include /tmp/unknown;'),
            SOURCE.replace('stream {', 'stream { map $other $other_result { default no; }'),
            SOURCE.replace('stream {', 'stream { server extra { listen 443; }'),
            SOURCE.replace('proxy_pass $mtproxyl_upstream;', 'proxy_pass $other;'),
            SOURCE.replace('ssl_preread on;', 'ssl_preread off;'),
            SOURCE.replace('listen 443;', 'listen 443; listen 8443;'),
            SOURCE + 'stream { }',
            SOURCE.replace('map $ssl_preread_server_name $mtproxyl_upstream',
                           'map $other $mtproxyl_upstream'),
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                check_admin_sni(source, DOMAIN, ADMIN)

    def test_invalid_domain_inputs_fail_closed(self):
        for name in ('', 'default', 'admin..example.com', '*.example.com',
                     'admin.dns.example.com..', None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_admin_sni(SOURCE, DOMAIN, name)

    def test_preflight_has_no_io_or_process_side_effects(self):
        with mock.patch('builtins.open', side_effect=AssertionError('unexpected file access')), \
             mock.patch('os.open', side_effect=AssertionError('unexpected file access')), \
             mock.patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
            self.assertIsNone(check_admin_sni(SOURCE, DOMAIN, ADMIN))


class OverlayTest(unittest.TestCase):
    def test_roundtrip_and_idempotence(self):
        result = patch(SOURCE, DOMAIN)
        self.assertEqual(patch(result, DOMAIN), result)
        self.assertEqual(unpatch(result, DOMAIN), SOURCE)
        self.assertEqual(unpatch(SOURCE, DOMAIN), SOURCE)
        self.assertIn('web.dns.example.com mtproxyl_web;', result)
        self.assertIn('default mtproxyl_faketls;', result)
        self.assertIn('location / { try_files $uri $uri/ =404; }', result)
        self.assertIn('server 127.0.0.1:24443;', result)
        self.assertEqual(result.count('hostnames;'), 1)
        self.assertNotIn('dns.example.com adguardhome_doh;', result)
        self.assertNotIn('location ~', result)

    def test_empty_quoted_argument_and_unclosed_quotes(self):
        source = REALISTIC.replace('http {', "http {\n    add_header X-Empty '';\n    add_header X-Also-Empty \"\";")
        result = patch(source, DOMAIN)
        self.assertEqual(unpatch(result, DOMAIN), source)
        for bad in (source.replace("X-Empty '';", "X-Empty ';"),
                    source.replace('X-Also-Empty "";', 'X-Also-Empty ";')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                patch(bad, DOMAIN)

    def test_map_empty_key_allowed_only_as_map_entry(self):
        mapping = "map $http_upgrade $connection_upgrade { default upgrade; '' close; }"
        source = REALISTIC.replace('http {', 'http {\n    ' + mapping)
        self.assertEqual(unpatch(patch(source, DOMAIN), DOMAIN), source)
        bad = (
            REALISTIC.replace('http {', "http { '' close;"),
            REALISTIC.replace('http {', "http { map $http_upgrade $connection_upgrade { '' close extra; }"),
            REALISTIC.replace('http {', "http { map $http_upgrade $connection_upgrade { '' close { } }"),
            REALISTIC.replace('http {', "http { map $http_upgrade $connection_upgrade { ' close; }"),
        )
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                patch(candidate, DOMAIN)

    def test_six_server_template_is_preserved_and_idempotent(self):
        result = patch(REALISTIC, DOMAIN)
        self.assertEqual(unpatch(result, DOMAIN), REALISTIC)
        self.assertEqual(patch(result, DOMAIN), result)
        self.assertEqual(result.count('include /etc/adguardhome-doh/mtproxyl-http.conf;'), 1)
        self.assertIn('include /opt/mtproxyl-nginx/conf/mime.types;', result)
        self.assertIn('error_page 404 /404.html;', result)
        self.assertIn('web.dns.example.com mtproxyl_web;', result)
        self.assertIn('default mtproxyl_faketls;', result)
        self.assertIn('server 127.0.0.1:15443;', result)
        self.assertIn('server 127.0.0.1:15444;', result)

    def test_rejects_competing_six_server_variants(self):
        variants = [
            REALISTIC.replace('server_name _; return 444; }\n    server { listen 127.0.0.1:15444', 'server_name dns.example.com; return 444; }\n    server { listen 127.0.0.1:15444', 1),
            REALISTIC.replace('listen 127.0.0.1:8444 ssl default_server;', 'listen 127.0.0.1:8444 ssl;'),
            REALISTIC.replace('listen 127.0.0.1:8444 ssl default_server;', 'listen 0.0.0.0:8444 ssl default_server;'),
            REALISTIC.replace('web.dns.example.com mtproxyl_web;', 'web.dns.example.com mtproxyl_faketls;'),
            REALISTIC.replace('127.0.0.1:15444;', '127.0.0.1:15445;'),
            REALISTIC.replace('include /opt/mtproxyl-nginx/conf/mime.types;', 'include /tmp/unknown;'),
            REALISTIC.replace('error_page 404 /404.html;', 'error_page 404 /doh/error;'),
            REALISTIC.replace('location ~*', 'location = /doh/abc { return 403; } location ~*'),
            REALISTIC.replace('(wget|curl|chmod|/tmp/|eval', '(wget|curl|chmod|/doh/|eval'),
            REALISTIC.replace('return 403; }', 'return 200; }'),
        ]
        for source in variants:
            with self.subTest(source=source), self.assertRaises(ValueError):
                patch(source, DOMAIN)

    def test_http_is_token_free_and_verified(self):
        result = render_http(DOMAIN)
        self.assertEqual(result.count('location ~'), 2)
        self.assertIn('^/doh/[a-f0-9]{32,64}$', result)
        self.assertIn(r'^/[a-f0-9]{32,64}\.mobileconfig$', result)
        for expected in ('access_log off;', 'proxy_pass https://127.0.0.1:4443;',
                         'proxy_ssl_server_name on;', 'proxy_ssl_name dns.example.com;',
                         'proxy_ssl_verify on;', 'proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;',
                         'proxy_set_header Host dns.example.com;'):
            self.assertEqual(result.count(expected), 2)
        self.assertNotIn('a' * 48, result)

    def test_rejects_ambiguous_structures(self):
        cases = [
            SOURCE.replace('default mtproxyl_faketls;', 'default mtproxyl_web;'),
            SOURCE.replace('default mtproxyl_faketls;', 'default mtproxyl_faketls; default mtproxyl_faketls;'),
            SOURCE.replace('web.dns.example.com mtproxyl_web;', 'dns.example.com mtproxyl_web;'),
            SOURCE.replace('web.dns.example.com mtproxyl_web;', '*.pressroll.ru mtproxyl_web;'),
            SOURCE.replace('upstream mtproxyl_web', 'upstream adguardhome_doh { server 127.0.0.1:1; } upstream mtproxyl_web'),
            SOURCE.replace('http {', 'http { server { listen 127.0.0.1:8444 ssl default_server; }'),
            SOURCE.replace('server_name dns.example.com;', 'server_name dns.example.com other.example;'),
            SOURCE.replace('location / {', 'location ^~ /doh/ { return 200; } location / {'),
            SOURCE.replace('location / {', 'location ~ "^/doh/" { return 200; } location / {'),
            SOURCE.replace('location / {', 'include /tmp/unknown; location / {'),
            SOURCE.replace('listen 443;', 'listen 443; listen 8443;'),
            SOURCE.replace('proxy_protocol on;', 'proxy_protocol off;'),
            SOURCE.replace('proxy_pass $mtproxyl_upstream;', 'proxy_pass $mtproxyl_upstream; proxy_pass mtproxyl_web;'),
            SOURCE.replace('events {', 'events { include /tmp/unknown;'),
            SOURCE.replace('http {', 'http { rewrite ^ /doh/x;'),
            SOURCE + '}',
        ]
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                patch(candidate, DOMAIN)

    def test_partial_duplicate_moved_and_modified_overlay_fail(self):
        result = patch(SOURCE, DOMAIN)
        for candidate in (result.replace('        hostnames;\n', ''),
                          result.replace('# END DOHDNS MTPROXYL HTTP', '# END OTHER'),
                          result + '# BEGIN DOHDNS MTPROXYL MAP\n',
                          result.replace('hostnames;', 'hostnames; hostnames;')):
            for operation in (patch, unpatch):
                with self.subTest(operation=operation, candidate=candidate), self.assertRaises(ValueError):
                    operation(candidate, DOMAIN)

    def test_bad_domains_fail(self):
        for domain in ('UPPER.example', 'dns.example;bad', '*.example.org', 'example', 'bad..org', '-a.org'):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                render_http(domain)

    def test_cli_rejects_mutating_subcommands(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_front.py'
        for command in ('apply', 'remove'):
            result = subprocess.run(['python3', str(script), command], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'invalid choice', result.stderr)

    def test_cli_render_http_private_exclusive_and_deterministic(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_front.py'
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            first, second, link = (folder / name for name in ('first', 'second', 'link'))
            cmd = ['python3', str(script), 'render-http', '--domain', DOMAIN, '--output', str(first)]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            self.assertEqual(first.read_text(), render_http(DOMAIN))
            self.assertNotIn('a' * 48, first.read_text())
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            cmd[-1] = str(second)
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            link.symlink_to(first)
            cmd[-1] = str(link)
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(first.read_text(), render_http(DOMAIN))
            cmd[-1] = str(folder / 'bad')
            cmd[cmd.index(DOMAIN)] = 'bad;domain'
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertFalse((folder / 'bad').exists())

    def test_cli_exclusive_private_output_and_symlinks(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_front.py'
        with tempfile.TemporaryDirectory() as tmp:
            src, out, link = (Path(tmp).resolve() / n for n in ('src', 'out', 'link'))
            src.write_text(SOURCE)
            cmd = ['python3', str(script), 'render', '--source', str(src), '--domain', DOMAIN, '--output', str(out)]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.read_text(), patch(SOURCE, DOMAIN))
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            link.symlink_to(src)
            cmd[cmd.index(str(src))] = str(link)
            cmd[cmd.index(str(out))] = str(Path(tmp).resolve() / 'new')
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            link.unlink()
            link.symlink_to(src)
            cmd[cmd.index(str(link))] = str(src)
            cmd[cmd.index(str(Path(tmp).resolve() / 'new'))] = str(link)
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(src.read_text(), SOURCE)
            dirlink = Path(tmp).resolve().parent / (Path(tmp).name + '-link')
            dirlink.symlink_to(Path(tmp).resolve(), target_is_directory=True)
            try:
                cmd[cmd.index(str(src))] = str(dirlink / 'src')
                cmd[cmd.index(str(link))] = str(Path(tmp).resolve() / 'new')
                self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            finally:
                dirlink.unlink()


class AdminHttpOverlayTest(unittest.TestCase):
    root = '/var/www/adguardhome-doh-acme'

    def test_optional_overlay_roundtrip(self):
        result = patch(REALISTIC, DOMAIN, ADMIN)
        self.assertEqual(patch(result, DOMAIN, ADMIN), result)
        self.assertEqual(unpatch(result, DOMAIN, ADMIN), REALISTIC)
        self.assertEqual(unpatch(REALISTIC, DOMAIN, ADMIN), REALISTIC)
        self.assertEqual(result.count('include /etc/adguardhome-doh/mtproxyl-admin-acme.conf;'), 1)
        self.assertIn('web.dns.example.com mtproxyl_web;', result)
        self.assertIn('default mtproxyl_faketls;', result)
        self.assertIn('listen 80 default_server; server_name _; return 444;', result)
        with self.assertRaises(ValueError):
            unpatch(result, DOMAIN)
        with self.assertRaisesRegex(ValueError, 'explicit handling'):
            _strip(result)
        self.assertEqual(_strip(patch(REALISTIC, DOMAIN)), (REALISTIC, True))

    def test_conflicts_and_unprovable_routing_fail(self):
        for name in (ADMIN, ADMIN.upper(), ADMIN + '.', '"' + ADMIN.upper() + '"',
                     '*.dns.example.com', '.example.com', '"~^admin"', '$hostname'):
            source = REALISTIC.replace('server_name dns.example.com; return 301',
                                       'server_name ' + name + '; return 301')
            with self.subTest(name=name), self.assertRaises(ValueError):
                patch(source, DOMAIN, ADMIN)
        for source in (REALISTIC.replace('listen 80;', 'listen 127.0.0.1:80;'),
                       REALISTIC.replace('listen 80;', 'listen 80 reuseport;'),
                       REALISTIC.replace('http {', 'http { include /tmp/other;')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                patch(source, DOMAIN, ADMIN)
        for name in (DOMAIN, 'web.' + DOMAIN, 'ADMIN.example.com', 'a.example.com;return 200'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                patch(REALISTIC, DOMAIN, name)

    def test_admin_marker_is_strict(self):
        result = patch(REALISTIC, DOMAIN, ADMIN)
        for candidate in (result + '# DOHDNS MTPROXYL ADMIN HTTP\n',
                          result.replace('ADMIN HTTP', 'ADMIN OTHER', 1),
                          result.replace('include /etc/adguardhome-doh/mtproxyl-admin-acme.conf;',
                                         'include /tmp/foreign;'),
                          result.replace('    # END DOHDNS MTPROXYL ADMIN HTTP\n',
                                         '    # END DOHDNS MTPROXYL ADMIN HTTP\n' * 2)):
            for op in (patch, unpatch):
                with self.subTest(op=op), self.assertRaises(ValueError):
                    op(candidate, DOMAIN, ADMIN)

    def test_render_limits_tokens_and_paths(self):
        config = render_admin_http(ADMIN, self.root)
        self.assertIn('server_name ' + ADMIN + ';', config)
        self.assertIn('([A-Za-z0-9_-]+)$', config)
        self.assertIn('alias ' + self.root + '/.well-known/acme-challenge/$1;', config)
        self.assertIn('disable_symlinks on;', config)
        self.assertIn('location / { return 404; }', config)
        for root in ('/tmp/acme', '/var/www/adguardhome-doh-acme/../x',
                     '/var/lib/adguardhome-doh/acme;', '/var/lib/adguardhome-doh/acme/',
                     '/var/lib/adguardhome-doh/a b', '/var/lib/adguardhome-doh/$host'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                render_admin_http(ADMIN, root)
        for name in ('ADMIN.example.com', 'x.example.com;return 200', '*.example.com'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                render_admin_http(name, self.root)


if __name__ == '__main__':
    unittest.main()
