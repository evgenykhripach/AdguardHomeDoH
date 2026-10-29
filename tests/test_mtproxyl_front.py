import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.lib import mtproxyl_front as front

from deploy.lib.mtproxyl_front import patch, unpatch, render_http

DOMAIN = 'dns.example.com'
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

    def test_apply_remove_validate_and_preserve_metadata(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_front.py'
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            source, nginx = folder / 'nginx.conf', folder / 'nginx'
            source.write_text(REALISTIC)
            source.chmod(0o640)
            nginx.write_text('#!/bin/sh\nexit 0\n')
            nginx.chmod(0o700)
            original = source.stat()
            command = ['python3', str(script), 'apply', '--source', str(source),
                       '--domain', DOMAIN, '--nginx-bin', str(nginx)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.read_text(), patch(REALISTIC, DOMAIN))
            after = source.stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode & 0o7777),
                             (original.st_uid, original.st_gid, original.st_mode & 0o7777))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.stat().st_ino, after.st_ino)
            command[2] = 'remove'
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.read_text(), REALISTIC)
            after = source.stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode & 0o7777),
                             (original.st_uid, original.st_gid, original.st_mode & 0o7777))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.stat().st_ino, after.st_ino)
            self.assertEqual(sorted(p.name for p in folder.iterdir()), ['nginx', 'nginx.conf'])

    def test_apply_reject_and_concurrent_source_change(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_front.py'
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            source, nginx = folder / 'nginx.conf', folder / 'nginx'
            source.write_text(REALISTIC)
            nginx.write_text('#!/bin/sh\necho SECRET_CONFIG_CONTENT >&2\nexit 1\n')
            nginx.chmod(0o700)
            cmd = ['python3', str(script), 'apply', '--source', str(source),
                   '--domain', DOMAIN, '--nginx-bin', str(nginx)]
            result = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'SECRET_CONFIG_CONTENT', result.stderr)
            self.assertEqual(source.read_text(), REALISTIC)
            nginx.write_text('#!/bin/sh\nprintf changed > ' + str(source) + '\nexit 0\n')
            result = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_text(), 'changed')
            self.assertEqual(sorted(p.name for p in folder.iterdir()), ['nginx', 'nginx.conf'])
            link = folder / 'link'
            link.symlink_to(source)
            cmd[cmd.index(str(source))] = str(link)
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(source.read_text(), 'changed')

    def test_best_effort_missing_includes_and_unknown_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            source, nginx = folder / 'nginx.conf', folder / 'nginx'
            source.write_text(REALISTIC)
            nginx.write_text('#!/bin/sh\nexit 0\n')
            nginx.chmod(0o700)
            with mock.patch.object(front, '_includes_available', return_value=False):
                front.apply_or_remove(source, DOMAIN, nginx, best_effort=True)
                self.assertEqual(source.read_text(), REALISTIC)
                source.write_text(patch(REALISTIC, DOMAIN))
                front.apply_or_remove(source, DOMAIN, nginx, best_effort=True)
                self.assertEqual(source.read_text(), REALISTIC)
                overlay = patch(REALISTIC, DOMAIN)
                source.write_text(overlay)
                nginx.write_text('#!/bin/sh\nexit 1\n')
                front.apply_or_remove(source, DOMAIN, nginx, best_effort=True)
                self.assertEqual(source.read_text(), overlay)
            source.write_text('events {}')
            with mock.patch.object(front, '_includes_available', return_value=True):
                front.apply_or_remove(source, DOMAIN, nginx, best_effort=True)
                self.assertEqual(source.read_text(), 'events {}')
                with self.assertRaises(ValueError):
                    front.apply_or_remove(source, DOMAIN, nginx)
                # No managed overlay: removal does not depend on template support.
                front.apply_or_remove(source, DOMAIN, nginx, remove=True)
                self.assertEqual(source.read_text(), 'events {}')

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


if __name__ == '__main__':
    unittest.main()
