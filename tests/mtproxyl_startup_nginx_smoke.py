#!/usr/bin/env python3
"""Run only inside a disposable, network-disabled container with real nginx.

Example: mount repository read-only at /repo, nginx binary at /tmp/nginx,
then run this script from a Python container as root with --network none.
"""
import os
import signal
import socket
import time
from pathlib import Path
import subprocess
import sys
import tempfile

if not Path('/.dockerenv').exists() or os.geteuid() != 0:
    raise SystemExit('disposable root container required')
sys.path.insert(0, '/repo')
from deploy.lib import mtproxyl_reload as startup
from deploy.lib import mtproxyl_front as front
from tests.test_mtproxyl_front import ADMIN, DOMAIN, REALISTIC

for path in ('/etc/adguardhome-doh', '/opt/mtproxyl-nginx/conf',
             '/etc/letsencrypt/live/dns.example.com', '/var/cache/nginx', '/var/log/nginx'):
    Path(path).mkdir(parents=True, exist_ok=True)
Path('/opt/mtproxyl-nginx/conf/mime.types').write_text('types { }\n')
Path('/etc/adguardhome-doh/mtproxyl-sni.map').write_text('doh.example.com adguardhome_doh;\n')
Path('/etc/adguardhome-doh/mtproxyl-http.conf').write_text('location = /doh-test { return 200; }\n')
Path('/etc/adguardhome-doh/mtproxyl-admin-acme.conf').write_text('server { listen 127.0.0.1:18081; server_name admin.dns.example.com; }\n')
subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
                '-subj', '/CN=dns.example.com', '-keyout', '/etc/letsencrypt/live/dns.example.com/privkey.pem',
                '-out', '/etc/letsencrypt/live/dns.example.com/fullchain.pem'],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
source = 'user root;\n' + REALISTIC.replace('return 444;', 'return 200 first;', 1).replace('http {\n', 'http {\n    ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;\n')
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    vendor, target, lock = root / 'vendor.conf', root / 'runtime.conf', root / 'front.lock'
    vendor.write_text(source)
    args = dict(source=vendor, runtime_path=target, domain=DOMAIN, admin_host=ADMIN,
                nginx_bin=Path('/tmp/nginx'), lock_path=lock)
    candidate = root / 'check.conf'
    candidate.write_text(front.patch(source, DOMAIN, ADMIN))
    subprocess.run(['/tmp/nginx', '-t', '-c', str(candidate)], check=True)
    assert startup.prepare_startup(**args) == 'overlay'
    process = subprocess.Popen(['/tmp/nginx', '-c', str(target), '-g', 'daemon off;'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def response():
        with socket.create_connection(('127.0.0.1', 80), timeout=1) as conn:
            conn.sendall(b'GET / HTTP/1.0\r\nHost: other.example.com\r\n\r\n')
            data = b''
            while chunk := conn.recv(4096):
                data += chunk
            return data
    try:
        for _ in range(50):
            try:
                if b'first' in response():
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise AssertionError('nginx did not start')
        cgroup = Path('/proc/%d/cgroup' % process.pid).read_text().strip().split('::', 1)[1]
        vendor.write_text(source.replace('return 200 first;', 'return 200 second;', 1))
        startup.reload_running(**args, main_pid=process.pid, cgroup=cgroup)
        for _ in range(50):
            if b'second' in response():
                break
            time.sleep(0.1)
        else:
            raise AssertionError('nginx did not load new vendor value')
    finally:
        process.send_signal(signal.SIGQUIT)
        process.wait(timeout=10)
    before = target.read_bytes()
    vendor.write_text('invalid vendor')
    assert startup.prepare_startup(**args) == 'last-known-good'
    assert target.read_bytes() == before
    Path('/etc/adguardhome-doh/mtproxyl-http.conf').write_text('invalid directive;\n')
    try:
        startup.prepare_startup(**args)
    except ValueError:
        pass
    else:
        raise AssertionError('invalid previous runtime must fail')
    assert target.read_bytes() == before
print('real nginx startup and last-known-good smoke passed')
