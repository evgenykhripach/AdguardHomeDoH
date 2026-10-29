"""Synthetic configuration and local-only selfmask probe for the Docker smoke test."""
import os
from pathlib import Path
import socket
import ssl
import sys

WORK = Path('/work')
DOMAIN = 'dns.example.com'
SOURCE = '''error_log stderr;
pid /tmp/mtproxy-nginx.pid;
worker_processes 1;
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
        ssl_certificate /work/cert/fullchain.pem;
        ssl_certificate_key /work/cert/privkey.pem;
        location / { return 200 SELF_MASK_OK; }
    }
}
'''


def prepare():
    sys.path.insert(0, '/repo')
    from deploy.lib.mtproxyl_front import _write_private, patch, render_http
    (WORK / 'includes').mkdir(exist_ok=True)
    (WORK / 'vendor.conf').write_text(SOURCE)
    (WORK / 'vendor-original.conf').write_text(SOURCE)
    patched = patch(SOURCE, DOMAIN)
    assert patch(patched, DOMAIN) == patched
    _write_private(WORK / 'runtime.conf', patched)
    (WORK / 'includes/mtproxyl-sni.map').write_text('outside.example adguardhome_doh;\n')
    (WORK / 'includes/mtproxyl-http.conf').write_text(render_http(DOMAIN))
    (WORK / 'mtg.toml').write_text('''secret = "ee00112233445566778899aabbccddeeff646e732e6578616d706c652e636f6d"
bind-to = "127.0.0.1:15443"
proxy-protocol-listener = true
[domain-fronting]
ip = "127.0.0.1"
port = 8444
[defense.blocklist]
enabled = false
''')


def verify_files():
    assert (WORK / 'vendor.conf').read_bytes() == (WORK / 'vendor-original.conf').read_bytes(), 'vendor changed'
    assert os.stat(WORK / 'runtime.conf').st_mode & 0o777 == 0o600, 'runtime mode'
    print('vendor unchanged; runtime mode 0600')


def probe():
    port = int(sys.argv[2])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # disposable synthetic certificate only
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=DOMAIN) as conn:
            conn.sendall(b'GET / HTTP/1.1\r\nHost: dns.example.com\r\nConnection: close\r\n\r\n')
            result = b''
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                result += data
    if b'200 OK' not in result or not result.endswith(b'SELF_MASK_OK'):
        raise SystemExit('selfmask failed')
    print('selfmask port %d: 200 SELF_MASK_OK' % port)


if __name__ == '__main__':
    {'prepare': prepare, 'verify': verify_files, 'probe': probe}[sys.argv[1]]()
