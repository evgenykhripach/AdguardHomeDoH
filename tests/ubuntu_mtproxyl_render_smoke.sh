#!/usr/bin/env bash
# Disposable-container smoke for the shared-front renderer. FakeTLS is modelled
# by a local stream proxy; no real MTProxy credentials or server are used.
set -eEuo pipefail

PROJECT_ROOT="${1:-/repo}"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get update >/dev/null
env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nginx libnginx-mod-stream python3 python3-yaml openssl curl ca-certificates >/dev/null

mkdir -p /etc/adguardhome-doh /etc/nginx/stream.d /var/www/adguardhome-doh \
    /var/www/selfmask /var/log/adguardhome-doh /tmp/shared-front \
    /etc/letsencrypt/live/dns.example.com
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj '/CN=dns.example.com' \
    -addext 'subjectAltName=DNS:dns.example.com' \
    -keyout /etc/letsencrypt/live/dns.example.com/privkey.pem \
    -out /etc/letsencrypt/live/dns.example.com/fullchain.pem >/dev/null 2>&1
install -m 644 /etc/letsencrypt/live/dns.example.com/fullchain.pem \
    /usr/local/share/ca-certificates/doh-smoke.crt
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj '/CN=chatgpt.com' \
    -addext 'subjectAltName=DNS:chatgpt.com' -keyout /tmp/shared-front/site.key \
    -out /tmp/shared-front/site.crt >/dev/null 2>&1
install -m 644 /tmp/shared-front/site.crt /usr/local/share/ca-certificates/doh-site.crt
update-ca-certificates >/dev/null

token="$(printf '%048d' 0 | tr 0 a)"
python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py" --front mtproxyl \
    --config-dir "$PROJECT_ROOT/config" --services chatgpt --healthy-services chatgpt \
    --public-ip 203.0.113.10 --doh-host dns.example.com --doh-token "$token" \
    --password-hash test-hash --certificate-root /etc/letsencrypt/live/dns.example.com \
    --webroot /var/www/adguardhome-doh --output /tmp/shared-front/rendered
install -m 644 /tmp/shared-front/rendered/mtproxyl-sni.map /etc/adguardhome-doh/mtproxyl-sni.map
install -m 600 /tmp/shared-front/rendered/nginx-http.conf /etc/adguardhome-doh/mtproxyl-http-site.conf
# Use a local synthetic TLS site for the routed service; all other renderer
# directives, including PROXY-protocol handling, are exercised unchanged.
sed 's/\$ssl_preread_server_name:443/127.0.0.1:15446/g' \
    /tmp/shared-front/rendered/nginx-stream.conf > /etc/adguardhome-doh/mtproxyl-stream-site.conf
chmod 600 /etc/adguardhome-doh/mtproxyl-stream-site.conf
chown root:www-data /var/www/adguardhome-doh
chmod 750 /var/www/adguardhome-doh
install -m 640 -o root -g www-data /tmp/shared-front/rendered/dns.example.com.mobileconfig \
    /var/www/adguardhome-doh/dns.example.com.mobileconfig
printf 'selfmask-ok\n' > /var/www/selfmask/index.html

cat > /tmp/shared-front/frontend.conf <<'NGINX'
user www-data;
worker_processes 1;
pid /run/fake-mtproxyl.pid;
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
events { worker_connections 1024; }
stream {
    map_hash_bucket_size 128;
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
        root /var/www/selfmask;
        location / { try_files $uri $uri/ =404; }
    }
    server {
        listen 127.0.0.1:15444 ssl proxy_protocol;
        server_name web.dns.example.com;
        ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
        return 200 'mtproxyl-web-ok';
    }
}
NGINX
python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_front.py" render-http \
    --domain dns.example.com --output /etc/adguardhome-doh/mtproxyl-http.conf
source_hash="$(sha256sum /tmp/shared-front/frontend.conf)"
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx)" == overlay ]]
[[ "$(sha256sum /tmp/shared-front/frontend.conf)" == "$source_hash" ]]
[[ "$(stat -c '%a' /tmp/shared-front/patched.conf)" == 600 ]]
# If DoHDNS's include is absent, the explicitly allowed startup fallback
# must publish a validated vendor config and report the degraded state.
mv /etc/adguardhome-doh/mtproxyl-http.conf /tmp/shared-front/mtproxyl-http.saved
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx --allow-fallback)" == degraded ]]
cmp -s /tmp/shared-front/frontend.conf /tmp/shared-front/patched.conf
mv /tmp/shared-front/mtproxyl-http.saved /etc/adguardhome-doh/mtproxyl-http.conf
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx)" == overlay ]]
[[ "$(sha256sum /tmp/shared-front/frontend.conf)" == "$source_hash" ]]
# Verify that a candidate can be checked entirely in memory on Linux: production
# configs may contain private data and need not be copied to another machine.
python3 - <<'PY'
import os
import subprocess
from pathlib import Path

opened = []
def memory_file(name, contents):
    fd = os.memfd_create(name)
    opened.append(fd)
    os.write(fd, contents)
    return f'/proc/self/fd/{fd}'

try:
    source = Path('/tmp/shared-front/patched.conf').read_text()
    for path in ('/etc/adguardhome-doh/mtproxyl-sni.map',
                 '/etc/adguardhome-doh/mtproxyl-http.conf'):
        assert path in source
        source = source.replace(path, memory_file('doh-include', Path(path).read_bytes()))
    candidate = memory_file('doh-nginx', source.encode())
    subprocess.run(['nginx', '-t', '-c', candidate], check=True, pass_fds=tuple(opened))
finally:
    for fd in opened:
        os.close(fd)
PY
# Check that HUP actually loads the new generation in a new worker. This does
# not exercise systemd or prove crash recovery; the entire nginx is disposable.
python3 - "$PROJECT_ROOT" <<'PY'
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from deploy.lib import mtproxyl_controller as identity
from deploy.lib import mtproxyl_runtime as runtime

root = Path('/tmp/shared-front/generation')
root.mkdir(mode=0o700)
source = Path('/tmp/shared-front/frontend.conf')
before = source.read_bytes()
target = root / 'runtime.conf'
marker = root / 'generation.sock'
first, second = 'a' * 32, 'b' * 32
assert runtime.prepare(source, target, 'dns.example.com', '/usr/sbin/nginx',
                       marker_socket=marker, generation=first) == 'overlay'
master = subprocess.Popen(['/usr/sbin/nginx', '-c', str(target), '-g', 'daemon off;'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_generation(expected):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if master.poll() is not None:
            raise RuntimeError('disposable nginx stopped')
        try:
            return runtime.probe_generation(marker, expected, timeout=0.5)
        except (OSError, ValueError):
            time.sleep(0.05)
    raise RuntimeError('generation probe timed out')

try:
    old_worker = wait_generation(first)
    cgroup = Path('/proc/%d/cgroup' % master.pid).read_text().strip().split('::', 1)[1]
    original = identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup)
    assert runtime.prepare(source, target, 'dns.example.com', '/usr/sbin/nginx',
                           marker_socket=marker, generation=second) == 'overlay'
    assert runtime.probe_generation(marker, first) == old_worker
    baseline = identity.capture_workers(original)
    os.kill(master.pid, signal.SIGHUP)
    deadline = time.monotonic() + 10
    while True:
        try:
            new_worker = identity.confirm_generation(original, baseline, marker, second)
            break
        except identity.IdentityError:
            if master.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    assert new_worker.pid != old_worker
    assert identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup) == original
    assert source.read_bytes() == before
    assert target.stat().st_mode & 0o777 == 0o600
    print('nginx generation and master identity smoke: ok')
finally:
    master.terminate()
    try:
        master.wait(timeout=5)
    except subprocess.TimeoutExpired:
        master.kill()
        master.wait(timeout=5)
PY
cat > /tmp/shared-front/faketls.conf <<'NGINX'
worker_processes 1;
pid /run/fake-faketls.pid;
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
events { worker_connections 128; }
stream {
    server { listen 127.0.0.1:15443 proxy_protocol; proxy_pass 127.0.0.1:8444; }
}
NGINX
cat > /tmp/shared-front/dns.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer

class DNS(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/dns-query?dns='):
            self.send_error(404)
            return
        answer = (b'\0\0\x81\x80\0\1\0\1\0\0\0\0'
                  b'\3www\7example\3com\0\0\1\0\1'
                  b'\xc0\x0c\0\1\0\1\0\0\1\x2c\0\4\x7f\0\0\1')
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)
    def log_message(self, *args):
        pass

HTTPServer(('127.0.0.1', 3001), DNS).serve_forever()
PY
python3 /tmp/shared-front/dns.py >/tmp/shared-front/dns.log 2>&1 & dns_pid=$!
openssl s_server -quiet -www -accept 127.0.0.1:15446 \
    -cert /tmp/shared-front/site.crt -key /tmp/shared-front/site.key \
    >/tmp/shared-front/site.log 2>&1 & site_pid=$!
trap 'kill "$dns_pid" "$site_pid" 2>/dev/null || true; for pid_file in /run/fake-mtproxyl.pid /run/fake-faketls.pid /run/adguardhome-doh-nginx.pid; do [[ ! -s "$pid_file" ]] || kill "$(<"$pid_file")" 2>/dev/null || true; done' EXIT

nginx -t -c /tmp/shared-front/faketls.conf
nginx -c /tmp/shared-front/faketls.conf
nginx -t -c "$PROJECT_ROOT/deploy/templates/mtproxyl-nginx.conf"
nginx -c "$PROJECT_ROOT/deploy/templates/mtproxyl-nginx.conf"
nginx -t -c /tmp/shared-front/patched.conf
nginx -c /tmp/shared-front/patched.conf

[[ "$(curl --noproxy '*' --fail --silent --show-error --resolve dns.example.com:443:127.0.0.1 https://dns.example.com/)" == selfmask-ok ]]
curl --noproxy '*' --fail --silent --show-error --resolve dns.example.com:443:127.0.0.1 \
    "https://dns.example.com/$token.mobileconfig" -o /tmp/shared-front/profile
grep -Fq 'SupplementalMatchDomains' /tmp/shared-front/profile
python3 - "$PROJECT_ROOT/deploy/templates/healthcheck.py" "$token" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('health', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.probe_doh('dns.example.com', sys.argv[2], attempts=1, delay=0)
PY
curl --noproxy '*' --fail --silent --show-error --resolve chatgpt.com:443:127.0.0.1 \
    https://chatgpt.com/ -o /dev/null
[[ "$(curl --noproxy '*' --insecure --fail --silent --show-error \
    --resolve web.dns.example.com:443:127.0.0.1 https://web.dns.example.com/)" == mtproxyl-web-ok ]]
printf 'ubuntu shared-front renderer smoke: ok\n'
