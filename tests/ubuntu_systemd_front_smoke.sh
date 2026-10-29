#!/usr/bin/env bash
# Run only on a disposable systemd host: exercises real nginx process-title
# and unit tracking without touching production or real MTProxy credentials.
set -eEuo pipefail

PROJECT_ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
[[ "$(cat /proc/1/comm)" == systemd ]] || { printf 'systemd is required\n' >&2; exit 1; }
[[ ! -e /opt/mtproxyl-nginx && ! -e /etc/systemd/system/mtproxyl-pq-nginx.service ]] || {
    printf 'refusing to replace an existing MTProxy installation\n' >&2; exit 1;
}
cleanup() {
    systemctl stop mtproxyl-pq-nginx.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/mtproxyl-pq-nginx.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f /opt/mtproxyl-nginx/conf/nginx.conf /opt/mtproxyl-nginx/conf/other.conf \
        /opt/mtproxyl-nginx/sbin/nginx
    rmdir /opt/mtproxyl-nginx/conf /opt/mtproxyl-nginx/sbin /opt/mtproxyl-nginx 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p /opt/mtproxyl-nginx/sbin /opt/mtproxyl-nginx/conf
install -m 755 /usr/sbin/nginx /opt/mtproxyl-nginx/sbin/nginx
cat > /opt/mtproxyl-nginx/conf/nginx.conf <<'NGINX'
worker_processes 1;
pid /run/doh-test-nginx.pid;
events { worker_connections 32; }
http { server { listen 127.0.0.1:18765; return 200 'ok'; } }
NGINX
cp /opt/mtproxyl-nginx/conf/nginx.conf /opt/mtproxyl-nginx/conf/other.conf
cat > /etc/systemd/system/mtproxyl-pq-nginx.service <<'UNIT'
[Unit]
Description=Disposable nginx process identity test
[Service]
Type=simple
ExecStart=/opt/mtproxyl-nginx/sbin/nginx -c /opt/mtproxyl-nginx/conf/nginx.conf -g 'daemon off;'
UNIT
systemctl daemon-reload
systemctl start mtproxyl-pq-nginx.service
python3 - "$PROJECT_ROOT/deploy/manage.py" <<'PY'
import importlib.util
import subprocess
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location('manager', sys.argv[1])
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
assert manager._verify_mtproxyl_active_config(Path('/'), subprocess.run) > 0
PY

# A different config must be rejected even when the binary and unit match.
systemctl stop mtproxyl-pq-nginx.service
sed -i 's@/conf/nginx.conf@/conf/other.conf@' /etc/systemd/system/mtproxyl-pq-nginx.service
systemctl daemon-reload
systemctl start mtproxyl-pq-nginx.service
python3 - "$PROJECT_ROOT/deploy/manage.py" <<'PY'
import importlib.util
import subprocess
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location('manager', sys.argv[1])
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
try:
    manager._verify_mtproxyl_active_config(Path('/'), subprocess.run)
except RuntimeError:
    pass
else:
    raise AssertionError('unexpected nginx config was accepted')
PY
printf 'ubuntu systemd front identity smoke: ok\n'
