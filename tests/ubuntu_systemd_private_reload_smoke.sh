#!/usr/bin/env bash
# Only disposable GitHub-hosted Ubuntu; test service has a random name.
set -eEuo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true && "${RUNNER_OS:-}" == Linux && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || { printf 'GitHub-hosted Linux required\n' >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 && "$(cat /proc/1/comm)" == systemd ]] || { printf 'root and systemd PID 1 required\n' >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || { printf 'Ubuntu 24.04 required\n' >&2; exit 1; }
project="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
python3 - "$project" <<'PY'
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

project = Path(sys.argv[1])
sys.path.insert(0, str(project))
from deploy.lib.mtproxyl_front import patch
from tests.test_mtproxyl_front import ADMIN, DOMAIN, REALISTIC

spec = importlib.util.spec_from_file_location('doh_manager_smoke', project / 'deploy/manage.py')
manager = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = manager
spec.loader.exec_module(manager)
identity = secrets.token_hex(16)
unit = 'doh-private-reload-smoke-' + identity + '.service'
description = 'DoHDNS private reload smoke ' + identity
command = ['/usr/bin/python3', manager.MTPROXY_RELOAD_HELPER, 'reload',
           '--source', manager.MTPROXY_NGINX_CONFIG, '--runtime', manager.MTPROXY_RUNTIME_CONFIG,
           '--domain', DOMAIN, '--admin-host', ADMIN, '--nginx-bin', manager.MTPROXY_NGINX_BINARY,
           '--lock', manager.MTPROXY_FRONT_LOCK, '--main-pid', '$MAINPID',
           '--cgroup', '/system.slice/mtproxyl-pq-nginx.service']

def show(*properties):
    result = subprocess.run(['systemctl', 'show', unit, '--property=' + ','.join(properties)],
                            check=True, capture_output=True, text=True, timeout=20)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

if show('LoadState').get('LoadState') != 'not-found':
    raise RuntimeError('test unit collision')
invocation = None
try:
    subprocess.run(['systemd-run', '--quiet', '--unit=' + unit, '--description=' + description,
                    '--property=ExecReload=' + ' '.join(command), '/bin/sleep', '120'],
                   check=True, timeout=30)
    info = show('LoadState', 'ActiveState', 'Transient', 'Description', 'InvocationID')
    if (info.get('LoadState') != 'loaded' or info.get('ActiveState') != 'active'
            or info.get('Transient') != 'yes' or info.get('Description') != description
            or len(info.get('InvocationID', '')) != 32):
        raise RuntimeError('test unit identity unavailable')
    invocation = info['InvocationID']
    with tempfile.TemporaryDirectory(prefix='doh-private-reload-smoke-', dir='/run') as temporary:
        root = Path(temporary)
        def create(relative, data, mode):
            target = root / relative.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(data)
            target.chmod(mode)
        create('/var/lib/adguardhome-doh/install.json', json.dumps({'domain': DOMAIN, 'admin_host': ADMIN}).encode(), 0o600)
        create(manager.MTPROXY_RUNTIME_CONFIG, patch(REALISTIC, DOMAIN, ADMIN).encode(), 0o600)
        create('/etc/systemd/system/mtproxyl-pq-nginx.service.d/adguardhome-doh.conf', b'fixture only\n', 0o644)
        for path in manager.MTPROXY_HELPERS:
            source = project / 'deploy/lib' / Path(path).name
            create(path, source.read_bytes(), 0o755)
        def runner(argv, **kwargs):
            return subprocess.run([unit if arg == 'mtproxyl-pq-nginx' else arg for arg in argv], **kwargs)
        # Reads actual PID1 ExecReload, but all files are confined to /run fixture.
        manager._verify_private_mtproxy(root, runner)
        print('real systemd ExecReload accepted by private runtime verifier')
finally:
    if invocation:
        try:
            info = show('LoadState', 'Transient', 'Description', 'InvocationID')
            if (info.get('LoadState') == 'loaded' and info.get('Transient') == 'yes'
                    and info.get('Description') == description and info.get('InvocationID') == invocation):
                subprocess.run(['systemctl', 'stop', unit], check=True, timeout=30)
            else:
                print('refusing to stop changed test unit', file=sys.stderr)
        except (OSError, subprocess.SubprocessError):
            print('test unit cleanup failed', file=sys.stderr)
PY
