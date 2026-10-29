#!/usr/bin/env bash
# Runs only on a disposable GitHub Actions Ubuntu systemd host. Never run on a
# shared runner: even isolated test units operate on the host systemd.
set -eEuo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true && "${RUNNER_OS:-}" == Linux && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || { printf 'GitHub Actions Linux required\n' >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 && "$(cat /proc/1/comm)" == systemd ]] || { printf 'root and systemd PID 1 required\n' >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || { printf 'Ubuntu 24.04 required\n' >&2; exit 1; }
PROJECT_ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
logical_units=(adguardhome-doh-health.timer adguardhome-doh-health.service adguardhome-doh.service adguardhome-doh-nginx.service nginx.service mtproxyl-pq-nginx.service)
token="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
[[ "$token" =~ ^[0-9a-f]{32}$ ]] || { printf 'invalid generated id\n' >&2; exit 1; }
prefix="doh-maintenance-smoke-$token-"
units=()
for logical in "${logical_units[@]}"; do units+=("$prefix$logical"); done
for unit in "${units[@]}"; do
    [[ "$(systemctl show "$unit" --property=LoadState --value)" == not-found ]] || { printf 'unit already exists: %s\n' "$unit" >&2; exit 1; }
    [[ ! -e "/run/systemd/system/$unit" && ! -L "/run/systemd/system/$unit" ]] || { printf 'unit file already exists: %s\n' "$unit" >&2; exit 1; }
done

work="$(mktemp -d /tmp/doh-maintenance-systemd.XXXXXXXX)"
chmod 700 "$work"
created=()
identities=()
checksums=()
cleanup() {
    local index unit path identity checksum fragment
    for ((index=${#created[@]}-1; index>=0; index--)); do
        unit="${created[index]}"
        path="/run/systemd/system/$unit"
        [[ -f "$path" && ! -L "$path" ]] || continue
        identity="$(stat -c '%d:%i' "$path")"
        checksum="$(sha256sum "$path" | cut -d ' ' -f 1)"
        [[ "$identity" == "${identities[index]}" && "$checksum" == "${checksums[index]}" ]] || { printf 'refusing cleanup of changed unit %s\n' "$unit" >&2; continue; }
        fragment="$(systemctl show "$unit" --property=FragmentPath --value 2>/dev/null || true)"
        if [[ "$fragment" == "$path" ]]; then
            systemctl stop "$unit" >/dev/null 2>&1 || true
        fi
        rm -f -- "$path"
    done
    if ((${#created[@]})); then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    if [[ "$work" == /tmp/doh-maintenance-systemd.* && -d "$work" && ! -L "$work" ]]; then rm -rf -- "$work"; fi
}
trap cleanup EXIT
create_unit() {
    local unit="$1" content="$2" path="/run/systemd/system/$1"
    # noclobber prevents replacing any pre-existing file, including symlinks.
    (set -o noclobber; printf '%s\n' "$content" > "$path")
    created+=("$unit")
    identities+=("$(stat -c '%d:%i' "$path")")
    checksums+=("$(sha256sum "$path" | cut -d ' ' -f 1)")
}
service='[Unit]
Description=Disposable DoHDNS maintenance smoke
[Service]
Type=simple
ExecStart=/bin/sleep 300'
for unit in adguardhome-doh-health.service adguardhome-doh.service nginx.service mtproxyl-pq-nginx.service; do
    create_unit "$prefix$unit" "$service"
done
create_unit "${prefix}adguardhome-doh-nginx.service" '[Unit]
Description=Disposable DoHDNS maintenance transitioning unit
[Service]
Type=notify
TimeoutStartSec=120
ExecStart=/bin/sleep 300'
create_unit "${prefix}adguardhome-doh-health.timer" "[Unit]
Description=Disposable DoHDNS maintenance timer
[Timer]
OnActiveSec=1h
Unit=${prefix}adguardhome-doh-health.service"
systemctl daemon-reload
for unit in "${created[@]}"; do
    [[ "$(systemctl show "$unit" --property=FragmentPath --value)" == "/run/systemd/system/$unit" ]] || { printf 'unexpected unit fragment\n' >&2; exit 1; }
done
systemctl start "${prefix}adguardhome-doh.service" "${prefix}nginx.service" "${prefix}mtproxyl-pq-nginx.service" "${prefix}adguardhome-doh-health.timer"

python3 - "$PROJECT_ROOT" "$work" "$prefix" <<'PY'
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

project, root = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(project))
from deploy.lib import mtproxyl_maintenance as maintenance

prefix = sys.argv[3]
units = {unit: prefix + unit for unit in maintenance.UNITS}
def translated_runner(argv, **kwargs):
    if argv and argv[0] == 'systemctl':
        argv = [units.get(arg, arg) for arg in argv]
    result = subprocess.run(argv, **kwargs)
    if argv[:2] == ['systemctl', 'list-jobs']:
        for logical, actual in units.items():
            result.stdout = result.stdout.replace(actual, logical)
    return result

agh = root / 'opt/AdGuardHome/AdGuardHome.yaml'
agh.parent.mkdir(parents=True)
agh.write_text('original user settings\n')
front = root / 'etc/adguardhome-doh/mtproxyl-admin-acme.conf'
front.parent.mkdir(parents=True)
front.write_text('original admin\n')
backup = maintenance.snapshot(root, 'dns.example.com', translated_runner)
baseline = maintenance.validate(backup)['units']
assert baseline['adguardhome-doh.service']['active']
assert baseline['mtproxyl-pq-nginx.service']['active']
assert not baseline['adguardhome-doh-nginx.service']['active']
agh.write_text('changed\n')
front.write_text('changed\n')
result = translated_runner(['systemctl', 'show', 'mtproxyl-pq-nginx.service', '--property=MainPID', '--value'], check=True, capture_output=True, text=True)
pid = int(result.stdout.strip())
assert pid > 1
os.kill(pid, signal.SIGKILL)
translated_runner(['systemctl', 'start', '--no-block', 'adguardhome-doh-nginx.service'], check=True)
for _ in range(100):
    failed, _ = maintenance._stoppable_state('mtproxyl-pq-nginx.service', translated_runner)
    starting, _ = maintenance._stoppable_state('adguardhome-doh-nginx.service', translated_runner)
    if failed['ActiveState'] == 'failed' and starting['ActiveState'] == 'activating':
        break
    time.sleep(.1)
else:
    raise RuntimeError('failed/activating test states did not appear')

groups = {}
for unit in maintenance.UNITS:
    state, _ = maintenance._stoppable_state(unit, translated_runner)
    groups[unit] = state['ControlGroup']

def checked_runner(argv, **kwargs):
    # At daemon-reload restore has stopped all units, but has not started any.
    if argv[:2] == ['systemctl', 'daemon-reload']:
        for unit, group in groups.items():
            state, pid = maintenance._stoppable_state(unit, translated_runner)
            assert state['ActiveState'] in ('inactive', 'failed') and pid == 0
            assert maintenance._cgroup_empty(group)
    return translated_runner(argv, **kwargs)

assert maintenance.restore(root, backup, checked_runner) == []
assert agh.read_text() == 'original user settings\n'
assert front.read_text() == 'original admin\n'
for unit, expected in baseline.items():
    assert maintenance._unit_state(unit, translated_runner) == expected, unit
print('real systemd maintenance snapshot/restore smoke: ok')
PY
