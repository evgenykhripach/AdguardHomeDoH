#!/usr/bin/env python3
"""Backup/restore primitive for a future MTProxyL maintenance transaction.

This is not a cutover tool: callers must arrange autonomous recovery, fence all
writers, and hold the manager operation and health locks across the transaction.
A snapshot made while AdGuard is running is preliminary: it cannot capture changes
made after the final read. A settled YAML snapshot is required after stopping
AdGuard and before modifying its files, with earlier unit state retained separately.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

SPEC = importlib.util.spec_from_file_location('doh_manager', Path(__file__).resolve().parents[1] / 'manage.py')
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)

UNITS = ('adguardhome-doh-health.timer', 'adguardhome-doh-health.service',
         'adguardhome-doh.service', 'adguardhome-doh-nginx.service',
         'nginx.service', 'mtproxyl-pq-nginx.service')
EXTRA = ('/etc/adguardhome-doh/mtproxyl-admin-acme.conf',
         '/run/adguardhome-doh/mtproxyl-nginx.conf')
ID = re.compile(r'maintenance-[a-f0-9]{32}\Z')


def _private_dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('unsafe backup directory')


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_tree(path):
    for child in path.iterdir():
        if child.is_symlink():
            continue
        if child.is_dir():
            _sync_tree(child)
        else:
            fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    _sync_dir(path)


def _unit_state(unit, runner):
    result = runner(['systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,UnitFileState'],
                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if set(values) != {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'}:
        raise RuntimeError('cannot read systemd state')
    load, active, substate, enabled = (values[k] for k in ('LoadState', 'ActiveState', 'SubState', 'UnitFileState'))
    if load == 'not-found' and active == 'inactive' and enabled in ('', 'not-found'):
        return {'load': 'not-found', 'active': False, 'enabled': 'not-found', 'auto_restart': False, 'degraded': ''}
    auto_restart = unit == 'nginx.service' and active == 'activating' and substate in ('start', 'auto-restart')
    health_failed = unit == 'adguardhome-doh-health.service' and active == 'failed' and substate == 'failed'
    if load != 'loaded' or (active not in ('active', 'inactive') and not auto_restart and not health_failed) or enabled not in ('enabled', 'disabled', 'static'):
        raise RuntimeError('unsupported systemd state for ' + unit)
    return {'load': load, 'active': active == 'active', 'enabled': enabled, 'auto_restart': auto_restart,
            'degraded': substate if (auto_restart or health_failed) else ''}



def _stoppable_state(unit, runner):
    """Read current state without treating a failed activation as a baseline."""
    result = runner(['systemctl', 'show', unit,
                     '--property=LoadState,ActiveState,MainPID,ControlGroup'],
                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=30)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if unit.endswith('.timer') and set(values) == {'LoadState', 'ActiveState'}:
        # Timers have no process or cgroup properties in systemd.
        values.update(MainPID='0', ControlGroup='')
    elif set(values) != {'LoadState', 'ActiveState', 'MainPID', 'ControlGroup'}:
        raise RuntimeError('cannot read current systemd state')
    if values['LoadState'] not in ('loaded', 'not-found'):
        raise RuntimeError('unknown current systemd unit state')
    try:
        pid = int(values['MainPID'])
    except ValueError:
        raise RuntimeError('invalid systemd MainPID') from None
    if pid < 0:
        raise RuntimeError('invalid systemd MainPID')
    return values, pid


def _cgroup_empty(group):
    """Confirm the service cgroup no longer owns processes on cgroup v2."""
    if not group:
        return True
    parts = Path(group).parts
    if not group.startswith('/') or any(part in ('.', '..') for part in parts):
        raise RuntimeError('invalid cgroup path')
    if not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        raise RuntimeError('cgroup v2 is required to verify stopped services')
    path = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
    try:
        values = dict(line.split() for line in path.read_text().splitlines())
    except FileNotFoundError:
        return True
    if values.get('populated') not in ('0', '1'):
        raise RuntimeError('cannot verify cgroup state')
    return values['populated'] == '0'

def _validate_state(value):
    if not isinstance(value, dict) or set(value) != set(UNITS):
        raise RuntimeError('invalid systemd snapshot')
    for unit, state in value.items():
        if (not isinstance(state, dict) or set(state) != {'load', 'active', 'enabled', 'auto_restart', 'degraded'}
                or type(state['active']) is not bool or type(state['auto_restart']) is not bool
                or state['degraded'] not in ('', 'start', 'auto-restart', 'failed')
                or (state['auto_restart'] and (unit != 'nginx.service' or state['active'] or state['load'] != 'loaded' or state['degraded'] not in ('start', 'auto-restart')))
                or (state['degraded'] in ('start', 'auto-restart') and not state['auto_restart'])
                or (state['degraded'] == 'failed' and (unit != 'adguardhome-doh-health.service' or state['active'] or state['load'] != 'loaded'))):
            raise RuntimeError('invalid systemd snapshot')
        if not ((state['load'] == 'not-found' and state['enabled'] == 'not-found' and not state['active']) or
                (state['load'] == 'loaded' and state['enabled'] in ('enabled', 'disabled', 'static'))):
            raise RuntimeError('invalid systemd snapshot')


def _sync_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_dir(path.parent)



def _observe(path):
    """Detect source replacement or edits while hashing a managed file."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not (stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)):
        raise RuntimeError('managed path is not a file or symlink')
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    digest = manager._path_digest(path)
    if identity(before) != identity(path.lstat()):
        raise RuntimeError('snapshot source changed while hashing')
    return identity(before), digest

def snapshot(root, domain, runner=subprocess.run):
    """Create a preliminary snapshot. Caller owns both manager locks.

    If AdGuard is running, stop and take a settled YAML snapshot before mutation.
    Caller must separately retain the pre-stop unit state for recovery.
    """
    root = Path(root)
    if not manager._valid_domain(domain):
        raise ValueError('invalid domain')
    backup_root = manager.under_root(root, '/var/backups/adguardhome-doh')
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_dir(backup_root)
    dest = backup_root / ('maintenance-' + uuid.uuid4().hex)
    dest.mkdir(mode=0o700)
    _sync_dir(backup_root)
    states = {unit: _unit_state(unit, runner) for unit in UNITS}
    paths = manager._managed_paths(domain) + EXTRA
    observations = {path: _observe(manager.under_root(root, path)) for path in paths}
    files = dest / 'files'
    manager.create_backup(root, files, operation='manual', domain=domain)
    manager._validated_backup_manifest(files)
    extras = []
    for index, relative in enumerate(EXTRA):
        src = manager.under_root(root, relative)
        exists = src.exists() or src.is_symlink()
        entry = {'path': relative, 'name': 'extra-%d' % index, 'present': exists}
        if exists:
            if src.is_symlink() or not src.is_file():
                raise RuntimeError('supplemental path is not a regular file')
            target = dest / entry['name']
            manager._copy_path(src, target)
            entry['sha256'] = manager._path_digest(target)
            if entry['sha256'] != manager._path_digest(src):
                raise RuntimeError('snapshot source changed')
        extras.append(entry)
    if {path: _observe(manager.under_root(root, path)) for path in paths} != observations:
        raise RuntimeError('snapshot source changed during copy')
    after_states = {unit: _unit_state(unit, runner) for unit in UNITS}
    # The observed failed nginx naturally alternates between these two substates.
    # Save the last observed value while rejecting all other state changes.
    before_cmp = {unit: dict(value) for unit, value in states.items()}
    after_cmp = {unit: dict(value) for unit, value in after_states.items()}
    if before_cmp['nginx.service']['auto_restart'] and after_cmp['nginx.service']['auto_restart']:
        before_cmp['nginx.service']['degraded'] = after_cmp['nginx.service']['degraded']
    if before_cmp != after_cmp:
        raise RuntimeError('systemd state changed during snapshot')
    states = after_states
    _sync_tree(files)
    _sync_json(dest / 'snapshot.json', {'version': 1, 'domain': domain, 'units': states, 'extra': extras})
    _sync_tree(dest)
    validate(dest)
    return dest


def validate(dest):
    dest = Path(dest)
    if not ID.fullmatch(dest.name):
        raise ValueError('invalid snapshot id')
    _private_dir(dest)
    _private_dir(dest / 'files')
    info = (dest / 'snapshot.json').lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError('unsafe snapshot manifest')
    with (dest / 'snapshot.json').open() as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or set(data) != {'version', 'domain', 'units', 'extra'} or data['version'] != 1 or not manager._valid_domain(data['domain']):
        raise RuntimeError('invalid snapshot manifest')
    _validate_state(data['units'])
    manifest = manager._read_json(dest / 'files' / 'manifest.json')
    if not isinstance(manifest, dict) or manifest.get('domain') != data['domain'] or manifest.get('version') != manager.BACKUP_VERSION:
        raise RuntimeError('invalid file snapshot')
    entries = manager._validated_backup_manifest(dest / 'files')
    if {item[0] for item in entries} != set(manager._managed_paths(data['domain'])):
        raise RuntimeError('file snapshot is incomplete')
    if not isinstance(data['extra'], list) or len(data['extra']) != len(EXTRA):
        raise RuntimeError('invalid supplemental snapshot')
    for index, (entry, path) in enumerate(zip(data['extra'], EXTRA)):
        if not isinstance(entry, dict) or entry.get('path') != path or entry.get('name') != 'extra-%d' % index or type(entry.get('present')) is not bool:
            raise RuntimeError('invalid supplemental snapshot')
        expected_keys = {'path', 'name', 'present'} | ({'sha256'} if entry['present'] else set())
        if set(entry) != expected_keys:
            raise RuntimeError('invalid supplemental snapshot')
        if entry['present'] and manager._path_digest(dest / entry['name']) != entry['sha256']:
            raise RuntimeError('supplemental snapshot checksum mismatch')
    return data


def restore(root, dest, runner=subprocess.run):
    """Restore files and unit states; caller must fence writers and own locks."""
    root, dest = Path(root), Path(dest)
    expected_parent = manager.under_root(root, '/var/backups/adguardhome-doh')
    _private_dir(expected_parent)
    if dest.parent != expected_parent:
        raise ValueError('snapshot outside backup root')
    data = validate(dest)
    # Even a failed or transitioning unit can own a listener. Stop every
    # loaded unit and prove its processes are gone before touching files.
    groups = {}
    for unit in UNITS:
        current, pid = _stoppable_state(unit, runner)
        if pid and not current['ControlGroup']:
            raise RuntimeError('running unit has no verifiable cgroup: ' + unit)
        groups[unit] = current['ControlGroup']
        if current['LoadState'] == 'loaded':
            runner(['systemctl', 'stop', unit], check=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=45)
    jobs = runner(['systemctl', 'list-jobs', '--no-legend', '--plain'], check=True,
                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    for line in jobs.stdout.splitlines():
        if any(unit in line.split() for unit in UNITS):
            raise RuntimeError('unit still has a pending systemd job')
    for unit in UNITS:
        current, pid = _stoppable_state(unit, runner)
        if (current['ActiveState'] not in ('inactive', 'failed') or pid != 0
                or not _cgroup_empty(groups[unit]) or not _cgroup_empty(current['ControlGroup'])):
            raise RuntimeError('unit did not stop completely: ' + unit)
    # Certbot renewal and deploy hooks are shared with other applications.
    # A concurrent renewal must not be undone by this transaction.
    skipped = {target for target, _, _ in manager._restore_targets(dest / 'files', root)
               if str(target.relative_to(root)).startswith('etc/letsencrypt/')}
    manager._restore_backup(dest / 'files', root, skip_targets=skipped)
    for entry in data['extra']:
        target = manager.under_root(root, entry['path'])
        if target.is_dir() and not target.is_symlink():
            raise RuntimeError('refusing to replace directory')
        if entry['present']:
            manager._atomic_copy(dest / entry['name'], target)
        else:
            manager._remove_path(target)
    # Verify every restored entry before starting any service.
    for target, backup, present in manager._restore_targets(dest / 'files', root):
        if target in skipped:
            continue
        exists = target.exists() or target.is_symlink()
        if exists != present or (present and manager._path_digest(target) != manager._path_digest(backup)):
            raise RuntimeError('restored file differs from snapshot')
    for entry in data['extra']:
        target = manager.under_root(root, entry['path'])
        exists = target.exists() or target.is_symlink()
        if exists != entry['present'] or (exists and manager._path_digest(target) != entry['sha256']):
            raise RuntimeError('restored supplemental file differs from snapshot')
    runner(['systemctl', 'daemon-reload'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if data['units']['adguardhome-doh-health.service']['degraded'] == 'failed':
        runner(['systemctl', 'reset-failed', 'adguardhome-doh-health.service'],
               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    for unit, old in data['units'].items():
        if old['enabled'] in ('enabled', 'disabled'):
            runner(['systemctl', 'enable' if old['enabled'] == 'enabled' else 'disable', unit],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Restore backends before listeners; health checks start last.
    for unit in ('adguardhome-doh.service', 'adguardhome-doh-nginx.service',
                 'nginx.service', 'mtproxyl-pq-nginx.service',
                 'adguardhome-doh-health.service', 'adguardhome-doh-health.timer'):
        if data['units'][unit]['active']:
            runner(['systemctl', 'start', unit], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for unit, old in data['units'].items():
        expected = dict(old)
        # A previously failing nginx is left stopped while preserving its enablement.
        # Recreating the auto-restart loop would not restore a working service.
        expected['auto_restart'] = False
        expected['degraded'] = ''
        if _unit_state(unit, runner) != expected:
            raise RuntimeError('restored systemd state differs for ' + unit)
    warnings = []
    if data['units']['nginx.service']['auto_restart']:
        warnings.append('nginx.service was in a restart cycle; left inactive with previous enablement')
    if data['units']['adguardhome-doh-health.service']['degraded'] == 'failed':
        warnings.append('adguardhome-doh-health.service was failed; left inactive with previous enablement')
    return warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'validate', 'restore'))
    parser.add_argument('--domain')
    parser.add_argument('--snapshot', type=Path)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError('root is required')
        if args.action == 'snapshot':
            if not args.domain or args.snapshot:
                raise ValueError('snapshot requires --domain')
            with manager.operation_lock(), manager.health_lock():
                print(snapshot(Path('/'), args.domain))
        else:
            if not args.snapshot or args.domain:
                raise ValueError('action requires --snapshot')
            if args.snapshot.parent != Path('/var/backups/adguardhome-doh'):
                raise ValueError('snapshot outside backup root')
            if args.action == 'validate':
                _private_dir(args.snapshot.parent)
                validate(args.snapshot)
            else:
                with manager.operation_lock(), manager.health_lock():
                    warnings = restore(Path('/'), args.snapshot)
                    for warning in warnings:
                        print(warning, file=sys.stderr)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError):
        print('maintenance snapshot operation failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
