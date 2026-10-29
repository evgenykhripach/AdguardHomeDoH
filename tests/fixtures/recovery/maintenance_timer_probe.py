#!/usr/bin/env python3
"""Disposable-file experiment for a systemd rollback timer; NOT an installer.

Only operates on a pre-created, private /tmp/doh-maintenance-lab.* directory
and its fixed ``target`` file. It is not a production service orchestrator.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

NAME = re.compile(r'doh-maintenance-lab\.[A-Za-z0-9_]+\Z')
ID = re.compile(r'[a-f0-9]{32}\Z')
SCRIPT = str(Path(__file__).resolve())


def directory(path):
    p = Path(path)
    if not p.is_absolute() or p.parent != Path('/tmp') or not NAME.fullmatch(p.name):
        raise ValueError('only disposable /tmp/doh-maintenance-lab.* directories are permitted')
    s = p.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise ValueError('unsafe lab directory')
    return p


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError('unsafe file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(1048577)
        if len(data) > 1048576:
            raise ValueError('file too large')
        return data, {'dev': st.st_dev, 'ino': st.st_ino, 'sha256': hashlib.sha256(data).hexdigest()}
    finally:
        os.close(fd)


def sync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(p, data):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(p.parent)


def save_plan(p, plan):
    temp = p / ('.plan-' + uuid.uuid4().hex)
    create(temp, json.dumps(plan, sort_keys=True).encode())
    os.replace(temp, p / 'plan.json')
    sync_dir(p)


def load_plan(p):
    data, _ = read_file(p / 'plan.json')
    plan = json.loads(data)
    if (not isinstance(plan, dict) or set(plan) != {'version', 'id', 'state', 'original', 'backup', 'candidate'}
            or plan['version'] != 1 or not isinstance(plan['id'], str) or not ID.fullmatch(plan['id'])
            or plan['state'] not in ('prepared', 'armed', 'committed', 'restored')):
        raise ValueError('unknown plan')
    for key in ('original', 'backup', 'candidate'):
        value = plan[key]
        if (not isinstance(value, dict) or set(value) != {'dev', 'ino', 'sha256'}
                or not isinstance(value['dev'], int) or not isinstance(value['ino'], int)
                or not isinstance(value['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])):
            raise ValueError('invalid snapshot identity')
    return plan


@contextlib.contextmanager
def locked(p):
    fd = os.open(p / 'lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError('unsafe lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def prepare(p, candidate):
    p = directory(p)
    original_data, original = read_file(p / 'target')
    create(p / 'lock', b'')
    create(p / 'backup', original_data)
    create(p / 'candidate', candidate)
    _, backup = read_file(p / 'backup')
    _, new = read_file(p / 'candidate')
    plan = {'version': 1, 'id': uuid.uuid4().hex, 'state': 'prepared',
            'original': original, 'backup': backup, 'candidate': new}
    save_plan(p, plan)
    return plan['id']


def unit(id):
    if not ID.fullmatch(id):
        raise ValueError('invalid unit identity')
    return 'doh-maintenance-lab-' + id


def properties(name):
    result = subprocess.run(['systemctl', 'show', name, '--property=LoadState', '--property=ActiveState',
                             '--property=Transient', '--property=Description', '--property=Triggers'],
                            check=False, capture_output=True, text=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def verify_timer(plan):
    name = unit(plan['id'])
    value = properties(name + '.timer')
    if (value.get('LoadState') != 'loaded' or value.get('ActiveState') != 'active'
            or value.get('Transient') != 'yes' or value.get('Description') != 'DoHDNS lab ' + plan['id']
            or value.get('Triggers') != name + '.service'):
        raise ValueError('timer identity or state is unknown')


def arm(p, delay):
    p = directory(p)
    if not 5 <= delay <= 3600:
        raise ValueError('invalid timer delay')
    with locked(p):
        plan = load_plan(p)
        if plan['state'] != 'prepared':
            raise ValueError('unexpected phase')
        name = unit(plan['id'])
        for suffix in ('.timer', '.service'):
            if properties(name + suffix).get('LoadState') != 'not-found':
                raise ValueError('unit name already in use or unknown')
        subprocess.run(['systemd-run', '--quiet', '--unit=' + name,
                        '--description=DoHDNS lab ' + plan['id'], '--on-active=%ds' % delay,
                        '--property=Type=oneshot', sys.executable, SCRIPT, 'recover', str(p)], check=True)
        verify_timer(plan)
        plan['state'] = 'armed'
        save_plan(p, plan)


def publish(p):
    p = directory(p)
    with locked(p):
        plan = load_plan(p)
        if plan['state'] != 'armed':
            raise ValueError('timer is not armed')
        verify_timer(plan)
        if read_file(p / 'target')[1] != plan['original'] or read_file(p / 'candidate')[1] != plan['candidate']:
            raise ValueError('target or candidate changed')
        os.replace(p / 'candidate', p / 'target')
        sync_dir(p)


def recover(p):
    p = directory(p)
    with locked(p):
        plan = load_plan(p)
        if plan['state'] in ('committed', 'restored'):
            return
        if plan['state'] not in ('prepared', 'armed'):
            raise ValueError('unexpected phase')
        _, current = read_file(p / 'target')
        if current == plan['candidate']:
            if read_file(p / 'backup')[1] != plan['backup']:
                raise ValueError('backup changed')
            os.replace(p / 'backup', p / 'target')
            sync_dir(p)
        elif current not in (plan['original'], plan['backup']):
            raise ValueError('target changed externally')
        plan['state'] = 'restored'
        save_plan(p, plan)


def commit(p):
    p = directory(p)
    with locked(p):
        plan = load_plan(p)
        if plan['state'] != 'armed':
            raise ValueError('unexpected phase')
        verify_timer(plan)
        if read_file(p / 'target')[1] != plan['candidate']:
            raise ValueError('candidate not published')
        plan['state'] = 'committed'
        save_plan(p, plan)
    # Timer is intentionally left armed; it acquires the same lock and sees
    # the durable commit. Avoid stopping a unit whose identity may have changed.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'arm', 'publish', 'recover', 'commit'))
    parser.add_argument('directory')
    parser.add_argument('--candidate', help='literal disposable candidate text')
    parser.add_argument('--delay', type=int, default=15)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            if args.candidate is None:
                raise ValueError('candidate required')
            print(prepare(args.directory, args.candidate.encode()))
        elif args.action == 'arm':
            arm(args.directory, args.delay)
        else:
            globals()[args.action](args.directory)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print('maintenance lab: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
