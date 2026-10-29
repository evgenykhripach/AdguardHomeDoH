#!/usr/bin/env python3
"""Read-only process identity checks for a future MTProxyL runtime controller.

This module deliberately does not send signals or change configuration. A
reload controller additionally requires a durable journal, a shared lock, a
mandatory recovery entrypoint, and acknowledgement from a new nginx worker.
PID observations alone are not a reload confirmation. Linux /proc and cgroup
v2 are required; unsupported systems fail closed.
"""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import sys


class IdentityError(RuntimeError):
    """The process identity cannot be established unambiguously."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    start_ticks: int
    boot_id: str
    cgroup: str
    exe_device: int
    exe_inode: int
    owner_uid: int
    argv: tuple[str, ...]


def _read_bounded(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - len(chunks)))
            if not chunk:
                return bytes(chunks)
            chunks.extend(chunk)
        raise IdentityError('oversized process metadata')
    finally:
        os.close(fd)


def _proc_stat(data, pid):
    try:
        text = data.decode('ascii').strip()
        end = text.rindex(')')
        if not text.startswith(str(pid) + ' ('):
            raise ValueError('PID mismatch')
        fields = text[end + 1:].split()
        state, ppid, start = fields[0], int(fields[1]), int(fields[19])
        if state not in {'R', 'S', 'D', 'I'} or ppid < 0 or start <= 0:
            raise ValueError('invalid process state')
        return ppid, start
    except (ValueError, IndexError, UnicodeError) as exc:
        raise IdentityError('invalid process stat') from exc


def _boot_id(proc_root):
    try:
        value = _read_bounded(proc_root / 'sys/kernel/random/boot_id', 100).decode('ascii').strip()
    except (OSError, UnicodeError) as exc:
        raise IdentityError('boot ID unavailable') from exc
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise IdentityError('invalid boot ID')
    return value


def _cgroup(data):
    try:
        lines = data.decode('utf-8').splitlines()
    except UnicodeError as exc:
        raise IdentityError('invalid cgroup metadata') from exc
    if len(lines) != 1 or not lines[0].startswith('0::/'):
        raise IdentityError('cgroup v2 identity required')
    path = lines[0][3:]
    if any(c in path for c in ('\x00', '\n', '\r')) or os.path.normpath(path) != path:
        raise IdentityError('invalid cgroup path')
    return path


def _argv(data):
    try:
        text = data.replace(b'\0', b' ').decode('utf-8').strip()
        prefix = 'nginx: master process '
        if not text.startswith(prefix):
            raise ValueError('not an nginx master title')
        args = tuple(shlex.split(text[len(prefix):]))
        if not args:
            raise ValueError('missing master arguments')
        return args
    except (ValueError, UnicodeError) as exc:
        raise IdentityError('invalid master command line') from exc


def inspect_master(pid, nginx_bin, runtime_path, expected_cgroup, *, proc_root=Path('/proc')):
    """Return a stable master snapshot; does not authorize or send HUP.

    Real callers must recheck the result while holding a common lock, use a
    pidfd when signalling, and verify the answering worker's incarnation.
    ``proc_root`` exists for isolated tests and is not exposed by the CLI.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise IdentityError('invalid PID')
    nginx_bin, runtime_path = Path(nginx_bin), Path(runtime_path)
    if not nginx_bin.is_absolute() or not runtime_path.is_absolute():
        raise IdentityError('absolute paths required')
    if (not expected_cgroup.startswith('/') or os.path.normpath(expected_cgroup) != expected_cgroup or
            any(c in expected_cgroup for c in ('\x00', '\r', '\n'))):
        raise IdentityError('invalid expected cgroup')
    proc_root = Path(proc_root)
    node = proc_root / str(pid)
    try:
        boot = _boot_id(proc_root)
        before_ppid, before_start = _proc_stat(_read_bounded(node / 'stat'), pid)
        proc_uid = os.stat(node, follow_symlinks=False).st_uid
        expected_exe = os.stat(nginx_bin)
        actual_exe = os.stat(node / 'exe')
        cgroup = _cgroup(_read_bounded(node / 'cgroup'))
        argv = _argv(_read_bounded(node / 'cmdline'))
        after_ppid, after_start = _proc_stat(_read_bounded(node / 'stat'), pid)
        after_exe = os.stat(node / 'exe')
        after_uid = os.stat(node, follow_symlinks=False).st_uid
        after_cgroup = _cgroup(_read_bounded(node / 'cgroup'))
        after_argv = _argv(_read_bounded(node / 'cmdline'))
        after_boot = _boot_id(proc_root)
    except OSError as exc:
        raise IdentityError('process metadata unavailable') from exc
    if ((before_ppid, before_start, proc_uid, cgroup, argv, boot) !=
            (after_ppid, after_start, after_uid, after_cgroup, after_argv, after_boot)):
        raise IdentityError('master changed during inspection')
    if proc_uid != 0:
        raise IdentityError('master must be root owned')
    if cgroup != expected_cgroup:
        raise IdentityError('unexpected master cgroup')
    if ((actual_exe.st_dev, actual_exe.st_ino) != (expected_exe.st_dev, expected_exe.st_ino) or
            (after_exe.st_dev, after_exe.st_ino) != (expected_exe.st_dev, expected_exe.st_ino)):
        raise IdentityError('unexpected executable')
    positions = [i for i, arg in enumerate(argv) if arg == '-c']
    if len(positions) != 1 or positions[0] + 1 >= len(argv) or argv[positions[0] + 1] != str(runtime_path):
        raise IdentityError('unexpected master configuration argument')
    return ProcessIdentity(pid, before_ppid, before_start, boot, cgroup,
                           actual_exe.st_dev, actual_exe.st_ino, proc_uid, argv)


def main():
    parser = argparse.ArgumentParser(description='Read-only nginx master identity check')
    parser.add_argument('command', choices=('inspect-master',))
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--nginx-bin', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--cgroup', required=True)
    args = parser.parse_args()
    try:
        identity = inspect_master(args.pid, args.nginx_bin, args.runtime, args.cgroup)
    except (IdentityError, OSError, ValueError):
        print('error: master identity not established', file=sys.stderr)
        return 1
    print(json.dumps({'pid': identity.pid, 'start_ticks': identity.start_ticks,
                      'boot_id': identity.boot_id, 'cgroup': identity.cgroup}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
