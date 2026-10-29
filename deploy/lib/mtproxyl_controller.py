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


try:
    from . import mtproxyl_runtime as runtime
except ImportError:
    import mtproxyl_runtime as runtime


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



@dataclass(frozen=True)
class WorkerIdentity:
    pid: int
    ppid: int
    start_ticks: int
    boot_id: str
    cgroup: str
    exe_device: int
    exe_inode: int
    owner_uid: int


@dataclass(frozen=True)
class WorkerSnapshot:
    master: ProcessIdentity
    workers: frozenset[WorkerIdentity]


def _recheck_master(master, proc_root):
    """Re-read all fingerprint fields, not just the reusable numeric PID."""
    try:
        index = master.argv.index('-c')
        config = master.argv[index + 1]
    except (ValueError, IndexError) as exc:
        raise IdentityError('invalid master fingerprint') from exc
    exe = Path(proc_root) / str(master.pid) / 'exe'
    current = inspect_master(master.pid, exe, Path(config), master.cgroup, proc_root=proc_root)
    if current != master:
        raise IdentityError('master incarnation changed')


def _children(master, proc_root):
    path = Path(proc_root) / str(master.pid) / 'task' / str(master.pid) / 'children'
    try:
        tokens = _read_bounded(path).decode('ascii').split()
        if any(not re.fullmatch(r'[1-9][0-9]*', token) for token in tokens):
            raise ValueError('invalid child PID')
        children = tuple(sorted(int(token) for token in tokens))
        if len(children) != len(set(children)):
            raise ValueError('duplicate child PID')
        return children
    except (OSError, UnicodeError, ValueError) as exc:
        raise IdentityError('children metadata unavailable') from exc


def _child_identity(pid, master, proc_root, *, require_worker=False):
    proc_root = Path(proc_root)
    node = proc_root / str(pid)
    try:
        boot = _boot_id(proc_root)
        ppid, start = _proc_stat(_read_bounded(node / 'stat'), pid)
        cgroup = _cgroup(_read_bounded(node / 'cgroup'))
        executable = os.stat(node / 'exe')
        uid = os.stat(node, follow_symlinks=False).st_uid
        command = _read_bounded(node / 'cmdline')
        ppid_after, start_after = _proc_stat(_read_bounded(node / 'stat'), pid)
        cgroup_after = _cgroup(_read_bounded(node / 'cgroup'))
        executable_after = os.stat(node / 'exe')
        uid_after = os.stat(node, follow_symlinks=False).st_uid
        command_after = _read_bounded(node / 'cmdline')
        boot_after = _boot_id(proc_root)
    except OSError as exc:
        raise IdentityError('worker metadata unavailable') from exc
    if ((ppid, start, cgroup, uid, command, boot) !=
            (ppid_after, start_after, cgroup_after, uid_after, command_after, boot_after) or
            (executable.st_dev, executable.st_ino) != (executable_after.st_dev, executable_after.st_ino)):
        raise IdentityError('worker changed during inspection')
    if (ppid != master.pid or cgroup != master.cgroup or boot != master.boot_id or
            (executable.st_dev, executable.st_ino) != (master.exe_device, master.exe_inode) or
            start < master.start_ticks):
        raise IdentityError('worker does not belong to master')
    if require_worker and command.replace(b'\0', b' ').strip() != b'nginx: worker process':
        raise IdentityError('responding process is not an active nginx worker')
    return WorkerIdentity(pid, ppid, start, boot, cgroup, executable.st_dev, executable.st_ino, uid)


def capture_workers(master, *, proc_root=Path('/proc')):
    """Capture all current master child incarnations, failing on any ambiguity.

    The caller must serialize its own reload and capture immediately before
    signalling. Uncoordinated external writers and signals remain a race.
    """
    _recheck_master(master, proc_root)
    before = _children(master, proc_root)
    if not before:
        raise IdentityError('master has no observable children')
    workers = frozenset(_child_identity(pid, master, proc_root) for pid in before)
    if _children(master, proc_root) != before:
        raise IdentityError('children changed during capture')
    _recheck_master(master, proc_root)
    return WorkerSnapshot(master, workers)


def confirm_generation(master, old_workers, marker_socket, generation, *,
                       proc_root=Path('/proc'), probe=None):
    """Verify a marker response is from a new worker of the unchanged master.

    This is only a point-in-time observation. Caller must hold its shared lock,
    signal an already captured pidfd, and handle recovery on every failure.
    """
    if not isinstance(old_workers, WorkerSnapshot) or old_workers.master != master or not old_workers.workers:
        raise IdentityError('invalid worker baseline')
    _recheck_master(master, proc_root)
    if probe is None:
        probe = runtime.probe_generation
    try:
        worker_pid = probe(marker_socket, generation)
    except (OSError, ValueError, RuntimeError) as exc:
        raise IdentityError('generation probe failed') from exc
    if isinstance(worker_pid, bool) or not isinstance(worker_pid, int) or worker_pid <= 0:
        raise IdentityError('invalid worker PID')
    worker = _child_identity(worker_pid, master, proc_root, require_worker=True)
    if any(previous.pid == worker.pid for previous in old_workers.workers):
        # A stale response can race an exit and PID reuse before /proc is read.
        raise IdentityError('old or reused PID cannot confirm reload')
    if worker.pid not in _children(master, proc_root):
        raise IdentityError('worker is not a current master child')
    _recheck_master(master, proc_root)
    if _child_identity(worker_pid, master, proc_root, require_worker=True) != worker:
        raise IdentityError('worker incarnation changed')
    _recheck_master(master, proc_root)
    return worker

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
