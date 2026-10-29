#!/usr/bin/env python3
"""Read-only process identity checks for a future MTProxyL runtime controller.

This module deliberately does not send signals or change configuration. A
reload controller additionally requires a durable journal, a shared lock, a
mandatory recovery entrypoint, and acknowledgement from a new nginx worker.
PID observations alone are not a reload confirmation. Linux /proc and cgroup
v2 are required; unsupported systems fail closed.
"""
import argparse
import hashlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import time
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


class ReloadFailed(RuntimeError):
    """Reload failed; prior generation was confirmed again."""


class RecoveryUncertain(RuntimeError):
    """Failure could not be safely rolled back; durable journal must remain."""


@dataclass(frozen=True)
class ReloadRecord:
    transaction_id: str
    master: ProcessIdentity
    source_identity: tuple
    previous_identity: tuple
    previous_generation: str
    next_generation: str
    candidate_sha256: str
    source_path: str
    runtime_path: str
    marker_socket: str
    source_exact: tuple
    previous_exact: tuple
    candidate_identity: tuple
    candidate_exact: tuple
    candidate_path: str


@dataclass(frozen=True)
class JournalReceipt:
    transaction_id: str
    durable: bool


def _path_snapshot(path):
    parent, name = runtime._secure_parent(path)
    try:
        return runtime._snapshot(parent, name)
    finally:
        os.close(parent)


def _assert_lock_held(lock_fd, lock_path):
    """Require this process to own an exclusive Linux flock on a private file."""
    if isinstance(lock_fd, bool) or not isinstance(lock_fd, int) or lock_fd < 0:
        raise IdentityError('front lock required')
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise IdentityError('unsafe front lock')
        if not Path(lock_path).is_absolute():
            raise IdentityError('absolute front lock path required')
        parent, name = runtime._secure_parent(lock_path)
        try:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise IdentityError('front lock path changed')
        finally:
            os.close(parent)
        target = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        # /proc/locks alone is process/inode scoped and can describe a flock
        # held through a *different* open-file description. fdinfo is scoped
        # to this specific descriptor (and any descriptors duplicated from it).
        fdinfo = _read_bounded(Path('/proc/self/fdinfo') / str(lock_fd)).decode('ascii').splitlines()
        matches = 0
        for line in fdinfo:
            fields = line.split()
            if len(fields) != 9 or fields[0] != 'lock:' or fields[2:5] != ['FLOCK', 'ADVISORY', 'WRITE']:
                continue
            try:
                owner = int(fields[5])
                major, minor, inode = fields[6].split(':')
                found = (int(major, 16), int(minor, 16), int(inode))
            except ValueError:
                continue
            if owner == os.getpid() and found == target and fields[7:] == ['0', 'EOF']:
                matches += 1
        if matches != 1:
            raise IdentityError('front lock is not held through this descriptor')
        lines = _read_bounded(Path('/proc/locks'), 1048576).decode('ascii').splitlines()
        for line in lines:
            fields = line.split()
            if len(fields) < 6 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE']:
                continue
            try:
                owner = int(fields[4])
                major, minor, inode = fields[5].split(':')
                found = (int(major, 16), int(minor, 16), int(inode))
            except ValueError:
                continue
            if owner == os.getpid() and found == target:
                return
    except (OSError, UnicodeError, ValueError) as exc:
        raise IdentityError('front lock not verifiable') from exc
    raise IdentityError('exclusive front lock is not held by this process')


def _marker_fragment(socket_path, generation):
    path = runtime._generation_args(socket_path, generation)
    return (runtime._GENERATION_BEGIN + "\n"
            "    server {\n"
            "        listen unix:" + path + ";\n"
            "        server_name _;\n"
            "        access_log off;\n"
            "        location = / { default_type text/plain; return 200 \"" + generation + " $pid\"; }\n"
            "    }\n"
            "    " + runtime._GENERATION_END)


def _validate_previous(content, socket_path, generation, nginx_bin, runtime_path):
    try:
        text = content.decode('utf-8')
        fragment = _marker_fragment(socket_path, generation)
    except (ValueError, UnicodeError) as exc:
        raise IdentityError('previous generation unavailable') from exc
    if (text.count(runtime._GENERATION_BEGIN) != 1 or text.count(runtime._GENERATION_END) != 1 or
            text.count(fragment) != 1):
        raise IdentityError('previous generation unavailable')
    try:
        nodes = runtime.front._parse(text)
        http = runtime.front._one(nodes, 'http', ['http'], True)
        servers = [node for node in runtime.front._named(http.children, 'server')
                   if node.children is not None and any(
                       entry.args == ['listen', 'unix:' + os.fspath(socket_path)]
                       and entry.children is None for entry in node.children)]
        if len(servers) != 1:
            raise ValueError('ambiguous generation server')
        location = runtime.front._one(servers[0].children, 'location', ['location', '=', '/'], True)
        runtime.front._one(location.children, 'return', ['return', '200', generation + ' $pid'], False)
    except (ValueError, IndexError) as exc:
        raise IdentityError('previous generation server invalid') from exc
    checked = subprocess.run([os.fspath(nginx_bin), '-t', '-c', os.fspath(runtime_path)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=False)
    if checked.returncode:
        raise IdentityError('previous runtime does not validate')



def _assert_binary(master, nginx_bin):
    try:
        executable = os.stat(nginx_bin)
    except OSError as exc:
        raise IdentityError('nginx executable unavailable') from exc
    if (executable.st_dev, executable.st_ino) != (master.exe_device, master.exe_inode):
        raise IdentityError('nginx executable changed')

def _signal_checked(master, lock_fd, lock_path, *, proc_root=Path('/proc')):
    """Signal the same Linux process incarnation through a pidfd."""
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise IdentityError('pidfd signalling unavailable')
    _assert_lock_held(lock_fd, lock_path)
    _recheck_master(master, proc_root)
    fd = os.pidfd_open(master.pid, 0)
    try:
        _recheck_master(master, proc_root)
        _assert_lock_held(lock_fd, lock_path)
        signal.pidfd_send_signal(fd, signal.SIGHUP)
        _recheck_master(master, proc_root)
        _assert_lock_held(lock_fd, lock_path)
    finally:
        os.close(fd)



def _capture_stable_workers(master, lock_fd, lock_path, *, proc_root, timeout):
    """Allow graceful workers to exit, without accepting an ambiguous snapshot."""
    deadline = time.monotonic() + timeout
    while True:
        _assert_lock_held(lock_fd, lock_path)
        _recheck_master(master, proc_root)
        try:
            return capture_workers(master, proc_root=proc_root)
        except IdentityError:
            if time.monotonic() >= deadline:
                raise IdentityError('stable worker snapshot unavailable')
            time.sleep(min(.05, max(0.0, deadline - time.monotonic())))

def _wait_generation(master, baseline, socket_path, generation, lock_fd, lock_path, *,
                     proc_root, timeout):
    deadline = time.monotonic() + timeout
    while True:
        _assert_lock_held(lock_fd, lock_path)
        _recheck_master(master, proc_root)
        try:
            return confirm_generation(master, baseline, socket_path, generation, proc_root=proc_root)
        except IdentityError:
            if time.monotonic() >= deadline:
                raise IdentityError('generation confirmation timed out')
            time.sleep(min(.05, max(0.0, deadline - time.monotonic())))


def _strict_reload_impl(*, source, runtime_path, domain, nginx_bin, marker_socket,
                  previous_generation, master, lock_fd, lock_path, record_before_publish,
                  restore_previous, verify_business, verify_previous,
                  proc_root=Path('/proc'), timeout=5.0):
    """Publish, HUP and confirm under caller's lock and durable journal.

    The four callbacks are trusted external components, not optional checks:
    record_before_publish(record) must fsync its journal and backup, then return
    JournalReceipt(record.transaction_id, True); restore_previous(record) must
    atomically restore the exact saved runtime and return its generation;
    verify_business(record, worker) and verify_previous(record, worker) must
    return True only after checking the actual corresponding business path.
    This function never clears a journal. The caller owns crash recovery and
    must retain the same lock through journal commit and systemd integration.
    Source writers that ignore this lock can still race the final checks.
    """
    callbacks = (record_before_publish, restore_previous, verify_business, verify_previous)
    if any(not callable(callback) for callback in callbacks):
        raise ValueError('all transaction callbacks are required')
    if not isinstance(master, ProcessIdentity) or not (0 < timeout <= 60):
        raise ValueError('valid master and timeout required')
    source, runtime_path, nginx_bin = Path(source), Path(runtime_path), Path(nginx_bin)
    if not all(path.is_absolute() for path in (source, runtime_path, nginx_bin)):
        raise ValueError('absolute paths required')
    _assert_lock_held(lock_fd, lock_path)
    _recheck_master(master, proc_root)
    positions = [i for i, arg in enumerate(master.argv) if arg == '-c']
    if len(positions) != 1 or positions[0] + 1 >= len(master.argv) or master.argv[positions[0] + 1] != str(runtime_path):
        raise IdentityError('master uses another runtime')
    _assert_binary(master, nginx_bin)
    prior = _path_snapshot(runtime_path)
    vendor = _path_snapshot(source)
    if (prior[1].st_dev, prior[1].st_ino) == (vendor[1].st_dev, vendor[1].st_ino):
        raise IdentityError('vendor and runtime coincide')
    _validate_previous(prior[0], marker_socket, previous_generation, nginx_bin, runtime_path)
    _assert_binary(master, nginx_bin)
    if runtime._exact_identity(_path_snapshot(runtime_path)) != runtime._exact_identity(prior):
        raise IdentityError('previous runtime changed')
    baseline = _capture_stable_workers(master, lock_fd, lock_path, proc_root=proc_root, timeout=timeout)
    try:
        old_pid = runtime.probe_generation(marker_socket, previous_generation)
        old_worker = _child_identity(old_pid, master, proc_root, require_worker=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise IdentityError('previous generation not confirmed') from exc
    if old_worker not in baseline.workers:
        raise IdentityError('previous worker absent from baseline')
    _recheck_master(master, proc_root)
    generation = secrets.token_hex(16)
    if generation == previous_generation:
        raise IdentityError('new generation is not distinct')
    candidate = runtime.patch_with_generation(vendor[0].decode('utf-8'), domain, marker_socket, generation).encode('utf-8')
    with runtime.stage(source, runtime_path, domain, nginx_bin,
                       marker_socket=marker_socket, generation=generation) as staged:
        if (staged.status != 'overlay' or staged.source_exact != runtime._exact_identity(vendor) or
                staged.previous_exact != runtime._exact_identity(prior) or
                staged.candidate_identity[-1] != candidate):
            raise IdentityError('staged candidate does not match transaction')
        record = ReloadRecord(secrets.token_hex(16), master, runtime._identity(vendor),
                              runtime._identity(prior), previous_generation, generation,
                              hashlib.sha256(candidate).hexdigest(), str(source), str(runtime_path),
                              os.fspath(marker_socket), staged.source_exact, staged.previous_exact,
                              staged.candidate_identity, staged.candidate_exact, staged.candidate_path)
        try:
            receipt = record_before_publish(record)
            if not isinstance(receipt, JournalReceipt) or receipt.transaction_id != record.transaction_id or receipt.durable is not True:
                raise IdentityError('durable journal not confirmed')
            _assert_lock_held(lock_fd, lock_path)
            _recheck_master(master, proc_root)
            if (runtime._exact_identity(_path_snapshot(source)) != record.source_exact or
                    runtime._exact_identity(_path_snapshot(runtime_path)) != record.previous_exact):
                raise IdentityError('source or previous runtime changed before publish')
        except BaseException as exc:
            raise RecoveryUncertain('journal preparation failed; retain any journal') from exc
        published = None
        try:
            runtime.publish(staged)
            published = _path_snapshot(runtime_path)
            _assert_lock_held(lock_fd, lock_path)
            if runtime._exact_identity(_path_snapshot(source)) != record.source_exact:
                raise IdentityError('source changed after publish')
            current = published
            if (runtime._identity(current) != record.candidate_identity or
                    current[1].st_mtime_ns != record.candidate_exact[1] or
                    stat.S_IMODE(current[1].st_mode) != 0o600 or current[1].st_uid != os.geteuid()):
                raise IdentityError('runtime changed after publish')
            baseline = _capture_stable_workers(master, lock_fd, lock_path, proc_root=proc_root, timeout=timeout)
            _assert_binary(master, nginx_bin)
            _signal_checked(master, lock_fd, lock_path, proc_root=proc_root)
            worker = _wait_generation(master, baseline, marker_socket, generation, lock_fd, lock_path,
                                      proc_root=proc_root, timeout=timeout)
            if verify_business(record, worker) is not True:
                raise IdentityError('business verification failed')
            _assert_lock_held(lock_fd, lock_path)
            _recheck_master(master, proc_root)
            if (runtime._exact_identity(_path_snapshot(source)) != record.source_exact or
                    runtime._exact_identity(_path_snapshot(runtime_path)) != runtime._exact_identity(current)):
                raise IdentityError('source or runtime changed after reload')
            return generation
        except BaseException as failure:
            try:
                _assert_lock_held(lock_fd, lock_path)
                _recheck_master(master, proc_root)
                observed = _path_snapshot(runtime_path)
                # Candidate inode was journaled before rename. Its ctime may have
                # changed during rename, so compare stable inode, contents, metadata
                # and mtime; if available also require the post-publish exact snapshot.
                is_previous = runtime._exact_identity(observed) == record.previous_exact
                is_candidate = (runtime._identity(observed) == record.candidate_identity and
                                observed[1].st_mtime_ns == record.candidate_exact[1] and
                                (published is None or runtime._exact_identity(observed) == runtime._exact_identity(published)))
                if not (is_previous or is_candidate):
                    raise IdentityError('runtime changed before rollback')
                restored_generation = restore_previous(record)
                if restored_generation != previous_generation:
                    raise IdentityError('rollback generation mismatch')
                restored = _path_snapshot(runtime_path)
                if (restored[0] != prior[0] or stat.S_IMODE(restored[1].st_mode) != stat.S_IMODE(prior[1].st_mode) or
                        restored[1].st_uid != prior[1].st_uid or restored[1].st_gid != prior[1].st_gid):
                    raise IdentityError('rollback content or ownership mismatch')
                _assert_binary(master, nginx_bin)
                _validate_previous(restored[0], marker_socket, previous_generation, nginx_bin, runtime_path)
                _assert_binary(master, nginx_bin)
                if runtime._exact_identity(_path_snapshot(runtime_path)) != runtime._exact_identity(restored):
                    raise IdentityError('restored runtime changed')
                rollback_baseline = _capture_stable_workers(master, lock_fd, lock_path, proc_root=proc_root, timeout=timeout)
                _signal_checked(master, lock_fd, lock_path, proc_root=proc_root)
                worker = _wait_generation(master, rollback_baseline, marker_socket, previous_generation,
                                          lock_fd, lock_path, proc_root=proc_root, timeout=timeout)
                if verify_previous(record, worker) is not True:
                    raise IdentityError('previous business verification failed')
                _assert_lock_held(lock_fd, lock_path)
                _recheck_master(master, proc_root)
                if (runtime._exact_identity(_path_snapshot(runtime_path)) != runtime._exact_identity(restored) or
                        runtime._exact_identity(_path_snapshot(source)) != record.source_exact):
                    raise IdentityError('source or restored runtime changed after rollback')
            except BaseException as rollback_error:
                raise RecoveryUncertain('reload and rollback were not both confirmed; retain journal') from rollback_error
            raise ReloadFailed('reload failed; prior generation confirmed; retain journal') from failure


def strict_reload(*, source, runtime_path, domain, nginx_bin, marker_socket,
                  previous_generation, master, lock_fd, lock_path, record_before_publish,
                  restore_previous, verify_business, verify_previous,
                  proc_root=Path('/proc'), timeout=5.0):
    """Pin the caller's locked open-file description across the transaction.

    The caller must keep its own lock and journal until commit after return.
    A duplicate protects this operation from accidental close of the supplied
    descriptor. A concurrent explicit LOCK_UN still releases all duplicates,
    so the caller must not unlock before the transaction and commit complete.
    """
    if isinstance(lock_fd, bool) or not isinstance(lock_fd, int) or lock_fd < 0:
        raise IdentityError('front lock required')
    try:
        pinned_fd = os.dup(lock_fd)
    except OSError as exc:
        raise IdentityError('front lock unavailable') from exc
    try:
        _assert_lock_held(pinned_fd, lock_path)
        try:
            result = _strict_reload_impl(
                source=source, runtime_path=runtime_path, domain=domain, nginx_bin=nginx_bin,
                marker_socket=marker_socket, previous_generation=previous_generation,
                master=master, lock_fd=pinned_fd, lock_path=lock_path,
                record_before_publish=record_before_publish, restore_previous=restore_previous,
                verify_business=verify_business, verify_previous=verify_previous,
                proc_root=proc_root, timeout=timeout)
        except BaseException as original:
            try:
                _assert_lock_held(lock_fd, lock_path)
            except (IdentityError, OSError, ValueError) as exc:
                raise RecoveryUncertain('caller lost front lock; retain any journal') from exc
            raise original
        try:
            _assert_lock_held(lock_fd, lock_path)
        except (IdentityError, OSError, ValueError) as exc:
            raise RecoveryUncertain('caller lost front lock; retain journal') from exc
        return result
    finally:
        os.close(pinned_fd)


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
