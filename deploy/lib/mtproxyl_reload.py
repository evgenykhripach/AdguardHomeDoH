#!/usr/bin/env python3
"""Prepare or reload the MTProxyL runtime from its vendor configuration.

All cooperating writers must use the same lock. Acquisition is nonblocking,
so a caller must release it before starting or reloading the service. A reload
validates the candidate before signalling nginx; the caller must still verify
the public services after nginx accepts the signal.
"""
import argparse
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys

try:
    from . import mtproxyl_runtime as runtime
    from . import mtproxyl_front as front
    from . import mtproxyl_controller as controller
except ImportError:
    import mtproxyl_runtime as runtime
    import mtproxyl_front as front
    import mtproxyl_controller as controller


def _require_root():
    if os.geteuid() != 0:
        raise ValueError('root required')


def _lock_check(fd, parent, name, path, directory):
    runtime._check_parent(path, directory)
    info = os.fstat(fd)
    path_info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
        raise ValueError('unsafe lock')


def _previous(path):
    parent, name = runtime._secure_parent(path)
    try:
        info = os.fstat(parent)
        snap = runtime._snapshot(parent, name, optional=True)
        if snap and (snap[1].st_uid != os.geteuid() or stat.S_IMODE(snap[1].st_mode) != 0o600):
            raise ValueError('unsafe runtime')
        return info, runtime._exact_identity(snap)
    finally:
        os.close(parent)


def _verify_previous(path, directory, previous, domain, admin_host, nginx_bin):
    if previous is None:
        raise ValueError('no previous runtime')
    runtime._check_parent(path, directory)
    before_dir, before = _previous(path)
    if (before_dir.st_dev, before_dir.st_ino) != (directory.st_dev, directory.st_ino) or before != previous:
        raise ValueError('previous runtime changed')
    content = previous[0][-1].decode('utf-8')
    _, has_overlay, has_admin = front._strip_with_admin(content)
    if not has_overlay or (admin_host is not None and not has_admin):
        raise ValueError('previous overlay incomplete')
    front.unpatch(content, domain, admin_host)
    result = subprocess.run([os.fspath(nginx_bin), '-t', '-c', os.fspath(path)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError('previous runtime invalid')
    runtime._check_parent(path, directory)
    _, after = _previous(path)
    if after != previous:
        raise ValueError('previous runtime changed')


def prepare_startup(*, source, runtime_path, domain, admin_host, nginx_bin, lock_path):
    """Return 'overlay' or 'last-known-good'; raise on unsafe or invalid state.

    The caller must run this only with the target nginx stopped. Validation of
    the previous runtime includes its overlay and the requested admin route.
    Any error during or after publish fails closed, as its result can be
    ambiguous after rename. Output from nginx is deliberately suppressed.
    """
    _require_root()
    front._domain(domain)
    front._domain(admin_host)
    source, target, binary, lock_path = map(Path, (source, runtime_path, nginx_bin, lock_path))
    if not all(p.is_absolute() for p in (source, target, binary, lock_path)):
        raise ValueError('absolute paths required')
    if len({str(source), str(target), str(lock_path)}) != 3:
        raise ValueError('paths must differ')
    parent, name = runtime._secure_parent(lock_path)
    fd = None
    try:
        directory = os.fstat(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        _lock_check(fd, parent, name, lock_path, directory)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_check(fd, parent, name, lock_path, directory)
        previous_dir, previous = _previous(target)
        try:
            staged = runtime.stage(source, target, domain, binary, admin_host=admin_host)
        except (OSError, ValueError, RuntimeError, UnicodeError):
            _lock_check(fd, parent, name, lock_path, directory)
            _verify_previous(target, previous_dir, previous, domain, admin_host, binary)
            _lock_check(fd, parent, name, lock_path, directory)
            return 'last-known-good'
        with staged:
            if staged.previous_exact != previous:
                raise ValueError('previous runtime changed')
            _lock_check(fd, parent, name, lock_path, directory)
            result = runtime.publish(staged)
            _lock_check(fd, parent, name, lock_path, directory)
            return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)



def reload_running(*, source, runtime_path, domain, admin_host, nginx_bin, lock_path, main_pid, cgroup):
    """Validate and publish vendor overlay, then HUP the identified nginx master.

    HUP acceptance does not prove new workers or business routes are healthy.
    A post-publication failure leaves the validated runtime in place and raises.
    Caller must coordinate all writers using the same front lock.
    """
    _require_root()
    front._domain(domain)
    front._domain(admin_host)
    source, target, binary, lock_path = map(Path, (source, runtime_path, nginx_bin, lock_path))
    if not all(p.is_absolute() for p in (source, target, binary, lock_path)):
        raise ValueError('absolute paths required')
    if len({str(source), str(target), str(lock_path)}) != 3:
        raise ValueError('paths must differ')
    parent, name = runtime._secure_parent(lock_path)
    fd = None
    try:
        directory = os.fstat(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        _lock_check(fd, parent, name, lock_path, directory)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_check(fd, parent, name, lock_path, directory)
        master = controller.inspect_master(main_pid, binary, target, cgroup)
        _, previous = _previous(target)
        if previous is None:
            raise ValueError('runtime missing')
        with runtime.stage(source, target, domain, binary, admin_host=admin_host) as staged:
            if staged.previous_exact != previous:
                raise ValueError('runtime changed')
            _lock_check(fd, parent, name, lock_path, directory)
            controller._recheck_master(master, Path('/proc'))
            controller._assert_binary(master, binary)
            runtime.publish(staged)
            _lock_check(fd, parent, name, lock_path, directory)
            controller._assert_binary(master, binary)
            controller._signal_checked(master, fd, lock_path)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def main():
    is_reload = len(sys.argv) > 1 and sys.argv[1] == 'reload'
    parser = argparse.ArgumentParser(description='Prepare MTProxyL runtime')
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--admin-host', required=True)
    parser.add_argument('--nginx-bin', required=True, type=Path)
    parser.add_argument('--lock', required=True, type=Path)
    if is_reload:
        parser.add_argument('--main-pid', required=True, type=int)
        parser.add_argument('--cgroup', required=True)
    args = parser.parse_args(sys.argv[2:] if is_reload else None)
    if is_reload:
        try:
            reload_running(source=args.source, runtime_path=args.runtime, domain=args.domain,
                           admin_host=args.admin_host, nginx_bin=args.nginx_bin, lock_path=args.lock,
                           main_pid=args.main_pid, cgroup=args.cgroup)
        except (OSError, ValueError, RuntimeError, UnicodeError):
            print('error: MTProxyL reload failed; runtime may have been published', file=sys.stderr)
            return 1
        return 0
    try:
        result = prepare_startup(source=args.source, runtime_path=args.runtime, domain=args.domain,
                                 admin_host=args.admin_host, nginx_bin=args.nginx_bin, lock_path=args.lock)
    except (OSError, ValueError, RuntimeError, UnicodeError):
        print('error: MTProxyL runtime preparation failed', file=sys.stderr)
        return 1
    if result == 'last-known-good':
        print('warning: using last-known-good MTProxyL runtime', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
