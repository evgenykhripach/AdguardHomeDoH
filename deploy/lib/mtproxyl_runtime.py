#!/usr/bin/env python3
"""Prepare a verified runtime nginx configuration without touching the vendor file.

Callers coordinating MTProxyL must hold a common lock across this function and
any subsequent nginx reload. Uncoordinated writers can still race the final
checks and rename; this primitive neither locks nor reloads a service.
"""
import argparse
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from . import mtproxyl_front as front
except ImportError:
    import mtproxyl_front as front


def _secure_parent(path):
    """Reject symlinks and writable/untrusted parents, allowing root sticky ancestors."""
    path = os.fspath(path)
    if '..' in path.split('/'):
        raise ValueError('invalid path')
    path = os.path.abspath(path)
    parts = path.split('/')
    name = parts.pop()
    if not name or name in ('.', '..') or '..' in parts:
        raise ValueError('invalid path')
    components = [p for p in parts if p and p != '.']
    fd = os.open('/' if path.startswith('/') else '.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def check(directory_fd, terminal):
            st = os.fstat(directory_fd)
            if st.st_uid not in (0, os.geteuid()):
                raise ValueError('untrusted directory')
            if st.st_mode & 0o022:
                if terminal or st.st_uid != 0 or not st.st_mode & stat.S_ISVTX:
                    raise ValueError('writable directory')
        check(fd, not components)
        for index, part in enumerate(components):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            check(fd, index == len(components) - 1)
        return fd, name
    except BaseException:
        os.close(fd)
        raise


def _snapshot(parent, name, *, optional=False):
    try:
        data, info, digest = front._snapshot(parent, name)
    except FileNotFoundError:
        if optional:
            return None
        raise
    if info.st_nlink != 1 or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError('unsafe file')
    return data, info, digest


def _identity(snapshot):
    if snapshot is None:
        return None
    data, info, digest = snapshot
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, digest, data)



def _exact_identity(snapshot):
    """Snapshot identity including times; rename legitimately changes ctime."""
    if snapshot is None:
        return None
    return (_identity(snapshot), snapshot[1].st_mtime_ns, snapshot[1].st_ctime_ns)

def _check_parent(path, previous):
    fd, _ = _secure_parent(path)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != (previous.st_dev, previous.st_ino):
            raise RuntimeError('directory changed')
    finally:
        os.close(fd)



_GENERATION_BEGIN = '# BEGIN DOHDNS GENERATION PROBE'
_GENERATION_END = '# END DOHDNS GENERATION PROBE'


def _generation_args(socket_path, generation):
    path = os.fspath(socket_path)
    if (not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or
            os.path.normpath(path) != path or len(path.encode('ascii')) > 100 or
            not re.fullmatch(r'[a-f0-9]{32}', generation)):
        raise ValueError('invalid generation probe parameters')
    parent, _ = _secure_parent(path)
    try:
        if stat.S_IMODE(os.fstat(parent).st_mode) & 0o077:
            raise ValueError('generation socket directory must be private')
    finally:
        os.close(parent)
    return path


def patch_with_generation(source, domain, socket_path, generation):
    """Render overlay and private local generation endpoint, without activation.

    The response identifies one worker. Caller must independently verify that
    worker is new and belongs to the expected master/process incarnation.
    """
    path = _generation_args(socket_path, generation)
    if _GENERATION_BEGIN in source or _GENERATION_END in source:
        raise ValueError('generation marker already exists')
    result = front.patch(source, domain)
    nodes = front._parse(result)
    http = front._one(nodes, 'http', ['http'], True)
    def socket_in_use(entries):
        return any((n.args[0] == 'listen' and len(n.args) > 1 and n.args[1] == 'unix:' + path)
                   or (n.children is not None and socket_in_use(n.children)) for n in entries)
    if socket_in_use(nodes):
        raise ValueError('generation socket already in config')
    insertion = ("\n    " + _GENERATION_BEGIN + "\n"
                 "    server {\n"
                 "        listen unix:" + path + ";\n"
                 "        server_name _;\n"
                 "        access_log off;\n"
                 "        location = / { default_type text/plain; return 200 \"" + generation + " $pid\"; }\n"
                 "    }\n"
                 "    " + _GENERATION_END + "\n")
    index = http.opening + 1
    return result[:index] + insertion + result[index:]


def probe_generation(socket_path, generation, *, timeout=2.0):
    """Read expected generation and responding worker PID, not a reload verdict."""
    path = _generation_args(socket_path, generation)
    parent, name = _secure_parent(path)
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid not in (0, os.geteuid()):
            raise ValueError('unsafe generation socket')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(path)
            connection.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            response = bytearray()
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > 8192:
                    raise ValueError('oversized generation response')
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError('generation socket changed')
    finally:
        os.close(parent)
    head, separator, body = bytes(response).partition(b'\r\n\r\n')
    if not separator or not re.fullmatch(rb'HTTP/1\.[01] 200(?: [^\r\n]*)?', head.split(b'\r\n', 1)[0]):
        raise ValueError('invalid generation response')
    match = re.fullmatch(re.escape(generation.encode('ascii')) + rb' ([1-9][0-9]*)', body)
    if not match:
        raise ValueError('generation mismatch')
    return int(match.group(1))

class CandidateInvalid(RuntimeError):
    pass



@dataclass
class StagedRuntime:
    """An open, checked candidate; close removes only the owned staged inode."""
    source_path: Path
    runtime_path: Path
    source_parent: int
    runtime_parent: int
    source_name: str
    runtime_name: str
    source_dir: os.stat_result
    runtime_dir: os.stat_result
    source_identity: tuple
    previous_identity: tuple | None
    source_exact: tuple
    previous_exact: tuple | None
    candidate_name: str
    candidate_identity: tuple
    candidate_exact: tuple
    candidate_fd: int
    status: str
    _closed: bool = False
    _published: bool = False

    @property
    def candidate_path(self):
        return str(self.runtime_path.absolute().parent / self.candidate_name)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            info = os.fstat(self.candidate_fd)
            _unlink_own(self.runtime_parent, self.candidate_name, info)
        finally:
            os.close(self.candidate_fd)
            os.close(self.runtime_parent)
            os.close(self.source_parent)

    def __enter__(self):
        if self._closed:
            raise RuntimeError('candidate closed')
        return self

    def __exit__(self, *_):
        self.close()


def stage(source, runtime, domain, nginx_bin, *, allow_fallback=False,
          marker_socket=None, generation=None):
    """Create and validate a durable private candidate without publishing it.

    Caller must retain the open object, journal candidate_identity and
    candidate_path before calling publish, and coordinate any nginx reload.
    """
    front._domain(domain)
    if (marker_socket is None) != (generation is None):
        raise ValueError('both generation arguments required')
    if marker_socket is not None:
        _generation_args(marker_socket, generation)
    source, runtime = Path(source), Path(runtime)
    source_parent, source_name = _secure_parent(source)
    runtime_parent = None
    candidate_fd = None
    candidate_name = None
    candidate_created = None
    try:
        runtime_parent, runtime_name = _secure_parent(runtime)
        source_dir = os.fstat(source_parent)
        runtime_dir = os.fstat(runtime_parent)
        if ((source_dir.st_dev, source_dir.st_ino, source_name) ==
                (runtime_dir.st_dev, runtime_dir.st_ino, runtime_name)):
            raise ValueError('vendor and runtime coincide')
        vendor = _snapshot(source_parent, source_name)
        previous = _snapshot(runtime_parent, runtime_name, optional=True)
        if previous and previous[1].st_uid != os.geteuid():
            raise ValueError('runtime owner mismatch')
        if previous and ((previous[1].st_dev, previous[1].st_ino) ==
                         (vendor[1].st_dev, vendor[1].st_ino)):
            raise ValueError('vendor and runtime coincide')
        original = vendor[0].decode('utf-8')
        _, has_overlay = front._strip(original)
        if has_overlay:
            raise ValueError('vendor contains managed overlay')

        def verified_candidate(content):
            name = '.' + runtime_name + '.doh-' + secrets.token_hex(16)
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=runtime_parent)
            created = os.fstat(fd)
            try:
                os.fchmod(fd, 0o600)
                encoded = content.encode('utf-8')
                with os.fdopen(fd, 'wb', closefd=False) as out:
                    out.write(encoded)
                    out.flush()
                os.fsync(fd)
                candidate_path = str(runtime.absolute().parent / name)
                checked = subprocess.run([os.fspath(nginx_bin), '-t', '-c', candidate_path],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, check=False)
                if checked.returncode:
                    raise CandidateInvalid('candidate validation failed')
                actual = _snapshot(runtime_parent, name)
                opened = os.fstat(fd)
                if ((actual[1].st_dev, actual[1].st_ino) != (created.st_dev, created.st_ino) or
                        (opened.st_dev, opened.st_ino) != (created.st_dev, created.st_ino) or
                        actual[0] != encoded or stat.S_IMODE(actual[1].st_mode) != 0o600 or
                        actual[1].st_uid != os.geteuid()):
                    raise RuntimeError('candidate changed')
                # The journal may refer to the candidate by name after a crash.
                os.fsync(runtime_parent)
                return name, fd, created, _identity(actual), _exact_identity(actual)
            except BaseException:
                _unlink_own(runtime_parent, name, created)
                os.close(fd)
                raise

        try:
            overlay = (patch_with_generation(original, domain, marker_socket, generation)
                       if marker_socket is not None else front.patch(original, domain))
        except ValueError:
            if not allow_fallback:
                raise
            overlay = None
        if overlay is not None:
            try:
                candidate_name, candidate_fd, candidate_created, candidate_identity, candidate_exact = verified_candidate(overlay)
                status = 'overlay'
            except CandidateInvalid:
                if not allow_fallback:
                    raise
                overlay = None
        if overlay is None:
            candidate_name, candidate_fd, candidate_created, candidate_identity, candidate_exact = verified_candidate(original)
            status = 'degraded'
        _check_parent(source, source_dir)
        _check_parent(runtime, runtime_dir)
        if _exact_identity(_snapshot(source_parent, source_name)) != _exact_identity(vendor):
            raise RuntimeError('vendor changed')
        if _exact_identity(_snapshot(runtime_parent, runtime_name, optional=True)) != _exact_identity(previous):
            raise RuntimeError('runtime changed')
        obj = StagedRuntime(source, runtime, source_parent, runtime_parent, source_name, runtime_name,
                            source_dir, runtime_dir, _identity(vendor), _identity(previous),
                            _exact_identity(vendor), _exact_identity(previous), candidate_name,
                            candidate_identity, candidate_exact, candidate_fd, status)
        # Ownership of all descriptors and the candidate transfers to obj.
        source_parent = runtime_parent = candidate_fd = None
        candidate_name = None
        return obj
    finally:
        if candidate_name is not None and runtime_parent is not None:
            _unlink_own(runtime_parent, candidate_name, candidate_created)
        if candidate_fd is not None:
            os.close(candidate_fd)
        if runtime_parent is not None:
            os.close(runtime_parent)
        if source_parent is not None:
            os.close(source_parent)


def publish(staged):
    """Atomically publish the same inode, then fsync its parent directory.

    Errors after rename are intentionally ambiguous; the external durable
    journal must compare current inode and digest against candidate_identity.
    """
    if not isinstance(staged, StagedRuntime) or staged._closed or staged._published:
        raise ValueError('invalid staged runtime')
    _check_parent(staged.source_path, staged.source_dir)
    _check_parent(staged.runtime_path, staged.runtime_dir)
    if _exact_identity(_snapshot(staged.source_parent, staged.source_name)) != staged.source_exact:
        raise RuntimeError('vendor changed')
    previous = _snapshot(staged.runtime_parent, staged.runtime_name, optional=True)
    if _exact_identity(previous) != staged.previous_exact:
        raise RuntimeError('runtime changed')
    candidate = _snapshot(staged.runtime_parent, staged.candidate_name)
    opened = os.fstat(staged.candidate_fd)
    if (_exact_identity(candidate) != staged.candidate_exact or
            (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid,
             opened.st_nlink, opened.st_mtime_ns, opened.st_ctime_ns) !=
            (candidate[1].st_dev, candidate[1].st_ino, candidate[1].st_mode,
             candidate[1].st_uid, candidate[1].st_gid, candidate[1].st_nlink,
             candidate[1].st_mtime_ns, candidate[1].st_ctime_ns)):
        raise RuntimeError('candidate changed')
    if (previous and previous[0] == candidate[0] and
            stat.S_IMODE(previous[1].st_mode) == 0o600 and previous[1].st_uid == os.geteuid()):
        staged._published = True
        return staged.status
    os.fsync(staged.candidate_fd)
    os.replace(staged.candidate_name, staged.runtime_name,
               src_dir_fd=staged.runtime_parent, dst_dir_fd=staged.runtime_parent)
    published = _snapshot(staged.runtime_parent, staged.runtime_name)
    # rename changes ctime on Linux; inode, contents, ownership, mode and
    # mtime must still match. Recovery may not require equality of old ctime.
    if (_identity(published) != staged.candidate_identity or
            published[1].st_mtime_ns != staged.candidate_exact[1]):
        raise RuntimeError('published candidate identity changed')
    os.fsync(staged.runtime_parent)
    staged._published = True
    return staged.status


def prepare(source, runtime, domain, nginx_bin, *, allow_fallback=False,
            marker_socket=None, generation=None):
    """Backward-compatible atomic preparation; caller coordinates reload."""
    with stage(source, runtime, domain, nginx_bin, allow_fallback=allow_fallback,
               marker_socket=marker_socket, generation=generation) as candidate:
        return publish(candidate)

def _unlink_own(parent, name, info):
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
            os.unlink(name, dir_fd=parent)
    except FileNotFoundError:
        pass


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'probe-generation':
        parser = argparse.ArgumentParser()
        parser.add_argument('--socket', required=True, type=Path)
        parser.add_argument('--generation', required=True)
        args = parser.parse_args(sys.argv[2:])
        try:
            worker = probe_generation(args.socket, args.generation)
        except (OSError, ValueError, RuntimeError):
            print('error: generation probe failed', file=sys.stderr)
            return 1
        print('worker %d' % worker)
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--nginx-bin', required=True, type=Path)
    parser.add_argument('--allow-fallback', action='store_true')
    parser.add_argument('--marker-socket', type=Path)
    parser.add_argument('--generation')
    args = parser.parse_args()
    try:
        status = prepare(args.source, args.runtime, args.domain, args.nginx_bin,
                         allow_fallback=args.allow_fallback, marker_socket=args.marker_socket,
                         generation=args.generation)
    except (OSError, ValueError, RuntimeError, UnicodeError):
        print('error: runtime preparation failed', file=sys.stderr)
        return 1
    print(status)
    return 0


if __name__ == '__main__':
    sys.exit(main())
