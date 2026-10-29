"""Verify three locks received from systemd FDSTORE without changing them.

This is a checking primitive, not a supervisor, job barrier, boot recovery,
or permission to deploy. The caller must supply trusted, isolated absolute
lock paths and expected FDNAMEs, and must keep the environment, descriptors,
paths, and locks stable while this check and subsequent work run. Receipt does
not prove the original acquisition order or prevent a later unlock/replacement.
"""

import os
from pathlib import Path
import re
import stat
from collections.abc import Mapping

from .mtproxyl_controller import _read_bounded
from .recovery import _secure_directory, _secure_file


class FDStoreGuardError(RuntimeError):
    """The inherited lock set cannot be verified safely."""


_ROLES = ("operation", "health", "front")


def _fstat(fd):
    return os.fstat(fd)


def _roles(mapping, what):
    if not isinstance(mapping, Mapping) or set(mapping) != set(_ROLES):
        raise FDStoreGuardError("expected exactly the three %s roles" % what)
    return {role: mapping[role] for role in _ROLES}


def _paths(paths):
    result = {}
    for role, value in _roles(paths, "path").items():
        value = os.fspath(value)
        if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
                or value == "/" or "\0" in value or os.path.normpath(value) != value):
            raise FDStoreGuardError("lock paths must be normalized absolute paths")
        result[role] = Path(value)
    return result


def _names(names):
    result = _roles(names, "name")
    if (any(not isinstance(value, str) or not value or ":" in value or "\0" in value
            for value in result.values()) or len(set(result.values())) != len(_ROLES)):
        raise FDStoreGuardError("FDSTORE names must be nonempty and distinct")
    return result


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_ctime_ns)


def _file_snapshot(fd, path, role):
    parent = _secure_directory(path.parent)
    descriptor = _fstat(fd)
    named = path.lstat()
    _secure_file(descriptor)
    _secure_file(named)
    if role == "front" and (stat.S_IMODE(descriptor.st_mode) != 0o600
                            or stat.S_IMODE(named.st_mode) != 0o600):
        raise FDStoreGuardError("front lock mode must be 0600")
    identity = _file_identity(descriptor)
    if _file_identity(named) != identity:
        raise FDStoreGuardError("lock descriptor and path differ")
    return parent, identity


def _lock_record(fields):
    """Return owner/device/inode for an exact whole-file exclusive flock."""
    if (len(fields) != 8 or not re.fullmatch(r"[0-9]+:", fields[0])
            or fields[1:4] != ["FLOCK", "ADVISORY", "WRITE"]
            or not re.fullmatch(r"[0-9]+", fields[4]) or fields[6:] != ["0", "EOF"]):
        return None
    device = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)", fields[5])
    if device is None:
        return None
    return (int(fields[4]), int(device[1], 16), int(device[2], 16), int(device[3]))


def _descriptor_record(fd, identity):
    data = _read_bounded(Path("/proc/self/fdinfo") / str(fd))
    if not isinstance(data, bytes):
        raise FDStoreGuardError("unreadable descriptor lock evidence")
    lines = [line.split()[1:] for line in data.decode("ascii").splitlines()
             if line.split() and line.split()[0] == "lock:"]
    if len(lines) != 1:
        raise FDStoreGuardError("descriptor must have exactly one lock record")
    record = _lock_record(lines[0])
    device, inode = identity[:2]
    if record is None or record[1:] != (os.major(device), os.minor(device), inode):
        raise FDStoreGuardError("descriptor does not hold the expected flock")
    return record


def _verify_lock_set(paths, descriptors):
    """Internal verifier; descriptor and proc stubs are useful to test fixtures."""
    paths = _paths(paths)
    descriptors = _roles(descriptors, "descriptor")
    values = list(descriptors.values())
    if (any(type(fd) is not int or fd < 0 for fd in values)
            or len(set(values)) != len(_ROLES)):
        raise FDStoreGuardError("descriptors must be distinct open file descriptors")

    snapshots = {role: _file_snapshot(descriptors[role], paths[role], role) for role in _ROLES}
    if len({snapshot[1][:2] for snapshot in snapshots.values()}) != len(_ROLES):
        raise FDStoreGuardError("lock inodes must be distinct")
    records = {role: _descriptor_record(descriptors[role], snapshots[role][1]) for role in _ROLES}
    data = _read_bounded(Path("/proc/locks"), 1048576)
    if not isinstance(data, bytes):
        raise FDStoreGuardError("unreadable global lock evidence")
    global_records = [_lock_record(line.split()) for line in data.decode("ascii").splitlines()]
    for record in records.values():
        if global_records.count(record) != 1:
            raise FDStoreGuardError("descriptor flock is absent or ambiguous in /proc/locks")
    for role in _ROLES:
        if _file_snapshot(descriptors[role], paths[role], role) != snapshots[role]:
            raise FDStoreGuardError("lock identity changed during verification")
    return descriptors


def receive_inherited_locks(paths, names):
    """Return role-to-fd mapping after fail-closed verification of FDSTORE receipt.

    The calling supervisor must trust systemd's LISTEN_* environment and pass
    the prevalidated paths and expected names. FD names may arrive in any order.
    No inherited descriptor is closed, locked, unlocked, or otherwise modified.
    """
    try:
        paths = _paths(paths)
        names = _names(names)
        if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "3":
            raise FDStoreGuardError("expected exactly three descriptors for this process")
        received = os.environ.get("LISTEN_FDNAMES", "").split(":")
        if len(received) != len(_ROLES) or len(set(received)) != len(_ROLES) or set(received) != set(names.values()):
            raise FDStoreGuardError("FDSTORE names are missing, extra, or duplicated")
        descriptors = {role: 3 + received.index(names[role]) for role in _ROLES}
        return _verify_lock_set(paths, descriptors)
    except FDStoreGuardError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise FDStoreGuardError("inherited locks cannot be verified") from exc
