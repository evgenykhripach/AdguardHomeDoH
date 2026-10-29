"""Durable recovery journal primitive; not connected to runtime orchestration.

Callers must provide real, held locks in operation -> health order, a systemd
writer/cgroup barrier, and a complete manager-manifest validator. Callbacks are
trusted orchestration, not a substitute for a systemd supervisor or start gate.
The journal directory and snapshot root must already exist and be durable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Callable, Mapping


class RecoveryError(RuntimeError):
    """Recovery is unsafe or the journal is invalid."""


def _confirmed(check: Callable[..., bool], *args: object) -> None:
    if check(*args) is not True:
        raise RecoveryError("orchestration precondition was not confirmed")


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple:
    # Directory timestamps change when legitimate entries are created.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _secure_directory(path: Path) -> tuple:
    """Reject symlink components and writable directories except sticky ancestors."""
    if not path.is_absolute() or ".." in path.parts:
        raise RecoveryError("directory path must be absolute without traversal")
    current = Path(path.anchor)
    result = []
    for part in (None, *path.parts[1:]):
        if part is not None:
            current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            raise RecoveryError("untrusted or non-directory path component")
        if info.st_mode & 0o022 and (current == path or not info.st_mode & stat.S_ISVTX):
            raise RecoveryError("writable directory is not trusted")
        result.append((str(current), _directory_identity(info)))
    return tuple(result)


def _secure_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022):
        raise RecoveryError("unsafe regular file ownership, mode, or link count")


def _sync_directory(path: Path) -> None:
    before = _secure_directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if _directory_identity(os.fstat(fd)) != before[-1][1]:
            raise RecoveryError("directory changed before fsync")
        os.fsync(fd)
    finally:
        os.close(fd)
    if _secure_directory(path) != before:
        raise RecoveryError("directory changed during fsync")


def _read_regular(path: Path) -> tuple[bytes, tuple]:
    before = path.lstat()
    _secure_file(before)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise RecoveryError("file changed before reading")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            contents = stream.read()
        if _identity(os.fstat(fd)) != _identity(before) or _identity(path.lstat()) != _identity(before):
            raise RecoveryError("file changed while reading")
        return contents, _identity(before)
    finally:
        os.close(fd)


def _sync_regular(path: Path) -> None:
    before = path.lstat()
    _secure_file(before)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise RecoveryError("file changed before fsync")
        os.fsync(fd)
        if _identity(os.fstat(fd)) != _identity(before) or _identity(path.lstat()) != _identity(before):
            raise RecoveryError("file changed during fsync")
    finally:
        os.close(fd)


class Journal:
    """One operation journal. All callbacks must remain true until return.

    ``validate_snapshot`` must wrap the manager's version-aware
    ``_validated_backup_manifest`` and additionally require the complete
    current set of managed paths. Its legacy compatibility exceptions alone
    are insufficient for a newly created recovery snapshot.
    ``restore`` must be idempotent, check for conflicting target changes, and
    durably restore only explicitly allowed project-owned files. It must never
    restore generic nginx configuration or start services. The orchestrator
    retains its locks and cgroup/job barrier throughout every call. A job
    barrier must prevent new writer jobs for the duration of recovery, not
    merely report that no job was queued at one instant. Callbacks must check
    the complete writer incarnation against PID1 and procfs, not just a unit
    name or a reused cgroup path. They must also exclude other active writers.
    These checks are external; this module does not implement systemd control.
    """

    def __init__(self, directory: Path, snapshot_root: Path):
        self.directory = Path(directory)
        self.snapshot_root = Path(snapshot_root)
        self._directories = (_secure_directory(self.directory), _secure_directory(self.snapshot_root))
        self.path = self.directory / "intent.json"
        self._intent_identity = None

    def _check_roots(self) -> None:
        if (_secure_directory(self.directory), _secure_directory(self.snapshot_root)) != self._directories:
            raise RecoveryError("journal or snapshot root changed")

    def _load(self) -> dict:
        self._check_roots()
        try:
            raw, identity = _read_regular(self.path)
            data = json.loads(raw)
        except (OSError, ValueError, TypeError) as exc:
            raise RecoveryError("missing or invalid intent") from exc
        if not isinstance(data, dict) or set(data) != {
            "version", "phase", "operation", "writer", "runtime_before", "snapshot"
        } or type(data["version"]) is not int or data["version"] != 2 or data["phase"] not in {
            "PREPARED", "SNAPSHOT_READY", "RESTORING", "RESTORED", "COMMITTED"
        }:
            raise RecoveryError("unknown intent format or phase")
        writer = data["writer"]
        if (not isinstance(data["operation"], str) or not data["operation"]
                or not isinstance(data["runtime_before"], dict)
                or not self._valid_writer(writer)):
            raise RecoveryError("invalid intent fields")
        snapshot = data["snapshot"]
        if snapshot is not None and (
            not isinstance(snapshot, dict) or set(snapshot) != {"path", "manifest_sha256"}
            or not isinstance(snapshot["path"], str)
            or not isinstance(snapshot["manifest_sha256"], str)
            or len(snapshot["manifest_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in snapshot["manifest_sha256"])
        ):
            raise RecoveryError("invalid snapshot reference")
        if (data["phase"] == "PREPARED" and snapshot is not None
                or data["phase"] in {"SNAPSHOT_READY", "COMMITTED"} and snapshot is None):
            raise RecoveryError("inconsistent intent")
        self._intent_identity = identity
        return data

    @staticmethod
    def _valid_writer(writer: object) -> bool:
        if not isinstance(writer, dict) or set(writer) != {
            "boot_id", "unit", "cgroup", "invocation_id", "main_pid", "proc_starttime"
        }:
            return False
        boot = writer["boot_id"]
        unit = writer["unit"]
        group = writer["cgroup"]
        invocation = writer["invocation_id"]
        if (not isinstance(boot, str) or not re.fullmatch(
                r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot)
                or not isinstance(unit, str) or not re.fullmatch(
                    r"adguardhome-doh-writer-[0-9a-f]{32}\.service", unit)
                or not isinstance(group, str) or not group.startswith("/")
                or any(part in {"", ".", ".."} for part in group[1:].split("/"))
                or group.split("/")[-1] != unit
                or not isinstance(invocation, str) or not re.fullmatch(r"[0-9a-f]{32}", invocation)
                or invocation == "0" * 32):
            return False
        return (type(writer["main_pid"]) is int and writer["main_pid"] > 0
                and type(writer["proc_starttime"]) is int and writer["proc_starttime"] > 0)

    def _write(self, data: dict) -> None:
        self._check_roots()
        encoded = (json.dumps(data, sort_keys=True, separators=(",", ":"),
                              allow_nan=False) + "\n").encode()
        fd, temporary = tempfile.mkstemp(prefix=".intent-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_roots()
            if self._intent_identity is None:
                if os.path.lexists(self.path):
                    raise RecoveryError("intent appeared before publishing")
            elif _read_regular(self.path)[1] != self._intent_identity:
                raise RecoveryError("intent changed before publishing")
            os.replace(temporary, self.path)
            _sync_directory(self.directory)
            self._intent_identity = _read_regular(self.path)[1]
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _snapshot_path(self, path: str | Path) -> Path:
        value = Path(path)
        self._check_roots()
        _secure_directory(value)
        if value == self.snapshot_root or self.snapshot_root not in value.parents:
            raise RecoveryError("snapshot is outside the snapshot root")
        return value

    def _validate_snapshot(self, path: Path, validator: Callable, expected: str | None = None) -> str:
        manifest_path = path / "manifest.json"
        self._check_roots()
        directories = _secure_directory(path)
        raw, manifest_identity = _read_regular(manifest_path)
        digest = hashlib.sha256(raw).hexdigest()
        if expected is not None and digest != expected:
            raise RecoveryError("snapshot manifest changed")
        try:
            manifest = json.loads(raw)
            # Version 3+ includes owner-aware digests. Legacy manifests are not
            # sufficient for a new automatic recovery snapshot.
            if (not isinstance(manifest, dict) or type(manifest.get("version")) is not int
                    or manifest["version"] < 3 or not isinstance(manifest.get("files"), list)):
                raise RecoveryError("unsupported snapshot manifest")
            entries = list(validator(path))
            declared = [(item["path"], item["backup"], item["present"]) for item in manifest["files"]]
            if not declared or entries != declared:
                raise RecoveryError("snapshot validator did not confirm every entry")
            identities = {}
            for _, name, present in declared:
                if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
                    raise RecoveryError("invalid snapshot file name")
                if type(present) is not bool:
                    raise RecoveryError("invalid snapshot entry")
                if present:
                    backup = path / name
                    before = backup.lstat()
                    if backup.is_symlink():
                        if before.st_uid not in {0, os.geteuid()} or before.st_nlink != 1:
                            raise RecoveryError("unsafe snapshot symlink")
                        identities[name] = _identity(before)
                        continue  # The link itself is persisted with its directory.
                    _secure_file(before)
                    identities[name] = _identity(before)
                    _sync_regular(backup)
            _sync_regular(manifest_path)
            _sync_directory(path)
            # Persist the snapshot directory's entry before publishing it.
            current = path.parent
            while True:
                _sync_directory(current)
                if current == self.snapshot_root:
                    break
                current = current.parent
            second_raw, second_identity = _read_regular(manifest_path)
            if second_identity != manifest_identity or hashlib.sha256(second_raw).hexdigest() != digest:
                raise RecoveryError("snapshot manifest changed during validation")
            if list(validator(path)) != entries:
                raise RecoveryError("snapshot validator result changed")
            for name, identity in identities.items():
                if _identity((path / name).lstat()) != identity:
                    raise RecoveryError("snapshot file changed during validation")
            if _secure_directory(path) != directories:
                raise RecoveryError("snapshot directory changed during validation")
            self._check_roots()
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryError("invalid snapshot manifest") from exc
        return digest

    def begin(self, operation: str, writer: Mapping, runtime_before: Mapping,
              *, locks_held: Callable[[], bool], writer_confirmed: Callable[[Mapping], bool],
              job_barrier_held: Callable[[], bool], markers_clear: Callable[[], bool]) -> None:
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        self._check_roots()
        _confirmed(writer_confirmed, writer)
        _confirmed(markers_clear)
        if os.path.lexists(self.path):
            raise RecoveryError("an intent already exists")
        self._intent_identity = None
        data = {"version": 2, "phase": "PREPARED", "operation": operation,
                "writer": dict(writer), "runtime_before": dict(runtime_before), "snapshot": None}
        if (not isinstance(operation, str) or not operation
                or not self._valid_writer(data["writer"])):
            raise RecoveryError("invalid operation or writer identity")
        self._write(data)

    def seal(self, snapshot: Path, *, locks_held: Callable[[], bool],
             writer_confirmed: Callable[[Mapping], bool], stopped: Callable[[], bool],
             job_barrier_held: Callable[[], bool], markers_clear: Callable[[], bool],
             validate_snapshot: Callable) -> None:
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        data = self._load()
        _confirmed(writer_confirmed, data["writer"])
        _confirmed(stopped)
        _confirmed(markers_clear)
        if data["phase"] != "PREPARED":
            raise RecoveryError("intent is not prepared")
        path = self._snapshot_path(snapshot)
        digest = self._validate_snapshot(path, validate_snapshot)
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        _confirmed(writer_confirmed, data["writer"])
        _confirmed(stopped)
        _confirmed(markers_clear)
        data["phase"] = "SNAPSHOT_READY"
        data["snapshot"] = {"path": str(path), "manifest_sha256": digest}
        self._write(data)

    def commit(self, *, locks_held: Callable[[], bool], writer_confirmed: Callable[[Mapping], bool],
               job_barrier_held: Callable[[], bool], markers_clear: Callable[[], bool], validated: Callable[[], bool],
               validate_snapshot: Callable) -> None:
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        data = self._load()
        _confirmed(writer_confirmed, data["writer"])
        _confirmed(markers_clear)
        _confirmed(validated)
        if data["phase"] != "SNAPSHOT_READY":
            raise RecoveryError("snapshot is not ready")
        snapshot = data["snapshot"]
        self._validate_snapshot(self._snapshot_path(snapshot["path"]), validate_snapshot,
                                snapshot["manifest_sha256"])
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        _confirmed(writer_confirmed, data["writer"])
        _confirmed(markers_clear)
        _confirmed(validated)
        data["phase"] = "COMMITTED"
        self._write(data)

    def recover(self, *, locks_held: Callable[[], bool], writer_gone: Callable[[Mapping], bool],
                stopped: Callable[[], bool], job_barrier_held: Callable[[], bool],
                markers_clear: Callable[[], bool], validate_snapshot: Callable,
                restore: Callable[[Path, Mapping], None]) -> str:
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        data = self._load()
        _confirmed(writer_gone, data["writer"])
        _confirmed(markers_clear)
        if data["phase"] in {"RESTORED", "COMMITTED"}:
            return data["phase"]
        _confirmed(stopped)
        snapshot = data["snapshot"]
        path = None
        if snapshot is not None:
            path = self._snapshot_path(snapshot["path"])
            self._validate_snapshot(path, validate_snapshot, snapshot["manifest_sha256"])
        if data["phase"] != "RESTORING":
            data["phase"] = "RESTORING"
            self._write(data)
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        _confirmed(writer_gone, data["writer"])
        _confirmed(stopped)
        if path is not None:
            restore(path, data)
        data["phase"] = "RESTORED"
        self._write(data)
        return "RESTORED"

    def retire(self, *, locks_held: Callable[[], bool], writer_gone: Callable[[Mapping], bool],
               job_barrier_held: Callable[[], bool], markers_clear: Callable[[], bool]) -> None:
        """Remove a terminal intent only after external runtime handling."""
        _confirmed(locks_held)
        _confirmed(job_barrier_held)
        data = self._load()
        _confirmed(writer_gone, data["writer"])
        _confirmed(markers_clear)
        if data["phase"] not in {"RESTORED", "COMMITTED"}:
            raise RecoveryError("intent is not terminal")
        self._check_roots()
        if _read_regular(self.path)[1] != self._intent_identity:
            raise RecoveryError("intent changed before retiring")
        os.unlink(self.path)
        _sync_directory(self.directory)
        self._intent_identity = None
