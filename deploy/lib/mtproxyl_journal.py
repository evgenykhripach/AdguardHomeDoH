"""Private durable journal for a staged MTProxyL reload.

This is a library primitive, not a watchdog or systemd integration. Its trusted
callbacks must hold the common front lock and exclude all other writers for the
whole call. A non-cooperating privileged writer can race a pathname check and
rename; device/inode/hash alone do not eliminate ABA after inode reuse.
"""

import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path

try:
    from . import mtproxyl_controller as controller
except ImportError:
    import mtproxyl_controller as controller

runtime = controller.runtime


class JournalError(RuntimeError):
    """The journal, its dependencies or the runtime cannot be trusted."""


def _require_root():
    if os.geteuid() != 0:
        raise JournalError('root is required')


def _confirm(check, *args):
    if check(*args) is not True:
        raise JournalError('external safety confirmation failed')


def _stat_id(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]


def _metadata(exact, *, ctime):
    try:
        identity, mtime, change = exact
        dev, ino, mode, uid, gid, links, digest, data = identity
        if (any(type(value) is not int or value < 0 for value in (dev, ino, mode, uid, gid, links, mtime, change))
                or ino == 0 or links != 1 or not stat.S_ISREG(mode) or mode & 0o022
                or uid not in {0, os.geteuid()}
                or not isinstance(data, bytes) or not isinstance(digest, bytes) or len(digest) != 32
                or hashlib.sha256(data).digest() != digest):
            raise ValueError('bad digest')
        result = {'identity': [dev, ino, mode, uid, gid, links],
                  'sha256': digest.hex(), 'mtime_ns': mtime}
        if ctime:
            result['ctime_ns'] = change
        return result
    except (TypeError, ValueError) as exc:
        raise JournalError('invalid file identity') from exc


def _snapshot(parent, name, *, ctime):
    return _metadata(runtime._exact_identity(runtime._snapshot(parent, name)), ctime=ctime)


def _record_data(record):
    if not isinstance(record, controller.ReloadRecord):
        raise JournalError('invalid reload record')
    if (not re.fullmatch(r'[0-9a-f]{32}', record.transaction_id)
            or not re.fullmatch(r'[0-9a-f]{32}', record.previous_generation)
            or not re.fullmatch(r'[0-9a-f]{32}', record.next_generation)
            or record.previous_generation == record.next_generation
            or not re.fullmatch(r'[0-9a-f]{64}', record.candidate_sha256)):
        raise JournalError('invalid transaction or generation')
    source = Path(record.source_path)
    target = Path(record.runtime_path)
    candidate = Path(record.candidate_path)
    if (not source.is_absolute() or not target.is_absolute() or not candidate.is_absolute()
            or source == target or source == candidate
            or candidate.parent != target.parent
            or not re.fullmatch(re.escape('.' + target.name + '.doh-') + r'[0-9a-f]{32}', candidate.name)):
        raise JournalError('invalid transaction paths')
    source_meta = _metadata(record.source_exact, ctime=True)
    previous_meta = _metadata(record.previous_exact, ctime=True)
    candidate_meta = _metadata(record.candidate_exact, ctime=False)
    if (record.source_exact[0] != record.source_identity
            or record.previous_exact[0] != record.previous_identity
            or record.candidate_exact[0] != record.candidate_identity
            or candidate_meta['sha256'] != record.candidate_sha256
            or stat.S_IMODE(candidate_meta['identity'][2]) != 0o600
            or candidate_meta['identity'][3] != os.geteuid()
            or candidate_meta['identity'][5] != 1
            or source_meta['identity'][:2] == previous_meta['identity'][:2]):
        raise JournalError('inconsistent record identities')
    try:
        for identity, generation in ((record.previous_identity, record.previous_generation),
                                     (record.candidate_identity, record.next_generation)):
            text = identity[-1].decode('utf-8')
            fragment = controller._marker_fragment(record.marker_socket, generation)
            if (text.count(runtime._GENERATION_BEGIN) != 1 or text.count(runtime._GENERATION_END) != 1
                    or text.count(fragment) != 1):
                raise ValueError('generation marker unavailable')
    except (UnicodeError, ValueError) as exc:
        raise JournalError('unmarked or invalid generation is not supported') from exc
    # argv can contain secrets; record only its hash, not the raw arguments.
    master = record.master
    if (not isinstance(master, controller.ProcessIdentity)
            or type(master.pid) is not int or master.pid <= 0
            or type(master.start_ticks) is not int or master.start_ticks <= 0
            or type(master.ppid) is not int or master.ppid < 0
            or type(master.exe_device) is not int or master.exe_device < 0
            or type(master.exe_inode) is not int or master.exe_inode <= 0
            or type(master.owner_uid) is not int or master.owner_uid != 0 or not isinstance(master.boot_id, str)
            or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', master.boot_id)
            or not isinstance(master.cgroup, str) or not master.cgroup.startswith('/')
            or os.path.normpath(master.cgroup) != master.cgroup
            or any(char in master.cgroup for char in ('\x00', '\n', '\r'))
            or not isinstance(master.argv, tuple) or not all(isinstance(arg, str) for arg in master.argv)):
        raise JournalError('invalid master identity')
    positions = [index for index, value in enumerate(master.argv) if value == '-c']
    if (len(positions) != 1 or positions[0] + 1 >= len(master.argv)
            or master.argv[positions[0] + 1] != str(target)):
        raise JournalError('master runtime path mismatch')
    master_data = {'pid': master.pid, 'ppid': master.ppid, 'start_ticks': master.start_ticks,
                   'boot_id': master.boot_id, 'cgroup': master.cgroup,
                   'exe_device': master.exe_device, 'exe_inode': master.exe_inode,
                   'owner_uid': master.owner_uid,
                   'argv_sha256': hashlib.sha256(json.dumps(master.argv).encode()).hexdigest()}
    return {'transaction_id': record.transaction_id, 'source_path': str(source),
            'runtime_path': str(target), 'candidate_path': str(candidate),
            'marker_socket': record.marker_socket, 'source': source_meta,
            'previous': previous_meta, 'candidate': candidate_meta,
            'candidate_staged_ctime_ns': record.candidate_exact[2],
            'previous_generation': record.previous_generation, 'next_generation': record.next_generation,
            'master': master_data}


class Journal:
    """One private journal; callbacks attest locks, writer barrier and master.

    No callback can prove those external facts by its return value alone. The
    caller must keep all barriers held until each method returns. ``business``
    must check the actual worker and business path, not merely HUP delivery.
    """

    def __init__(self, directory, *, lock_fd, lock_path, barrier, master):
        _require_root()
        if not callable(barrier) or not callable(master):
            raise ValueError('barrier and master callbacks are required')
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise JournalError('absolute journal path required')
        self.lock_fd, self.lock_path = lock_fd, lock_path
        self.barrier, self.master = barrier, master
        fd, _ = runtime._secure_parent(self.directory / 'intent.json')
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise JournalError('journal directory must be private and owned by root')
            self._directory_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)

    def _guard(self, record):
        _require_root()
        controller._assert_lock_held(self.lock_fd, self.lock_path)
        _confirm(self.barrier)
        _confirm(self.master, record)
        return self._open_directory()

    def _open_directory(self):
        fd, _ = runtime._secure_parent(self.directory / 'intent.json')
        info = os.fstat(fd)
        if ((info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(fd)
            raise JournalError('journal directory changed')
        return fd

    @staticmethod
    def _read_file(parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise JournalError('unsafe journal file')
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_stat_id(info) != _stat_id(after) or _stat_id(info) != _stat_id(named)
                    or info.st_mtime_ns != after.st_mtime_ns or info.st_ctime_ns != after.st_ctime_ns):
                raise JournalError('journal file changed')
            return b''.join(chunks)
        finally:
            os.close(fd)

    @staticmethod
    def _create(parent, name, data):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)

    def _load(self, parent):
        raw = self._read_file(parent, 'intent.json')
        try:
            data = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise JournalError('invalid journal') from exc
        if (not isinstance(data, dict) or set(data) != {'version', 'phase', 'record', 'backup', 'candidate_backup', 'restore'}
                or type(data['version']) is not int or data['version'] != 2 or data['phase'] not in {
                    'PREPARED', 'RESTORE_READY', 'RESTORED_FILE', 'COMMITTED', 'ROLLED_BACK',
                    'RETIRED_COMMITTED', 'RETIRED_ROLLED_BACK'}):
            raise JournalError('unknown journal or phase')
        return data, raw

    def _write(self, parent, data, previous=None):
        raw = (json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        temp = '.intent-' + secrets.token_hex(16)
        self._create(parent, temp, raw)
        try:
            if previous is None:
                try:
                    os.stat('intent.json', dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise JournalError('journal already exists')
            elif self._read_file(parent, 'intent.json') != previous:
                raise JournalError('journal changed')
            os.replace(temp, 'intent.json', src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass

    def _archive_directory(self, parent, transaction_id, *, create=False):
        name = 'archive-' + transaction_id
        if create:
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise JournalError('unsafe archive directory')
        return fd

    def _archive_put(self, parent, name, data):
        try:
            self._create(parent, name, data)
        except FileExistsError:
            if self._read_file(parent, name) != data:
                raise JournalError('archive entry changed')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)

    def _verified_archive(self, parent, transaction_id):
        archive = self._archive_directory(parent, transaction_id)
        try:
            if set(os.listdir(archive)) != {'intent.json', 'backup', 'candidate', 'complete.json'}:
                raise JournalError('archive incomplete or contains unknown files')
            intent = self._read_file(archive, 'intent.json')
            backup = self._read_file(archive, 'backup')
            candidate = self._read_file(archive, 'candidate')
            receipt = json.loads(self._read_file(archive, 'complete.json'))
            data = json.loads(intent)
            expected = {'version': 2, 'transaction_id': transaction_id,
                        'intent_sha256': hashlib.sha256(intent).hexdigest(),
                        'backup_sha256': hashlib.sha256(backup).hexdigest(),
                        'candidate_sha256': hashlib.sha256(candidate).hexdigest()}
            if (receipt != expected or not isinstance(data, dict)
                    or type(data.get('version')) is not int or data['version'] != 2
                    or data.get('phase') not in {'RETIRED_COMMITTED', 'RETIRED_ROLLED_BACK'}
                    or not isinstance(data.get('record'), dict)
                    or data['record'].get('transaction_id') != transaction_id
                    or not isinstance(data.get('backup'), dict)
                    or data['backup'].get('name') != transaction_id + '.backup'
                    or data['backup'].get('sha256') != expected['backup_sha256']
                    or not isinstance(data.get('candidate_backup'), dict)
                    or data['candidate_backup'].get('name') != transaction_id + '.candidate'
                    or data['candidate_backup'].get('sha256') != expected['candidate_sha256']):
                raise JournalError('archive receipt does not match data')
            return data, intent, backup, candidate
        finally:
            os.close(archive)

    def _check_archives(self, parent):
        """Do not start while unknown or unfinished journal files exist."""
        entries = set(os.listdir(parent))
        archives = {name[8:] for name in entries if re.fullmatch(r'archive-[0-9a-f]{32}', name)}
        allowed = {'archive-' + ident for ident in archives}
        for ident in archives:
            _, _, archived_backup, archived_candidate = self._verified_archive(parent, ident)
            for suffix, saved in (('.backup', archived_backup), ('.candidate', archived_candidate)):
                backup_name = ident + suffix
                if backup_name in entries:
                    if self._read_file(parent, backup_name) != saved:
                        raise JournalError('retained backup differs from archive')
                    allowed.add(backup_name)
        if entries - allowed:
            raise JournalError('unknown or unfinished journal files')

    def _archive_terminal(self, parent, data, raw, backup, candidate):
        ident = data['record']['transaction_id']
        archive = self._archive_directory(parent, ident, create=True)
        try:
            if set(os.listdir(archive)) - {'intent.json', 'backup', 'candidate', 'complete.json'}:
                raise JournalError('unknown archive entry')
            self._archive_put(archive, 'intent.json', raw)
            self._archive_put(archive, 'backup', backup)
            self._archive_put(archive, 'candidate', candidate)
            receipt = {'version': 2, 'transaction_id': ident,
                       'intent_sha256': hashlib.sha256(raw).hexdigest(),
                       'backup_sha256': hashlib.sha256(backup).hexdigest(),
                       'candidate_sha256': hashlib.sha256(candidate).hexdigest()}
            encoded = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
            self._archive_put(archive, 'complete.json', encoded)
            os.fsync(archive)
            os.fsync(parent)
        finally:
            os.close(archive)
        saved, saved_raw, saved_backup, saved_candidate = self._verified_archive(parent, ident)
        if saved != data or saved_raw != raw or saved_backup != backup or saved_candidate != candidate:
            raise JournalError('archived transaction changed')
        if self._read_file(parent, 'intent.json') != raw:
            raise JournalError('terminal intent changed during archival')
        os.unlink('intent.json', dir_fd=parent)
        os.fsync(parent)

    def _check_record(self, record, data):
        if not isinstance(data['record'], dict):
            raise JournalError('invalid record')
        details = dict(data['record'])
        source_parent = details.pop('source_parent', None)
        runtime_parent = details.pop('runtime_parent', None)
        if (details != _record_data(record) or not isinstance(source_parent, list)
                or len(source_parent) != 2 or not isinstance(runtime_parent, list)
                or len(runtime_parent) != 2):
            raise JournalError('record does not match journal')
        backup = data['backup']
        if backup != {'name': record.transaction_id + '.backup', 'sha256': data['record']['previous']['sha256']}:
            raise JournalError('invalid backup reference')
        if data['candidate_backup'] != {'name': record.transaction_id + '.candidate',
                                        'sha256': data['record']['candidate']['sha256']}:
            raise JournalError('invalid candidate backup reference')
        restore = data['restore']
        if data['phase'] == 'PREPARED' and restore is not None:
            raise JournalError('unexpected restore stage')
        if data['phase'] == 'RESTORE_READY' and restore is None:
            raise JournalError('missing restore stage')
        if restore is not None:
            previous = data['record']['previous']
            if (not isinstance(restore, dict) or set(restore) != {'name', 'identity'}
                    or not isinstance(restore['identity'], dict)
                    or set(restore['identity']) != {'identity', 'sha256', 'mtime_ns'}
                    or not isinstance(restore['identity']['identity'], list)
                    or len(restore['identity']['identity']) != 6
                    or restore['identity']['sha256'] != previous['sha256']
                    or restore['identity']['identity'][2:5] != previous['identity'][2:5]
                    or restore['identity']['identity'][5] != 1):
                raise JournalError('restore stage does not match backup')

    def _read_backups(self, parent, data):
        result = []
        for name in ('backup', 'candidate_backup'):
            entry = data[name]
            if not isinstance(entry, dict) or set(entry) != {'name', 'sha256'}:
                raise JournalError('invalid backup metadata')
            content = self._read_file(parent, entry['name'])
            if hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise JournalError('backup changed')
            result.append(content)
        return tuple(result)

    def _parents(self, record):
        src, src_name = runtime._secure_parent(record.source_path)
        try:
            dst, dst_name = runtime._secure_parent(record.runtime_path)
        except BaseException:
            os.close(src)
            raise
        return src, src_name, dst, dst_name

    def _check_source(self, src, name, data):
        if _snapshot(src, name, ctime=True) != data['record']['source']:
            raise JournalError('source changed')

    @staticmethod
    def _sync_candidate(parent, name, expected):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (_stat_id(before) != expected['identity']
                    or before.st_mtime_ns != expected['mtime_ns']):
                raise JournalError('candidate identity changed before fsync')
            os.fsync(fd)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_stat_id(after) != _stat_id(before) or _stat_id(named) != _stat_id(before)
                    or after.st_mtime_ns != before.st_mtime_ns
                    or after.st_ctime_ns != before.st_ctime_ns):
                raise JournalError('candidate changed during fsync')
        finally:
            os.close(fd)
        os.fsync(parent)

    @staticmethod
    def _check_parents(src, dst, data, record):
        source_info, runtime_info = os.fstat(src), os.fstat(dst)
        if ([source_info.st_dev, source_info.st_ino] != data['record']['source_parent']
                or [runtime_info.st_dev, runtime_info.st_ino] != data['record']['runtime_parent']):
            raise JournalError('transaction directory changed')
        runtime._check_parent(record.source_path, source_info)
        runtime._check_parent(record.runtime_path, runtime_info)

    def record_before_publish(self, record):
        parent = self._guard(record)
        src = dst = None
        try:
            self._check_archives(parent)
            details = _record_data(record)
            src, src_name, dst, dst_name = self._parents(record)
            source_info, runtime_info = os.fstat(src), os.fstat(dst)
            details['source_parent'] = [source_info.st_dev, source_info.st_ino]
            details['runtime_parent'] = [runtime_info.st_dev, runtime_info.st_ino]
            runtime._check_parent(record.source_path, source_info)
            runtime._check_parent(record.runtime_path, runtime_info)
            if (_snapshot(src, src_name, ctime=True) != details['source']
                    or _snapshot(dst, dst_name, ctime=True) != details['previous']
                    or _snapshot(dst, Path(record.candidate_path).name, ctime=False) != details['candidate']
                    or runtime._exact_identity(runtime._snapshot(dst, Path(record.candidate_path).name)) != record.candidate_exact):
                raise JournalError('transaction files changed before journaling')
            self._sync_candidate(dst, Path(record.candidate_path).name, details['candidate'])
            if runtime._exact_identity(runtime._snapshot(dst, Path(record.candidate_path).name)) != record.candidate_exact:
                raise JournalError('candidate changed during journaling')
            previous_bytes = record.previous_identity[-1]
            backup = record.transaction_id + '.backup'
            self._create(parent, backup, previous_bytes)
            if hashlib.sha256(self._read_file(parent, backup)).hexdigest() != details['previous']['sha256']:
                raise JournalError('backup validation failed')
            candidate_backup = record.transaction_id + '.candidate'
            self._create(parent, candidate_backup, record.candidate_identity[-1])
            if hashlib.sha256(self._read_file(parent, candidate_backup)).hexdigest() != details['candidate']['sha256']:
                raise JournalError('candidate backup validation failed')
            data = {'version': 2, 'phase': 'PREPARED', 'record': details,
                    'backup': {'name': backup, 'sha256': details['previous']['sha256']},
                    'candidate_backup': {'name': candidate_backup, 'sha256': details['candidate']['sha256']},
                    'restore': None}
            self._write(parent, data)
            os.fsync(parent)
            # Recheck before returning an authorization to publish.
            controller._assert_lock_held(self.lock_fd, self.lock_path)
            _confirm(self.barrier)
            _confirm(self.master, record)
            self._check_parents(src, dst, data, record)
            if (_snapshot(src, src_name, ctime=True) != details['source']
                    or _snapshot(dst, dst_name, ctime=True) != details['previous']
                    or runtime._exact_identity(runtime._snapshot(dst, Path(record.candidate_path).name)) != record.candidate_exact):
                raise JournalError('transaction files changed after journaling')
            return controller.JournalReceipt(record.transaction_id, True)
        finally:
            if src is not None:
                os.close(src)
            if dst is not None:
                os.close(dst)
            os.close(parent)

    def read_pending(self, record):
        parent = self._guard(record)
        try:
            data, _ = self._load(parent)
            self._check_record(record, data)
            self._read_backups(parent, data)
            return data
        finally:
            os.close(parent)

    def inspect_pending(self):
        """Read pending metadata after a crash, before a master is selected.

        The caller must still hold the real front lock and writer barrier.
        The resulting metadata is not proof that recovery may be performed.
        """
        _require_root()
        controller._assert_lock_held(self.lock_fd, self.lock_path)
        _confirm(self.barrier)
        parent = self._open_directory()
        try:
            data, _ = self._load(parent)
            record, backup, candidate = data['record'], data['backup'], data['candidate_backup']
            if (not isinstance(record, dict) or not isinstance(backup, dict)
                    or not isinstance(candidate, dict)
                    or set(record) != {'transaction_id', 'source_path', 'runtime_path', 'candidate_path',
                                       'marker_socket', 'source', 'previous', 'candidate',
                                       'candidate_staged_ctime_ns',
                                       'previous_generation', 'next_generation', 'master',
                                       'source_parent', 'runtime_parent'}
                    or set(backup) != {'name', 'sha256'}
                    or set(candidate) != {'name', 'sha256'}
                    or not re.fullmatch(r'[0-9a-f]{32}', record.get('transaction_id', ''))
                    or not isinstance(record.get('previous'), dict)
                    or not isinstance(record.get('candidate'), dict)
                    or backup.get('sha256') != record['previous'].get('sha256')
                    or candidate.get('sha256') != record['candidate'].get('sha256')
                    or backup.get('name') != record['transaction_id'] + '.backup'
                    or candidate.get('name') != record['transaction_id'] + '.candidate'
                    or not isinstance(backup.get('sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', backup['sha256'])
                    or not isinstance(candidate.get('sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', candidate['sha256'])
                    or (data['phase'] == 'PREPARED' and data['restore'] is not None)
                    or (data['phase'] == 'RESTORE_READY' and not isinstance(data['restore'], dict))
                    or hashlib.sha256(self._read_file(parent, backup['name'])).hexdigest() != backup['sha256']
                    or hashlib.sha256(self._read_file(parent, candidate['name'])).hexdigest() != candidate['sha256']):
                raise JournalError('pending journal or backup invalid')
            return data
        finally:
            os.close(parent)

    def reconstruct(self, master):
        """Rebuild a record after process loss using checked on-disk bytes.

        The caller supplies a freshly inspected *same* master incarnation;
        ``master`` callback must independently validate it. A reboot, new
        master, invalid private candidate backup or unknown identity fails closed.
        """
        if not isinstance(master, controller.ProcessIdentity):
            raise JournalError('fresh master identity required')
        data = self.inspect_pending()
        details = data['record']
        parent = self._open_directory()
        source_fd = runtime_fd = None
        try:
            fresh, _ = self._load(parent)
            if fresh != data:
                raise JournalError('journal changed during reconstruction')
            old_bytes, candidate_bytes = self._read_backups(parent, data)
            source_fd, source_name = runtime._secure_parent(details['source_path'])
            runtime_fd, runtime_name = runtime._secure_parent(details['runtime_path'])
            source_info, runtime_info = os.fstat(source_fd), os.fstat(runtime_fd)
            if ([source_info.st_dev, source_info.st_ino] != details['source_parent']
                    or [runtime_info.st_dev, runtime_info.st_ino] != details['runtime_parent']):
                raise JournalError('transaction directory changed')
            source_exact = runtime._exact_identity(runtime._snapshot(source_fd, source_name))
            if _metadata(source_exact, ctime=True) != details['source']:
                raise JournalError('source changed')
            candidate_path = Path(details['candidate_path'])
            target_path = Path(details['runtime_path'])
            if candidate_path.parent != target_path.parent:
                raise JournalError('candidate directory changed')
            previous = details['previous']
            if (not isinstance(previous, dict) or set(previous) != {'identity', 'sha256', 'mtime_ns', 'ctime_ns'}
                    or not isinstance(previous['identity'], list) or len(previous['identity']) != 6
                    or previous['sha256'] != hashlib.sha256(old_bytes).hexdigest()
                    or type(details['candidate_staged_ctime_ns']) is not int):
                raise JournalError('previous identity is invalid')
            previous_identity = tuple(previous['identity']) + (bytes.fromhex(previous['sha256']), old_bytes)
            candidate = details['candidate']
            if (not isinstance(candidate, dict) or set(candidate) != {'identity', 'sha256', 'mtime_ns'}
                    or not isinstance(candidate['identity'], list) or len(candidate['identity']) != 6
                    or candidate['sha256'] != hashlib.sha256(candidate_bytes).hexdigest()):
                raise JournalError('candidate identity is invalid')
            candidate_identity = tuple(candidate['identity']) + (bytes.fromhex(candidate['sha256']), candidate_bytes)
            candidate_exact = (candidate_identity, details['candidate']['mtime_ns'],
                               details['candidate_staged_ctime_ns'])
            record = controller.ReloadRecord(
                details['transaction_id'], master, source_exact[0], previous_identity,
                details['previous_generation'], details['next_generation'], details['candidate']['sha256'],
                details['source_path'], details['runtime_path'], details['marker_socket'], source_exact,
                (previous_identity, previous['mtime_ns'], previous['ctime_ns']), candidate_identity,
                candidate_exact, details['candidate_path'])
            self._check_record(record, data)
            try:
                stage = runtime._exact_identity(runtime._snapshot(runtime_fd, candidate_path.name))
                if stage != candidate_exact:
                    raise JournalError('staged candidate changed')
            except FileNotFoundError:
                pass
            current = _snapshot(runtime_fd, runtime_name, ctime=False)
            previous_plain = {key: value for key, value in previous.items() if key != 'ctime_ns'}
            restore = data['restore']
            restored = [restore['identity']] if restore else []
            if data['phase'] == 'PREPARED':
                allowed = [previous_plain, candidate]
            elif data['phase'] == 'RESTORE_READY':
                allowed = [previous_plain, candidate] + restored
            elif data['phase'] in {'RESTORED_FILE', 'ROLLED_BACK', 'RETIRED_ROLLED_BACK'}:
                allowed = [previous_plain] + restored
            else:
                allowed = [candidate]
            if current not in allowed:
                raise JournalError('runtime is not owned by this transaction')
            if current == previous_plain and _snapshot(runtime_fd, runtime_name, ctime=True) != previous:
                raise JournalError('previous runtime metadata changed')
            controller._assert_lock_held(self.lock_fd, self.lock_path)
            _confirm(self.barrier)
            _confirm(self.master, record)
            self._check_parents(source_fd, runtime_fd, data, record)
            self._check_source(source_fd, source_name, data)
            if _snapshot(runtime_fd, runtime_name, ctime=False) != current:
                raise JournalError('runtime changed during reconstruction')
            if self._read_backups(parent, data) != (old_bytes, candidate_bytes):
                raise JournalError('backup changed during reconstruction')
            if self._load(parent)[0] != data:
                raise JournalError('journal changed during reconstruction')
            return record
        except (KeyError, TypeError, ValueError) as exc:
            raise JournalError('invalid recovery metadata') from exc
        finally:
            if source_fd is not None:
                os.close(source_fd)
            if runtime_fd is not None:
                os.close(runtime_fd)
            os.close(parent)

    def restore_previous(self, record):
        parent = self._guard(record)
        src = dst = None
        try:
            data, raw = self._load(parent)
            self._check_record(record, data)
            if data['phase'] not in {'PREPARED', 'RESTORE_READY', 'RESTORED_FILE'}:
                raise JournalError('journal cannot be restored in this phase')
            backup, candidate = self._read_backups(parent, data)
            if backup != record.previous_identity[-1] or candidate != record.candidate_identity[-1]:
                raise JournalError('backup changed')
            src, src_name, dst, dst_name = self._parents(record)
            self._check_parents(src, dst, data, record)
            self._check_source(src, src_name, data)
            observed = _snapshot(dst, dst_name, ctime=False)
            previous = {k: v for k, v in data['record']['previous'].items() if k != 'ctime_ns'}
            candidate = data['record']['candidate']
            restore = data['restore']
            if restore is not None and (not isinstance(restore, dict) or set(restore) != {'name', 'identity'}
                    or not isinstance(restore['name'], str)
                    or not re.fullmatch(re.escape('.' + dst_name + '.restore-') + r'[0-9a-f]{32}', restore['name'])):
                raise JournalError('invalid restore stage')
            allowed = [previous, candidate] + ([restore['identity']] if restore else [])
            if observed not in allowed:
                raise JournalError('runtime is not owned by this transaction')
            if data['phase'] == 'RESTORED_FILE':
                if observed not in [previous] + ([restore['identity']] if restore else []):
                    raise JournalError('restored runtime changed')
                os.fsync(dst)
                return record.previous_generation
            if observed == previous:
                if _snapshot(dst, dst_name, ctime=True) != data['record']['previous']:
                    raise JournalError('previous runtime metadata changed')
                os.fsync(dst)
                data['phase'] = 'RESTORED_FILE'
                self._write(parent, data, raw)
                return record.previous_generation
            if observed == candidate and restore is None:
                stage = '.' + dst_name + '.restore-' + secrets.token_hex(16)
                fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
                try:
                    with os.fdopen(fd, 'wb', closefd=False) as stream:
                        stream.write(backup)
                        stream.flush()
                    previous_info = data['record']['previous']['identity']
                    created = os.fstat(fd)
                    if (created.st_uid, created.st_gid) != (previous_info[3], previous_info[4]):
                        os.fchown(fd, previous_info[3], previous_info[4])
                    os.fchmod(fd, stat.S_IMODE(previous_info[2]))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(dst)
                restore = {'name': stage, 'identity': _snapshot(dst, stage, ctime=False)}
                data['restore'], data['phase'] = restore, 'RESTORE_READY'
                self._write(parent, data, raw)
                data, raw = self._load(parent)
                self._check_record(record, data)
            if observed != restore['identity']:
                controller._assert_lock_held(self.lock_fd, self.lock_path)
                _confirm(self.barrier)
                _confirm(self.master, record)
                self._check_parents(src, dst, data, record)
                self._check_source(src, src_name, data)
                if (_snapshot(dst, dst_name, ctime=False) != candidate
                        or _snapshot(dst, restore['name'], ctime=False) != restore['identity']):
                    raise JournalError('runtime or restore stage changed')
                os.replace(restore['name'], dst_name, src_dir_fd=dst, dst_dir_fd=dst)
            if _snapshot(dst, dst_name, ctime=False) != restore['identity']:
                raise JournalError('restored runtime identity changed')
            os.fsync(dst)
            data['phase'] = 'RESTORED_FILE'
            self._write(parent, data, raw)
            return record.previous_generation
        finally:
            if src is not None:
                os.close(src)
            if dst is not None:
                os.close(dst)
            os.close(parent)

    def _terminal(self, record, phase, expected_phase, generation, business):
        if not callable(business):
            raise ValueError('business verification callback required')
        parent = self._guard(record)
        src = dst = None
        try:
            data, raw = self._load(parent)
            self._check_record(record, data)
            if data['phase'] != expected_phase:
                raise JournalError('unexpected terminal phase')
            backup, candidate = self._read_backups(parent, data)
            if backup != record.previous_identity[-1] or candidate != record.candidate_identity[-1]:
                raise JournalError('backup changed')
            src, src_name, dst, dst_name = self._parents(record)
            self._check_parents(src, dst, data, record)
            self._check_source(src, src_name, data)
            current = _snapshot(dst, dst_name, ctime=False)
            if phase == 'COMMITTED':
                expected = [data['record']['candidate']]
            else:
                previous = {k: v for k, v in data['record']['previous'].items() if k != 'ctime_ns'}
                expected = [previous] + ([data['restore']['identity']] if data['restore'] else [])
            if current not in expected:
                raise JournalError('runtime does not match terminal generation')
            if phase == 'ROLLED_BACK' and current == previous:
                if _snapshot(dst, dst_name, ctime=True) != data['record']['previous']:
                    raise JournalError('previous runtime metadata changed')
            _confirm(business, record, generation)
            controller._assert_lock_held(self.lock_fd, self.lock_path)
            _confirm(self.barrier)
            _confirm(self.master, record)
            self._check_parents(src, dst, data, record)
            self._check_source(src, src_name, data)
            if _snapshot(dst, dst_name, ctime=False) != current:
                raise JournalError('runtime changed during business verification')
            data['phase'] = phase
            self._write(parent, data, raw)
        finally:
            if src is not None:
                os.close(src)
            if dst is not None:
                os.close(dst)
            os.close(parent)

    def commit(self, record, *, business):
        self._terminal(record, 'COMMITTED', 'PREPARED', record.next_generation, business)

    def confirm_rollback(self, record, *, business):
        self._terminal(record, 'ROLLED_BACK', 'RESTORED_FILE', record.previous_generation, business)

    def retire(self, record, *, business):
        """Retire only after a fresh business confirmation of a terminal state."""
        if not callable(business):
            raise ValueError('business verification callback required')
        parent = self._guard(record)
        src = dst = None
        try:
            data, raw = self._load(parent)
            self._check_record(record, data)
            if data['phase'] not in {'COMMITTED', 'ROLLED_BACK', 'RETIRED_COMMITTED', 'RETIRED_ROLLED_BACK'}:
                raise JournalError('journal is not terminal')
            backup, candidate = self._read_backups(parent, data)
            if backup != record.previous_identity[-1] or candidate != record.candidate_identity[-1]:
                raise JournalError('backup changed')
            src, src_name, dst, dst_name = self._parents(record)
            self._check_parents(src, dst, data, record)
            self._check_source(src, src_name, data)
            observed = _snapshot(dst, dst_name, ctime=False)
            previous = {k: v for k, v in data['record']['previous'].items() if k != 'ctime_ns'}
            terminal = data['phase'].removeprefix('RETIRED_')
            allowed = ([data['record']['candidate']] if terminal == 'COMMITTED'
                       else [previous] + ([data['restore']['identity']] if data['restore'] else []))
            if observed not in allowed:
                raise JournalError('terminal runtime changed')
            if terminal == 'ROLLED_BACK' and observed == previous:
                if _snapshot(dst, dst_name, ctime=True) != data['record']['previous']:
                    raise JournalError('previous runtime metadata changed')
            generation = record.next_generation if terminal == 'COMMITTED' else record.previous_generation
            _confirm(business, record, generation)
            controller._assert_lock_held(self.lock_fd, self.lock_path)
            _confirm(self.barrier)
            _confirm(self.master, record)
            self._check_parents(src, dst, data, record)
            self._check_source(src, src_name, data)
            if _snapshot(dst, dst_name, ctime=False) != observed or self._read_file(parent, 'intent.json') != raw:
                raise JournalError('terminal state changed during verification')
            if not data['phase'].startswith('RETIRED_'):
                data['phase'] = 'RETIRED_' + data['phase']
                self._write(parent, data, raw)
                data, raw = self._load(parent)
                self._check_record(record, data)
            self._archive_terminal(parent, data, raw, backup, candidate)
        finally:
            if src is not None:
                os.close(src)
            if dst is not None:
                os.close(dst)
            os.close(parent)
