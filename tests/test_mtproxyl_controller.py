import fcntl
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_mtproxyl_front import DOMAIN, REALISTIC

from deploy.lib import mtproxyl_controller as controller


class MasterIdentityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.proc = self.root / 'proc'
        self.node = self.proc / '123'
        self.node.mkdir(parents=True)
        boot_dir = self.proc / 'sys/kernel/random'
        boot_dir.mkdir(parents=True)
        (boot_dir / 'boot_id').write_text('01234567-89ab-cdef-0123-456789abcdef\n')
        self.binary = self.root / 'nginx'
        self.binary.write_text('synthetic binary')
        (self.node / 'exe').symlink_to(self.binary)
        self.runtime = self.root / 'runtime.conf'
        self.cgroup = '/system.slice/mtproxyl-test.service'
        self.write_stat()
        (self.node / 'cgroup').write_text('0::' + self.cgroup + '\n')
        (self.node / 'cmdline').write_bytes(
            ('nginx: master process %s -c %s' % (self.binary, self.runtime)).encode() + b'\0'
        )

    def tearDown(self):
        self.temp.cleanup()

    def write_stat(self, pid=123, ppid=1, start=456, state='S'):
        fields = [state, str(ppid)] + ['0'] * 17 + [str(start)]
        (self.node / 'stat').write_text('%d (nginx: master) %s\n' % (pid, ' '.join(fields)))

    def root_proc_stat(self):
        # Synthetic /proc lives under the test user, while a real master must
        # be root-owned. All other stat fields remain real.
        real_stat = os.stat
        def fake_stat(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            if Path(path) == self.node:
                values = list(value)
                values[4] = 0
                return os.stat_result(values)
            return value
        return mock.patch.object(controller.os, 'stat', side_effect=fake_stat)

    def inspect(self, **overrides):
        with self.root_proc_stat():
            return controller.inspect_master(
                overrides.get('pid', 123), overrides.get('binary', self.binary),
                overrides.get('runtime', self.runtime), overrides.get('cgroup', self.cgroup),
                proc_root=self.proc,
            )

    def write_children(self, *pids):
        path = self.node / 'task/123'
        path.mkdir(parents=True, exist_ok=True)
        (path / 'children').write_text(' '.join(str(pid) for pid in pids))

    def write_worker(self, pid, *, ppid=123, start=457, cgroup=None, title='nginx: worker process'):
        node = self.proc / str(pid)
        node.mkdir(exist_ok=True)
        fields = ['S', str(ppid)] + ['0'] * 17 + [str(start)]
        (node / 'stat').write_text('%d (nginx: worker) %s\n' % (pid, ' '.join(fields)))
        (node / 'cgroup').write_text('0::' + (cgroup or self.cgroup) + '\n')
        (node / 'cmdline').write_bytes(title.encode() + b'\0')
        if not (node / 'exe').is_symlink():
            (node / 'exe').symlink_to(self.binary)

    def capture(self, master):
        with self.root_proc_stat():
            return controller.capture_workers(master, proc_root=self.proc)

    def confirm(self, master, baseline, probe):
        with self.root_proc_stat():
            return controller.confirm_generation(master, baseline, '/private/synthetic.sock', 'a' * 32,
                                                 proc_root=self.proc, probe=probe)

    def test_correct_master_identity(self):
        identity = self.inspect()
        self.assertEqual((identity.pid, identity.ppid, identity.start_ticks), (123, 1, 456))
        self.assertEqual(identity.boot_id, '01234567-89ab-cdef-0123-456789abcdef')
        self.assertEqual(identity.cgroup, self.cgroup)
        self.assertEqual(identity.owner_uid, 0)
        self.assertIn(str(self.runtime), identity.argv)

    def test_wrong_exe_cgroup_argv_or_state_rejected(self):
        other = self.root / 'other'
        other.write_text('other binary')
        with self.assertRaises(controller.IdentityError):
            self.inspect(binary=other)
        with self.assertRaises(controller.IdentityError):
            self.inspect(cgroup='/other.service')
        (self.node / 'cmdline').write_bytes(b'nginx: worker process\0')
        with self.assertRaises(controller.IdentityError):
            self.inspect()
        (self.node / 'cmdline').write_bytes(b'nginx: master process nginx -c /wrong\0')
        with self.assertRaises(controller.IdentityError):
            self.inspect()
        self.write_stat(state='Z')
        with self.assertRaises(controller.IdentityError):
            self.inspect()

    def test_v1_or_ambiguous_cgroup_and_bad_boot_rejected(self):
        for data in ('1:systemd:/system.slice/test\n', '0::/a\n0::/b\n', '0::/a/../b\n'):
            with self.subTest(data=data):
                (self.node / 'cgroup').write_text(data)
                with self.assertRaises(controller.IdentityError):
                    self.inspect()
        (self.node / 'cgroup').write_text('0::' + self.cgroup + '\n')
        (self.proc / 'sys/kernel/random/boot_id').write_text('not-a-boot-id')
        with self.assertRaises(controller.IdentityError):
            self.inspect()

    def test_pid_reuse_or_cgroup_change_during_read_rejected(self):
        original = controller._read_bounded
        calls = {'stat': 0, 'cgroup': 0}
        def changing(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == self.node / 'stat':
                calls['stat'] += 1
                if calls['stat'] == 2:
                    self.write_stat(start=999)
                    return original(path)
            return value
        with mock.patch.object(controller, '_read_bounded', side_effect=changing):
            with self.assertRaises(controller.IdentityError):
                self.inspect()
        self.write_stat()
        def changing_cgroup(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == self.node / 'cgroup':
                calls['cgroup'] += 1
                if calls['cgroup'] == 2:
                    return b'0::/different\n'
            return value
        with mock.patch.object(controller, '_read_bounded', side_effect=changing_cgroup):
            with self.assertRaises(controller.IdentityError):
                self.inspect()

    def test_new_worker_confirmation_and_stale_worker_rejection(self):
        self.write_worker(124)
        self.write_children(124)
        master = self.inspect()
        baseline = self.capture(master)
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 124)
        self.write_worker(125, start=458)
        self.write_children(124, 125)
        result = self.confirm(master, baseline, lambda *_: 125)
        self.assertEqual((result.pid, result.ppid, result.start_ticks), (125, 123, 458))

    def test_reused_pid_never_confirms_stale_marker(self):
        self.write_worker(124)
        self.write_children(124)
        master = self.inspect()
        baseline = self.capture(master)
        self.write_worker(124, start=999)
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 124)

    def test_foreign_disappeared_or_shutting_down_worker_rejected(self):
        self.write_worker(124)
        self.write_children(124)
        master = self.inspect()
        baseline = self.capture(master)
        self.write_worker(125, start=458, cgroup='/foreign')
        self.write_children(124, 125)
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 125)
        self.write_worker(125, start=458, ppid=999)
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 125)
        self.write_worker(125, start=458, title='nginx: worker process is shutting down')
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 125)
        (self.proc / '125/stat').unlink()
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: 125)

    def test_master_change_while_probe_in_flight_rejected(self):
        self.write_worker(124)
        self.write_children(124)
        master = self.inspect()
        baseline = self.capture(master)
        self.write_worker(125, start=458)
        self.write_children(124, 125)
        def probe(*_):
            self.write_stat(start=999)
            return 125
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, probe)

    def test_capture_rejects_missing_children_and_bad_probe(self):
        self.write_children()
        master = self.inspect()
        with self.assertRaises(controller.IdentityError):
            self.capture(master)
        self.write_worker(124)
        self.write_children(124)
        baseline = self.capture(master)
        def broken(*_):
            raise OSError('missing marker')
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, broken)
        with self.assertRaises(controller.IdentityError):
            self.confirm(master, baseline, lambda *_: True)

    def test_missing_metadata_and_invalid_inputs_rejected(self):
        (self.node / 'exe').unlink()
        with self.assertRaises(controller.IdentityError):
            self.inspect()
        with self.assertRaises(controller.IdentityError):
            self.inspect(pid=0)
        with self.assertRaises(controller.IdentityError):
            self.inspect(runtime=Path('relative.conf'))


class StrictReloadTest(unittest.TestCase):
    root_proc_stat = MasterIdentityTest.root_proc_stat
    inspect = MasterIdentityTest.inspect
    write_stat = MasterIdentityTest.write_stat
    write_children = MasterIdentityTest.write_children
    write_worker = MasterIdentityTest.write_worker
    def tearDown(self):
        os.close(self.front_lock_fd)
        MasterIdentityTest.tearDown(self)

    def setUp(self):
        MasterIdentityTest.setUp(self)
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)
        self.source = self.root / 'vendor.conf'
        self.source.write_text(REALISTIC)
        self.marker = self.root / 'probe.sock'
        self.previous_generation = 'a' * 32
        self.previous = controller.runtime.patch_with_generation(
            REALISTIC, DOMAIN, self.marker, self.previous_generation).encode()
        self.runtime.write_bytes(self.previous)
        self.runtime.chmod(0o600)
        self.journal = self.root / 'journal'
        self.write_worker(124)
        self.write_children(124)
        self.master = self.inspect()
        self.events = []
        self.front_lock_path = self.root / 'front.lock'
        self.front_lock_fd = os.open(self.front_lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.front_lock_fd, fcntl.LOCK_EX)

    def record(self, item):
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(item.previous_generation, self.previous_generation)
        self.assertRegex(item.candidate_sha256, r'^[a-f0-9]{64}$')
        self.assertNotEqual(item.next_generation, item.previous_generation)
        candidate = Path(item.candidate_path)
        self.assertTrue(candidate.is_file())
        self.assertEqual((candidate.stat().st_dev, candidate.stat().st_ino), item.candidate_identity[:2])
        self.assertEqual((candidate.stat().st_mtime_ns, candidate.stat().st_ctime_ns), item.candidate_exact[1:])
        with self.journal.open('w') as out:
            out.write(item.transaction_id)
            out.flush()
            os.fsync(out.fileno())
        fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.events.append('record')
        return controller.JournalReceipt(item.transaction_id, True)

    def restore(self, item):
        self.events.append('restore')
        temporary = self.root / 'restore.tmp'
        temporary.write_bytes(item.previous_identity[-1])
        temporary.chmod(0o600)
        os.replace(temporary, self.runtime)
        return item.previous_generation

    def business(self, _record, _worker):
        self.events.append('business')
        return True

    def previous_business(self, _record, _worker):
        self.events.append('previous')
        return True

    def run_reload(self, **overrides):
        test_wait = overrides.pop('test_wait', None)
        test_signal = overrides.pop('test_signal', None)
        args = dict(source=self.source, runtime_path=self.runtime, domain=DOMAIN,
                    nginx_bin=self.binary, marker_socket=self.marker,
                    previous_generation=self.previous_generation, master=self.master,
                    lock_fd=self.front_lock_fd, lock_path=self.front_lock_path, record_before_publish=self.record,
                    restore_previous=self.restore, verify_business=self.business,
                    verify_previous=self.previous_business, proc_root=self.proc, timeout=.1)
        args.update(overrides)
        with self.root_proc_stat(), \
             mock.patch.object(controller, '_assert_lock_held'), \
             mock.patch.object(controller, '_signal_checked', side_effect=test_signal or (lambda *_a, **_kw: self.events.append('hup'))), \
             mock.patch.object(controller, '_wait_generation', side_effect=test_wait or (lambda *_a, **_kw: self.events.append('confirm') or object())), \
             mock.patch.object(controller.runtime, 'probe_generation', return_value=124):
            return controller.strict_reload(**args)

    def test_success_records_before_publish_and_keeps_journal(self):
        generation = self.run_reload()
        self.assertRegex(generation, r'^[a-f0-9]{32}$')
        self.assertEqual(self.events, ['record', 'hup', 'confirm', 'business'])
        self.assertNotEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.source.read_text(), REALISTIC)
        self.assertTrue(self.journal.exists())

    def test_business_failure_rolls_back_and_confirms_previous(self):
        with self.assertRaises(controller.ReloadFailed):
            self.run_reload(verify_business=lambda *_: False)
        self.assertEqual(self.events, ['record', 'hup', 'confirm', 'restore', 'hup', 'confirm', 'previous'])
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertTrue(self.journal.exists())

    def test_source_drift_after_publish_rolls_back(self):
        original = controller.runtime.publish
        def changing(*args, **kwargs):
            result = original(*args, **kwargs)
            self.source.write_text('external writer')
            return result
        with mock.patch.object(controller.runtime, 'publish', side_effect=changing):
            with self.assertRaises(controller.RecoveryUncertain):
                self.run_reload()
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.source.read_text(), 'external writer')
        self.assertEqual(self.events, ['record', 'restore', 'hup', 'confirm', 'previous'])
        self.assertTrue(self.journal.exists())

    def test_failure_after_rename_uses_prejournaled_candidate_identity(self):
        def rename_then_crash(staged):
            os.replace(staged.candidate_name, staged.runtime_name,
                       src_dir_fd=staged.runtime_parent, dst_dir_fd=staged.runtime_parent)
            raise OSError('simulated crash before directory fsync')
        with mock.patch.object(controller.runtime, 'publish', side_effect=rename_then_crash):
            with self.assertRaises(controller.ReloadFailed):
                self.run_reload()
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, ['record', 'restore', 'hup', 'confirm', 'previous'])
        self.assertTrue(self.journal.exists())

    def test_replaced_candidate_is_not_published_or_deleted(self):
        replacement_identity = []
        candidate_path = []
        def replace(item):
            receipt = self.record(item)
            candidate = Path(item.candidate_path)
            candidate_path.append(candidate)
            foreign = self.root / 'foreign.tmp'
            foreign.write_bytes(candidate.read_bytes())
            foreign.chmod(0o600)
            os.replace(foreign, candidate)
            replacement_identity.append(candidate.stat().st_ino)
            return receipt
        with self.assertRaises(controller.ReloadFailed):
            self.run_reload(record_before_publish=replace)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(candidate_path[0].stat().st_ino, replacement_identity[0])
        self.assertTrue(self.journal.exists())

    def test_external_runtime_change_is_not_overwritten(self):
        def mutate(*_):
            self.runtime.write_bytes(b'external runtime')
            raise RuntimeError('probe failed')
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(verify_business=mutate)
        self.assertEqual(self.runtime.read_bytes(), b'external runtime')
        self.assertNotIn('restore', self.events)
        self.assertTrue(self.journal.exists())

    def test_runtime_replaced_with_identical_bytes_is_not_overwritten(self):
        foreign_inode = []
        def replace_with_same_bytes(*_):
            replacement = self.root / 'foreign.tmp'
            replacement.write_bytes(self.runtime.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, self.runtime)
            foreign_inode.append(self.runtime.stat().st_ino)
            return False
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(verify_business=replace_with_same_bytes)
        self.assertEqual(self.runtime.stat().st_ino, foreign_inode[0])
        self.assertNotIn('restore', self.events)
        self.assertTrue(self.journal.exists())

    def test_rollback_failure_preserves_journal_and_reports_uncertain(self):
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(verify_business=lambda *_: False, verify_previous=lambda *_: False)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertTrue(self.journal.exists())
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(verify_business=lambda *_: False, restore_previous=lambda *_: 'b' * 32)
        self.assertTrue(self.journal.exists())

    def test_unconfirmed_journal_callbacks_and_unmarked_fallback_block(self):
        with self.assertRaises(ValueError):
            self.run_reload(verify_business=None)
        self.assertEqual(self.events, [])
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(record_before_publish=lambda *_: None)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, [])
        self.runtime.write_text(REALISTIC)
        with self.assertRaises(controller.IdentityError):
            self.run_reload()
        self.assertEqual(self.runtime.read_text(), REALISTIC)
        self.assertEqual(self.events, [])

    def test_journal_callback_exception_or_prepublication_drift_is_uncertain(self):
        def interrupted(item):
            self.record(item)
            raise RuntimeError('callback interrupted')
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(record_before_publish=interrupted)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, ['record'])
        self.assertTrue(self.journal.exists())
        self.events.clear()
        def drift(item):
            receipt = self.record(item)
            self.source.write_text('external change')
            return receipt
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(record_before_publish=drift)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, ['record'])

    def test_pid_reuse_during_signal_blocks_unconfirmed_rollback(self):
        def changed(*_args, **_kwargs):
            raise controller.IdentityError('master incarnation changed')
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(test_signal=changed)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertTrue(self.journal.exists())
        self.assertEqual(self.events, ['record', 'restore'])

    def test_stale_generation_confirmation_causes_confirmed_rollback(self):
        calls = 0
        def waiting(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise controller.IdentityError('old worker cannot confirm reload')
            return object()
        with self.assertRaises(controller.ReloadFailed):
            self.run_reload(test_wait=waiting)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertTrue(self.journal.exists())
        self.assertEqual(self.events, ['record', 'hup', 'restore', 'hup', 'previous'])

    def test_source_change_during_rollback_keeps_journal_uncertain(self):
        def previous_probe(*_):
            self.source.write_text('changed during rollback')
            return True
        with self.assertRaises(controller.RecoveryUncertain):
            self.run_reload(verify_business=lambda *_: False, verify_previous=previous_probe)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.source.read_text(), 'changed during rollback')
        self.assertTrue(self.journal.exists())

    def test_master_runtime_or_binary_mismatch_never_publishes(self):
        other = self.root / 'other.conf'
        other.write_bytes(self.previous)
        other.chmod(0o600)
        with self.assertRaises(controller.IdentityError):
            self.run_reload(runtime_path=other)
        self.assertEqual(other.read_bytes(), self.previous)
        with self.assertRaises(controller.IdentityError):
            self.run_reload(nginx_bin=self.source)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, [])

    def test_vendor_and_runtime_same_inode_rejected_before_journal(self):
        self.source.write_bytes(self.previous)
        with self.assertRaises(controller.IdentityError):
            self.run_reload(source=self.runtime)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertEqual(self.events, [])
        self.assertFalse(self.journal.exists())

    def test_real_unheld_lock_rejected_before_any_callback(self):
        path = self.root / 'unheld.lock'
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with self.root_proc_stat(), self.assertRaises(controller.IdentityError):
                controller.strict_reload(
                    source=self.source, runtime_path=self.runtime, domain=DOMAIN,
                    nginx_bin=self.binary, marker_socket=self.marker,
                    previous_generation=self.previous_generation, master=self.master,
                    lock_fd=fd, lock_path=path, record_before_publish=self.record,
                    restore_previous=self.restore, verify_business=self.business,
                    verify_previous=self.previous_business, proc_root=self.proc)
            self.assertEqual(self.events, [])
            self.assertFalse(self.journal.exists())
            self.assertEqual(self.runtime.read_bytes(), self.previous)
        finally:
            os.close(fd)

    def test_exception_in_business_is_rolled_back(self):
        def interrupt(*_):
            raise KeyboardInterrupt()
        with self.assertRaises(controller.ReloadFailed):
            self.run_reload(verify_business=interrupt)
        self.assertEqual(self.runtime.read_bytes(), self.previous)
        self.assertTrue(self.journal.exists())



class LockFdInfoTest(unittest.TestCase):
    def test_fdinfo_must_report_exact_exclusive_flock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'front.lock'
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                info = os.fstat(fd)
                device = '%02x:%02x:%d' % (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
                line = '1: FLOCK ADVISORY WRITE %d %s 0 EOF' % (os.getpid(), device)
                lock_line = ('lock: ' + line + '\n').encode()
                global_line = (line + '\n').encode()
                def metadata(path_arg, *_args):
                    if str(path_arg) == '/proc/locks':
                        return global_line
                    if str(path_arg) == '/proc/self/fdinfo/%d' % fd:
                        return lock_line
                    raise AssertionError('unexpected metadata path')
                with mock.patch.object(controller, '_read_bounded', side_effect=metadata):
                    controller._assert_lock_held(fd, path)
                    global_line = ('1: FLOCK ADVISORY WRITE 999999 %s 0 EOF\n' % device).encode()
                    with self.assertRaises(controller.IdentityError):
                        controller._assert_lock_held(fd, path)
                    global_line = (line + '\n').encode()
                    for bad in (b'', lock_line.replace(b'WRITE', b'READ'),
                                lock_line.replace(b'FLOCK', b'POSIX'), lock_line * 2):
                        lock_line = bad
                        with self.subTest(fdinfo=bad), self.assertRaises(controller.IdentityError):
                            controller._assert_lock_held(fd, path)
            finally:
                os.close(fd)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux fdinfo')
    def test_inherited_description_keeps_original_owner_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'front.lock'
            first = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(first, fcntl.LOCK_EX)
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    controller._assert_lock_held(first, path)
                    other = os.open(path, os.O_RDWR)
                    try:
                        try:
                            controller._assert_lock_held(other, path)
                        except controller.IdentityError:
                            os.write(write_fd, b'ok')
                        else:
                            os.write(write_fd, b'other description accepted')
                    finally:
                        os.close(other)
                except BaseException as exc:
                    os.write(write_fd, ('error: ' + type(exc).__name__).encode())
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                result = os.read(read_fd, 128)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(0, status)
                self.assertEqual(b'ok', result)
            finally:
                os.close(read_fd)
                os.close(first)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux fdinfo')
    def test_independent_fd_is_rejected_and_duplicate_retains_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'front.lock'
            first = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            second = os.open(path, os.O_RDWR)
            duplicate = None
            try:
                fcntl.flock(first, fcntl.LOCK_EX)
                duplicate = os.dup(first)
                controller._assert_lock_held(first, path)
                controller._assert_lock_held(duplicate, path)
                with self.assertRaises(controller.IdentityError):
                    controller._assert_lock_held(second, path)
                os.close(first)
                first = None
                controller._assert_lock_held(duplicate, path)
                with self.assertRaises(controller.IdentityError):
                    controller._assert_lock_held(second, path)
            finally:
                if first is not None:
                    os.close(first)
                if duplicate is not None:
                    os.close(duplicate)
                os.close(second)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux fdinfo')
    def test_transaction_pins_lock_if_original_fd_is_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'front.lock'
            first = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            competitor = os.open(path, os.O_RDWR)
            fcntl.flock(first, fcntl.LOCK_EX)
            def simulated_impl(**kwargs):
                os.close(first)
                controller._assert_lock_held(kwargs['lock_fd'], path)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return 'not-committed'
            try:
                with mock.patch.object(controller, '_strict_reload_impl', side_effect=simulated_impl):
                    with self.assertRaises(controller.RecoveryUncertain):
                        controller.strict_reload(source='/x', runtime_path='/y', domain='dns.example.com',
                            nginx_bin='/z', marker_socket='/probe', previous_generation='a' * 32,
                            master=None, lock_fd=first, lock_path=path, record_before_publish=lambda *_: None,
                            restore_previous=lambda *_: None, verify_business=lambda *_: None,
                            verify_previous=lambda *_: None)
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(competitor)



if __name__ == '__main__':
    unittest.main()
