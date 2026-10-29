"""Journal tests; fake locks/barriers/master/business do not prove orchestration."""

import hashlib
import fcntl
import json
import os
import sys
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.lib import mtproxyl_controller as controller
from deploy.lib import mtproxyl_journal as journal_module

REAL_LOCK_CHECK = controller._assert_lock_held


def yes(*args):
    return True


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.private = self.base / 'private'
        self.private.mkdir(mode=0o700)
        self.source = self.base / 'vendor.conf'
        self.target = self.base / 'runtime.conf'
        self.candidate = self.base / ('.runtime.conf.doh-' + 'c' * 32)
        self.source.write_bytes(b'vendor secret\n')
        self.marker = str(self.base / 'test.sock')
        self.previous_bytes = ('previous private runtime\n' + controller._marker_fragment(self.marker, 'a' * 32)).encode()
        self.candidate_bytes = ('candidate private runtime\n' + controller._marker_fragment(self.marker, 'b' * 32)).encode()
        self.target.write_bytes(self.previous_bytes)
        self.candidate.write_bytes(self.candidate_bytes)
        for file in (self.source, self.target, self.candidate):
            file.chmod(0o600)
        self.patches = [patch.object(journal_module, '_require_root'),
                        patch.object(controller, '_assert_lock_held')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.master = controller.ProcessIdentity(1, 0, 1, '12345678-1234-1234-1234-123456789abc', '/test', 1, 2, 0,
                                                 ('nginx', '-c', str(self.target)))
        source = controller.runtime._exact_identity(controller._path_snapshot(self.source))
        previous = controller.runtime._exact_identity(controller._path_snapshot(self.target))
        candidate = controller.runtime._exact_identity(controller._path_snapshot(self.candidate))
        self.record = controller.ReloadRecord('1' * 32, self.master, source[0], previous[0],
                                             'a' * 32, 'b' * 32,
                                             hashlib.sha256(candidate[0][-1]).hexdigest(),
                                             str(self.source), str(self.target), self.marker,
                                             source, previous, candidate[0], candidate, str(self.candidate))
        self.journal = self.new_journal()

    def new_journal(self, **kwargs):
        options = {'lock_fd': 3, 'lock_path': self.base / 'front.lock', 'barrier': yes, 'master': yes}
        options.update(kwargs)
        return journal_module.Journal(self.private, **options)

    def publish(self):
        os.replace(self.candidate, self.target)
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def next_record(self):
        candidate = self.base / ('.runtime.conf.doh-' + 'd' * 32)
        candidate_bytes = ('next runtime\n' + controller._marker_fragment(self.marker, 'c' * 32)).encode()
        candidate.write_bytes(candidate_bytes)
        candidate.chmod(0o600)
        source = controller.runtime._exact_identity(controller._path_snapshot(self.source))
        previous = controller.runtime._exact_identity(controller._path_snapshot(self.target))
        staged = controller.runtime._exact_identity(controller._path_snapshot(candidate))
        return controller.ReloadRecord('2' * 32, self.master, source[0], previous[0], 'b' * 32,
                                       'c' * 32, hashlib.sha256(candidate_bytes).hexdigest(),
                                       str(self.source), str(self.target), self.marker,
                                       source, previous, staged[0], staged, str(candidate))

    def intent(self):
        return json.loads((self.private / 'intent.json').read_text())

    def test_durable_prepared_backup_and_new_instance_inspection(self):
        receipt = self.journal.record_before_publish(self.record)
        self.assertEqual(receipt, controller.JournalReceipt('1' * 32, True))
        self.assertEqual(self.journal.inspect_pending()['phase'], 'PREPARED')
        self.assertEqual(self.new_journal().read_pending(self.record)['phase'], 'PREPARED')
        manifest = (self.private / 'intent.json').read_bytes()
        self.assertNotIn(b'vendor secret', manifest)
        self.assertNotIn(b'previous private runtime', manifest)
        self.assertEqual((self.private / ('1' * 32 + '.backup')).read_bytes(), self.previous_bytes)

    def test_restore_is_idempotent_after_rename_and_requires_business_proof(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        self.assertEqual(self.journal.restore_previous(self.record), 'a' * 32)
        self.assertEqual(self.target.read_bytes(), self.previous_bytes)
        self.assertEqual(self.new_journal().restore_previous(self.record), 'a' * 32)
        with self.assertRaises(journal_module.JournalError):
            self.journal.confirm_rollback(self.record, business=lambda *_: False)
        self.journal.confirm_rollback(self.record, business=yes)
        with self.assertRaises(journal_module.JournalError):
            self.journal.retire(self.record, business=lambda *_: False)
        self.assertTrue((self.private / 'intent.json').exists())
        self.journal.retire(self.record, business=yes)
        self.assertFalse((self.private / 'intent.json').exists())
        archive = self.private / ('archive-' + '1' * 32)
        self.assertEqual(json.loads((archive / 'intent.json').read_text())['phase'], 'RETIRED_ROLLED_BACK')

    def test_foreign_inode_with_same_bytes_is_not_overwritten(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        foreign = self.base / 'foreign'
        foreign.write_bytes(self.target.read_bytes())
        foreign.chmod(0o600)
        os.replace(foreign, self.target)
        inode = self.target.stat().st_ino
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        self.assertEqual(self.target.stat().st_ino, inode)
        self.assertEqual(self.intent()['phase'], 'PREPARED')

    def test_lock_barrier_master_required(self):
        for override in ({'barrier': lambda: False}, {'master': lambda _: False}):
            with self.subTest(override=override):
                with self.assertRaises(journal_module.JournalError):
                    self.new_journal(**override).record_before_publish(self.record)
        with patch.object(controller, '_assert_lock_held', side_effect=RuntimeError('lost lock')):
            with self.assertRaises(RuntimeError):
                self.journal.record_before_publish(self.record)
        self.assertFalse((self.private / 'intent.json').exists())

    def test_early_fsync_error_does_not_authorize_publish(self):
        with patch.object(journal_module.os, 'fsync', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.journal.record_before_publish(self.record)
        self.assertEqual(self.target.read_bytes(), self.previous_bytes)

    def test_changed_source_backup_or_manifest_fails_closed(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        backup = self.private / ('1' * 32 + '.backup')
        saved = backup.read_bytes()
        backup.write_bytes(b'tamper')
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        backup.write_bytes(saved)
        self.source.write_bytes(b'changed')
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        data = self.intent()
        data['record']['candidate']['identity'][1] += 1
        (self.private / 'intent.json').write_text(json.dumps(data))
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        self.assertEqual(self.target.read_bytes(), self.candidate_bytes)

    def test_repeated_crash_after_restore_ready_and_after_rename(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        original_replace = journal_module.os.replace

        def stop_before_rename(src, dst, **kwargs):
            if dst == 'runtime.conf':
                raise OSError('crash before rename')
            return original_replace(src, dst, **kwargs)

        with patch.object(journal_module.os, 'replace', side_effect=stop_before_rename):
            with self.assertRaises(OSError):
                self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'RESTORE_READY')
        ready = self.intent()['restore']
        original_write = journal_module.Journal._write

        def stop_after_rename(instance, parent, data, previous=None):
            if data['phase'] == 'RESTORED_FILE':
                raise OSError('crash after rename')
            return original_write(instance, parent, data, previous)

        with patch.object(journal_module.Journal, '_write', stop_after_rename):
            with self.assertRaises(OSError):
                self.new_journal().restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'RESTORE_READY')
        self.assertEqual(self.target.stat().st_ino, ready['identity']['identity'][1])
        self.assertEqual(self.new_journal().restore_previous(self.record), 'a' * 32)
        self.assertEqual(self.intent()['phase'], 'RESTORED_FILE')

    def test_commit_requires_real_callback_and_terminal_retire_rechecks(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        with self.assertRaises(journal_module.JournalError):
            self.journal.commit(self.record, business=lambda *_: False)
        self.journal.commit(self.record, business=yes)
        self.assertEqual(self.intent()['phase'], 'COMMITTED')
        with self.assertRaises(journal_module.JournalError):
            self.journal.retire(self.record, business=lambda *_: False)
        self.journal.retire(self.record, business=yes)

    def test_absent_candidate_with_exact_old_runtime_requires_business_proof(self):
        self.journal.record_before_publish(self.record)
        self.candidate.unlink()
        original_inode = self.target.stat().st_ino
        self.assertEqual(self.journal.restore_previous(self.record), 'a' * 32)
        self.assertEqual(self.target.stat().st_ino, original_inode)
        with self.assertRaises(journal_module.JournalError):
            self.journal.confirm_rollback(self.record, business=lambda *_: False)
        self.assertEqual(self.intent()['phase'], 'RESTORED_FILE')
        self.journal.confirm_rollback(self.record, business=yes)

    def test_absent_candidate_rejects_changed_previous_ctime(self):
        self.journal.record_before_publish(self.record)
        self.candidate.unlink()
        self.target.chmod(0o640)
        self.target.chmod(0o600)
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'PREPARED')

    def test_fsync_failure_during_restore_keeps_marker_and_candidate(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        with patch.object(journal_module.os, 'fsync', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'PREPARED')
        self.assertEqual(self.target.read_bytes(), self.candidate_bytes)

    def test_rejects_forged_restore_manifest(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        original = journal_module.os.replace

        def fail_stage(src, dst, **kwargs):
            if dst == 'runtime.conf':
                raise OSError('stopped')
            return original(src, dst, **kwargs)

        with patch.object(journal_module.os, 'replace', side_effect=fail_stage):
            with self.assertRaises(OSError):
                self.journal.restore_previous(self.record)
        data = self.intent()
        data['restore']['identity']['sha256'] = data['record']['candidate']['sha256']
        (self.private / 'intent.json').write_text(json.dumps(data))
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        self.assertEqual(self.target.read_bytes(), self.candidate_bytes)

    def test_degraded_unmarked_previous_is_rejected(self):
        previous = self.record.previous_exact
        identity = list(previous[0])
        identity[-1] = b'unmarked old configuration'
        identity[-2] = hashlib.sha256(identity[-1]).digest()
        record = replace(self.record, previous_identity=tuple(identity),
                         previous_exact=(tuple(identity), previous[1], previous[2]))
        with self.assertRaises(journal_module.JournalError):
            self.journal.record_before_publish(record)
        self.assertFalse((self.private / 'intent.json').exists())

    def test_hardlinked_and_symlink_backup_fail_closed(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        backup = self.private / ('1' * 32 + '.backup')
        alias = self.private / 'alias'
        os.link(backup, alias)
        with self.assertRaises(journal_module.JournalError):
            self.journal.restore_previous(self.record)
        alias.unlink()
        backup.rename(alias)
        backup.symlink_to(alias)
        with self.assertRaises(OSError):
            self.journal.restore_previous(self.record)
        self.assertEqual(self.target.read_bytes(), self.candidate_bytes)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux fdinfo flock is required')
    def test_real_flock_is_required_on_linux(self):
        lock = self.base / 'real-front.lock'
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            instance = self.new_journal(lock_fd=fd, lock_path=lock)
            with patch.object(controller, '_assert_lock_held', REAL_LOCK_CHECK):
                instance.record_before_publish(self.record)
                fcntl.flock(fd, fcntl.LOCK_UN)
                with self.assertRaises(controller.IdentityError):
                    instance.restore_previous(self.record)
        finally:
            os.close(fd)

    def test_two_successive_transactions(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        self.journal.commit(self.record, business=yes)
        self.journal.retire(self.record, business=yes)
        next_record = self.next_record()
        self.new_journal().record_before_publish(next_record)
        self.assertEqual(self.intent()['record']['transaction_id'], '2' * 32)

    def test_archive_crash_each_phase_then_next_transaction(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        self.journal.commit(self.record, business=yes)
        original_put = journal_module.Journal._archive_put
        for entry in ('intent.json', 'backup', 'candidate', 'complete.json'):
            def interrupt(instance, parent, name, payload):
                original_put(instance, parent, name, payload)
                if name == entry:
                    raise OSError('interrupted after archive ' + entry)

            with self.subTest(entry=entry), patch.object(journal_module.Journal, '_archive_put', interrupt):
                with self.assertRaises(OSError):
                    self.new_journal().retire(self.record, business=yes)
            self.assertEqual(self.intent()['phase'], 'RETIRED_COMMITTED')
        real_unlink = journal_module.os.unlink

        def before_delete(name, **kwargs):
            if name == 'intent.json':
                raise OSError('interrupted before unlink')
            return real_unlink(name, **kwargs)

        with patch.object(journal_module.os, 'unlink', side_effect=before_delete):
            with self.assertRaises(OSError):
                self.new_journal().retire(self.record, business=yes)
        self.assertEqual(self.intent()['phase'], 'RETIRED_COMMITTED')
        removed = [False]
        real_fsync = journal_module.os.fsync

        def after_delete(name, **kwargs):
            result = real_unlink(name, **kwargs)
            if name == 'intent.json':
                removed[0] = True
            return result

        def fail_after_delete(fd):
            if removed[0]:
                raise OSError('fsync failed after unlink')
            return real_fsync(fd)

        with patch.object(journal_module.os, 'unlink', side_effect=after_delete), \
             patch.object(journal_module.os, 'fsync', side_effect=fail_after_delete):
            with self.assertRaises(OSError):
                self.new_journal().retire(self.record, business=yes)
        self.assertFalse((self.private / 'intent.json').exists())
        self.new_journal().record_before_publish(self.next_record())
        self.assertEqual(self.intent()['record']['transaction_id'], '2' * 32)

    def test_incomplete_or_unknown_archive_blocks_next_transaction(self):
        (self.private / ('archive-' + '9' * 32)).mkdir(mode=0o700)
        with self.assertRaises(journal_module.JournalError):
            self.journal.record_before_publish(self.record)
        self.assertFalse((self.private / 'intent.json').exists())

    def test_reconstruct_after_process_loss_before_and_after_publish(self):
        self.journal.record_before_publish(self.record)
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(rebuilt, self.record)
        self.publish()
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(rebuilt, self.record)
        self.assertEqual(self.new_journal().restore_previous(rebuilt), 'a' * 32)

    def test_reconstruct_rejects_new_master_and_accepts_absent_stage_with_old_runtime(self):
        self.journal.record_before_publish(self.record)
        changed_master = replace(self.master, boot_id='other-boot')
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().reconstruct(changed_master)
        self.candidate.unlink()
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(rebuilt, self.record)
        self.assertEqual(self.intent()['phase'], 'PREPARED')

    def test_reconstruct_after_restore_rename_when_candidate_disappears(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        original_write = journal_module.Journal._write

        def interrupt(instance, parent, data, previous=None):
            if data['phase'] == 'RESTORED_FILE':
                raise OSError('interrupted after restore rename')
            return original_write(instance, parent, data, previous)

        with patch.object(journal_module.Journal, '_write', interrupt):
            with self.assertRaises(OSError):
                self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'RESTORE_READY')
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(self.new_journal().restore_previous(rebuilt), 'a' * 32)
        self.assertEqual(self.intent()['phase'], 'RESTORED_FILE')

    def test_reconstruct_after_restore_intent_before_rename(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        original_replace = journal_module.os.replace

        def interrupt(src, dst, **kwargs):
            if dst == 'runtime.conf':
                raise OSError('interrupted before restore rename')
            return original_replace(src, dst, **kwargs)

        with patch.object(journal_module.os, 'replace', side_effect=interrupt):
            with self.assertRaises(OSError):
                self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'RESTORE_READY')
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(self.new_journal().restore_previous(rebuilt), 'a' * 32)

    def test_reconstruct_after_restored_file_state(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        self.journal.restore_previous(self.record)
        self.assertEqual(self.intent()['phase'], 'RESTORED_FILE')
        rebuilt = self.new_journal().reconstruct(self.master)
        self.assertEqual(self.new_journal().restore_previous(rebuilt), 'a' * 32)

    def test_tampered_candidate_backup_blocks_all_recovery(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        candidate = self.private / ('1' * 32 + '.candidate')
        candidate.write_bytes(b'tampered')
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().reconstruct(self.master)
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().restore_previous(self.record)
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().commit(self.record, business=yes)
        self.assertEqual(self.target.read_bytes(), self.candidate_bytes)

    def test_failure_during_candidate_backup_never_publishes_prepared(self):
        original_create = journal_module.Journal._create

        def interrupted(parent, name, data):
            original_create(parent, name, data)
            if name.endswith('.candidate'):
                raise OSError('interrupted after candidate backup')

        with patch.object(journal_module.Journal, '_create', staticmethod(interrupted)):
            with self.assertRaises(OSError):
                self.journal.record_before_publish(self.record)
        self.assertFalse((self.private / 'intent.json').exists())
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().record_before_publish(self.record)

    def test_tampered_archived_candidate_blocks_next_transaction(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        self.journal.commit(self.record, business=yes)
        self.journal.retire(self.record, business=yes)
        archive = self.private / ('archive-' + '1' * 32)
        (archive / 'candidate').write_bytes(b'tampered')
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().record_before_publish(self.next_record())

    def test_reconstruct_rejects_unknown_runtime_even_with_valid_backup(self):
        self.journal.record_before_publish(self.record)
        self.publish()
        foreign = self.base / 'foreign'
        foreign.write_bytes(self.candidate_bytes)
        foreign.chmod(0o600)
        os.replace(foreign, self.target)
        with self.assertRaises(journal_module.JournalError):
            self.new_journal().reconstruct(self.master)


if __name__ == '__main__':
    unittest.main()
