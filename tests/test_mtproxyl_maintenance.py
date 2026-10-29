import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    'maintenance_timer_probe', Path(__file__).parent / 'fixtures/recovery/maintenance_timer_probe.py'
)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class MaintenanceLabTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='doh-maintenance-lab.', dir='/tmp')
        self.path = Path(self.tmp.name)
        self.target = self.path / 'target'
        self.target.write_bytes(b'original')
        self.target.chmod(0o600)
        lab.prepare(self.path, b'candidate')

    def tearDown(self):
        self.tmp.cleanup()

    def arm(self):
        with mock.patch.object(lab, 'properties', return_value={'LoadState': 'not-found'}), \
                mock.patch.object(lab.subprocess, 'run'), mock.patch.object(lab, 'verify_timer'):
            lab.arm(self.path, 15)

    def publish(self):
        with mock.patch.object(lab, 'verify_timer'):
            lab.publish(self.path)

    def test_recovery_after_publish_and_repeated_recovery(self):
        self.arm()
        self.publish()
        self.assertEqual(self.target.read_bytes(), b'candidate')
        lab.recover(self.path)
        lab.recover(self.path)
        self.assertEqual(self.target.read_bytes(), b'original')
        self.assertEqual(lab.load_plan(self.path)['state'], 'restored')

    def test_recovery_after_restore_rename_before_state_commit(self):
        self.arm()
        self.publish()
        os.replace(self.path / 'backup', self.target)
        lab.recover(self.path)
        self.assertEqual(self.target.read_bytes(), b'original')
        self.assertEqual(lab.load_plan(self.path)['state'], 'restored')

    def test_commit_prevents_later_rollback(self):
        self.arm()
        self.publish()
        with mock.patch.object(lab, 'verify_timer'):
            lab.commit(self.path)
        lab.recover(self.path)
        self.assertEqual(self.target.read_bytes(), b'candidate')

    def test_recovery_refuses_foreign_replacement_even_with_same_bytes(self):
        self.arm()
        self.publish()
        replacement = self.path / 'foreign'
        replacement.write_bytes(b'candidate')
        replacement.chmod(0o600)
        os.replace(replacement, self.target)
        with self.assertRaisesRegex(ValueError, 'externally'):
            lab.recover(self.path)
        self.assertEqual(self.target.read_bytes(), b'candidate')

    def test_publish_rejects_unarmed_and_unknown_timer(self):
        with self.assertRaisesRegex(ValueError, 'not armed'):
            lab.publish(self.path)
        self.arm()
        with mock.patch.object(lab, 'properties', return_value={'LoadState': 'not-found'}):
            with self.assertRaisesRegex(ValueError, 'timer identity'):
                lab.publish(self.path)
        self.assertEqual(self.target.read_bytes(), b'original')

    def test_refuses_replaced_backup_and_symlinks(self):
        self.arm()
        self.publish()
        (self.path / 'backup').unlink()
        (self.path / 'backup').symlink_to(self.target)
        with self.assertRaises(OSError):
            lab.recover(self.path)
        self.assertEqual(self.target.read_bytes(), b'candidate')

    def test_refuses_directory_outside_lab(self):
        with self.assertRaises(ValueError):
            lab.directory('/tmp')

    def test_arm_rejects_existing_unit(self):
        with mock.patch.object(lab, 'properties', return_value={'LoadState': 'loaded'}):
            with self.assertRaisesRegex(ValueError, 'already in use'):
                lab.arm(self.path, 15)
        self.assertEqual(lab.load_plan(self.path)['state'], 'prepared')


if __name__ == '__main__':
    unittest.main()
