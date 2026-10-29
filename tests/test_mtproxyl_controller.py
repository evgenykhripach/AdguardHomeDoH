import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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

    def inspect(self, **overrides):
        # The fake /proc directory is owned by the local test user, whereas a
        # real system nginx master must be root owned.
        real_stat = os.stat
        def fake_stat(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            if Path(path) == self.node:
                values = list(value)
                values[4] = 0
                return os.stat_result(values)
            return value
        with mock.patch.object(controller.os, 'stat', side_effect=fake_stat):
            return controller.inspect_master(
                overrides.get('pid', 123), overrides.get('binary', self.binary),
                overrides.get('runtime', self.runtime), overrides.get('cgroup', self.cgroup),
                proc_root=self.proc,
            )

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

    def test_missing_metadata_and_invalid_inputs_rejected(self):
        (self.node / 'exe').unlink()
        with self.assertRaises(controller.IdentityError):
            self.inspect()
        with self.assertRaises(controller.IdentityError):
            self.inspect(pid=0)
        with self.assertRaises(controller.IdentityError):
            self.inspect(runtime=Path('relative.conf'))


if __name__ == '__main__':
    unittest.main()
