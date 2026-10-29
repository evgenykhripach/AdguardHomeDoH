import hashlib
import json
import os
import signal
import stat
import sys
import time
import stat
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.lib import mtproxyl_front as front
from deploy.lib import mtproxyl_runtime as runtime
from tests.test_mtproxyl_front import DOMAIN, REALISTIC


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name).resolve()
        self.source = self.folder / 'vendor.conf'
        self.target = self.folder / 'runtime.conf'
        self.nginx = self.folder / 'nginx'
        self.source.write_text(REALISTIC)
        self.target.write_text('previous runtime')
        self.target.chmod(0o600)
        self.stub('exit 0')

    def tearDown(self):
        self.temp.cleanup()

    def stub(self, body):
        self.nginx.write_text('#!/bin/sh\n' + body + '\n')
        self.nginx.chmod(0o700)

    def prepare(self, **kwargs):
        return runtime.prepare(self.source, self.target, DOMAIN, self.nginx, **kwargs)

    def test_overlay_success_keeps_vendor_and_private_runtime(self):
        before = self.source.stat()
        self.assertEqual(self.prepare(), 'overlay')
        self.assertEqual(self.source.read_text(), REALISTIC)
        self.assertEqual(self.source.stat().st_ino, before.st_ino)
        self.assertEqual(self.target.read_text(), front.patch(REALISTIC, DOMAIN))
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.target.stat().st_uid, os.geteuid())
        first = self.target.stat().st_ino
        self.assertEqual(self.prepare(), 'overlay')
        self.assertEqual(self.target.stat().st_ino, first)
        self.assertFalse(list(self.folder.glob('.*.doh-*')))

    def test_stage_journals_exact_candidate_before_same_inode_publish(self):
        before = self.target.read_bytes()
        with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
            self.assertEqual(self.target.read_bytes(), before)
            staged = Path(candidate.candidate_path)
            self.assertTrue(staged.is_file())
            self.assertEqual(candidate.candidate_identity[1], staged.stat().st_ino)
            self.assertEqual(candidate.candidate_exact[1:], (staged.stat().st_mtime_ns, staged.stat().st_ctime_ns))
            self.assertEqual(runtime.publish(candidate), 'overlay')
            after = self.target.stat()
            self.assertEqual((after.st_dev, after.st_ino), candidate.candidate_identity[:2])
            self.assertEqual(after.st_mtime_ns, candidate.candidate_exact[1])
            self.assertEqual(self.target.read_bytes(), candidate.candidate_identity[-1])
            self.assertEqual(hashlib.sha256(self.target.read_bytes()).digest(), candidate.candidate_identity[-2])
            self.assertFalse(staged.exists())
        self.assertEqual(self.source.read_text(), REALISTIC)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux rename ctime check')
    def test_linux_rename_allows_ctime_change_but_preserves_inode_and_mtime(self):
        with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
            before = Path(candidate.candidate_path).stat()
            time.sleep(.02)
            self.assertEqual(runtime.publish(candidate), 'overlay')
            after = self.target.stat()
            self.assertEqual((after.st_dev, after.st_ino, after.st_mtime_ns),
                             (before.st_dev, before.st_ino, before.st_mtime_ns))
            self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)

    def test_stage_and_publish_fsync_file_and_parent_in_order(self):
        actual = os.fsync
        events = []
        def tracked(fd):
            events.append('dir' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            return actual(fd)
        with mock.patch.object(runtime.os, 'fsync', side_effect=tracked):
            with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
                self.assertEqual(events, ['file', 'dir'])
                runtime.publish(candidate)
                self.assertEqual(events, ['file', 'dir', 'file', 'dir'])

    def test_stage_fsync_failure_does_not_publish(self):
        actual = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('simulated directory fsync failure')
            return actual(fd)
        with mock.patch.object(runtime.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(OSError):
                runtime.stage(self.source, self.target, DOMAIN, self.nginx)
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertFalse(list(self.folder.glob('.*.doh-*')))

    def test_stage_rejects_same_bytes_different_candidate_inode(self):
        with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
            name = Path(candidate.candidate_path)
            foreign = self.folder / 'foreign'
            foreign.write_bytes(name.read_bytes())
            foreign.chmod(0o600)
            os.replace(foreign, name)
            foreign_inode = name.stat().st_ino
            with self.assertRaises(RuntimeError):
                runtime.publish(candidate)
            self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertEqual(name.stat().st_ino, foreign_inode)

    def test_stage_rejects_source_or_candidate_metadata_aba(self):
        with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
            before = self.source.stat()
            self.source.write_bytes(self.source.read_bytes())
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaises(RuntimeError):
                runtime.publish(candidate)
        self.assertEqual(self.target.read_text(), 'previous runtime')
        with runtime.stage(self.source, self.target, DOMAIN, self.nginx) as candidate:
            path = Path(candidate.candidate_path)
            before = path.stat()
            path.write_bytes(path.read_bytes())
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaises(RuntimeError):
                runtime.publish(candidate)
        self.assertEqual(self.target.read_text(), 'previous runtime')

    def test_stage_close_and_unpublished_failure_preserve_runtime(self):
        candidate = runtime.stage(self.source, self.target, DOMAIN, self.nginx)
        path = Path(candidate.candidate_path)
        candidate.close()
        candidate.close()
        self.assertFalse(path.exists())
        self.assertEqual(self.target.read_text(), 'previous runtime')
        with self.assertRaises(ValueError):
            runtime.publish(candidate)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux SIGKILL crash window')
    def test_sigkill_after_rename_leaves_journaled_candidate_identity(self):
        script = r"""
import hashlib, json, os, signal, sys
from pathlib import Path
from deploy.lib import mtproxyl_runtime as r
source, target, nginx, journal = map(Path, sys.argv[1:])
s = r.stage(source, target, 'dns.example.com', nginx)
base, mtime, ctime = s.candidate_exact
record = {'dev':base[0], 'ino':base[1], 'mode':base[2], 'uid':base[3], 'gid':base[4],
          'nlink':base[5], 'sha256':base[6].hex(), 'mtime':mtime, 'pre_ctime':ctime,
          'candidate_path':s.candidate_path}
with journal.open('x') as f:
 os.fchmod(f.fileno(),0o600); json.dump(record,f); f.flush(); os.fsync(f.fileno())
dirfd=os.open(journal.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dirfd); os.close(dirfd)
os.replace(s.candidate_name,s.runtime_name,src_dir_fd=s.runtime_parent,dst_dir_fd=s.runtime_parent)
os.kill(os.getpid(), signal.SIGKILL)
"""
        journal = self.folder / 'journal.json'
        result = subprocess.run([sys.executable, '-c', script, str(self.source), str(self.target),
                                 str(self.nginx), str(journal)], capture_output=True)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        record = json.loads(journal.read_text())
        actual = self.target.stat()
        self.assertEqual((actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid,
                          actual.st_nlink, actual.st_mtime_ns),
                         (record['dev'], record['ino'], record['mode'], record['uid'], record['gid'],
                          record['nlink'], record['mtime']))
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(), record['sha256'])
        self.assertEqual(self.source.read_text(), REALISTIC)

    def test_patch_failure_strict_and_fallback(self):
        self.source.write_text('events {}\n')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertEqual(self.prepare(allow_fallback=True), 'degraded')
        self.assertEqual(self.target.read_text(), 'events {}\n')
        self.assertEqual(self.source.read_text(), 'events {}\n')

    def test_nginx_rejection_fallback_and_both_rejected(self):
        self.stub('if grep -q "BEGIN DOHDNS" "$3"; then exit 1; fi\nexit 0')
        with self.assertRaises(runtime.CandidateInvalid):
            self.prepare()
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertEqual(self.prepare(allow_fallback=True), 'degraded')
        self.assertEqual(self.target.read_text(), REALISTIC)
        self.target.write_text('previous runtime')
        self.stub('exit 1')
        with self.assertRaises(runtime.CandidateInvalid):
            self.prepare(allow_fallback=True)
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertFalse(list(self.folder.glob('.*.doh-*')))

    def test_source_change_during_nginx_test_aborts(self):
        self.stub("printf 'changed' > " + str(self.source) + '\nexit 0')
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.assertEqual(self.source.read_text(), 'changed')
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertFalse(list(self.folder.glob('.*.doh-*')))

    def test_runtime_and_candidate_tampering_abort_even_with_fallback(self):
        self.stub("printf 'changed' > " + str(self.target) + '\nexit 0')
        with self.assertRaises(RuntimeError):
            self.prepare(allow_fallback=True)
        self.assertEqual(self.target.read_text(), 'changed')
        self.target.write_text('previous runtime')
        self.stub('printf tampered > "$3"\nexit 0')
        with self.assertRaises(RuntimeError):
            self.prepare(allow_fallback=True)
        self.assertEqual(self.target.read_text(), 'previous runtime')
        self.assertFalse(list(self.folder.glob('.*.doh-*')))

    def test_symlinks_hardlinks_and_unsafe_directory_rejected(self):
        link = self.folder / 'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            runtime.prepare(link, self.target, DOMAIN, self.nginx)
        link.unlink()
        os.link(self.source, link)
        with self.assertRaises(ValueError):
            self.prepare()
        link.unlink()
        self.target.unlink()
        self.target.symlink_to(self.source)
        with self.assertRaises(OSError):
            self.prepare()
        self.target.unlink()
        self.target.write_text('previous runtime')
        os.link(self.target, link)
        with self.assertRaises(ValueError):
            self.prepare()
        link.unlink()
        unsafe = self.folder / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with self.assertRaises(ValueError):
            runtime.prepare(self.source, unsafe / 'runtime', DOMAIN, self.nginx)
        parent_link = self.folder / 'dirlink'
        parent_link.symlink_to(unsafe, target_is_directory=True)
        with self.assertRaises(OSError):
            runtime.prepare(self.source, parent_link / 'runtime', DOMAIN, self.nginx)

    def test_generation_marker_render_and_fallback(self):
        marker = self.folder / 'generation.sock'
        generation = '0123456789abcdef0123456789abcdef'
        self.assertEqual(runtime.prepare(self.source, self.target, DOMAIN, self.nginx,
                                         marker_socket=marker, generation=generation), 'overlay')
        content = self.target.read_text()
        self.assertIn('listen unix:' + str(marker) + ';', content)
        self.assertIn('return 200 "' + generation + ' $pid";', content)
        self.assertIn('access_log off;', content)
        self.assertEqual(self.source.read_text(), REALISTIC)
        with self.assertRaises(ValueError):
            runtime.patch_with_generation(REALISTIC, DOMAIN, marker, 'not-a-generation')
        with self.assertRaises(ValueError):
            runtime.patch_with_generation(content, DOMAIN, marker, generation)
        self.source.write_text('events {}')
        self.assertEqual(runtime.prepare(self.source, self.target, DOMAIN, self.nginx,
                                         allow_fallback=True, marker_socket=marker,
                                         generation=generation), 'degraded')
        self.assertEqual(self.target.read_text(), 'events {}')

    def test_probe_generation_reports_worker_and_rejects_mismatch(self):
        path = self.folder / 'generation.sock'
        generation = 'a' * 32
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.geteuid(), st_dev=1, st_ino=2)
        def probe(body):
            connection = mock.MagicMock()
            connection.recv.side_effect = [b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n' + body, b'']
            factory = mock.MagicMock()
            factory.return_value.__enter__.return_value = connection
            with mock.patch.object(runtime.os, 'stat', return_value=info), \
                 mock.patch.object(runtime.socket, 'socket', factory):
                return runtime.probe_generation(path, generation)
        self.assertEqual(probe((generation + ' 123').encode()), 123)
        with self.assertRaises(ValueError):
            probe(('b' * 32 + ' 123').encode())
        path.symlink_to(self.source)
        with self.assertRaises(ValueError):
            runtime.probe_generation(path, generation)

    def test_generation_socket_requires_private_directory(self):
        self.folder.chmod(0o755)
        try:
            with self.assertRaises(ValueError):
                runtime.patch_with_generation(REALISTIC, DOMAIN, self.folder / 'marker.sock', 'a' * 32)
        finally:
            self.folder.chmod(0o700)

    def test_writable_vendor_or_runtime_is_rejected(self):
        for mode in (0o664, 0o606, 0o666):
            with self.subTest(file='vendor', mode=mode):
                self.source.chmod(mode)
                with self.assertRaises(ValueError):
                    self.prepare(allow_fallback=True)
                self.assertEqual(self.target.read_text(), 'previous runtime')
                self.assertEqual(self.source.read_text(), REALISTIC)
                self.source.chmod(0o644)
            with self.subTest(file='runtime', mode=mode):
                self.target.chmod(mode)
                with self.assertRaises(ValueError):
                    self.prepare(allow_fallback=True)
                self.assertEqual(self.target.read_text(), 'previous runtime')
                self.assertEqual(self.source.read_text(), REALISTIC)
                self.target.chmod(0o600)
        self.source.chmod(0o644)
        self.target.chmod(0o644)
        self.assertEqual(self.prepare(), 'overlay')
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_cli_generation_prepare_and_missing_probe(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_runtime.py'
        marker = self.folder / 'generation.sock'
        generation = 'a' * 32
        command = ['python3', str(script), '--source', str(self.source), '--runtime', str(self.target),
                   '--domain', DOMAIN, '--nginx-bin', str(self.nginx), '--marker-socket', str(marker),
                   '--generation', generation]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'overlay\n', ''))
        self.assertIn('return 200 "' + generation + ' $pid";', self.target.read_text())
        result = subprocess.run(['python3', str(script), 'probe-generation', '--socket', str(marker),
                                 '--generation', generation], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'error: generation probe failed\n')
        with self.assertRaises(ValueError):
            runtime.prepare(self.source, self.target, DOMAIN, self.nginx, marker_socket=marker)

    def test_cli_only_status_and_generic_errors(self):
        script = Path(__file__).resolve().parents[1] / 'deploy/lib/mtproxyl_runtime.py'
        cmd = ['python3', str(script), '--source', str(self.source), '--runtime', str(self.target),
               '--domain', DOMAIN, '--nginx-bin', str(self.nginx)]
        self.stub('echo secret_config_to_stderr >&2\nexit 0')
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'overlay\n', ''))
        self.stub('echo secret_config_to_stderr >&2\nexit 1')
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('secret_config_to_stderr', result.stderr)
        self.assertNotIn('server_name', result.stderr)
        self.stub('if grep -q "BEGIN DOHDNS" "$3"; then exit 1; fi\nexit 0')
        result = subprocess.run(cmd + ['--allow-fallback'], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'degraded\n', ''))


if __name__ == '__main__':
    unittest.main()
