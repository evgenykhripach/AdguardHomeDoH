import contextlib
import fcntl
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.lib import mtproxyl_front as front
from deploy.lib import mtproxyl_reload as reload
from tests.test_mtproxyl_front import ADMIN, DOMAIN, REALISTIC


class StartupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'vendor.conf'
        self.target = self.root / 'runtime.conf'
        self.lock = self.root / 'front.lock'
        self.nginx = self.root / 'nginx'
        self.source.write_text(REALISTIC)
        self.target.write_text(front.patch(REALISTIC, DOMAIN, ADMIN))
        self.target.chmod(0o600)
        self.nginx.write_text('#!/bin/sh\nexit 0\n')
        self.nginx.chmod(0o700)
        self.root_patch = mock.patch.object(reload, '_require_root')
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def run_prepare(self):
        return reload.prepare_startup(source=self.source, runtime_path=self.target, domain=DOMAIN,
                                      admin_host=ADMIN, nginx_bin=self.nginx, lock_path=self.lock)

    def test_success_preserves_vendor_and_installs_admin_overlay(self):
        self.target.write_text('old')
        self.assertEqual(self.run_prepare(), 'overlay')
        self.assertEqual(self.source.read_text(), REALISTIC)
        self.assertEqual(self.target.read_text(), front.patch(REALISTIC, DOMAIN, ADMIN))
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_invalid_vendor_uses_validated_previous(self):
        old = self.target.read_bytes()
        self.source.write_text('broken')
        self.assertEqual(self.run_prepare(), 'last-known-good')
        self.assertEqual(self.target.read_bytes(), old)

    def test_previous_requires_admin_overlay_and_valid_nginx(self):
        self.source.write_text('broken')
        self.target.write_text(front.patch(REALISTIC, DOMAIN))
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.target.write_text(front.patch(REALISTIC, DOMAIN, ADMIN))
        self.nginx.write_text('#!/bin/sh\necho secret >&2\nexit 1\n')
        with self.assertRaises(ValueError):
            self.run_prepare()

    def test_fallback_rejects_foreign_change_during_validation(self):
        self.source.write_text('broken')
        def change(*args, **kwargs):
            self.target.write_text('foreign')
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(reload.subprocess, 'run', side_effect=change):
            with self.assertRaises(ValueError):
                self.run_prepare()
        self.assertEqual(self.target.read_text(), 'foreign')

    def test_publish_failure_never_claims_fallback(self):
        with mock.patch.object(reload.runtime, 'publish', side_effect=OSError('failure')):
            with self.assertRaises(OSError):
                self.run_prepare()

    def test_rejects_symlink_and_unsafe_lock_or_runtime(self):
        self.lock.symlink_to(self.target)
        with self.assertRaises(OSError):
            self.run_prepare()
        self.lock.unlink()
        self.lock.write_text('')
        self.lock.chmod(0o666)
        with self.assertRaises(ValueError):
            self.run_prepare()
        self.lock.chmod(0o600)
        self.target.chmod(0o644)
        with self.assertRaises(ValueError):
            self.run_prepare()

    def test_cli_failure_does_not_leak_nginx_output(self):
        self.source.write_text('broken')
        self.nginx.write_text('#!/bin/sh\necho SECRET_MARKER >&2\nexit 1\n')
        stderr = io.StringIO()
        argv = ['program', '--source', str(self.source), '--runtime', str(self.target),
                '--domain', DOMAIN, '--admin-host', ADMIN, '--nginx-bin', str(self.nginx), '--lock', str(self.lock)]
        with mock.patch('sys.argv', argv), contextlib.redirect_stderr(stderr):
            self.assertEqual(reload.main(), 1)
        self.assertNotIn('SECRET_MARKER', stderr.getvalue())

    def test_busy_lock_fails_without_waiting(self):
        self.lock.write_text('')
        self.lock.chmod(0o600)
        with self.lock.open('r+') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError):
                self.run_prepare()

    def run_reload(self):
        return reload.reload_running(source=self.source, runtime_path=self.target, domain=DOMAIN,
                                     admin_host=ADMIN, nginx_bin=self.nginx, lock_path=self.lock,
                                     main_pid=123, cgroup='/system.slice/example.service')

    def test_reload_publishes_before_signal(self):
        self.source.write_text(REALISTIC.replace('worker_processes 1;', 'worker_processes 2;'))
        with mock.patch.object(reload.controller, 'inspect_master', return_value='master'), \
             mock.patch.object(reload.controller, '_recheck_master'), \
             mock.patch.object(reload.controller, '_assert_binary'), \
             mock.patch.object(reload.controller, '_signal_checked') as signal:
            signal.side_effect = lambda *args: self.assertIn('worker_processes 2;', self.target.read_text())
            self.run_reload()
            signal.assert_called_once()
            self.assertIn(front.ADMIN_HTTP_PATH, self.target.read_text())

    def test_reload_validation_failure_preserves_runtime_and_does_not_signal(self):
        old = self.target.read_bytes()
        self.source.write_text('broken')
        with mock.patch.object(reload.controller, 'inspect_master', return_value='master'), \
             mock.patch.object(reload.controller, '_signal_checked') as signal:
            with self.assertRaises(ValueError):
                self.run_reload()
            signal.assert_not_called()
        self.assertEqual(self.target.read_bytes(), old)

    def test_reload_signal_failure_is_reported_after_publish(self):
        self.source.write_text(REALISTIC.replace('worker_processes 1;', 'worker_processes 2;'))
        with mock.patch.object(reload.controller, 'inspect_master', return_value='master'), \
             mock.patch.object(reload.controller, '_recheck_master'), \
             mock.patch.object(reload.controller, '_assert_binary'), \
             mock.patch.object(reload.controller, '_signal_checked', side_effect=OSError('signal failed')):
            with self.assertRaises(OSError):
                self.run_reload()
        self.assertIn('worker_processes 2;', self.target.read_text())

    def test_reload_rejects_unverified_master_before_publish(self):
        old = self.target.read_bytes()
        with mock.patch.object(reload.controller, 'inspect_master', side_effect=reload.controller.IdentityError):
            with self.assertRaises(reload.controller.IdentityError):
                self.run_reload()
        self.assertEqual(self.target.read_bytes(), old)

    def test_root_required(self):
        self.root_patch.stop()
        if os.geteuid() != 0:
            with self.assertRaises(ValueError):
                self.run_prepare()


if __name__ == '__main__':
    unittest.main()
