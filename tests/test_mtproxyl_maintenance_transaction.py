import json
import os
import signal
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from deploy.lib import mtproxyl_maintenance as maintenance


class FakeSystemd:
    def __init__(self):
        self.states = {unit: {'load': 'loaded', 'active': True, 'enabled': 'enabled', 'auto_restart': False, 'degraded': ''}
                       for unit in maintenance.UNITS}
        self.states['adguardhome-doh-health.service'] = {'load': 'loaded', 'active': False, 'enabled': 'static', 'auto_restart': False, 'degraded': ''}
        self.commands = []
        self.current_override = {}
        self.jobs = ''

    def __call__(self, argv, **kwargs):
        self.commands.append(argv)
        action = argv[1]
        if action == 'list-jobs':
            return SimpleNamespace(stdout=self.jobs)
        if action == 'show':
            state = self.states[argv[2]]
            if 'MainPID' in argv[3]:
                current = self.current_override.get(argv[2], 'activating' if state['auto_restart'] else ('active' if state['active'] else 'inactive'))
                if argv[2].endswith('.timer'):
                    return SimpleNamespace(stdout='LoadState=%s\nActiveState=%s\n' % (state['load'], current))
                return SimpleNamespace(stdout='LoadState=%s\nActiveState=%s\nMainPID=0\nControlGroup=\n' % (state['load'], current))
            return SimpleNamespace(stdout='LoadState=%s\nActiveState=%s\nSubState=%s\nUnitFileState=%s\n' %
                (state['load'], 'activating' if state['auto_restart'] else ('failed' if state['degraded'] == 'failed' else ('active' if state['active'] else 'inactive')),
                 (state['degraded'] or 'auto-restart') if state['auto_restart'] else ('failed' if state['degraded'] == 'failed' else ('running' if state['active'] else 'dead')),
                 '' if state['load'] == 'not-found' else state['enabled']))
        if action in ('start', 'stop'):
            self.states[argv[2]]['active'] = action == 'start'
            self.states[argv[2]]['auto_restart'] = False
            self.states[argv[2]]['degraded'] = ''
            self.current_override.pop(argv[2], None)
        if action in ('enable', 'disable'):
            self.states[argv[2]]['enabled'] = 'enabled' if action == 'enable' else 'disabled'
        return SimpleNamespace(stdout='')


class MaintenanceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.systemd = FakeSystemd()
        self.yaml = self.root / 'opt/AdGuardHome/AdGuardHome.yaml'
        self.yaml.parent.mkdir(parents=True)
        self.yaml.write_text('user settings\n')
        self.extra = self.root / 'etc/adguardhome-doh/mtproxyl-admin-acme.conf'
        self.extra.parent.mkdir(parents=True)
        self.extra.write_text('previous admin\n')
        self.unrelated = self.extra.parent / 'unrelated'
        self.unrelated.write_text('keep\n')
        self.snapshot = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)

    def test_restore_files_and_unit_states(self):
        self.yaml.write_text('changed\n')
        self.extra.write_text('changed\n')
        new = self.root / 'etc/adguardhome-doh/mtproxyl-sni.map'
        new.write_text('new\n')
        expected = {unit: dict(state) for unit, state in self.systemd.states.items()}
        self.systemd.states['nginx.service']['enabled'] = 'disabled'
        maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertEqual(self.yaml.read_text(), 'user settings\n')
        self.assertEqual(self.extra.read_text(), 'previous admin\n')
        self.assertFalse(new.exists())
        self.assertEqual(self.unrelated.read_text(), 'keep\n')
        self.assertEqual(self.systemd.states, expected)

    def test_tamper_rejected_before_any_stop(self):
        data = json.loads((self.snapshot / 'snapshot.json').read_text())
        (self.snapshot / data['extra'][0]['name']).write_text('corrupt')
        before = len(self.systemd.commands)
        with self.assertRaises(RuntimeError):
            maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertFalse(any(command[1] == 'stop' for command in self.systemd.commands[before:]))

    def test_unsupported_unit_state_rejected(self):
        self.systemd.states['nginx.service']['enabled'] = 'masked'
        with self.assertRaises(RuntimeError):
            maintenance.snapshot(self.root, 'dns.example.com', self.systemd)

    def test_certbot_files_remain_at_current_state(self):
        hook = self.root / 'etc/letsencrypt/renewal-hooks/deploy/adguardhome-doh-reload'
        renewal = self.root / 'etc/letsencrypt/renewal/dns.example.com.conf'
        hook.parent.mkdir(parents=True)
        renewal.parent.mkdir(parents=True)
        hook.write_text('old hook')
        renewal.write_text('old renewal')
        snap = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)
        hook.write_text('renewed hook')
        renewal.write_text('renewed profile')
        maintenance.restore(self.root, snap, self.systemd)
        self.assertEqual(hook.read_text(), 'renewed hook')
        self.assertEqual(renewal.read_text(), 'renewed profile')

    def test_original_nginx_auto_restart_left_stopped_with_enablement(self):
        nginx = self.systemd.states['nginx.service']
        nginx['active'] = False
        nginx['auto_restart'] = True
        nginx['degraded'] = 'auto-restart'
        snap = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)
        warnings = maintenance.restore(self.root, snap, self.systemd)
        self.assertEqual(nginx, {'load': 'loaded', 'active': False, 'enabled': 'enabled', 'auto_restart': False, 'degraded': ''})
        self.assertEqual(len(warnings), 1)
        self.assertTrue(self.systemd.states['mtproxyl-pq-nginx.service']['active'])
        self.assertTrue(self.systemd.states['adguardhome-doh.service']['active'])

    def test_failed_health_and_nginx_start_restore_with_warnings(self):
        nginx = self.systemd.states['nginx.service']
        nginx.update(active=False, auto_restart=True, degraded='start', enabled='enabled')
        health = self.systemd.states['adguardhome-doh-health.service']
        health.update(active=False, degraded='failed', enabled='disabled')
        snap = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)
        saved = maintenance.validate(snap)['units']
        self.assertEqual(saved['nginx.service']['degraded'], 'start')
        self.assertEqual(saved['adguardhome-doh-health.service']['degraded'], 'failed')
        warnings = maintenance.restore(self.root, snap, self.systemd)
        self.assertEqual(len(warnings), 2)
        self.assertFalse(nginx['active'])
        self.assertEqual(nginx['enabled'], 'enabled')
        self.assertFalse(health['active'])
        self.assertEqual(health['enabled'], 'disabled')
        self.assertTrue(self.systemd.states['adguardhome-doh-health.timer']['active'])

    def test_nginx_cycle_can_change_substate_during_snapshot(self):
        nginx = self.systemd.states['nginx.service']
        nginx.update(active=False, auto_restart=True, degraded='start')
        real = self.systemd
        count = 0
        def runner(argv, **kwargs):
            nonlocal count
            if argv[1:3] == ['show', 'nginx.service'] and 'SubState' in argv[3]:
                count += 1
                if count == 2:
                    nginx['degraded'] = 'auto-restart'
            return real(argv, **kwargs)
        snap = maintenance.snapshot(self.root, 'dns.example.com', runner)
        self.assertEqual(maintenance.validate(snap)['units']['nginx.service']['degraded'], 'auto-restart')

    def test_not_found_private_unit_remains_not_found(self):
        private = self.systemd.states['adguardhome-doh-nginx.service']
        private.update(load='not-found', active=False, enabled='not-found')
        snap = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)
        maintenance.restore(self.root, snap, self.systemd)
        self.assertEqual(private, {'load': 'not-found', 'active': False, 'enabled': 'not-found', 'auto_restart': False, 'degraded': ''})

    def test_disabled_private_unit_restored(self):
        private = self.systemd.states['adguardhome-doh-nginx.service']
        private.update(active=False, enabled='disabled')
        snap = maintenance.snapshot(self.root, 'dns.example.com', self.systemd)
        private.update(active=True, enabled='enabled')
        maintenance.restore(self.root, snap, self.systemd)
        self.assertEqual(private, {'load': 'loaded', 'active': False, 'enabled': 'disabled', 'auto_restart': False, 'degraded': ''})

    def test_concurrent_yaml_change_rejects_snapshot(self):
        original = maintenance.manager.create_backup
        def copy_then_change(*args, **kwargs):
            result = original(*args, **kwargs)
            self.yaml.write_text('changed during snapshot\n')
            return result
        with patch.object(maintenance.manager, 'create_backup', side_effect=copy_then_change):
            with self.assertRaisesRegex(RuntimeError, 'snapshot source changed'):
                maintenance.snapshot(self.root, 'dns.example.com', self.systemd)

    def test_restore_stops_failed_and_transitioning_units(self):
        self.systemd.current_override.update({'adguardhome-doh.service': 'failed',
            'mtproxyl-pq-nginx.service': 'activating', 'nginx.service': 'deactivating'})
        maintenance.restore(self.root, self.snapshot, self.systemd)
        stopped = [cmd[2] for cmd in self.systemd.commands if cmd[1] == 'stop']
        for unit in ('adguardhome-doh.service', 'mtproxyl-pq-nginx.service', 'nginx.service'):
            self.assertIn(unit, stopped)
        self.assertTrue(self.systemd.states['adguardhome-doh.service']['active'])
        self.assertTrue(self.systemd.states['mtproxyl-pq-nginx.service']['active'])

    def test_stopping_recovery_preserves_stopped_yaml(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        self.yaml.write_text('saved by stopping AdGuard\n')
        maintenance.restore(self.root, self.snapshot, self.systemd, yaml_checkpoint=True)
        self.assertEqual(self.yaml.read_text(), 'saved by stopping AdGuard\n')

    def test_settled_recovery_uses_yaml_after_stop(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        self.yaml.write_text('saved by stopping AdGuard\n')
        maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
        self.yaml.write_text('published candidate\n')
        maintenance.restore(self.root, self.snapshot, self.systemd, yaml_checkpoint=True)
        self.assertEqual(self.yaml.read_text(), 'saved by stopping AdGuard\n')

    def test_checkpoint_detected_automatically_and_cannot_be_bypassed(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        self.yaml.write_text('saved after stop\n')
        with self.assertRaisesRegex(RuntimeError, 'cannot ignore'):
            maintenance.restore(self.root, self.snapshot, self.systemd, yaml_checkpoint=False)
        maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertEqual(self.yaml.read_text(), 'saved after stop\n')

    def test_yaml_change_during_settle_is_rejected(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        original = maintenance.manager._copy_path
        def copy_then_modify(source, target):
            original(source, target)
            self.yaml.write_text('concurrent write\n')
        with patch.object(maintenance.manager, '_copy_path', side_effect=copy_then_modify):
            with self.assertRaisesRegex(RuntimeError, 'YAML changed'):
                maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
        self.assertEqual(maintenance._checkpoint_read(self.snapshot)['phase'], 'STOPPING')

    def test_exception_during_settled_publication_leaves_stopping(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        with patch.object(maintenance.os, 'replace', side_effect=OSError('failure')):
            with self.assertRaisesRegex(RuntimeError, 'outcome ambiguous'):
                maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
        self.assertEqual(maintenance._checkpoint_read(self.snapshot)['phase'], 'STOPPING')

    def test_unknown_checkpoint_phase_fails_before_stop(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        (self.snapshot / 'yaml-checkpoint.json').write_text('{"version": 1, "phase": "UNKNOWN"}')
        before = len(self.systemd.commands)
        with self.assertRaisesRegex(RuntimeError, 'invalid YAML checkpoint'):
            maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertFalse(any(command[1] == 'stop' for command in self.systemd.commands[before:]))

    def test_replaced_settled_inode_is_rejected(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        data = maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
        original = self.snapshot / data['file']
        replacement = self.snapshot / 'replacement'
        shutil.copy2(original, replacement)
        os.replace(replacement, original)
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            maintenance.restore(self.root, self.snapshot, self.systemd)

    def test_fsync_failure_after_publication_keeps_settled_file(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        original = maintenance._sync_dir
        calls = 0
        def fail_last(path):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError('simulated fsync failure')
            original(path)
        with patch.object(maintenance, '_sync_dir', side_effect=fail_last):
            with self.assertRaisesRegex(RuntimeError, 'outcome ambiguous'):
                maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
        state = maintenance._checkpoint_read(self.snapshot)
        self.assertEqual(state['phase'], 'SETTLED')
        self.assertTrue((self.snapshot / state['file']).exists())

    def test_checkpoint_rejects_unconfirmed_stop(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        with self.assertRaises(RuntimeError):
            maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=lambda: False)
        self.assertEqual(maintenance._checkpoint_read(self.snapshot)['phase'], 'STOPPING')

    def test_kill_before_settled_publication_preserves_current_yaml(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        self.yaml.write_text('saved by stopping AdGuard\n')
        child = os.fork()
        if child == 0:
            original = maintenance.manager._copy_path
            def killed_after_copy(source, target):
                original(source, target)
                os.kill(os.getpid(), signal.SIGKILL)
            with patch.object(maintenance.manager, '_copy_path', side_effect=killed_after_copy):
                maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
            os._exit(1)
        _, status = os.waitpid(child, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(maintenance._checkpoint_read(self.snapshot)['phase'], 'STOPPING')
        maintenance.restore(self.root, self.snapshot, self.systemd, yaml_checkpoint=True)
        self.assertEqual(self.yaml.read_text(), 'saved by stopping AdGuard\n')

    def test_kill_after_settled_publication_restores_checkpoint(self):
        yes = lambda: True
        maintenance.yaml_mark_stopping(self.snapshot, locks_held=yes, writer_fenced=yes)
        self.yaml.write_text('saved by stopping AdGuard\n')
        child = os.fork()
        if child == 0:
            original = maintenance.os.replace
            def killed_after_replace(source, target):
                original(source, target)
                if str(target).endswith('yaml-checkpoint.json'):
                    os.kill(os.getpid(), signal.SIGKILL)
            with patch.object(maintenance.os, 'replace', side_effect=killed_after_replace):
                maintenance.yaml_settle(self.root, self.snapshot, locks_held=yes, writer_fenced=yes, adguard_stopped=yes)
            os._exit(1)
        _, status = os.waitpid(child, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(maintenance._checkpoint_read(self.snapshot)['phase'], 'SETTLED')
        self.yaml.write_text('published candidate\n')
        maintenance.restore(self.root, self.snapshot, self.systemd, yaml_checkpoint=True)
        self.assertEqual(self.yaml.read_text(), 'saved by stopping AdGuard\n')

    def test_pending_timer_job_prevents_restore(self):
        self.yaml.write_text('changed\n')
        self.systemd.jobs = '42 adguardhome-doh-health.timer start waiting\n'
        with self.assertRaisesRegex(RuntimeError, 'pending systemd job'):
            maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertEqual(self.yaml.read_text(), 'changed\n')

    def test_timer_show_only_load_and_active(self):
        state, pid = maintenance._stoppable_state('adguardhome-doh-health.timer', self.systemd)
        self.assertEqual(pid, 0)
        self.assertEqual(state['ControlGroup'], '')
        self.assertEqual(state['ActiveState'], 'active')

    def test_populated_cgroup_prevents_restore(self):
        self.yaml.write_text('changed\n')
        with patch.object(maintenance, '_cgroup_empty', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'unit did not stop completely'):
                maintenance.restore(self.root, self.snapshot, self.systemd)
        self.assertEqual(self.yaml.read_text(), 'changed\n')

    def test_stop_failure_does_not_restore_files(self):
        self.yaml.write_text('changed\n')
        def fail_stop(argv, **kwargs):
            if argv[1] == 'stop':
                raise RuntimeError('stop failed')
            return self.systemd(argv, **kwargs)
        with self.assertRaises(RuntimeError):
            maintenance.restore(self.root, self.snapshot, fail_stop)
        self.assertEqual(self.yaml.read_text(), 'changed\n')

    def test_outside_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            maintenance.restore(self.root, self.root / self.snapshot.name, self.systemd)


class WatchdogIdentityTests(unittest.TestCase):
    transaction = 'a' * 32
    boot = 'a2345678-1234-1234-1234-123456789abc'

    @staticmethod
    def runner(fields):
        def run(argv, **kwargs):
            return SimpleNamespace(stdout=''.join(key + '=' + value + '\n' for key, value in fields.items()))
        return run

    def test_writer_incarnation_records_pid_start_and_systemd_identity(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        with patch.object(maintenance, '_boot_id', return_value=self.boot), patch.object(maintenance, '_process_start', return_value=321), patch.object(maintenance, '_process_cgroup', return_value='/system.slice/' + unit):
            identity = maintenance.writer_identity(self.transaction, self.runner(fields))
        self.assertEqual(identity['unit'], unit)
        self.assertEqual(identity['invocation_id'], 'b' * 32)
        self.assertEqual(identity['proc_starttime'], 321)

    def test_writer_replaced_between_observations_is_rejected(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        calls = 0
        def runner(argv, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                fields['InvocationID'] = 'c' * 32
            return self.runner(fields)(argv, **kwargs)
        with patch.object(maintenance, '_boot_id', return_value=self.boot), patch.object(maintenance, '_process_start', return_value=321), patch.object(maintenance, '_process_cgroup', return_value='/system.slice/' + unit):
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                maintenance.writer_identity(self.transaction, runner)

    def test_process_cgroup_v2_parser(self):
        with patch.object(Path, 'read_text', return_value='0::/system.slice/example.service\n'):
            self.assertEqual(maintenance._process_cgroup(123), '/system.slice/example.service')
        for invalid in ('1:name=/system.slice/example.service\n', '0::/system.slice/../other\n',
                        '0::/system.slice/a\n1:name=/other\n'):
            with patch.object(Path, 'read_text', return_value=invalid):
                with self.assertRaises(RuntimeError):
                    maintenance._process_cgroup(123)

    def test_writer_process_cgroup_changes_during_observation(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        with patch.object(maintenance, '_boot_id', return_value=self.boot), patch.object(maintenance, '_process_start', return_value=321), patch.object(maintenance, '_process_cgroup', side_effect=['/system.slice/' + unit, '/other.slice/a.service']):
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                maintenance.writer_identity(self.transaction, self.runner(fields))

    def test_writer_process_cgroup_mismatch_rejected(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        with patch.object(maintenance, '_boot_id', return_value=self.boot), patch.object(maintenance, '_process_start', return_value=321), patch.object(maintenance, '_process_cgroup', return_value='/other.slice/unrelated.service'):
            with self.assertRaisesRegex(RuntimeError, 'cgroup does not match'):
                maintenance.writer_identity(self.transaction, self.runner(fields))

    def test_writer_pid_reused_during_observation_rejected(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        with patch.object(maintenance, '_boot_id', return_value=self.boot), patch.object(maintenance, '_process_start', side_effect=[321, 322]), patch.object(maintenance, '_process_cgroup', return_value='/system.slice/' + unit):
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                maintenance.writer_identity(self.transaction, self.runner(fields))

    def test_writer_boot_changed_during_observation_rejected(self):
        unit = 'adguardhome-doh-writer-' + self.transaction + '.service'
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '123',
                  'ControlGroup': '/system.slice/' + unit, 'InvocationID': 'b' * 32,
                  'Transient': 'yes', 'Description': 'DoHDNS writer ' + self.transaction}
        with patch.object(maintenance, '_boot_id', side_effect=[self.boot, 'b2345678-1234-1234-1234-123456789abc']), patch.object(maintenance, '_process_start', return_value=321), patch.object(maintenance, '_process_cgroup', return_value='/system.slice/' + unit):
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                maintenance.writer_identity(self.transaction, self.runner(fields))

    def test_timer_expected_identity_is_accepted(self):
        name = 'adguardhome-doh-recovery-' + self.transaction
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'Transient': 'yes',
                  'Description': 'DoHDNS recovery ' + self.transaction,
                  'Triggers': name + '.service'}
        maintenance.verify_watchdog_timer(self.transaction, self.runner(fields))

    def test_timer_unknown_trigger_is_rejected(self):
        fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'Transient': 'yes',
                  'Description': 'DoHDNS recovery ' + self.transaction,
                  'Triggers': 'other.service'}
        with self.assertRaisesRegex(RuntimeError, 'timer identity'):
            maintenance.verify_watchdog_timer(self.transaction, self.runner(fields))

    def test_invalid_transaction_never_calls_systemd(self):
        def fail(*args, **kwargs):
            raise AssertionError('unexpected systemctl')
        with self.assertRaises(ValueError):
            maintenance.writer_identity('../unsafe', fail)


if __name__ == '__main__':
    unittest.main()
