import json
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


if __name__ == '__main__':
    unittest.main()
