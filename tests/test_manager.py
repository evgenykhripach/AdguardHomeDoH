import hashlib
import importlib.util
import io
import json
import fcntl
import contextlib
import shutil
import re
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.render_config import Catalog


ROOT = Path(__file__).resolve().parents[1]
MANAGER_PATH = ROOT / "deploy" / "manage.py"


class TTYBuffer(io.StringIO):
    def isatty(self):
        return True


class InterruptingInput:
    def readline(self):
        raise KeyboardInterrupt

    def isatty(self):
        return True


def load_manager():
    spec = importlib.util.spec_from_file_location("neutral_manager", MANAGER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagerTests(unittest.TestCase):
    def _menu_status(self):
        return {
            "version": "1.0.33",
            "domain": "dns.example.com",
            "units": {
                "adguardhome-doh.service": True,
                "nginx.service": True,
                "adguardhome-doh-health.timer": True,
            },
            "overall": "running",
            "enabled_services": 2,
            "healthy_services": 1,
            "active_domain_count": 1,
            "certificate": True,
            "profile": True,
            "rollback_available": True,
        }

    def test_full_backup_includes_adguard_binary_for_update_rollback(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "opt/AdGuardHome/AdGuardHome"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"old-binary")
            binary.chmod(0o755)
            backup = root / "backup"
            manager.create_backup(root, backup)
            manifest = json.loads(
                (backup / "manifest.json").read_text(encoding="utf-8")
            )
            entry = next(
                item for item in manifest["files"]
                if item["path"] == "/opt/AdGuardHome/AdGuardHome"
            )
            self.assertTrue(entry["present"])
            self.assertEqual(
                b"old-binary", (backup / entry["backup"]).read_bytes()
            )

    def test_system_check_requires_domain_named_mobileconfig(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            webroot = root / "var/www/adguardhome-doh"
            state.mkdir(parents=True)
            webroot.mkdir(parents=True)
            (state / "install.json").write_text(
                '{"domain":"dns.example.com"}\n', encoding="utf-8"
            )
            (webroot / "dns.example.com.mobileconfig").write_text(
                "profile\n", encoding="utf-8"
            )
            runner = mock.Mock(return_value=mock.Mock(returncode=0))
            report = manager.collect_system_check(root, runner=runner)
        self.assertTrue(report["endpoints"]["mobileconfig"])

    def test_system_check_uses_successful_last_oneshot_result(self):
        manager = load_manager()
        commands = []

        def runner(command, **_kwargs):
            commands.append(command)
            stdout = b""
            if command[:2] == ["systemctl", "show"]:
                stdout = (
                    b"ActiveState=inactive\n"
                    b"Result=success\n"
                    b"ExecMainStatus=0\n"
                )
            return subprocess.CompletedProcess(command, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory:
            report = manager.collect_system_check(Path(directory), runner=runner)

        self.assertTrue(report["units"]["adguardhome-doh-health.service"])
        self.assertIn(
            [
                "systemctl", "show",
                "--property=ActiveState",
                "--property=Result",
                "--property=ExecMainStatus",
                "adguardhome-doh-health.service",
            ],
            commands,
        )
        self.assertNotIn(
            [
                "systemctl", "is-active", "--quiet",
                "adguardhome-doh-health.service",
            ],
            commands,
        )

    def test_system_check_rejects_failed_last_oneshot_result(self):
        manager = load_manager()
        result = subprocess.CompletedProcess(
            [], 0,
            b"ActiveState=failed\nResult=exit-code\nExecMainStatus=1\n",
            b"",
        )
        runner = mock.Mock(return_value=result)
        self.assertFalse(manager._oneshot_last_run_ok(
            "adguardhome-doh-health.service", runner
        ))

    def test_unhealthy_service_names_use_catalog_labels(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            state.mkdir(parents=True)
            (state / "health-state.json").write_text(
                json.dumps({
                    "chatgpt": {"healthy": True},
                    "claude": {"healthy": False},
                }),
                encoding="utf-8",
            )
            with mock.patch.object(manager, "_load_catalog", return_value=catalog):
                names = manager._unhealthy_service_names(root)
        self.assertEqual(["Claude"], names)

    def test_menu_status_is_fast_local_and_never_contains_secrets(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            config = root / "etc/adguardhome-doh"
            webroot = root / "var/www/adguardhome-doh"
            certificate = root / "etc/letsencrypt/live/dns.example.com"
            version = root / "usr/local/libexec/adguardhome-doh/VERSION"
            for path in (state, config, webroot, certificate, version.parent):
                path.mkdir(parents=True, exist_ok=True)
            (state / "install.json").write_text(
                json.dumps({
                    "domain": "dns.example.com",
                    "public_ip": "203.0.113.10",
                    "email": "private@example.com",
                    "version": "0.107.79",
                    "repository": "evgenykhripach/AdguardHomeDoH",
                }), encoding="utf-8",
            )
            (state / "enabled-services.json").write_text(
                '["chatgpt","claude"]\n', encoding="utf-8"
            )
            (state / "health-state.json").write_text(
                '{"chatgpt":{"healthy":true},"claude":{"healthy":false}}\n',
                encoding="utf-8",
            )
            (state / "admin-credentials.json").write_text(
                '{"login":"secret-login","password":"secret-password"}\n',
                encoding="utf-8",
            )
            (state / "doh-token").write_text("secret-token\n", encoding="utf-8")
            (config / "health-policy.json").write_text(
                json.dumps({"domains": [
                    {"domain": "chatgpt.com", "services": ["chatgpt"]},
                    {"domain": "claude.ai", "services": ["claude"]},
                ]}), encoding="utf-8",
            )
            (webroot / "dns.example.com.mobileconfig").write_text(
                "profile\n", encoding="utf-8"
            )
            (certificate / "fullchain.pem").write_text("cert\n", encoding="utf-8")
            (certificate / "privkey.pem").write_text("key\n", encoding="utf-8")
            version.write_text("1.0.33\n", encoding="utf-8")
            backup = manager.create_backup(
                root,
                root / "var/backups/adguardhome-doh/20260823T000000000000Z",
                operation="update",
            )
            manager.finalize_update_backup(backup, root, "dns.example.com")

            def runner(command, **_kwargs):
                active = command[-1] in {
                    "adguardhome-doh.service",
                    "nginx.service",
                    "adguardhome-doh-health.timer",
                }
                return mock.Mock(returncode=0 if active else 3)

            status = manager.collect_menu_status(root, catalog, runner=runner)

        self.assertEqual("1.0.33", status["version"])
        self.assertEqual("dns.example.com", status["domain"])
        self.assertEqual(2, status["enabled_services"])
        self.assertEqual(1, status["healthy_services"])
        self.assertEqual(1, status["active_domain_count"])
        self.assertTrue(status["certificate"])
        self.assertTrue(status["profile"])
        self.assertTrue(status["rollback_available"])
        serialized = json.dumps(status, ensure_ascii=False)
        for secret in ("secret-login", "secret-password", "secret-token", "private@example.com"):
            self.assertNotIn(secret, serialized)

    def test_uncertain_enabled_service_is_warning_in_menu_and_diagnostics(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            config = root / "etc/adguardhome-doh"
            state.mkdir(parents=True)
            config.mkdir(parents=True)
            (state / "enabled-services.json").write_text('["chatgpt"]', encoding="utf-8")
            (state / "install.json").write_text(
                '{"domain":"dns.example.com","email":"private@example.com"}', encoding="utf-8"
            )
            (state / "admin-credentials.json").write_text('{"password":"private-password"}', encoding="utf-8")
            (state / "doh-token").write_text("private-token", encoding="utf-8")
            (state / "health-state.json").write_text(json.dumps({
                "chatgpt": {"healthy": True, "probe_uncertain": True, "private": "state-secret"},
                "claude": {"healthy": True, "probe_uncertain": True},
            }), encoding="utf-8")
            (config / "health-policy.json").write_text(json.dumps({
                "enabled_services": ["chatgpt"],
                "services": {"chatgpt": {"probes": ["chatgpt.com"]}},
                "domains": [{"domain": "chatgpt.com", "services": ["chatgpt"]}],
            }), encoding="utf-8")

            def runner(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, b"ActiveState=inactive\nResult=success\nExecMainStatus=0\n", b"")

            status = manager.collect_menu_status(root, catalog, runner=runner)
            report = manager.collect_system_check(root, runner=runner)
            menu = io.StringIO()
            diagnostic = io.StringIO()
            manager.render_main_screen(status, menu, width=40)
            with mock.patch.object(manager, "collect_system_check", return_value=report), \
                 mock.patch.object(manager, "_terminal_width", return_value=40):
                manager.print_system_check(root, diagnostic)

        self.assertEqual("attention", status["overall"])
        self.assertTrue(status["probe_uncertain"])
        self.assertEqual(1, status["enabled_services"])
        self.assertEqual({"services": 1, "healthy": 1, "probe_uncertain": True}, report["health_state"])
        for text in (menu.getvalue(), diagnostic.getvalue()):
            flattened = " ".join(text.split())
            self.assertIn("Текущее состояние неизвестно", flattened)
            self.assertIn("Прежние DNS-правила сохранены", flattened)
            for secret in ("private@example.com", "private-password", "private-token", "state-secret"):
                self.assertNotIn(secret, text)
            for line in text.splitlines():
                self.assertLessEqual(len(manager._strip_ansi(line)), 40, line)
        self.assertNotIn("● РАБОТАЕТ", menu.getvalue())
        self.assertNotIn("1 / 1 здоровы", menu.getvalue())
        self.assertIn("результат неопределён", diagnostic.getvalue())
        self.assertNotIn("последняя проверка успешна", diagnostic.getvalue())
        status["overall"] = "running"
        stale_summary = io.StringIO()
        manager.render_main_screen(status, stale_summary, width=80)
        self.assertIn("ТРЕБУЕТ ВНИМАНИЯ", stale_summary.getvalue())
        self.assertNotIn("● РАБОТАЕТ", stale_summary.getvalue())

    def test_disabled_or_legacy_probe_state_does_not_show_uncertain_warning(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            state.mkdir(parents=True)
            (state / "enabled-services.json").write_text('["chatgpt"]', encoding="utf-8")
            health = state / "health-state.json"
            health.write_text(json.dumps({
                "chatgpt": {"healthy": True},
                "claude": {"healthy": False, "probe_uncertain": True},
            }), encoding="utf-8")
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"Result=success\nExecMainStatus=0\n", b""))
            status = manager.collect_menu_status(root, catalog, runner=runner)
            report = manager.collect_system_check(root, runner=runner)
            with mock.patch.object(manager, "_load_catalog", return_value=catalog):
                unhealthy = manager._unhealthy_service_names(root)
            self.assertFalse(status["probe_uncertain"])
            self.assertEqual("running", status["overall"])
            self.assertFalse(report["health_state"]["probe_uncertain"])
            self.assertEqual(1, report["health_state"]["services"])
            self.assertEqual([], unhealthy)
            health.write_text('{"chatgpt":{"healthy":true,"probe_uncertain":true}}', encoding="utf-8")
            (state / "enabled-services.json").write_text('[]', encoding="utf-8")
            self.assertFalse(manager.collect_menu_status(root, catalog, runner=runner)["probe_uncertain"])
            self.assertFalse(manager.collect_system_check(root, runner=runner)["health_state"]["probe_uncertain"])

    def test_uncertain_compatibility_policy_tracks_only_current_domains(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            config = root / "etc/adguardhome-doh"
            state.mkdir(parents=True)
            config.mkdir(parents=True)
            (state / "enabled-services.json").write_text('["chatgpt"]', encoding="utf-8")
            policy = {"enabled_services": [], "services": {}, "domains": [
                {"domain": "current.example.com", "services": []},
            ]}
            policy_file = config / "health-policy.json"
            policy_file.write_text(json.dumps(policy), encoding="utf-8")
            health = state / "health-state.json"
            health.write_text(json.dumps({
                "current.example.com": {"healthy": True, "probe_uncertain": True},
                "removed.example.com": {"healthy": True, "probe_uncertain": True},
            }), encoding="utf-8")
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"Result=success\nExecMainStatus=0\n", b""))
            self.assertTrue(manager.collect_menu_status(root, runner=runner)["probe_uncertain"])
            self.assertTrue(manager.collect_system_check(root, runner=runner)["health_state"]["probe_uncertain"])
            policy_file.write_text(json.dumps(policy["domains"]), encoding="utf-8")
            self.assertTrue(manager.collect_menu_status(root, runner=runner)["probe_uncertain"])
            self.assertTrue(manager.collect_system_check(root, runner=runner)["health_state"]["probe_uncertain"])
            health.write_text(json.dumps({
                "current.example.com": {"healthy": True},
                "removed.example.com": {"healthy": True, "probe_uncertain": True},
            }), encoding="utf-8")
            self.assertFalse(manager.collect_menu_status(root, runner=runner)["probe_uncertain"])
            self.assertFalse(manager.collect_system_check(root, runner=runner)["health_state"]["probe_uncertain"])

    def test_main_screen_is_responsive_and_uses_semantic_status_text(self):
        manager = load_manager()
        status = self._menu_status()
        wide = io.StringIO()
        manager.render_main_screen(status, wide, width=80)
        wide_text = wide.getvalue()
        self.assertIn(manager.FULL_BANNER[0], wide_text)
        self.assertIn("● РАБОТАЕТ", wide_text)
        self.assertIn("2 / 1 здоровы", wide_text)
        self.assertIn("[0] Выход", wide_text)

        narrow = io.StringIO()
        manager.render_main_screen(status, narrow, width=40)
        narrow_text = narrow.getvalue()
        self.assertNotIn(manager.FULL_BANNER[0], narrow_text)
        self.assertIn("ADGUARDHOME DOH", narrow_text)
        for line in narrow_text.splitlines():
            self.assertLessEqual(len(manager._strip_ansi(line)), 40, line)

    def test_ansi_colors_require_tty_and_respect_no_color_and_dumb_term(self):
        manager = load_manager()
        status = self._menu_status()
        colored = TTYBuffer()
        with mock.patch.dict(manager.os.environ, {"TERM": "xterm-256color"}, clear=True):
            manager.render_main_screen(status, colored, width=80)
        self.assertIn("\x1b[", colored.getvalue())

        for environment in ({"NO_COLOR": "1", "TERM": "xterm-256color"}, {"TERM": "dumb"}):
            plain = TTYBuffer()
            with mock.patch.dict(manager.os.environ, environment, clear=True):
                manager.render_main_screen(status, plain, width=80)
            self.assertNotIn("\x1b[", plain.getvalue())

        captured = io.StringIO()
        manager.render_main_screen(status, captured, width=80)
        self.assertNotIn("\x1b[", captured.getvalue())

    def test_system_check_prints_readable_screen_not_json(self):
        manager = load_manager()
        report = {
            "units": {
                "adguardhome-doh.service": True,
                "nginx.service": False,
                "adguardhome-doh-health.service": True,
                "adguardhome-doh-health.timer": True,
            },
            "nginx": False,
            "adguard_config": True,
            "certificate": True,
            "endpoints": {"admin": True, "doh": True, "mobileconfig": False},
            "health_state": {"services": 2, "healthy": 1},
            "active_domain_count": 42,
        }
        output = io.StringIO()
        with mock.patch.object(manager, "collect_system_check", return_value=report), \
             mock.patch.object(manager, "_unhealthy_service_names", return_value=["Claude"]):
            manager.print_system_check(Path("/"), output)
        text = output.getvalue()
        self.assertIn("ДИАГНОСТИКА СИСТЕМЫ", text)
        self.assertIn("AdGuard Home", text)
        self.assertIn("nginx", text)
        self.assertIn("последняя проверка успешна", text)
        self.assertIn("Требуют внимания: Claude", text)
        self.assertIn("42", text)
        self.assertNotIn('{"', text)

        narrow = io.StringIO()
        with mock.patch.object(manager, "_terminal_width", return_value=40):
            manager._render_system_check(
                report, narrow, ["Claude", "Microsoft Copilot"]
            )
        for line in narrow.getvalue().splitlines():
            self.assertLessEqual(len(manager._strip_ansi(line)), 40, line)

    def test_access_screen_is_explicitly_confidential(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh"
            state.mkdir(parents=True)
            (state / "admin-credentials.json").write_text(
                json.dumps({
                    "url": "https://dns.example.com/",
                    "login": "admin-user",
                    "password": "admin-password",
                }), encoding="utf-8",
            )
            (state / "doh-token").write_text("private-token\n", encoding="utf-8")
            (state / "install.json").write_text(
                '{"domain":"dns.example.com"}\n', encoding="utf-8"
            )
            output = io.StringIO()
            manager.print_access_data(root, output)
        text = output.getvalue()
        self.assertIn("ДАННЫЕ ДОСТУПА", text)
        self.assertIn("Конфиденциально", text)
        self.assertIn("admin-user", text)
        self.assertIn("admin-password", text)
        self.assertIn("https://dns.example.com/doh/private-token", text)

    def test_runtime_services_are_reloaded_after_service_change(self):
        manager = load_manager()
        runner = mock.Mock()
        manager.reload_runtime_services(
            Path("/"), "dns.example.com", runner=runner, smoke_attempts=1, smoke_delay=0
        )
        self.assertEqual(
            [
                mock.call(["systemctl", "restart", "adguardhome-doh"], check=True),
                mock.call(["systemctl", "reload", "nginx"], check=True),
                mock.call(
                    [
                        "curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                        "--resolve", "dns.example.com:443:127.0.0.1",
                        "--connect-timeout", "3", "--max-time", "8",
                        "--output", "/dev/null", "https://dns.example.com/",
                    ],
                    check=True, stdout=mock.ANY, stderr=mock.ANY,
                ),
            ],
            runner.call_args_list,
        )

    def test_https_sni_smoke_retries_then_raises(self):
        manager = load_manager()
        runner = mock.Mock(side_effect=subprocess.CalledProcessError(28, ["curl"]))
        with self.assertRaisesRegex(RuntimeError, "HTTPS/SNI smoke check failed"):
            manager.smoke_https_sni(
                "dns.example.com", runner=runner, attempts=3, delay=0
            )
        self.assertEqual(3, runner.call_count)

    def test_backup_restore_reloads_previous_runtime(self):
        manager = load_manager()
        runner = mock.Mock()
        with mock.patch.object(manager, "reload_runtime_services") as reload_services:
            manager._reload_restored_runtime(Path("/"), "dns.example.com", runner)
        self.assertEqual(
            [
                mock.call(["systemctl", "daemon-reload"], check=False),
                mock.call(["nginx", "-t"], check=True),
                mock.call(
                    ["systemctl", "restart", "adguardhome-doh-health.timer"],
                    check=True,
                ),
            ],
            runner.call_args_list,
        )
        reload_services.assert_called_once_with(
            Path("/"), "dns.example.com", runner=runner
        )

    def test_restore_rejects_invalid_manifest_without_mutating_target(self):
        manager = load_manager()
        invalid_manifests = [
            ("empty", []),
            ("non_mapping", ["invalid"]),
            (
                "unknown_path",
                [{"path": "/tmp/not-managed", "backup": "backup", "present": False}],
            ),
            (
                "present_not_bool",
                [{"path": "/opt/AdGuardHome/AdGuardHome.yaml", "backup": "backup", "present": 1}],
            ),
            (
                "unsafe_backup_name",
                [{"path": "/opt/AdGuardHome/AdGuardHome.yaml", "backup": "../backup", "present": True}],
            ),
            (
                "missing_present_backup",
                [{"path": "/opt/AdGuardHome/AdGuardHome.yaml", "backup": "missing", "present": True}],
            ),
        ]
        for name, manifest in invalid_manifests:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "opt/AdGuardHome/AdGuardHome.yaml"
                target.parent.mkdir(parents=True)
                target.write_text("before\n", encoding="utf-8")
                backup = root / "backup"
                manager.create_backup(root, backup)
                (backup / "manifest.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                with self.assertRaises(RuntimeError):
                    manager._restore_backup(backup, root)
                self.assertEqual("before\n", target.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            backup = root / "backup"
            manager.create_backup(root, backup)
            (backup / "manifest.json").unlink()
            with self.assertRaises(RuntimeError):
                manager._restore_backup(backup, root)
            self.assertEqual("before\n", target.read_text(encoding="utf-8"))

    def test_restore_rejects_partial_or_duplicate_manifest_without_mutation(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            backup = root / "backup"
            manager.create_backup(root, backup)
            manifest = json.loads(
                (backup / "manifest.json").read_text(encoding="utf-8")
            )

            for name, invalid in (
                ("partial", {**manifest, "files": manifest["files"][:1]}),
                ("duplicate", {**manifest, "files": manifest["files"] + [manifest["files"][0]]}),
            ):
                with self.subTest(name=name):
                    (backup / "manifest.json").write_text(
                        json.dumps(invalid), encoding="utf-8"
                    )
                    with self.assertRaises(RuntimeError):
                        manager._restore_backup(backup, root)
                    self.assertEqual(
                        "before\n", target.read_text(encoding="utf-8")
                    )

    def test_rollback_ignores_newer_incomplete_backup(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            backup_root = root / "var/backups/adguardhome-doh"
            previous = manager.create_backup(root, backup_root / "20240101T000000000000Z", operation="update")
            manager.finalize_update_backup(previous, root, "")
            target.write_text("after\n", encoding="utf-8")
            newer = backup_root / "20240201T00000000000000Z"
            newer.mkdir(parents=True)

            self.assertTrue(manager.rollback_last(root, runner=mock.Mock()))
            self.assertEqual("before\n", target.read_text(encoding="utf-8"))

    def test_rollback_skips_nested_service_change_snapshot(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            nested = root / "var/backups/adguardhome-doh/20240301T00000000000000Z/full"
            manager.create_backup(root, nested, operation="service-change")
            target.write_text("after\n", encoding="utf-8")

            self.assertFalse(manager.rollback_last(root, runner=mock.Mock()))
            self.assertEqual("after\n", target.read_text(encoding="utf-8"))

    def test_rollback_returns_false_when_only_incomplete_backups_exist(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "var/backups/adguardhome-doh/20240401T00000000000000Z"
            backup.mkdir(parents=True)

            self.assertFalse(manager.rollback_last(root, runner=mock.Mock()))

    def test_yes_answer_accepts_lowercase_and_terminal_invisibles(self):
        manager = load_manager()
        self.assertTrue(manager._is_yes_answer("y\r\n"))
        self.assertTrue(manager._is_yes_answer("\x1b[200~y\x1b[201~\r\n"))
        self.assertTrue(manager._is_yes_answer("\x1b[1;5~y\x1b[0m\r\n"))
        self.assertTrue(manager._is_yes_answer("\ufeffY"))
        self.assertTrue(manager._is_yes_answer("да"))
        self.assertFalse(manager._is_yes_answer("n"))

    def test_service_selector_matches_installer_categories_and_search(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        output = io.StringIO()
        selected = manager.select_services_interactive(
            catalog,
            catalog.default_service_ids,
            io.StringIO("/chatgpt\n1\nB\nY\ny\n"),
            output,
        )
        self.assertIsNotNone(selected)
        self.assertNotIn("chatgpt", selected)
        self.assertIn("СЕРВИСЫ И ДОМЕНЫ", output.getvalue())
        self.assertIn("Категории:", output.getvalue())
        self.assertIn("Результаты поиска:", output.getvalue())
        self.assertIn("[✓]", output.getvalue())
        self.assertIn("[D] Стандартные", output.getvalue())
        self.assertNotIn("Новый выбор (ID", output.getvalue())

    def test_service_selector_uses_two_category_columns_only_when_wide(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        selected = set(catalog.default_service_ids)
        wide = io.StringIO()
        manager._print_selector_categories(catalog, selected, wide, width=80)
        wide_category_lines = [line for line in wide.getvalue().splitlines()
                               if line.strip().startswith("[") and line.count("]") >= 2]
        self.assertTrue(any(line.count("]") >= 2 for line in wide_category_lines))

        narrow = io.StringIO()
        manager._print_selector_categories(catalog, selected, narrow, width=40)
        narrow_category_lines = [line for line in narrow.getvalue().splitlines()
                                 if re.match(r"^\[[0-9]+\]", line.strip())]
        self.assertTrue(narrow_category_lines)
        self.assertTrue(all(line.count("]") == 1 for line in narrow_category_lines))
        for line in narrow.getvalue().splitlines():
            self.assertLessEqual(len(manager._strip_ansi(line)), 40, line)

    def test_menu_exits_after_successful_update_to_reload_new_code(self):
        manager = load_manager()
        output = io.StringIO()
        with mock.patch.object(manager, "_load_catalog", return_value=Catalog.load(ROOT / "config")), \
             mock.patch.object(manager, "update_status", return_value={
                 "available": True, "current": "1.0.12", "latest": "1.0.13",
             }), \
             mock.patch.object(manager, "install_update", return_value=True), \
             mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()):
            result = manager.run_menu(
                root=Path("/"), input_stream=io.StringIO("4\ny\n"), output=output
            )
        self.assertEqual(0, result)
        self.assertIn("Запустите менеджер заново", output.getvalue())

    def test_menu_is_root_tty_only_and_has_required_entries(self):
        manager = load_manager()
        self.assertEqual(
            [
                "Данные доступа",
                "Сервисы и домены",
                "Диагностика системы",
                "Проверить обновления",
                "Откатить обновление",
            ],
            list(manager.MENU_ENTRIES),
        )
        with mock.patch.object(manager.os, "geteuid", return_value=1000), mock.patch.object(
            manager.sys.stdin, "isatty", return_value=True
        ), mock.patch.object(manager.sys.stdout, "isatty", return_value=True):
            self.assertNotEqual(0, manager.main([]))

    def test_menu_accepts_zero_and_legacy_six_and_reports_invalid_input(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        for answer in ("0\n", "6\n"):
            output = io.StringIO()
            with mock.patch.object(manager, "_load_catalog", return_value=catalog), \
                 mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()):
                self.assertEqual(0, manager.run_menu(
                    Path("/"), io.StringIO(answer), output
                ))
            self.assertIn("[0] Выход", output.getvalue())

        output = io.StringIO()
        with mock.patch.object(manager, "_load_catalog", return_value=catalog), \
             mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()):
            self.assertEqual(0, manager.run_menu(
                Path("/"), io.StringIO("9\n0\n"), output
            ))
        self.assertIn("Введите номер пункта от 0 до 5", output.getvalue())

    def test_menu_handles_eof_and_keyboard_interrupt_without_traceback(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        with mock.patch.object(manager, "_load_catalog", return_value=catalog), \
             mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()):
            self.assertEqual(0, manager.run_menu(
                Path("/"), io.StringIO(""), io.StringIO()
            ))
            output = TTYBuffer()
            self.assertEqual(130, manager.run_menu(
                Path("/"), InterruptingInput(), output
            ))
        self.assertIn("Выход прерван", manager._strip_ansi(output.getvalue()))

        main_output = TTYBuffer()
        with mock.patch.object(manager.os, "geteuid", return_value=0), \
             mock.patch.object(manager.sys, "stdin", TTYBuffer()), \
             mock.patch.object(manager.sys, "stdout", main_output), \
             mock.patch.object(manager, "run_menu", side_effect=KeyboardInterrupt), \
             mock.patch.dict(manager.os.environ, {"TERM": "xterm-256color"}, clear=True):
            self.assertEqual(130, manager.main([]))
        self.assertIn("Выход прерван", manager._strip_ansi(main_output.getvalue()))
        self.assertTrue(main_output.getvalue().endswith(manager.ANSI_RESET))

    def test_menu_runs_diagnostics_and_confirmed_rollback_screens(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        report = {
            "units": {
                "adguardhome-doh.service": True,
                "nginx.service": True,
                "adguardhome-doh-health.service": True,
                "adguardhome-doh-health.timer": True,
            },
            "nginx": True,
            "adguard_config": True,
            "certificate": True,
            "endpoints": {"admin": True, "doh": True, "mobileconfig": True},
            "health_state": {"services": 2, "healthy": 2},
            "active_domain_count": 50,
        }
        output = io.StringIO()
        selected = Path("/var/backups/adguardhome-doh/fixture")
        with mock.patch.object(manager, "_load_catalog", return_value=catalog), \
             mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()), \
             mock.patch.object(manager, "collect_system_check", return_value=report), \
             mock.patch.object(manager, "_latest_valid_backup", return_value=selected), \
             mock.patch.object(manager, "_read_json", return_value={"version_before": "1.0.0", "version_after": "2.0.0"}), \
             mock.patch.object(manager, "rollback_last", return_value=True) as rollback:
            result = manager.run_menu(
                Path("/"), io.StringIO("3\n5\ny\n0\n"), output
            )
        self.assertEqual(0, result)
        rollback.assert_called_once_with(Path("/"), selected=selected)
        self.assertIn("ДИАГНОСТИКА СИСТЕМЫ", output.getvalue())
        self.assertIn("ОТКАТ ОБНОВЛЕНИЯ", output.getvalue())
        self.assertIn("Откат выполнен", output.getvalue())

    def test_service_change_preview_counts_union_domains(self):
        manager = load_manager()
        catalog = Catalog.load(ROOT / "config")
        preview = manager.preview_service_change(
            catalog, ["chatgpt"], ["chatgpt", "google_shared"]
        )
        self.assertEqual({"google_shared"}, set(preview["added_services"]))
        self.assertGreater(preview["new_domains"], preview["old_domains"])
        self.assertIn("new_domains", preview)
        self.assertIn("removed_domains", preview)

    def test_update_status_uses_installed_project_version_not_adguard_version(self):
        manager = load_manager()
        releases = manager._load_releases()
        release = releases.parse_release(
            {
                "tag_name": "v1.0.9",
                "draft": False,
                "prerelease": False,
                "assets": [
                    {"name": "adguardhome-doh.tar.gz", "browser_download_url": "archive"},
                    {"name": "adguardhome-doh.tar.gz.sha256", "browser_download_url": "checksum"},
                ],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "var/lib/adguardhome-doh"
            state_dir.mkdir(parents=True)
            (state_dir / "install.json").write_text(
                '{"domain":"dns.example.com","public_ip":"203.0.113.10",'
                '"email":"admin@example.com","version":"0.107.78",'
                '"repository":"evgenykhripach/AdguardHomeDoH"}',
                encoding="utf-8",
            )
            version_file = root / "usr/local/libexec/adguardhome-doh/VERSION"
            version_file.parent.mkdir(parents=True)
            version_file.write_text("1.0.8\n", encoding="utf-8")
            status = manager.update_status(root, release_loader=lambda: release)
            self.assertEqual("1.0.8", status["current"])

    def test_transaction_restores_all_targets_when_validation_fails(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.conf"
            target.write_text("before\n", encoding="utf-8")
            stage = root / "stage.conf"
            stage.write_text("after\n", encoding="utf-8")
            backup = root / "backup"
            with self.assertRaises(RuntimeError):
                manager.activate_transaction(
                    {target: stage},
                    backup,
                    validate=lambda: (_ for _ in ()).throw(RuntimeError("invalid")),
                )
            self.assertEqual("before\n", target.read_text(encoding="utf-8"))


class BackupSafetyTests(unittest.TestCase):
    def _legacy_snapshot(self, manager, root, backup, paths):
        backup.mkdir(parents=True)
        entries = []
        for index, path in enumerate(paths):
            source = manager.under_root(root, path)
            name = "%03d-%s" % (index, Path(path).name)
            present = source.exists() or source.is_symlink()
            if present:
                manager._copy_path(source, backup / name)
            entries.append({"path": path, "backup": name, "present": present})
        (backup / "manifest.json").write_text(json.dumps(entries), encoding="utf-8")

    def test_legacy_update_is_partial_and_skips_newer_service_snapshot(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "opt/AdGuardHome/AdGuardHome"
            binary.parent.mkdir(parents=True)
            binary.write_text("old binary", encoding="utf-8")
            yaml = binary.with_name("AdGuardHome.yaml")
            yaml.write_text("old yaml", encoding="utf-8")
            backup_root = root / "var/backups/adguardhome-doh"
            old = backup_root / "20240101T000000000000Z"
            self._legacy_snapshot(manager, root, old, manager.LEGACY_NO_BINARY_FILES)
            binary.write_text("new binary", encoding="utf-8")
            yaml.write_text("new yaml", encoding="utf-8")
            manager.create_backup(
                root, backup_root / "20240201T000000000000Z/full", operation="service-change"
            )
            self.assertEqual(old, manager._latest_valid_backup(root))
            self.assertTrue(manager.rollback_last(root))
            self.assertEqual("old yaml", yaml.read_text(encoding="utf-8"))
            self.assertEqual("new binary", binary.read_text(encoding="utf-8"))

    def test_legacy_unrecognised_list_is_rejected(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "backup"
            self._legacy_snapshot(manager, root, backup, manager.LEGACY_NO_BINARY_FILES[:-1])
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                manager._validated_backup_manifest(backup)

    def test_pending_update_is_not_selected_until_finalized(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_root = root / "var/backups/adguardhome-doh"
            previous = manager.create_backup(root, backup_root / "20240101T000000000000Z",
                                             operation="update", domain="dns.example.com")
            manager.finalize_update_backup(previous, root, "dns.example.com")
            pending = manager.create_backup(root, backup_root / "20240201T000000000000Z",
                                            operation="update", domain="dns.example.com")
            self.assertEqual("pending", json.loads((pending / "manifest.json").read_text())["status"])
            self.assertEqual(previous, manager._latest_valid_backup(root))
            self.assertEqual(0, manager.main(["--finalize-update-backup", str(pending),
                                              "--root", str(root), "--domain", "dns.example.com"]))
            self.assertEqual("applied", json.loads((pending / "manifest.json").read_text())["status"])
            self.assertEqual(pending, manager._latest_valid_backup(root))

    def test_finalize_rejects_wrong_domain_tampered_files_and_outside_path(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "opt/AdGuardHome/AdGuardHome.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("saved", encoding="utf-8")
            backup_root = root / "var/backups/adguardhome-doh"
            backup = manager.create_backup(root, backup_root / "20240101T000000000000Z",
                                           operation="update", domain="dns.example.com")
            with self.assertRaisesRegex(RuntimeError, "pending update for this domain"):
                manager.finalize_update_backup(backup, root, "other.example.com")
            with self.assertRaisesRegex(RuntimeError, "outside the backup directory"):
                manager.finalize_update_backup(root / "other", root, "dns.example.com")
            manifest = json.loads((backup / "manifest.json").read_text())
            entry = next(item for item in manifest["files"] if item["path"].endswith("AdGuardHome.yaml"))
            (backup / entry["backup"]).write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                manager.finalize_update_backup(backup, root, "dns.example.com")
            self.assertEqual("pending", json.loads((backup / "manifest.json").read_text())["status"])
            self.assertIsNone(manager._latest_valid_backup(root))

    def test_finalize_write_failure_keeps_snapshot_pending(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            with mock.patch.object(manager.os, "replace", side_effect=OSError("disk error")):
                with self.assertRaisesRegex(OSError, "disk error"):
                    manager.finalize_update_backup(backup, root, "dns.example.com")
            self.assertEqual("pending", json.loads((backup / "manifest.json").read_text())["status"])
            self.assertIsNone(manager._latest_valid_backup(root))

    def test_old_versioned_manifest_without_owner_hash_is_readable(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "opt/AdGuardHome/AdGuardHome.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("saved", encoding="utf-8")
            backup = manager.create_backup(root, root / "backup", operation="update", domain="dns.example.com")
            manifest_path = backup / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["version"] = 2
            manifest.pop("status")
            manifest["files"] = [item for item in manifest["files"]
                                 if not item["path"].endswith(".conf.pre-webroot")
                                 and item["path"] not in manager.FRONT_MANAGED_FILES]
            for item in manifest["files"]:
                if item["present"]:
                    item["sha256"] = manager._path_digest(backup / item["backup"], include_owners=False)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertTrue(manager._validated_backup_manifest(backup))
            source.write_text("current", encoding="utf-8")
            manager.restore_backup_runtime(backup, root, "dns.example.com")
            self.assertEqual("saved", source.read_text())

    def test_version_three_snapshot_without_front_files_remains_readable(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            yaml.parent.mkdir(parents=True)
            yaml.write_text("old", encoding="utf-8")
            backup = manager.create_backup(root, root / "backup", operation="update", domain="dns.example.com")
            manifest_path = backup / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["version"] = 3
            manifest["files"] = [item for item in manifest["files"]
                                 if item["path"] not in manager.FRONT_MANAGED_FILES]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertTrue(manager._validated_backup_manifest(backup))
            yaml.write_text("new", encoding="utf-8")
            manager.restore_backup_runtime(backup, root, "dns.example.com")
            self.assertEqual("old", yaml.read_text(encoding="utf-8"))

    def test_previous_v4_snapshot_without_overlay_files_remains_readable(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, root / "backup", operation="recovery", domain="dns.example.com")
            manifest_path = backup / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"] = [item for item in manifest["files"]
                                 if item["path"] not in manager.FRONT_OVERLAY_FILES + manager.FRONT_SITE_FILES]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertTrue(manager._validated_backup_manifest(backup))

    def test_previous_v4_snapshot_with_overlay_without_private_sites_remains_readable(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, root / "backup", operation="recovery", domain="dns.example.com")
            manifest_path = backup / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"] = [item for item in manifest["files"]
                                 if item["path"] not in manager.FRONT_SITE_FILES]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertTrue(manager._validated_backup_manifest(backup))

    def test_v4_snapshot_missing_only_one_private_site_is_invalid(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, root / "backup", operation="recovery", domain="dns.example.com")
            manifest_path = backup / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"] = [item for item in manifest["files"]
                                 if item["path"] != manager.PRIVATE_NGINX_HTTP_SITE]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "backup manifest is incomplete"):
                manager._validated_backup_manifest(backup)

    def test_backup_copy_preserves_owner_and_group_or_fails_closed(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_text("data", encoding="utf-8")
            destination = Path(directory) / "destination"
            original_lstat = Path.lstat

            def different_destination(path):
                info = original_lstat(path)
                if path == destination:
                    return SimpleNamespace(st_uid=info.st_uid, st_gid=info.st_gid + 1)
                return info

            with mock.patch.object(Path, "lstat", different_destination), \
                 mock.patch.object(manager.os, "chown") as chown:
                manager._copy_path(source, destination)
            chown.assert_called_once_with(destination, source.stat().st_uid, source.stat().st_gid,
                                          follow_symlinks=False)
            destination.unlink()
            with mock.patch.object(Path, "lstat", different_destination), \
                 mock.patch.object(manager.os, "chown", side_effect=PermissionError("cannot preserve owner")):
                with self.assertRaisesRegex(PermissionError, "cannot preserve owner"):
                    manager._copy_path(source, destination)

    def test_new_hash_includes_owner_but_version_two_hash_does_not(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source"
            path.write_text("data", encoding="utf-8")
            current = manager._path_digest(path)
            old = manager._path_digest(path, include_owners=False)
            original_lstat = Path.lstat

            def changed_owner(item):
                info = original_lstat(item)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1, st_gid=info.st_gid)

            with mock.patch.object(Path, "lstat", changed_owner):
                self.assertNotEqual(current, manager._path_digest(path))
                self.assertEqual(old, manager._path_digest(path, include_owners=False))

    def test_domain_pre_webroot_file_is_restored(self):
        manager = load_manager()
        for existed in (False, True):
            with self.subTest(existed=existed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                renewal = root / "etc/letsencrypt/renewal/dns.example.com.conf.pre-webroot"
                renewal.parent.mkdir(parents=True)
                if existed:
                    renewal.write_text("before", encoding="utf-8")
                backup = manager.create_backup(root, root / "backup", operation="recovery", domain="dns.example.com")
                renewal.write_text("after", encoding="utf-8")
                manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True)
                self.assertEqual(existed, renewal.exists())
                if existed:
                    self.assertEqual("before", renewal.read_text())

    def test_restore_preserves_only_new_live_certbot_lineage(self):
        manager = load_manager()
        domain = "dns.example.com"
        cases = (
            (False, True, True, True, "new profile"),
            (True, True, True, True, "old profile"),
            (False, True, False, True, None),
            (False, False, True, True, None),
            (False, True, True, False, None),
        )
        for existed, fullchain, key, preserve, expected in cases:
            with self.subTest(existed=existed, fullchain=fullchain, key=key, preserve=preserve), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                renewal = root / ("etc/letsencrypt/renewal/%s.conf" % domain)
                renewal.parent.mkdir(parents=True)
                if existed:
                    renewal.write_text("old profile", encoding="utf-8")
                nginx = root / "etc/nginx/nginx.conf"
                nginx.parent.mkdir(parents=True)
                nginx.write_text("old nginx", encoding="utf-8")
                backup = manager.create_backup(root, operation="recovery", domain=domain)
                renewal.write_text("new profile", encoding="utf-8")
                nginx.write_text("new nginx", encoding="utf-8")
                foreign = root / "var/www/adguardhome-doh/unrelated.txt"
                foreign.parent.mkdir(parents=True)
                foreign.write_text("keep", encoding="utf-8")
                live = root / ("etc/letsencrypt/live/%s" % domain)
                live.mkdir(parents=True)
                if fullchain:
                    (live / "fullchain.pem").write_text("cert", encoding="utf-8")
                if key:
                    (live / "privkey.pem").write_text("key", encoding="utf-8")
                args = ["--restore-update-backup", str(backup), "--root", str(root),
                        "--domain", domain, "--files-only"]
                if preserve:
                    args.append("--preserve-new-certbot-lineage")
                self.assertEqual(0, manager.main(args))
                if expected is None:
                    self.assertFalse(renewal.exists())
                else:
                    self.assertEqual(expected, renewal.read_text(encoding="utf-8"))
                self.assertEqual("old nginx", nginx.read_text(encoding="utf-8"))
                self.assertEqual("keep", foreign.read_text(encoding="utf-8"))

    def test_certbot_preservation_refuses_wrong_domain_before_restore(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            target = root / "etc/nginx/nginx.conf"
            target.parent.mkdir(parents=True)
            target.write_text("current", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "cannot establish the Certbot lineage domain"):
                manager.restore_backup_runtime(backup, root, "other.example.com", files_only=True,
                                               preserve_new_certbot_lineage=True)
            self.assertEqual("current", target.read_text(encoding="utf-8"))

    def test_checksum_corruption_is_rejected_before_replacement(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("old", encoding="utf-8")
            backup = manager.create_backup(root, root / "backup", operation="update")
            manifest = json.loads((backup / "manifest.json").read_text())
            entry = next(item for item in manifest["files"] if item["path"].endswith("AdGuardHome.yaml"))
            (backup / entry["backup"]).write_text("corrupt", encoding="utf-8")
            target.write_text("current", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                manager.restore_backup_runtime(backup, root, "")
            self.assertEqual("current", target.read_text(encoding="utf-8"))

    def test_staged_validation_failure_does_not_replace_current_yaml(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("old", encoding="utf-8")
            backup = manager.create_backup(root, root / "backup", operation="update")
            target.write_text("current", encoding="utf-8")
            with mock.patch.object(manager, "_validate_staged_adguard", side_effect=RuntimeError("invalid YAML")):
                with self.assertRaisesRegex(RuntimeError, "invalid YAML"):
                    manager.restore_backup_runtime(backup, root, "")
            self.assertEqual("current", target.read_text(encoding="utf-8"))

    def test_live_staged_validation_uses_snapshot_binary_and_yaml_paths(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            yaml = Path(directory) / "AdGuardHome.yaml"
            yaml.write_text("dns: {}\n", encoding="utf-8")
            binary = Path(directory) / "AdGuardHome"
            runner = mock.Mock()
            manager._validate_staged_adguard(Path("/"), yaml, binary, runner)
            self.assertEqual([str(binary), "--check-config", "-c", str(yaml),
                              "-w", "/var/lib/AdGuardHome"], runner.call_args.args[0])

    def test_keyboard_interrupt_restores_transaction_and_marks_it_restored(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            stage_a, stage_b = root / "stage-a", root / "stage-b"
            for path, value in ((first, "old A"), (second, "old B"),
                                (stage_a, "new A"), (stage_b, "new B")):
                path.write_text(value, encoding="utf-8")
            atomic_copy = manager._atomic_copy
            calls = []

            def interrupt(source, target):
                calls.append(target)
                if len(calls) == 2:
                    raise KeyboardInterrupt()
                atomic_copy(source, target)

            backup = root / "backup"
            with mock.patch.object(manager, "_atomic_copy", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    manager.activate_transaction({first: stage_a, second: stage_b}, backup)
            self.assertEqual("old A", first.read_text())
            self.assertEqual("old B", second.read_text())
            self.assertEqual("restored", json.loads((backup / "transaction.json").read_text())["state"])

    def test_failed_restore_reverts_to_state_before_attempt(self):
        manager = load_manager()
        for failure in (RuntimeError("restore failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "opt/AdGuardHome/AdGuardHome.yaml"
                target.parent.mkdir(parents=True)
                target.write_text("old", encoding="utf-8")
                backup = manager.create_backup(root, root / "backup", operation="update")
                target.write_text("current", encoding="utf-8")

                def fail_restore(*_args):
                    target.write_text("partially replaced", encoding="utf-8")
                    raise failure

                with mock.patch.object(manager, "_restore_backup", side_effect=fail_restore):
                    with self.assertRaises(type(failure)):
                        manager.restore_backup_runtime(backup, root, "")
                self.assertEqual("current", target.read_text(encoding="utf-8"))

    def test_failed_reversal_reports_failure_and_blocks_later_operations(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, root / "backup", operation="update")
            with mock.patch.object(manager, "_restore_backup", side_effect=RuntimeError("restore error")), \
                 mock.patch.object(manager, "_restore_transaction_entries", side_effect=RuntimeError("disk error")):
                with self.assertRaisesRegex(RuntimeError, "returning to previous state also failed: disk error"):
                    manager.restore_backup_runtime(backup, root, "")
            with self.assertRaisesRegex(RuntimeError, "unfinished transaction"):
                manager.rollback_last(root)

    def test_new_snapshot_preserves_unrelated_files_in_managed_directories(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "etc/adguardhome-doh/catalog"
            catalog.mkdir(parents=True)
            (catalog / "services.csv").write_text("old", encoding="utf-8")
            backup = manager.create_backup(root, root / "backup", operation="update", domain="dns.example.com")
            (catalog / "services.csv").write_text("new", encoding="utf-8")
            unrelated = catalog / "unrelated.txt"
            unrelated.write_text("keep", encoding="utf-8")
            manager.restore_backup_runtime(backup, root, "dns.example.com")
            self.assertEqual("old", (catalog / "services.csv").read_text())
            self.assertEqual("keep", unrelated.read_text())

    def test_restore_never_deletes_directory_at_file_target(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, root / "backup", operation="update")
            target = root / "etc/nginx/nginx.conf"
            target.mkdir(parents=True)
            (target / "unrelated").write_text("keep")
            with self.assertRaisesRegex(RuntimeError, "refusing to replace a directory"):
                manager.restore_backup_runtime(backup, root, "")
            self.assertEqual("keep", (target / "unrelated").read_text())

    def test_installer_cli_snapshot_and_files_only_restore(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "opt/AdGuardHome/AdGuardHome"
            binary.parent.mkdir(parents=True)
            binary.write_text("old", encoding="utf-8")
            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                result = manager.main(["--create-update-backup", "--root", str(root),
                                       "--domain", "dns.example.com", "--target-version", "2.0.0"])
            self.assertEqual(0, result)
            backup = Path(output.getvalue().strip())
            manifest = json.loads((backup / "manifest.json").read_text())
            self.assertEqual("update", manifest["operation"])
            self.assertEqual("2.0.0", manifest["version_after"])
            binary.write_text("new", encoding="utf-8")
            self.assertEqual(0, manager.main(["--restore-update-backup", str(backup),
                                              "--root", str(root), "--domain", "dns.example.com",
                                              "--files-only"]))
            self.assertEqual("old", binary.read_text())

    def test_files_only_preserve_system_nginx_on_standard_to_shared_rollback(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_file = root / "var/lib/adguardhome-doh/install.json"
            state_file.parent.mkdir(parents=True)
            state_file.write_text('{"domain":"dns.example.com"}', encoding="utf-8")
            system = root / "etc/nginx/nginx.conf"
            system.parent.mkdir(parents=True)
            system.write_text("old system")
            system_site = root / "etc/nginx/sites-enabled/adguardhome-doh"
            system_site.parent.mkdir(parents=True)
            system_site.write_text("old system site")
            system_stream = root / "etc/nginx/stream.d/adguardhome-doh.conf"
            system_stream.parent.mkdir(parents=True)
            system_stream.write_text("old system stream")
            dropin = root / "etc/systemd/system/nginx.service.d/adguardhome-doh.conf"
            dropin.parent.mkdir(parents=True)
            dropin.write_text("old dropin")
            enabled = root / "etc/systemd/system/multi-user.target.wants/nginx.service"
            enabled.parent.mkdir(parents=True)
            enabled.symlink_to("/usr/lib/systemd/system/nginx.service")
            runtime = root / "etc/adguardhome-doh/runtime.env"
            runtime.parent.mkdir(parents=True)
            runtime.write_text("old runtime")
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            system.write_text("user changed system")
            system_site.write_text("user changed system site")
            system_stream.write_text("user changed system stream")
            dropin.write_text("user changed dropin")
            enabled.unlink()
            enabled.symlink_to("/some/other/unit")
            runtime.write_text("new runtime")
            state_file.write_text('{"domain":"dns.example.com","front":"mtproxyl"}', encoding="utf-8")
            for path in manager.FRONT_SITE_FILES:
                manager.under_root(root, path).write_text("new private site")
            result = manager.main(["--restore-update-backup", str(backup), "--root", str(root),
                                   "--domain", "dns.example.com", "--files-only", "--preserve-system-nginx"])
            self.assertEqual(0, result)
            self.assertEqual("user changed system", system.read_text())
            self.assertEqual("user changed system site", system_site.read_text())
            self.assertEqual("user changed system stream", system_stream.read_text())
            self.assertEqual("user changed dropin", dropin.read_text())
            self.assertEqual("/some/other/unit", str(enabled.readlink()))
            self.assertEqual("old runtime", runtime.read_text())
            self.assertNotIn("front", json.loads(state_file.read_text()))
            for path in manager.FRONT_SITE_FILES:
                self.assertFalse(manager.under_root(root, path).exists())

    def test_preserve_system_nginx_requires_files_only_restore_and_valid_manifest(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            system = root / "etc/nginx/nginx.conf"
            system.parent.mkdir(parents=True)
            system.write_text("old system")
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            system.write_text("current system")
            manifest = json.loads((backup / "manifest.json").read_text())
            entry = next(item for item in manifest["files"] if item["path"] == "/etc/nginx/nginx.conf")
            (backup / entry["backup"]).write_text("tampered")
            with mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(1, manager.main(["--create-update-backup", "--root", str(root),
                                                  "--preserve-system-nginx"]))
                self.assertEqual(1, manager.main(["--restore-update-backup", str(backup), "--root", str(root),
                                                  "--preserve-system-nginx"]))
                self.assertEqual(1, manager.main(["--restore-update-backup", str(backup), "--root", str(root),
                                                  "--files-only", "--preserve-system-nginx"]))
            self.assertEqual("current system", system.read_text())

    def test_skipped_system_site_backups_still_require_valid_hashes(self):
        manager = load_manager()
        for relative in ("/etc/nginx/sites-enabled/adguardhome-doh", "/etc/nginx/stream.d/adguardhome-doh.conf"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                system = manager.under_root(root, relative)
                system.parent.mkdir(parents=True)
                system.write_text("old system")
                backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                system.write_text("current system")
                manifest = json.loads((backup / "manifest.json").read_text())
                entry = next(item for item in manifest["files"] if item["path"] == relative)
                (backup / entry["backup"]).write_text("tampered")
                with mock.patch("sys.stderr", io.StringIO()):
                    self.assertEqual(1, manager.main(["--restore-update-backup", str(backup), "--root", str(root),
                                                      "--files-only", "--preserve-system-nginx"]))
                self.assertEqual("current system", system.read_text())

    def test_standard_restore_still_restores_system_nginx_sites(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [manager.under_root(root, path) for path in (
                "/etc/nginx/sites-enabled/adguardhome-doh",
                "/etc/nginx/stream.d/adguardhome-doh.conf",
            )]
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("old system config")
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            for path in files:
                path.write_text("changed system config")
            manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True)
            for path in files:
                self.assertEqual("old system config", path.read_text())

    def test_absent_private_files_are_removed_on_restore(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            for relative in manager.FRONT_SITE_FILES:
                target = manager.under_root(root, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("created after snapshot")
            manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True)
            for relative in manager.FRONT_SITE_FILES:
                self.assertFalse(manager.under_root(root, relative).exists())


class ServiceChangeSeedingTests(unittest.TestCase):
    """Changing services must not drop a working service for a probe cycle."""

    def build_root(self, directory):
        root = Path(directory)
        project = Path(__file__).resolve().parents[1]
        (root / "var/lib/adguardhome-doh").mkdir(parents=True)
        (root / "etc/adguardhome-doh/catalog").mkdir(parents=True)
        for name in ("services.csv", "domains.csv", "service-domains.csv",
                     "service-probes.csv"):
            (root / "etc/adguardhome-doh/catalog" / name).write_bytes(
                (project / "config" / name).read_bytes()
            )
        (root / "var/lib/adguardhome-doh/health-state.json").write_text(
            json.dumps({"chatgpt": {"healthy": True}, "claude": {"healthy": False}}),
            encoding="utf-8",
        )
        (root / "var/lib/adguardhome-doh/install.json").write_text(
            json.dumps({"domain": "dns.example.com", "public_ip": "203.0.113.10"}),
            encoding="utf-8",
        )
        (root / "var/lib/adguardhome-doh/doh-token").write_text("a" * 48, encoding="utf-8")
        (root / "opt/AdGuardHome").mkdir(parents=True)
        (root / "opt/AdGuardHome/AdGuardHome.yaml").write_text(
            "users:\n  - name: admin\n    password: $2a$10$hash\n", encoding="utf-8"
        )
        return root

    def test_service_change_keeps_adguard_config_private(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            manager.apply_service_change(["chatgpt"], root=root, validator=lambda: None)
            adguard = root / "opt/AdGuardHome/AdGuardHome.yaml"
            self.assertEqual(0, adguard.stat().st_mode & 0o007)

    def test_standard_service_change_uses_system_stream_not_private_stream(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            private = root / "etc/adguardhome-doh/mtproxyl-stream-site.conf"
            private.write_text("unchanged private stream")
            manager.apply_service_change(["chatgpt"], root=root, validator=lambda: None)
            stream = (root / "etc/nginx/stream.d/adguardhome-doh.conf").read_text()
            self.assertIn("listen 443", stream)
            self.assertEqual("unchanged private stream", private.read_text())

    def test_render_command_passes_healthy_services_as_a_complete_pair(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            captured = {}
            real_run = subprocess.run

            def fake_run(command, **kwargs):
                captured["command"] = list(command)
                return real_run(command, **kwargs)

            with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
                try:
                    manager.apply_service_change(
                        ["chatgpt", "claude"], root=root, validator=lambda: None
                    )
                except Exception:
                    # Reloading live units is skipped for a non-/ root; the
                    # rendered command is what this test is about.
                    pass

        command = captured.get("command")
        self.assertIsNotNone(command)
        # A flag spliced into the wrong position would corrupt its neighbour.
        self.assertEqual("203.0.113.10", command[command.index("--public-ip") + 1])
        self.assertEqual("chatgpt", command[command.index("--healthy-services") + 1])
        self.assertEqual("chatgpt,claude", command[command.index("--services") + 1])
        self.assertIn("--existing-config", command)
        self.assertIn("--existing-public-ip", command)
        self.assertIn("--doh-token-file", command)
        self.assertNotIn("--doh-token", command)
        self.assertNotIn("--password-hash", command)
        self.assertNotIn("--front", command)

    def test_service_change_waits_for_health_lock_before_reading_health(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            catalog = Catalog.load(root / "etc/adguardhome-doh/catalog")
            renderer_started = threading.Event()
            worker_started = threading.Event()
            commands = []
            errors = []

            def render(command, **_kwargs):
                commands.append(command)
                renderer_started.set()
                stage = Path(command[command.index("--output") + 1])
                (stage / "AdGuardHome.yaml").write_text("dns: {}\n", encoding="utf-8")
                (stage / "nginx-stream.conf").write_text("stream", encoding="utf-8")
                (stage / "health-policy.json").write_text("{}", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0)

            def worker():
                worker_started.set()
                try:
                    manager.apply_service_change(["chatgpt", "claude"], root=root,
                                                 catalog=catalog, validator=lambda: None)
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(manager.subprocess, "run", side_effect=render):
                with manager.health_lock(root):
                    thread = threading.Thread(target=worker)
                    thread.start()
                    self.assertTrue(worker_started.wait(1))
                    self.assertFalse(renderer_started.wait(0.1))
                    (root / "var/lib/adguardhome-doh/health-state.json").write_text(
                        '{"chatgpt":{"healthy":true},"claude":{"healthy":true}}',
                        encoding="utf-8",
                    )
                thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            command = commands[0]
            self.assertEqual("chatgpt,claude", command[command.index("--healthy-services") + 1])
            self.assertNotIn("a" * 48, command)

    def test_operation_lock_blocks_service_change_without_holding_health_lock(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            renderer_started = threading.Event()
            worker_started = threading.Event()
            errors = []

            def renderer(stage, _selected):
                renderer_started.set()
                (stage / "AdGuardHome.yaml").write_text("dns: {}\n")
                (stage / "nginx-stream.conf").write_text("stream")
                (stage / "health-policy.json").write_text("{}")

            def worker():
                worker_started.set()
                try:
                    manager.apply_service_change(["chatgpt"], root=root, renderer=renderer,
                                                 validator=lambda: None)
                except BaseException as exc:
                    errors.append(exc)

            with manager.operation_lock(root):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(worker_started.wait(1))
                self.assertFalse(renderer_started.wait(0.1))
                health = manager.under_root(root, manager.HEALTH_LOCK)
                with health.open("a+") as stream:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            self.assertTrue(renderer_started.is_set())

    def test_operation_lock_blocks_rollback_until_installer_finishes(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            before = yaml.read_text(encoding="utf-8")
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            yaml.write_text("current", encoding="utf-8")
            started, finished = threading.Event(), threading.Event()
            errors = []

            def worker():
                started.set()
                try:
                    manager.rollback_last(root)
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    finished.set()

            with manager.operation_lock(root):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(started.wait(1))
                self.assertFalse(finished.wait(0.1))
                health = manager.under_root(root, manager.HEALTH_LOCK)
                with health.open("a+") as stream:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                self.assertEqual("current", yaml.read_text(encoding="utf-8"))
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(before, yaml.read_text(encoding="utf-8"))

    def test_stop_command_runs_only_for_live_root(self):
        manager = load_manager()
        runner = mock.Mock()
        manager._stop_adguard(Path("/"), runner=runner)
        manager._stop_adguard(Path("/tmp/isolated"), runner=runner)
        runner.assert_called_once_with(["systemctl", "stop", "adguardhome-doh"], check=True)

    def test_live_service_change_stops_before_yaml_read_snapshot_and_activation(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            catalog = Catalog.load(root / "etc/adguardhome-doh/catalog")
            events = []
            under_root, copy_path, atomic_copy = manager.under_root, manager._copy_path, manager._atomic_copy

            def map_root(_root, path):
                return under_root(root, path)

            def renderer(stage, _selected):
                events.append("read")
                self.assertIn("password", yaml.read_text(encoding="utf-8"))
                (stage / "AdGuardHome.yaml").write_text("dns: {}\n")
                (stage / "nginx-stream.conf").write_text("stream")
                (stage / "health-policy.json").write_text("{}")

            def copy(source, destination):
                if Path(source) == yaml:
                    events.append("snapshot")
                return copy_path(source, destination)

            def activate(source, target):
                if Path(target) == yaml:
                    events.append("activate")
                return atomic_copy(source, target)

            with mock.patch.object(manager, "under_root", side_effect=map_root), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=lambda *_a, **_k: events.append("stop")), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services", side_effect=lambda *_a, **_k: events.append("start")), \
                 mock.patch.object(manager, "_copy_path", side_effect=copy), \
                 mock.patch.object(manager, "_atomic_copy", side_effect=activate):
                manager.apply_service_change(["chatgpt"], root=Path("/"), catalog=catalog,
                                             renderer=renderer, validator=lambda: None)
            self.assertEqual(["stop", "read", "snapshot", "snapshot", "activate", "start"], events)

    def test_live_rollback_stops_before_saving_current_yaml_and_restoring(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            before = yaml.read_text(encoding="utf-8")
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            yaml.write_text("current", encoding="utf-8")
            events = []
            under_root, copy_path, restore_backup = manager.under_root, manager._copy_path, manager._restore_backup

            def copy(source, destination):
                if Path(source) == yaml:
                    events.append("snapshot")
                return copy_path(source, destination)

            def restore(*args, **kwargs):
                events.append("restore")
                return restore_backup(*args, **kwargs)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=lambda *_a, **_k: events.append("stop")), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "_reload_restored_runtime", side_effect=lambda *_a, **_k: events.append("start")), \
                 mock.patch.object(manager, "_copy_path", side_effect=copy), \
                 mock.patch.object(manager, "_restore_backup", side_effect=restore):
                self.assertTrue(manager.rollback_last(Path("/"), selected=backup, runner=mock.Mock()))
            self.assertEqual(["stop", "snapshot", "restore", "start"], events)
            self.assertEqual(before, yaml.read_text(encoding="utf-8"))

    def test_live_failure_or_interrupt_recovers_runtime_and_reports_recovery_failure(self):
        manager = load_manager()
        for original in (RuntimeError("failed"), KeyboardInterrupt()):
            with self.subTest(original=type(original).__name__), \
                 mock.patch.object(manager, "operation_lock", return_value=contextlib.nullcontext()), \
                 mock.patch.object(manager, "health_lock", return_value=contextlib.nullcontext()), \
                 mock.patch.object(manager, "_check_incomplete_transactions"), \
                 mock.patch.object(manager, "_read_json", return_value={"domain": "dns.example.com"}), \
                 mock.patch.object(manager, "_stop_adguard") as stop, \
                 mock.patch.object(manager, "_apply_service_change_locked", side_effect=original), \
                 mock.patch.object(manager, "reload_runtime_services") as reload:
                with self.assertRaises(type(original)):
                    manager.apply_service_change(["chatgpt"], root=Path("/"))
                stop.assert_called_once()
                reload.assert_called_once()
        with mock.patch.object(manager, "operation_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(manager, "health_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(manager, "_check_incomplete_transactions"), \
             mock.patch.object(manager, "_read_json", return_value={"domain": "dns.example.com"}), \
             mock.patch.object(manager, "_stop_adguard"), \
             mock.patch.object(manager, "_apply_service_change_locked", side_effect=RuntimeError("activation")), \
             mock.patch.object(manager, "reload_runtime_services", side_effect=RuntimeError("restart")):
            with self.assertRaisesRegex(RuntimeError, "restoring previous runtime also failed: restart"):
                manager.apply_service_change(["chatgpt"], root=Path("/"))

    def test_live_activation_failure_restores_yaml_before_restart(self):
        manager = load_manager()
        for original in (RuntimeError("invalid"), KeyboardInterrupt()):
            with self.subTest(original=type(original).__name__), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
                before = yaml.read_text(encoding="utf-8")
                events = []
                under_root = manager.under_root

                def renderer(stage, _selected):
                    (stage / "AdGuardHome.yaml").write_text("new yaml", encoding="utf-8")
                    (stage / "nginx-stream.conf").write_text("stream", encoding="utf-8")
                    (stage / "health-policy.json").write_text("{}", encoding="utf-8")

                def validate():
                    self.assertEqual("new yaml", yaml.read_text(encoding="utf-8"))
                    raise original

                def reload(*_args, **_kwargs):
                    events.append(("restart", yaml.read_text(encoding="utf-8")))

                with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                     mock.patch.object(manager, "_stop_adguard", side_effect=lambda *_a, **_k: events.append(("stop", None))), \
                     mock.patch.object(manager, "_validate_staged_adguard"), \
                     mock.patch.object(manager, "reload_runtime_services", side_effect=reload):
                    with self.assertRaises(type(original)):
                        manager.apply_service_change(["chatgpt"], root=Path("/"), renderer=renderer,
                                                     validator=validate)
                self.assertEqual([("stop", None), ("stop", None), ("restart", before)], events)
                self.assertEqual(before, yaml.read_text(encoding="utf-8"))

    def test_activation_smoke_failure_stops_new_process_before_file_recovery(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            previous = yaml.read_text(encoding="utf-8")
            events = []
            under_root, restore_entries = manager.under_root, manager._restore_transaction_entries

            def renderer(stage, _selected):
                (stage / "AdGuardHome.yaml").write_text("new yaml")
                (stage / "nginx-stream.conf").write_text("stream")
                (stage / "health-policy.json").write_text("{}")

            def reload(*_args, **_kwargs):
                if not any(event == "start new" for event in events):
                    self.assertEqual("new yaml", yaml.read_text())
                    events.extend(("start new", "smoke failure"))
                    raise RuntimeError("smoke failure")
                self.assertEqual(previous, yaml.read_text())
                events.append("start previous")

            def restore(saved):
                self.assertEqual("new yaml", yaml.read_text())
                events.append("restore files")
                return restore_entries(saved)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=lambda *_a, **_k: events.append("stop")), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services", side_effect=reload), \
                 mock.patch.object(manager, "_restore_transaction_entries", side_effect=restore):
                with self.assertRaisesRegex(RuntimeError, "smoke failure"):
                    manager.apply_service_change(["chatgpt"], root=Path("/"), renderer=renderer,
                                                 validator=lambda: None)
            self.assertEqual(["stop", "start new", "smoke failure", "stop",
                              "restore files", "start previous"], events)
            self.assertEqual(previous, yaml.read_text())

    def test_activation_failed_stop_keeps_new_yaml_and_pending_transaction(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            under_root = manager.under_root
            stops = []

            def renderer(stage, _selected):
                (stage / "AdGuardHome.yaml").write_text("new yaml")
                (stage / "nginx-stream.conf").write_text("stream")
                (stage / "health-policy.json").write_text("{}")

            def stop(*_args, **_kwargs):
                stops.append("stop")
                if len(stops) == 2:
                    raise RuntimeError("cannot stop")

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=stop), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services", side_effect=RuntimeError("smoke")) as reload, \
                 mock.patch.object(manager, "_restore_transaction_entries") as restore:
                with self.assertRaisesRegex(RuntimeError, "AdGuard may still be running"):
                    manager.apply_service_change(["chatgpt"], root=Path("/"), renderer=renderer,
                                                 validator=lambda: None)
            self.assertEqual(2, len(stops))
            reload.assert_called_once()
            restore.assert_not_called()
            self.assertEqual("new yaml", yaml.read_text())
            markers = list((root / "var/backups/adguardhome-doh").glob("*/transaction.json"))
            self.assertEqual(1, len(markers))
            self.assertEqual("prepared", json.loads(markers[0].read_text())["state"])
            with self.assertRaisesRegex(RuntimeError, "unfinished transaction"):
                manager._check_incomplete_transactions(root)

    def test_rollback_smoke_failure_stops_restored_process_before_file_recovery(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            backup_yaml = yaml.read_text(encoding="utf-8")
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            yaml.write_text("current yaml")
            events = []
            under_root, restore_entries = manager.under_root, manager._restore_transaction_entries

            def reload_rollback(*_args, **_kwargs):
                self.assertEqual(backup_yaml, yaml.read_text())
                events.extend(("start rollback", "smoke failure"))
                raise RuntimeError("smoke failure")

            def restore(saved):
                self.assertEqual(backup_yaml, yaml.read_text())
                events.append("restore files")
                return restore_entries(saved)

            def reload_previous(*_args, **_kwargs):
                self.assertEqual("current yaml", yaml.read_text())
                events.append("start previous")

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=lambda *_a, **_k: events.append("stop")), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "_reload_restored_runtime", side_effect=reload_rollback), \
                 mock.patch.object(manager, "reload_runtime_services", side_effect=reload_previous), \
                 mock.patch.object(manager, "_restore_transaction_entries", side_effect=restore):
                with self.assertRaisesRegex(RuntimeError, "smoke failure"):
                    manager.rollback_last(Path("/"), selected=backup, runner=mock.Mock())
            self.assertEqual(["stop", "start rollback", "smoke failure", "stop",
                              "restore files", "start previous"], events)
            self.assertEqual("current yaml", yaml.read_text())

    def test_rollback_failed_stop_keeps_files_and_pending_transaction(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            yaml = root / "opt/AdGuardHome/AdGuardHome.yaml"
            backup_yaml = yaml.read_text(encoding="utf-8")
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            yaml.write_text("current yaml")
            stops = []
            under_root = manager.under_root

            def stop(*_args, **_kwargs):
                stops.append("stop")
                if len(stops) == 2:
                    raise RuntimeError("cannot stop")

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_stop_adguard", side_effect=stop), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "_reload_restored_runtime", side_effect=RuntimeError("smoke")), \
                 mock.patch.object(manager, "reload_runtime_services") as reload, \
                 mock.patch.object(manager, "_restore_transaction_entries") as restore:
                with self.assertRaisesRegex(RuntimeError, "AdGuard may still be running"):
                    manager.rollback_last(Path("/"), selected=backup, runner=mock.Mock())
            self.assertEqual(2, len(stops))
            reload.assert_not_called()
            restore.assert_not_called()
            self.assertEqual(backup_yaml, yaml.read_text())
            markers = list((root / "var/backups/adguardhome-doh").glob(".restore-*/transaction.json"))
            self.assertEqual(1, len(markers))
            self.assertEqual("prepared", json.loads(markers[0].read_text())["state"])
            with self.assertRaisesRegex(RuntimeError, "unfinished transaction"):
                manager._check_incomplete_transactions(root)

    def test_live_file_recovery_failure_leaves_adguard_stopped(self):
        manager = load_manager()
        with mock.patch.object(manager, "operation_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(manager, "health_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(manager, "_check_incomplete_transactions"), \
             mock.patch.object(manager, "_read_json", return_value={"domain": "dns.example.com"}), \
             mock.patch.object(manager, "_stop_adguard") as stop, \
             mock.patch.object(manager, "_apply_service_change_locked",
                               side_effect=manager._FileRecoveryError("disk error")), \
             mock.patch.object(manager, "reload_runtime_services") as reload:
            with self.assertRaisesRegex(RuntimeError, "AdGuard left stopped"):
                manager.apply_service_change(["chatgpt"], root=Path("/"))
            stop.assert_called_once()
            reload.assert_not_called()

    def test_live_rollback_error_or_failed_stop_restarts_previous_runtime(self):
        manager = load_manager()
        for failed_stop in (False, True):
            with self.subTest(failed_stop=failed_stop):
                events = []

                def stop(*_args, **_kwargs):
                    events.append("stop")
                    if failed_stop:
                        raise RuntimeError("stop failed")

                def restore(*_args, **_kwargs):
                    events.append("restore")
                    raise RuntimeError("restore failed")

                with mock.patch.object(manager, "operation_lock", return_value=contextlib.nullcontext()), \
                     mock.patch.object(manager, "health_lock", return_value=contextlib.nullcontext()), \
                     mock.patch.object(manager, "_check_incomplete_transactions"), \
                     mock.patch.object(manager, "_validated_backup_manifest"), \
                     mock.patch.object(manager, "_backup_operation", return_value="update"), \
                     mock.patch.object(manager, "_current_install_state", return_value={"domain": "dns.example.com"}), \
                     mock.patch.object(manager, "_stop_adguard", side_effect=stop), \
                     mock.patch.object(manager, "restore_backup_runtime", side_effect=restore), \
                     mock.patch.object(manager, "reload_runtime_services", side_effect=lambda *_a, **_k: events.append("restart")):
                    with self.assertRaises(RuntimeError):
                        manager.rollback_last(Path("/"), selected=Path("/backup"), runner=mock.Mock())
                self.assertEqual(["stop", "restart"] if failed_stop else ["stop", "restore", "restart"], events)

    def test_service_change_removes_compat_policy_only_after_success(self):
        manager = load_manager()
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                install = root / "var/lib/adguardhome-doh/install.json"
                state = json.loads(install.read_text())
                state["policy"] = "/etc/adguardhome-doh/compat-policy.csv"
                install.write_text(json.dumps(state), encoding="utf-8")

                def renderer(stage, _selected):
                    (stage / "AdGuardHome.yaml").write_text("dns: {}\n")
                    (stage / "nginx-stream.conf").write_text("stream")
                    (stage / "health-policy.json").write_text("{}")

                def validator():
                    if fail:
                        raise RuntimeError("invalid")

                if fail:
                    with self.assertRaisesRegex(RuntimeError, "invalid"):
                        manager.apply_service_change(["chatgpt"], root=root, renderer=renderer,
                                                     validator=validator)
                else:
                    manager.apply_service_change(["chatgpt"], root=root, renderer=renderer,
                                                 validator=validator)
                current = json.loads(install.read_text())
                self.assertEqual(fail, "policy" in current)

    def test_service_change_keeps_the_relay_exit_host(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            (root / "var/lib/adguardhome-doh/install.json").write_text(
                json.dumps({"domain": "dns.example.com", "public_ip": "203.0.113.10",
                            "relay": "203.0.113.99",
                            "local_sites": ["app.example.org=127.0.0.1:9443"]}),
                encoding="utf-8",
            )
            captured = {}
            real_run = subprocess.run

            def fake_run(command, **kwargs):
                captured["command"] = list(command)
                return real_run(command, **kwargs)

            with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
                try:
                    manager.apply_service_change(["chatgpt"], root=root, validator=lambda: None)
                except Exception:
                    pass

        command = captured.get("command")
        self.assertIsNotNone(command)
        self.assertEqual("203.0.113.99", command[command.index("--relay") + 1])
        self.assertEqual("203.0.113.10", command[command.index("--public-ip") + 1])
        self.assertEqual("app.example.org=127.0.0.1:9443", command[command.index("--local-site") + 1])

    def test_update_command_keeps_the_relay_exit_host(self):
        manager = load_manager()
        releases = manager._load_releases()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            (root / "var/lib/adguardhome-doh/install.json").write_text(
                json.dumps({"domain": "dns.example.com", "public_ip": "203.0.113.10",
                            "email": "admin@example.com", "version": "1.0.0",
                            "repository": "custom-owner/private-doh",
                            "relay": "203.0.113.99",
                            "local_sites": ["app.example.org=127.0.0.1:9443", "*=127.0.0.1:9443"]}),
                encoding="utf-8",
            )
            fixture = Path(directory) / "fixture" / "adguardhome-doh-9.9.9"
            # The archive contract lists every required file; real copies
            # keep the catalog loadable, stubs satisfy the rest.
            for name in releases.REQUIRED_FILES:
                target = fixture / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if (ROOT / name).is_file() and name != "VERSION":
                    shutil.copy2(ROOT / name, target)
                else:
                    target.write_text("# fixture\n", encoding="utf-8")
            (fixture / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            (fixture / "deploy/install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (fixture / "deploy/install.sh").chmod(0o755)
            archive = Path(directory) / "adguardhome-doh.tar.gz"
            subprocess.run(["tar", "-czf", str(archive), "adguardhome-doh-9.9.9"],
                           cwd=fixture.parent, check=True)
            checksum = Path(directory) / "adguardhome-doh.tar.gz.sha256"
            checksum.write_text(
                "%s  adguardhome-doh.tar.gz\n" % hashlib.sha256(archive.read_bytes()).hexdigest(),
                encoding="utf-8",
            )
            release = releases.parse_release({
                "tag_name": "v9.9.9", "draft": False, "prerelease": False,
                "assets": [
                    {"name": "adguardhome-doh.tar.gz", "browser_download_url": "https://fixture/archive"},
                    {"name": "adguardhome-doh.tar.gz.sha256", "browser_download_url": "https://fixture/checksum"},
                ],
            })
            commands = []
            environments = []

            def downloader(url, path):
                shutil.copy2(archive if url.endswith("archive") else checksum, path)

            def runner(command, **kwargs):
                commands.append([str(part) for part in command])
                environments.append(kwargs["env"])
                for lock_path in (manager.HEALTH_LOCK, manager.OPERATION_LOCK):
                    lock = manager.under_root(root, lock_path)
                    with lock.open("a+") as stream:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                return subprocess.CompletedProcess(command, 0)

            old_catalog = Catalog.load(root / "etc/adguardhome-doh/catalog")
            new_catalog = SimpleNamespace(
                services=old_catalog.services,
                default_service_ids=old_catalog.default_service_ids,
                full_policy=lambda: list(old_catalog.full_policy()) + [SimpleNamespace(domain="new.example")],
            )
            warning = io.StringIO()
            with mock.patch.object(manager, "_load_catalog", side_effect=lambda path: (
                old_catalog if Path(path) == root / "etc/adguardhome-doh/catalog" else new_catalog
            )):
                self.assertTrue(manager.install_update(
                    root=root, release=release, downloader=downloader, runner=runner, output=warning
                ))
                state_file = root / "var/lib/adguardhome-doh/install.json"
                state = json.loads(state_file.read_text())
                state["policy"] = "/etc/adguardhome-doh/compat-policy.csv"
                state_file.write_text(json.dumps(state), encoding="utf-8")
                policy = root / "etc/adguardhome-doh/compat-policy.csv"
                policy.write_text("domain,kind,probe\n", encoding="utf-8")
                self.assertTrue(manager.install_update(
                    root=root, release=release, downloader=downloader, runner=runner, output=warning
                ))
            policy_command = commands[-1]
            self.assertEqual(str(policy), policy_command[policy_command.index("--policy") + 1])
            self.assertNotIn("--services", policy_command)
            self.assertEqual(2, len(commands))
            self.assertNotIn("--front", commands[0])
            self.assertNotIn("--front", policy_command)
            self.assertIn("заново установите Apple-профиль", warning.getvalue())
            self.assertEqual("custom-owner/private-doh", environments[0]["ADGUARDHOME_DOH_REPOSITORY"])
            self.assertEqual("1", environments[0]["ADGUARDHOME_DOH_MANAGER_UPDATE"])

        install = next(c for c in commands if any(part.endswith("deploy/install.sh") for part in c))
        # The relay must survive an update, or the exit host silently becomes
        # the real sites and every routed service breaks on the client path.
        self.assertEqual("203.0.113.99", install[install.index("--relay") + 1])
        self.assertEqual("203.0.113.10", install[install.index("--public-ip") + 1])
        self.assertIn("--update", install)
        self.assertEqual(2, install.count("--local-site"))
        self.assertIn("*=127.0.0.1:9443", install)

    def test_shared_update_is_blocked_before_release_lookup_download_or_installer(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            state_file = root / "var/lib/adguardhome-doh/install.json"
            state = json.loads(state_file.read_text())
            state["front"] = "mtproxyl"
            state_file.write_text(json.dumps(state))
            for release in (None, object()):
                with self.subTest(release=release), mock.patch.object(manager, "_load_releases") as loader:
                    downloader = mock.Mock()
                    runner = mock.Mock()
                    with self.assertRaisesRegex(RuntimeError, "обновление с общим front MTProxyL временно отключено"):
                        manager.install_update(root=root, release=release, downloader=downloader, runner=runner)
                    loader.assert_not_called()
                    downloader.assert_not_called()
                    runner.assert_not_called()

    def test_healthy_services_ignores_unselected_and_unproven_services(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            paths = manager._runtime_paths(root)

            self.assertEqual(
                ["chatgpt"], manager.healthy_services(paths, ["chatgpt", "claude"])
            )
            self.assertEqual([], manager.healthy_services(paths, ["claude"]))

            (root / "var/lib/adguardhome-doh/health-state.json").write_text(
                "not json", encoding="utf-8"
            )
            self.assertEqual([], manager.healthy_services(paths, ["chatgpt"]))

class MTProxyFrontTests(unittest.TestCase):
    def build_root(self, directory):
        root = ServiceChangeSeedingTests.build_root(self, directory)
        state_file = root / "var/lib/adguardhome-doh/install.json"
        state = json.loads(state_file.read_text())
        state["front"] = "mtproxyl"
        state_file.write_text(json.dumps(state), encoding="utf-8")
        for relative, content in (
            ("etc/adguardhome-doh/mtproxyl-sni.map", "old map"),
            ("etc/adguardhome-doh/mtproxyl-nginx.conf", "old dedicated config"),
            ("etc/systemd/system/adguardhome-doh-nginx.service", "old dedicated unit"),
            ("etc/adguardhome-doh/mtproxyl-http-site.conf", "old private http"),
            ("etc/adguardhome-doh/mtproxyl-stream-site.conf", "old private stream"),
            ("opt/AdGuardHome/AdGuardHome", "binary"),
            ("usr/local/libexec/adguardhome-doh/healthcheck.py", "helper"),
            ("usr/local/libexec/adguardhome-doh/mtproxyl_front.py", "front helper"),
            ("etc/adguardhome-doh/mtproxyl-http.conf", "front http"),
            ("etc/systemd/system/mtproxyl-pq-nginx.service.d/adguardhome-doh.conf", "front dropin"),
            ("opt/mtproxyl/nginx-custom.conf", "user config"),
            ("opt/mtproxyl-nginx/sbin/nginx", "test binary"),
            ("opt/mtproxyl-nginx/conf/nginx.conf", "generated config"),
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        (root / "opt/mtproxyl-nginx/sbin/nginx").chmod(0o755)
        proc = root / "proc/123/cmdline"
        proc.parent.mkdir(parents=True, exist_ok=True)
        proc.write_bytes(b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl-nginx/conf/nginx.conf\0-g\0daemon off;\0")
        (proc.parent / "exe").symlink_to("/opt/mtproxyl-nginx/sbin/nginx")
        return root

    def test_service_change_passes_front_preserves_map_and_front_state(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            state_file = root / "var/lib/adguardhome-doh/install.json"
            state = json.loads(state_file.read_text())
            state["policy"] = "/etc/adguardhome-doh/compat-policy.csv"
            state_file.write_text(json.dumps(state), encoding="utf-8")
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            system_stream = root / "etc/nginx/stream.d/adguardhome-doh.conf"
            system_stream.parent.mkdir(parents=True)
            system_stream.write_text("unrelated system nginx stream")
            calls = []

            def render(command, **_kwargs):
                calls.append(command)
                stage = Path(command[command.index("--output") + 1])
                (stage / "AdGuardHome.yaml").write_text("dns: {}\n")
                (stage / "nginx-stream.conf").write_text("loopback")
                (stage / "health-policy.json").write_text("{}")
                (stage / "mtproxyl-sni.map").write_text("different staged map")
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(manager.subprocess, "run", side_effect=render):
                manager.apply_service_change(["chatgpt"], root=root, validator=lambda: None)
            command = calls[0]
            self.assertEqual("mtproxyl", command[command.index("--front") + 1])
            self.assertNotIn("a" * 48, command)
            self.assertEqual("old map", map_path.read_text())
            self.assertEqual("loopback", (root / "etc/adguardhome-doh/mtproxyl-stream-site.conf").read_text())
            self.assertEqual("unrelated system nginx stream", system_stream.read_text())
            state = json.loads(state_file.read_text())
            self.assertEqual("mtproxyl", state["front"])
            self.assertNotIn("policy", state)
            self.assertFalse(any("mtproxyl-pq-nginx" in part for call in calls for part in call))

    def test_real_renderer_service_change_uses_loopback_without_replacing_front_map(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            manager.apply_service_change(["chatgpt"], root=root, validator=lambda: None)
            stream = (root / "etc/adguardhome-doh/mtproxyl-stream-site.conf").read_text()
            self.assertIn("listen 127.0.0.1:24443 proxy_protocol", stream)
            self.assertNotIn("listen 443", stream)
            self.assertEqual("old map", map_path.read_text())
            self.assertFalse((root / "etc/nginx/stream.d/adguardhome-doh.conf").exists())

    def test_shared_activation_failure_restores_private_stream_only(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            private = root / "etc/adguardhome-doh/mtproxyl-stream-site.conf"
            system = root / "etc/nginx/stream.d/adguardhome-doh.conf"
            system.parent.mkdir(parents=True)
            system.write_text("unrelated system stream")

            def renderer(stage, _selected):
                (stage / "AdGuardHome.yaml").write_text("dns: {}\n")
                (stage / "nginx-stream.conf").write_text("new private stream")
                (stage / "health-policy.json").write_text("{}")

            def validator():
                self.assertEqual("new private stream", private.read_text())
                raise RuntimeError("validation failed")

            with self.assertRaisesRegex(RuntimeError, "validation failed"):
                manager.apply_service_change(["chatgpt"], root=root, renderer=renderer, validator=validator)
            self.assertEqual("old private stream", private.read_text())
            self.assertEqual("unrelated system stream", system.read_text())

    def test_shared_service_change_rejects_missing_site_before_rendering(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            private = root / "etc/adguardhome-doh/mtproxyl-stream-site.conf"
            private.unlink()
            renderer = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "файл общего front отсутствует"):
                manager.apply_service_change(["chatgpt"], root=root, renderer=renderer, validator=lambda: None)
            renderer.assert_not_called()
            self.assertFalse(private.exists())

    def test_front_runtime_reloads_only_private_nginx_and_probes_doh(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            under_root = manager.under_root
            runner = mock.Mock()
            probe = mock.Mock(return_value=True)
            output = io.StringIO()
            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck", return_value=SimpleNamespace(probe_doh=probe)), \
                 mock.patch("sys.stdout", output):
                manager.reload_runtime_services(Path("/"), "dns.example.com", runner=runner,
                                                smoke_attempts=1, smoke_delay=0)
            self.assertEqual([
                mock.call(["systemctl", "restart", "adguardhome-doh"], check=True),
                mock.call(["systemctl", "reload", "adguardhome-doh-nginx"], check=True),
            ], runner.call_args_list)
            self.assertEqual("dns.example.com", probe.call_args.args[0])
            self.assertEqual("a" * 48, probe.call_args.args[1])
            self.assertNotIn("a" * 48, str(runner.call_args_list))
            self.assertNotIn("a" * 48, output.getvalue())

    def test_front_status_uses_private_nginx_and_mtproxy(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            calls = []

            def runner(command, **_kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, b"Result=success\nExecMainStatus=0\n", b"")

            status = manager.collect_menu_status(root, runner=runner)
            report = manager.collect_system_check(root, runner=runner)
            menu, diagnostic = io.StringIO(), io.StringIO()
            manager.render_main_screen(status, menu, width=80)
            manager._render_system_check(report, diagnostic)
            self.assertEqual("running", status["overall"])
            self.assertIn("nginx DoH", menu.getvalue())
            self.assertIn("MTProxy front", menu.getvalue())
            self.assertIn("MTProxy front", diagnostic.getvalue())
            self.assertIn(["/usr/sbin/nginx", "-t", "-c", manager.PRIVATE_NGINX_CONFIG], calls)
            self.assertIn(["/opt/mtproxyl-nginx/sbin/nginx", "-t", "-c", "/opt/mtproxyl-nginx/conf/nginx.conf"], calls)
            self.assertNotIn(["systemctl", "is-active", "--quiet", "nginx.service"], calls)
            def front_down(command, **_kwargs):
                return subprocess.CompletedProcess(command, 3 if command[-1] == "mtproxyl-pq-nginx.service" else 0)
            down = manager.collect_menu_status(root, runner=front_down)
            self.assertEqual("attention", down["overall"])
            self.assertFalse(down["units"]["mtproxyl-pq-nginx.service"])

    def test_active_mtproxy_config_requires_stable_pid_and_exact_argv(self):
        manager = load_manager()
        valid = b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl-nginx/conf/nginx.conf\0-g\0daemon off;\0"
        title = b"nginx: master process /opt/mtproxyl-nginx/sbin/nginx -c /opt/mtproxyl-nginx/conf/nginx.conf -g daemon off;\0"
        expected_exe = "/opt/mtproxyl-nginx/sbin/nginx"
        cases = (
            (valid, expected_exe, (b"123\n", b"123\n"), True),
            (title, expected_exe, (b"123\n", b"123\n"), True),
            (valid.replace(b"/opt/mtproxyl-nginx/conf/nginx.conf", b"/opt/mtproxyl/nginx-custom.conf"),
             expected_exe, (b"123\n", b"123\n"), False),
            (title.replace(b"/opt/mtproxyl-nginx/conf/nginx.conf", b"/opt/mtproxyl/nginx-custom.conf"),
             expected_exe, (b"123\n", b"123\n"), False),
            (valid.replace(b"/opt/mtproxyl-nginx/sbin/nginx", b"/usr/sbin/nginx"),
             expected_exe, (b"123\n", b"123\n"), False),
            (title, "/usr/sbin/nginx", (b"123\n", b"123\n"), False),
            (title, expected_exe + " (deleted)", (b"123\n", b"123\n"), False),
            (valid + b"-c\0/other.conf\0", expected_exe, (b"123\n", b"123\n"), False),
            (b"nginx: master process nginx\0", expected_exe, (b"123\n", b"123\n"), False),
            (b"nginx: master process /opt/mtproxyl-nginx/sbin/nginx -c 'unterminated\0",
             expected_exe, (b"123\n", b"123\n"), False),
            (title[:-1], expected_exe, (b"123\n", b"123\n"), False),
            (title, expected_exe, (b"123\n", b"456\n"), False),
            (valid, expected_exe, (b"0\n", b"0\n"), False),
            (valid, None, (b"123\n", b"123\n"), False),
        )
        for argv, executable, pids, expected in cases:
            with self.subTest(argv=argv, executable=executable, pids=pids), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                (root / "proc/123/cmdline").write_bytes(argv)
                exe_link = root / "proc/123/exe"
                exe_link.unlink()
                if executable is not None:
                    exe_link.symlink_to(executable)
                under_root = manager.under_root
                outputs = iter(pids)

                def runner(command, **_kwargs):
                    return subprocess.CompletedProcess(command, 0, next(outputs), b"")

                with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)):
                    if expected:
                        self.assertEqual(123, manager._verify_mtproxyl_active_config(Path("/"), runner))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                            manager._verify_mtproxyl_active_config(Path("/"), runner)

    def test_unverified_runtime_front_and_degraded_fallback_block_changes(self):
        from deploy.lib.mtproxyl_front import patch
        from tests.test_mtproxyl_front import DOMAIN, REALISTIC

        manager = load_manager()
        for condition, content in (("prepared_overlay", patch(REALISTIC, DOMAIN)),
                                   ("degraded_fallback", REALISTIC)):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                runtime = root / "run/adguardhome-doh/mtproxyl-nginx.conf"
                runtime.parent.mkdir(parents=True)
                runtime.write_text(content)
                runtime.chmod(0o600)
                backup = manager.create_backup(root, operation="update", domain=DOMAIN)
                manager.finalize_update_backup(backup, root, DOMAIN)
                map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
                map_path.write_text("current map")
                (root / "proc/123/cmdline").write_bytes(
                    b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0"
                    b"/run/adguardhome-doh/mtproxyl-nginx.conf\0-g\0daemon off;\0"
                )
                commands = []

                def runner(command, **_kwargs):
                    commands.append(command)
                    stdout = b"123\n" if command[:2] == ["systemctl", "show"] else b""
                    return subprocess.CompletedProcess(command, 0, stdout, b"")

                under_root = manager.under_root
                with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                     mock.patch.object(manager, "_load_healthcheck"), \
                     mock.patch.object(manager.subprocess, "run", side_effect=runner), \
                     mock.patch.object(manager, "_stop_adguard") as stop:
                    status = manager.collect_menu_status(Path("/"), runner=runner)
                    report = manager.collect_system_check(Path("/"), runner=runner)
                    with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                        manager.apply_service_change(["chatgpt"], root=Path("/"))
                    with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                        manager.rollback_last(Path("/"), selected=backup, runner=runner)
                stop.assert_not_called()
                self.assertFalse(status["front_config_supported"])
                self.assertEqual("attention", status["overall"])
                self.assertFalse(report["mtproxyl_config"])
                self.assertNotIn(["systemctl", "reload", "mtproxyl-pq-nginx"], commands)
                self.assertEqual("current map", map_path.read_text())

    def test_custom_mode_blocks_live_service_change_before_stop(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            (root / "proc/123/cmdline").write_bytes(
                b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl/nginx-custom.conf\0"
            )
            under_root = manager.under_root
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"123\n", b""))
            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager.subprocess, "run", runner), \
                 mock.patch.object(manager, "_stop_adguard") as stop:
                with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                    manager.apply_service_change(["chatgpt"], root=Path("/"))
            stop.assert_not_called()

    def test_custom_mode_blocks_live_rollback_before_stop(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            map_path.write_text("new map")
            (root / "proc/123/cmdline").write_bytes(
                b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl/nginx-custom.conf\0"
            )
            under_root = manager.under_root
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"123\n", b""))
            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_stop_adguard") as stop:
                with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                    manager.rollback_last(Path("/"), selected=backup, runner=runner)
            stop.assert_not_called()
            self.assertEqual("new map", map_path.read_text())

    def test_custom_mode_is_not_reported_as_healthy_configuration(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            (root / "proc/123/cmdline").write_bytes(
                b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl/nginx-custom.conf\0"
            )
            under_root = manager.under_root
            commands = []

            def runner(command, **_kwargs):
                commands.append(command)
                output = b"123\n" if "--property=MainPID" in command else b"Result=success\nExecMainStatus=0\n"
                return subprocess.CompletedProcess(command, 0, output, b"")

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)):
                status = manager.collect_menu_status(Path("/"), runner=runner)
                report = manager.collect_system_check(Path("/"), runner=runner)
            menu = io.StringIO()
            manager.render_main_screen(status, menu, width=80)
            self.assertEqual("attention", status["overall"])
            self.assertFalse(status["front_config_supported"])
            self.assertIn("Активная конфигурация MTProxy не подтверждена", menu.getvalue())
            self.assertFalse(report["mtproxyl_config"])
            self.assertNotIn([manager.MTPROXY_NGINX_BINARY, "-t", "-c", manager.MTPROXY_NGINX_CONFIG], commands)

    def test_mtproxy_pid_change_after_validation_blocks_reload(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            under_root = manager.under_root
            outputs = iter((b"123\n", b"123\n", b"123\n", b"456\n"))
            commands = []

            def runner(command, **_kwargs):
                commands.append(command)
                if command[:2] == ["systemctl", "show"]:
                    return subprocess.CompletedProcess(command, 0, next(outputs), b"")
                return subprocess.CompletedProcess(command, 0, b"", b"")

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)):
                with self.assertRaisesRegex(RuntimeError, "custom mode не поддерживается"):
                    manager._reload_mtproxyl_map(Path("/"), runner)
            self.assertIn([manager.MTPROXY_NGINX_BINARY, "-t", "-c", manager.MTPROXY_NGINX_CONFIG], commands)
            self.assertNotIn(["systemctl", "reload", "mtproxyl-pq-nginx"], commands)

    def test_front_backup_and_rollback_preserve_user_mtproxy_config(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            external = root / "opt/mtproxyl/nginx-custom.conf"
            external.parent.mkdir(parents=True, exist_ok=True)
            external.write_text("user config", encoding="utf-8")
            system_config = root / "etc/nginx/nginx.conf"
            system_config.parent.mkdir(parents=True)
            system_config.write_text("system config", encoding="utf-8")
            system_site = root / "etc/nginx/sites-enabled/adguardhome-doh"
            system_site.parent.mkdir(parents=True)
            system_site.write_text("old system site")
            system_stream = root / "etc/nginx/stream.d/adguardhome-doh.conf"
            system_stream.parent.mkdir(parents=True)
            system_stream.write_text("old system stream")
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            manifest = json.loads((backup / "manifest.json").read_text())
            self.assertEqual(4, manifest["version"])
            self.assertTrue(set(manager.FRONT_MANAGED_FILES).issubset({item["path"] for item in manifest["files"]}))
            self.assertNotIn("/opt/mtproxyl/nginx-custom.conf", {item["path"] for item in manifest["files"]})
            self.assertNotIn("/opt/mtproxyl-nginx/conf/nginx.conf", {item["path"] for item in manifest["files"]})
            (root / "etc/adguardhome-doh/mtproxyl-sni.map").write_text("new map")
            (root / "etc/adguardhome-doh/mtproxyl-nginx.conf").write_text("new dedicated config")
            (root / "etc/systemd/system/adguardhome-doh-nginx.service").write_text("new dedicated unit")
            (root / "etc/adguardhome-doh/mtproxyl-http-site.conf").write_text("new private http")
            (root / "etc/adguardhome-doh/mtproxyl-stream-site.conf").write_text("new private stream")
            external.write_text("user changed config", encoding="utf-8")
            system_config.write_text("system changed config", encoding="utf-8")
            system_site.write_text("user changed system site")
            system_stream.write_text("user changed system stream")
            self.assertTrue(manager.rollback_last(root))
            self.assertEqual("old map", (root / "etc/adguardhome-doh/mtproxyl-sni.map").read_text())
            self.assertEqual("old dedicated config", (root / "etc/adguardhome-doh/mtproxyl-nginx.conf").read_text())
            self.assertEqual("old dedicated unit", (root / "etc/systemd/system/adguardhome-doh-nginx.service").read_text())
            self.assertEqual("old private http", (root / "etc/adguardhome-doh/mtproxyl-http-site.conf").read_text())
            self.assertEqual("old private stream", (root / "etc/adguardhome-doh/mtproxyl-stream-site.conf").read_text())
            self.assertEqual("user changed config", external.read_text())
            self.assertEqual("system changed config", system_config.read_text())
            self.assertEqual("user changed system site", system_site.read_text())
            self.assertEqual("user changed system stream", system_stream.read_text())
            self.assertEqual("mtproxyl", json.loads((root / "var/lib/adguardhome-doh/install.json").read_text())["front"])

    def test_files_only_shared_restore_preserves_system_nginx_sites(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            system_site = root / "etc/nginx/sites-enabled/adguardhome-doh"
            system_site.parent.mkdir(parents=True)
            system_site.write_text("old system site")
            system_stream = root / "etc/nginx/stream.d/adguardhome-doh.conf"
            system_stream.parent.mkdir(parents=True)
            system_stream.write_text("old system stream")
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            system_site.write_text("user changed system site")
            system_stream.write_text("user changed system stream")
            private = root / "etc/adguardhome-doh/mtproxyl-stream-site.conf"
            private.write_text("changed private stream")
            result = manager.main(["--restore-update-backup", str(backup), "--root", str(root),
                                   "--domain", "dns.example.com", "--files-only", "--preserve-system-nginx"])
            self.assertEqual(0, result)
            self.assertEqual("user changed system site", system_site.read_text())
            self.assertEqual("user changed system stream", system_stream.read_text())
            self.assertEqual("old private stream", private.read_text())

    def test_files_only_shared_reload_is_transactional(self):
        manager = load_manager()
        cases = (
            ("success", set(), set(), "committed"),
            ("reload_fails_once", set(), {1}, "restored"),
            ("recovery_reload_fails", set(), {1, 2}, "prepared"),
            ("daemon_reload_fails_once", {1}, set(), "restored"),
            ("recovery_daemon_reload_fails", {1, 2}, set(), "prepared"),
            ("recovery_daemon_reload_after_front_failure", {2}, {1}, "prepared"),
        )
        for name, daemon_failures, front_failures, final_state in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                overlay = root / "etc/adguardhome-doh/mtproxyl-http.conf"
                map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
                system_site = root / "etc/nginx/sites-enabled/adguardhome-doh"
                system_site.parent.mkdir(parents=True)
                system_site.write_text("snapshot system site")
                backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                overlay.write_text("current front http")
                system_site.write_text("current system site")
                self.assertEqual("old map", map_path.read_text())
                events = []
                daemon_calls = 0
                front_calls = 0
                under_root = manager.under_root
                original_restore = manager._restore_backup
                original_reverse = manager._restore_transaction_entries
                original_marker = manager._transaction_marker

                def runner(command, **_kwargs):
                    nonlocal daemon_calls, front_calls
                    if command[:2] == ["systemctl", "show"]:
                        return subprocess.CompletedProcess(command, 0, b"123\n", b"")
                    if command == ["systemctl", "daemon-reload"]:
                        daemon_calls += 1
                        events.append(("daemon", overlay.read_text()))
                        if daemon_calls in daemon_failures:
                            raise subprocess.CalledProcessError(1, command)
                    elif command[0] == manager.MTPROXY_NGINX_BINARY:
                        events.append(("test", overlay.read_text()))
                    elif command == ["systemctl", "reload", "mtproxyl-pq-nginx"]:
                        front_calls += 1
                        events.append(("reload", overlay.read_text()))
                        if front_calls in front_failures:
                            raise subprocess.CalledProcessError(1, command)
                    return subprocess.CompletedProcess(command, 0, b"", b"")

                def restore(*args, **kwargs):
                    events.append(("restore", overlay.read_text()))
                    return original_restore(*args, **kwargs)

                def reverse(*args, **kwargs):
                    result = original_reverse(*args, **kwargs)
                    events.append(("reverse", overlay.read_text()))
                    return result

                def marker(path, state, entries):
                    events.append((state, overlay.read_text()))
                    return original_marker(path, state, entries)

                with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                     mock.patch.object(manager, "_validate_staged_adguard"), \
                     mock.patch.object(manager, "_restore_backup", side_effect=restore), \
                     mock.patch.object(manager, "_restore_transaction_entries", side_effect=reverse), \
                     mock.patch.object(manager, "_transaction_marker", side_effect=marker):
                    call = lambda: manager.restore_backup_runtime(
                        backup, Path("/"), "dns.example.com", runner=runner,
                        files_only=True, preserve_system_nginx=True, reload_shared_front=True,
                    )
                    if name == "success":
                        call()
                    elif final_state == "prepared":
                        with self.assertRaisesRegex(manager._FrontRecoveryError, "previous MTProxy front"):
                            call()
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            call()
                marker_paths = list((root / "var/backups/adguardhome-doh").glob(".restore-*/transaction.json"))
                self.assertEqual(1, len(marker_paths))
                self.assertEqual(final_state, json.loads(marker_paths[0].read_text())["state"])
                self.assertEqual("current system site", system_site.read_text())
                self.assertEqual("old map", map_path.read_text())
                self.assertEqual("front http" if name == "success" else "current front http", overlay.read_text())
                self.assertEqual(["prepared", "restore"], [event[0] for event in events[:2]])
                if name == "success":
                    self.assertEqual(["prepared", "restore", "daemon", "test", "reload", "committed"],
                                     [event[0] for event in events])
                    self.assertEqual(("reload", "front http"), events[-2])
                else:
                    reversal = events.index(("reverse", "current front http"))
                    self.assertEqual(("daemon", "current front http"), events[reversal + 1])
                    attempted = ["daemon"] if 1 in daemon_failures else ["daemon", "test", "reload"]
                    recovery = ["daemon"] if 2 in daemon_failures else ["daemon", "test", "reload"]
                    expected = ["prepared", "restore"] + attempted + ["reverse"] + recovery
                    if final_state == "restored":
                        expected.append("restored")
                    self.assertEqual(expected, [event[0] for event in events])
                    if final_state == "restored":
                        self.assertEqual("restored", events[-1][0])
                        self.assertEqual(("reload", "current front http"), events[-2])
                    else:
                        self.assertEqual("daemon" if daemon_failures else "reload", events[-1][0])
                        with self.assertRaisesRegex(RuntimeError, "unfinished transaction"):
                            manager._check_incomplete_transactions(root)

    def test_reload_shared_front_cli_requires_files_only_and_preserve_system_nginx(self):
        manager = load_manager()
        invalid = (
            ["--reload-shared-front"],
            ["--create-update-backup", "--reload-shared-front"],
            ["--finalize-update-backup", "/snapshot", "--reload-shared-front"],
            ["--restore-update-backup", "/snapshot", "--reload-shared-front"],
            ["--restore-update-backup", "/snapshot", "--files-only", "--reload-shared-front"],
            ["--restore-update-backup", "/snapshot", "--preserve-system-nginx", "--reload-shared-front"],
        )
        with mock.patch("sys.stderr", io.StringIO()), \
             mock.patch.object(manager, "restore_backup_runtime") as restore:
            for args in invalid:
                with self.subTest(args=args):
                    self.assertEqual(1, manager.main(args))
            restore.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
            with mock.patch.object(manager, "_reload_mtproxyl_map") as reload_front:
                self.assertEqual(0, manager.main([
                    "--restore-update-backup", str(backup), "--root", str(root), "--domain", "dns.example.com",
                    "--files-only", "--preserve-system-nginx", "--reload-shared-front",
                ]))
            reload_front.assert_called_once()

    def test_files_only_shared_reload_rejects_front_and_domain_mismatch_before_restore(self):
        manager = load_manager()
        for mismatch in ("current_front", "saved_front", "current_domain", "saved_domain", "argument_domain"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                state_file = root / "var/lib/adguardhome-doh/install.json"
                state = json.loads(state_file.read_text())
                if mismatch == "saved_front":
                    state.pop("front")
                    state_file.write_text(json.dumps(state))
                elif mismatch == "saved_domain":
                    state["domain"] = "other.example.com"
                    state_file.write_text(json.dumps(state))
                backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                if mismatch == "current_front":
                    state.pop("front")
                elif mismatch == "saved_front":
                    state["front"] = "mtproxyl"
                elif mismatch == "current_domain":
                    state["domain"] = "other.example.com"
                elif mismatch == "saved_domain":
                    state["domain"] = "dns.example.com"
                state_file.write_text(json.dumps(state))
                domain = "other.example.com" if mismatch == "argument_domain" else "dns.example.com"
                with mock.patch.object(manager, "_restore_backup") as restore:
                    with self.assertRaisesRegex(RuntimeError, "front|domain"):
                        manager.restore_backup_runtime(backup, root, domain, files_only=True,
                                                       preserve_system_nginx=True, reload_shared_front=True)
                restore.assert_not_called()
                self.assertEqual([], list((root / "var/backups/adguardhome-doh").glob(".restore-*")))

    def test_files_only_shared_reload_validates_active_front_before_restore(self):
        manager = load_manager()
        for condition in ("missing_binary", "missing_config", "custom_config", "pid_race"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                if condition == "missing_binary":
                    (root / "opt/mtproxyl-nginx/sbin/nginx").unlink()
                elif condition == "missing_config":
                    (root / "opt/mtproxyl-nginx/conf/nginx.conf").unlink()
                elif condition == "custom_config":
                    (root / "proc/123/cmdline").write_bytes(
                        b"/opt/mtproxyl-nginx/sbin/nginx\0-c\0/opt/mtproxyl/nginx-custom.conf\0"
                    )
                commands = []
                pids = iter((b"123\n", b"456\n" if condition == "pid_race" else b"123\n"))

                def runner(command, **_kwargs):
                    commands.append(command)
                    return subprocess.CompletedProcess(command, 0, next(pids), b"")

                under_root = manager.under_root
                with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                     mock.patch.object(manager, "_restore_backup") as restore:
                    with self.assertRaises(RuntimeError):
                        manager.restore_backup_runtime(backup, Path("/"), "dns.example.com", runner=runner,
                                                       files_only=True, preserve_system_nginx=True,
                                                       reload_shared_front=True)
                restore.assert_not_called()
                self.assertTrue(all(command[:2] == ["systemctl", "show"] for command in commands))
                self.assertEqual([], list((root / "var/backups/adguardhome-doh").glob(".restore-*")))

    def test_files_only_shared_reload_requires_all_safe_current_and_saved_front_files(self):
        manager = load_manager()
        required = ((manager.MT_PROXY_SNI_MAP, manager.PRIVATE_NGINX_CONFIG, manager.PRIVATE_NGINX_UNIT)
                    + manager.FRONT_OVERLAY_FILES + manager.FRONT_SITE_FILES)
        for relative in required:
            for missing in ("current", "snapshot"):
                with self.subTest(relative=relative, missing=missing), tempfile.TemporaryDirectory() as directory:
                    root = self.build_root(directory)
                    backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                    if missing == "current":
                        manager.under_root(root, relative).unlink()
                    else:
                        manifest_path = backup / "manifest.json"
                        manifest = json.loads(manifest_path.read_text())
                        entry = next(item for item in manifest["files"] if item["path"] == relative)
                        entry["present"] = False
                        entry.pop("sha256")
                        manifest_path.write_text(json.dumps(manifest))
                    with mock.patch.object(manager, "_restore_backup") as restore:
                        with self.assertRaisesRegex(RuntimeError, "отсутствует|не содержит"):
                            manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True,
                                                           preserve_system_nginx=True, reload_shared_front=True)
                    restore.assert_not_called()
                    self.assertEqual([], list((root / "var/backups/adguardhome-doh").glob(".restore-*")))

    def test_files_only_shared_reload_rejects_tampered_or_symlink_front_files(self):
        manager = load_manager()
        for condition in ("tampered_snapshot", "symlink_snapshot", "symlink_current"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                backup = manager.create_backup(root, operation="recovery", domain="dns.example.com")
                current = manager.under_root(root, manager.MT_PROXY_SNI_MAP)
                manifest_path = backup / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                entry = next(item for item in manifest["files"] if item["path"] == manager.MT_PROXY_SNI_MAP)
                snapshot = backup / entry["backup"]
                if condition == "tampered_snapshot":
                    snapshot.write_text("tampered")
                elif condition == "symlink_snapshot":
                    snapshot.unlink()
                    snapshot.symlink_to("elsewhere")
                    entry["sha256"] = manager._path_digest(snapshot)
                    manifest_path.write_text(json.dumps(manifest))
                else:
                    current.unlink()
                    current.symlink_to(root / "etc/adguardhome-doh/mtproxyl-http.conf")
                with mock.patch.object(manager, "_restore_backup") as restore:
                    with self.assertRaises(RuntimeError):
                        manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True,
                                                       preserve_system_nginx=True, reload_shared_front=True)
                restore.assert_not_called()
                self.assertEqual([], list((root / "var/backups/adguardhome-doh").glob(".restore-*")))

    def test_mtproxy_rollback_rejects_snapshot_without_shared_front_before_stop(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = ServiceChangeSeedingTests.build_root(self, directory)
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            state_file = root / "var/lib/adguardhome-doh/install.json"
            state = json.loads(state_file.read_text())
            state["front"] = "mtproxyl"
            state_file.write_text(json.dumps(state), encoding="utf-8")
            with mock.patch.object(manager, "_stop_adguard") as stop:
                with self.assertRaisesRegex(RuntimeError, "снимок несовместим с общим MTProxy front"):
                    manager.rollback_last(root)
            stop.assert_not_called()
            self.assertEqual("mtproxyl", json.loads(state_file.read_text())["front"])

    def test_missing_shared_site_blocks_snapshot_and_rollback_before_mutation(self):
        manager = load_manager()
        for relative in manager.FRONT_SITE_FILES:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                target = manager.under_root(root, relative)
                target.unlink()
                with self.assertRaisesRegex(RuntimeError, "файл общего front отсутствует"):
                    manager.create_backup(root, operation="update", domain="dns.example.com")
                target.write_text("current site")
                backup = manager.create_backup(root, operation="update", domain="dns.example.com")
                manager.finalize_update_backup(backup, root, "dns.example.com")
                target.unlink()
                with mock.patch.object(manager, "_stop_adguard") as stop:
                    with self.assertRaisesRegex(RuntimeError, "файл общего front отсутствует"):
                        manager.rollback_last(root, selected=backup)
                stop.assert_not_called()
                self.assertFalse(target.exists())

    def test_shared_snapshot_missing_private_sites_cannot_finalize_or_restore(self):
        manager = load_manager()
        for missing_style in ("unrecorded", "recorded_absent"):
            with self.subTest(missing_style=missing_style), tempfile.TemporaryDirectory() as directory:
                root = self.build_root(directory)
                backup = manager.create_backup(root, operation="update", domain="dns.example.com")
                manifest_path = backup / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                if missing_style == "unrecorded":
                    manifest["files"] = [item for item in manifest["files"]
                                         if item["path"] not in manager.FRONT_SITE_FILES]
                else:
                    for item in manifest["files"]:
                        if item["path"] == manager.PRIVATE_NGINX_STREAM_SITE:
                            item["present"] = False
                            item.pop("sha256")
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                self.assertTrue(manager._validated_backup_manifest(backup))
                target = root / "etc/adguardhome-doh/mtproxyl-stream-site.conf"
                target.write_text("current site")
                with self.assertRaisesRegex(RuntimeError, "снимок не содержит необходимые файлы"):
                    manager.finalize_update_backup(backup, root, "dns.example.com")
                with self.assertRaisesRegex(RuntimeError, "снимок не содержит необходимые файлы"):
                    manager.restore_backup_runtime(backup, root, "dns.example.com", files_only=True)
                self.assertEqual("current site", target.read_text())

    def test_changed_front_map_is_tested_and_reloaded_without_system_nginx(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            map_path.write_text("new map")
            under_root = manager.under_root
            calls = []

            def runner(command, **_kwargs):
                calls.append(command)
                if command[:2] == ["systemctl", "show"]:
                    return subprocess.CompletedProcess(command, 0, b"123\n", b"")
                if command[0] == "/opt/mtproxyl-nginx/sbin/nginx":
                    self.assertEqual("old map", map_path.read_text())
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services") as reload:
                self.assertTrue(manager.rollback_last(Path("/"), selected=backup, runner=runner))
            self.assertIn(["/usr/sbin/nginx", "-t", "-c", manager.PRIVATE_NGINX_CONFIG], calls)
            self.assertIn(["/opt/mtproxyl-nginx/sbin/nginx", "-t", "-c", "/opt/mtproxyl-nginx/conf/nginx.conf"], calls)
            self.assertIn(["systemctl", "reload", "mtproxyl-pq-nginx"], calls)
            self.assertNotIn(["nginx", "-t"], calls)
            self.assertNotIn(["systemctl", "restart", "mtproxyl-pq-nginx"], calls)
            reload.assert_called_once()
            self.assertEqual("old map", map_path.read_text())

    def test_unchanged_front_map_does_not_reload_mtproxy(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            under_root = manager.under_root
            calls = []

            def runner(command, **_kwargs):
                calls.append(command)
                if command[:2] == ["systemctl", "show"]:
                    return subprocess.CompletedProcess(command, 0, b"123\n", b"")
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services"):
                self.assertTrue(manager.rollback_last(Path("/"), selected=backup, runner=runner))
            self.assertNotIn(["systemctl", "reload", "mtproxyl-pq-nginx"], calls)

    def test_changed_front_map_requires_mtproxy_validator_before_stopping(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            (root / "etc/adguardhome-doh/mtproxyl-sni.map").write_text("new map")
            (root / "opt/mtproxyl-nginx/sbin/nginx").unlink()
            under_root = manager.under_root
            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_stop_adguard") as stop:
                with self.assertRaisesRegex(RuntimeError, "проверка MTProxy недоступна"):
                    manager.rollback_last(Path("/"), selected=backup, runner=mock.Mock())
            stop.assert_not_called()
            self.assertEqual("new map", (root / "etc/adguardhome-doh/mtproxyl-sni.map").read_text())

    def test_failed_shared_front_rollback_restores_previous_map_and_reloads_it(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            map_path.write_text("new map")
            under_root = manager.under_root
            tested_maps = []
            reloads = []

            def runner(command, **_kwargs):
                if command[:2] == ["systemctl", "show"]:
                    return subprocess.CompletedProcess(command, 0, b"123\n", b"")
                if command[0] == "/opt/mtproxyl-nginx/sbin/nginx":
                    tested_maps.append(map_path.read_text())
                if command == ["systemctl", "reload", "mtproxyl-pq-nginx"]:
                    reloads.append(map_path.read_text())
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services", side_effect=[RuntimeError("DoH smoke failed"), None]):
                with self.assertRaisesRegex(RuntimeError, "DoH smoke failed"):
                    manager.rollback_last(Path("/"), selected=backup, runner=runner)
            self.assertEqual(["old map", "new map"], tested_maps)
            self.assertEqual(["old map", "new map"], reloads)
            self.assertEqual("new map", map_path.read_text())

    def test_failed_mtproxy_recovery_leaves_transaction_pending(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_root(directory)
            map_path = root / "etc/adguardhome-doh/mtproxyl-sni.map"
            backup = manager.create_backup(root, operation="update", domain="dns.example.com")
            manager.finalize_update_backup(backup, root, "dns.example.com")
            map_path.write_text("new map")
            under_root = manager.under_root
            front_tests = []

            def runner(command, **_kwargs):
                if command[:2] == ["systemctl", "show"]:
                    return subprocess.CompletedProcess(command, 0, b"123\n", b"")
                if command[0] == "/opt/mtproxyl-nginx/sbin/nginx":
                    front_tests.append(map_path.read_text())
                    if len(front_tests) == 2:
                        raise subprocess.CalledProcessError(1, command)
                if command == ["systemctl", "reload", "mtproxyl-pq-nginx"]:
                    raise subprocess.CalledProcessError(1, command)
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(manager, "under_root", side_effect=lambda _r, path: under_root(root, path)), \
                 mock.patch.object(manager, "_load_healthcheck"), \
                 mock.patch.object(manager, "_validate_staged_adguard"), \
                 mock.patch.object(manager, "reload_runtime_services") as reload:
                with self.assertRaisesRegex(RuntimeError, "MTProxy recovery failed"):
                    manager.rollback_last(Path("/"), selected=backup, runner=runner)
            self.assertEqual(["old map", "new map"], front_tests)
            self.assertEqual("new map", map_path.read_text())
            reload.assert_not_called()
            markers = list((root / "var/backups/adguardhome-doh").glob(".restore-*/transaction.json"))
            self.assertEqual(1, len(markers))
            self.assertEqual("prepared", json.loads(markers[0].read_text())["state"])


if __name__ == "__main__":
    unittest.main()
