import importlib.util
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
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
            "version": "1.0.31",
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
                item for item in manifest
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
            version.write_text("1.0.31\n", encoding="utf-8")
            manager.create_backup(
                root,
                root / "var/backups/adguardhome-doh/20260823T000000000000Z",
            )

            def runner(command, **_kwargs):
                active = command[-1] in {
                    "adguardhome-doh.service",
                    "nginx.service",
                    "adguardhome-doh-health.timer",
                }
                return mock.Mock(returncode=0 if active else 3)

            status = manager.collect_menu_status(root, catalog, runner=runner)

        self.assertEqual("1.0.31", status["version"])
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
        with mock.patch.object(manager, "collect_system_check", return_value=report):
            manager.print_system_check(Path("/"), output)
        text = output.getvalue()
        self.assertIn("ДИАГНОСТИКА СИСТЕМЫ", text)
        self.assertIn("AdGuard Home", text)
        self.assertIn("nginx", text)
        self.assertIn("42", text)
        self.assertNotIn('{"', text)

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
                        "curl", "--fail", "--silent", "--show-error",
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

    def test_backup_restore_reloads_and_checks_previous_runtime(self):
        manager = load_manager()
        runner = mock.Mock()
        backup = Path("/var/backups/adguardhome-doh/test")
        with mock.patch.object(manager, "_restore_backup") as restore, mock.patch.object(
            manager, "reload_runtime_services"
        ) as reload_services:
            manager.restore_backup_runtime(
                backup, Path("/"), "dns.example.com", runner=runner
            )
        restore.assert_called_once_with(backup, Path("/"))
        self.assertEqual(
            [
                mock.call(["systemctl", "daemon-reload"], check=False),
                mock.call(
                    [
                        "/opt/AdGuardHome/AdGuardHome", "--check-config",
                        "-c", "/opt/AdGuardHome/AdGuardHome.yaml",
                        "-w", "/var/lib/AdGuardHome",
                    ],
                    check=True, stdout=mock.ANY, stderr=mock.ANY,
                ),
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
                ("partial", manifest[:1]),
                ("duplicate", manifest + [manifest[0]]),
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
            manager.create_backup(root, backup_root / "20240101T00000000000000Z")
            target.write_text("after\n", encoding="utf-8")
            newer = backup_root / "20240201T00000000000000Z"
            newer.mkdir(parents=True)
            (newer / "transaction.json").write_text("{}\n", encoding="utf-8")

            self.assertTrue(manager.rollback_last(root, runner=mock.Mock()))
            self.assertEqual("before\n", target.read_text(encoding="utf-8"))

    def test_rollback_accepts_nested_full_backup_manifest(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "opt/AdGuardHome/AdGuardHome.yaml"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            nested = root / "var/backups/adguardhome-doh/20240301T00000000000000Z/full"
            manager.create_backup(root, nested)
            target.write_text("after\n", encoding="utf-8")

            self.assertTrue(manager.rollback_last(root, runner=mock.Mock()))
            self.assertEqual("before\n", target.read_text(encoding="utf-8"))

    def test_rollback_returns_false_when_only_incomplete_backups_exist(self):
        manager = load_manager()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "var/backups/adguardhome-doh/20240401T00000000000000Z"
            backup.mkdir(parents=True)
            (backup / "transaction.json").write_text("{}\n", encoding="utf-8")

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
        with mock.patch.object(manager, "_load_catalog", return_value=catalog), \
             mock.patch.object(manager, "collect_menu_status", return_value=self._menu_status()), \
             mock.patch.object(manager, "collect_system_check", return_value=report), \
             mock.patch.object(manager, "rollback_last", return_value=True) as rollback:
            result = manager.run_menu(
                Path("/"), io.StringIO("3\n5\ny\n0\n"), output
            )
        self.assertEqual(0, result)
        rollback.assert_called_once_with(Path("/"))
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


if __name__ == "__main__":
    unittest.main()
