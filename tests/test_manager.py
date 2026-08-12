import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.render_config import Catalog


ROOT = Path(__file__).resolve().parents[1]
MANAGER_PATH = ROOT / "deploy" / "manage.py"


def load_manager():
    spec = importlib.util.spec_from_file_location("neutral_manager", MANAGER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagerTests(unittest.TestCase):
    def test_yes_answer_accepts_lowercase_and_terminal_invisibles(self):
        manager = load_manager()
        self.assertTrue(manager._is_yes_answer("y\r\n"))
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
        self.assertIn("Категории:", output.getvalue())
        self.assertIn("Результаты поиска:", output.getvalue())
        self.assertNotIn("Новый выбор (ID", output.getvalue())

    def test_menu_exits_after_successful_update_to_reload_new_code(self):
        manager = load_manager()
        output = io.StringIO()
        with mock.patch.object(manager, "_load_catalog", return_value=Catalog.load(ROOT / "config")), \
             mock.patch.object(manager, "update_status", return_value={
                 "available": True, "current": "1.0.12", "latest": "1.0.13",
             }), \
             mock.patch.object(manager, "install_update", return_value=True):
            result = manager.run_menu(
                root=Path("/"), input_stream=io.StringIO("4\ny\n"), output=output
            )
        self.assertEqual(0, result)
        self.assertIn("Запустите менеджер заново", output.getvalue())

    def test_menu_is_root_tty_only_and_has_required_entries(self):
        manager = load_manager()
        self.assertEqual(
            [
                "Доступ к данным",
                "Изменить сервисы",
                "Проверка системы",
                "Проверить и установить обновление",
                "Откатить последнее обновление",
                "Выход",
            ],
            list(manager.MENU_ENTRIES),
        )
        with mock.patch.object(manager.os, "geteuid", return_value=1000), mock.patch.object(
            manager.sys.stdin, "isatty", return_value=True
        ), mock.patch.object(manager.sys.stdout, "isatty", return_value=True):
            self.assertNotEqual(0, manager.main([]))

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
