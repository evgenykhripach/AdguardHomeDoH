import os
import pty
import re
import select
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "deploy" / "install.sh"
COMMON = ROOT / "deploy" / "lib" / "common.sh"
UI = ROOT / "deploy" / "lib" / "ui.sh"


def run_pty(*args, input_text="", timeout=5, env_overrides=None, env_unset=()):
    master, slave = pty.openpty()
    env = dict(os.environ)
    env["PYTHONPYCACHEPREFIX"] = "/tmp/adguardhome-doh-pycache"
    env.pop("ADGUARDHOME_DOH_TTY_FD", None)
    for key in env_unset:
        env.pop(key, None)
    if env_overrides:
        env.update(env_overrides)
    process = subprocess.Popen(
        [str(INSTALL), *args], cwd=ROOT, env=env,
        stdin=slave, stdout=slave, stderr=slave,
    )
    os.close(slave)
    os.set_blocking(master, False)
    if input_text:
        os.write(master, input_text.encode())
    chunks = []
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                data = os.read(master, 65536)
                if not data:
                    break
                chunks.append(data)
            except OSError:
                break
    while True:
        ready, _, _ = select.select([master], [], [], 0)
        if not ready:
            break
        try:
            data = os.read(master, 65536)
            if not data:
                break
            chunks.append(data)
        except OSError:
            break
    if process.poll() is None:
        process.kill()
        process.wait()
    os.close(master)
    return process.returncode, b"".join(chunks).decode("utf-8", "replace")


class InteractiveInstallerTests(unittest.TestCase):
    def test_non_tty_missing_flags_fail_without_hanging(self):
        result = subprocess.run(
            [str(INSTALL), "--dry-run", "--root", tempfile.gettempdir()],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=3,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertRegex(result.stderr, r"(TTY|tty|--domain)")

    def test_non_tty_real_install_requires_yes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    str(INSTALL), "--domain", "dns.example.com",
                    "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                    "--services", "chatgpt,claude", "--root", directory,
                ],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertRegex(result.stderr, r"(?i)(non-interactive|non-tty|--yes)")

    def test_dry_run_emits_neutral_progress_milestones_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    str(INSTALL), "--domain", "dns.example.com",
                    "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                    "--services", "chatgpt,claude", "--dry-run", "--root", directory,
                ],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        for milestone in (0, 5, 20, 35, 50, 65, 75, 85, 95, 100):
            self.assertIn(f"[{milestone:02d}%]", result.stdout)
        self.assertIn("https://dns.example.com/", result.stdout)
        self.assertIn("sudo adguardhome-doh", result.stdout)
        self.assertNotIn("legacy", result.stdout.lower())

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_interactive_defaults_and_confirmation_are_read_in_order(self):
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(),
            input_text="dns.example.com\n203.0.113.10\nadmin@example.com\nd\ny\n",
        )
        self.assertEqual(0, code, output)
        self.assertIn("chatgpt", output.lower())
        self.assertIn("install", output.lower())
        self.assertEqual(1, output.count("Домен (например, dns.example.com):"), output)
        normalized_output = output.replace("\r\n", "\n")
        self.assertIn("[00%] проверка параметров\nДомен (например, dns.example.com):", normalized_output)
        self.assertIn("Категории:", output)
        self.assertNotIn("78) [", output)

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_category_selector_opens_category_and_returns_to_categories(self):
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(),
            input_text="dns.example.com\n203.0.113.10\nadmin@example.com\n1\n1 2\nb\ny\ny\n",
        )
        self.assertEqual(0, code, output)
        self.assertIn("ИИ:", output)
        self.assertIn("ChatGPT", output)
        self.assertIn("Claude", output)
        self.assertIn("Выбрано сервисов: 2", output)
        self.assertIn("Активных уникальных доменов:", output)

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_selector_search_matches_name_and_id(self):
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(),
            input_text="dns.example.com\n203.0.113.10\nadmin@example.com\n/copilot\n1 2\nb\ny\ny\n",
        )
        self.assertEqual(0, code, output)
        self.assertIn("Результаты поиска", output)
        self.assertIn("Microsoft Copilot", output)
        self.assertIn("GitHub Copilot", output)
        self.assertIn("Выбрано сервисов: 2", output)

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_category_all_none_and_experimental_are_explicit(self):
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(),
            input_text="dns.example.com\n203.0.113.10\nadmin@example.com\nx\n1\nb\n1\na\nn\nb\nc\n",
        )
        self.assertEqual(2, code, output)
        self.assertIn("Экспериментальные:", output)
        self.assertIn("[A] Все  [N] Снять все  [B] Назад  [C] Отмена", output)
        self.assertIn("выбор отменён", output)

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_selector_uses_ansi_on_tty_and_no_color_override_is_plain(self):
        input_text = "dns.example.com\n203.0.113.10\nadmin@example.com\nc\n"
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(), input_text=input_text,
            env_overrides={"TERM": "xterm-256color", "COLUMNS": "80"},
            env_unset=("NO_COLOR",),
        )
        self.assertEqual(2, code, output)
        self.assertIn("\x1b[36mСЕРВИСЫ И ДОМЕНЫ\x1b[0m", output)
        self.assertIn("\x1b[36m[D] Стандартные", output)
        self.assertIn("\x1b[31m[C] Отмена\x1b[0m", output)

        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(), input_text=input_text,
            env_overrides={"TERM": "xterm-256color", "COLUMNS": "80", "NO_COLOR": ""},
        )
        self.assertEqual(2, code, output)
        self.assertNotIn("\x1b[", output)
        self.assertIn("СЕРВИСЫ И ДОМЕНЫ", output)

    def test_selector_category_layout_follows_terminal_width(self):
        script = (
            f'source "{UI}"; '
            f'adguardhome_doh_load_service_catalog "{ROOT / "config"}"; '
            'ADGUARDHOME_DOH_SELECTOR_SELECTED=; '
            'adguardhome_doh_selector_category_init; '
            'adguardhome_doh_selector_print_categories'
        )

        def render(width):
            env = dict(os.environ)
            env.update({"ADGUARDHOME_DOH_TTY_FD": "0", "NO_COLOR": "", "COLUMNS": str(width)})
            result = subprocess.run(
                ["bash", "-c", script], cwd=ROOT, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True,
            )
            return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)

        wide = render(80)
        category_lines = [line for line in wide.splitlines() if re.match(r"^\[[0-9]+\] ", line)]
        self.assertTrue(any("[1] ИИ" in line and "[13] Работа" in line for line in category_lines), wide)
        self.assertTrue(all(len(line) <= 80 for line in category_lines), wide)

        narrow = render(40)
        category_lines = [line for line in narrow.splitlines() if re.match(r"^\[[0-9]+\] ", line)]
        self.assertTrue(all(len(line) <= 40 for line in narrow.splitlines()), narrow)
        self.assertFalse(any("[1] ИИ" in line and "[2] Разработка" in line for line in category_lines), narrow)
        self.assertIn("[D] Стандартные  [X] Экспериментальные", narrow)
        self.assertIn("[Y] Итог  [C] Отмена", narrow)
        self.assertNotIn("…", narrow)

    def test_selector_wraps_long_text_without_losing_commands(self):
        value = "Первый очень-длинный-сервис Второй"
        script = (
            f'source "{UI}"; '
            f'adguardhome_doh_selector_emit_wrapped "Сервисы: " "{value}" 24'
        )
        env = dict(os.environ)
        env.update({"ADGUARDHOME_DOH_TTY_FD": "0", "NO_COLOR": ""})
        result = subprocess.run(
            ["bash", "-c", script], cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True,
        )
        lines = result.stdout.splitlines()
        self.assertTrue(all(len(line) <= 24 for line in lines), result.stdout)
        self.assertNotIn("…", result.stdout)
        self.assertEqual(
            "Сервисы:" + value.replace(" ", ""),
            "".join(line.strip().replace(" ", "") for line in lines),
        )

    @unittest.skipUnless(os.environ.get("RUN_PTY_TESTS"), "PTY unavailable in restricted test runner")
    def test_selector_markers_and_command_labels_are_explicit(self):
        code, output = run_pty(
            "--dry-run", "--root", tempfile.gettempdir(),
            input_text="dns.example.com\n203.0.113.10\nadmin@example.com\n1\n1\nb\ny\ny\n",
            env_overrides={"TERM": "dumb", "COLUMNS": "60"},
        )
        self.assertEqual(0, code, output)
        self.assertIn("[ ] ChatGPT", output)
        self.assertIn("[✓] ChatGPT", output)
        self.assertIn("Команды: номер — открыть, /текст — поиск", output)
        self.assertIn("[D] Стандартные  [X] Экспериментальные  [Y] Итог  [C] Отмена", output)
        self.assertIn("Команды: номера — переключить", output)
        self.assertIn("[A] Все  [N] Снять все  [B] Назад  [C] Отмена", output)

    def test_interactive_input_trims_terminal_carriage_return_and_spaces(self):
        target_domain = "dns2." + "pre" + "ssroll" + ".ru"
        script = (
            f'source "{COMMON}"; source "{UI}"; '
            'ADGUARDHOME_DOH_TTY_FD=0; '
            'adguardhome_doh_prompt_value normalized "" adguardhome_doh_validate_hostname; '
            'printf "<%s>\\n" "$normalized"'
        )
        result = subprocess.run(
            ["bash", "-c", script],
            input=f"\x1b[200~\u200b {target_domain}\u200b\x1b[201~\r\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(f"<{target_domain}>\n", result.stdout)

    def test_selector_tty_detection_survives_command_substitution(self):
        ui_source = UI.read_text(encoding="utf-8")
        self.assertIn("[[ -r /dev/tty ]] || return 1", ui_source)
        self.assertIn("[[ -w /dev/tty ]] && return 0", ui_source)
        self.assertNotIn("( -t 0 || -t 1 )", ui_source)

    def test_selector_no_long_global_service_list_or_legacy_shortcuts(self):
        ui_source = UI.read_text(encoding="utf-8")
        self.assertIn("Категории:", ui_source)
        self.assertIn("Результаты поиска", ui_source)
        self.assertNotIn("A/S — все стандартные", ui_source)

    def test_log_path_and_secrets_are_not_emitted_during_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    str(INSTALL), "--domain", "dns.example.com",
                    "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                    "--dry-run", "--root", directory,
                ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/var/log/adguardhome-doh/install-", result.stdout)
        self.assertNotIn("password=", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
