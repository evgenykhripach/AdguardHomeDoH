import os
import pty
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


def run_pty(*args, input_text="", timeout=5):
    master, slave = pty.openpty()
    env = dict(os.environ)
    env["PYTHONPYCACHEPREFIX"] = "/tmp/adguardhome-doh-pycache"
    env.pop("ADGUARDHOME_DOH_TTY_FD", None)
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
        self.assertIn("Сервисы:", output)

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
