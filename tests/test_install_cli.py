import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from deploy.lib.credentials import read_credentials, write_credentials


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "deploy" / "install.sh"


class InstallerCliTests(unittest.TestCase):
    def run_install(self, *args):
        env = dict(os.environ)
        env["PYTHONPYCACHEPREFIX"] = "/tmp/adguardhome-doh-pycache"
        return subprocess.run(
            [str(INSTALL), *args], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )

    def test_help_is_available(self):
        result = self.run_install("--help")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--domain HOST", result.stdout)
        self.assertIn("--rollback", result.stdout)

    def test_adguard_release_version_is_independent_from_project_version(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'ADGUARD_VERSION="${ADGUARDHOME_DOH_ADGUARD_VERSION:-0.107.78}"',
            source,
        )
        self.assertIn('PROJECT_VERSION="$(tr -d \'\\r\\n\' < "$VERSION_FILE")"', source)
        self.assertIn('"$PROJECT_VERSION" "$REPOSITORY"', source)

    def test_dry_run_validates_without_writing_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_install(
                "--domain", "dns.example.com",
                "--public-ip", "203.0.113.10",
                "--email", "admin@example.com",
                "--root", directory,
                "--dry-run",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("dry-run завершён", result.stdout)
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_missing_required_argument_fails(self):
        result = self.run_install("--domain", "dns.example.com")
        self.assertNotEqual(0, result.returncode)
        self.assertRegex(result.stderr, r"TTY|tty|--public-ip")

    def test_invalid_email_fails_before_installation(self):
        result = self.run_install(
            "--domain", "dns.example.com",
            "--public-ip", "203.0.113.10",
            "--email", "not-an-email",
            "--dry-run",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("invalid email", result.stderr)

    def test_ubuntu_24_04_or_newer_is_supported(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            os_release = Path(directory) / "os-release"
            for version, expected in (("24.04", 0), ("24.10", 0), ("25.04", 0), ("22.04", 1)):
                os_release.write_text(
                    f'ID=ubuntu\nVERSION_ID="{version}"\n', encoding="utf-8"
                )
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; adguardhome_doh_require_ubuntu "$2"',
                     "bash", str(common), str(os_release)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(expected, result.returncode, version)

    def test_adguard_checksum_parser_accepts_release_path(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        checksum = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            checksums = Path(directory) / "checksums.txt"
            checksums.write_text(
                f"{checksum}  ./AdGuardHome_linux_amd64.tar.gz\n", encoding="utf-8"
            )
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; adguardhome_doh_find_checksum "$2" "$3"',
                 "bash", str(common), str(checksums),
                 "AdGuardHome_linux_amd64.tar.gz"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(checksum, result.stdout.strip())

    def test_adguard_binary_is_found_after_archive_extraction(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "nested" / "AdGuardHome" / "AdGuardHome"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; adguardhome_doh_find_binary "$2"',
                 "bash", str(common), directory],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(str(binary), result.stdout.strip())

    def test_runtime_directories_use_mkdir_p(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT"', source
        )

    def test_health_templates_receive_release_root_before_target_root(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'adguardhome_doh_run_logged adguardhome_doh_install_health_templates "$PROJECT_ROOT" /',
            source,
        )

    def test_health_templates_install_outside_repository_working_directory(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "destination"
            unrelated_cwd = Path(directory) / "cwd"
            unrelated_cwd.mkdir()
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; cd "$2"; '
                    'adguardhome_doh_install_health_templates "$3" "$4"',
                    "bash", str(common), str(unrelated_cwd), str(ROOT),
                    str(destination),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(
                (destination / "usr/local/libexec/adguardhome-doh/healthcheck.py").is_file()
            )
            self.assertTrue(
                (destination / "etc/systemd/system/adguardhome-doh-health.service").is_file()
            )
            self.assertTrue(
                (destination / "etc/systemd/system/adguardhome-doh-health.timer").is_file()
            )

    def test_required_packages_include_nginx_stream_module(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; adguardhome_doh_required_packages',
             "bash", str(common)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("libnginx-mod-stream", result.stdout.splitlines())

    def test_service_validation_has_awk_fallback_before_python_is_installed(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            (bin_dir / "awk").symlink_to("/usr/bin/awk")
            env = dict(os.environ, PATH=str(bin_dir))
            result = subprocess.run(
                [
                    "/bin/bash", "-c",
                    'source "$1"; adguardhome_doh_validate_services "$2" "$3"',
                    "bash", str(common), str(ROOT), "chatgpt,context7",
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("chatgpt,context7\n", result.stdout)

    def test_nginx_stream_include_is_deduplicated_idempotently(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        include = "include /etc/nginx/stream.d/*.conf;"
        with tempfile.TemporaryDirectory() as directory:
            nginx_conf = Path(directory) / "nginx.conf"
            nginx_conf.write_text(
                f"user www-data;\n{include}\n{include}\nhttp {{\n}}\n",
                encoding="utf-8",
            )
            command = [
                "bash", "-c",
                'source "$1"; adguardhome_doh_ensure_nginx_stream_include "$2"',
                "bash", str(common), str(nginx_conf),
            ]
            first = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            first_content = nginx_conf.read_text(encoding="utf-8")
            self.assertEqual(1, first_content.splitlines().count(include))
            second = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertEqual(first_content, nginx_conf.read_text(encoding="utf-8"))

    def test_doh_token_is_created_once_and_reused(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "doh-token"
            command = [
                "bash", "-c",
                'source "$1"; adguardhome_doh_load_or_create_doh_token "$2"',
                "bash", str(common), str(token_file),
            ]
            first = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            second = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertRegex(first.stdout.strip(), r"^[a-f0-9]{48}$")
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(0o600, token_file.stat().st_mode & 0o777)

    def test_certbot_contact_args_use_no_email_for_reserved_example_domain(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        command = [
            "bash", "-c",
            'source "$1"; adguardhome_doh_certbot_contact_args "$2"',
            "bash", str(common), "admin@example.com",
        ]
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("--register-unsafely-without-email\n", result.stdout)
        self.assertIn("example.com", result.stderr)

    def test_certbot_contact_args_keep_real_email(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        command = [
            "bash", "-c",
            'source "$1"; adguardhome_doh_certbot_contact_args "$2"',
            "bash", str(common), "admin@adguardhome.example",
        ]
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("--email\nadmin@adguardhome.example\n", result.stdout)
        self.assertEqual("", result.stderr)

    def test_first_install_prints_doh_and_mobileconfig_urls(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn("printf 'DoH URL: https://%s/doh/%s\\n'", source)
        self.assertIn("printf 'mobileconfig URL: https://%s/%s.mobileconfig\\n'", source)

    def test_real_install_initializes_log_before_logged_preflight(self):
        source = INSTALL.read_text(encoding="utf-8")
        init = source.index("adguardhome_doh_init_log /")
        preflight = source.index("adguardhome_doh_preflight /")
        self.assertLess(init, preflight)
        self.assertIn("adguardhome_doh_run_logged adguardhome_doh_preflight / \"$DOMAIN\" \"$PUBLIC_IP\" \"$UPDATE\"", source)

    def test_update_preflight_allows_only_existing_managed_nginx(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site = root / "etc/nginx/sites-enabled"
            stream = root / "etc/nginx/stream.d"
            site.mkdir(parents=True)
            stream.mkdir(parents=True)
            (site / "adguardhome-doh").write_text(
                "server { listen 80; server_name dns.example.com; }\n", encoding="utf-8"
            )
            (stream / "adguardhome-doh.conf").write_text(
                "server { listen 443; }\n", encoding="utf-8"
            )
            listeners = (
                'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* '
                'users:(("nginx",pid=10,fd=7))\n'
                'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* '
                'users:(("nginx",pid=10,fd=8))\n'
            )
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_managed_nginx_update_allowed "$2" "$3" "$4"',
                    "bash", str(common), str(root), "dns.example.com", listeners,
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            foreign = listeners.replace('(("nginx"', '(("xray"')
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_managed_nginx_update_allowed "$2" "$3" "$4"',
                    "bash", str(common), str(root), "dns.example.com", foreign,
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, result.returncode)

    def test_logged_command_output_is_redacted_and_written_to_private_log(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            command = [
                "bash", "-c",
                'source "$1"; '
                'ADGUARDHOME_DOH_ADMIN_PASSWORD=secret-password; '
                'ADGUARDHOME_DOH_DOH_TOKEN=secret-token; '
                'ADGUARDHOME_DOH_ADMIN_HASH=secret-hash; '
                'adguardhome_doh_init_log "$2"; '
                "adguardhome_doh_run_logged sh -c 'printf \"normal output\\\\n\"; "
                "printf \"secret-password secret-token secret-hash\\\\n\" >&2'; "
                'printf "%s\\n" "$ADGUARDHOME_DOH_LOG_PATH"',
                "bash", str(common), directory,
            ]
            result = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            log_path = Path(result.stdout.strip())
            self.assertEqual(0o600, log_path.stat().st_mode & 0o777)
            log = log_path.read_text(encoding="utf-8")
            self.assertIn("normal output", log)
            self.assertNotIn("secret-password", log)
            self.assertNotIn("secret-token", log)
            self.assertNotIn("secret-hash", log)

    def test_credentials_are_mode_600_and_preserve_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin-credentials"
            write_credentials(path, "https://dns.example.com/", "a" * 48)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            values = read_credentials(path)
            self.assertEqual("admin", values["login"])
            self.assertEqual("a" * 48, values["password"])


if __name__ == "__main__":
    unittest.main()
