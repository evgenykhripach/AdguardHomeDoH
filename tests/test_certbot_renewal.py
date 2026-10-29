import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy" / "lib" / "certbot_renewal.py"

STANDALONE_PROFILE = """# renew_before_expiry = 30 days
version = 2.9.0
archive_dir = /etc/letsencrypt/archive/dns.example.com
cert = /etc/letsencrypt/live/dns.example.com/cert.pem
privkey = /etc/letsencrypt/live/dns.example.com/privkey.pem
chain = /etc/letsencrypt/live/dns.example.com/chain.pem
fullchain = /etc/letsencrypt/live/dns.example.com/fullchain.pem

[renewalparams]
account = 0123456789abcdef
authenticator = standalone
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
pre_hook = systemctl stop nginx
post_hook = systemctl start nginx
"""


def load_module():
    spec = importlib.util.spec_from_file_location("adguardhome_doh_certbot_renewal", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CertbotRenewalTests(unittest.TestCase):
    def test_standalone_profile_is_rewritten_to_webroot(self):
        """Renewal must stop taking the whole endpoint down for the exchange."""

        module = load_module()
        self.assertTrue(module.needs_migration(STANDALONE_PROFILE))

        migrated = module.migrate(
            STANDALONE_PROFILE, "dns.example.com", "/var/www/adguardhome-doh"
        )

        self.assertIn("authenticator = webroot", migrated)
        self.assertNotIn("standalone", migrated)
        self.assertNotIn("pre_hook", migrated)
        self.assertNotIn("post_hook", migrated)
        self.assertIn("webroot_path = /var/www/adguardhome-doh,", migrated)
        self.assertIn("[[webroot_map]]", migrated)
        self.assertIn("dns.example.com = /var/www/adguardhome-doh", migrated)
        # The lineage, its account and its history must survive untouched.
        self.assertIn("account = 0123456789abcdef", migrated)
        self.assertIn("archive_dir = /etc/letsencrypt/archive/dns.example.com", migrated)
        self.assertIn("key_type = ecdsa", migrated)

    def test_migration_is_idempotent_and_skips_healthy_profiles(self):
        module = load_module()
        once = module.migrate(STANDALONE_PROFILE, "dns.example.com", "/var/www/adguardhome-doh")

        self.assertFalse(module.needs_migration(once))
        self.assertEqual(
            once, module.migrate(once, "dns.example.com", "/var/www/adguardhome-doh")
        )
        self.assertEqual(1, once.count("[[webroot_map]]"))
        self.assertEqual(1, once.count("authenticator = webroot"))

    def test_migrate_file_keeps_a_backup_and_reports_no_op(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "dns.example.com.conf"
            profile.write_text(STANDALONE_PROFILE, encoding="utf-8")
            profile.chmod(0o640)
            unrelated_temp = profile.with_name(profile.name + ".tmp")
            unrelated_temp.write_text("unrelated user data", encoding="utf-8")

            self.assertTrue(
                module.migrate_file(profile, "dns.example.com", "/var/www/adguardhome-doh")
            )
            backup = profile.with_suffix(profile.suffix + ".pre-webroot")
            self.assertEqual(STANDALONE_PROFILE, backup.read_text(encoding="utf-8"))
            self.assertIn("authenticator = webroot", profile.read_text(encoding="utf-8"))
            self.assertEqual(0o640, profile.stat().st_mode & 0o777)
            self.assertEqual("unrelated user data", unrelated_temp.read_text(encoding="utf-8"))

            # A second pass must leave both the profile and the backup alone.
            self.assertFalse(
                module.migrate_file(profile, "dns.example.com", "/var/www/adguardhome-doh")
            )
            self.assertEqual(STANDALONE_PROFILE, backup.read_text(encoding="utf-8"))

    def test_missing_profile_is_not_an_error(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(
                module.migrate_file(
                    Path(directory) / "absent.conf", "dns.example.com", "/var/www"
                )
            )

    def test_unrelated_hooks_survive_and_reload_hook_is_lineage_specific(self):
        module = load_module()
        profile = STANDALONE_PROFILE.replace(
            "pre_hook = systemctl stop nginx", "pre_hook = /opt/local/pre-renew"
        ).replace(
            "post_hook = systemctl start nginx", "post_hook = /opt/local/post-renew"
        ) + "deploy_hook = /opt/local/deploy && /opt/local/audit\n"
        migrated = module.migrate(profile, "dns.example.com", "/var/www/adguardhome-doh")
        self.assertIn("pre_hook = /opt/local/pre-renew", migrated)
        self.assertIn("post_hook = /opt/local/post-renew", migrated)
        self.assertIn("deploy_hook = /opt/local/deploy && /opt/local/audit", migrated)
        self.assertEqual(1, migrated.count("deploy_hook ="))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            fake = root / "systemctl"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMANDS"\n', encoding="utf-8")
            fake.chmod(0o755)
            hook = module.ensure_reload_hook(root / "hooks", "dns.example.com")
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", COMMANDS=str(commands))
            env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/other.example.com"
            subprocess.run([str(hook)], env=env, check=True)
            self.assertFalse(commands.exists())
            env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/dns.example.com"
            subprocess.run([str(hook)], env=env, check=True)
            self.assertEqual("reload nginx\n", commands.read_text(encoding="utf-8"))
            module.ensure_reload_hook(root / "hooks", "new.example.com")
            subprocess.run([str(hook)], env=env, check=True)
            env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/new.example.com"
            subprocess.run([str(hook)], env=env, check=True)
            self.assertEqual("reload nginx\n" * 3, commands.read_text(encoding="utf-8"))

    def test_combined_user_hook_is_not_removed(self):
        module = load_module()
        profile = STANDALONE_PROFILE.replace(
            "pre_hook = systemctl stop nginx", "pre_hook = systemctl stop nginx && /opt/local/audit"
        )
        migrated = module.migrate(profile, "dns.example.com", "/var/www")
        self.assertIn("pre_hook = systemctl stop nginx && /opt/local/audit", migrated)
        self.assertNotIn("post_hook = systemctl start nginx", migrated)
        self.assertIn("deploy_hook = systemctl reload nginx", migrated)

    def test_user_owned_directory_hook_is_never_replaced(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "adguardhome-doh-reload"
            hook.write_text("#!/bin/sh\necho user-owned\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                module.ensure_reload_hook(Path(directory), "dns.example.com")
            self.assertIn("user-owned", hook.read_text(encoding="utf-8"))
            hook.unlink()
            module.ensure_reload_hook(Path(directory), "dns.example.com")
            with hook.open("a", encoding="utf-8") as stream:
                stream.write("echo custom-command\n")
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                module.ensure_reload_hook(Path(directory), "dns.example.com")
            self.assertIn("custom-command", hook.read_text(encoding="utf-8"))

    def test_shared_lineage_keeps_existing_profiles_and_other_hooks(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "dns.example.com.conf"
            profile.write_text(STANDALONE_PROFILE, encoding="utf-8")
            hooks = root / "hooks"
            hook = module.ensure_reload_hook(hooks, "other.example.com")
            mtproxy_hook = hooks / "mtproxyl-selfmask.sh"
            mtproxy_hook.write_text("#!/bin/sh\n# existing MTProxyL hook\n", encoding="utf-8")
            original_hook = mtproxy_hook.read_bytes()
            subprocess.run([
                "python3", str(MODULE_PATH), "--path", str(profile), "--domain", "dns.example.com",
                "--webroot", "/var/www/mtproxyl-selfmask", "--hook-dir", str(hooks),
                "--front", "mtproxyl",
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(STANDALONE_PROFILE, profile.read_text(encoding="utf-8"))
            self.assertEqual(original_hook, mtproxy_hook.read_bytes())
            commands = root / "commands"
            fake = root / "systemctl"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMANDS"\n', encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", COMMANDS=str(commands))
            env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/dns.example.com"
            subprocess.run([str(hook)], env=env, check=True)
            env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/other.example.com"
            subprocess.run([str(hook)], env=env, check=True)
            self.assertEqual("reload adguardhome-doh-nginx\nreload nginx\n", commands.read_text())

    def test_shared_lineage_can_change_back_without_affecting_others(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = module.ensure_reload_hook(root, "dns.example.com")
            module.ensure_reload_hook(root, "other.example.com", front="mtproxyl")
            module.ensure_reload_hook(root, "dns.example.com", front="mtproxyl")
            shared = hook.read_text(encoding="utf-8")
            module.ensure_reload_hook(root, "dns.example.com", front="mtproxyl")
            self.assertEqual(shared, hook.read_text(encoding="utf-8"))
            module.ensure_reload_hook(root, "dns.example.com", front="standard")
            content = hook.read_text(encoding="utf-8")
            self.assertIn("/etc/letsencrypt/live/dns.example.com ]; then\n    systemctl reload nginx", content)
            self.assertIn("/etc/letsencrypt/live/other.example.com ]; then\n    systemctl reload adguardhome-doh-nginx", content)

    def test_refuses_unsafe_hook_file_or_directory(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = module.ensure_reload_hook(root, "dns.example.com")
            original = hook.read_bytes()
            hook.chmod(0o775)
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                module.ensure_reload_hook(root, "dns.example.com", front="mtproxyl")
            self.assertEqual(original, hook.read_bytes())
            hook.chmod(0o755)
            second = root / "hardlink"
            os.link(hook, second)
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                module.ensure_reload_hook(root, "dns.example.com", front="mtproxyl")
            second.unlink()
            root.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "unsafe Certbot hook directory"):
                module.ensure_reload_hook(root, "dns.example.com", front="mtproxyl")
            self.assertEqual(original, hook.read_bytes())


if __name__ == "__main__":
    unittest.main()
