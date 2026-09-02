import importlib.util
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

            self.assertTrue(
                module.migrate_file(profile, "dns.example.com", "/var/www/adguardhome-doh")
            )
            backup = profile.with_suffix(profile.suffix + ".pre-webroot")
            self.assertEqual(STANDALONE_PROFILE, backup.read_text(encoding="utf-8"))
            self.assertIn("authenticator = webroot", profile.read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()
