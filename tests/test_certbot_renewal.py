import importlib.util
import hashlib
import os
import selectors
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


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


class _StatOverride:
    def __init__(self, original, **overrides):
        self.original = original
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides[name] if name in self.overrides else getattr(self.original, name)


class CreateOnlyLineageHookTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        # macOS tests run without root. Substitute only the test user's owner
        # metadata; root-run Linux tests exercise the real owner checks.
        temp_parent = "/private/tmp" if Path("/private/tmp").is_dir() else None
        self.temporary = tempfile.TemporaryDirectory(dir=temp_parent)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.staging = self.base / "renewal-hooks"
        self.root = self.staging / "deploy"
        self.root.mkdir(parents=True)
        self.foreign = set()
        real_stat = os.stat
        real_fstat = os.fstat
        uid = os.geteuid()

        def adjusted(info):
            if (info.st_dev, info.st_ino) in self.foreign:
                return _StatOverride(info, st_uid=12345)
            if info.st_uid == uid and uid != 0:
                return _StatOverride(info, st_uid=0)
            return info

        stat_patch = mock.patch.object(self.module.os, "stat",
                                      side_effect=lambda *a, **kw: adjusted(real_stat(*a, **kw)))
        fstat_patch = mock.patch.object(self.module.os, "fstat",
                                       side_effect=lambda fd: adjusted(real_fstat(fd)))
        stat_patch.start()
        self.addCleanup(stat_patch.stop)
        fstat_patch.start()
        self.addCleanup(fstat_patch.stop)

    def create(self, domain="dns.example.com"):
        return self.module.ensure_lineage_reload_hook(
            self.root, domain, self.module.ReloadUnit.SHARED_NGINX
        )

    def target(self, domain="dns.example.com"):
        name = "adguardhome-doh-reload-" + hashlib.sha256(domain.encode("ascii")).hexdigest()
        return self.root / name

    def assert_no_temporary_hooks(self):
        self.assertEqual([], list(self.root.glob(".adguardhome-doh-reload-*")))
        self.assertEqual([], list(self.staging.glob(".adguardhome-doh-reload-*")))

    def test_creates_separate_run_parts_safe_hook_for_matching_lineage_only(self):
        legacy = self.root / "adguardhome-doh-reload"
        legacy.write_text("#!/bin/sh\necho third-party-hook\n", encoding="utf-8")
        original = (legacy.read_bytes(), legacy.stat().st_ino, legacy.stat().st_mode)
        hook = self.create()
        self.assertEqual(self.target(), hook)
        self.assertRegex(hook.name, r"^[A-Za-z0-9_-]+$")
        self.assertEqual(0o755, stat.S_IMODE(hook.stat().st_mode))
        self.assertEqual(original, (legacy.read_bytes(), legacy.stat().st_ino, legacy.stat().st_mode))
        other_hook = self.create("other.example.com")
        self.assertNotEqual(hook.name, other_hook.name)

        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "systemctl"
        commands = self.base / "commands"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMANDS"\n', encoding="utf-8")
        fake.chmod(0o755)
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", COMMANDS=str(commands))
        env.pop("RENEWED_LINEAGE", None)
        subprocess.run([str(hook)], env=env, check=True)
        env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/other.example.com"
        subprocess.run([str(hook)], env=env, check=True)
        self.assertFalse(commands.exists())
        env["RENEWED_LINEAGE"] = "/etc/letsencrypt/live/dns.example.com"
        subprocess.run([str(hook)], env=env, check=True)
        self.assertEqual("reload adguardhome-doh-nginx\n", commands.read_text(encoding="utf-8"))
        self.assert_no_temporary_hooks()

    def test_identical_existing_hook_is_verified_without_replacement(self):
        hook = self.create()
        before = (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mtime_ns)
        self.assertEqual(hook, self.create())
        self.assertEqual(before, (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mtime_ns))
        self.assert_no_temporary_hooks()

    def test_conflicting_content_or_mode_is_never_changed(self):
        hook = self.create()
        hook.write_text("#!/bin/sh\necho another-owner\n", encoding="utf-8")
        before = (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mode)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.create()
        self.assertEqual(before, (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mode))

        hook.unlink()
        hook = self.create()
        for mode in (0o775, 0o1755):
            with self.subTest(mode=oct(mode)):
                hook.chmod(mode)
                before = (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mode)
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    self.create()
                self.assertEqual(before, (hook.read_bytes(), hook.stat().st_ino, hook.stat().st_mode))
        self.assert_no_temporary_hooks()

    def test_existing_symlink_fifo_and_foreign_owner_are_rejected(self):
        hook = self.target()
        external = self.root / "other-hook"
        external.write_text("third-party contents\n", encoding="utf-8")
        hook.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.create()
        self.assertTrue(hook.is_symlink())
        self.assertEqual("third-party contents\n", external.read_text(encoding="utf-8"))

        hook.unlink()
        os.mkfifo(hook)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.create()
        self.assertTrue(stat.S_ISFIFO(hook.lstat().st_mode))

        hook.unlink()
        hook = self.create()
        before = hook.read_bytes()
        info = hook.stat()
        self.foreign.add((info.st_dev, info.st_ino))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.create()
        self.assertEqual(before, hook.read_bytes())
        self.assert_no_temporary_hooks()

    def test_existing_hardlink_is_rejected_without_changing_either_name(self):
        hook = self.create()
        second = self.root / "another-link"
        os.link(hook, second)
        before = hook.read_bytes()
        with self.assertRaisesRegex(ValueError, "hardlinks"):
            self.create()
        self.assertEqual(before, hook.read_bytes())
        self.assertEqual(before, second.read_bytes())
        self.assertEqual(hook.stat().st_ino, second.stat().st_ino)
        self.assert_no_temporary_hooks()

    def test_unsafe_domain_and_unit_are_rejected_before_any_write(self):
        bad_domains = ("", "single", "DNS.example.com", "dns.example.com.", "a..example.com",
                       "-a.example.com", "a-.example.com", "a_b.example.com", "é.example.com",
                       "x.example.com;id", "x.example.com$(id)", "x.example.com\nwhoami",
                       "x/example.com", "a" * 64 + ".example.com", ("a." * 127) + "aa")
        for domain in bad_domains:
            with self.subTest(domain=domain):
                with self.assertRaisesRegex(ValueError, "canonical domain"):
                    self.create(domain)
        for unit in ("adguardhome-doh-nginx", "nginx", "nginx;id", None):
            with self.subTest(unit=unit):
                with self.assertRaisesRegex(ValueError, "invalid unit"):
                    self.module.ensure_lineage_reload_hook(self.root, "dns.example.com", unit)
        self.assertEqual([], list(self.root.iterdir()))

    def test_directory_and_ancestor_must_be_trusted(self):
        invalid = self.base / "other"
        invalid.mkdir()
        with self.assertRaisesRegex(ValueError, "renewal-hooks/deploy"):
            self.module.ensure_lineage_reload_hook(
                invalid, "dns.example.com", self.module.ReloadUnit.SHARED_NGINX
            )
        linked_parent = self.base / "linked" / "renewal-hooks"
        linked_parent.mkdir(parents=True)
        link = linked_parent / "deploy"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.module.ensure_lineage_reload_hook(
                link, "dns.example.com", self.module.ReloadUnit.SHARED_NGINX
            )
        linked_ancestor = self.base / "linked-ancestor"
        linked_ancestor.mkdir()
        (linked_ancestor / "renewal-hooks").symlink_to(self.staging, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.module.ensure_lineage_reload_hook(
                linked_ancestor / "renewal-hooks" / "deploy", "dns.example.com",
                self.module.ReloadUnit.SHARED_NGINX,
            )
        self.staging.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.create()
        self.staging.chmod(0o755)
        parent = self.base / "writable-parent"
        child = parent / "renewal-hooks" / "deploy"
        child.mkdir(parents=True)
        parent.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.module.ensure_lineage_reload_hook(
                child, "dns.example.com", self.module.ReloadUnit.SHARED_NGINX
            )
        parent.chmod(0o755)
        child.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.module.ensure_lineage_reload_hook(
                child, "dns.example.com", self.module.ReloadUnit.SHARED_NGINX
            )
        child.chmod(0o755)
        info = child.stat()
        self.foreign.add((info.st_dev, info.st_ino))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.module.ensure_lineage_reload_hook(
                child, "dns.example.com", self.module.ReloadUnit.SHARED_NGINX
            )
        self.assertEqual([], list(child.iterdir()))

    def test_staging_stays_outside_certbot_scanned_directories(self):
        real_link = os.link
        seen = []

        def inspect_staging(source, target, **kwargs):
            stage_info = os.fstat(kwargs["src_dir_fd"])
            deploy_info = os.fstat(kwargs["dst_dir_fd"])
            self.assertEqual(self.staging.stat().st_ino, stage_info.st_ino)
            self.assertEqual(self.root.stat().st_ino, deploy_info.st_ino)
            self.assertNotEqual(stage_info.st_ino, deploy_info.st_ino)
            self.assertEqual(stage_info.st_dev, deploy_info.st_dev)
            temporary = os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False)
            self.assertEqual(0o755, stat.S_IMODE(temporary.st_mode))
            self.assertEqual([], [path.name for path in self.root.iterdir()
                                  if path.is_file() and os.access(path, os.X_OK)])
            seen.append(source)
            return real_link(source, target, **kwargs)

        with mock.patch.object(self.module.os, "link", side_effect=inspect_staging):
            self.create()
        self.assertEqual(1, len(seen))
        self.assert_no_temporary_hooks()

    def test_staging_and_hook_must_share_a_filesystem(self):
        staging_info = self.staging.stat()
        previous_fstat = os.fstat

        def changed_device(fd):
            info = previous_fstat(fd)
            if (info.st_dev, info.st_ino) == (staging_info.st_dev, staging_info.st_ino):
                return _StatOverride(info, st_dev=info.st_dev + 1)
            return info

        with mock.patch.object(self.module.os, "fstat", side_effect=changed_device):
            with self.assertRaisesRegex(ValueError, "share a filesystem"):
                self.create()
        self.assertEqual([], list(self.root.iterdir()))
        self.assert_no_temporary_hooks()

    def test_directory_identity_change_is_rejected_before_link(self):
        previous_stat = os.stat
        seen = 0

        def changed_stat(path, *args, **kwargs):
            nonlocal seen
            info = previous_stat(path, *args, **kwargs)
            if path == "deploy" and kwargs.get("dir_fd") is not None:
                seen += 1
                if seen == 2:
                    return _StatOverride(info, st_ino=info.st_ino + 1)
            return info

        with mock.patch.object(self.module.os, "stat", side_effect=changed_stat):
            with self.assertRaisesRegex(ValueError, "deploy directory changed"):
                self.create()
        self.assertFalse(self.target().exists())
        self.assert_no_temporary_hooks()

    def test_file_and_both_directories_are_synced_in_publication_order(self):
        real_fsync = os.fsync
        real_link = os.link
        real_unlink = os.unlink
        staging_ino = self.staging.stat().st_ino
        deploy_ino = self.root.stat().st_ino
        events = []

        def record_fsync(fd):
            info = os.fstat(fd)
            if (stat.S_ISDIR(info.st_mode) and info.st_ino == staging_ino):
                events.append("sync staging")
            elif stat.S_ISDIR(info.st_mode) and info.st_ino == deploy_ino:
                events.append("sync deploy")
            elif stat.S_ISREG(info.st_mode):
                events.append("sync file")
            return real_fsync(fd)

        def record_link(*args, **kwargs):
            events.append("link")
            return real_link(*args, **kwargs)

        def record_unlink(name, *args, **kwargs):
            if str(name).startswith(".adguardhome-doh-reload-"):
                events.append("unlink temporary")
            return real_unlink(name, *args, **kwargs)

        with mock.patch.object(self.module.os, "fsync", side_effect=record_fsync), \
                mock.patch.object(self.module.os, "link", side_effect=record_link), \
                mock.patch.object(self.module.os, "unlink", side_effect=record_unlink):
            self.create()
        self.assertLess(events.index("sync file"), events.index("link"))
        self.assertLess(events.index("link"), events.index("unlink temporary"))
        self.assertLess(events.index("unlink temporary"), events.index("sync deploy"))
        self.assertLess(events.index("unlink temporary"), events.index("sync staging"))
        self.assert_no_temporary_hooks()

    def test_concurrent_creators_wait_for_temporary_hardlink_and_both_verify(self):
        barrier = threading.Barrier(2)
        transient_seen = threading.Event()
        real_link = os.link
        real_check = self.module._check_existing_lineage_hook

        def simultaneous_link(*args, **kwargs):
            barrier.wait(timeout=5)
            result = real_link(*args, **kwargs)
            if not transient_seen.wait(timeout=5):
                raise RuntimeError("second creator did not observe the temporary hardlink")
            return result

        def check(*args, **kwargs):
            try:
                return real_check(*args, **kwargs)
            except self.module._HookHasHardlink:
                transient_seen.set()
                raise

        with mock.patch.object(self.module.os, "link", side_effect=simultaneous_link), \
                mock.patch.object(self.module, "_check_existing_lineage_hook", side_effect=check):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = [future.result(timeout=10) for future in
                           [pool.submit(self.create) for _ in range(2)]]
        self.assertTrue(transient_seen.is_set())
        self.assertEqual([self.target(), self.target()], results)
        self.assertEqual(1, self.target().stat().st_nlink)
        self.assert_no_temporary_hooks()

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires two real root-owned processes on Linux")
    def test_two_processes_create_without_overwriting(self):
        child_code = r'''
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("renewal", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_link = module.os.link

def gated_link(*args, **kwargs):
    module.os.link = real_link
    print("READY", flush=True)
    if sys.stdin.readline().strip() != "go":
        raise RuntimeError("barrier failed")
    return real_link(*args, **kwargs)

module.os.link = gated_link
def create():
    return module.ensure_lineage_reload_hook(
        Path(sys.argv[2]), "dns.example.com", module.ReloadUnit.SHARED_NGINX
    )

try:
    hook = create()
except module._HookHasHardlink:
    print("RETRY", flush=True)
    if sys.stdin.readline().strip() != "retry":
        raise RuntimeError("retry barrier failed")
    hook = create()
print("SUCCESS " + str(hook), flush=True)
'''
        processes = [subprocess.Popen(
            [sys.executable, "-c", child_code, str(MODULE_PATH), str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        ) for _ in range(2)]

        def read_line(process):
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=10):
                    self.fail("process timed out waiting at Certbot hook barrier")
            return process.stdout.readline().strip()

        try:
            self.assertNotEqual(processes[0].pid, processes[1].pid)
            self.assertEqual(["READY", "READY"], [read_line(p) for p in processes])
            for process in processes:
                process.stdin.write("go\n")
                process.stdin.flush()
            outcomes = [read_line(p) for p in processes]
            self.assertTrue(any(value.startswith("SUCCESS ") for value in outcomes), outcomes)
            for process, outcome in zip(processes, outcomes):
                if outcome == "RETRY":
                    process.stdin.write("retry\n")
                    process.stdin.flush()
                    outcome = read_line(process)
                self.assertEqual("SUCCESS " + str(self.target()), outcome)
            for process in processes:
                process.stdin.close()
                self.assertEqual(0, process.wait(timeout=10), process.stderr.read())
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream and not stream.closed:
                        stream.close()
        self.assertEqual(1, self.target().stat().st_nlink)
        self.assert_no_temporary_hooks()

    def test_changed_identity_during_existing_file_read_is_rejected(self):
        hook = self.create()
        before = (hook.read_bytes(), hook.stat().st_ino)
        previous_stat = os.stat
        seen = 0

        def changed_stat(path, *args, **kwargs):
            nonlocal seen
            info = previous_stat(path, *args, **kwargs)
            if path == hook.name and kwargs.get("dir_fd") is not None:
                seen += 1
                if seen == 2:
                    return _StatOverride(info, st_ino=info.st_ino + 1)
            return info

        with mock.patch.object(self.module.os, "stat", side_effect=changed_stat):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.create()
        self.assertEqual(before, (hook.read_bytes(), hook.stat().st_ino))
        self.assert_no_temporary_hooks()

    def test_failures_before_link_do_not_create_target(self):
        real_fsync = os.fsync

        def fail_file_fsync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("injected file fsync failure")
            return real_fsync(fd)

        with mock.patch.object(self.module.os, "fsync", side_effect=fail_file_fsync):
            with self.assertRaisesRegex(OSError, "file fsync failure"):
                self.create()
        self.assertFalse(self.target().exists())
        self.assert_no_temporary_hooks()
        with mock.patch.object(self.module.os, "link", side_effect=OSError("injected link failure")):
            with self.assertRaisesRegex(self.module.HookPartialCommitError, "target may already exist"):
                self.create()
        self.assertFalse(self.target().exists())
        self.assert_no_temporary_hooks()

    def test_directory_fsync_failure_reports_possible_partial_commit(self):
        real_fsync = os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory fsync failure")
            return real_fsync(fd)

        with mock.patch.object(self.module.os, "fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(self.module.HookPartialCommitError, "may already exist"):
                self.create()
        self.assertTrue(self.target().is_file())
        self.assertEqual(0o755, stat.S_IMODE(self.target().stat().st_mode))
        self.assert_no_temporary_hooks()

    def test_staging_fsync_failure_reports_possible_partial_commit(self):
        real_fsync = os.fsync
        staging_info = self.staging.stat()

        def fail_staging_fsync(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (staging_info.st_dev, staging_info.st_ino):
                raise OSError("injected staging fsync failure")
            return real_fsync(fd)

        with mock.patch.object(self.module.os, "fsync", side_effect=fail_staging_fsync):
            with self.assertRaisesRegex(self.module.HookPartialCommitError, "may already exist"):
                self.create()
        self.assertTrue(self.target().is_file())
        self.assert_no_temporary_hooks()


class RealOwnerCheckTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "root owns this test directory")
    def test_nonroot_owned_directory_is_rejected_without_metadata_substitution(self):
        module = load_module()
        temp_parent = "/private/tmp" if Path("/private/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(dir=temp_parent) as directory:
            hooks = Path(directory) / "renewal-hooks" / "deploy"
            hooks.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                module.ensure_lineage_reload_hook(
                    hooks, "dns.example.com", module.ReloadUnit.SHARED_NGINX
                )
            self.assertEqual([], list(hooks.iterdir()))


if __name__ == "__main__":
    unittest.main()
