import importlib.util
import os
from pathlib import Path
import subprocess
import stat
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "deploy/lib/certbot_renewal.py"
spec = importlib.util.spec_from_file_location("admin_renewal", MODULE)
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)


class AdminRenewalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.webroot = root / "webroot"
        (self.webroot / ".well-known/acme-challenge").mkdir(parents=True)
        self.hooks = root / "renewal-hooks/deploy"
        self.hooks.mkdir(parents=True)
        self.domain = "admin.example.com"
        (root / "renewal").mkdir()
        (root / "live" / self.domain).mkdir(parents=True)
        for kind in ("pre", "post"):
            (root / "renewal-hooks" / kind).mkdir()
        self.profile = root / "renewal" / (self.domain + ".conf")
        self.cert = root / "live" / self.domain / "cert.pem"
        self.profile.write_text(f"cert = {self.cert}\n[renewalparams]\nauthenticator = manual\n")
        self.patches = [mock.patch.object(renewal, "CERTBOT_ROOT", root),
                        mock.patch.object(renewal, "ADMIN_WEBROOT", self.webroot),
                        mock.patch.object(renewal.ssl._ssl, "_test_decode_cert", return_value={
                            "subjectAltName": (("DNS", self.domain),)}),
                        mock.patch.object(renewal, "_open_trusted_hook_directory",
                                          side_effect=lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY))]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def invoke(self):
        return renewal.reconfigure_admin_renewal(self.domain, self.webroot, self.hooks)

    def test_success_runs_probe_before_single_staging_reconfigure(self):
        calls = []
        environments = []
        homes = []
        def run(args, **kwargs):
            calls.append(args)
            environments.append(kwargs["env"])
            if args[0] == "curl":
                name = args[-1].rsplit("/", 1)[-1]
                data = (self.webroot / ".well-known/acme-challenge" / name).read_bytes()
                return subprocess.CompletedProcess(args, 0, data)
            self.assertEqual(300, kwargs["timeout"])
            home = Path(kwargs["env"]["HOME"])
            self.assertTrue(home.is_dir())
            self.assertEqual(0o700, stat.S_IMODE(home.stat().st_mode))
            self.assertEqual(str(home), kwargs["env"]["XDG_CONFIG_HOME"])
            homes.append(home)
            self.profile.write_text(f"cert = {self.cert}\n[renewalparams]\nauthenticator = webroot\n"
                                    f"[[webroot_map]]\n{self.domain} = {self.webroot}\n")
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(renewal.subprocess, "run", side_effect=run), \
             mock.patch.object(renewal, "ensure_lineage_reload_hook") as hook:
            self.invoke()
        self.assertEqual(["curl", "certbot"], [call[0] for call in calls])
        self.assertEqual(["certbot", "reconfigure", "--cert-name", self.domain,
                          "--webroot", "--webroot-path", str(self.webroot),
                          "--preferred-challenges", "http", "--non-interactive"], calls[1])
        self.assertEqual({"PATH", "LC_ALL"}, set(environments[0]))
        self.assertEqual({"PATH", "LC_ALL", "HOME", "XDG_CONFIG_HOME"}, set(environments[1]))
        self.assertFalse(homes[0].exists())
        hook.assert_called_once_with(self.hooks, self.domain, renewal.ReloadUnit.SHARED_NGINX)
        self.assertEqual([], list((self.webroot / ".well-known/acme-challenge").iterdir()))

    def test_probe_failure_never_runs_certbot_or_publishes_hook(self):
        with mock.patch.object(renewal.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"wrong")) as run, \
             mock.patch.object(renewal, "ensure_lineage_reload_hook") as hook:
            with self.assertRaisesRegex(ValueError, "unexpected content"):
                self.invoke()
        self.assertEqual(1, run.call_count)
        hook.assert_not_called()
        self.assertEqual([], list((self.webroot / ".well-known/acme-challenge").iterdir()))

    def test_existing_profile_hook_and_shared_hook_conflict_are_refused(self):
        with mock.patch.object(renewal, "_verify_public_http01") as probe:
            self.profile.write_text(f"cert = {self.cert}\n[renewalparams]\npre_hook = systemctl stop nginx\n")
            with self.assertRaisesRegex(ValueError, "contains a hook"):
                self.invoke()
            self.profile.write_text(f"cert = {self.cert}\n[renewalparams]\nauthenticator = manual\n")
            legacy = self.hooks / "adguardhome-doh-reload"
            legacy.write_text("/etc/letsencrypt/live/" + self.domain)
            legacy.chmod(0o755)
            real_fstat, real_stat = os.fstat, os.stat
            class RootOwner:
                def __init__(self, value):
                    self.value = value
                    self.st_uid = 0
                def __getattr__(self, name):
                    return getattr(self.value, name)
            def root_fstat(fd):
                value = real_fstat(fd)
                return RootOwner(value) if stat.S_ISREG(value.st_mode) else value
            def root_stat(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                return RootOwner(value) if path == legacy.name else value
            with mock.patch.object(renewal.os, "fstat", side_effect=root_fstat), \
                 mock.patch.object(renewal.os, "stat", side_effect=root_stat):
                with self.assertRaisesRegex(ValueError, "already references"):
                    self.invoke()
            probe.assert_not_called()

    def test_multiple_names_and_wrong_result_fail_closed(self):
        with mock.patch.object(renewal.ssl._ssl, "_test_decode_cert", return_value={
                "subjectAltName": (("DNS", self.domain), ("DNS", "other.example"))}):
            with self.assertRaisesRegex(ValueError, "exactly"):
                self.invoke()
        with mock.patch.object(renewal, "_verify_public_http01"), \
             mock.patch.object(renewal, "_check_legacy_admin_hook"), \
             mock.patch.object(renewal, "ensure_lineage_reload_hook"), \
             mock.patch.object(renewal.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(ValueError, "unexpected"):
                self.invoke()

    def test_executable_pre_and_post_hooks_block_before_probe(self):
        for kind in ("pre", "post"):
            hook = self.hooks.parent / kind / "foreign-hook"
            hook.write_text("#!/bin/sh\nexit 1\n")
            hook.chmod(0o755)
            with mock.patch.object(renewal, "_verify_public_http01") as probe, \
                 mock.patch.object(renewal, "ensure_lineage_reload_hook") as publish:
                with self.assertRaisesRegex(ValueError, "unknown Certbot"):
                    self.invoke()
                probe.assert_not_called()
                publish.assert_not_called()
            hook.unlink()

    def test_global_cli_config_blocks_before_any_write(self):
        config = self.hooks.parent.parent / "cli.ini"
        config.write_text("max-log-backups = 0\npreconfigured-renewal = true\n")
        config.chmod(0o600)
        real_fstat, real_stat = os.fstat, os.stat
        class RootOwner:
            def __init__(self, value):
                self.value = value
                self.st_uid = 0
            def __getattr__(self, name):
                return getattr(self.value, name)
        def root_fstat(fd):
            value = real_fstat(fd)
            return RootOwner(value) if stat.S_ISREG(value.st_mode) else value
        def root_stat(path, *args, **kwargs):
            value = real_stat(path, *args, **kwargs)
            return RootOwner(value) if path == "cli.ini" else value
        with mock.patch.object(renewal.os, "fstat", side_effect=root_fstat), \
             mock.patch.object(renewal.os, "stat", side_effect=root_stat), \
             mock.patch.object(renewal, "_verify_public_http01") as probe, \
             mock.patch.object(renewal, "ensure_lineage_reload_hook") as publish:
            for value in ("true", "True", "TRUE"):
                config.write_text(f"max-log-backups = 0\npreconfigured-renewal = {value}\n")
                renewal._check_safe_global_cli_config()
            invalid = (
                "pre-hook = dangerous-command\n", "post-hook = dangerous-command\n",
                "server = https://example.com/acme\n", "max-log-backups = -1\n",
                "max-log-backups = 0; pre-hook = run\n", "preconfigured-renewal = false\n", "preconfigured-renewal = other\n",
                "max-log-backups = 0\nmax-log-backups = 1\n",
                "preconfigured-renewal = true\npreconfigured-renewal = true\n",
            )
            for text in invalid:
                with self.subTest(config=text):
                    config.write_text(text)
                    with self.assertRaisesRegex(ValueError, "global cli.ini"):
                        self.invoke()
            probe.assert_not_called()
            publish.assert_not_called()

    def test_invalid_hostname_and_unexpected_webroot_fail_before_probe(self):
        with mock.patch.object(renewal, "_verify_public_http01") as probe:
            with self.assertRaisesRegex(ValueError, "canonical domain"):
                renewal.reconfigure_admin_renewal("Admin.example.com", self.webroot, self.hooks)
            with self.assertRaisesRegex(ValueError, "webroot"):
                renewal.reconfigure_admin_renewal(self.domain, self.webroot / "other", self.hooks)
            probe.assert_not_called()

    def test_certbot_timeout_removes_private_home(self):
        homes = []
        def timeout(args, **kwargs):
            homes.append(Path(kwargs["env"]["HOME"]))
            self.assertTrue(homes[0].is_dir())
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        with mock.patch.object(renewal, "_verify_public_http01"), \
             mock.patch.object(renewal, "_check_legacy_admin_hook"), \
             mock.patch.object(renewal, "ensure_lineage_reload_hook"), \
             mock.patch.object(renewal.subprocess, "run", side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.invoke()
        self.assertFalse(homes[0].exists())

    def test_certbot_failure_is_propagated(self):
        with mock.patch.object(renewal, "_verify_public_http01"), \
             mock.patch.object(renewal, "_check_legacy_admin_hook"), \
             mock.patch.object(renewal, "ensure_lineage_reload_hook"), \
             mock.patch.object(renewal.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "certbot")):
            with self.assertRaises(subprocess.CalledProcessError):
                self.invoke()


if __name__ == "__main__":
    unittest.main()
