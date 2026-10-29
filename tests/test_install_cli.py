import os
import json
import re
import subprocess
import sys
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

    def run_install_capturing_renderer(self, capture, *args, extra_env=None):
        fake_bin = capture / "bin"
        fake_bin.mkdir(parents=True)
        shim = fake_bin / "python3"
        shim.write_text(
            '#!/bin/sh\n'
            'case "$1" in\n'
            '  */deploy/lib/render_runtime.py)\n'
            '    printf "CALL\\n" >> "$RENDER_ARGS"\n'
            '    for arg in "$@"; do printf "%s\\n" "$arg" >> "$RENDER_ARGS"; done\n'
            '    "$REAL_PYTHON" "$@" || exit $?\n'
            '    while [ "$#" -gt 0 ]; do\n'
            '      if [ "$1" = --output ]; then output="$2"; break; fi\n'
            '      shift\n'
            '    done\n'
            '    cp "$output/nginx-stream.conf" "$CAPTURE_DIR/stream"\n'
            '    cp "$output/nginx-http.conf" "$CAPTURE_DIR/http"\n'
            '    cp "$output/AdGuardHome.yaml" "$CAPTURE_DIR/adguard"\n'
            '    cp "$output/health-policy.json" "$CAPTURE_DIR/policy"\n'
            '    if [ -f "$output/mtproxyl-sni.map" ]; then\n'
            '      cp "$output/mtproxyl-sni.map" "$CAPTURE_DIR/map"\n'
            '    fi\n'
            '    exit 0;;\n'
            'esac\nexec "$REAL_PYTHON" "$@"\n', encoding="utf-8",
        )
        shim.chmod(0o755)
        env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}",
                   REAL_PYTHON=sys.executable, RENDER_ARGS=str(capture / "args"),
                   CAPTURE_DIR=str(capture))
        env.update(extra_env or {})
        return subprocess.run([str(INSTALL), *args], cwd=ROOT, env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_help_is_available(self):
        result = self.run_install("--help")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--domain HOST", result.stdout)
        self.assertIn("--admin-host HOST", result.stdout)
        self.assertIn("--rollback", result.stdout)

    def test_adguard_release_version_is_independent_from_project_version(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'ADGUARD_VERSION="${ADGUARDHOME_DOH_ADGUARD_VERSION:-0.107.79}"',
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

    def test_front_dry_runs_render_the_selected_topology_and_full_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (("standard", False, False), ("mtproxyl", False, False),
                     ("mtproxyl", True, False), ("mtproxyl", False, True),
                     ("mtproxyl", True, True))
            for front, policy, admin in cases:
                with self.subTest(front=front, policy=policy, admin=admin):
                    capture = root / f"capture-{front}-{policy}-{admin}"
                    isolated = root / f"target-{front}-{policy}-{admin}"
                    isolated.mkdir()
                    command = ["--front", front, "--domain", "dns.example.com",
                               "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                               "--root", str(isolated), "--dry-run"]
                    if policy:
                        policy_path = root / "policy with spaces.csv"
                        policy_path.write_bytes((ROOT / "config/policy.csv").read_bytes())
                        command += ["--policy", str(policy_path)]
                    if admin:
                        command += ["--admin-host", "Admin.Example.COM"]
                    result = self.run_install_capturing_renderer(capture, *command)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn(f"Front: {front}", result.stdout)
                    arguments = (capture / "args").read_text(encoding="utf-8")
                    self.assertEqual(2, arguments.count(f"--front\n{front}\n"))
                    stream = (capture / "stream").read_text(encoding="utf-8")
                    if front == "mtproxyl":
                        self.assertIn("listen 127.0.0.1:24443 proxy_protocol", stream)
                        self.assertTrue((capture / "map").read_text(encoding="utf-8"))
                        self.assertEqual(2, arguments.count("--config-dir\n"))
                    else:
                        self.assertIn("listen 443 ", stream)
                        self.assertFalse((capture / "map").exists())
                    if policy:
                        self.assertEqual(2, arguments.count("--policy\n"))
                    if admin:
                        self.assertIn("Admin URL: https://admin.example.com/", result.stdout)
                        self.assertEqual(2, arguments.count("--admin-host\nadmin.example.com\n"))
                        self.assertEqual(2, arguments.count(
                            "--admin-certificate-root\n/etc/letsencrypt/live/admin.example.com\n"))
                        self.assertIn("admin.example.com adguardhome_doh;",
                                      (capture / "map").read_text(encoding="utf-8"))
                        self.assertIn("admin.example.com 127.0.0.1:4443;", stream)
                        http = (capture / "http").read_text(encoding="utf-8")
                        self.assertIn("server_name admin.example.com;", http)
                        self.assertIn("ssl_certificate /etc/letsencrypt/live/admin.example.com/fullchain.pem;", http)
                        self.assertIn("ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;", http)
                    else:
                        self.assertIn("Admin URL: https://dns.example.com/", result.stdout)
                        self.assertNotIn("--admin-host", arguments)
                        self.assertNotIn("--admin-certificate-root", arguments)
                    self.assertEqual([], list(isolated.iterdir()))

    def test_front_option_validation_and_local_site_compatibility(self):
        base = ("--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                "--email", "admin@example.com", "--dry-run")
        for value in ("", "MTProxyL", "unknown", "mtproxyl;reboot"):
            with self.subTest(value=value):
                result = self.run_install(*base, "--front", value)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("invalid --front", result.stderr)
        missing = self.run_install("--front")
        self.assertNotEqual(0, missing.returncode)
        self.assertIn("--front requires a value", missing.stderr)
        standard = self.run_install(*base, "--front", "standard",
                                    "--local-site", "app.example.org=127.0.0.1:9443")
        self.assertEqual(0, standard.returncode, standard.stderr)
        shared = self.run_install(*base, "--front", "mtproxyl",
                                  "--local-site", "app.example.org=127.0.0.1:9443")
        self.assertNotEqual(0, shared.returncode)
        self.assertIn("local sites are not supported with mtproxyl front", shared.stderr)

    def test_admin_host_rejects_invalid_names_and_route_conflicts_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = ("--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                    "--email", "admin@example.com", "--root", directory, "--dry-run")
            for host, error in (("", "invalid --admin-host"),
                                ("bad host", "invalid --admin-host"),
                                ("admin.example.com;reboot", "invalid --admin-host"),
                                ("dns.example.com", "conflicts"),
                                ("WEB.DNS.EXAMPLE.COM", "conflicts"),
                                ("admin.spotify.com", "conflicts with a routed domain")):
                with self.subTest(host=host):
                    result = self.run_install(*base, "--front", "mtproxyl", "--admin-host", host)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn(error, result.stderr)
                    self.assertEqual([], list(root.iterdir()))
            standard = self.run_install(*base, "--admin-host", "admin.example.com")
            self.assertNotEqual(0, standard.returncode)
            self.assertIn("--admin-host requires --front mtproxyl", standard.stderr)
            self.assertEqual([], list(root.iterdir()))
            missing = self.run_install("--admin-host")
            self.assertNotEqual(0, missing.returncode)
            self.assertIn("--admin-host requires a value", missing.stderr)

    def test_update_inherits_or_overrides_admin_host_and_manager_uses_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            base = ("--root", str(target), "--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                    "--email", "admin@example.com", "--dry-run")
            seed = root / "seed"
            result = self.run_install_capturing_renderer(seed, *base, "--front", "mtproxyl",
                                                        "--admin-host", "admin.example.com")
            self.assertEqual(0, result.returncode, result.stderr)
            state = target / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            saved = dict(domain="dns.example.com", public_ip="203.0.113.10",
                         email="admin@example.com", version="1.0.0", repository="owner/repo",
                         front="mtproxyl", admin_host="admin.example.com")
            state.write_text(json.dumps(saved), encoding="utf-8")
            state.chmod(0o600)
            config = target / "opt/AdGuardHome/AdGuardHome.yaml"
            config.parent.mkdir(parents=True)
            secret_hash = "existing-secret-password-hash"
            rendered = (seed / "adguard").read_text(encoding="utf-8")
            self.assertIn("dry-run-hash", rendered)
            config.write_text(rendered.replace("dry-run-hash", secret_hash), encoding="utf-8")
            policy = target / "etc/adguardhome-doh/health-policy.json"
            policy.parent.mkdir(parents=True)
            policy.write_bytes((seed / "policy").read_bytes())
            credential_secret = "existing-secret-password"
            token_secret = "existing-secret-token"
            (state.parent / "admin-credentials.json").write_text(credential_secret, encoding="utf-8")
            (state.parent / "doh-token").write_text(token_secret, encoding="utf-8")
            before = {path: path.read_bytes() for path in target.rglob("*") if path.is_file()}

            for name, flags, extra_env, expected in (
                ("inherited", (), None, "admin.example.com"),
                ("override", ("--admin-host", "new.example.com"), None, "new.example.com"),
                ("manager", ("--front", "standard", "--admin-host", "stale.example.com"),
                 {"ADGUARDHOME_DOH_MANAGER_UPDATE": "1"}, "admin.example.com"),
            ):
                with self.subTest(name=name):
                    capture = root / name
                    result = self.run_install_capturing_renderer(capture, *base, "--update", *flags,
                                                                extra_env=extra_env)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn(f"Admin URL: https://{expected}/", result.stdout)
                    arguments = (capture / "args").read_text(encoding="utf-8")
                    self.assertEqual(2, arguments.count(f"--admin-host\n{expected}\n"))
                    self.assertEqual(2, arguments.count(
                        f"--admin-certificate-root\n/etc/letsencrypt/live/{expected}\n"))
                    self.assertEqual(1, arguments.count(f"--existing-config\n{config}\n"))
                    self.assertIn(f"{expected} adguardhome_doh;", (capture / "map").read_text(encoding="utf-8"))
                    self.assertIn(f"ssl_certificate /etc/letsencrypt/live/{expected}/fullchain.pem;",
                                  (capture / "http").read_text(encoding="utf-8"))
                    for secret in (secret_hash, credential_secret, token_secret):
                        self.assertNotIn(secret, result.stdout + result.stderr + arguments)
                    self.assertEqual(before, {path: path.read_bytes() for path in target.rglob("*") if path.is_file()})

            incompatible = self.run_install(*base, "--update", "--front", "standard")
            self.assertNotEqual(0, incompatible.returncode)
            self.assertIn("--admin-host requires --front mtproxyl", incompatible.stderr)
            self.assertEqual(before, {path: path.read_bytes() for path in target.rglob("*") if path.is_file()})

    def test_update_inherits_front_and_explicit_direct_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            legacy = dict(domain="dns.example.com", public_ip="203.0.113.10",
                          email="admin@example.com", version="1.0.0", repository="owner/repo")
            base = ("--update", "--dry-run", "--root", directory, "--domain", legacy["domain"],
                    "--public-ip", legacy["public_ip"], "--email", legacy["email"])
            state.write_text(json.dumps(legacy), encoding="utf-8")
            state.chmod(0o600)
            result = self.run_install(*base)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Front: standard", result.stdout)
            manager_env = dict(os.environ, ADGUARDHOME_DOH_MANAGER_UPDATE="1")
            manager_legacy = subprocess.run(
                [str(INSTALL), *base, "--front", "mtproxyl", "--admin-host", "stale.example.com"],
                cwd=ROOT, env=manager_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, manager_legacy.returncode, manager_legacy.stderr)
            self.assertIn("Front: standard", manager_legacy.stdout)
            self.assertIn("Admin URL: https://dns.example.com/", manager_legacy.stdout)
            self.assertNotIn("stale.example.com", manager_legacy.stdout + manager_legacy.stderr)
            state.write_text(json.dumps({**legacy, "front": "mtproxyl"}), encoding="utf-8")
            before = state.read_bytes()
            inherited = self.run_install(*base)
            self.assertEqual(0, inherited.returncode, inherited.stderr)
            self.assertIn("Front: mtproxyl", inherited.stdout)
            overridden = self.run_install(*base, "--front", "standard")
            self.assertEqual(0, overridden.returncode, overridden.stderr)
            self.assertIn("Front: standard", overridden.stdout)
            self.assertEqual(before, state.read_bytes())
            env = dict(os.environ, ADGUARDHOME_DOH_MANAGER_UPDATE="1")
            manager = subprocess.run([str(INSTALL), *base, "--front", "standard"],
                                     cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, manager.returncode, manager.stderr)
            self.assertIn("Front: mtproxyl", manager.stdout)

    def test_shared_front_staging_renders_private_files_only(self):
        source = INSTALL.read_text(encoding="utf-8")
        start = source.index("adguardhome_doh_stage_shared_front() {")
        end = source.index("\n# Integration boundary:", start)
        function = source[start:end]
        with tempfile.TemporaryDirectory(dir="/private/tmp" if sys.platform == "darwin" else None) as directory:
            stage = Path(directory) / "stage"
            stage.mkdir(mode=0o700)
            result = subprocess.run(
                ["bash", "-c", function + '\nadguardhome_doh_stage_shared_front "$1" '
                 'dns.example.com admin.example.com',
                 "bash", str(stage)], cwd=ROOT, text=True, capture_output=True,
                env={**os.environ, "PROJECT_ROOT": str(ROOT), "SCRIPT_DIR": str(ROOT / "deploy")},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({"mtproxyl-nginx.conf", "adguardhome-doh-nginx.service",
                              "mtproxyl-http.conf", "mtproxyl-admin-acme.conf"},
                             {p.name for p in stage.iterdir()})
            self.assertIn("admin.example.com", (stage / "mtproxyl-admin-acme.conf").read_text())
            self.assertIn("127.0.0.1:4443", (stage / "mtproxyl-http.conf").read_text())
            self.assertEqual(0o600, (stage / "mtproxyl-http.conf").stat().st_mode & 0o777)

    def test_shared_front_real_install_is_rejected_before_system_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fresh = root / "fresh"
            fresh.mkdir()
            fresh_result = self.run_install(
                "--root", str(fresh), "--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                "--email", "admin@example.com", "--yes", "--front", "mtproxyl",
                "--admin-host", "admin.example.com",
            )
            self.assertNotEqual(0, fresh_result.returncode)
            self.assertIn("совместный front MTProxyL ещё не активирован", fresh_result.stderr)
            self.assertEqual([], list(fresh.iterdir()))
            fresh.rmdir()
            state = root / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            saved = dict(domain="dns.example.com", public_ip="203.0.113.10",
                         email="admin@example.com", version="1.0.0", repository="owner/repo",
                         front="mtproxyl", admin_host="admin.example.com")
            state.write_text(json.dumps(saved), encoding="utf-8")
            state.chmod(0o600)
            before = state.read_bytes()
            args = ("--root", directory, "--domain", saved["domain"], "--public-ip", saved["public_ip"],
                    "--email", saved["email"], "--yes")
            for flags in (("--front", "mtproxyl"), ("--update",),
                          ("--update", "--front", "standard"), ("--front", "standard")):
                with self.subTest(flags=flags):
                    result = self.run_install(*args, *flags)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("совместный front MTProxyL ещё не активирован", result.stderr)
                    self.assertEqual(before, state.read_bytes())
                    self.assertEqual([state], [path for path in root.rglob("*") if path.is_file()])

            state.write_text(json.dumps({key: value for key, value in saved.items()
                                         if key not in ("front", "admin_host")}),
                             encoding="utf-8")
            standard = self.run_install(*args, "--front", "standard")
            self.assertNotEqual(0, standard.returncode)
            self.assertNotIn("совместный front MTProxyL ещё не активирован", standard.stderr)

        source = INSTALL.read_text(encoding="utf-8")
        guard = source.index("совместный front MTProxyL ещё не активирован")
        self.assertLess(guard, source.index("adguardhome_doh_acquire_operation_lock ||"))
        self.assertLess(guard, source.index("adguardhome_doh_init_log /"))
        self.assertLess(guard, source.index("apt-get"))

    def test_all_renderer_branches_receive_the_selected_front(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertEqual(4, source.count('--front "$FRONT"'))
        self.assertEqual(2, source.count('${POLICY_CATALOG_ARGS[@]+"${POLICY_CATALOG_ARGS[@]}"}'))
        self.assertEqual(4, source.count('${ADMIN_HOST_ARGS[@]+"${ADMIN_HOST_ARGS[@]}"}'))

    def test_state_writer_embedded_in_installer_persists_only_mtproxyl_front(self):
        source = INSTALL.read_text(encoding="utf-8")
        match = re.search(r'^python3 - [^\n]* "\$FRONT" "\$ADMIN_HOST" <<\'PY\'\n(.*?)\nPY$', source,
                          re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "install.json"
            enabled = root / "enabled-services.json"
            for front, admin in (("standard", ""), ("mtproxyl", ""), ("mtproxyl", "admin.example.com")):
                args = [sys.executable, "-", str(ROOT / "deploy/lib/state.py"), str(state),
                        "dns.example.com", "203.0.113.10", "admin@example.com", "1.0.0",
                        "owner/repo", str(enabled), "chatgpt", "", "", "", front, admin]
                result = subprocess.run(args, input=match.group(1), cwd=ROOT, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, result.returncode, result.stderr)
                data = json.loads(state.read_text(encoding="utf-8"))
                if front == "standard":
                    self.assertNotIn("front", data)
                else:
                    self.assertEqual("mtproxyl", data["front"])
                if admin:
                    self.assertEqual(admin, data["admin_host"])
                else:
                    self.assertNotIn("admin_host", data)

    def test_dry_run_accepts_a_relay_exit_host_but_not_itself(self):
        base = ("--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                "--email", "admin@example.com", "--dry-run")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_install(*base, "--relay", "203.0.113.99", "--root", directory)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("dry-run завершён", result.stdout)
            same = self.run_install(*base, "--relay", "203.0.113.10", "--root", directory)
            self.assertNotEqual(0, same.returncode)
            self.assertIn("relay must differ", same.stderr)
            bad = self.run_install(*base, "--relay", "nope", "--root", directory)
            self.assertNotEqual(0, bad.returncode)
            self.assertIn("invalid relay", bad.stderr)
        source = INSTALL.read_text(encoding="utf-8")
        # Every render call and the saved state must carry the relay.
        self.assertEqual(4, source.count('${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"}'))
        self.assertIn("relay=relay or None", source)

    def test_dry_run_accepts_local_sites_served_behind_the_listener(self):
        base = ("--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                "--email", "admin@example.com", "--dry-run")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_install(
                *base, "--local-site", "app.example.org=127.0.0.1:9443",
                "--local-site", "*=127.0.0.1:9443", "--root", directory,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            bad = self.run_install(*base, "--local-site", "app.example.org=127.0.0.1:443", "--root", directory)
            self.assertNotEqual(0, bad.returncode)
            self.assertIn("invalid local site", bad.stderr)
        source = INSTALL.read_text(encoding="utf-8")
        self.assertEqual(4, source.count('${LOCAL_SITE_ARGS[@]+"${LOCAL_SITE_ARGS[@]}"}'))
        self.assertIn('adguardhome_doh_preflight / "$DOMAIN" "$PUBLIC_IP" "$UPDATE" "${#LOCAL_SITES[@]}"', source)

    def test_fronting_preflight_requires_nginx_to_own_both_ports(self):
        nginx_only = (
            'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=7))\n'
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=10,fd=8))\n'
            'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=11,fd=9))\n'
        )
        mixed = nginx_only + 'LISTEN 0 511 [::]:443 [::]:* users:(("apache2",pid=12,fd=5))\n'
        for listeners, expected in ((nginx_only, 0), (mixed, 1), ("", 1)):
            result = self.run_common('adguardhome_doh_nginx_owns_listeners "$1"', listeners)
            self.assertEqual(expected, result.returncode, listeners)
        for value, expected in (
            ("app.example.org=127.0.0.1:9443", 0), ("*=10.0.0.5:9443", 0),
            ("app.example.org=127.0.0.1:443", 1), ("app.example.org=127.0.0.1", 1),
            ("=127.0.0.1:9443", 1), ("bad host=127.0.0.1:9443", 1),
        ):
            result = self.run_common('adguardhome_doh_validate_local_site "$1"', value)
            self.assertEqual(expected, result.returncode, value)

    def test_nginx_listener_must_belong_to_the_system_nginx_service(self):
        listeners = (
            'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=7))\n'
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=11,fd=8))\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            for pid, unit in ((10, "nginx.service"), (11, "mtproxyl-pq-nginx.service")):
                path = proc / str(pid)
                path.mkdir(parents=True)
                (path / "cgroup").write_text("0::/system.slice/%s\n" % unit, encoding="utf-8")
            systemctl = 'systemctl() { case "$*" in "is-active --quiet nginx") return 0;; ' \
                        '"show --property=ControlGroup --value nginx") echo /system.slice/nginx.service;; ' \
                        '*) return 1;; esac; }; '
            check = systemctl + 'adguardhome_doh_system_nginx_owns_listeners "$1" "$2"'
            other = self.run_common(check, listeners, str(proc))
            self.assertNotEqual(0, other.returncode)
            (proc / "11/cgroup").write_text("0::/system.slice/nginx.service\n", encoding="utf-8")
            ours = self.run_common(check, listeners, str(proc))
            self.assertEqual(0, ours.returncode, ours.stderr)
            (proc / "11/cgroup").unlink()
            missing = self.run_common(check, listeners, str(proc))
            self.assertNotEqual(0, missing.returncode)

    def test_shared_port_snapshot_checks_all_listener_owners_and_both_private_ports(self):
        mtproxy = "/system.slice/mtproxyl-pq-nginx.service"
        private = "/system.slice/adguardhome-doh-nginx.service"
        system = "/system.slice/nginx.service"
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid, group in ((10, mtproxy), (11, mtproxy), (20, private), (30, system)):
                path = proc / str(pid)
                path.mkdir()
                (path / "cgroup").write_text(f"0::{group}\n", encoding="utf-8")
            public = (
                'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=7))\n'
                'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=11,fd=8))\n'
            )
            check = 'adguardhome_doh_shared_verify_listener_snapshot "$1" "$2" "$3" "$4" "$5" "$6"'

            def verify(listeners, previous="standard", private_group=""):
                return self.run_common(check, listeners, str(proc), mtproxy, previous,
                                       private_group, "203.0.113.10")

            self.assertEqual(0, verify(public).returncode)
            ipv6_system = 'LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=30,fd=3))\n'
            self.assertNotEqual(0, verify(public + ipv6_system).returncode)
            busy_4443 = 'LISTEN 0 511 127.0.0.1:4443 0.0.0.0:* users:(("nginx",pid=30,fd=9))\n'
            self.assertNotEqual(0, verify(public + busy_4443).returncode)
            private_sockets = (
                'LISTEN 0 511 127.0.0.1:4443 0.0.0.0:* users:(("nginx",pid=20,fd=9))\n'
                'LISTEN 0 511 127.0.0.1:24443 0.0.0.0:* users:(("nginx",pid=20,fd=10))\n'
            )
            self.assertNotEqual(0, verify(public + private_sockets).returncode)
            self.assertEqual(0, verify(public + private_sockets, "mtproxyl", private).returncode)
            self.assertNotEqual(0, verify(public + private_sockets + busy_4443, "mtproxyl", private).returncode)
            self.assertNotEqual(0, verify(public, "mtproxyl", private).returncode)
            self.assertNotEqual(0, verify(public.replace("pid=11", "pid=99")).returncode)
            self.assertNotEqual(0, verify(public.replace("pid=11", "pid=11,pid=bad")).returncode)
            self.assertNotEqual(0, verify(public.replace('users:(("nginx",pid=11,fd=8))',
                                                        'users:(("nginx",pid=bad,fd=4),("nginx",pid=11,fd=8))')).returncode)
            self.assertNotEqual(0, verify(public.replace("0.0.0.0:443", "127.0.0.1:443")).returncode)
            self.assertNotEqual(0, verify(public.replace('users:(("nginx",pid=11,fd=8))',
                                                        'users:(("nginx",pid=11,fd=8),("nginx",pid=30,fd=5))')).returncode)
            self.assertNotEqual(0, verify(public.replace(' users:(("nginx",pid=11,fd=8))', "")).returncode)
            self.assertNotEqual(0, verify(public, "mtproxyl", "/").returncode)

    def test_shared_port_preflight_queries_read_only_and_fails_closed(self):
        listeners = (
            'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=7))\n'
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=10,fd=8))\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "10").mkdir()
            (proc / "10/cgroup").write_text("0::/system.slice/mtproxyl-pq-nginx.service\n", encoding="utf-8")
            (proc / "20").mkdir()
            (proc / "20/cgroup").write_text("0::/system.slice/adguardhome-doh-nginx.service\n", encoding="utf-8")
            script = r'''
fixture="$1" scenario="$2"
systemctl() {
    case "$*" in
        'is-active --quiet mtproxyl-pq-nginx.service') [[ "$scenario" != inactive ]];;
        'show --property=ControlGroup --value mtproxyl-pq-nginx.service')
            if [[ "$scenario" == bad_group ]]; then printf '/\n'; else printf '/system.slice/mtproxyl-pq-nginx.service\n'; fi;;
        'is-active --quiet adguardhome-doh-nginx.service') [[ "$scenario" != private_inactive ]];;
        'show --property=ControlGroup --value adguardhome-doh-nginx.service') printf '/system.slice/adguardhome-doh-nginx.service\n';;
        *) printf 'unexpected systemctl action: %s\n' "$*" >&2; return 1;;
    esac
}
ss() { [[ "$*" == '-H -ltnp' && "$scenario" != ss_error ]] || return 1; printf '%s' "$fixture"; }
adguardhome_doh_shared_preflight_listeners '203.0.113.10' "$4" "$3"
'''
            for scenario, expected in (("ok", 0), ("inactive", 1), ("bad_group", 1), ("ss_error", 1)):
                with self.subTest(scenario=scenario):
                    result = self.run_common(script, listeners, scenario, str(proc), "standard")
                    self.assertEqual(expected, result.returncode, result.stderr)
            shared = listeners + (
                'LISTEN 0 511 127.0.0.1:4443 0.0.0.0:* users:(("nginx",pid=20,fd=9))\n'
                'LISTEN 0 511 127.0.0.1:24443 0.0.0.0:* users:(("nginx",pid=20,fd=10))\n'
            )
            for scenario, expected in (("ok", 0), ("private_inactive", 1)):
                with self.subTest(scenario=scenario):
                    result = self.run_common(script, shared, scenario, str(proc), "mtproxyl")
                    self.assertEqual(expected, result.returncode, result.stderr)

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

    def test_managed_update_reinstalls_an_existing_adguard_binary(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "AdGuardHome"
            target.write_bytes(b"old-binary")
            target.chmod(0o755)
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_should_install_binary "$2" 1',
                    "bash", str(common), str(target),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_existing_binary_is_kept_during_non_update_install(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "AdGuardHome"
            target.write_bytes(b"current-binary")
            target.chmod(0o755)
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_should_install_binary "$2" 0',
                    "bash", str(common), str(target),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(1, result.returncode, result.stderr)

    def test_adguard_binary_activation_replaces_target_with_executable(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "new-binary"
            target = root / "AdGuardHome"
            source.write_bytes(b"new-binary")
            target.write_bytes(b"old-binary")
            target.chmod(0o755)
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_activate_binary "$2" "$3"',
                    "bash", str(common), str(source), str(target),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(b"new-binary", target.read_bytes())
            self.assertEqual(0o755, target.stat().st_mode & 0o777)

    def test_failed_installer_exit_restores_previous_adguard_binary(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "AdGuardHome.backup"
            target = root / "AdGuardHome"
            work = root / "download"
            backup.write_bytes(b"old-binary")
            backup.chmod(0o755)
            target.write_bytes(b"new-binary")
            target.chmod(0o755)
            work.mkdir()
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; '
                    'ADGUARDHOME_DOH_WORK_DIR="$2"; '
                    'ADGUARDHOME_DOH_BINARY_BACKUP="$3"; '
                    'ADGUARDHOME_DOH_BINARY_TARGET="$4"; '
                    'trap adguardhome_doh_install_exit EXIT; exit 23',
                    "bash", str(common), str(work), str(backup), str(target),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(23, result.returncode, result.stderr)
            self.assertEqual(b"old-binary", target.read_bytes())
            self.assertFalse(work.exists())

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
            diag = destination / "usr/local/sbin/adguardhome-doh-diag"
            self.assertTrue(diag.is_file())
            self.assertTrue(diag.stat().st_mode & 0o111)

    def test_required_packages_include_nginx_stream_module(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; adguardhome_doh_required_packages',
             "bash", str(common)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("libnginx-mod-stream", result.stdout.splitlines())

    def test_missing_packages_reports_only_packages_not_fully_installed(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            dpkg_query = fake_bin / "dpkg-query"
            dpkg_query.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${@: -1}\" in\n"
                "  installed) printf 'ii ' ;;\n"
                "  configured-only) printf 'iF ' ;;\n"
                "  reinstall-required) printf 'iiR' ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            dpkg_query.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; shift; adguardhome_doh_missing_packages "$@"',
                    "bash", str(common), "installed", "missing", "configured-only",
                    "reinstall-required",
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            ["missing", "configured-only", "reinstall-required"],
            result.stdout.splitlines(),
        )

    def test_installer_skips_apt_when_all_dependencies_are_installed(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'mapfile -t missing_packages < <(adguardhome_doh_missing_packages "${required_packages[@]}")',
            source,
        )
        self.assertIn('if ((${#missing_packages[@]})); then', source)
        self.assertIn(
            'install -y --no-install-recommends "${missing_packages[@]}"',
            source,
        )
        self.assertNotIn(
            'apt-get install -y --no-install-recommends "${required_packages[@]}"',
            source,
        )

    def test_managed_update_summary_does_not_print_credentials(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            'if ((UPDATE)); then\n    adguardhome_doh_update_summary "$LOG_PATH"',
            source,
        )
        self.assertIn(
            'else\n    adguardhome_doh_summary "$LOG_PATH" "$DOH_TOKEN" "$ADMIN_PASSWORD" "$CREDENTIALS_FILE"',
            source,
        )
        start = source.index("adguardhome_doh_update_summary()")
        end = source.index("adguardhome_doh_render_dry_run()", start)
        update_summary = source[start:end]
        self.assertNotIn("Password:", update_summary)
        self.assertNotIn("DoH URL:", update_summary)
        self.assertNotIn("mobileconfig URL:", update_summary)

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

    def test_https_sni_smoke_retries_and_uses_local_stream_listener(self):
        common = ROOT / "deploy" / "lib" / "common.sh"
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            calls = temp / "calls"
            fake_curl = temp / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$CALLS_FILE\"\n"
                "count=$(wc -l < \"$CALLS_FILE\")\n"
                "(( count >= 3 ))\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{temp}:{env['PATH']}"
            env["CALLS_FILE"] = str(calls)
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; adguardhome_doh_smoke_https_sni "$2" 3 0',
                    "bash", str(common), "dns.example.com",
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            call_lines = calls.read_text(encoding="utf-8").splitlines()
        self.assertEqual(3, len(call_lines))
        self.assertTrue(
            all("--resolve dns.example.com:443:127.0.0.1" in line for line in call_lines)
        )
        self.assertTrue(all("--noproxy *" in line for line in call_lines))
        self.assertTrue(all("https://dns.example.com/" in line for line in call_lines))

    def test_installer_reloads_nginx_once_after_final_config_and_smoke_checks(self):
        source = INSTALL.read_text(encoding="utf-8")
        reload_command = "adguardhome_doh_run_logged systemctl reload nginx"
        # One reload activates the stream listener and the port-80 site
        # before the ACME challenge; the final one follows the TLS site.
        self.assertEqual(2, source.count(reload_command))
        first_reload = source.index(reload_command)
        self.assertLess(source.index("adguardhome_doh_run_logged systemctl start nginx"), first_reload)
        self.assertLess(first_reload, source.index("certbot certonly --webroot"))
        final_config = source.index(
            'mv -f -- "$ADGUARDHOME_DOH_NGINX_TEMP" /etc/nginx/sites-enabled/adguardhome-doh'
        )
        reload_index = source.rindex(reload_command)
        smoke_index = source.index(
            'adguardhome_doh_run_logged adguardhome_doh_smoke_https_sni "$DOMAIN"'
        )
        completion_index = source.index(
            'install -m 600 /dev/null "$INSTALL_COMPLETE_FILE"'
        )
        self.assertLess(final_config, reload_index)
        self.assertLess(reload_index, smoke_index)
        self.assertLess(smoke_index, completion_index)

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


    def test_certificate_issuance_never_stops_nginx(self):
        """Stopping nginx to renew takes DNS down for every client."""

        source = INSTALL.read_text(encoding="utf-8")

        self.assertIn('certbot certonly --webroot --webroot-path "$WEBROOT"', source)
        self.assertIn("--deploy-hook 'systemctl reload nginx'", source)
        self.assertNotIn("--standalone", source)
        self.assertNotIn("--pre-hook", source)
        self.assertNotIn("--post-hook", source)
        # Servers installed before this change keep their stored hooks until
        # the profile is migrated, so an update has to rewrite it.
        self.assertIn("adguardhome_doh_migrate_certbot_renewal", source)

    def test_runtime_units_recover_without_an_operator(self):
        source = INSTALL.read_text(encoding="utf-8")

        self.assertIn("Restart=always", source)
        self.assertIn("StartLimitIntervalSec=0", source)
        self.assertIn("adguardhome_doh_install_nginx_restart_dropin", source)
        self.assertIn("adguardhome_doh_ensure_nginx_worker_limits", source)
        self.assertIn("ADGUARDHOME_DOH_FAILURE_THRESHOLD=5", source)
        self.assertIn("adguardhome_doh_install_sysctl / || true", source)
        self.assertIn("adguardhome_doh_install_logrotate /", source)
        self.assertIn("ADGUARDHOME_DOH_DOMAIN=$DOMAIN", source)
        self.assertIn("ADGUARDHOME_DOH_TOKEN_FILE=$DOH_TOKEN_FILE", source)

    def run_common(self, script, *args):
        common = ROOT / "deploy" / "lib" / "common.sh"
        return subprocess.run(
            ["bash", "-c", 'source "$1"; shift; ' + script, "bash", str(common), *args],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_nginx_worker_limits_are_raised_idempotently(self):
        """One DoH connection costs three slots; 768 is reached far too soon."""

        default_conf = (
            "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\n"
            "\nevents {\n\tworker_connections 768;\n}\n\nhttp {\n}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / "nginx.conf"
            conf.write_text(default_conf, encoding="utf-8")

            result = self.run_common(
                'adguardhome_doh_ensure_nginx_worker_limits "$1"', str(conf)
            )
            self.assertEqual(0, result.returncode, result.stderr)
            once = conf.read_text(encoding="utf-8")
            self.assertIn("worker_rlimit_nofile 65535;", once)
            self.assertIn("worker_connections 8192;", once)
            self.assertNotIn("worker_connections 768;", once)

            result = self.run_common(
                'adguardhome_doh_ensure_nginx_worker_limits "$1"', str(conf)
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(once, conf.read_text(encoding="utf-8"))
            self.assertEqual(1, once.count("worker_rlimit_nofile"))
            self.assertEqual(1, once.count("worker_connections"))

    def test_nginx_worker_limits_keep_an_existing_rlimit_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / "nginx.conf"
            conf.write_text(
                "user www-data;\nevents {\n}\nworker_rlimit_nofile 1024;\nhttp {\n}\n",
                encoding="utf-8",
            )

            result = self.run_common(
                'adguardhome_doh_ensure_nginx_worker_limits "$1"', str(conf)
            )

            self.assertEqual(0, result.returncode, result.stderr)
            updated = conf.read_text(encoding="utf-8")
            # A duplicate directive would make nginx refuse to start at all.
            self.assertEqual(1, updated.count("worker_rlimit_nofile"))
            self.assertIn("worker_rlimit_nofile 65535;", updated)
            self.assertIn("worker_connections 8192;", updated)

    def test_nginx_worker_limits_handle_a_single_line_events_block(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / "nginx.conf"
            conf.write_text(
                "user www-data;\nevents { worker_connections 768; }\nhttp {\n}\n",
                encoding="utf-8",
            )

            result = self.run_common(
                'adguardhome_doh_ensure_nginx_worker_limits "$1"', str(conf)
            )

            self.assertEqual(0, result.returncode, result.stderr)
            updated = conf.read_text(encoding="utf-8")
            self.assertIn("events { worker_connections 8192; }", updated)
            self.assertIn("worker_rlimit_nofile 65535;", updated)
            self.assertEqual(1, updated.count("worker_connections"))

    def test_nginx_worker_limits_leave_an_unfamiliar_file_untouched(self):
        """Capacity tuning must never half-edit nginx.conf or fail an update."""

        original = "http {\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / "nginx.conf"
            conf.write_text(original, encoding="utf-8")

            result = self.run_common(
                'adguardhome_doh_ensure_nginx_worker_limits "$1"', str(conf)
            )

            self.assertEqual(1, result.returncode)
            self.assertIn("warning", result.stderr)
            self.assertEqual(original, conf.read_text(encoding="utf-8"))
            # The installer tolerates the warning instead of aborting.
            self.assertIn(
                "adguardhome_doh_ensure_nginx_worker_limits || true",
                INSTALL.read_text(encoding="utf-8"),
            )

    def test_nginx_restart_dropin_is_installed_under_the_target_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_common(
                'adguardhome_doh_install_nginx_restart_dropin "$1"', directory
            )

            self.assertEqual(0, result.returncode, result.stderr)
            dropin = Path(directory) / "etc/systemd/system/nginx.service.d/adguardhome-doh.conf"
            self.assertIn("Restart=on-failure", dropin.read_text(encoding="utf-8"))
            self.assertEqual(0o644, dropin.stat().st_mode & 0o777)

    def test_kernel_parameters_for_mobile_clients_are_installed_under_the_target_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_common('adguardhome_doh_install_sysctl "$1"', directory)

            self.assertEqual(0, result.returncode, result.stderr)
            conf = Path(directory) / "etc/sysctl.d/90-adguardhome-doh.conf"
            text = conf.read_text(encoding="utf-8")
            self.assertIn("net.ipv4.tcp_mtu_probing = 1", text)
            self.assertEqual(0o644, conf.stat().st_mode & 0o777)
            # BBR is only enabled on a live host where the module can be probed.
            self.assertNotIn("bbr", text)

    def test_stream_logs_rotate_under_the_target_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_common('adguardhome_doh_install_logrotate "$1"', directory)

            self.assertEqual(0, result.returncode, result.stderr)
            profile = Path(directory) / "etc/logrotate.d/adguardhome-doh"
            text = profile.read_text(encoding="utf-8")
            self.assertIn("/var/log/adguardhome-doh/nginx-stream.access.log", text)
            self.assertIn("/var/log/adguardhome-doh/nginx-stream.error.log", text)
            self.assertIn("rotate 7", text)
            # Reopen, never restart: a restart would drop every live session.
            self.assertIn("kill -USR1", text)
            self.assertNotIn("systemctl restart", text)

    def test_health_unit_can_write_its_run_lock(self):
        """ProtectSystem=strict makes /run read-only for the unit."""

        unit = (ROOT / "deploy" / "templates" / "healthcheck.service").read_text(encoding="utf-8")

        self.assertIn("ReadWritePaths=/var/lib/adguardhome-doh /run/lock", unit)
        self.assertIn("ProtectSystem=strict", unit)

    def test_direct_update_inherits_settings_and_honors_explicit_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "domain": "dns.example.com", "public_ip": "203.0.113.10",
                "email": "admin@example.com", "version": "1.0.0",
                "repository": "private/custom", "relay": "203.0.113.50",
                "local_sites": ["shop.example.org=127.0.0.1:9443"],
            }), encoding="utf-8")
            state.chmod(0o600)
            env = dict(os.environ, ADGUARDHOME_DOH_TTY_FD="0")
            env.pop("ADGUARDHOME_DOH_REPOSITORY", None)
            base = [str(INSTALL), "--update", "--dry-run", "--root", directory,
                    "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                    "--services", "chatgpt"]
            inherited = subprocess.run(base, input="DNS.EXAMPLE.COM\ny\n", env=env, cwd=ROOT,
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, inherited.returncode, inherited.stderr)
            self.assertIn("Домен: dns.example.com", inherited.stdout)
            self.assertIn("Relay: 203.0.113.50", inherited.stdout)
            self.assertIn("shop.example.org=127.0.0.1:9443", inherited.stdout)
            self.assertIn("Репозиторий: private/custom", inherited.stdout)
            overridden = subprocess.run(
                [*base, "--relay", "203.0.113.60", "--repository", "new/repo",
                 "--local-site", "other.example.org=127.0.0.1:9444"],
                input="dns.example.com\ny\n", env=env, cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, overridden.returncode, overridden.stderr)
            self.assertIn("Relay: 203.0.113.60", overridden.stdout)
            self.assertIn("Репозиторий: new/repo", overridden.stdout)
            self.assertIn("other.example.org=127.0.0.1:9444", overridden.stdout)
            self.assertNotIn("shop.example.org", overridden.stdout)

    def test_direct_update_rejects_untrusted_saved_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text('{"relay":"203.0.113.9"}', encoding="utf-8")
            state.chmod(0o644)
            result = self.run_install("--update", "--root", directory, "--dry-run",
                                      "--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                                      "--email", "admin@example.com")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("cannot load existing installation settings", result.stderr)
            self.assertEqual(0o644, state.stat().st_mode & 0o777)

    def test_direct_update_preserves_enabled_services_without_an_override(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "domain": "dns.example.com", "public_ip": "203.0.113.10",
                "email": "admin@example.com", "version": "1.0.0",
                "repository": "private/custom",
                "local_sites": ["chatgpt.com=127.0.0.1:9443"],
            }), encoding="utf-8")
            state.chmod(0o600)
            enabled = state.parent / "enabled-services.json"
            enabled.write_text('["claude"]\n', encoding="utf-8")
            enabled.chmod(0o600)
            args = ("--update", "--dry-run", "--root", directory,
                    "--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                    "--email", "admin@example.com")
            preserved = self.run_install(*args)
            self.assertEqual(0, preserved.returncode, preserved.stderr)
            explicit = self.run_install(*args, "--services", "chatgpt")
            self.assertNotEqual(0, explicit.returncode)

    def test_saved_compat_policy_survives_legacy_manager_services_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "etc/adguardhome-doh/compat-policy.csv"
            policy.parent.mkdir(parents=True)
            policy.write_bytes((ROOT / "config/policy.csv").read_bytes())
            state = root / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "domain": "dns.example.com", "public_ip": "203.0.113.10",
                "email": "admin@example.com", "version": "1.0.0",
                "repository": "owner/repo", "policy": "/etc/adguardhome-doh/compat-policy.csv",
            }), encoding="utf-8")
            state.chmod(0o600)
            env = dict(os.environ, ADGUARDHOME_DOH_TTY_FD="0")
            result = subprocess.run(
                [str(INSTALL), "--update", "--dry-run", "--root", directory,
                 "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                 "--services", "chatgpt"], input="dns.example.com\ny\n", env=env,
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Политика: " + str(policy), result.stdout)
            self.assertNotIn("Сервисы:", result.stdout)

    def test_legacy_policy_is_reconstructed_when_old_manager_passes_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "domain": "dns.example.com", "public_ip": "203.0.113.10",
                "email": "admin@example.com", "version": "1.0.0", "repository": "owner/repo",
            }), encoding="utf-8")
            state.chmod(0o600)
            health = root / "etc/adguardhome-doh/health-policy.json"
            health.parent.mkdir(parents=True)
            health.write_text(json.dumps({"services": {}, "domains": [
                {"domain": "old.example.org", "kind": "fqdn", "probe": "old.example.org", "services": []}
            ]}), encoding="utf-8")
            env = dict(os.environ, ADGUARDHOME_DOH_TTY_FD="0")
            base = [str(INSTALL), "--update", "--dry-run", "--root", directory,
                    "--public-ip", "203.0.113.10", "--email", "admin@example.com",
                    "--services", "chatgpt"]
            result = subprocess.run(base, input="dns.example.com\ny\n", env=env, cwd=ROOT,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Политика: восстановлена из предыдущей установки", result.stdout)
            collision = subprocess.run([*base, "--local-site", "old.example.org=127.0.0.1:9443"],
                                       input="dns.example.com\n", env=env, cwd=ROOT, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, collision.returncode)
            self.assertIn("collides with a routed domain", collision.stderr)

    def test_manager_arguments_are_refreshed_from_install_and_enabled_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "var/lib/adguardhome-doh/install.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "domain": "dns.example.com", "public_ip": "203.0.113.10",
                "email": "admin@example.com", "version": "1.0.0", "repository": "owner/repo",
                "local_sites": ["chatgpt.com=127.0.0.1:9443"],
            }), encoding="utf-8")
            state.chmod(0o600)
            enabled = state.parent / "enabled-services.json"
            enabled.write_text('["claude"]\n', encoding="utf-8")
            enabled.chmod(0o600)
            env = dict(os.environ, ADGUARDHOME_DOH_MANAGER_UPDATE="1")
            result = subprocess.run(
                [str(INSTALL), "--update", "--dry-run", "--root", directory,
                 "--domain", "stale.example.com", "--public-ip", "203.0.113.20",
                 "--email", "old@example.com", "--services", "chatgpt",
                 "--local-site", "old.example.net=127.0.0.1:9443", "--repository", "old/repo"],
                env=env, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("https://dns.example.com/", result.stdout)
            # Without the manager sentinel an explicit selection still wins;
            # it collides with the saved local-site and must be rejected.
            env.pop("ADGUARDHOME_DOH_MANAGER_UPDATE")
            explicit = subprocess.run(
                [str(INSTALL), "--update", "--dry-run", "--root", directory,
                 "--domain", "dns.example.com", "--public-ip", "203.0.113.10",
                 "--email", "admin@example.com", "--services", "chatgpt"],
                env=env, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, explicit.returncode)
            self.assertIn("collides with a routed domain", explicit.stderr)

    def test_password_stdin_is_not_echoed_or_passed_to_htpasswd_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials.json"
            secret = "not-an-argument-xyz"
            result = subprocess.run(
                ["python3", str(ROOT / "deploy/lib/credentials.py"), "--path", str(credentials),
                 "--url", "https://dns.example.com/", "--password-stdin"], input=secret,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout)
            self.assertEqual(secret, read_credentials(credentials)["password"])
            fake = root / "htpasswd"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARG_FILE"\n'
                            'cat > "$INPUT_FILE"\nprintf "admin:hashvalue\\n"\n', encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       ARG_FILE=str(root / "args"), INPUT_FILE=str(root / "input"))
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; adguardhome_doh_hash_password "$2"',
                 "bash", str(ROOT / "deploy/lib/common.sh"), secret],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("hashvalue\n", result.stdout)
            self.assertNotIn(secret, (root / "args").read_text(encoding="utf-8"))
            self.assertEqual(secret + "\n", (root / "input").read_text(encoding="utf-8"))

    def test_lock_fails_closed_when_flock_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "health.lock"
            script = ('source "$1"; PATH="$2"; ADGUARDHOME_DOH_LOCK_PATH="$3"; '
                      'adguardhome_doh_acquire_health_lock')
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh"), directory, str(lock)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("flock is required", result.stderr)
            self.assertFalse(lock.exists())

    def test_legacy_health_worker_is_stopped_before_configuration_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "systemctl"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                            '[ "$1" = show ] && printf "loaded\\n"\nexit 0\n', encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CALLS=str(root / "calls"))
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; adguardhome_doh_pause_health',
                 "bash", str(ROOT / "deploy/lib/common.sh")], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual([
                "show --property=LoadState --value adguardhome-doh-health.timer", "stop adguardhome-doh-health.timer",
                "show --property=LoadState --value adguardhome-doh-health.service", "stop adguardhome-doh-health.service",
            ], (root / "calls").read_text(encoding="utf-8").splitlines())

    def test_activating_health_service_and_queued_job_are_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "systemctl"
            fake.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'case "$*" in *health.timer) echo not-found;; '
                '"show --property=LoadState --value adguardhome-doh-health.service") echo loaded;; '
                '"is-active --quiet adguardhome-doh-health.service") exit 3;; '
                '"stop adguardhome-doh-health.service") rm -f "$QUEUED";; esac\nexit 0\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            queued = root / "queued"
            queued.touch()
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       CALLS=str(root / "calls"), QUEUED=str(queued))
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; adguardhome_doh_pause_health',
                 "bash", str(ROOT / "deploy/lib/common.sh")], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(queued.exists())
            self.assertIn("stop adguardhome-doh-health.service", (root / "calls").read_text(encoding="utf-8"))

    def test_restoration_keeps_existing_nginx_and_stops_new_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "systemctl").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'case "$1" in is-active) exit 0;; is-enabled) echo disabled; exit 1;; esac\nexit 0\n',
                encoding="utf-8",
            )
            (root / "nginx").write_text('#!/bin/sh\nexit 0\n', encoding="utf-8")
            (root / "systemctl").chmod(0o755)
            (root / "nginx").chmod(0o755)
            calls = root / "calls"
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CALLS=str(calls))
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; ADGUARDHOME_DOH_NGINX_ACTIVE=active; '
                 'ADGUARDHOME_DOH_AGH_ACTIVE=inactive; ADGUARDHOME_DOH_TIMER_ACTIVE=inactive; '
                 'adguardhome_doh_restore_runtime', "bash", str(ROOT / "deploy/lib/common.sh")],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            commands = calls.read_text(encoding="utf-8").splitlines()
            self.assertIn("stop adguardhome-doh", commands)
            self.assertIn("stop adguardhome-doh-health.timer", commands)
            self.assertIn("reload nginx", commands)
            self.assertNotIn("stop nginx", commands)

    def test_failure_restores_snapshot_and_preserves_unrelated_webroot_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "etc/nginx/nginx.conf"
            config.parent.mkdir(parents=True)
            config.write_text("original nginx configuration\n", encoding="utf-8")
            create = subprocess.run(
                ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                 "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                 "--snapshot-operation", "recovery"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, create.returncode, create.stderr)
            snapshot = create.stdout.strip()
            config.write_text("partial change\n", encoding="utf-8")
            webroot = root / "var/www/adguardhome-doh"
            webroot.mkdir(parents=True)
            owned = webroot / "dns.example.com.mobileconfig"
            owned.write_text("new profile\n", encoding="utf-8")
            foreign = webroot / "foreign.txt"
            foreign.write_text("preserve me\n", encoding="utf-8")
            fake_flock = root / "flock"
            fake_flock.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_flock.chmod(0o755)
            script = (
                'source "$1"; PROJECT_ROOT="$2"; ROOT="$3"; DOMAIN=dns.example.com; '
                'ADGUARDHOME_DOH_SNAPSHOT="$4"; ADGUARDHOME_DOH_MUTATIONS=1; '
                'ADGUARDHOME_DOH_LOCK_HELD=1; ADGUARDHOME_DOH_RUNTIME_TOUCHED=0; '
                'trap adguardhome_doh_install_exit EXIT; exit 7'
            )
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh"),
                 str(ROOT), str(root), snapshot], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertNotIn("automatic restoration failed", result.stderr)
            self.assertEqual("original nginx configuration\n", config.read_text(encoding="utf-8"))
            self.assertFalse(owned.exists())
            self.assertEqual("preserve me\n", foreign.read_text(encoding="utf-8"))

    def test_package_failure_does_not_remove_new_package_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "nginx.conf"
            config.write_text("package configuration\n", encoding="utf-8")
            for name in ("systemctl", "flock"):
                executable = root / name
                executable.write_text('#!/bin/sh\n[ "$1" = is-active ] && exit 3\nexit 0\n', encoding="utf-8")
                executable.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
            script = (
                'source "$1"; ADGUARDHOME_DOH_RUNTIME_TOUCHED=1; '
                'ADGUARDHOME_DOH_LOCK_HELD=1; ADGUARDHOME_DOH_MUTATIONS=0; '
                'trap adguardhome_doh_install_exit EXIT; exit 17'
            )
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh")],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(17, result.returncode, result.stderr)
            self.assertIn("package changes are not reverted", result.stderr)
            self.assertEqual("package configuration\n", config.read_text(encoding="utf-8"))

    def test_adguard_is_stopped_before_restoring_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "opt/AdGuardHome/AdGuardHome.yaml"
            config.parent.mkdir(parents=True)
            config.write_text("original configuration\n", encoding="utf-8")
            create = subprocess.run(
                ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                 "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                 "--snapshot-operation", "recovery"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, create.returncode, create.stderr)
            config.write_text("new configuration\n", encoding="utf-8")
            (root / "systemctl").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'if [ "$1" = show ]; then echo loaded; exit 0; fi\n'
                'if [ "$1" = is-active ]; then [ "$3" = adguardhome-doh ]; exit $?; fi\n'
                'if [ "$1" = is-enabled ]; then echo disabled; exit 1; fi\n'
                'if [ "$1" = stop ] && [ "$2" = adguardhome-doh ]; then '
                'printf "saved by stopping service\\n" > "$CONFIG"; fi\nexit 0\n', encoding="utf-8",
            )
            (root / "flock").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            for name in ("systemctl", "flock"):
                (root / name).chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       CONFIG=str(config), CALLS=str(root / "calls"))
            script = (
                'source "$1"; PROJECT_ROOT="$2"; ROOT="$3"; DOMAIN=dns.example.com; '
                'ADGUARDHOME_DOH_SNAPSHOT="$4"; ADGUARDHOME_DOH_MUTATIONS=1; '
                'ADGUARDHOME_DOH_LOCK_HELD=1; ADGUARDHOME_DOH_RUNTIME_TOUCHED=1; '
                'ADGUARDHOME_DOH_AGH_ACTIVE=active; trap adguardhome_doh_install_exit EXIT; exit 7'
            )
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh"),
                 str(ROOT), str(root), create.stdout.strip()], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertNotIn("automatic restoration failed", result.stderr)
            self.assertEqual("original configuration\n", config.read_text(encoding="utf-8"))
            self.assertIn("start adguardhome-doh", (root / "calls").read_text(encoding="utf-8"))

    def _run_exit_after_failed_restore(self, root, project, snapshot, extra_env=None,
                                       systemctl_script=None, initial_agh_state="active"):
        for name, content in {
            "systemctl": systemctl_script or (
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'if [ "$1" = show ]; then echo loaded; exit 0; fi\n'
                'if [ "$1" = is-active ]; then [ "$3" = adguardhome-doh ]; exit $?; fi\n'
                'exit 0\n'
            ),
            "flock": "#!/bin/sh\nexit 0\n",
        }.items():
            executable = root / name
            executable.write_text(content, encoding="utf-8")
            executable.chmod(0o755)
        env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CALLS=str(root / "calls"))
        env.update(extra_env or {})
        script = (
            'source "$1"; PROJECT_ROOT="$2"; ROOT="$3"; DOMAIN=dns.example.com; '
            'ADGUARDHOME_DOH_SNAPSHOT="$4"; ADGUARDHOME_DOH_MUTATIONS=1; '
            'ADGUARDHOME_DOH_LOCK_HELD=1; ADGUARDHOME_DOH_RUNTIME_TOUCHED=1; '
            'ADGUARDHOME_DOH_AGH_ACTIVE="$5"; trap adguardhome_doh_install_exit EXIT; exit 7'
        )
        return subprocess.run(
            ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh"),
             str(project), str(root), str(snapshot), initial_agh_state], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_double_restore_failure_leaves_adguard_stopped_and_marker_intact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "etc/nginx/nginx.conf"
            config.parent.mkdir(parents=True)
            config.write_text("original configuration\n", encoding="utf-8")
            created = subprocess.run(
                ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                 "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                 "--snapshot-operation", "recovery"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            snapshot = Path(created.stdout.strip())
            config.write_text("activation before restore\n", encoding="utf-8")
            project = root / "fake-project"
            manager = project / "deploy/manage.py"
            manager.parent.mkdir(parents=True)
            manager.write_text(
                'import importlib.util, os, sys\n'
                'from pathlib import Path\n'
                'spec = importlib.util.spec_from_file_location("manager_under_test", os.environ["REAL_MANAGER"])\n'
                'module = importlib.util.module_from_spec(spec)\n'
                'sys.modules[spec.name] = module\n'
                'spec.loader.exec_module(module)\n'
                'def partial_restore(*args, **kwargs):\n'
                '    Path(os.environ["CONFIG"]).write_text("mixed state\\n", encoding="utf-8")\n'
                '    raise OSError("initial restore failed")\n'
                'def failed_emergency_restore(*args, **kwargs):\n'
                '    raise OSError("emergency restore failed")\n'
                'module._restore_backup = partial_restore\n'
                'module._restore_transaction_entries = failed_emergency_restore\n'
                'raise SystemExit(module.main())\n', encoding="utf-8",
            )
            result = self._run_exit_after_failed_restore(
                root, project, snapshot,
                {"REAL_MANAGER": str(ROOT / "deploy/manage.py"), "CONFIG": str(config)},
            )
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertIn("emergency restore failed", result.stderr)
            self.assertIn("AdGuard left stopped", result.stderr)
            calls = (root / "calls").read_text(encoding="utf-8").splitlines()
            self.assertIn("stop adguardhome-doh", calls)
            self.assertNotIn("start adguardhome-doh", calls)
            markers = list((root / "var/backups/adguardhome-doh").glob(".restore-*/transaction.json"))
            self.assertEqual(1, len(markers))
            self.assertEqual("prepared", json.loads(markers[0].read_text(encoding="utf-8"))["state"])
            self.assertEqual("mixed state\n", config.read_text(encoding="utf-8"))
            self.assertTrue(snapshot.is_dir())

    def test_early_restore_refusal_restarts_only_without_pending_transactions(self):
        for unfinished in (False, True):
            with self.subTest(unfinished=unfinished), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                created = subprocess.run(
                    ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                     "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                     "--snapshot-operation", "recovery"], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(0, created.returncode, created.stderr)
                snapshot = Path(created.stdout.strip())
                (snapshot / "manifest.json").write_text("invalid manifest", encoding="utf-8")
                if unfinished:
                    marker = root / "var/backups/adguardhome-doh/.restore-previous/transaction.json"
                    marker.parent.mkdir()
                    marker.write_text(json.dumps({"version": 1, "state": "prepared", "entries": []}),
                                      encoding="utf-8")
                result = self._run_exit_after_failed_restore(root, ROOT, snapshot)
                self.assertEqual(7, result.returncode, result.stderr)
                self.assertIn("automatic restoration failed", result.stderr)
                calls = (root / "calls").read_text(encoding="utf-8").splitlines()
                self.assertIn("stop adguardhome-doh", calls)
                self.assertEqual(not unfinished, "start adguardhome-doh" in calls)
                if unfinished:
                    self.assertIn("AdGuard left stopped", result.stderr)
                    self.assertTrue(marker.is_file())

    def test_activating_adguard_and_queued_start_are_stopped_before_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "etc/nginx/nginx.conf"
            config.parent.mkdir(parents=True)
            config.write_text("original configuration\n", encoding="utf-8")
            created = subprocess.run(
                ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                 "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                 "--snapshot-operation", "recovery"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            config.write_text("changed configuration\n", encoding="utf-8")
            queued = root / "queued"
            queued.touch()
            project = root / "fake-project"
            manager = project / "deploy/manage.py"
            manager.parent.mkdir(parents=True)
            manager.write_text(
                'import os, runpy, sys\nfrom pathlib import Path\n'
                'if Path(os.environ["QUEUED"]).exists():\n'
                '    raise SystemExit("queued AdGuard job was not stopped")\n'
                'runpy.run_path(os.environ["REAL_MANAGER"], run_name="__main__")\n',
                encoding="utf-8",
            )
            systemctl_script = (
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'case "$1" in show) echo loaded;; is-active) exit 3;; '
                'is-enabled) echo disabled; exit 1;; '
                'stop) [ "$2" != adguardhome-doh ] || rm -f "$QUEUED";; esac\nexit 0\n'
            )
            result = self._run_exit_after_failed_restore(
                root, project, Path(created.stdout.strip()),
                {"REAL_MANAGER": str(ROOT / "deploy/manage.py"), "QUEUED": str(queued)},
                systemctl_script=systemctl_script, initial_agh_state="activating",
            )
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertNotIn("automatic restoration failed", result.stderr)
            self.assertFalse(queued.exists())
            self.assertEqual("original configuration\n", config.read_text(encoding="utf-8"))
            calls = (root / "calls").read_text(encoding="utf-8").splitlines()
            self.assertIn("stop adguardhome-doh", calls)
            self.assertIn("start adguardhome-doh", calls)
            self.assertLess(calls.index("stop adguardhome-doh"), calls.index("start adguardhome-doh"))

    def test_failed_adguard_stop_prevents_restore_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            project = root / "fake-project"
            manager = project / "deploy/manage.py"
            manager.parent.mkdir(parents=True)
            manager.write_text(
                'import os\nfrom pathlib import Path\n'
                'Path(os.environ["INVOKED"]).touch()\n', encoding="utf-8",
            )
            invoked = root / "invoked"
            systemctl_script = (
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                'if [ "$1" = show ]; then echo loaded; exit 0; fi\n'
                'if [ "$1" = stop ] && [ "$2" = adguardhome-doh ]; then exit 1; fi\nexit 0\n'
            )
            result = self._run_exit_after_failed_restore(
                root, project, snapshot, {"INVOKED": str(invoked)}, systemctl_script=systemctl_script,
            )
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertIn("failed to stop AdGuard; files were not restored", result.stderr)
            self.assertFalse(invoked.exists())
            calls = (root / "calls").read_text(encoding="utf-8").splitlines()
            self.assertNotIn("start adguardhome-doh", calls)

    def test_early_refusal_returns_previously_activating_adguard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            created = subprocess.run(
                ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                 "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                 "--snapshot-operation", "recovery"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            snapshot = Path(created.stdout.strip())
            (snapshot / "manifest.json").write_text("invalid", encoding="utf-8")
            result = self._run_exit_after_failed_restore(root, ROOT, snapshot, initial_agh_state="activating")
            self.assertEqual(7, result.returncode, result.stderr)
            self.assertIn("automatic restoration failed", result.stderr)
            self.assertIn("start adguardhome-doh", (root / "calls").read_text(encoding="utf-8"))

    def test_new_certbot_lineage_survives_failure_and_existing_profile_is_restored(self):
        for previously_present in (False, True):
            with self.subTest(previously_present=previously_present), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                profile = root / "etc/letsencrypt/renewal/dns.example.com.conf"
                profile.parent.mkdir(parents=True)
                old_profile = "[renewalparams]\nauthenticator = standalone\n"
                if previously_present:
                    profile.write_text(old_profile, encoding="utf-8")
                create = subprocess.run(
                    ["python3", str(ROOT / "deploy/manage.py"), "--create-update-backup",
                     "--root", str(root), "--domain", "dns.example.com", "--target-version", "1.2.3",
                     "--snapshot-operation", "recovery"], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(0, create.returncode, create.stderr)
                issued = ("[renewalparams]\nauthenticator = webroot\n"
                          "deploy_hook = systemctl reload nginx\n")
                profile.write_text(issued, encoding="utf-8")
                live = root / "etc/letsencrypt/live/dns.example.com"
                live.mkdir(parents=True)
                (live / "fullchain.pem").write_text("certificate\n", encoding="utf-8")
                (live / "privkey.pem").write_text("private key\n", encoding="utf-8")
                fake = root / "flock"
                fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                fake.chmod(0o755)
                env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
                script = (
                    'source "$1"; PROJECT_ROOT="$2"; ROOT="$3"; DOMAIN=dns.example.com; '
                    'ADGUARDHOME_DOH_SNAPSHOT="$4"; ADGUARDHOME_DOH_MUTATIONS=1; '
                    'ADGUARDHOME_DOH_NEW_CERTBOT_LINEAGE=1; ADGUARDHOME_DOH_LOCK_HELD=1; '
                    'ADGUARDHOME_DOH_RUNTIME_TOUCHED=0; trap adguardhome_doh_install_exit EXIT; exit 7'
                )
                result = subprocess.run(
                    ["bash", "-c", script, "bash", str(ROOT / "deploy/lib/common.sh"),
                     str(ROOT), str(root), create.stdout.strip()], env=env, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(7, result.returncode, result.stderr)
                self.assertNotIn("automatic restoration failed", result.stderr)
                self.assertEqual(old_profile if previously_present else issued, profile.read_text(encoding="utf-8"))
                if not previously_present:
                    retry = self.run_common(
                        'adguardhome_doh_migrate_certbot_renewal "$1" dns.example.com /var/www/adguardhome-doh "$2"',
                        str(root), str(ROOT),
                    )
                    self.assertEqual(0, retry.returncode, retry.stderr)
                    self.assertTrue((root / "etc/letsencrypt/renewal-hooks/deploy/adguardhome-doh-reload").is_file())

    def test_shared_renewal_adapter_preserves_lineage_and_existing_mtproxy_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "etc/letsencrypt/renewal/dns.example.com.conf"
            profile.parent.mkdir(parents=True)
            profile.write_text("[renewalparams]\nauthenticator = webroot\n", encoding="utf-8")
            hooks = root / "etc/letsencrypt/renewal-hooks/deploy"
            hooks.mkdir(parents=True)
            existing = hooks / "mtproxyl-selfmask.sh"
            existing.write_text("#!/bin/sh\nsystemctl reload mtproxyl-pq-nginx\n", encoding="utf-8")
            before_profile, before_existing = profile.read_bytes(), existing.read_bytes()
            call = ('adguardhome_doh_migrate_certbot_renewal "$1" dns.example.com '
                    '/var/www/mtproxyl-selfmask "$2" "$3"')
            result = self.run_common(call, str(root), str(ROOT), "mtproxyl")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(before_profile, profile.read_bytes())
            self.assertEqual(before_existing, existing.read_bytes())
            own = hooks / "adguardhome-doh-reload"
            own_before = own.read_text(encoding="utf-8")
            self.assertIn('/etc/letsencrypt/live/dns.example.com', own_before)
            self.assertIn('systemctl reload adguardhome-doh-nginx', own_before)
            self.assertNotIn('systemctl reload nginx\n', own_before)
            rejected = self.run_common(call, str(root), str(ROOT), "invalid")
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual(own_before, own.read_text(encoding="utf-8"))
            own.write_text("#!/bin/sh\n# foreign hook\n", encoding="utf-8")
            rejected = self.run_common(call, str(root), str(ROOT), "mtproxyl")
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual("#!/bin/sh\n# foreign hook\n", own.read_text(encoding="utf-8"))
            self.assertEqual(before_profile, profile.read_bytes())
            self.assertEqual(before_existing, existing.read_bytes())

    def test_preflight_rejects_symlink_that_would_modify_an_unbacked_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os_release = root / "etc/os-release"
            os_release.parent.mkdir(parents=True)
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")
            target = root / "user-owned.conf"
            target.write_text("preserve\n", encoding="utf-8")
            nginx = root / "etc/nginx/nginx.conf"
            nginx.parent.mkdir(parents=True)
            nginx.symlink_to(target)
            result = self.run_common(
                'adguardhome_doh_preflight "$1" dns.example.com 203.0.113.10 0 0', directory
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("managed file is a symlink", result.stderr)
            self.assertEqual("preserve\n", target.read_text(encoding="utf-8"))

    def test_directory_permissions_are_restored_without_following_replaced_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "webroot"
            path.mkdir(mode=0o755)
            script = ('adguardhome_doh_capture_directory_permissions "$1"; chmod 700 "$1"; '
                      'adguardhome_doh_restore_directory_permissions')
            result = self.run_common(script, str(path))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(0o755, path.stat().st_mode & 0o777)
            target = Path(directory) / "target"
            target.mkdir(mode=0o700)
            script = ('adguardhome_doh_capture_directory_permissions "$1"; rmdir "$1"; '
                      'ln -s "$2" "$1"; adguardhome_doh_restore_directory_permissions')
            result = self.run_common(script, str(path), str(target))
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(0o700, target.stat().st_mode & 0o777)

    def test_renderer_preflight_lock_and_health_start_order(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertLess(source.index("adguardhome_doh_render_dry_run\n"), source.index("apt-get"))
        self.assertLess(source.index("adguardhome_doh_acquire_operation_lock ||"), source.index("adguardhome_doh_acquire_health_lock ||"))
        self.assertLess(source.index("adguardhome_doh_pause_health ||"), source.index("--create-update-backup"))
        self.assertLess(source.index("adguardhome_doh_acquire_health_lock ||"), source.index("--create-update-backup"))
        self.assertLess(source.index("--create-update-backup"), source.index("apt-get"))
        self.assertLess(source.rindex("systemctl reload nginx"), source.index("adguardhome_doh_release_health_lock\n"))
        self.assertLess(source.index("adguardhome_doh_release_health_lock\n"), source.index("systemctl start adguardhome-doh-health.service"))
        self.assertLess(source.index("systemctl start adguardhome-doh-health.service"), source.index("--finalize-update-backup"))
        self.assertLess(source.index("--finalize-update-backup"), source.rindex("adguardhome_doh_release_operation_lock"))
        self.assertIn("ADGUARDHOME_DOH_LOCK=/run/lock/adguardhome-doh-health.lock", source)

    def test_punycode_hostname_and_invalid_symbols_use_renderer_rules(self):
        base = ("--public-ip", "203.0.113.10", "--email", "admin@example.com", "--dry-run")
        valid = self.run_install(*base, "--domain", "DNS.XN--P1AI")
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertIn("https://dns.xn--p1ai/", valid.stdout)
        for hostname in ("dns_.example.com", "dns.рф", "dns.example.1"):
            invalid = self.run_install(*base, "--domain", hostname)
            self.assertNotEqual(0, invalid.returncode, hostname)

if __name__ == "__main__":
    unittest.main()
