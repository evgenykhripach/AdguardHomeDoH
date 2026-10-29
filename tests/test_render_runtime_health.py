import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "deploy/lib/render_runtime.py"
IP = "203.0.113.10"


class RenderRuntimeHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        catalog = self.root / "catalog"
        catalog.mkdir()
        (catalog / "services.csv").write_text(
            "id,name_ru,category,default_enabled,risk_level\n"
            "good,Good,Test,true,standard\n"
            "bad,Bad,Test,true,standard\n"
            "unknown,Unknown,Test,true,standard\n"
            "invalid,Invalid,Test,true,standard\n"
            "removed,Removed,Test,true,standard\n", encoding="utf-8")
        (catalog / "domains.csv").write_text(
            "domain,kind\nhealthy.example,fqdn\nunhealthy.example,fqdn\n"
            "unknown.example,suffix\ndisabled.example,fqdn\nabsent.example,fqdn\n"
            "shared.example,suffix\ngood-shared.example,fqdn\n"
            "invalid.example,fqdn\ninvalid-absent.example,fqdn\n"
            "removed.example,suffix\nnew-user.example,fqdn\nnew-disabled.example,fqdn\n",
            encoding="utf-8")
        (catalog / "service-domains.csv").write_text(
            "service_id,domain\ngood,healthy.example\ngood,good-shared.example\n"
            "bad,unhealthy.example\nbad,shared.example\n"
            "unknown,unknown.example\nunknown,disabled.example\nunknown,absent.example\n"
            "unknown,shared.example\nunknown,good-shared.example\n"
            "unknown,new-user.example\nunknown,new-disabled.example\n"
            "invalid,invalid.example\ninvalid,invalid-absent.example\n"
            "removed,removed.example\nremoved,shared.example\n", encoding="utf-8")
        (catalog / "service-probes.csv").write_text("service_id,hostname\n", encoding="utf-8")
        self.previous_policy = self.root / "old-policy.json"
        self.previous_policy.write_text(json.dumps({"domains": [
            {"domain": name, "kind": kind} for name, kind in (
                ("healthy.example", "fqdn"), ("unhealthy.example", "fqdn"),
                ("unknown.example", "suffix"), ("disabled.example", "fqdn"),
                ("absent.example", "fqdn"), ("shared.example", "suffix"),
                ("good-shared.example", "fqdn"), ("invalid.example", "fqdn"),
                ("invalid-absent.example", "fqdn"), ("removed.example", "suffix"),
            )]}), encoding="utf-8")
        self.config = self.root / "AdGuardHome.yaml"
        self.records = [
            {"domain": "healthy.example", "answer": IP, "enabled": True},
            {"domain": "unhealthy.example", "answer": IP, "enabled": True},
            {"domain": "unknown.example", "answer": IP, "enabled": True,
             "client_id": "preserve", "extra": {"one": ["two"]}},
            {"domain": "*.unknown.example", "answer": IP, "enabled": False},
            {"domain": "disabled.example", "answer": IP, "enabled": False},
            {"domain": "shared.example", "answer": IP, "enabled": True},
            {"domain": "*.shared.example", "answer": IP, "enabled": True},
            {"domain": "good-shared.example", "answer": IP, "enabled": True,
             "client_id": "shared-metadata"},
            {"domain": "invalid.example", "answer": IP, "enabled": True},
            {"domain": "removed.example", "answer": IP, "enabled": True},
            {"domain": "*.removed.example", "answer": IP, "enabled": True},
            {"domain": "new-user.example", "answer": IP, "enabled": True,
             "note": "user-owned"},
            {"domain": "new-disabled.example", "answer": IP, "enabled": False,
             "note": "user-owned-disabled"},
            {"domain": "unrelated.example", "answer": IP, "enabled": True},
        ]
        self.write_config(self.records)
        self.health = self.root / "health.json"

    def write_config(self, records, enabled=True):
        self.config.write_text(yaml.safe_dump({
            "users": [{"name": "admin", "password": "hash"}],
            "filtering": {"rewrites_enabled": enabled, "rewrites": records},
        }), encoding="utf-8")

    def render(self, *, selected="good,bad,unknown,invalid", existing=True,
               old_policy=True, health_arg=True, extra=(), output="stage"):
        command = [sys.executable, str(RENDERER), "--config-dir", str(self.root / "catalog"),
                   "--services", selected, "--public-ip", IP, "--doh-host", "dns.example.com",
                   "--doh-token", "a" * 48, "--password-hash", "hash",
                   "--certificate-root", "/cert", "--webroot", "/web",
                   "--output", str(self.root / output)]
        if existing:
            command.extend(["--existing-config", str(self.config)])
        if old_policy:
            command.extend(["--existing-policy", str(self.previous_policy)])
        if health_arg:
            command.extend(["--health-state", str(self.health)])
        command.extend(extra)
        return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def rules(self, output="stage"):
        value = yaml.safe_load((self.root / output / "AdGuardHome.yaml").read_text(encoding="utf-8"))
        return value["filtering"]["rewrites"]

    def test_partial_state_preserves_unknown_and_shared_rules_without_reenabling(self):
        self.health.write_text(json.dumps({
            "good": {"healthy": True}, "bad": {"healthy": False},
            "unknown": {"healthy": None}, "invalid": {"healthy": "false"},
            "removed": {"healthy": True},
        }), encoding="utf-8")
        result = self.render(extra=("--healthy-services", "good,invalid,removed"))
        self.assertEqual(0, result.returncode, result.stderr)
        rules = self.rules()
        by_key = {(item["domain"], item["answer"]): item for item in rules}
        self.assertEqual(len(rules), len(by_key))
        for name in ("unknown.example", "shared.example", "*.shared.example",
                     "good-shared.example", "invalid.example", "new-user.example",
                     "new-disabled.example", "unrelated.example"):
            self.assertEqual(next(item for item in self.records if item["domain"] == name),
                             by_key[(name, IP)])
        for name in ("*.unknown.example", "disabled.example", "absent.example",
                     "invalid-absent.example", "removed.example", "*.removed.example",
                     "unhealthy.example"):
            self.assertNotIn((name, IP), by_key)
        self.assertTrue(by_key[("healthy.example", IP)]["enabled"])
        self.assertFalse(by_key[("new-disabled.example", IP)]["enabled"])

    def test_absent_corrupt_and_non_object_state_preserve_only_existing_enabled_rules(self):
        for index, payload in enumerate((None, "{", "null", "[]")):
            with self.subTest(payload=payload):
                if payload is not None:
                    self.health.write_text(payload, encoding="utf-8")
                result = self.render(output="stage%d" % index,
                                     extra=("--healthy-services", "good,bad,unknown,invalid"))
                self.assertEqual(0, result.returncode, result.stderr)
                rules = self.rules("stage%d" % index)
                by_key = {(item["domain"], item["answer"]): item for item in rules}
                self.assertIn(("unknown.example", IP), by_key)
                self.assertIn(("shared.example", IP), by_key)
                self.assertNotIn(("*.unknown.example", IP), by_key)
                self.assertNotIn(("disabled.example", IP), by_key)
                self.assertNotIn(("absent.example", IP), by_key)
                self.assertNotIn(("removed.example", IP), by_key)
                self.assertFalse(by_key[("new-disabled.example", IP)]["enabled"])

    def test_invalid_state_entry_never_seeds_missing_rule(self):
        for index, value in enumerate((None, {}, {"healthy": "true"}, {"healthy": 1},
                                       {"healthy": True, "successes": "bad"},
                                       {"healthy": True, "failures": -1},
                                       {"healthy": True, "probe_uncertain": "yes"})):
            with self.subTest(value=value):
                self.health.write_text(json.dumps({"invalid": value}), encoding="utf-8")
                result = self.render(selected="invalid", output="stage%d" % index,
                                     extra=("--healthy-services", "invalid"))
                self.assertEqual(0, result.returncode, result.stderr)
                by_key = {(item["domain"], item["answer"]): item
                          for item in self.rules("stage%d" % index)}
                self.assertIn(("invalid.example", IP), by_key)
                self.assertNotIn(("invalid-absent.example", IP), by_key)

    def test_existing_config_requires_valid_old_policy_with_health_state(self):
        original = self.config.read_bytes()
        result = self.render(old_policy=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("existing health policy", result.stderr)
        self.assertFalse((self.root / "stage").exists())
        for payload in ("{", "null", '{"domains":"bad"}',
                        '{"domains":[{"domain":"bad host","kind":"fqdn"}]}',
                        '{"domains":[],"services":"bad"}',
                        '{"domains":[],"domains":[]}'):
            with self.subTest(payload=payload):
                self.previous_policy.write_text(payload, encoding="utf-8")
                result = self.render()
                self.assertNotEqual(0, result.returncode)
                self.assertIn("existing health policy", result.stderr)
                self.assertFalse((self.root / "stage").exists())
                self.assertEqual(original, self.config.read_bytes())

    def test_global_disable_never_activates_unknown_managed_rule(self):
        records = [item for item in self.records if item["domain"] not in
                   ("new-user.example", "new-disabled.example")]
        self.write_config(records, enabled=False)
        result = self.render(selected="unknown")
        self.assertEqual(0, result.returncode, result.stderr)
        by_key = {(item["domain"], item["answer"]): item for item in self.rules()}
        self.assertNotIn(("unknown.example", IP), by_key)
        self.assertNotIn(("shared.example", IP), by_key)

    def test_global_disable_with_unknown_user_rule_fails_closed(self):
        self.write_config(self.records, enabled=False)
        original = self.config.read_bytes()
        result = self.render(selected="unknown")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("disabled", result.stderr.lower())
        self.assertFalse((self.root / "stage").exists())
        self.assertEqual(original, self.config.read_bytes())

    def test_changed_ip_with_unknown_active_managed_rule_fails_closed(self):
        old_ip = "203.0.113.9"
        records = [{**item, "answer": old_ip} if item["domain"] == "unknown.example" else item
                   for item in self.records]
        self.write_config(records)
        original = self.config.read_bytes()
        result = self.render(selected="unknown", extra=("--existing-public-ip", old_ip))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public ip", result.stderr.lower())
        self.assertFalse((self.root / "stage").exists())
        self.assertEqual(original, self.config.read_bytes())

    def test_changed_ip_does_not_enable_disabled_unknown_rule(self):
        old_ip = "203.0.113.9"
        self.write_config([{"domain": "unknown.example", "answer": old_ip, "enabled": False}])
        result = self.render(selected="unknown", extra=("--existing-public-ip", old_ip))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.rules())

    def test_stale_healthy_service_is_not_used_for_selected_catalog(self):
        self.health.write_text(json.dumps({"good": {"healthy": True},
                                           "obsolete": {"healthy": True}}), encoding="utf-8")
        result = self.render(selected="good")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(("healthy.example", IP),
                      {(item["domain"], item["answer"]) for item in self.rules()})

    def test_unknown_active_rule_without_enabled_field_preserves_metadata(self):
        records = [dict(item) for item in self.records]
        del records[2]["enabled"]
        self.write_config(records)
        result = self.render(selected="unknown")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(records[2], next(item for item in self.rules()
                                          if item["domain"] == "unknown.example"))

    def test_ambiguous_duplicate_unknown_rewrites_fail_closed(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.write_config(self.records + [{**self.records[2], "enabled": enabled}])
                result = self.render(selected="unknown")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("duplicate", result.stderr.lower())
                self.assertFalse((self.root / "stage").exists())

    def test_installed_renderer_loads_sibling_healthcheck(self):
        installed = self.root / "installed" / "libexec"
        installed.mkdir(parents=True)
        for source, name in ((RENDERER, "render_runtime.py"),
                             (ROOT / "tools/render_config.py", "render_config.py"),
                             (ROOT / "deploy/templates/healthcheck.py", "healthcheck.py")):
            shutil.copy2(source, installed / name)
        command = [sys.executable, str(installed / "render_runtime.py"), "--policy", str(self.root / "policy.csv"),
                   "--public-ip", IP, "--doh-host", "dns.example.com", "--doh-token", "a" * 48,
                   "--password-hash", "hash", "--certificate-root", "/cert", "--webroot", "/web",
                   "--output", str(self.root / "installed-stage"), "--existing-config", str(self.config),
                   "--existing-policy", str(self.previous_policy), "--health-state", str(self.health)]
        (self.root / "policy.csv").write_text("domain,kind,probe\nunknown.example,suffix,\n", encoding="utf-8")
        result = subprocess.run(command, cwd=installed, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(self.records[2], next(item for item in self.rules("installed-stage")
                                               if item["domain"] == "unknown.example"))

    def test_first_install_and_old_cli_remain_compatible(self):
        result = self.render(existing=False, old_policy=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.rules())
        result = self.render(health_arg=False, old_policy=False, output="legacy",
                             selected="good", extra=("--healthy-services", "good"))
        self.assertEqual(0, result.returncode, result.stderr)
        names = {item["domain"] for item in self.rules("legacy")}
        self.assertIn("healthy.example", names)

    def test_compatibility_policy_uses_domain_health_keys(self):
        policy = self.root / "custom.csv"
        policy.write_text("domain,kind,probe\nunknown.example,suffix,\ndisabled.example,fqdn,\n"
                          "absent.example,fqdn,\n", encoding="utf-8")
        self.health.write_text(json.dumps({"unknown.example": {"healthy": None},
                                           "disabled.example": {"healthy": False}}), encoding="utf-8")
        old_rows = json.loads(self.previous_policy.read_text(encoding="utf-8"))["domains"]
        self.previous_policy.write_text(json.dumps(old_rows), encoding="utf-8")
        command = [sys.executable, str(RENDERER), "--policy", str(policy), "--public-ip", IP,
                   "--doh-host", "dns.example.com", "--doh-token", "a" * 48,
                   "--password-hash", "hash", "--certificate-root", "/cert", "--webroot", "/web",
                   "--output", str(self.root / "compat"), "--existing-config", str(self.config),
                   "--existing-policy", str(self.previous_policy), "--health-state", str(self.health),
                   "--healthy-services", "unknown.example"]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(0, result.returncode, result.stderr)
        by_key = {(item["domain"], item["answer"]): item for item in self.rules("compat")}
        self.assertEqual(self.records[2], by_key[("unknown.example", IP)])
        for name in ("*.unknown.example", "disabled.example", "absent.example"):
            self.assertNotIn((name, IP), by_key)


if __name__ == "__main__":
    unittest.main()
