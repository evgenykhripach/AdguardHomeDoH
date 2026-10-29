import base64
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HEALTH_PATH = ROOT / "deploy" / "templates" / "healthcheck.py"


def load_healthcheck():
    spec = importlib.util.spec_from_file_location("neutral_healthcheck", HEALTH_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RewriteApi:
    """In-memory AdGuard rewrite API for exercising the full health cycle."""

    def __init__(self, records):
        self.records = {(item["domain"], item["answer"]): dict(item) for item in records}
        self.calls = []

    def __call__(self, method, path, cookie, body=None):
        self.calls.append((method, path, body))
        if path == "/control/rewrite/list":
            return [dict(item) for item in self.records.values()]
        if path == "/control/rewrite/add":
            self.records[(body["domain"], body["answer"])] = dict(body)
        elif path == "/control/rewrite/update":
            target = body["target"]
            self.records[(target["domain"], target["answer"])].update(body["update"])
        elif path == "/control/rewrite/delete":
            del self.records[(body["domain"], body["answer"])]


class HealthcheckTests(unittest.TestCase):
    def test_service_health_requires_all_probes_and_limits_concurrency(self):
        health = load_healthcheck()
        policy = {
            "services": {
                "chatgpt": ["chatgpt.com", "files.oaiusercontent.com"],
                "claude": ["claude.ai"],
            },
            "domains": [],
        }
        active = 0
        peak = 0
        guard = threading.Lock()

        def probe(host):
            nonlocal active, peak
            with guard:
                active += 1
                peak = max(peak, active)
            time.sleep(0.01)
            with guard:
                active -= 1
            return host != "files.oaiusercontent.com"

        results = health.probe_services(policy, probe_func=probe, max_workers=2)
        self.assertEqual({"chatgpt": False, "claude": True}, results)
        self.assertLessEqual(peak, 2)

    def test_catalog_service_probes_do_not_expand_to_all_owned_domains(self):
        health = load_healthcheck()
        policy = {
            "services": {"chatgpt": ["chatgpt.com", "files.oaiusercontent.com"]},
            "domains": [
                {"domain": "chat.com", "services": ["chatgpt"]},
                {"domain": "chatgpt.livekit.cloud", "services": ["chatgpt"]},
            ],
        }
        self.assertEqual(
            ("chatgpt.com", "files.oaiusercontent.com"),
            health.service_probe_map(policy)["chatgpt"],
        )

    def test_success_and_failure_thresholds_transition_service_state(self):
        health = load_healthcheck()
        state = {}
        for _ in range(2):
            state, transitions = health.update_health_state(
                state, {"chatgpt": True}, success_threshold=3, failure_threshold=2
            )
            self.assertEqual([], transitions)
        state, transitions = health.update_health_state(
            state, {"chatgpt": True}, success_threshold=3, failure_threshold=2
        )
        self.assertEqual(["chatgpt"], transitions)
        self.assertTrue(state["chatgpt"]["healthy"])
        state, transitions = health.update_health_state(
            state, {"chatgpt": False}, success_threshold=3, failure_threshold=2
        )
        self.assertEqual([], transitions)
        state, transitions = health.update_health_state(
            state, {"chatgpt": False}, success_threshold=3, failure_threshold=2
        )
        self.assertEqual(["chatgpt"], transitions)
        self.assertFalse(state["chatgpt"]["healthy"])

    def test_first_successful_probe_does_not_raise_uncertain_warning(self):
        health = load_healthcheck()
        state, _ = health.update_health_state({}, {"example": True}, success_threshold=3)
        self.assertIsNone(state["example"]["healthy"])
        self.assertFalse(state["example"].get("probe_uncertain", False))
        state, _ = health.update_health_state(state, {"example": False}, success_threshold=3)
        self.assertTrue(state["example"]["probe_uncertain"])
        for _ in range(2):
            state, _ = health.update_health_state(state, {"example": True}, success_threshold=3)
            self.assertIsNone(state["example"]["healthy"])
            self.assertTrue(state["example"]["probe_uncertain"])
        state, _ = health.update_health_state(state, {"example": True}, success_threshold=3)
        self.assertIs(state["example"]["healthy"], True)
        self.assertFalse(state["example"].get("probe_uncertain", False))

    def test_non_overlapping_lock_rejects_second_health_run(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "health.lock"
            with health.health_lock(lock_path):
                with self.assertRaises(health.LockBusy):
                    with health.health_lock(lock_path):
                        pass

    def test_run_acquires_lock_before_reading_policy_or_state(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "health.lock"
            with health.health_lock(lock_path), mock.patch.object(
                Path, "read_text", side_effect=AssertionError("read before lock")
            ):
                with self.assertRaises(health.LockBusy):
                    health.run_once(
                        policy_path=root / "policy.json", state_path=root / "state.json",
                        lock_path=lock_path, doh_probe_func=lambda: None,
                    )

    def test_lock_is_held_until_reconcile_finishes(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = {"services": {"example": ["example.com"]}, "domains": []}
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            entered_probe, release_probe = threading.Event(), threading.Event()
            entered_reconcile, release_reconcile = threading.Event(), threading.Event()
            errors = []

            def probe(host):
                entered_probe.set()
                if not release_probe.wait(5):
                    raise AssertionError("probe release timed out")
                return True

            def reconcile(*args):
                entered_reconcile.set()
                if not release_reconcile.wait(5):
                    raise AssertionError("reconcile release timed out")
                return 0, 0

            def run():
                try:
                    health.run_once(
                        policy_path=root / "policy.json", state_path=root / "state.json",
                        lock_path=root / "health.lock", probe_func=probe,
                        reconcile_func=reconcile, doh_probe_func=lambda: None,
                    )
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(entered_probe.wait(5))
                with self.assertRaises(health.LockBusy):
                    with health.health_lock(root / "health.lock"):
                        pass
                release_probe.set()
                self.assertTrue(entered_reconcile.wait(5))
                with self.assertRaises(health.LockBusy):
                    with health.health_lock(root / "health.lock"):
                        pass
            finally:
                release_probe.set()
                release_reconcile.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            with health.health_lock(root / "health.lock"):
                pass

    def test_policy_update_lock_prevents_stale_reconcile(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path, state_path, lock_path = root / "policy.json", root / "state.json", root / "health.lock"
            old = {"services": {"old": ["old.example.com"]},
                   "domains": [{"domain": "old.example.com", "kind": "fqdn", "services": ["old"]}]}
            new = {"services": {"new": ["new.example.com"]},
                   "domains": [{"domain": "new.example.com", "kind": "fqdn", "services": ["new"]}]}
            policy_path.write_text(json.dumps(old), encoding="utf-8")
            state_path.write_text(json.dumps({"old": {"healthy": True}}), encoding="utf-8")
            probed, reconciled = [], []
            common = dict(policy_path=policy_path, state_path=state_path, lock_path=lock_path,
                          probe_func=lambda host: probed.append(host) or True,
                          reconcile_func=lambda policy, state, ip: (reconciled.append((policy, state)) or (0, 0)),
                          doh_probe_func=lambda: None)
            with health.health_lock(lock_path):
                policy_path.write_text(json.dumps(new), encoding="utf-8")
                state_path.write_text(json.dumps({"new": {"healthy": True}}), encoding="utf-8")
                with self.assertRaises(health.LockBusy):
                    health.run_once(**common)
                self.assertEqual([], probed)
                self.assertEqual([], reconciled)
            health.run_once(**common)
        self.assertEqual(["new.example.com"], probed)
        self.assertEqual(new, reconciled[0][0])
        self.assertEqual({"new"}, set(reconciled[0][1]))
        self.assertTrue(reconciled[0][1]["new"]["healthy"])

    def test_compatibility_policy_probes_each_domain_and_activates_rewrites(self):
        health = load_healthcheck()
        policy = {
            "enabled_services": [], "services": {},
            "domains": [
                {"domain": "example.com", "kind": "suffix", "probe": "www.example.com", "services": []},
                {"domain": "example.net", "kind": "fqdn", "probe": "example.net", "services": []},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            probed, records = [], {}

            def fake_api(method, path, cookie, body=None):
                if method == "GET":
                    return list(records.values())
                if path == "/control/rewrite/add":
                    records[(body["domain"], body["answer"])] = body

            def probe(host):
                probed.append(host)
                return True

            with mock.patch.object(health, "login", return_value="sid=x"), \
                    mock.patch.object(health, "api", side_effect=fake_api), \
                    mock.patch.object(health, "PUBLIC_IP", "203.0.113.10"):
                for _ in range(3):
                    summary = health.run_once(
                        policy_path=root / "policy.json", state_path=root / "state.json",
                        lock_path=root / "health.lock", probe_func=probe,
                        doh_probe_func=lambda: None,
                    )
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        self.assertEqual({"www.example.com", "example.net"}, set(probed))
        self.assertEqual({"example.com", "example.net"}, set(state))
        self.assertEqual(3, summary["active_rules"])
        self.assertEqual({("example.com", "203.0.113.10"),
                          ("*.example.com", "203.0.113.10"),
                          ("example.net", "203.0.113.10")}, set(records))

    def test_legacy_domain_policy_defaults_empty_probe_to_domain(self):
        health = load_healthcheck()
        policy = [{"domain": "example.xn--p1ai", "kind": "fqdn", "probe": ""}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            loaded = health.load_policy(path)
        self.assertEqual({"example.xn--p1ai": ("example.xn--p1ai",)},
                         health.service_probe_map(loaded))

    def test_rendered_csv_policy_runs_the_domain_gate(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "rendered"
            subprocess.run([
                sys.executable, str(ROOT / "deploy/lib/render_runtime.py"),
                "--policy", str(ROOT / "config/policy.csv"),
                "--public-ip", "203.0.113.10", "--doh-host", "dns.example.com",
                "--doh-token", "a" * 48, "--password-hash", "test-hash",
                "--certificate-root", "/tmp/cert", "--webroot", "/tmp/webroot",
                "--output", str(output),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            policy = health.load_policy(output / "health-policy.json")
            probes = health.service_probe_map(policy)
            self.assertTrue(policy["domains"])
            self.assertEqual({}, policy["services"])
            self.assertEqual(len(policy["domains"]), len(probes))
            for _ in range(health.SUCCESS_THRESHOLD):
                summary = health.run_once(
                    policy_path=output / "health-policy.json", state_path=root / "state.json",
                    lock_path=root / "health.lock", probe_func=lambda host: True,
                    reconcile_func=lambda value, state, ip: (0, len(health.desired_rules(value, state, ip))),
                    doh_probe_func=lambda: None,
                )
            self.assertEqual(len(probes), summary["healthy_services"])
            self.assertEqual(sum(1 + (row["kind"] == "suffix") for row in policy["domains"]),
                             summary["active_rules"])

    def test_invalid_or_unreadable_policy_leaves_state_and_rules_untouched(self):
        health = load_healthcheck()
        invalid_policies = [
            "{", "null", "{}", '{"services": {}, "domains": "not-a-list"}',
            '{"services": {}, "domains": [{}]}',
            '{"services": {"example": [1]}, "domains": []}',
            '{"services": {}, "domains": [{"domain": "example.com", "kind": "wrong"}]}',
            '{"services": {}, "domains": [{"domain": "example.com", "kind": "fqdn", "probe": 42}]}',
            '{"services": {}, "domains": [{"domain": "example.com", "kind": "fqdn", "services": ["missing"]}]}',
            '{"services": {"example": ["example.com"]}, "domains": [{"domain": "example.com", "kind": "fqdn", "services": []}]}',
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path, state_path = root / "policy.json", root / "state.json"
            original = b'{"example":{"healthy":true,"successes":3,"failures":0}}\n'
            state_path.write_bytes(original)
            reconcile = mock.Mock(return_value=(0, 0))
            common = dict(policy_path=policy_path, state_path=state_path,
                          lock_path=root / "health.lock", probe_func=mock.Mock(),
                          reconcile_func=reconcile, doh_probe_func=lambda: None)
            for payload in [None] + invalid_policies:
                with self.subTest(payload=payload):
                    if payload is not None:
                        policy_path.write_text(payload, encoding="utf-8")
                    with self.assertRaises((OSError, ValueError)):
                        health.run_once(**common)
                    self.assertEqual(original, state_path.read_bytes())
                    common["probe_func"].assert_not_called()
                    reconcile.assert_not_called()
            with mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    health.run_once(**common)
            self.assertEqual(original, state_path.read_bytes())
            reconcile.assert_not_called()

    def test_desired_rules_use_enabled_healthy_service_union(self):
        health = load_healthcheck()
        policy = {
            "services": {"chatgpt": ["chatgpt.com"], "google_shared": ["google.com"]},
            "domains": [
                {"domain": "shared.example", "kind": "suffix", "services": ["chatgpt", "google_shared"]},
                {"domain": "chat.example", "kind": "fqdn", "services": ["chatgpt"]},
            ],
        }
        rules = health.desired_rules(policy, {"chatgpt": {"healthy": True}, "google_shared": {"healthy": False}}, "203.0.113.10")
        self.assertEqual(
            {
                ("chat.example", "203.0.113.10"),
                ("shared.example", "203.0.113.10"),
                ("*.shared.example", "203.0.113.10"),
            },
            set(rules),
        )

    def test_reconcile_removes_legacy_loopback_rules(self):
        health = load_healthcheck()
        policy = {
            "services": {"chatgpt": ["chatgpt.com"]},
            "domains": [
                {"domain": "chatgpt.com", "kind": "suffix", "services": ["chatgpt"]}
            ],
        }
        calls = []

        def fake_api(method, path, cookie, body=None):
            calls.append((method, path, body))
            if method == "GET":
                return [
                    {"domain": "chatgpt.com", "answer": "127.0.0.1", "enabled": False},
                    {"domain": "*.chatgpt.com", "answer": "127.0.0.1", "enabled": False},
                    {"domain": "chatgpt.com", "answer": "203.0.113.10", "enabled": True},
                ]
            return None

        with mock.patch.object(health, "login", return_value="sid=x"), mock.patch.object(
            health, "api", side_effect=fake_api
        ):
            changes, active = health.reconcile(policy, {"chatgpt": {"healthy": True}}, "203.0.113.10")

        self.assertEqual(2, active)
        self.assertEqual(3, changes)
        deleted = {(body["domain"], body["answer"]) for method, path, body in calls
                   if method == "POST" and path == "/control/rewrite/delete"}
        self.assertEqual(
            {("chatgpt.com", "127.0.0.1"), ("*.chatgpt.com", "127.0.0.1")},
            deleted,
        )

    def test_a_total_probe_sweep_keeps_the_previous_state(self):
        """A total probe failure preserves the last known service states."""

        health = load_healthcheck()
        policy = {
            "services": {"chatgpt": ["chatgpt.com"], "claude": ["claude.ai"]},
            "domains": [
                {"domain": "chatgpt.com", "kind": "suffix", "services": ["chatgpt"]},
                {"domain": "claude.ai", "kind": "suffix", "services": ["claude"]},
            ],
        }
        self.assertTrue(health.is_global_failure({"chatgpt": False, "claude": False}))
        self.assertFalse(health.is_global_failure({"chatgpt": False, "claude": True}))
        # A lone remote failure cannot be distinguished from a local fault.
        self.assertTrue(health.is_global_failure({"chatgpt": False}))
        self.assertFalse(health.is_global_failure({}))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "health-policy.json"
            state_path = root / "health-state.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            state_path.write_text(json.dumps({
                "chatgpt": {"healthy": True, "successes": 9, "failures": 0},
                "claude": {"healthy": True, "successes": 9, "failures": 0},
            }), encoding="utf-8")
            reconciled = {}

            def fake_reconcile(policy_value, state_value, public_ip):
                reconciled.update(state_value)
                return 0, len(health.desired_rules(policy_value, state_value, public_ip))

            summary = health.run_once(
                policy_path=policy_path, state_path=state_path,
                lock_path=root / "health.lock",
                probe_func=lambda host: False, reconcile_func=fake_reconcile,
                doh_probe_func=lambda: None,
            )

        self.assertEqual(1, summary["global_failure"])
        self.assertEqual(2, summary["healthy_services"])
        self.assertEqual(0, summary["transitions"])
        # Rewrites stay in place; withdrawing them would send clients to the
        # very addresses this server exists to reroute, for a cached TTL.
        self.assertEqual(4, summary["active_rules"])
        self.assertTrue(all(item["healthy"] for item in reconciled.values()))
        self.assertTrue(all(item["probe_uncertain"] for item in reconciled.values()))

    def test_single_service_total_failure_preserves_rewrites_across_threshold(self):
        health = load_healthcheck()
        policy = {
            "services": {"example": ["example.com"]},
            "domains": [{"domain": "example.com", "kind": "fqdn", "services": ["example"]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            (root / "state.json").write_text(json.dumps({
                "example": {"healthy": True, "successes": 3, "failures": 0},
            }), encoding="utf-8")
            states = []

            def reconcile(policy_value, state, public_ip):
                states.append(state)
                return 0, len(health.desired_rules(policy_value, state, public_ip))

            for _ in range(health.FAILURE_THRESHOLD + 2):
                summary = health.run_once(
                    policy_path=root / "policy.json", state_path=root / "state.json",
                    lock_path=root / "health.lock", probe_func=lambda host: False,
                    reconcile_func=reconcile, doh_probe_func=lambda: True,
                )
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            health.run_once(
                policy_path=root / "policy.json", state_path=root / "state.json",
                lock_path=root / "health.lock", probe_func=lambda host: True,
                reconcile_func=reconcile, doh_probe_func=lambda: True,
            )
            recovered = json.loads((root / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(1, summary["global_failure"])
        self.assertEqual(1, summary["active_rules"])
        self.assertTrue(state["example"]["healthy"])
        self.assertTrue(state["example"]["probe_uncertain"])
        self.assertFalse(recovered["example"].get("probe_uncertain", False))
        self.assertTrue(all(item["example"]["healthy"] for item in states))

    def test_unproven_single_service_does_not_become_healthy_after_failures(self):
        health = load_healthcheck()
        policy = {"services": {"example": ["example.com"]},
                  "domains": [{"domain": "example.com", "kind": "fqdn", "services": ["example"]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            args = dict(policy_path=root / "policy.json", state_path=root / "state.json",
                        lock_path=root / "health.lock", reconcile_func=lambda *args: (0, 0),
                        doh_probe_func=lambda: True)
            health.run_once(**args, probe_func=lambda host: False)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertFalse(state["example"]["healthy"])
            self.assertTrue(state["example"]["probe_uncertain"])
            for _ in range(health.SUCCESS_THRESHOLD - 1):
                health.run_once(**args, probe_func=lambda host: True)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertFalse(state["example"]["healthy"])
            health.run_once(**args, probe_func=lambda host: True)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertTrue(state["example"]["healthy"])
            self.assertFalse(state["example"].get("probe_uncertain", False))

    def test_missing_or_corrupt_state_keeps_only_existing_enabled_rules_until_proven(self):
        health = load_healthcheck()
        ip = "203.0.113.10"
        payloads = [None, "{", "null", '{"example":{}}',
                    '{"example":{"healthy":"false"}}',
                    '{"example":{"healthy":true,"successes":"broken"}}']
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy = {
                    "services": {"example": ["example.com"]},
                    "domains": [
                        {"domain": "example.com", "kind": "suffix", "services": ["example"]},
                        {"domain": "disabled.example", "kind": "fqdn", "services": ["example"]},
                        {"domain": "missing.example", "kind": "fqdn", "services": ["example"]},
                    ],
                }
                (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
                if payload is not None:
                    (root / "state.json").write_text(payload, encoding="utf-8")
                api = RewriteApi([
                    {"domain": "example.com", "answer": ip, "enabled": True},
                    {"domain": "disabled.example", "answer": ip, "enabled": False},
                ])
                args = dict(policy_path=root / "policy.json", state_path=root / "state.json",
                            lock_path=root / "health.lock", doh_probe_func=lambda: None)

                def run(success):
                    summary = health.run_once(**args, probe_func=lambda host: success)
                    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
                    return summary, state["example"]

                with mock.patch.object(health, "PUBLIC_IP", ip), \
                        mock.patch.object(health, "login", return_value="sid=x"), \
                        mock.patch.object(health, "api", side_effect=api):
                    for _ in range(health.FAILURE_THRESHOLD + 2):
                        summary, item = run(False)
                        self.assertEqual(1, summary["global_failure"])
                        self.assertEqual(1, summary["active_rules"])
                        self.assertIsNone(item["healthy"])
                        self.assertTrue(item["probe_uncertain"])
                    for _ in range(health.SUCCESS_THRESHOLD - 1):
                        _, item = run(True)
                        self.assertIsNone(item["healthy"])
                    _, item = run(False)
                    self.assertIsNone(item["healthy"])
                    self.assertEqual(0, item["successes"])
                    for _ in range(health.SUCCESS_THRESHOLD - 1):
                        _, item = run(True)
                        self.assertIsNone(item["healthy"])
                    self.assertEqual([], [call for call in api.calls if call[0] != "GET"])
                    self.assertTrue(api.records[("example.com", ip)]["enabled"])
                    self.assertFalse(api.records[("disabled.example", ip)]["enabled"])
                    self.assertNotIn(("*.example.com", ip), api.records)
                    self.assertNotIn(("missing.example", ip), api.records)

                    summary, item = run(True)
                self.assertIs(item["healthy"], True)
                self.assertFalse(item.get("probe_uncertain", False))
                self.assertEqual(4, summary["active_rules"])
                self.assertTrue(all(item["enabled"] for item in api.records.values()))
                self.assertEqual({("example.com", ip), ("*.example.com", ip),
                                  ("disabled.example", ip), ("missing.example", ip)},
                                 set(api.records))

    def test_partial_state_preserves_unknown_owners_but_not_known_unhealthy(self):
        health = load_healthcheck()
        ip = "203.0.113.10"
        services = {name: [name + ".example"] for name in
                    ("good", "bad", "missing", "invalid", "partial", "counter")}
        policy = {
            "services": services,
            "domains": [
                {"domain": "good.example", "kind": "fqdn", "services": ["good"]},
                {"domain": "bad.example", "kind": "fqdn", "services": ["bad"]},
                {"domain": "missing.example", "kind": "fqdn", "services": ["missing"]},
                {"domain": "invalid.example", "kind": "fqdn", "services": ["invalid"]},
                {"domain": "partial.example", "kind": "fqdn", "services": ["partial"]},
                {"domain": "counter.example", "kind": "fqdn", "services": ["counter"]},
                {"domain": "disabled.example", "kind": "fqdn", "services": ["partial"]},
                {"domain": "absent.example", "kind": "fqdn", "services": ["partial"]},
                {"domain": "shared.example", "kind": "suffix", "services": ["bad", "missing"]},
                {"domain": "healthy-shared.example", "kind": "fqdn", "services": ["good", "invalid"]},
            ],
        }
        records = [{"domain": name, "answer": ip, "enabled": name != "disabled.example"}
                   for name in ("good.example", "bad.example", "missing.example", "invalid.example",
                                "partial.example", "counter.example", "disabled.example",
                                "shared.example", "*.shared.example")]
        api = RewriteApi(records)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            (root / "state.json").write_text(json.dumps({
                "good": {"healthy": True}, "bad": {"healthy": False},
                "invalid": "not-an-object", "partial": {"successes": 2},
                "counter": {"healthy": True, "failures": -1},
            }), encoding="utf-8")
            recovery = set()
            args = dict(policy_path=root / "policy.json", state_path=root / "state.json",
                        lock_path=root / "health.lock", doh_probe_func=lambda: None,
                        probe_func=lambda host: host == "good.example" or host in recovery)
            with mock.patch.object(health, "PUBLIC_IP", ip), \
                    mock.patch.object(health, "login", return_value="sid=x"), \
                    mock.patch.object(health, "api", side_effect=api):
                for _ in range(health.FAILURE_THRESHOLD + 2):
                    summary = health.run_once(**args)
                    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
                    self.assertEqual(0, summary["global_failure"])
                    self.assertIs(state["good"]["healthy"], True)
                    self.assertIs(state["bad"]["healthy"], False)
                    for service in ("missing", "invalid", "partial", "counter"):
                        self.assertIsNone(state[service]["healthy"])
                        self.assertTrue(state[service]["probe_uncertain"])
                self.assertFalse(api.records[("bad.example", ip)]["enabled"])
                self.assertFalse(api.records[("disabled.example", ip)]["enabled"])
                self.assertNotIn(("absent.example", ip), api.records)
                for name in ("missing.example", "invalid.example", "partial.example",
                             "counter.example", "shared.example", "*.shared.example"):
                    self.assertTrue(api.records[(name, ip)]["enabled"])
                self.assertTrue(api.records[("healthy-shared.example", ip)]["enabled"])
                updates = [body for method, path, body in api.calls if path == "/control/rewrite/update"]
                self.assertEqual([{"target": {"domain": "bad.example", "answer": ip},
                                   "update": {"enabled": False}}], updates)

                recovery.add("partial.example")
                for _ in range(health.SUCCESS_THRESHOLD - 1):
                    health.run_once(**args)
                    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
                    self.assertIsNone(state["partial"]["healthy"])
                    self.assertFalse(api.records[("disabled.example", ip)]["enabled"])
                    self.assertNotIn(("absent.example", ip), api.records)
                health.run_once(**args)
                state = json.loads((root / "state.json").read_text(encoding="utf-8"))
                self.assertIs(state["partial"]["healthy"], True)
                self.assertTrue(api.records[("disabled.example", ip)]["enabled"])
                self.assertTrue(api.records[("absent.example", ip)]["enabled"])
                self.assertIsNone(state["missing"]["healthy"])
                self.assertTrue(api.records[("shared.example", ip)]["enabled"])

    def test_known_unhealthy_still_disables_existing_rule_in_global_failure(self):
        health = load_healthcheck()
        ip = "203.0.113.10"
        policy = {"services": {"example": ["example.com"]},
                  "domains": [{"domain": "example.com", "kind": "fqdn", "services": ["example"]}]}
        api = RewriteApi([{"domain": "example.com", "answer": ip, "enabled": True}])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            (root / "state.json").write_text('{"example":{"healthy":false}}', encoding="utf-8")
            with mock.patch.object(health, "PUBLIC_IP", ip), \
                    mock.patch.object(health, "login", return_value="sid=x"), \
                    mock.patch.object(health, "api", side_effect=api):
                health.run_once(policy_path=root / "policy.json", state_path=root / "state.json",
                                lock_path=root / "health.lock", probe_func=lambda host: False,
                                doh_probe_func=lambda: None)
        self.assertFalse(api.records[("example.com", ip)]["enabled"])

    def test_unknown_compatibility_domain_preserves_existing_rule(self):
        health = load_healthcheck()
        ip = "203.0.113.10"
        policy = [{"domain": "example.com", "kind": "fqdn", "probe": "example.com"}]
        api = RewriteApi([{"domain": "example.com", "answer": ip, "enabled": True}])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            with mock.patch.object(health, "PUBLIC_IP", ip), \
                    mock.patch.object(health, "login", return_value="sid=x"), \
                    mock.patch.object(health, "api", side_effect=api):
                health.run_once(policy_path=root / "policy.json", state_path=root / "state.json",
                                lock_path=root / "health.lock", probe_func=lambda host: False,
                                doh_probe_func=lambda: None)
        self.assertTrue(api.records[("example.com", ip)]["enabled"])
        self.assertEqual([], [call for call in api.calls if call[0] != "GET"])

    def test_tls_probe_requires_verified_chain_and_hostname(self):
        health = load_healthcheck()
        good = b"Protocol version: TLSv1.3\nPeer certificate: CN=example.com\nVerification: OK\n"
        with mock.patch.object(health.subprocess, "run") as runner:
            runner.return_value = mock.Mock(returncode=0, stdout=good)
            self.assertTrue(health.probe("example.com"))
            command = runner.call_args.args[0]
            self.assertIn("-verify_return_error", command)
            self.assertEqual("example.com", command[command.index("-verify_hostname") + 1])
            runner.return_value = mock.Mock(returncode=1, stdout=good)
            self.assertFalse(health.probe("example.com"))
            runner.return_value = mock.Mock(returncode=0, stdout=good.replace(b"Verification: OK", b"Verification error"))
            self.assertFalse(health.probe("example.com"))

    def test_doh_self_probe_walks_the_public_path_from_loopback(self):
        health = load_healthcheck()
        calls = []
        query = base64.urlsafe_b64decode(health.DOH_PROBE_QUERY + "===")
        response = (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:]
                    + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01")

        class Result:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.returncode = returncode

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return Result(response + b"\n200 application/dns-message")

        token = "a" * 48
        self.assertTrue(health.probe_doh("dns.example.com", token, runner=runner, attempts=1))
        command, kwargs = calls[0]
        self.assertIn("--resolve", command)
        self.assertIn("dns.example.com:443:127.0.0.1", command)
        self.assertNotIn(token, " ".join(command))
        self.assertIn(("/doh/" + token + "?dns=").encode(), kwargs["input"])
        self.assertIn("--config", command)
        self.assertEqual("-", command[command.index("--config") + 1])
        invalid_responses = [
            Result(response + b"\n200 application/dns-message", 18),
            Result(response + b"\n404 text/html"),
            Result(response + b"\n200 application/json"),
            Result(response[:3] + b"\x82" + response[4:] + b"\n200 application/dns-message"),
            Result(response[:2] + b"\x01" + response[3:] + b"\n200 application/dns-message"),
            Result(response[:2] + b"\x83" + response[3:] + b"\n200 application/dns-message"),
            Result(response[:-1] + b"\n200 application/dns-message"),
            Result(b"not a DNS packet\n200 application/dns-message"),
            Result(b"\x01" + response[1:] + b"\n200 application/dns-message"),
            Result(response[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
                   + query[12:] + b"\n200 application/dns-message"),
            Result(response[:len(query)] + b"\xc0\x10" + response[len(query) + 2:]
                   + b"\n200 application/dns-message"),
            Result(response[:10] + b"\x00\x01" + response[12:]
                   + b"\x00" + struct.pack("!HHIH", 41, 1232, 0x01000000, 0)
                   + b"\n200 application/dns-message"),
        ]
        for result in invalid_responses:
            with self.subTest(result=result.stdout, returncode=result.returncode):
                self.assertFalse(health.probe_doh(
                    "dns.example.com", token, attempts=1,
                    runner=lambda command, **kwargs: result,
                ))

    def test_doh_accepts_cname_answer_with_compressed_dns_names(self):
        health = load_healthcheck()
        query = base64.urlsafe_b64decode(health.DOH_PROBE_QUERY + "===")
        cname_target = b"\x05alias\xc0\x10"
        alias_offset = len(query) + 2 + 10
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname_target)) + cname_target
                  + struct.pack("!H", 0xc000 | alias_offset) + struct.pack("!HHIH", 1, 1, 60, 4)
                  + b"\xc0\x00\x02\x01")
        response = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0) + query[12:] + answer
        result = mock.Mock(returncode=0, stdout=response + b"\n200 application/dns-message; charset=binary")
        self.assertTrue(health.probe_doh("dns.example.com", "a" * 48, attempts=1,
                                         runner=lambda command, **kwargs: result))

    def test_doh_probe_target_needs_a_domain_and_a_saved_token(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "doh-token"
            self.assertIsNone(health.doh_probe_target("dns.example.com", token_file))
            token_file.write_text("b" * 48 + "\n", encoding="utf-8")
            self.assertEqual(
                ("dns.example.com", "b" * 48),
                health.doh_probe_target("dns.example.com", token_file),
            )
            self.assertIsNone(health.doh_probe_target("", token_file))
            self.assertEqual(
                ("dns.xn--p1ai", "b" * 48),
                health.doh_probe_target("dns.xn--p1ai", token_file),
            )
            self.assertIsNone(health.doh_probe_target("dns.рф", token_file))
            token_file.write_text("not-a-token\n", encoding="utf-8")
            self.assertIsNone(health.doh_probe_target("dns.example.com", token_file))

    def test_run_once_reports_the_doh_self_probe_without_touching_state(self):
        health = load_healthcheck()
        policy = {
            "services": {"chatgpt": ["chatgpt.com"]},
            "domains": [{"domain": "chatgpt.com", "kind": "suffix", "services": ["chatgpt"]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "health-policy.json").write_text(json.dumps(policy), encoding="utf-8")
            common = dict(
                policy_path=root / "health-policy.json", state_path=root / "health-state.json",
                lock_path=root / "health.lock", probe_func=lambda host: True,
                reconcile_func=lambda *args: (0, 0),
            )
            failed = health.run_once(doh_probe_func=lambda: False, **common)
            state = json.loads((root / "health-state.json").read_text(encoding="utf-8"))
            unconfigured = health.run_once(doh_probe_func=lambda: None, **common)

        self.assertEqual(0, failed["doh_ok"])
        # The self-probe is diagnostic only: the state file keeps service IDs.
        self.assertEqual({"chatgpt"}, set(state))
        self.assertEqual(-1, unconfigured["doh_ok"])

    def test_failure_threshold_defaults_to_five_cycles(self):
        health = load_healthcheck()
        self.assertEqual(5, health.FAILURE_THRESHOLD)
        self.assertEqual(3, health.SUCCESS_THRESHOLD)

    def test_api_prefers_basic_auth_over_accumulating_sessions(self):
        """One session per minute would fill the session store for 30 days."""

        health = load_healthcheck()
        requests = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(request, timeout=None):
            requests.append((request.full_url, dict(request.header_items())))
            return Response()

        with mock.patch.object(health, "credentials", return_value={"login": "admin", "password": "secret"}), \
                mock.patch.object(health, "urlopen", side_effect=fake_urlopen):
            credential = health.login()

        self.assertEqual("Basic YWRtaW46c2VjcmV0", credential)
        self.assertNotIn("/control/login", requests[0][0])
        self.assertEqual({"Authorization": credential}, health._auth_header(credential))
        self.assertEqual({"Cookie": "sid=x"}, health._auth_header("sid=x"))

    def test_login_falls_back_to_a_session_when_basic_auth_is_refused(self):
        health = load_healthcheck()

        class Response:
            def __init__(self, headers):
                self._headers = headers

            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            @property
            def headers(self):
                return self._headers

        class Headers:
            @staticmethod
            def get_all(name):
                return ["agh_session=abc; Path=/"]

        def fake_urlopen(request, timeout=None):
            if request.full_url.endswith("/control/status"):
                raise OSError("401 unauthorized")
            return Response(Headers())

        with mock.patch.object(health, "credentials", return_value={"login": "admin", "password": "secret"}), \
                mock.patch.object(health, "urlopen", side_effect=fake_urlopen):
            self.assertEqual("agh_session=abc", health.login())


if __name__ == "__main__":
    unittest.main()
