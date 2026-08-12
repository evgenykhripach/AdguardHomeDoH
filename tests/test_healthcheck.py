import importlib.util
import json
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

    def test_non_overlapping_lock_rejects_second_health_run(self):
        health = load_healthcheck()
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "health.lock"
            with health.health_lock(lock_path):
                with self.assertRaises(health.LockBusy):
                    with health.health_lock(lock_path):
                        pass

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


if __name__ == "__main__":
    unittest.main()
