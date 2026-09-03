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

    def test_a_total_probe_sweep_keeps_the_previous_state(self):
        """A fault that takes out every service at once is local, not remote."""

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
        # One configured service cannot be told apart from a local fault.
        self.assertFalse(health.is_global_failure({"chatgpt": False}))

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
            )

        self.assertEqual(1, summary["global_failure"])
        self.assertEqual(2, summary["healthy_services"])
        self.assertEqual(0, summary["transitions"])
        # Rewrites stay in place; withdrawing them would send clients to the
        # very addresses this server exists to reroute, for a cached TTL.
        self.assertEqual(4, summary["active_rules"])
        self.assertTrue(all(item["healthy"] for item in reconciled.values()))

    def test_doh_self_probe_walks_the_public_path_from_loopback(self):
        health = load_healthcheck()
        commands = []

        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def runner(command, **kwargs):
            commands.append(command)
            return Result(b"200 application/dns-message")

        self.assertTrue(health.probe_doh("dns.example.com", "a" * 48, runner=runner, attempts=1))
        command = commands[0]
        self.assertIn("--resolve", command)
        self.assertIn("dns.example.com:443:127.0.0.1", command)
        self.assertTrue(command[-1].startswith("https://dns.example.com/doh/" + "a" * 48 + "?dns="))
        self.assertFalse(health.probe_doh(
            "dns.example.com", "a" * 48, attempts=1,
            runner=lambda command, **kwargs: Result(b"404 text/html"),
        ))
        self.assertFalse(health.probe_doh(
            "dns.example.com", "a" * 48, attempts=1,
            runner=lambda command, **kwargs: Result(b"200 application/json"),
        ))

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
            unconfigured = health.run_once(**common)

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
