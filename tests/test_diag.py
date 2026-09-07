import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAG_PATH = ROOT / "deploy" / "templates" / "diag.py"


def load_diag():
    spec = importlib.util.spec_from_file_location("adguardhome_doh_diag", DIAG_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SAMPLE = [
    "2026-09-07T11:00:01+03:00 client=5.6.7.0 sni=chatgpt.com status=200 session=12.345"
    " in=5120 out=90000 upstream=104.18.32.47:443 connect=0.021",
    "2026-09-07T11:00:05+03:00 client=5.6.7.0 sni= status=400 session=30.001"
    " in=0 out=0 upstream= connect=",
    "2026-09-07T11:00:09+03:00 client=anon sni=claude.ai status=502 session=5.002"
    " in=517 out=0 upstream=160.79.104.10:443 connect=",
    "not a log line",
]


class DiagTests(unittest.TestCase):
    def test_summary_separates_a_missing_clienthello_from_upstream_failures(self):
        diag = load_diag()
        records = [item for item in map(diag.parse_line, SAMPLE) if item]

        self.assertEqual(3, len(records))
        summary = diag.summarize(records)
        self.assertEqual(3, summary["connections"])
        self.assertEqual(1, summary["ok"])
        self.assertEqual(2, summary["failed"])
        # TCP handshake done, no byte of TLS ever arrived: the path ate it.
        self.assertEqual(1, summary["no_clienthello"])
        self.assertEqual({"5.6.7.0": 1}, summary["no_clienthello_by_client"])
        self.assertEqual(1, summary["upstream_failures"])
        self.assertEqual({200: 1, 400: 1, 502: 1}, summary["by_status"])
        self.assertEqual({"-": 1, "claude.ai": 1}, summary["failed_by_sni"])
        self.assertEqual(12.345, summary["session_p50"])
        self.assertEqual(0.021, summary["connect_p95"])

        text = diag.render(summary, {"TcpExtTCPSynRetrans": "7"}, {"doh_fail": 0, "runs": 5},
                           60, Path("/var/log/x"))
        self.assertIn("connections=3 ok=1 failed=2 no_clienthello=1 upstream_failures=1", text)
        self.assertIn("status: 200=1 400=1 502=1", text)
        self.assertIn("tcp: TcpExtTCPSynRetrans=7", text)
        self.assertIn("без ClientHello", text)
        self.assertIn("ошибок апстрима", text)

    def test_window_filter_uses_the_log_timestamps(self):
        diag = load_diag()
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(minutes=5)).isoformat(timespec="seconds")
        old = (now - timedelta(hours=3)).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "stream.log"
            log.write_text(
                "%s client=anon sni=a.example status=200 session=1.0 in=10 out=10 upstream=x connect=0.1\n"
                "%s client=anon sni=b.example status=200 session=1.0 in=10 out=10 upstream=x connect=0.1\n"
                % (old, recent),
                encoding="utf-8",
            )
            records = diag.read_records(log, now - timedelta(minutes=60))
            self.assertEqual(["b.example"], [item["sni"] for item in records])
            self.assertEqual([], diag.read_records(Path(directory) / "missing.log", now))

    def test_empty_window_and_unavailable_tools_render_without_error(self):
        diag = load_diag()
        text = diag.render(diag.summarize([]), {}, {}, 15, Path("/var/log/x"))
        self.assertIn("connections=0", text)
        self.assertIn("tcp: unavailable", text)
        self.assertIn("не было ни одного соединения", text)

        def missing(*args, **kwargs):
            raise OSError("no such tool")

        self.assertEqual({}, diag.tcp_counters(runner=missing))
        self.assertEqual({}, diag.health_journal(10, runner=missing))


if __name__ == "__main__":
    unittest.main()
