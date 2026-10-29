import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


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
    def setUp(self):
        self.diag = load_diag()
        self.end = datetime(2026, 9, 7, 9, 0, tzinfo=timezone.utc)
        self.start = self.end - timedelta(minutes=60)

    def render(self, summary, *, first=None, invalid=0):
        return self.diag.render(summary, {}, {}, 60, Path("/var/log/x"),
                                self.start, self.end, first, invalid)

    def test_summary_separates_zero_received_from_upstream_failures(self):
        records = [item for item in map(self.diag.parse_line, SAMPLE) if item]
        summary = self.diag.summarize(records)
        self.assertEqual(3, summary["connections"])
        self.assertEqual(1, summary["ok"])
        self.assertEqual(2, summary["failed"])
        self.assertEqual(1, summary["no_clienthello"])
        self.assertEqual({"5.6.7.0": 1}, summary["no_clienthello_by_client"])
        self.assertEqual(1, summary["upstream_failures"])
        self.assertEqual({200: 1, 400: 1, 502: 1}, summary["by_status"])
        self.assertEqual({"-": 1, "claude.ai": 1}, summary["failed_by_sni"])
        self.assertEqual(12.345, summary["session_p50"])
        self.assertEqual(0.021, summary["connect_p95"])

        text = self.render(summary, first=self.start - timedelta(seconds=1))
        self.assertIn("connections=3 ok=1 failed=2 no_clienthello=1 upstream_failures=1", text)
        self.assertIn("status: 200=1 400=1 502=1", text)
        self.assertIn("нулём принятых байт", text)
        self.assertNotIn("DPI", text)
        self.assertNotIn("обслужил все", text)

    def test_window_filter_excludes_future_and_reports_first_and_invalid_lines(self):
        old = (self.start - timedelta(minutes=1)).isoformat()
        recent = (self.end - timedelta(minutes=5)).isoformat()
        future = (self.end + timedelta(minutes=5)).isoformat()
        template = ("%s client=anon sni=%s status=200 session=1.0 "
                    "in=10 out=10 upstream=x connect=0.1\n")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "stream.log"
            log.write_text(template % (old, "old") + template % (recent, "recent") +
                           template % (future, "future") + "bad line\n", encoding="utf-8")
            records, first, invalid = self.diag.read_records(log, self.start, self.end)
        self.assertEqual(["recent"], [item["sni"] for item in records])
        self.assertEqual(datetime.fromisoformat(old), first)
        self.assertEqual(1, invalid)
        self.assertIn("window_coverage=unverified", self.render(
            self.diag.summarize(records), first=first, invalid=invalid))

    def test_unavailable_log_does_not_report_zero_connections(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(self.diag, "tcp_counters", return_value={}), \
             patch.object(self.diag, "health_journal", return_value={}), \
             redirect_stdout(output):
            result = self.diag.main(["--log", str(Path(directory) / "missing")])
        self.assertNotEqual(0, result)
        self.assertIn("log_state=unavailable", output.getvalue())
        self.assertNotIn("connections=0", output.getvalue())
        self.assertNotIn("пакеты до сервера не дошли", output.getvalue())

    def test_empty_or_recent_log_cannot_confirm_complete_window(self):
        text = self.render(self.diag.summarize([]))
        self.assertIn("log_state=available", text)
        self.assertIn("window_coverage=unverified", text)
        self.assertIn("полнота окна не подтверждена", text)
        self.assertNotIn("не было ни одного соединения", text)
        recent = self.render(self.diag.summarize([]), first=self.start + timedelta(minutes=10))
        self.assertIn("window_coverage=unverified", recent)

    def test_readable_empty_log_reports_empty_observation(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(self.diag, "tcp_counters", return_value={}), \
             patch.object(self.diag, "health_journal", return_value={}), \
             redirect_stdout(output):
            log = Path(directory) / "empty.log"
            log.write_text("", encoding="utf-8")
            result = self.diag.main(["--log", str(log)])
        self.assertEqual(0, result)
        self.assertIn("log_state=available window_coverage=unverified", output.getvalue())
        self.assertIn("connections=0", output.getvalue())
        self.assertIn("window_start=", output.getvalue())
        self.assertIn("window_end=", output.getvalue())

    def test_observed_old_log_with_empty_window_reports_only_missing_records(self):
        text = self.render(self.diag.summarize([]), first=self.start - timedelta(seconds=1))
        self.assertIn("window_coverage=observed_before_start", text)
        self.assertIn("не найдено записей о завершённых соединениях", text)
        self.assertIn("открытые соединения", text)
        self.assertNotIn("пакеты до сервера не дошли", text)

    def test_non_upstream_failure_cannot_be_reported_as_success(self):
        record = self.diag.parse_line(SAMPLE[0].replace("status=200", "status=400"))
        text = self.render(self.diag.summarize([record]), first=self.start)
        self.assertIn("failed=1", text)
        self.assertIn("статусом, отличным от 200", text)
        self.assertNotIn("обслужил все", text)

    def test_unavailable_tools_do_not_crash(self):
        def missing(*args, **kwargs):
            raise OSError("no such tool")

        self.assertEqual({}, self.diag.tcp_counters(runner=missing))
        self.assertEqual({}, self.diag.health_journal(10, runner=missing))


if __name__ == "__main__":
    unittest.main()
