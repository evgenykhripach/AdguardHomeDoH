import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ClientProbeTests(unittest.TestCase):
    def test_doh_token_is_sent_to_curl_stdin_not_arguments_or_csv(self):
        token = "a" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            capture = root / "curl.jsonl"
            curl = fake_bin / "curl"
            curl.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['PROBE_CAPTURE'], 'a') as stream:\n"
                "    stream.write(json.dumps({'args': sys.argv[1:], 'input': sys.stdin.read()}) + '\\n')\n"
                "print('0.01|0.02|0.03|200|127.0.0.1', end='')\n",
                encoding="utf-8",
            )
            curl.chmod(0o755)
            ping = fake_bin / "ping"
            ping.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            ping.chmod(0o755)
            env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                       PROBE_CAPTURE=str(capture), DOH_URL="https://dns.example.com/doh/" + token)
            process = subprocess.Popen(
                ["bash", str(ROOT / "tools/client-probe.sh"), "dns.example.com", "chatgpt.com", "5"],
                cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if capture.exists() and len(capture.read_text(encoding="utf-8").splitlines()) >= 4:
                        break
                    if process.poll() is not None:
                        self.fail("client probe exited before completing one cycle")
                    time.sleep(0.05)
                records = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()]
                self.assertGreaterEqual(len(records), 4)
                self.assertTrue(any(token in item["input"] for item in records))
                self.assertTrue(all(token not in " ".join(item["args"]) for item in records))
                for csv in root.glob("client-probe-*.csv"):
                    self.assertNotIn(token, csv.read_text(encoding="utf-8"))
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
