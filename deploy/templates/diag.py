#!/usr/bin/env python3
"""Summarize recent stream connections and TCP health of this host.

A client that reports stalls while the host looks healthy needs evidence
from both sides.  This command reads the nginx stream access log written by
the deployment and answers three questions for the last N minutes: did the
connections arrive at all, did their ClientHello arrive, and did the upstream
connect succeed.  Pair it with tools/client-probe.sh run on the affected
network and compare timestamps.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

LOG = Path("/var/log/adguardhome-doh/nginx-stream.access.log")
LINE_RE = re.compile(
    r"^(?P<time>\S+) client=(?P<client>\S+) sni=(?P<sni>\S*) status=(?P<status>\d+)"
    r" session=(?P<session>[0-9.]+) in=(?P<received>\d+) out=(?P<sent>\d+)"
    r" upstream=(?P<upstream>\S*) connect=(?P<connect>\S*)$"
)
TCP_COUNTERS = (
    "TcpExtListenDrops", "TcpExtListenOverflows", "TcpExtTCPSynRetrans",
    "TcpExtTCPAbortOnTimeout", "TcpExtTCPTimeouts", "TcpRetransSegs",
)


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    item: Dict[str, Any] = match.groupdict()
    try:
        when = datetime.fromisoformat(item["time"])
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    item["when"] = when
    item["status"] = int(item["status"])
    item["session"] = float(item["session"])
    item["received"] = int(item["received"])
    item["sent"] = int(item["sent"])
    try:
        item["connect"] = float(item["connect"])
    except ValueError:
        item["connect"] = None
    return item


def read_records(path: Path, since: datetime) -> List[Dict[str, Any]]:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records = []
    for line in lines:
        item = parse_line(line)
        if item is not None and item["when"] >= since:
            records.append(item)
    return records


def percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round(fraction * (len(ordered) - 1)))
    return ordered[min(len(ordered) - 1, max(0, index))]


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    records = list(records)
    # A session that closed without one byte from the client never carried
    # a ClientHello: the TCP handshake completed and the path then swallowed
    # the TLS record.  That is the signature of DPI throttling between the
    # client and this host, not of a fault here.
    no_hello = [item for item in records if item["received"] == 0]
    failed = [item for item in records if item["status"] != 200]
    return {
        "connections": len(records),
        "ok": sum(1 for item in records if item["status"] == 200),
        "failed": len(failed),
        "no_clienthello": len(no_hello),
        "upstream_failures": sum(1 for item in records if item["status"] in (502, 504)),
        "by_status": dict(sorted(Counter(item["status"] for item in records).items())),
        "no_clienthello_by_client": dict(Counter(item["client"] for item in no_hello).most_common(10)),
        "failed_by_sni": dict(Counter(item["sni"] or "-" for item in failed).most_common(10)),
        "session_p50": percentile([item["session"] for item in records], 0.5),
        "session_p95": percentile([item["session"] for item in records], 0.95),
        "connect_p95": percentile(
            [item["connect"] for item in records if item["connect"] is not None], 0.95
        ),
    }


def tcp_counters(runner=subprocess.run) -> Dict[str, str]:
    try:
        result = runner(
            ["nstat", "-az"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    values: Dict[str, str] = {}
    for line in (getattr(result, "stdout", "") or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] in TCP_COUNTERS:
            values[fields[0]] = fields[1]
    return values


def health_journal(minutes: int, runner=subprocess.run) -> Dict[str, int]:
    try:
        result = runner(
            ["journalctl", "-u", "adguardhome-doh-health.service",
             "--since", "-%dmin" % minutes, "--no-pager", "-o", "cat"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    text = getattr(result, "stdout", "") or ""
    if not text.strip():
        return {}
    return {
        "runs": text.count("healthy_services="),
        "doh_fail": text.count("doh_ok=0"),
        "global_failure": text.count("global_failure=1"),
        "errors": text.count("health check failed"),
    }


def _fmt(value: Optional[float]) -> str:
    return "-" if value is None else "%.3f" % value


def _pairs(values: Dict[Any, Any]) -> str:
    return " ".join("%s=%s" % (key, value) for key, value in values.items()) or "-"


def render(summary: Dict[str, Any], counters: Dict[str, str], health: Dict[str, int],
           minutes: int, path: Path) -> str:
    lines = [
        "window_minutes=%d log=%s" % (minutes, path),
        "connections=%d ok=%d failed=%d no_clienthello=%d upstream_failures=%d" % (
            summary["connections"], summary["ok"], summary["failed"],
            summary["no_clienthello"], summary["upstream_failures"]),
        "status: " + _pairs(summary["by_status"]),
        "no_clienthello_by_client: " + _pairs(summary["no_clienthello_by_client"]),
        "failed_by_sni: " + _pairs(summary["failed_by_sni"]),
        "session_p50=%s session_p95=%s connect_p95=%s" % (
            _fmt(summary["session_p50"]), _fmt(summary["session_p95"]),
            _fmt(summary["connect_p95"])),
        "tcp: " + (_pairs(counters) if counters else "unavailable"),
        "health: " + (_pairs(health) if health else "unavailable"),
    ]
    hints = []
    if summary["connections"] == 0:
        hints.append("за окно не было ни одного соединения: если клиент в это время видел "
                     "зависание, его пакеты до сервера не дошли вовсе")
    if summary["no_clienthello"]:
        hints.append("%d соединений без ClientHello: TCP-handshake прошёл, TLS-запись потерялась "
                     "в пути; это почерк DPI или оператора, а не сервера" % summary["no_clienthello"])
    if summary["upstream_failures"]:
        hints.append("%d ошибок апстрима: сервер не смог подключиться к целевому сайту, "
                     "смотрите nginx-stream.error.log" % summary["upstream_failures"])
    if health.get("doh_fail"):
        hints.append("health-gate видел отказ DoH %d раз: проблема на самом сервере" % health["doh_fail"])
    if not hints and summary["connections"]:
        hints.append("сервер обслужил все соединения; если клиент видел зависания, "
                     "сравните время с выводом tools/client-probe.sh")
    lines.extend("hint: " + hint for hint in hints)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="stream connection summary for stall reports")
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--log", type=Path, default=LOG)
    args = parser.parse_args(argv)
    minutes = max(1, args.minutes)
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    records = read_records(args.log, since)
    print(render(summarize(records), tcp_counters(), health_journal(minutes), minutes, args.log))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
