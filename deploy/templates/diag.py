#!/usr/bin/env python3
"""Summarize recent stream connections and TCP health of this host.

A client that reports stalls while the host looks healthy needs evidence
from both sides. This command summarizes completed nginx stream sessions in
the available log. Missing records and zero received bytes do not identify
the cause of a stall. Pair it with tools/client-probe.sh on the affected
network and compare timestamps.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def read_records(path: Path, since: datetime, until: datetime) -> Tuple[
    List[Dict[str, Any]], Optional[datetime], int
]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    records = []
    first = None
    invalid = 0
    for line in lines:
        item = parse_line(line)
        if item is None:
            invalid += 1
            continue
        when = item["when"]
        if when <= until and (first is None or when < first):
            first = when
        if since <= when <= until:
            records.append(item)
    return records, first, invalid


def percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round(fraction * (len(ordered) - 1)))
    return ordered[min(len(ordered) - 1, max(0, index))]


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    records = list(records)
    # Retain the existing metric name; it counts zero bytes received, not a
    # confirmed cause or a proven loss of the ClientHello in transit.
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


def render(summary: Optional[Dict[str, Any]], counters: Dict[str, str], health: Dict[str, int],
           minutes: int, path: Path, since: datetime, until: datetime,
           first: Optional[datetime], invalid: int) -> str:
    available = summary is not None
    coverage = ("unavailable" if not available else
                "observed_before_start" if first is not None and first <= since and not invalid
                else "unverified")
    lines = [
        "window_minutes=%d window_start=%s window_end=%s log=%s" % (
            minutes, since.isoformat(), until.isoformat(), path),
        "log_state=%s window_coverage=%s first_record=%s unparsed_lines=%d" % (
            "available" if available else "unavailable", coverage,
            first.isoformat() if first else "-", invalid),
    ]
    if summary is not None:
        lines.extend([
            "connections=%d ok=%d failed=%d no_clienthello=%d upstream_failures=%d" % (
                summary["connections"], summary["ok"], summary["failed"],
                summary["no_clienthello"], summary["upstream_failures"]),
            "status: " + _pairs(summary["by_status"]),
            "no_clienthello_by_client: " + _pairs(summary["no_clienthello_by_client"]),
            "failed_by_sni: " + _pairs(summary["failed_by_sni"]),
            "session_p50=%s session_p95=%s connect_p95=%s" % (
                _fmt(summary["session_p50"]), _fmt(summary["session_p95"]),
                _fmt(summary["connect_p95"])),
        ])
    lines.extend([
        "tcp: " + (_pairs(counters) if counters else "unavailable"),
        "health: " + (_pairs(health) if health else "unavailable"),
    ])
    hints = []
    if summary is None:
        hints.append("журнал недоступен: проверьте путь и права доступа")
    else:
        if coverage == "unverified":
            hints.append("полнота окна не подтверждена: проверьте ротацию и нераспознанные строки")
        if not summary["connections"]:
            hints.append("в доступном журнале не найдено записей о завершённых соединениях; "
                         "открытые соединения могут ещё отсутствовать в журнале")
        if summary["no_clienthello"]:
            hints.append("%d записей с нулём принятых байт: причина по этому счётчику неизвестна" %
                         summary["no_clienthello"])
        if summary["failed"]:
            hints.append("%d записей со статусом, отличным от 200: проверьте журнал ошибок nginx" %
                         summary["failed"])
        if summary["upstream_failures"]:
            hints.append("%d записей со статусом 502 или 504: проверьте nginx-stream.error.log" %
                         summary["upstream_failures"])
    if health.get("doh_fail"):
        hints.append("health-gate видел отказ DoH %d раз; проверьте сервер и журнал" % health["doh_fail"])
    if not hints and summary is not None and summary["connections"] and not summary["failed"]:
        hints.append("у записанных сессий статус nginx 200; сравните время с tools/client-probe.sh")
    lines.extend("hint: " + hint for hint in hints)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="stream connection summary for stall reports")
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--log", type=Path, default=LOG)
    args = parser.parse_args(argv)
    minutes = max(1, args.minutes)
    until = datetime.now(timezone.utc).replace(microsecond=0)
    since = until - timedelta(minutes=minutes)
    try:
        records, first, invalid = read_records(args.log, since, until)
        summary = summarize(records)
    except OSError:
        summary, first, invalid = None, None, 0
    print(render(summary, tcp_counters(), health_journal(minutes), minutes, args.log,
                 since, until, first, invalid))
    return 0 if summary is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
