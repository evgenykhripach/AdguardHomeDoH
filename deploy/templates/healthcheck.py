#!/usr/bin/env python3
"""Service-level health gate for the neutral AdGuard Home deployment.

The policy file contains the enabled service set and the effective domain
union.  Health is persisted by service ID, never by a domain: shared domains
remain active while any selected healthy service owns them.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.request import Request, urlopen


AGH_URL = os.environ.get("ADGUARDHOME_DOH_AGH_URL", "http://127.0.0.1:3001")
POLICY = Path(os.environ.get("ADGUARDHOME_DOH_POLICY", "/etc/adguardhome-doh/health-policy.json"))
STATE = Path(os.environ.get("ADGUARDHOME_DOH_STATE", "/var/lib/adguardhome-doh/health-state.json"))
CREDENTIALS = Path(os.environ.get("ADGUARDHOME_DOH_CREDENTIALS", "/var/lib/adguardhome-doh/admin-credentials.json"))
PUBLIC_IP = os.environ.get("ADGUARDHOME_DOH_PUBLIC_IP", "127.0.0.1")
LOCK = Path(os.environ.get("ADGUARDHOME_DOH_LOCK", "/run/lock/adguardhome-doh-health.lock"))
SUCCESS_THRESHOLD = int(os.environ.get("ADGUARDHOME_DOH_SUCCESS_THRESHOLD", "3"))
FAILURE_THRESHOLD = int(os.environ.get("ADGUARDHOME_DOH_FAILURE_THRESHOLD", "2"))
MAX_CONCURRENT_PROBES = 8


class LockBusy(RuntimeError):
    """Raised when another health run currently owns the lock."""


def load_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return fallback


def save_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, name = tempfile.mkstemp(prefix=".state.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(name, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


@contextmanager
def health_lock(path: Path) -> Iterator[None]:
    """Acquire a non-overlapping process lock for one health run."""

    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("health check is already running") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _as_hosts(value: Any) -> Tuple[str, ...]:
    if isinstance(value, Mapping):
        value = value.get("probes", value.get("hosts", []))
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, Sequence):
        return ()
    return tuple(sorted({str(host).strip().lower() for host in value if str(host).strip()}))


def service_probe_map(policy: Any) -> Dict[str, Tuple[str, ...]]:
    """Normalize supported policy shapes to ``service_id -> probe hosts``."""

    result: Dict[str, set] = {}
    if isinstance(policy, Mapping):
        services = policy.get("services", {})
        if isinstance(services, Mapping):
            for service_id, value in services.items():
                result[str(service_id)] = set(_as_hosts(value))
            # The service map is authoritative for the catalog format.  Domain
            # ownership rows describe rewrite coverage, not extra TLS probes.
            return {service_id: tuple(sorted(hosts)) for service_id, hosts in sorted(result.items())}
        elif isinstance(services, Sequence):
            for item in services:
                if isinstance(item, Mapping):
                    service_id = item.get("id", item.get("service_id"))
                    if service_id:
                        result.setdefault(str(service_id), set()).update(_as_hosts(item))
            return {service_id: tuple(sorted(hosts)) for service_id, hosts in sorted(result.items())}
        rows = policy.get("domains", [])
    else:
        rows = policy if isinstance(policy, Sequence) else []

    for row in rows:
        if not isinstance(row, Mapping):
            continue
        service_ids = row.get("services", row.get("service_ids"))
        if service_ids is None and row.get("service_id") is not None:
            service_ids = [row["service_id"]]
        if isinstance(service_ids, str):
            service_ids = [service_ids]
        if not isinstance(service_ids, Sequence):
            continue
        hosts = _as_hosts(row.get("probes", row.get("probe", row.get("domain", ""))))
        for service_id in service_ids:
            result.setdefault(str(service_id), set()).update(hosts)

    # Every service needs an actual probe.  A malformed/empty service remains
    # unhealthy instead of becoming healthy by vacuous truth.
    return {service_id: tuple(sorted(hosts)) for service_id, hosts in sorted(result.items())}


def probe(host: str) -> bool:
    """Probe local TLS/SNI routing without exposing credentials or URLs."""

    try:
        result = subprocess.run(
            ["/usr/bin/timeout", "8", "/usr/bin/openssl", "s_client", "-brief",
             "-connect", "127.0.0.1:443", "-servername", host],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    text = result.stdout.decode("utf-8", "replace")
    return result.returncode == 0 and "Protocol version:" in text and "Peer certificate" in text


def probe_services(
    policy: Any,
    *,
    probe_func: Optional[Callable[[str], bool]] = None,
    max_workers: int = MAX_CONCURRENT_PROBES,
) -> Dict[str, bool]:
    """Probe all service hosts concurrently, capped at eight workers.

    A service succeeds only when every one of its probe hosts succeeds.  A
    host shared by multiple services is probed once and its result reused.
    """

    hosts_by_service = service_probe_map(policy)
    hosts = sorted({host for values in hosts_by_service.values() for host in values})
    if not hosts:
        return {service_id: False for service_id in hosts_by_service}
    worker_count = max(1, min(MAX_CONCURRENT_PROBES, int(max_workers)))
    check = probe_func or probe
    host_results: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=min(worker_count, len(hosts))) as executor:
        futures = {executor.submit(check, host): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                host_results[host] = bool(future.result())
            except Exception:
                host_results[host] = False
    return {
        service_id: bool(hosts and all(host_results.get(host, False) for host in hosts))
        for service_id, hosts in hosts_by_service.items()
    }


def update_health_state(
    old_state: Mapping[str, Any],
    results: Mapping[str, bool],
    *,
    success_threshold: int = SUCCESS_THRESHOLD,
    failure_threshold: int = FAILURE_THRESHOLD,
) -> Tuple[Dict[str, Dict[str, Any]], list]:
    """Apply one probe cycle and return ``(state, transitioned_service_ids)``."""

    state: Dict[str, Dict[str, Any]] = {}
    transitions = []
    for service_id in sorted(results):
        previous = old_state.get(service_id, {}) if isinstance(old_state, Mapping) else {}
        healthy = bool(previous.get("healthy", False))
        successes = int(previous.get("successes", 0) or 0)
        failures = int(previous.get("failures", 0) or 0)
        if results[service_id]:
            successes += 1
            failures = 0
            if not healthy and successes >= success_threshold:
                healthy = True
                transitions.append(service_id)
        else:
            failures += 1
            successes = 0
            if healthy and failures >= failure_threshold:
                healthy = False
                transitions.append(service_id)
        state[service_id] = {"healthy": healthy, "successes": successes, "failures": failures}
    return state, transitions


def _domain_rows(policy: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(policy, Mapping):
        rows = policy.get("domains", [])
    else:
        rows = policy if isinstance(policy, Sequence) else []
    return (row for row in rows if isinstance(row, Mapping))


def desired_rules(policy: Any, state: Mapping[str, Any], public_ip: str = PUBLIC_IP) -> list:
    """Return desired managed rewrite keys from selected healthy services."""

    result = []
    for row in _domain_rows(policy):
        service_ids = row.get("services", row.get("service_ids"))
        if service_ids is None and row.get("service_id") is not None:
            service_ids = [row["service_id"]]
        if isinstance(service_ids, str):
            service_ids = [service_ids]
        if service_ids:
            active = any(bool(state.get(str(service_id), {}).get("healthy", False)) for service_id in service_ids)
        else:
            # Compatibility policy has one state key per domain.
            active = bool(state.get(str(row.get("domain", "")), {}).get("healthy", False))
        if not active:
            continue
        domain = str(row.get("domain", ""))
        if not domain:
            continue
        result.append((domain, public_ip))
        if str(row.get("kind", "")) == "suffix":
            result.append(("*." + domain, public_ip))
    return sorted(set(result))


def credentials() -> Dict[str, str]:
    value = load_json(CREDENTIALS, {})
    if not isinstance(value, Mapping):
        raise RuntimeError("invalid administrator credentials")
    login_name = value.get("login")
    password = value.get("password")
    if not isinstance(login_name, str) or not isinstance(password, str) or not login_name or not password:
        raise RuntimeError("invalid administrator credentials")
    return {"login": login_name, "password": password}


def api(method: str, path: str, cookie: str, body: Optional[Mapping[str, Any]] = None) -> Any:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Cookie": cookie}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(AGH_URL + path, data=data, headers=headers, method=method)
    with urlopen(request, timeout=8) as response:
        raw = response.read()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def login() -> str:
    values = credentials()
    body = json.dumps({"name": values["login"], "password": values["password"]}).encode()
    request = Request(AGH_URL + "/control/login", data=body,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=8) as response:
        cookies = response.headers.get_all("Set-Cookie") or []
    if not cookies:
        raise RuntimeError("AdGuard login returned no session")
    return cookies[0].split(";", 1)[0]


def reconcile(policy: Any, state: Mapping[str, Any], public_ip: str = PUBLIC_IP) -> Tuple[int, int]:
    """Reconcile only managed rewrites and clear cache after any change."""

    cookie = login()
    current = api("GET", "/control/rewrite/list", cookie) or []
    by_key = {}
    for item in current:
        if isinstance(item, Mapping):
            by_key[(str(item.get("domain", "")), str(item.get("answer", "")))] = item
    desired = set(desired_rules(policy, state, public_ip))
    managed = set()
    for row in _domain_rows(policy):
        domain = str(row.get("domain", ""))
        if not domain:
            continue
        managed.add((domain, public_ip))
        if str(row.get("kind", "")) == "suffix":
            managed.add(("*." + domain, public_ip))
    legacy = {(domain, answer) for domain, _answer in managed
              for answer in ("127.0.0.1", "127.0.0.1:53")}
    changes = 0
    for key in sorted(desired):
        item = by_key.get(key)
        if item is None:
            api("POST", "/control/rewrite/add", cookie,
                {"domain": key[0], "answer": key[1], "enabled": True})
            changes += 1
        elif not item.get("enabled", True):
            api("PUT", "/control/rewrite/update", cookie,
                {"target": {"domain": key[0], "answer": key[1]}, "update": {"enabled": True}})
            changes += 1
    for key, item in by_key.items():
        if key in legacy:
            api("POST", "/control/rewrite/delete", cookie,
                {"domain": key[0], "answer": key[1]})
            changes += 1
            continue
        if key in managed and key not in desired and item.get("enabled", True):
            api("PUT", "/control/rewrite/update", cookie,
                {"target": {"domain": key[0], "answer": key[1]}, "update": {"enabled": False}})
            changes += 1
    if changes:
        api("POST", "/control/cache_clear", cookie)
    return changes, len(desired)


def run_once(
    *,
    policy_path: Path = POLICY,
    state_path: Path = STATE,
    lock_path: Path = LOCK,
    probe_func: Optional[Callable[[str], bool]] = None,
    reconcile_func: Optional[Callable[[Any, Mapping[str, Any], str], Tuple[int, int]]] = None,
) -> Dict[str, int]:
    policy = load_json(policy_path, {})
    old = load_json(state_path, {})
    with health_lock(lock_path):
        results = probe_services(policy, probe_func=probe_func)
        state, transitions = update_health_state(old, results)
        save_json(state_path, state)
        reconcile_call = reconcile_func or reconcile
        changes, active = reconcile_call(policy, state, PUBLIC_IP)
    healthy = sum(1 for item in state.values() if item.get("healthy", False))
    return {"healthy_services": healthy, "active_rules": active,
            "transitions": len(transitions), "changes": changes}


def main() -> int:
    try:
        summary = run_once()
    except LockBusy:
        print("health check already running")
        return 0
    except Exception as exc:
        # Error text is deliberately generic: never serialize credentials or
        # private endpoint data into the unit journal.
        print("health check failed: %s" % type(exc).__name__)
        return 1
    print("healthy_services=%d active_rules=%d transitions=%d changes=%d" % (
        summary["healthy_services"], summary["active_rules"],
        summary["transitions"], summary["changes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
