#!/usr/bin/env python3
"""Service-level health gate for the neutral AdGuard Home deployment.

The policy file contains the enabled service set and the effective domain
union. Health is persisted by service ID, or by domain for compatibility
policies. Shared domains remain active while any owner is healthy, and an
unknown owner protects an existing active rewrite.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import struct
import subprocess
import tempfile
import time
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
# Disabling a rewrite sends clients to the real address of a service they
# reach through this server on purpose, and the client then caches that answer
# for the upstream TTL.  A short outage must therefore cost several minutes of
# probing before anything is withdrawn.
FAILURE_THRESHOLD = int(os.environ.get("ADGUARDHOME_DOH_FAILURE_THRESHOLD", "5"))
MAX_CONCURRENT_PROBES = 8
DOMAIN = os.environ.get("ADGUARDHOME_DOH_DOMAIN", "")
TOKEN_FILE = Path(os.environ.get("ADGUARDHOME_DOH_TOKEN_FILE", "/var/lib/adguardhome-doh/doh-token"))
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)$"
)
# The RFC 8484 example query: A for www.example.com, base64url without padding.
DOH_PROBE_QUERY = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"


class LockBusy(RuntimeError):
    """Raised when another health run currently owns the lock."""


def _unique_json_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (FileNotFoundError, ValueError, OSError):
        return fallback


def load_policy(path: Path) -> Any:
    """Read and validate policy before changing persisted state or rewrites."""

    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    if isinstance(value, Mapping):
        if "domains" not in value or not isinstance(value["domains"], list):
            raise ValueError("invalid policy domains")
        rows = value["domains"]
        services = value.get("services", {})
    elif isinstance(value, list):
        rows, services = value, {}
    else:
        raise ValueError("invalid policy")

    def valid_hosts(hosts: Any, *, empty_string: bool = False) -> bool:
        if isinstance(hosts, str):
            hosts = [hosts]
        if not isinstance(hosts, list):
            return False
        return all(isinstance(host, str) and (
            (empty_string and not host) or HOST_RE.fullmatch(host.lower())
        ) for host in hosts)

    service_ids = set()
    if isinstance(services, Mapping):
        service_entries = services.items()
    elif isinstance(services, list):
        if not all(isinstance(item, Mapping) for item in services):
            raise ValueError("invalid policy services")
        service_entries = ((item.get("id", item.get("service_id")), item) for item in services)
    else:
        raise ValueError("invalid policy services")
    for service_id, hosts in service_entries:
        if not isinstance(service_id, str) or not service_id or service_id in service_ids:
            raise ValueError("invalid policy service ID")
        service_ids.add(service_id)
        if isinstance(hosts, Mapping):
            if "probes" not in hosts and "hosts" not in hosts:
                raise ValueError("invalid policy service probes")
            hosts = hosts.get("probes", hosts.get("hosts"))
        if not valid_hosts(hosts):
            raise ValueError("invalid policy service probes")

    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("invalid policy domain")
        domain = row.get("domain")
        if not isinstance(domain, str) or not HOST_RE.fullmatch(domain.lower()):
            raise ValueError("invalid policy domain")
        if row.get("kind") not in ("fqdn", "suffix"):
            raise ValueError("invalid policy domain kind")
        for key in ("probe", "probes"):
            if key in row and not valid_hosts(row[key], empty_string=True):
                raise ValueError("invalid policy domain probes")
        owners = row.get("services", row.get("service_ids"))
        if owners is None and row.get("service_id") is not None:
            owners = [row["service_id"]]
        if owners is None:
            owners = []
        if isinstance(owners, str):
            owners = [owners]
        if not isinstance(owners, list) or not all(
            isinstance(owner, str) and owner in service_ids for owner in owners
        ) or (service_ids and not owners):
            raise ValueError("invalid policy domain owners")
    return value


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
        if isinstance(services, Mapping) and services:
            for service_id, value in services.items():
                result[str(service_id)] = set(_as_hosts(value))
            # The service map is authoritative for the catalog format.  Domain
            # ownership rows describe rewrite coverage, not extra TLS probes.
            return {service_id: tuple(sorted(hosts)) for service_id, hosts in sorted(result.items())}
        elif isinstance(services, Sequence) and not isinstance(services, str) and services:
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
        if not service_ids:
            service_ids = [row.get("domain", "")]
        if not isinstance(service_ids, Sequence):
            continue
        hosts = _as_hosts(row.get("probes") or row.get("probe") or row.get("domain", ""))
        for service_id in service_ids:
            if service_id:
                result.setdefault(str(service_id), set()).update(hosts)

    # Every service needs an actual probe.  A malformed/empty service remains
    # unhealthy instead of becoming healthy by vacuous truth.
    return {service_id: tuple(sorted(hosts)) for service_id, hosts in sorted(result.items())}


def probe(host: str) -> bool:
    """Probe local TLS/SNI routing without exposing credentials or URLs."""

    try:
        result = subprocess.run(
            ["/usr/bin/timeout", "8", "/usr/bin/openssl", "s_client", "-brief",
             "-connect", "127.0.0.1:443", "-servername", host,
             "-verify_hostname", host, "-verify_return_error"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    text = result.stdout.decode("utf-8", "replace")
    return (result.returncode == 0 and "Protocol version:" in text
            and "Peer certificate" in text and "Verification: OK" in text)


def doh_probe_target(domain: str = DOMAIN, token_file: Path = TOKEN_FILE) -> Optional[Tuple[str, str]]:
    """Return ``(domain, token)`` for the DoH self-probe, or None when unset."""

    domain = (domain or "").strip().lower()
    if not HOST_RE.fullmatch(domain):
        return None
    try:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not re.fullmatch(r"[a-f0-9]{32,64}", token):
        return None
    return domain, token


def _valid_doh_answer(message: bytes) -> bool:
    """Validate the response to the fixed A query, including compressed names."""

    if len(message) < 12 or len(message) > 65535:
        return False

    def name_at(offset: int) -> Tuple[Tuple[bytes, ...], int]:
        labels = []
        end = None
        visited = set()
        while True:
            if offset >= len(message) or offset in visited:
                raise ValueError("invalid DNS name")
            visited.add(offset)
            length = message[offset]
            if length & 0xc0 == 0xc0:
                if offset + 1 >= len(message):
                    raise ValueError("truncated DNS pointer")
                if end is None:
                    end = offset + 2
                target = ((length & 0x3f) << 8) | message[offset + 1]
                if target >= offset:
                    raise ValueError("invalid DNS pointer")
                offset = target
                continue
            if length & 0xc0 or length > 63:
                raise ValueError("invalid DNS label")
            offset += 1
            if not length:
                break
            if offset + length > len(message):
                raise ValueError("truncated DNS label")
            labels.append(message[offset:offset + length])
            if sum(len(label) + 1 for label in labels) > 254:
                raise ValueError("DNS name too long")
            offset += length
        return tuple(label.lower() for label in labels), end if end is not None else offset

    try:
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!6H", message)
        if (transaction_id != 0 or not flags & 0x8000 or flags & 0x7800
                or flags & 0x0200 or flags & 0x000f or qdcount != 1 or not ancount):
            return False
        name, offset = name_at(12)
        if offset + 4 > len(message):
            return False
        qtype, qclass = struct.unpack_from("!HH", message, offset)
        query_name = (b"www", b"example", b"com")
        if name != query_name or qtype != 1 or qclass != 1:
            return False
        offset += 4
        aliases: Dict[Tuple[bytes, ...], set] = {}
        addresses = set()
        for index in range(ancount + nscount + arcount):
            owner, offset = name_at(offset)
            if offset + 10 > len(message):
                return False
            record_type, record_class, ttl, length = struct.unpack_from("!HHIH", message, offset)
            offset += 10
            end = offset + length
            if end > len(message):
                return False
            # EDNS carries the high bits of the response code in OPT's TTL.
            if index >= ancount + nscount and record_type == 41 and ttl >> 24:
                return False
            if index < ancount and record_class == 1:
                if record_type == 1:
                    if length != 4:
                        return False
                    addresses.add(owner)
                elif record_type == 5:
                    target, name_end = name_at(offset)
                    if name_end != end:
                        return False
                    aliases.setdefault(owner, set()).add(target)
            offset = end
        if offset != len(message):
            return False
        pending, visited = [query_name], set()
        while pending:
            owner = pending.pop()
            if owner in addresses:
                return True
            if owner not in visited:
                visited.add(owner)
                pending.extend(aliases.get(owner, ()))
        return False
    except (ValueError, struct.error):
        return False


def probe_doh(
    domain: str,
    token: str,
    *,
    runner: Callable[..., Any] = subprocess.run,
    attempts: int = 3,
    delay: float = 2.0,
) -> bool:
    """Resolve one name over the public DoH path exactly as a client does.

    The service probes prove only that nginx forwards SNI.  A phone with the
    profile installed crosses nginx, the internal TLS listener, AdGuard Home
    and its upstreams in a single request; this probe walks that same chain
    from loopback so the journal can tell a dead DoH path from a dead route
    between the phone and this host.
    """

    if not HOST_RE.fullmatch(domain) or not re.fullmatch(r"[a-f0-9]{32,64}", token):
        return False
    command = [
        "/usr/bin/curl", "--disable", "--silent", "--show-error",
        "--noproxy", "*", "--config", "-",
        "--resolve", "%s:443:127.0.0.1" % domain,
        "--connect-timeout", "3", "--max-time", "8",
        "--max-filesize", "65535",
        "--header", "accept: application/dns-message",
        "--output", "-", "--write-out", "\n%{http_code} %{content_type}",
    ]
    config = ('url = "https://%s/doh/%s?dns=%s"\n' % (domain, token, DOH_PROBE_QUERY)).encode("ascii")
    for attempt in range(max(1, int(attempts))):
        if attempt:
            time.sleep(delay)
        try:
            result = runner(
                command, input=config, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0 or not isinstance(result.stdout, bytes):
            continue
        body, separator, metadata = result.stdout.rpartition(b"\n")
        fields = metadata.decode("ascii", "replace").split(None, 1)
        if (separator and len(fields) == 2 and fields[0] == "200"
                and fields[1].split(";", 1)[0].strip().lower() == "application/dns-message"
                and _valid_doh_answer(body)):
            return True
    return False


def _doh_self_probe(probe_func: Optional[Callable[[], Optional[bool]]]) -> Optional[bool]:
    if probe_func is not None:
        return probe_func()
    target = doh_probe_target()
    if target is None:
        return None
    return probe_doh(*target)


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


def _health_record(value: Any) -> Tuple[Optional[bool], int, int]:
    """Read a prior service record; missing or malformed health is unknown."""

    if not isinstance(value, Mapping) or "healthy" not in value:
        return None, 0, 0
    healthy = value["healthy"]
    successes = value.get("successes", 0)
    failures = value.get("failures", 0)
    if ((healthy is not None and not isinstance(healthy, bool))
            or type(successes) is not int or successes < 0
            or type(failures) is not int or failures < 0
            or ("probe_uncertain" in value and not isinstance(value["probe_uncertain"], bool))):
        return None, 0, 0
    return healthy, successes, failures


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
        previous = old_state.get(service_id) if isinstance(old_state, Mapping) else None
        healthy, successes, failures = _health_record(previous)
        if results[service_id]:
            successes += 1
            failures = 0
            if healthy is not True and successes >= success_threshold:
                healthy = True
                transitions.append(service_id)
        else:
            failures += 1
            successes = 0
            if healthy is True and failures >= failure_threshold:
                healthy = False
                transitions.append(service_id)
        state[service_id] = {"healthy": healthy, "successes": successes, "failures": failures}
        if healthy is None and (not results[service_id] or (
                isinstance(previous, Mapping) and previous.get("probe_uncertain") is True)):
            state[service_id]["probe_uncertain"] = True
    return state, transitions


def _domain_rows(policy: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(policy, Mapping):
        rows = policy.get("domains", [])
    else:
        rows = policy if isinstance(policy, Sequence) else []
    return (row for row in rows if isinstance(row, Mapping))


def _rules_by_health(policy: Any, state: Mapping[str, Any], public_ip: str) -> Tuple[set, set]:
    """Separate desired rules from rules protected by an unknown owner."""

    desired, unknown = set(), set()
    for row in _domain_rows(policy):
        service_ids = row.get("services", row.get("service_ids"))
        if service_ids is None and row.get("service_id") is not None:
            service_ids = [row["service_id"]]
        if isinstance(service_ids, str):
            service_ids = [service_ids]
        if not service_ids:
            # Compatibility policy has one state key per domain.
            service_ids = [row.get("domain", "")]
        health = [_health_record(state.get(str(service_id)))[0] for service_id in service_ids]
        domain = str(row.get("domain", ""))
        if not domain:
            continue
        keys = {(domain, public_ip)}
        if str(row.get("kind", "")) == "suffix":
            keys.add(("*." + domain, public_ip))
        if any(value is True for value in health):
            desired.update(keys)
        if any(value is None for value in health):
            unknown.update(keys)
    return desired, unknown


def desired_rules(policy: Any, state: Mapping[str, Any], public_ip: str = PUBLIC_IP) -> list:
    """Return desired managed rewrite keys from selected healthy services."""

    desired, _unknown = _rules_by_health(policy, state, public_ip)
    return sorted(desired)


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
    headers = dict(_auth_header(cookie))
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


def _auth_header(credential: str) -> Dict[str, str]:
    """Map a credential produced by :func:`login` onto its HTTP header."""

    if credential.startswith("Basic "):
        return {"Authorization": credential}
    return {"Cookie": credential}


def login() -> str:
    """Return an authorization credential for the local AdGuard Home API.

    Basic authentication is preferred because this worker authenticates once a
    minute forever: a session cookie would leave one stored session per run in
    AdGuard Home's session database for the whole ``session_ttl``.  Releases
    without Basic authentication still get a session cookie.
    """

    values = credentials()
    token = base64.b64encode(
        ("%s:%s" % (values["login"], values["password"])).encode("utf-8")
    ).decode("ascii")
    basic = "Basic " + token
    request = Request(AGH_URL + "/control/status", headers={"Authorization": basic})
    try:
        with urlopen(request, timeout=8) as response:
            if 200 <= response.status < 300:
                return basic
    except Exception:
        pass
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
    desired, unknown = _rules_by_health(policy, state, public_ip)
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
                {"target": {"domain": key[0], "answer": key[1]},
                 "update": {"domain": key[0], "answer": key[1], "enabled": True}})
            changes += 1
    for key, item in by_key.items():
        if key in legacy:
            api("POST", "/control/rewrite/delete", cookie,
                {"domain": key[0], "answer": key[1]})
            changes += 1
            continue
        if key in managed and key not in desired and key not in unknown and item.get("enabled", True):
            api("PUT", "/control/rewrite/update", cookie,
                {"target": {"domain": key[0], "answer": key[1]},
                 "update": {"domain": key[0], "answer": key[1], "enabled": False}})
            changes += 1
    if changes:
        api("POST", "/control/cache_clear", cookie)
    preserved = {key for key, item in by_key.items()
                 if key in managed and key in unknown and item.get("enabled", True)}
    return changes, len(desired | preserved)


def is_global_failure(results: Mapping[str, bool]) -> bool:
    """Report whether every probed service failed in the same cycle.

    A clean sweep may reflect a local fault, such as nginx or the host uplink.
    Preserve the prior health states to avoid withdrawing every rewrite. This
    also preserves rewrites during a remote-only outage. These cases
    cannot be distinguished without an independent signal.
    """

    return bool(results) and not any(results.values())


def run_once(
    *,
    policy_path: Path = POLICY,
    state_path: Path = STATE,
    lock_path: Path = LOCK,
    probe_func: Optional[Callable[[str], bool]] = None,
    reconcile_func: Optional[Callable[[Any, Mapping[str, Any], str], Tuple[int, int]]] = None,
    doh_probe_func: Optional[Callable[[], Optional[bool]]] = None,
) -> Dict[str, int]:
    with health_lock(lock_path):
        policy = load_policy(policy_path)
        old = load_json(state_path, {})
        results = probe_services(policy, probe_func=probe_func)
        doh_ok = _doh_self_probe(doh_probe_func)
        global_failure = is_global_failure(results)
        if global_failure:
            state = {}
            for service_id in sorted(results):
                previous = old.get(service_id) if isinstance(old, Mapping) else None
                healthy, _successes, failures = _health_record(previous)
                state[service_id] = {"healthy": healthy, "successes": 0,
                                     "failures": failures, "probe_uncertain": True}
            transitions: list = []
        else:
            state, transitions = update_health_state(old, results)
        save_json(state_path, state)
        reconcile_call = reconcile_func or reconcile
        changes, active = reconcile_call(policy, state, PUBLIC_IP)
    healthy = sum(1 for item in state.values() if item.get("healthy", False))
    return {"healthy_services": healthy, "active_rules": active,
            "transitions": len(transitions), "changes": changes,
            "global_failure": int(global_failure),
            # -1 means the probe is not configured, never that it failed.
            "doh_ok": -1 if doh_ok is None else int(bool(doh_ok))}


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
    print("healthy_services=%d active_rules=%d transitions=%d changes=%d global_failure=%d doh_ok=%d" % (
        summary["healthy_services"], summary["active_rules"],
        summary["transitions"], summary["changes"], summary.get("global_failure", 0),
        summary.get("doh_ok", -1)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
