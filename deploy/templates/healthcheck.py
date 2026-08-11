#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen


AGH_URL = os.environ.get("PRESSROLL_AGH_URL", "http://127.0.0.1:3001")
POLICY = Path(os.environ["PRESSROLL_POLICY"])
STATE = Path(os.environ["PRESSROLL_STATE"])
CREDENTIALS = Path(os.environ["PRESSROLL_CREDENTIALS"])
PUBLIC_IP = os.environ["PRESSROLL_PUBLIC_IP"]
SUCCESS_THRESHOLD = int(os.environ.get("PRESSROLL_SUCCESS_THRESHOLD", "3"))
FAILURE_THRESHOLD = int(os.environ.get("PRESSROLL_FAILURE_THRESHOLD", "2"))


def load_json(path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return fallback


def save_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".state.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def credentials():
    values = {}
    for line in CREDENTIALS.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def probe(host):
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


def api(method, path, cookie, body=None):
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


def login():
    values = credentials()
    body = json.dumps({"name": values["login"], "password": values["password"]}).encode()
    request = Request(AGH_URL + "/control/login", data=body,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=8) as response:
        cookies = response.headers.get_all("Set-Cookie") or []
    if not cookies:
        raise RuntimeError("AdGuard login returned no session")
    return cookies[0].split(";", 1)[0]


def desired_rules(policy, state):
    result = {}
    for row in policy:
        if not state.get(row["domain"], {}).get("healthy", False):
            continue
        names = [row["domain"]]
        if row["kind"] == "suffix":
            names.append("*." + row["domain"])
        for name in names:
            result[(name, PUBLIC_IP)] = True
    return result


def reconcile(policy, state):
    cookie = login()
    current = api("GET", "/control/rewrite/list", cookie) or []
    by_key = {}
    for item in current:
        if isinstance(item, dict):
            by_key[(str(item.get("domain", "")), str(item.get("answer", "")))] = item
    desired = desired_rules(policy, state)
    managed = set()
    for row in policy:
        managed.add((row["domain"], PUBLIC_IP))
        if row["kind"] == "suffix":
            managed.add(("*." + row["domain"], PUBLIC_IP))
    changes = 0
    for key in desired:
        item = by_key.get(key)
        if item is None:
            api("POST", "/control/rewrite/add", cookie,
                {"domain": key[0], "answer": key[1], "enabled": True})
            changes += 1
        elif not item.get("enabled", True):
            api("PUT", "/control/rewrite/update", cookie,
                {"target": {"domain": key[0], "answer": key[1]},
                 "update": {"enabled": True}})
            changes += 1
    for key, item in by_key.items():
        if key in managed and key not in desired and item.get("enabled", True):
            api("PUT", "/control/rewrite/update", cookie,
                {"target": {"domain": key[0], "answer": key[1]},
                 "update": {"enabled": False}})
            changes += 1
    if changes:
        api("POST", "/control/cache_clear", cookie)
    return changes, len(desired)


def main():
    policy = load_json(POLICY, [])
    old = load_json(STATE, {})
    state = {row["domain"]: old.get(row["domain"], {
        "healthy": False, "successes": 0, "failures": 0,
    }) for row in policy}
    transitions = 0
    for row in policy:
        item = state[row["domain"]]
        if probe(row.get("probe") or row["domain"]):
            item["successes"] = int(item.get("successes", 0)) + 1
            item["failures"] = 0
            if not item.get("healthy", False) and item["successes"] >= SUCCESS_THRESHOLD:
                item["healthy"] = True
                transitions += 1
        else:
            item["failures"] = int(item.get("failures", 0)) + 1
            item["successes"] = 0
            if item.get("healthy", False) and item["failures"] >= FAILURE_THRESHOLD:
                item["healthy"] = False
                transitions += 1
        state[row["domain"]] = {
            "healthy": bool(item.get("healthy", False)),
            "successes": int(item.get("successes", 0)),
            "failures": int(item.get("failures", 0)),
        }
    changes, active = reconcile(policy, state)
    save_json(STATE, state)
    healthy = sum(1 for item in state.values() if item["healthy"])
    print("healthy_domains=%d active_rules=%d transitions=%d changes=%d" %
          (healthy, active, transitions, changes))


if __name__ == "__main__":
    main()
