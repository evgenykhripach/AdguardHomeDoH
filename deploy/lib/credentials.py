#!/usr/bin/env python3
"""Create and read server-local AdGuard administrator credentials."""

import argparse
import secrets
from pathlib import Path

LOGIN = "admin"


def generate_password():
    return secrets.token_hex(24)


def write_credentials(path, url, password):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text("url=%s\nlogin=%s\npassword=%s\n" % (url, LOGIN, password), encoding="utf-8")
    path.chmod(0o600)


def read_credentials(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    if values.get("login") != LOGIN or not values.get("password") or not values.get("url"):
        raise ValueError("invalid credentials file")
    return values


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--password")
    args = parser.parse_args(argv)
    password = args.password or generate_password()
    write_credentials(args.path, args.url, password)
    print(password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
