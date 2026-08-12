#!/usr/bin/env python3
"""Strict JSON credentials store for the local AdGuard Home administrator."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Any


LOGIN = "admin"
MODE = 0o600
FIELDS = ("url", "login", "password")


def generate_password() -> str:
    return secrets.token_hex(24)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def _validate(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError("credentials must contain exactly url, login, password")
    if any(not isinstance(value[field], str) or not value[field] for field in FIELDS):
        raise ValueError("credentials fields must be non-empty strings")
    if value["login"] != LOGIN:
        raise ValueError("invalid credentials login")
    return {field: value[field] for field in FIELDS}


def _atomic_write(path: Path, value: dict[str, str]) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(temporary, path)
        os.chmod(path, MODE)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_credentials(path: Path, url: str, password: str, login: str = LOGIN) -> dict[str, str]:
    """Validate and atomically write credentials as private JSON."""

    value = _validate({"url": url, "login": login, "password": password})
    _atomic_write(Path(path), value)
    return value


def read_credentials(path: Path) -> dict[str, str]:
    """Strictly parse credentials JSON; never execute its contents."""

    path = Path(path)
    try:
        if stat.S_IMODE(path.stat().st_mode) != MODE:
            raise ValueError("credentials file must have mode 0600: %s" % path)
    except OSError as exc:
        raise ValueError("cannot stat credentials file %s: %s" % (path, exc)) from exc
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("cannot read credentials file %s: %s" % (path, exc)) from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid credentials JSON: %s" % path) from exc
    return _validate(value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--url")
    parser.add_argument("--password")
    parser.add_argument("--login", default=LOGIN)
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--field", choices=FIELDS)
    args = parser.parse_args(argv)

    if args.read:
        if args.url is not None or args.password is not None:
            parser.error("--read cannot be combined with --url or --password")
        values = read_credentials(args.path)
        if args.field:
            print(values[args.field])
        else:
            print(json.dumps(values, ensure_ascii=False, sort_keys=True))
        return 0

    if args.url is None:
        parser.error("--url is required unless --read is used")
    password = args.password or generate_password()
    value = write_credentials(args.path, args.url, password, args.login)
    # Keep command output useful without printing a secret by default.
    print(value["password"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
