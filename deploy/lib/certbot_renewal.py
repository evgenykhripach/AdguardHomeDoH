#!/usr/bin/env python3
"""Migrate a Certbot renewal profile from standalone to webroot.

The first releases issued certificates with ``--standalone`` and the hook pair
``systemctl stop nginx`` / ``systemctl start nginx``.  Certbot stores those
options in the lineage's renewal profile and replays them on every renewal, so
roughly every sixty days the server dropped DNS, the admin panel and SNI
forwarding for the length of the ACME exchange - and a failing post hook left
nginx down until somebody noticed.

Rewriting the profile in place keeps the existing certificate, its account and
its history; only the authenticator changes.  The format is Certbot's own
configobj dialect, which nests ``[[webroot_map]]`` inside ``[renewalparams]``
and therefore cannot be round-tripped by :mod:`configparser`, so the file is
edited line by line and left untouched unless it really needs the change.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

DROPPED_KEYS = ("pre_hook", "post_hook")


def _key(line: str) -> Optional[str]:
    if line.lstrip().startswith("#") or "=" not in line:
        return None
    return line.split("=", 1)[0].strip()


def needs_migration(text: str) -> bool:
    """Report whether the profile still stops nginx to answer the challenge."""

    for line in text.splitlines():
        key = _key(line)
        if key in DROPPED_KEYS:
            return True
        if key == "authenticator" and line.split("=", 1)[1].strip() == "standalone":
            return True
    return False


def migrate(text: str, domain: str, webroot: str) -> str:
    """Return the profile rewritten to answer HTTP-01 from ``webroot``."""

    if not domain or not webroot:
        raise ValueError("domain and webroot are required")
    lines = text.splitlines()
    result: List[str] = []
    in_renewalparams = False
    seen_webroot_path = False
    dropped_map = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[[") and stripped.endswith("]]"):
            # Any stored webroot map is replaced wholesale below.
            dropped_map = stripped == "[[webroot_map]]"
            if dropped_map:
                continue
        elif dropped_map:
            if stripped.startswith("["):
                dropped_map = False
            else:
                continue
        if stripped.startswith("[") and not stripped.startswith("[["):
            in_renewalparams = stripped == "[renewalparams]"
        key = _key(line)
        if key in DROPPED_KEYS:
            continue
        if key == "authenticator":
            result.append("authenticator = webroot")
            continue
        if key == "webroot_path":
            result.append("webroot_path = %s," % webroot)
            seen_webroot_path = True
            continue
        result.append(line)
    if "[renewalparams]" not in [line.strip() for line in result]:
        result.append("[renewalparams]")
        in_renewalparams = True
    if not any(_key(line) == "authenticator" for line in result):
        result.append("authenticator = webroot")
    if not seen_webroot_path:
        result.append("webroot_path = %s," % webroot)
    result.append("[[webroot_map]]")
    result.append("%s = %s" % (domain, webroot))
    return "\n".join(result).rstrip("\n") + "\n"


def migrate_file(path: Path, domain: str, webroot: str) -> bool:
    """Rewrite ``path`` when needed; return whether anything changed."""

    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if not needs_migration(text):
        return False
    backup = path.with_suffix(path.suffix + ".pre-webroot")
    if not backup.exists():
        backup.write_text(text, encoding="utf-8")
        backup.chmod(0o600)
    updated = migrate(text, domain, webroot)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(updated, encoding="utf-8")
    temporary.chmod(0o644)
    temporary.replace(path)
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--webroot", required=True)
    args = parser.parse_args(argv)
    changed = migrate_file(args.path, args.domain, args.webroot)
    print("certbot renewal migrated" if changed else "certbot renewal already uses webroot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
