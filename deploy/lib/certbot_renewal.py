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
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

OLD_NGINX_HOOKS = {
    "pre_hook": re.compile(r"^(?:/usr/bin/)?systemctl\s+stop\s+nginx(?:\.service)?$") ,
    "post_hook": re.compile(r"^(?:/usr/bin/)?systemctl\s+start\s+nginx(?:\.service)?$") ,
}
HOOK_MARKER = "# Managed by adguardhome-doh"


def _key(line: str) -> Optional[str]:
    if line.lstrip().startswith("#") or "=" not in line:
        return None
    return line.split("=", 1)[0].strip()


def _old_nginx_hook(line: str) -> bool:
    pattern = OLD_NGINX_HOOKS.get(_key(line))
    return bool(pattern and pattern.fullmatch(line.split("=", 1)[1].strip()))


def needs_migration(text: str) -> bool:
    """Report whether the profile still stops nginx to answer the challenge."""

    for line in text.splitlines():
        key = _key(line)
        if _old_nginx_hook(line):
            return True
        if key == "authenticator" and line.split("=", 1)[1].strip() == "standalone":
            return True
    return False


def migrate(text: str, domain: str, webroot: str) -> str:
    """Return the profile rewritten to answer HTTP-01 from ``webroot``."""

    if not domain or not webroot:
        raise ValueError("domain and webroot are required")
    lines = text.splitlines()
    section = next((i for i, line in enumerate(lines) if line.strip() == "[renewalparams]"), None)
    if section is None:
        lines.append("[renewalparams]")
        section = len(lines) - 1
    end = next((i for i in range(section + 1, len(lines))
                if lines[i].strip().startswith("[") and not lines[i].strip().startswith("[[")), len(lines))
    body, nested, webroot_map = [], [], []
    subsection = None
    seen_authenticator = seen_path = seen_deploy = False
    for line in lines[section + 1:end]:
        stripped = line.strip()
        if stripped.startswith("[[") and stripped.endswith("]]"):
            subsection = stripped
            if subsection != "[[webroot_map]]":
                nested.append(line)
            continue
        if subsection == "[[webroot_map]]":
            if _key(line) != domain:
                webroot_map.append(line)
            continue
        if subsection is not None:
            nested.append(line)
            continue
        key = _key(line)
        if _old_nginx_hook(line):
            continue
        if key == "authenticator":
            body.append("authenticator = webroot")
            seen_authenticator = True
        elif key == "webroot_path":
            body.append("webroot_path = %s," % webroot)
            seen_path = True
        else:
            body.append(line)
            seen_deploy |= key == "deploy_hook"
    if not seen_authenticator:
        body.append("authenticator = webroot")
    if not seen_path:
        body.append("webroot_path = %s," % webroot)
    if not seen_deploy:
        body.append("deploy_hook = systemctl reload nginx")
    prefix = [line for line in lines[:section + 1] if not _old_nginx_hook(line)]
    result = (prefix + body + nested + ["[[webroot_map]]"] + webroot_map
              + ["%s = %s" % (domain, webroot)] + lines[end:])
    return "\n".join(result).rstrip("\n") + "\n"


def ensure_reload_hook(directory: Path, domain: str, *, front: str = "standard") -> Path:
    """Add a lineage-specific directory hook without replacing its deploy_hook."""

    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise ValueError("invalid domain for renewal hook")
    if front not in {"standard", "mtproxyl"}:
        raise ValueError("invalid front for renewal hook")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    directory_stat = directory.lstat()
    if (not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != os.geteuid()
            or directory_stat.st_mode & 0o022):
        raise ValueError("unsafe Certbot hook directory: %s" % directory)
    path = directory / "adguardhome-doh-reload"
    header = "#!/bin/sh\n" + HOOK_MARKER + "\n"
    block = re.compile(
        r'if \[ "\$\{RENEWED_LINEAGE:-\}" = (/etc/letsencrypt/live/[a-z0-9.-]+) \]; then\n'
        r'    systemctl reload (nginx|adguardhome-doh-nginx)\nfi\n'
    )
    lineages = []
    original_stat = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError("refusing to overwrite an unmanaged Certbot deploy hook: %s" % path) from exc
    else:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            original_stat = os.fstat(stream.fileno())
            if (not stat.S_ISREG(original_stat.st_mode) or original_stat.st_nlink != 1
                    or original_stat.st_uid != os.geteuid() or original_stat.st_mode & 0o022):
                raise ValueError("refusing to overwrite an unmanaged Certbot deploy hook: %s" % path)
            existing = stream.read()
        remainder = existing[len(header):] if existing.startswith(header) else existing
        while remainder:
            match = block.match(remainder)
            if match is None:
                raise ValueError("refusing to overwrite an unmanaged Certbot deploy hook: %s" % path)
            lineages.append((match.group(1), match.group(2)))
            remainder = remainder[match.end():]
        if not existing.startswith(header) or not lineages:
            raise ValueError("refusing to overwrite an unmanaged Certbot deploy hook: %s" % path)
    expected = "/etc/letsencrypt/live/" + domain
    unit = "adguardhome-doh-nginx" if front == "mtproxyl" else "nginx"
    if not any(lineage == expected for lineage, _ in lineages):
        lineages.append((expected, unit))
    else:
        lineages = [(lineage, unit if lineage == expected else previous)
                    for lineage, previous in lineages]
    content = header + "".join(
        'if [ "${RENEWED_LINEAGE:-}" = ' + lineage + ' ]; then\n'
        + "    systemctl reload " + selected + "\nfi\n" for lineage, selected in lineages
    )
    fd, temporary = tempfile.mkstemp(prefix=".adguardhome-doh-reload.", dir=str(directory))
    try:
        os.fchmod(fd, 0o755)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        try:
            current_stat = path.lstat()
        except FileNotFoundError:
            current_stat = None
        identity = lambda item: None if item is None else (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(current_stat) != identity(original_stat):
            raise ValueError("Certbot deploy hook changed during preparation: %s" % path)
        current_dir = directory.lstat()
        if ((current_dir.st_dev, current_dir.st_ino, current_dir.st_mode,
             current_dir.st_uid, current_dir.st_gid) !=
                (directory_stat.st_dev, directory_stat.st_ino, directory_stat.st_mode,
                 directory_stat.st_uid, directory_stat.st_gid)):
            raise ValueError("Certbot hook directory changed during preparation: %s" % directory)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


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
    if not backup.exists() and not backup.is_symlink():
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    updated = migrate(text, domain, webroot)
    metadata = path.stat()
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            current = os.fstat(stream.fileno())
            if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(updated)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--webroot", required=True)
    parser.add_argument("--hook-dir", type=Path, required=True)
    parser.add_argument("--front", choices=("standard", "mtproxyl"), default="standard")
    args = parser.parse_args(argv)
    if not args.path.is_file():
        parser.error("renewal profile is missing: %s" % args.path)
    # The shared lineage belongs to MTProxyL; its renewal profile, webroot,
    # and deploy hook are managed there. Add only our private nginx reload.
    if args.front == "mtproxyl":
        ensure_reload_hook(args.hook_dir, args.domain, front=args.front)
        print("shared nginx renewal hook configured; renewal profile unchanged")
        return 0
    changed = migrate_file(args.path, args.domain, args.webroot)
    ensure_reload_hook(args.hook_dir, args.domain, front=args.front)
    print("certbot renewal migrated" if changed else "certbot renewal already uses webroot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
