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
import hashlib
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence

OLD_NGINX_HOOKS = {
    "pre_hook": re.compile(r"^(?:/usr/bin/)?systemctl\s+stop\s+nginx(?:\.service)?$") ,
    "post_hook": re.compile(r"^(?:/usr/bin/)?systemctl\s+start\s+nginx(?:\.service)?$") ,
}
HOOK_MARKER = "# Managed by adguardhome-doh"


class ReloadUnit(Enum):
    """Units allowed in a new per-lineage hook."""

    SHARED_NGINX = "adguardhome-doh-nginx"


class HookPartialCommitError(OSError):
    """A hook may have been published, but its durable state is unknown."""


def _hook_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_trusted_hook_directory(directory):
    """Open a root-owned directory through root-owned, non-symlink parents."""
    raw = os.fspath(directory)
    if not isinstance(raw, str) or not raw or ".." in raw.split(os.sep):
        raise ValueError("invalid Certbot hook directory")
    parts = [part for part in os.path.abspath(raw).split(os.sep) if part]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(os.sep, flags)
    try:
        def check(terminal):
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or (info.st_mode & 0o022 and
                        (terminal or not info.st_mode & stat.S_ISVTX))):
                raise ValueError("unsafe Certbot hook directory: %s" % directory)

        check(not parts)
        for index, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            check(index == len(parts) - 1)
        return fd
    except OSError as exc:
        os.close(fd)
        raise ValueError("unsafe or inaccessible Certbot hook directory: %s" % directory) from exc
    except BaseException:
        os.close(fd)
        raise


def _check_hook_directory_identity(directory, original):
    fd = _open_trusted_hook_directory(directory)
    try:
        current = os.fstat(fd)
        fields = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                               info.st_uid, info.st_gid)
        if fields(current) != fields(original):
            raise ValueError("Certbot hook directory changed: %s" % directory)
    finally:
        os.close(fd)


def _check_deploy_directory_entry(staging_fd, directory_info):
    named = os.stat("deploy", dir_fd=staging_fd, follow_symlinks=False)
    fields = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if fields(named) != fields(directory_info):
        raise ValueError("Certbot deploy directory changed")


class _HookHasHardlink(ValueError):
    pass


def _check_existing_lineage_hook(directory_fd, name, expected):
    """Accept only the exact file opened and still named in the directory."""
    def check(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o755):
            raise ValueError("unsafe or conflicting Certbot lineage hook: %s" % name)
        if info.st_nlink != 1:
            raise _HookHasHardlink("Certbot lineage hook has hardlinks: %s" % name)

    try:
        named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        check(named_before)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError as exc:
        raise ValueError("unsafe or inaccessible Certbot lineage hook: %s" % name) from exc
    try:
        before = os.fstat(fd)
        check(before)
        if _hook_identity(named_before) != _hook_identity(before):
            raise ValueError("Certbot lineage hook changed during verification: %s" % name)
        # Limit the read even if an unexpected regular file is very large.
        data = bytearray()
        while len(data) <= len(expected):
            chunk = os.read(fd, len(expected) + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        os.fsync(fd)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        check(after)
        check(named_after)
        if (_hook_identity(before) != _hook_identity(after)
                or _hook_identity(after) != _hook_identity(named_after)
                or bytes(data) != expected):
            raise ValueError("Certbot lineage hook changed or conflicts: %s" % name)
    finally:
        os.close(fd)


def _check_existing_lineage_hook_with_retry(directory_fd, name, expected):
    # A concurrent creator briefly has both its temporary and final hardlinks.
    # Never accept that state; wait briefly for its temporary link to disappear.
    for attempt in range(50):
        try:
            _check_existing_lineage_hook(directory_fd, name, expected)
            return
        except _HookHasHardlink:
            if attempt == 49:
                raise
            time.sleep(0.01)


def ensure_lineage_reload_hook(directory: Path, domain: str, unit: ReloadUnit) -> Path:
    """Create, or verify, one root-owned reload hook without overwriting anything.

    The directory must be ``.../renewal-hooks/deploy``. Its trusted parent is
    used for staging because Certbot scans executable dotfiles in deploy too.
    Both directories and their ancestors must already exist and be trusted;
    both directories must be on the same filesystem. A root process that
    changes paths or files after our checks cannot be excluded.
    This does not inspect the legacy hook for a conflicting lineage block,
    remove the new hook on rollback, or integrate service/supervisor actions.
    Callers must handle those operations and a possible partial commit.
    """
    if (not isinstance(domain, str) or len(domain) > 253 or domain != domain.lower()
            or len(domain.split(".")) < 2
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in domain.split("."))):
        raise ValueError("invalid canonical domain for renewal hook")
    if unit is not ReloadUnit.SHARED_NGINX:
        raise ValueError("invalid unit for renewal hook")
    directory = Path(directory)
    if directory.name != "deploy" or directory.parent.name != "renewal-hooks":
        raise ValueError("Certbot hook directory must be renewal-hooks/deploy")
    staging_directory = directory.parent
    name = "adguardhome-doh-reload-" + hashlib.sha256(domain.encode("ascii")).hexdigest()
    path = directory / name
    content = ("#!/bin/sh\n" + HOOK_MARKER + "\n"
               + 'if [ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/' + domain + '" ]; then\n'
               + "    systemctl reload " + unit.value + "\nfi\n").encode("ascii")
    staging_fd = _open_trusted_hook_directory(staging_directory)
    try:
        directory_fd = _open_trusted_hook_directory(directory)
    except BaseException:
        os.close(staging_fd)
        raise
    temporary_fd = None
    temporary_name = None
    published = False
    try:
        directory_info = os.fstat(directory_fd)
        staging_info = os.fstat(staging_fd)
        if directory_info.st_dev != staging_info.st_dev:
            raise ValueError("Certbot hook and staging directories must share a filesystem")
        _check_deploy_directory_entry(staging_fd, directory_info)
        _check_hook_directory_identity(staging_directory, staging_info)
        for _ in range(10):
            temporary_name = ".adguardhome-doh-reload-" + secrets.token_hex(16)
            try:
                temporary_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                       | os.O_NOFOLLOW, 0o600, dir_fd=staging_fd)
                break
            except FileExistsError:
                temporary_name = None
        else:
            raise FileExistsError("cannot create temporary Certbot lineage hook")

        remaining = memoryview(content)
        while remaining:
            count = os.write(temporary_fd, remaining)
            if not count:
                raise OSError("short write to temporary Certbot lineage hook")
            remaining = remaining[count:]
        os.fchmod(temporary_fd, 0o755)
        os.fsync(temporary_fd)
        temporary_info = os.fstat(temporary_fd)
        if (not stat.S_ISREG(temporary_info.st_mode) or temporary_info.st_uid != 0
                or stat.S_IMODE(temporary_info.st_mode) != 0o755 or temporary_info.st_nlink != 1
                or _hook_identity(temporary_info) != _hook_identity(
                    os.stat(temporary_name, dir_fd=staging_fd, follow_symlinks=False))):
            raise ValueError("unsafe or changed temporary Certbot lineage hook")
        _check_hook_directory_identity(staging_directory, staging_info)
        _check_hook_directory_identity(directory, directory_info)
        _check_deploy_directory_entry(staging_fd, directory_info)
        try:
            os.link(temporary_name, name, src_dir_fd=staging_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False)
            published = True
        except FileExistsError:
            pass
        except OSError as exc:
            # Some filesystems can report an error after the namespace operation.
            raise HookPartialCommitError(
                "Certbot lineage hook link failed; the target may already exist: %s" % path
            ) from exc
        os.unlink(temporary_name, dir_fd=staging_fd)
        temporary_name = None
        if published and _hook_identity(os.fstat(temporary_fd)) != _hook_identity(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)):
            raise ValueError("published Certbot lineage hook changed: %s" % path)
        _check_existing_lineage_hook_with_retry(directory_fd, name, content)
        os.fsync(directory_fd)
        os.fsync(staging_fd)
        _check_hook_directory_identity(staging_directory, staging_info)
        _check_hook_directory_identity(directory, directory_info)
        _check_deploy_directory_entry(staging_fd, directory_info)
        _check_existing_lineage_hook_with_retry(directory_fd, name, content)
    except Exception as exc:
        if published:
            raise HookPartialCommitError(
                "Certbot lineage hook may already exist; publication or durability is uncertain: %s"
                % path
            ) from exc
        raise
    finally:
        try:
            if temporary_name is not None and temporary_fd is not None:
                try:
                    named = os.stat(temporary_name, dir_fd=staging_fd, follow_symlinks=False)
                    opened = os.fstat(temporary_fd)
                    if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError("temporary Certbot hook changed; refusing cleanup")
                    os.unlink(temporary_name, dir_fd=staging_fd)
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    error = (HookPartialCommitError if published else OSError)
                    raise error("temporary Certbot hook may remain; hook may already exist: %s" % path) from exc
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            os.close(directory_fd)
            os.close(staging_fd)
    return path


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
