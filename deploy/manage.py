#!/usr/bin/env python3
"""Root-only interactive manager for the neutral AdGuard Home deployment."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import io
import json
import os
import re
import shlex
import stat
import types
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, TextIO, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_RELEASES_MODULE = None
_HEALTHCHECK_MODULES: Dict[Path, Any] = {}
MENU_ENTRIES = (
    "Данные доступа",
    "Сервисы и домены",
    "Диагностика системы",
    "Проверить обновления",
    "Откатить обновление",
)
YES_ANSWERS = {"y", "yes", "д", "да"}
INVISIBLE_INPUT = "\ufeff\u200b\u200c\u200d\u2060\u2066\u2067\u2068\u2069"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[1;31m"
ANSI_GREEN = "\033[1;32m"
ANSI_YELLOW = "\033[1;33m"
ANSI_CYAN = "\033[1;36m"
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FULL_BANNER = (
    r"    _    ____   ____ _   _   _    ____  ____  ",
    r"   / \  |  _ \ / ___| | | | / \  |  _ \|  _ \ ",
    r"  / _ \ | | | | |  _| | | |/ _ \ | |_) | | | |",
    r" / ___ \| |_| | |_| | |_| / ___ \|  _ <| |_| |",
    r"/_/   \_\____/ \____|\___/_/   \_\_| \_\____/ ",
)


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _terminal_supports_control(output: TextIO) -> bool:
    return _stream_is_tty(output) and os.environ.get("TERM", "").casefold() != "dumb"


def _color_enabled(output: TextIO) -> bool:
    return _terminal_supports_control(output) and "NO_COLOR" not in os.environ


def _style(value: Any, ansi: str, output: TextIO) -> str:
    text = str(value)
    return "%s%s%s" % (ansi, text, ANSI_RESET) if _color_enabled(output) else text


def _strip_ansi(value: str) -> str:
    return ANSI_RE.sub("", str(value))


def _terminal_width(output: TextIO) -> int:
    try:
        columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    except OSError:
        columns = 80
    return max(40, min(int(columns or 80), 100))


def _clip(value: Any, width: int) -> str:
    text = str(value)
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[:width - 1] + "…"


def _clear_screen(output: TextIO) -> None:
    if _terminal_supports_control(output):
        print("\033[2J\033[H", end="", file=output)


def _section_title(title: str, output: TextIO, width: Optional[int] = None) -> None:
    width = width or _terminal_width(output)
    print(_style(_clip(title, width), ANSI_BOLD + ANSI_CYAN, output), file=output)
    print(_style("─" * min(width, max(24, len(title))), ANSI_DIM, output), file=output)


def _print_wrapped(prefix: str, value: str, output: TextIO, width: Optional[int] = None) -> None:
    width = width or _terminal_width(output)
    available = max(12, width - len(prefix))
    lines = textwrap.wrap(str(value), width=available, break_long_words=True,
                          break_on_hyphens=False) or [""]
    print(prefix + lines[0], file=output)
    continuation = " " * len(prefix)
    for line in lines[1:]:
        print(continuation + line, file=output)


def _is_yes_answer(value: str) -> bool:
    """Accept y/да regardless of terminal CR, case, or pasted invisibles."""

    normalized = str(value).strip().replace("\r", "")
    normalized = normalized.replace("\x1b[200~", "").replace("\x1b[201~", "")
    normalized = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", normalized)
    normalized = "".join(char for char in normalized if char not in INVISIBLE_INPUT)
    return normalized.casefold() in YES_ANSWERS


def _front_mode(state: Mapping[str, Any]) -> str:
    if "front" not in state:
        return "standard"
    if state["front"] == "mtproxyl":
        return "mtproxyl"
    raise RuntimeError("unsupported front mode")


def _require_front_files(root: Path) -> None:
    for relative in (MT_PROXY_SNI_MAP, PRIVATE_NGINX_CONFIG, PRIVATE_NGINX_UNIT) + FRONT_OVERLAY_FILES + FRONT_SITE_FILES:
        path = under_root(root, relative)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("файл общего front отсутствует или небезопасен: %s" % relative)


LEGACY_FULL_FILES = (
    "/opt/AdGuardHome/AdGuardHome",
    "/opt/AdGuardHome/AdGuardHome.yaml",
    "/etc/nginx/sites-enabled/adguardhome-doh",
    "/etc/nginx/stream.d/adguardhome-doh.conf",
    "/etc/adguardhome-doh/health-policy.json",
    "/etc/adguardhome-doh/runtime.env",
    "/etc/adguardhome-doh/catalog",
    "/var/lib/adguardhome-doh/install.json",
    "/var/lib/adguardhome-doh/enabled-services.json",
    "/var/lib/adguardhome-doh/health-state.json",
    "/var/lib/adguardhome-doh/doh-token",
    "/var/lib/adguardhome-doh/admin-credentials.json",
    "/var/www/adguardhome-doh",
    "/etc/systemd/system/adguardhome-doh.service",
    "/etc/systemd/system/adguardhome-doh-health.service",
    "/etc/systemd/system/adguardhome-doh-health.timer",
    "/usr/local/libexec/adguardhome-doh",
    "/usr/local/libexec/adguardhome-doh/VERSION",
    "/usr/local/sbin/adguardhome-doh",
)
LEGACY_NO_BINARY_FILES = LEGACY_FULL_FILES[1:]

# New snapshots record individual installer-owned files, not whole directories.
# This preserves unrelated files added to those directories after a snapshot.
MT_PROXY_SNI_MAP = "/etc/adguardhome-doh/mtproxyl-sni.map"
PRIVATE_NGINX_CONFIG = "/etc/adguardhome-doh/mtproxyl-nginx.conf"
PRIVATE_NGINX_UNIT = "/etc/systemd/system/adguardhome-doh-nginx.service"
PRIVATE_NGINX_HTTP_SITE = "/etc/adguardhome-doh/mtproxyl-http-site.conf"
PRIVATE_NGINX_STREAM_SITE = "/etc/adguardhome-doh/mtproxyl-stream-site.conf"
FRONT_SITE_FILES = (PRIVATE_NGINX_HTTP_SITE, PRIVATE_NGINX_STREAM_SITE)
MTPROXY_NGINX_BINARY = "/opt/mtproxyl-nginx/sbin/nginx"
MTPROXY_NGINX_CONFIG = "/opt/mtproxyl-nginx/conf/nginx.conf"
MTPROXY_RUNTIME_CONFIG = "/run/adguardhome-doh/mtproxyl-nginx.conf"
MTPROXY_RELOAD_HELPER = "/usr/local/libexec/adguardhome-doh/mtproxyl_reload.py"
MTPROXY_FRONT_LOCK = "/run/lock/adguardhome-doh-front.lock"
MTPROXY_HELPERS = tuple("/usr/local/libexec/adguardhome-doh/" + name for name in (
    "mtproxyl_front.py", "mtproxyl_runtime.py", "mtproxyl_controller.py", "mtproxyl_reload.py"))
FRONT_OVERLAY_FILES = (
    "/usr/local/libexec/adguardhome-doh/mtproxyl_front.py",
    "/etc/adguardhome-doh/mtproxyl-http.conf",
    "/etc/systemd/system/mtproxyl-pq-nginx.service.d/adguardhome-doh.conf",
)
FRONT_MANAGED_FILES = (
    MT_PROXY_SNI_MAP,
    PRIVATE_NGINX_CONFIG,
    PRIVATE_NGINX_UNIT,
    "/etc/systemd/system/multi-user.target.wants/adguardhome-doh-nginx.service",
) + FRONT_OVERLAY_FILES + FRONT_SITE_FILES
SYSTEM_NGINX_FILES = (
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/adguardhome-doh",
    "/etc/nginx/stream.d/adguardhome-doh.conf",
    "/etc/systemd/system/nginx.service.d/adguardhome-doh.conf",
    "/etc/systemd/system/multi-user.target.wants/nginx.service",
)
MANAGED_FILES = tuple(
    path for path in LEGACY_FULL_FILES
    if path not in {
        "/etc/adguardhome-doh/catalog", "/var/www/adguardhome-doh",
        "/usr/local/libexec/adguardhome-doh",
    }
) + tuple("/etc/adguardhome-doh/catalog/" + name for name in (
    "services.csv", "domains.csv", "service-domains.csv", "service-probes.csv",
)) + tuple("/usr/local/libexec/adguardhome-doh/" + name for name in (
    "healthcheck.py", "render_config.py", "render_runtime.py", "releases.py",
    "certbot_renewal.py",
)) + (
    "/usr/local/sbin/adguardhome-doh-diag",
    "/var/lib/adguardhome-doh/install-complete",
    "/etc/nginx/nginx.conf",
    "/etc/systemd/system/nginx.service.d/adguardhome-doh.conf",
    "/etc/sysctl.d/90-adguardhome-doh.conf",
    "/etc/modules-load.d/adguardhome-doh.conf",
    "/etc/logrotate.d/adguardhome-doh",
    "/etc/letsencrypt/renewal-hooks/deploy/adguardhome-doh-reload",
    "/etc/adguardhome-doh/compat-policy.csv",
    "/etc/systemd/system/multi-user.target.wants/adguardhome-doh.service",
    "/etc/systemd/system/multi-user.target.wants/nginx.service",
    "/etc/systemd/system/timers.target.wants/adguardhome-doh-health.timer",
) + FRONT_MANAGED_FILES
HEALTH_LOCK = "/run/lock/adguardhome-doh-health.lock"
OPERATION_LOCK = "/run/lock/adguardhome-doh-operations.lock"
BACKUP_VERSION = 4
BACKUP_WITH_OWNERS_VERSION = 3
BACKUP_WITHOUT_OWNERS_VERSION = 2
BACKUP_OPERATIONS = {"update", "service-change", "recovery", "manual"}


class _FileRecoveryError(RuntimeError):
    """Previous files could not be restored and runtime may be inconsistent."""


class _StopBeforeRestoreError(_FileRecoveryError):
    """AdGuard may still be running, so the saved files were not restored."""


class _FrontRecoveryError(_FileRecoveryError):
    """The previously active MTProxy map could not be reloaded."""


@contextlib.contextmanager
def health_lock(root: Path = Path("/")):
    """Serialize mutations with the health worker and installer."""

    path = under_root(Path(root), HEALTH_LOCK)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def operation_lock(root: Path = Path("/")):
    """Serialize the whole manager operation with installer activation."""

    path = under_root(Path(root), OPERATION_LOCK)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def under_root(root: Path, path: str) -> Path:
    root = Path(root)
    return Path(path) if root == Path("/") else root / path.lstrip("/")


def _read_json(path: Path, fallback: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return fallback


def _write_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _copy_path(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if source.is_dir() and not source.is_symlink():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination, follow_symlinks=False)
    _preserve_owners(source, destination)


def _preserve_owners(source: Path, destination: Path) -> None:
    source_stat = source.lstat()
    destination_stat = destination.lstat()
    if (source_stat.st_uid, source_stat.st_gid) != (destination_stat.st_uid, destination_stat.st_gid):
        os.chown(destination, source_stat.st_uid, source_stat.st_gid, follow_symlinks=False)
        # chown can clear permission bits; restore the source metadata.
        shutil.copystat(source, destination, follow_symlinks=False)
    if source.is_dir() and not source.is_symlink():
        for child in source.iterdir():
            _preserve_owners(child, destination / child.name)


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _valid_domain(domain: str) -> bool:
    labels = domain.split(".")
    return bool(domain and len(domain) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ))


def _managed_paths(domain: str = "", *, include_pre_webroot: bool = True,
                   include_front_map: bool = True) -> Tuple[str, ...]:
    managed = MANAGED_FILES if include_front_map else tuple(
        path for path in MANAGED_FILES if path not in FRONT_MANAGED_FILES
    )
    if not domain:
        return managed
    if not _valid_domain(domain):
        raise RuntimeError("invalid backup domain")
    paths = managed + (
        "/etc/letsencrypt/renewal/%s.conf" % domain,
        "/var/www/adguardhome-doh/%s.mobileconfig" % domain,
    )
    if include_pre_webroot:
        paths += ("/etc/letsencrypt/renewal/%s.conf.pre-webroot" % domain,)
    return paths


def _path_digest(path: Path, *, include_owners: bool = True) -> str:
    """Hash file bytes, directory members, symlinks, permissions and owners."""

    digest = hashlib.sha256()

    def visit(current: Path, name: str) -> None:
        stat = current.lstat()
        digest.update((name + "\0" + oct(stat.st_mode & 0o7777) + "\0").encode())
        if include_owners:
            digest.update(("%d:%d\0" % (stat.st_uid, stat.st_gid)).encode())
        if current.is_symlink():
            digest.update(b"link\0" + os.fsencode(os.readlink(current)))
        elif current.is_dir():
            digest.update(b"directory\0")
            for child in sorted(current.iterdir(), key=lambda item: item.name):
                visit(child, name + "/" + child.name)
        elif current.is_file():
            digest.update(b"file\0")
            with current.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        else:
            raise RuntimeError("unsupported backup file type: %s" % current)

    visit(Path(path), "")
    return digest.hexdigest()


def create_backup(
    root: Path = Path("/"), backup_dir: Optional[Path] = None, *,
    operation: str = "manual", target_version: str = "", domain: str = "",
) -> Path:
    """Copy installer-owned paths and record integrity and operation metadata."""

    root = Path(root)
    if operation not in BACKUP_OPERATIONS:
        raise RuntimeError("invalid backup operation")
    state = _read_json(under_root(root, "/var/lib/adguardhome-doh/install.json"), {})
    if not domain:
        domain = str(state.get("domain", "")) if isinstance(state, Mapping) else ""
    if isinstance(state, Mapping) and state.get("front") == "mtproxyl":
        for relative in FRONT_SITE_FILES:
            source = under_root(root, relative)
            if not source.is_file() or source.is_symlink():
                raise RuntimeError("файл общего front отсутствует или небезопасен: %s" % relative)
    paths = _managed_paths(domain)
    if backup_dir is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_dir = under_root(root, "/var/backups/adguardhome-doh") / timestamp
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = []
    for index, relative in enumerate(paths):
        source = under_root(root, relative)
        destination = backup_dir / ("%03d-%s" % (index, Path(relative).name))
        present = source.exists() or source.is_symlink()
        entry = {"path": relative, "backup": destination.name, "present": present}
        if present:
            if source.is_dir() and not source.is_symlink():
                raise RuntimeError("managed file is a directory: %s" % relative)
            _copy_path(source, destination)
            entry["sha256"] = _path_digest(destination)
            if entry["sha256"] != _path_digest(source):
                raise RuntimeError("backup source changed while copying: %s" % relative)
        manifest.append(entry)
    version_path = under_root(root, "/usr/local/libexec/adguardhome-doh/VERSION")
    try:
        version_before = version_path.read_text(encoding="utf-8").strip()
    except OSError:
        version_before = ""
    document = {
        "version": BACKUP_VERSION, "operation": operation, "domain": domain,
        "version_before": version_before, "version_after": target_version,
        "files": manifest,
    }
    if operation == "update":
        document["status"] = "pending"
    _write_json(backup_dir / "manifest.json", document)
    return backup_dir


def _validated_backup_manifest(backup_dir: Path) -> list[Tuple[str, str, bool]]:
    manifest_path = Path(backup_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("backup manifest is missing")
    manifest = _read_json(manifest_path, None)
    legacy = isinstance(manifest, list)
    if legacy:
        items = manifest
        expected = None
        version = 0
    elif isinstance(manifest, Mapping):
        version = manifest.get("version")
        if (version not in (BACKUP_VERSION, BACKUP_WITH_OWNERS_VERSION, BACKUP_WITHOUT_OWNERS_VERSION)
                or manifest.get("operation") not in BACKUP_OPERATIONS
                or not isinstance(manifest.get("domain"), str)
                or not isinstance(manifest.get("version_before"), str)
                or not isinstance(manifest.get("version_after"), str)):
            raise RuntimeError("backup manifest is invalid")
        if manifest.get("operation") == "update":
            allowed = ({"pending", "applied"} if version >= BACKUP_WITH_OWNERS_VERSION
                       else {None, "pending", "applied"})
            if manifest.get("status") not in allowed:
                raise RuntimeError("backup manifest is invalid")
        expected = set(_managed_paths(
            manifest["domain"], include_pre_webroot=version >= BACKUP_WITH_OWNERS_VERSION,
            include_front_map=version >= BACKUP_VERSION,
        ))
        items = manifest.get("files")
    else:
        raise RuntimeError("backup manifest is invalid")
    if not isinstance(items, list) or not items:
        raise RuntimeError("backup manifest is invalid")

    entries = []
    seen_paths = set()
    seen_backups = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise RuntimeError("backup manifest is invalid")
        relative = item.get("path")
        if (
            not isinstance(relative, str)
            or relative not in (set(LEGACY_FULL_FILES) if legacy else expected)
            or relative in seen_paths
        ):
            raise RuntimeError("backup manifest is invalid")
        seen_paths.add(relative)
        present = item.get("present")
        if not isinstance(present, bool):
            raise RuntimeError("backup manifest is invalid")
        backup_name = item.get("backup")
        if (
            not isinstance(backup_name, str)
            or not backup_name
            or backup_name in (".", "..")
            or Path(backup_name).name != backup_name
            or "/" in backup_name
            or "\\" in backup_name
            or backup_name in seen_backups
        ):
            raise RuntimeError("backup manifest is invalid")
        seen_backups.add(backup_name)
        backup = Path(backup_dir) / backup_name
        if present and not (backup.exists() or backup.is_symlink()):
            raise RuntimeError("backup manifest is incomplete")
        if present:
            try:
                actual = _path_digest(backup, include_owners=version >= BACKUP_WITH_OWNERS_VERSION)
            except (OSError, ValueError) as exc:
                raise RuntimeError("backup data is unreadable") from exc
            if not legacy and (not isinstance(item.get("sha256"), str)
                               or actual != item["sha256"]):
                raise RuntimeError("backup checksum mismatch: %s" % relative)
        elif not legacy and "sha256" in item:
            raise RuntimeError("backup manifest is invalid")
        entries.append((relative, backup_name, present))
    known_legacy = (set(LEGACY_FULL_FILES), set(LEGACY_NO_BINARY_FILES))
    previous_v4 = (version == BACKUP_VERSION and seen_paths in (
        expected - set(FRONT_SITE_FILES),
        expected - set(FRONT_SITE_FILES + FRONT_OVERLAY_FILES),
    ))
    if (legacy and seen_paths not in known_legacy) or (not legacy and seen_paths != expected and not previous_v4):
        raise RuntimeError("backup manifest is incomplete")
    return entries


def _restore_targets(backup_dir: Path, root: Path) -> list[Tuple[Path, Path, bool]]:
    entries = _validated_backup_manifest(backup_dir)
    legacy = isinstance(_read_json(Path(backup_dir) / "manifest.json", None), list)
    targets = []
    for relative, backup_name, present in entries:
        target = under_root(root, relative)
        backup = Path(backup_dir) / backup_name
        legacy_directory = legacy and relative in {
            "/etc/adguardhome-doh/catalog", "/var/www/adguardhome-doh",
            "/usr/local/libexec/adguardhome-doh",
        }
        if legacy_directory and not present:
            continue
        if legacy_directory and backup.is_dir() and not backup.is_symlink():
            # Only overwrite files actually recorded in the old snapshot;
            # later additions and unrelated files survive.
            for child in sorted(backup.rglob("*")):
                if child.is_symlink() or not child.is_dir():
                    targets.append((target / child.relative_to(backup), child, True))
        else:
            targets.append((target, backup, present))
    return targets


def _require_saved_front_sites(saved_state: Any, by_path: Mapping[str, Tuple[Optional[Path], bool]]) -> None:
    if not isinstance(saved_state, Mapping) or _front_mode(saved_state) != "mtproxyl":
        return
    for relative in FRONT_SITE_FILES:
        saved, present = by_path.get(relative, (None, False))
        if not present or saved is None or not saved.is_file() or saved.is_symlink():
            raise RuntimeError("снимок не содержит необходимые файлы DoH для MTProxy: %s" % relative)


def _restore_backup(backup_dir: Path, root: Path = Path("/"), *,
                    skip_targets: Iterable[Path] = ()) -> None:
    skipped = set(skip_targets)
    for target, backup, present in _restore_targets(backup_dir, root):
        if target in skipped:
            continue
        if target.is_dir() and not target.is_symlink():
            raise RuntimeError("refusing to replace a directory with a managed file: %s" % target)
        if present:
            _remove_path(target)
            _copy_path(backup, target)
        else:
            _remove_path(target)


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % target.name, dir=str(target.parent))
    os.close(fd)
    temporary_path = Path(temporary)
    try:
        _copy_path(source, temporary_path)
        os.replace(temporary_path, target)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _check_incomplete_transactions(root: Path) -> None:
    backup_root = under_root(root, "/var/backups/adguardhome-doh")
    if not backup_root.is_dir():
        return
    for marker in backup_root.glob("*/transaction.json"):
        transaction = _read_json(marker, None)
        # Historical transaction.json lists were left behind even after
        # success, so they cannot establish whether an operation completed.
        if isinstance(transaction, list):
            continue
        if not isinstance(transaction, Mapping) or transaction.get("version") != 1:
            raise RuntimeError("unrecognised transaction marker: %s" % marker)
        if transaction.get("state") not in {"committed", "restored"}:
            raise RuntimeError("unfinished transaction requires manual recovery: %s" % marker)


def _restore_transaction_entries(entries: Sequence[Tuple[Path, Path, bool]]) -> None:
    for target, backup, present in reversed(entries):
        if target.is_dir() and not target.is_symlink() and not (present and backup.is_dir()):
            raise RuntimeError("refusing to replace a directory with a managed file: %s" % target)
        if present:
            if backup.is_dir() and not backup.is_symlink():
                if target.is_symlink() or (target.exists() and not target.is_dir()):
                    _remove_path(target)
                shutil.copytree(backup, target, symlinks=True, dirs_exist_ok=True)
                _preserve_owners(backup, target)
            else:
                _remove_path(target)
                _copy_path(backup, target)
        else:
            _remove_path(target)


def _transaction_marker(path: Path, state: str, entries: Sequence[Tuple[Path, Path, bool]]) -> None:
    _write_json(path, {
        "version": 1, "state": state,
        "entries": [{"target": str(target), "backup": backup.name, "present": present}
                    for target, backup, present in entries],
    })


def activate_transaction(
    targets: Mapping[Path, Path],
    backup_dir: Path,
    *,
    validate: Optional[Callable[[], None]] = None,
    on_failure: Optional[Callable[[], None]] = None,
    root: Path = Path("/"),
) -> Path:
    """Back up, atomically activate staged files, validate, and restore on error."""

    backup_dir = Path(backup_dir)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    entries = []
    for index, (target, stage) in enumerate(targets.items()):
        target = Path(target)
        stage = Path(stage)
        if not stage.is_file():
            raise RuntimeError("staged file is missing: %s" % stage.name)
        backup = backup_dir / ("%03d-%s" % (index, target.name))
        present = target.exists() or target.is_symlink()
        entries.append((target, stage, backup, present))
        if present:
            _copy_path(target, backup)
    saved = [(target, backup, present) for target, _stage, backup, present in entries]
    marker = backup_dir / "transaction.json"
    _transaction_marker(marker, "prepared", saved)
    try:
        for target, stage, _backup, _present in entries:
            _atomic_copy(stage, target)
        if validate is not None:
            validate()
        _transaction_marker(marker, "committed", saved)
    except BaseException as original:
        if on_failure is not None:
            try:
                on_failure()
            except BaseException as stop_error:
                raise _StopBeforeRestoreError(
                    "activation failed; cannot stop AdGuard before restoring files: %s; "
                    "transaction remains pending at %s" % (stop_error, marker)
                ) from original
        try:
            _restore_transaction_entries(saved)
            _transaction_marker(marker, "restored", saved)
        except BaseException as restore_error:
            raise _FileRecoveryError("activation failed; restoring previous files also failed: %s"
                                     % restore_error) from original
        raise
    return backup_dir


def smoke_https_sni(
    domain: str, *, runner: Callable[..., Any] = subprocess.run,
    attempts: int = 3, delay: int = 2,
) -> None:
    """Verify the local public TLS path using the installation domain as SNI."""

    command = [
        "curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
        "--resolve", "%s:443:127.0.0.1" % domain,
        "--connect-timeout", "3", "--max-time", "8",
        "--output", "/dev/null", "https://%s/" % domain,
    ]
    last_error: Optional[BaseException] = None
    for attempt in range(attempts):
        try:
            runner(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return
        except (OSError, subprocess.SubprocessError) as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(delay)
    raise RuntimeError(
        "HTTPS/SNI smoke check failed for %s after %d attempts" % (domain, attempts)
    ) from last_error


def _load_healthcheck(root: Path) -> Any:
    """Keep the current probe in memory across a rollback of its installed file."""

    path = under_root(root, "/usr/local/libexec/adguardhome-doh/healthcheck.py")
    if path in _HEALTHCHECK_MODULES:
        return _HEALTHCHECK_MODULES[path]
    if not path.is_file():
        raise RuntimeError("DoH health probe is unavailable")
    import importlib.util
    spec = importlib.util.spec_from_file_location("adguardhome_doh_health_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("DoH health probe is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "probe_doh", None)):
        raise RuntimeError("DoH health probe is unavailable")
    _HEALTHCHECK_MODULES[path] = module
    return module


def smoke_doh(
    root: Path, domain: str, *, runner: Callable[..., Any] = subprocess.run,
    attempts: int = 3, delay: int = 2,
) -> None:
    try:
        token = _runtime_paths(root)["token"].read_text(encoding="utf-8").strip()
        probe = _load_healthcheck(root).probe_doh
        ok = probe(domain, token, runner=runner, attempts=attempts, delay=delay)
    except Exception:
        raise RuntimeError("DoH smoke check failed") from None
    if not ok:
        raise RuntimeError("DoH smoke check failed")


def reload_runtime_services(
    root: Path = Path("/"), domain: str = "",
    runner: Callable[..., Any] = subprocess.run,
    smoke_attempts: int = 3, smoke_delay: int = 2,
) -> None:
    """Load newly activated AdGuard and nginx configuration on a live host."""

    if Path(root) != Path("/"):
        return
    if not domain:
        raise RuntimeError("installation domain is unavailable")
    state = _read_json(_runtime_paths(Path(root))["install"], {})
    if not isinstance(state, Mapping):
        raise RuntimeError("install state is unavailable")
    front = _front_mode(state)
    runner(["systemctl", "restart", "adguardhome-doh"], check=True)
    if front == "mtproxyl":
        runner(["systemctl", "reload", "adguardhome-doh-nginx"], check=True)
        smoke_doh(root, domain, runner=runner, attempts=smoke_attempts, delay=smoke_delay)
    else:
        runner(["systemctl", "reload", "nginx"], check=True)
        smoke_https_sni(
            domain, runner=runner, attempts=smoke_attempts, delay=smoke_delay
        )


def _stop_adguard(root: Path, runner: Optional[Callable[..., Any]] = None) -> None:
    if Path(root) == Path("/"):
        (runner or subprocess.run)(["systemctl", "stop", "adguardhome-doh"], check=True)


def _recover_runtime_after_failure(
    root: Path, domain: str, original: BaseException,
    runner: Optional[Callable[..., Any]] = None,
) -> None:
    if Path(root) != Path("/"):
        return
    if isinstance(original, _StopBeforeRestoreError):
        raise RuntimeError("%s; AdGuard may still be running and previous files were not restored"
                           % original) from original
    if isinstance(original, _FrontRecoveryError):
        raise RuntimeError("%s; AdGuard left stopped because MTProxy recovery failed"
                           % original) from original
    if isinstance(original, _FileRecoveryError):
        raise RuntimeError("%s; AdGuard left stopped because files could not be restored"
                           % original) from original
    runner = runner or subprocess.run
    try:
        if domain:
            reload_runtime_services(root, domain, runner=runner)
        else:
            runner(["systemctl", "start", "adguardhome-doh"], check=True)
    except BaseException as recovery_error:
        raise RuntimeError("operation failed; restoring previous runtime also failed: %s"
                           % recovery_error) from original


def _validate_staged_adguard(
    root: Path, yaml_path: Path, binary_path: Path,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    if not yaml_path.is_file():
        raise RuntimeError("staged AdGuard configuration is missing")
    if Path(root) != Path("/"):
        # Isolated roots do not contain runnable production binaries.
        return
    runner([str(binary_path), "--check-config", "-c", str(yaml_path),
            "-w", str(under_root(root, "/var/lib/AdGuardHome"))],
           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)



def _read_root_owned(path: Path, mode: int) -> bytes:
    """Read a root-owned file through root-owned, non-writable directories."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("absolute path required")
    for directory in (path.parent, *path.parent.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError("unsafe parent directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode or before.st_size > 1048576):
            raise ValueError("unsafe file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(1048577)
        after = os.fstat(fd)
        current = path.lstat()
        identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                               st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(data) > 1048576 or identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError("file changed")
        return data
    finally:
        os.close(fd)


def _verify_private_mtproxy(root: Path, runner: Callable[..., Any]) -> None:
    state = _read_json(_runtime_paths(root)["install"], {})
    domain = state.get("domain") if isinstance(state, Mapping) else None
    admin = state.get("admin_host") if isinstance(state, Mapping) else None
    if not isinstance(domain, str) or not _valid_domain(domain) or not isinstance(admin, str) or not _valid_domain(admin):
        raise ValueError("shared front state is invalid")
    helpers = {path: _read_root_owned(under_root(root, path), 0o755) for path in MTPROXY_HELPERS}
    _read_root_owned(under_root(root, "/etc/systemd/system/mtproxyl-pq-nginx.service.d/adguardhome-doh.conf"), 0o644)
    runtime_bytes = _read_root_owned(under_root(root, MTPROXY_RUNTIME_CONFIG), 0o600)
    # The installed parser checks the exact overlay placement and all required
    # includes; loading the already-read root-owned bytes avoids path races.
    module = types.ModuleType("_doh_verified_front")
    previous = sys.modules.get(module.__name__)
    sys.modules[module.__name__] = module
    try:
        exec(compile(helpers[MTPROXY_HELPERS[0]], MTPROXY_HELPERS[0], "exec"), module.__dict__)
        text = runtime_bytes.decode("utf-8")
        _, overlay, admin_overlay = module._strip_with_admin(text)
        if not overlay or not admin_overlay:
            raise ValueError("shared overlay is missing")
        module.unpatch(text, domain, admin)
    finally:
        if previous is None:
            sys.modules.pop(module.__name__, None)
        else:
            sys.modules[module.__name__] = previous
    result = runner(["systemctl", "show", "--property=ExecReload", "--value", "mtproxyl-pq-nginx"],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
    if not isinstance(output, str):
        raise ValueError("ExecReload unavailable")
    match = re.fullmatch(r"\{ path=/usr/bin/python3 ; argv\[\]=(.+?) ; ignore_errors=no ; [^{}]*\}", output.strip())
    if not match:
        raise ValueError("unexpected ExecReload")
    args = shlex.split(match.group(1), comments=False, posix=True)
    expected = ["/usr/bin/python3", MTPROXY_RELOAD_HELPER, "reload", "--source", MTPROXY_NGINX_CONFIG,
                "--runtime", MTPROXY_RUNTIME_CONFIG, "--domain", domain, "--admin-host", admin,
                "--nginx-bin", MTPROXY_NGINX_BINARY, "--lock", MTPROXY_FRONT_LOCK,
                "--main-pid", "$MAINPID", "--cgroup", "/system.slice/mtproxyl-pq-nginx.service"]
    if args != expected:
        raise ValueError("unexpected ExecReload arguments")

def _verify_mtproxyl_active_config(root: Path, runner: Callable[..., Any], *, allow_private: bool = False, include_config: bool = False) -> Any:
    """Require a stable MTProxy nginx master using the supported generated config."""

    if Path(root) != Path("/"):
        return None

    def main_pid() -> int:
        result = runner(["systemctl", "show", "--property=MainPID", "--value", "mtproxyl-pq-nginx"],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if getattr(result, "returncode", 1) != 0:
            raise ValueError("MainPID unavailable")
        raw = getattr(result, "stdout", b"")
        text = raw.decode("ascii") if isinstance(raw, bytes) else raw
        if not isinstance(text, str) or not re.fullmatch(r"[1-9][0-9]*", text.strip()):
            raise ValueError("invalid MainPID")
        return int(text.strip())

    try:
        pid = main_pid()
        raw = under_root(root, "/proc/%d/cmdline" % pid).read_bytes()
        executable = os.readlink(under_root(root, "/proc/%d/exe" % pid))
        checked_pid = main_pid()
        if not raw.endswith(b"\0"):
            raise ValueError("unterminated command line")
        arguments = raw.rstrip(b"\0").split(b"\0")
        prefix = b"nginx: master process "
        if len(arguments) == 1 and arguments[0].startswith(prefix):
            argv = shlex.split(arguments[0][len(prefix):].decode("utf-8"), comments=False, posix=True)
        else:
            argv = [os.fsdecode(arg) for arg in arguments]
        if (pid != checked_pid or len(argv) < 3 or any(not arg for arg in argv)
                or executable != MTPROXY_NGINX_BINARY
                or argv[:2] != [MTPROXY_NGINX_BINARY, "-c"]
                or argv[2] not in ((MTPROXY_NGINX_CONFIG, MTPROXY_RUNTIME_CONFIG) if allow_private else (MTPROXY_NGINX_CONFIG,))
                or any(arg.startswith("-c") for arg in argv[3:])):
            raise ValueError("active config is custom or ambiguous")
        if argv[2] == MTPROXY_RUNTIME_CONFIG:
            _verify_private_mtproxy(root, runner)
            if main_pid() != pid:
                raise ValueError("master changed during private verification")
        return (pid, argv[2]) if include_config else pid
    except (OSError, UnicodeError, ValueError, SyntaxError, ImportError, AttributeError, TypeError, subprocess.SubprocessError):
        raise RuntimeError("активная конфигурация MTProxy не подтверждена; custom mode не поддерживается") from None


def _reload_mtproxyl_map(root: Path, runner: Callable[..., Any]) -> None:
    if Path(root) != Path("/"):
        return
    pid, config = _verify_mtproxyl_active_config(root, runner, allow_private=True, include_config=True)
    runner([MTPROXY_NGINX_BINARY, "-t", "-c", config],
           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if _verify_mtproxyl_active_config(root, runner, allow_private=True, include_config=True) != (pid, config):
        raise RuntimeError("процесс MTProxy изменился перед reload")
    runner(["systemctl", "reload", "mtproxyl-pq-nginx"], check=True)


def _reload_restored_runtime(root: Path, domain: str, runner: Callable[..., Any], *,
                             reload_front: Optional[Callable[[], None]] = None) -> None:
    if root != Path("/"):
        return
    runner(["systemctl", "daemon-reload"], check=False)
    # nginx includes the whole host configuration; it cannot be checked in
    # isolation. A failed live check triggers restoration of pre-rollback files.
    state = _read_json(_runtime_paths(root)["install"], {})
    if not isinstance(state, Mapping):
        raise RuntimeError("install state is unavailable")
    command = (["/usr/sbin/nginx", "-t", "-c", PRIVATE_NGINX_CONFIG]
               if _front_mode(state) == "mtproxyl" else ["nginx", "-t"])
    runner(command, check=True)
    if reload_front is not None:
        reload_front()
    reload_runtime_services(root, domain, runner=runner)
    runner(["systemctl", "restart", "adguardhome-doh-health.timer"], check=True)


def _validate_shared_front_restore(
    root: Path, backup_dir: Path, domain: str, current_state: Any, saved_state: Any,
    by_path: Mapping[str, Tuple[Optional[Path], bool]], runner: Callable[..., Any],
) -> None:
    manifest = _read_json(backup_dir / "manifest.json", None)
    if (not isinstance(current_state, Mapping) or not isinstance(saved_state, Mapping)
            or _front_mode(current_state) != "mtproxyl" or _front_mode(saved_state) != "mtproxyl"):
        raise RuntimeError("shared-front restore requires current and saved mtproxyl front")
    if (not _valid_domain(domain) or current_state.get("domain") != domain
            or saved_state.get("domain") != domain or not isinstance(manifest, Mapping)
            or manifest.get("domain") != domain):
        raise RuntimeError("shared-front restore domain mismatch")
    _require_front_files(root)
    for relative in (MT_PROXY_SNI_MAP, PRIVATE_NGINX_CONFIG, PRIVATE_NGINX_UNIT) + FRONT_OVERLAY_FILES + FRONT_SITE_FILES:
        saved, present = by_path.get(relative, (None, False))
        if not present or saved is None or not saved.is_file() or saved.is_symlink():
            raise RuntimeError("снимок не содержит необходимые файлы DoH для MTProxy: %s" % relative)
    if Path(root) == Path("/"):
        nginx_binary = under_root(root, MTPROXY_NGINX_BINARY)
        nginx_config = under_root(root, MTPROXY_NGINX_CONFIG)
        if not nginx_binary.is_file() or not os.access(nginx_binary, os.X_OK) or not nginx_config.is_file():
            raise RuntimeError("проверка MTProxy недоступна; восстановление невозможно")
        _verify_mtproxyl_active_config(root, runner)


def restore_backup_runtime(
    backup_dir: Path, root: Path, domain: str,
    runner: Callable[..., Any] = subprocess.run, *, files_only: bool = False,
    preserve_new_certbot_lineage: bool = False,
    preserve_system_nginx: bool = False,
    restart_on_failure: bool = True,
    reload_front_map: bool = False,
    reload_shared_front: bool = False,
) -> None:
    """Validate a snapshot before restoring, retaining an emergency reversal."""

    root, backup_dir = Path(root), Path(backup_dir)
    if preserve_system_nginx and not files_only:
        raise RuntimeError("preserve-system-nginx requires files-only restore")
    if reload_shared_front and (not files_only or not preserve_system_nginx):
        raise RuntimeError("reload-shared-front requires files-only and preserve-system-nginx")
    _check_incomplete_transactions(root)
    entries = _validated_backup_manifest(backup_dir)
    by_path = {relative: (backup_dir / name, present) for relative, name, present in entries}
    skipped = set()
    current_state = _read_json(_runtime_paths(root)["install"], {})
    saved_install, saved_present = by_path.get("/var/lib/adguardhome-doh/install.json", (None, False))
    saved_state = _read_json(saved_install, None) if saved_present else None
    _require_saved_front_sites(saved_state, by_path)
    if reload_shared_front:
        _validate_shared_front_restore(root, backup_dir, domain, current_state, saved_state, by_path, runner)
    if (preserve_system_nginx or
            (isinstance(current_state, Mapping) and isinstance(saved_state, Mapping)
             and _front_mode(current_state) == "mtproxyl" and _front_mode(saved_state) == "mtproxyl")):
        skipped.update(under_root(root, path) for path in SYSTEM_NGINX_FILES)
    if preserve_new_certbot_lineage:
        manifest = _read_json(backup_dir / "manifest.json", None)
        if not _valid_domain(domain) or not isinstance(manifest, Mapping) or manifest.get("domain") != domain:
            raise RuntimeError("cannot establish the Certbot lineage domain")
        renewal = "/etc/letsencrypt/renewal/%s.conf" % domain
        recorded = by_path.get(renewal)
        if recorded is None:
            raise RuntimeError("backup does not record the Certbot renewal profile")
        live = under_root(root, "/etc/letsencrypt/live/%s" % domain)
        if not recorded[1] and (live / "fullchain.pem").is_file() and (live / "privkey.pem").is_file():
            skipped.add(under_root(root, renewal))
    yaml_path, yaml_present = by_path["/opt/AdGuardHome/AdGuardHome.yaml"]
    if yaml_present:
        binary, binary_present = by_path.get(
            "/opt/AdGuardHome/AdGuardHome", (Path(""), False)
        )
        if not binary_present:
            binary = under_root(root, "/opt/AdGuardHome/AdGuardHome")
        _validate_staged_adguard(root, yaml_path, binary, runner)

    targets = [entry for entry in _restore_targets(backup_dir, root) if entry[0] not in skipped]
    backup_root = under_root(root, "/var/backups/adguardhome-doh")
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    safety = Path(tempfile.mkdtemp(prefix=".restore-", dir=str(backup_root)))
    saved = []
    for index, (target, _source, _present) in enumerate(targets):
        if target.is_dir() and not target.is_symlink():
            raise RuntimeError("refusing to replace a directory with a managed file: %s" % target)
        prior = safety / ("%03d-%s" % (index, target.name))
        exists = target.exists() or target.is_symlink()
        if exists:
            _copy_path(target, prior)
            if _path_digest(target) != _path_digest(prior):
                raise RuntimeError("current file changed while preparing restore: %s" % target)
        saved.append((target, prior, exists))
    marker = safety / "transaction.json"
    _transaction_marker(marker, "prepared", saved)
    runtime_may_be_running = False
    front_reload_attempted = False

    def reload_front_files() -> None:
        if reload_shared_front and root == Path("/"):
            runner(["systemctl", "daemon-reload"], check=True)
        _reload_mtproxyl_map(root, runner)

    def reload_front() -> None:
        nonlocal front_reload_attempted
        front_reload_attempted = True
        reload_front_files()

    try:
        if skipped:
            _restore_backup(backup_dir, root, skip_targets=skipped)
        else:
            _restore_backup(backup_dir, root)
        if files_only and reload_shared_front:
            reload_front()
        if not files_only and yaml_present:
            # Reload can start AdGuard and then fail at nginx or smoke.
            runtime_may_be_running = True
            if reload_front_map:
                _reload_restored_runtime(root, domain, runner, reload_front=reload_front)
            else:
                _reload_restored_runtime(root, domain, runner)
        _transaction_marker(marker, "committed", saved)
    except BaseException as original:
        if runtime_may_be_running:
            try:
                _stop_adguard(root, runner=runner)
            except BaseException as stop_error:
                raise _StopBeforeRestoreError(
                    "restore failed; cannot stop AdGuard before restoring files: %s; "
                    "transaction remains pending at %s" % (stop_error, marker)
                ) from original
        try:
            _restore_transaction_entries(saved)
        except BaseException as restore_error:
            raise _FileRecoveryError("restore failed; returning to previous state also failed: %s"
                                     % restore_error) from original
        if front_reload_attempted:
            try:
                reload_front_files()
            except BaseException as restore_error:
                raise _FrontRecoveryError("restore failed; returning to previous MTProxy front also failed: %s"
                                          % restore_error) from original
        try:
            if restart_on_failure and not files_only and root == Path("/"):
                _reload_restored_runtime(root, domain, runner)
            _transaction_marker(marker, "restored", saved)
        except BaseException as restore_error:
            raise RuntimeError("restore failed; returning to previous state also failed: %s"
                               % restore_error) from original
        raise


def _domain_set(catalog: Any, services: Iterable[str]) -> set:
    return {row.domain for row in catalog.enabled_policy(list(services))}


def preview_service_change(catalog: Any, current: Iterable[str], selected: Iterable[str]) -> Dict[str, Any]:
    current_ids = list(current)
    selected_ids = list(selected)
    old_domains = _domain_set(catalog, current_ids)
    new_domains = _domain_set(catalog, selected_ids)
    return {
        "old_services": current_ids,
        "new_services": selected_ids,
        "added_services": [item for item in selected_ids if item not in current_ids],
        "removed_services": [item for item in current_ids if item not in selected_ids],
        "old_domains": len(old_domains),
        "new_domains": len(new_domains),
        "added_domains": len(new_domains - old_domains),
        "removed_domains": len(old_domains - new_domains),
    }


def _load_render_config() -> Any:
    candidates = [PROJECT_ROOT / "tools" / "render_config.py",
                  Path("/usr/local/libexec/adguardhome-doh/render_config.py")]
    for candidate in candidates:
        if candidate.is_file():
            import importlib.util
            spec = importlib.util.spec_from_file_location("adguardhome_doh_render_config", candidate)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("catalog renderer is unavailable")


def _load_catalog(catalog_dir: Path) -> Any:
    return _load_render_config().Catalog.load(Path(catalog_dir))


def _service_change_admin_host(state: Mapping[str, Any], catalog: Any) -> Optional[str]:
    if "admin_host" not in state:
        return None
    admin_host = state["admin_host"]
    domain = state.get("domain")
    if (not isinstance(admin_host, str) or not admin_host or admin_host != admin_host.strip()
            or not isinstance(domain, str) or not domain or domain != domain.strip()):
        raise RuntimeError("некорректный admin_host в данных установки")
    if _front_mode(state) != "mtproxyl":
        raise RuntimeError("admin_host требует front mtproxyl")
    try:
        renderer = _load_render_config()
        domain = renderer._hostname(domain, "doh-host")
        return renderer._admin_hostname(admin_host, domain, catalog.full_policy())
    except (AttributeError, ValueError, RuntimeError) as exc:
        raise RuntimeError("некорректный admin_host в данных установки") from exc


def _validate_service_change_install_state(state: Any) -> None:
    if not isinstance(state, Mapping):
        raise ValueError("invalid install state")
    domain = state.get("domain")
    public_ip = state.get("public_ip")
    if (not isinstance(domain, str) or not domain or domain != domain.strip()
            or not isinstance(public_ip, str) or not public_ip or public_ip != public_ip.strip()):
        raise ValueError("invalid install state")
    _load_render_config()._hostname(domain, "doh-host")
    ipaddress.IPv4Address(public_ip)


def _load_releases() -> Any:
    global _RELEASES_MODULE
    if _RELEASES_MODULE is not None:
        return _RELEASES_MODULE
    candidates = [PROJECT_ROOT / "deploy" / "lib" / "releases.py",
                  Path("/usr/local/libexec/adguardhome-doh/releases.py")]
    for candidate in candidates:
        if candidate.is_file():
            import importlib.util
            spec = importlib.util.spec_from_file_location("adguardhome_doh_releases", candidate)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            _RELEASES_MODULE = module
            return _RELEASES_MODULE
    raise RuntimeError("release validator is unavailable")


def _process_error_detail(exc: BaseException) -> str:
    if not isinstance(exc, subprocess.CalledProcessError):
        return ""
    detail = exc.stderr or exc.stdout or b""
    if isinstance(detail, bytes):
        detail = detail.decode("utf-8", "replace")
    return str(detail).strip()


def _runtime_paths(root: Path) -> Dict[str, Path]:
    return {
        "state": under_root(root, "/var/lib/adguardhome-doh"),
        "config": under_root(root, "/etc/adguardhome-doh"),
        "catalog": under_root(root, "/etc/adguardhome-doh/catalog"),
        "backup": under_root(root, "/var/backups/adguardhome-doh"),
        "agh": under_root(root, "/opt/AdGuardHome/AdGuardHome.yaml"),
        "nginx_stream": under_root(root, "/etc/nginx/stream.d/adguardhome-doh.conf"),
        "private_nginx_http": under_root(root, PRIVATE_NGINX_HTTP_SITE),
        "private_nginx_stream": under_root(root, PRIVATE_NGINX_STREAM_SITE),
        "health_policy": under_root(root, "/etc/adguardhome-doh/health-policy.json"),
        "credentials": under_root(root, "/var/lib/adguardhome-doh/admin-credentials.json"),
        "token": under_root(root, "/var/lib/adguardhome-doh/doh-token"),
        "install": under_root(root, "/var/lib/adguardhome-doh/install.json"),
        "enabled": under_root(root, "/var/lib/adguardhome-doh/enabled-services.json"),
        "health_state": under_root(root, "/var/lib/adguardhome-doh/health-state.json"),
        "webroot": under_root(root, "/var/www/adguardhome-doh"),
        "manager_version": under_root(root, "/usr/local/libexec/adguardhome-doh/VERSION"),
    }


def _active_domain_count(policy: Any, health_state: Mapping[str, Any]) -> int:
    domains = policy.get("domains", []) if isinstance(policy, Mapping) else policy
    active = 0
    if not isinstance(domains, list):
        return active
    for row in domains:
        if not isinstance(row, Mapping):
            continue
        service_ids = row.get("services", row.get("service_ids", []))
        if isinstance(service_ids, str):
            service_ids = [service_ids]
        if service_ids and any(
            isinstance(health_state.get(str(item)), Mapping)
            and health_state.get(str(item), {}).get("healthy", False)
            for item in service_ids
        ):
            active += 1
    return active


def _active_probe_ids(paths: Mapping[str, Path], policy: Any) -> Optional[set[str]]:
    """Identify current probes without treating old state entries as enabled."""

    rows = None
    if isinstance(policy, list):
        rows = policy
    if isinstance(policy, Mapping):
        services = policy.get("services", {})
        if services in ({}, []) and "domains" in policy:
            rows = policy["domains"]
    if isinstance(rows, list):
        # Compatibility policies probe domain rows instead of catalog IDs.
        result = set()
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            owners = row.get("services", row.get("service_ids"))
            if owners is None and row.get("service_id") is not None:
                owners = [row["service_id"]]
            if isinstance(owners, str):
                owners = [owners]
            if not owners:
                owners = [row.get("domain")]
            if isinstance(owners, list):
                result.update(item for item in owners if isinstance(item, str) and item)
        return result
    enabled = _read_json(paths["enabled"], None)
    if isinstance(enabled, list):
        return {item for item in enabled if isinstance(item, str)}
    if isinstance(policy, Mapping) and isinstance(policy.get("enabled_services"), list):
        return {item for item in policy["enabled_services"] if isinstance(item, str)}
    return None


def _probe_uncertain(health_state: Mapping[str, Any], active_ids: Optional[set[str]]) -> bool:
    return bool(active_ids is not None and any(
        isinstance(health_state.get(service_id), Mapping)
        and health_state[service_id].get("probe_uncertain") is True
        for service_id in active_ids
    ))


def _endpoint_files(root: Path, paths: Mapping[str, Path], domain: str) -> Dict[str, bool]:
    certificate_root = Path("/etc/letsencrypt/live") / domain if domain else Path("/")
    certificate = under_root(root, str(certificate_root)) / "fullchain.pem"
    profile = paths["webroot"] / (domain + ".mobileconfig") if domain else None
    return {
        "certificate": bool(
            domain and certificate.is_file()
            and certificate.with_name("privkey.pem").is_file()
        ),
        "profile": bool(profile and profile.is_file()),
    }


def _installed_version_text(paths: Mapping[str, Path], install: Mapping[str, Any]) -> str:
    try:
        version = paths["manager_version"].read_text(encoding="utf-8").strip()
    except OSError:
        version = str(install.get("version", "0.0.0")).strip()
    return version or "0.0.0"


def _latest_valid_backup(root: Path = Path("/")) -> Optional[Path]:
    backup_root = _runtime_paths(Path(root))["backup"]
    if not backup_root.is_dir():
        return None
    try:
        candidates = sorted(
            (item for item in backup_root.iterdir() if item.is_dir()),
            key=lambda item: item.name,
            reverse=True,
        )
    except OSError:
        return None
    for candidate in candidates:
        manifest_dirs = []
        if (candidate / "manifest.json").is_file():
            manifest_dirs.append(candidate)
        if (candidate / "full" / "manifest.json").is_file():
            manifest_dirs.append(candidate / "full")
        for manifest_dir in manifest_dirs:
            try:
                _validated_backup_manifest(manifest_dir)
            except RuntimeError:
                continue
            if _backup_operation(manifest_dir) == "update":
                return manifest_dir
    return None


def _backup_operation(backup_dir: Path) -> str:
    manifest = _read_json(Path(backup_dir) / "manifest.json", None)
    if isinstance(manifest, Mapping):
        if manifest.get("operation") == "update" and manifest.get("status") != "applied":
            return "unknown"
        return str(manifest.get("operation", ""))
    if (isinstance(manifest, list)
            and re.fullmatch(r"\d{8}T\d{12}Z", Path(backup_dir).name)):
        # Known legacy managers wrote update snapshots at timestamp roots.
        # timestamp/full was used by service changes and is not an update.
        return "update"
    return "unknown"


def _snapshot_under_root(root: Path, backup_dir: Path) -> Path:
    backup_root = under_root(root, "/var/backups/adguardhome-doh").resolve()
    selected = Path(backup_dir).resolve()
    if selected == backup_root or backup_root not in selected.parents:
        raise RuntimeError("backup path is outside the backup directory")
    return selected


def finalize_update_backup(backup_dir: Path, root: Path, domain: str) -> None:
    """Publish a verified pending update snapshot; caller holds the lock."""

    root = Path(root)
    _check_incomplete_transactions(root)
    backup_dir = _snapshot_under_root(root, backup_dir)
    if backup_dir.parent != under_root(root, "/var/backups/adguardhome-doh").resolve():
        raise RuntimeError("update backup is not at the backup root")
    entries = _validated_backup_manifest(backup_dir)
    by_path = {relative: (backup_dir / name, present) for relative, name, present in entries}
    saved_install, present = by_path.get("/var/lib/adguardhome-doh/install.json", (None, False))
    saved_state = _read_json(saved_install, None) if present else None
    _require_saved_front_sites(saved_state, by_path)
    manifest_path = backup_dir / "manifest.json"
    manifest = _read_json(manifest_path, None)
    if (not isinstance(manifest, dict) or manifest.get("operation") != "update"
            or manifest.get("status") != "pending" or manifest.get("domain") != domain):
        raise RuntimeError("backup is not a pending update for this domain")
    manifest["status"] = "applied"
    _write_json(manifest_path, manifest)


def collect_menu_status(
    root: Path = Path("/"), catalog: Any = None,
    runner: Callable[..., Any] = subprocess.run,
) -> Dict[str, Any]:
    """Collect a fast local dashboard summary without reading secret values."""

    root = Path(root)
    paths = _runtime_paths(root)
    install = _read_json(paths["install"], {})
    if not isinstance(install, Mapping):
        install = {}
    domain = str(install.get("domain", ""))
    front = _front_mode(install)
    saved_enabled = _read_json(paths["enabled"], None)
    if isinstance(saved_enabled, list):
        enabled = [item for item in saved_enabled if isinstance(item, str)]
    else:
        enabled = _load_enabled(paths, catalog) if catalog is not None else []
    if catalog is not None:
        known = {service.id for service in catalog.services}
        enabled = [item for item in enabled if item in known]
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        health_state = {}
    policy = _read_json(paths["health_policy"], {})
    uncertain = _probe_uncertain(health_state, _active_probe_ids(paths, policy))
    units = {}
    runtime_units = ["adguardhome-doh.service",
                     "adguardhome-doh-nginx.service" if front == "mtproxyl" else "nginx.service",
                     "adguardhome-doh-health.timer"]
    if front == "mtproxyl":
        runtime_units.append("mtproxyl-pq-nginx.service")
    for unit in runtime_units:
        units[unit] = _command_ok(
            ["systemctl", "is-active", "--quiet", unit], runner
        )
    if all(units.values()):
        overall = "running"
    elif units["adguardhome-doh.service"] or units[runtime_units[1]]:
        overall = "attention"
    else:
        overall = "stopped"
    front_config_supported = True
    if front == "mtproxyl" and root == Path("/"):
        try:
            _verify_mtproxyl_active_config(root, runner, allow_private=True)
        except RuntimeError:
            front_config_supported = False
            if overall == "running":
                overall = "attention"
    if uncertain and overall == "running":
        overall = "attention"
    endpoints = _endpoint_files(root, paths, domain)
    return {
        "version": _installed_version_text(paths, install),
        "domain": domain,
        "front": front,
        "front_config_supported": front_config_supported,
        "units": units,
        "overall": overall,
        "probe_uncertain": uncertain,
        "enabled_services": len(enabled),
        "healthy_services": sum(
            1 for service_id in enabled
            if isinstance(health_state.get(service_id), Mapping)
            and health_state.get(service_id, {}).get("healthy", False)
        ),
        "active_domain_count": _active_domain_count(policy, health_state),
        "certificate": endpoints["certificate"],
        "profile": endpoints["profile"],
        "rollback_available": _latest_valid_backup(root) is not None,
    }


def _status_value(
    state: bool, yes: str = "активен", no: str = "неактивен",
    success_symbol: str = "●",
) -> Tuple[str, str]:
    return (((success_symbol + " " + yes), ANSI_GREEN)
            if state else ("✗ " + no, ANSI_RED))


def _metric_cell(
    label: str, value: str, tone: str, output: TextIO, width: int,
) -> str:
    label_width = min(15, max(12, width // 3 + 1))
    label_text = _clip(label + ":", label_width)
    label_text = "%-*s" % (label_width, label_text)
    value_text = _clip(value, max(1, width - label_width))
    plain_length = len(label_text) + len(value_text)
    padding = " " * max(0, width - plain_length)
    return (
        _style(label_text, ANSI_BOLD, output)
        + _style(value_text, tone, output)
        + padding
    )


def _render_banner(version: str, output: TextIO, width: int) -> None:
    if width >= 72:
        for line in FULL_BANNER:
            print(_style(line, ANSI_CYAN, output), file=output)
        print("%s %s" % (
            _style("ADGUARD HOME • DoH", ANSI_BOLD + ANSI_CYAN, output),
            _style("v" + version, ANSI_DIM, output),
        ), file=output)
    else:
        print(_style("ADGUARDHOME DOH", ANSI_BOLD + ANSI_CYAN, output), file=output)
        print(_style("adguardhome-doh v" + version, ANSI_DIM, output), file=output)
    print(file=output)


def render_main_screen(
    status: Mapping[str, Any], output: TextIO = sys.stdout,
    *, width: Optional[int] = None, notice: str = "",
) -> None:
    width = width or _terminal_width(output)
    _render_banner(str(status.get("version", "0.0.0")), output, width)
    overall = str(status.get("overall", "stopped"))
    uncertain = status.get("probe_uncertain") is True
    if uncertain and overall == "running":
        overall = "attention"
    overall_values = {
        "running": ("● РАБОТАЕТ", ANSI_GREEN),
        "attention": ("! ТРЕБУЕТ ВНИМАНИЯ", ANSI_YELLOW),
        "stopped": ("✗ ОСТАНОВЛЕН", ANSI_RED),
    }
    overall_text, overall_tone = overall_values.get(
        overall, overall_values["stopped"]
    )
    units = status.get("units", {})
    if not isinstance(units, Mapping):
        units = {}
    adguard = _status_value(bool(units.get("adguardhome-doh.service")))
    front = str(status.get("front", "standard"))
    nginx_unit = "adguardhome-doh-nginx.service" if front == "mtproxyl" else "nginx.service"
    nginx = _status_value(bool(units.get(nginx_unit)))
    timer = _status_value(bool(units.get("adguardhome-doh-health.timer")))
    enabled = int(status.get("enabled_services", 0) or 0)
    healthy = int(status.get("healthy_services", 0) or 0)
    if uncertain:
        service_tone = ANSI_YELLOW
    elif enabled > 0 and healthy == enabled:
        service_tone = ANSI_GREEN
    elif healthy > 0:
        service_tone = ANSI_YELLOW
    else:
        service_tone = ANSI_RED
    certificate = _status_value(
        bool(status.get("certificate")), "готов", "не готов", "✓"
    )
    profile = _status_value(bool(status.get("profile")), "готов", "не готов", "✓")
    rollback = _status_value(
        bool(status.get("rollback_available")), "доступен", "нет копии", "✓"
    )
    active_domains = int(status.get("active_domain_count", 0) or 0)
    metrics = [
        ("Статус", overall_text, overall_tone),
        ("Домен", str(status.get("domain") or "не настроен"),
         ANSI_GREEN if status.get("domain") else ANSI_YELLOW),
        ("AdGuard Home", adguard[0], adguard[1]),
        ("nginx DoH" if front == "mtproxyl" else "nginx", nginx[0], nginx[1]),
        ("Health timer", timer[0], timer[1]),
        ("Сервисы", "состояние неизвестно" if uncertain else "%d / %d здоровы" % (enabled, healthy), service_tone),
        ("Домены", "%d по оценке" % active_domains if uncertain else "%d активны" % active_domains,
         ANSI_YELLOW if uncertain or not active_domains else ANSI_GREEN),
        ("Сертификат", certificate[0], certificate[1]),
        ("Профиль", profile[0], profile[1]),
        ("Откат", rollback[0], rollback[1]),
    ]
    if front == "mtproxyl":
        mtproxy = _status_value(bool(units.get("mtproxyl-pq-nginx.service")))
        if units.get("mtproxyl-pq-nginx.service") and status.get("front_config_supported") is False:
            mtproxy = ("! конфиг не подтверждён", ANSI_YELLOW)
        metrics.append(("MTProxy front", mtproxy[0], mtproxy[1]))
    if width >= 72:
        cell_width = (width - 2) // 2
        for index in range(0, len(metrics), 2):
            left = _metric_cell(*metrics[index], output, cell_width)
            right = (_metric_cell(*metrics[index + 1], output, cell_width)
                     if index + 1 < len(metrics) else "")
            print(left + "  " + right, file=output)
    else:
        for metric in metrics:
            print(_metric_cell(*metric, output, width), file=output)
    if uncertain:
        print(file=output)
        _print_wrapped("! ", "Текущее состояние неизвестно. Прежние DNS-правила сохранены.", output, width)
    if front == "mtproxyl" and status.get("front_config_supported") is False:
        print(file=output)
        _print_wrapped("! ", "Активная конфигурация MTProxy не подтверждена. Изменения заблокированы.", output, width)
    print(file=output)
    print(_style("─" * min(width, 56), ANSI_DIM, output), file=output)
    print(file=output)
    for key, entry in enumerate(MENU_ENTRIES, 1):
        tone = ANSI_RED if key == 5 else ANSI_CYAN
        print("%s %s" % (_style("[%d]" % key, tone, output), entry), file=output)
    print(file=output)
    print("%s Выход" % _style("[0]", ANSI_CYAN, output), file=output)
    if notice:
        print(file=output)
        print(_style(_clip(notice, width), ANSI_YELLOW, output), file=output)


def healthy_services(paths: Mapping[str, Path], selected: Iterable[str]) -> list:
    """Return selected services the gate currently considers healthy."""

    state = _read_json(paths["health_state"], {})
    if not isinstance(state, Mapping):
        return []
    return [
        service_id for service_id in selected
        if isinstance(state.get(str(service_id)), Mapping)
        and state.get(str(service_id), {}).get("healthy", False)
    ]


def apply_service_change(
    selected: Sequence[str],
    *,
    root: Path = Path("/"),
    catalog: Any = None,
    renderer: Optional[Callable[[Path, Sequence[str]], None]] = None,
    validator: Optional[Callable[[], None]] = None,
    expected_services: Optional[Sequence[str]] = None,
    expected_relay: Optional[str] = None,
    expected_policy: Optional[str] = None,
    expected_policy_hash: Optional[str] = None,
    expected_admin_host: Optional[str] = None,
) -> Path:
    """Render selected services to staging, validate, then atomically activate."""

    root = Path(root)
    with operation_lock(root), health_lock(root):
        _check_incomplete_transactions(root)
        paths = _runtime_paths(root)
        current_catalog = None
        if expected_services is not None:
            try:
                if catalog is None:
                    catalog = _load_catalog(paths["catalog"])
                state, individual_policy, policy_hash, policy = _service_change_install_snapshot(root)
                current = _load_enabled(paths, catalog, strict=True)
                _validate_relay_service_policy(state, individual_policy, policy, catalog, current)
                current_catalog = _load_catalog(paths["catalog"])
                for service_ids in (current, selected):
                    shown = {(row.domain, row.kind) for row in catalog.enabled_policy(service_ids)}
                    actual = {(row.domain, row.kind) for row in current_catalog.enabled_policy(service_ids)}
                    if shown != actual:
                        raise RuntimeError("catalog changed")
            except Exception as exc:
                raise RuntimeError("Повторите выбор: состояние изменилось.") from exc
            if (set(current) != set(expected_services)
                    or state.get("relay") != expected_relay
                    or state.get("policy") != expected_policy
                    or state.get("admin_host") != expected_admin_host
                    or policy_hash != expected_policy_hash):
                raise RuntimeError("Повторите выбор: состояние изменилось.")
        else:
            state = _read_json(paths["install"], {})
        if renderer is None:
            try:
                healthcheck = _load_healthcheck(root)
                strict_state = healthcheck.load_json(paths["install"], None)
                if strict_state != state:
                    raise ValueError("install state is unavailable or changed")
                _validate_service_change_install_state(strict_state)
            except (OSError, ValueError, RuntimeError, AttributeError, TypeError) as exc:
                raise RuntimeError("данные установки недоступны или повреждены") from exc
        if isinstance(state, Mapping) and "admin_host" in state:
            try:
                current_catalog = current_catalog or _load_catalog(paths["catalog"])
                _service_change_admin_host(state, current_catalog)
                catalog = catalog or current_catalog
            except (OSError, ValueError, RuntimeError, AttributeError) as exc:
                raise RuntimeError("некорректный admin_host или каталог") from exc
        domain = str(state.get("domain", "")) if isinstance(state, Mapping) else ""
        if isinstance(state, Mapping) and _front_mode(state) == "mtproxyl":
            _require_front_files(root)
            if root == Path("/"):
                _load_healthcheck(root)
                _verify_mtproxyl_active_config(root, subprocess.run, allow_private=True)
        if renderer is None:
            try:
                healthcheck.load_policy(paths["health_policy"])
            except (OSError, ValueError, RuntimeError, AttributeError) as exc:
                raise RuntimeError("политика доменов недоступна или повреждена") from exc
        try:
            _stop_adguard(root)
            return _apply_service_change_locked(selected, root=root, catalog=catalog,
                                                renderer=renderer, validator=validator)
        except BaseException as original:
            _recover_runtime_after_failure(root, domain, original)
            raise


def _apply_service_change_locked(
    selected: Sequence[str], *, root: Path, catalog: Any,
    renderer: Optional[Callable[[Path, Sequence[str]], None]],
    validator: Optional[Callable[[], None]],
) -> Path:
    paths = _runtime_paths(root)
    catalog = catalog or _load_catalog(paths["catalog"])
    state = _read_json(paths["install"], {})
    if not isinstance(state, Mapping):
        raise RuntimeError("install state is unavailable")
    front = _front_mode(state)
    admin_host = (_service_change_admin_host(state, _load_catalog(paths["catalog"]))
                  if "admin_host" in state else None)
    if not paths["agh"].is_file():
        raise RuntimeError("AdGuard configuration is unavailable")
    stage = Path(tempfile.mkdtemp(prefix=".services.", dir=str(paths["config"])))
    try:
        if renderer is None:
            runtime = PROJECT_ROOT / "deploy" / "lib" / "render_runtime.py"
            if not runtime.is_file():
                runtime = Path("/usr/local/libexec/adguardhome-doh/render_runtime.py")
            command = [sys.executable, str(runtime), "--config-dir", str(paths["catalog"]),
                       "--services", ",".join(selected), "--public-ip", str(state["public_ip"]),
                       "--doh-host", str(state["domain"]), "--doh-token-file", str(paths["token"]),
                       "--existing-config", str(paths["agh"]),
                       "--health-state", str(paths["health_state"]),
                       "--existing-public-ip", str(state["public_ip"]),
                       "--certificate-root", "/etc/letsencrypt/live/%s" % state["domain"],
                       "--webroot", str(paths["webroot"]), "--output", str(stage)]
            if paths["health_policy"].is_file():
                command.extend(["--existing-policy", str(paths["health_policy"])])
            if front == "mtproxyl":
                command.extend(["--front", "mtproxyl"])
            if admin_host is not None:
                command.extend(["--admin-host", admin_host,
                                "--admin-certificate-root", "/etc/letsencrypt/live/%s" % admin_host])
            # A relay host forwards routed services to one exit host; the
            # stream map has to keep doing so after a service change.
            if state.get("relay"):
                command.extend(["--relay", str(state["relay"])])
            for item in state.get("local_sites") or []:
                command.extend(["--local-site", str(item)])
            # Activation restarts AdGuard Home, discarding the rewrites the
            # health gate keeps over the API.  Services already proven healthy
            # are written straight into the new file so that changing the
            # selection never drops a working service for a probe cycle.
            healthy = healthy_services(paths, selected)
            if healthy:
                command.extend(["--healthy-services", ",".join(healthy)])
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            renderer(stage, selected)
        # The generated YAML includes password hashes and may contain private
        # user settings. Its staging directory is private, but copy2 also
        # propagates the file mode when activating it under /opt/AdGuardHome.
        os.chmod(stage / "AdGuardHome.yaml", 0o600)
        os.chmod(stage / "health-policy.json", 0o600)
        enabled_stage = stage / "enabled-services.json"
        _write_json(enabled_stage, list(selected))
        targets = {
            paths["agh"]: stage / "AdGuardHome.yaml",
            paths["private_nginx_stream"] if front == "mtproxyl" else paths["nginx_stream"]: stage / "nginx-stream.conf",
            paths["health_policy"]: stage / "health-policy.json",
            paths["enabled"]: enabled_stage,
        }
        if state.get("policy"):
            updated_state = dict(state)
            updated_state.pop("policy", None)
            install_stage = stage / "install.json"
            _write_json(install_stage, updated_state)
            targets[paths["install"]] = install_stage
        _validate_staged_adguard(
            root, targets[paths["agh"]], under_root(root, "/opt/AdGuardHome/AdGuardHome")
        )
        backup_dir = paths["backup"] / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        create_backup(root, backup_dir / "full", operation="service-change")

        def validate() -> None:
            if validator is not None:
                validator()
            elif root == Path("/"):
                # nginx cannot validate a staged stream map without staging
                # the entire host configuration; validate immediately after
                # activation and roll back if the live check fails.
                command = (["/usr/sbin/nginx", "-t", "-c", PRIVATE_NGINX_CONFIG]
                           if front == "mtproxyl" else ["nginx", "-t"])
                subprocess.run(command, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reload_runtime_services(root, str(state["domain"]))

        return activate_transaction(
            targets, backup_dir, validate=validate,
            on_failure=lambda: _stop_adguard(root), root=root,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _command_ok(command: Sequence[str], runner: Callable[..., Any]) -> bool:
    try:
        result = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(result, "returncode", 1) == 0


def _oneshot_last_run_ok(unit: str, runner: Callable[..., Any]) -> bool:
    """Return whether a oneshot unit is running or last exited successfully."""

    command = [
        "systemctl", "show",
        "--property=ActiveState",
        "--property=Result",
        "--property=ExecMainStatus",
        unit,
    ]
    try:
        result = runner(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if getattr(result, "returncode", 1) != 0:
        return False
    output = getattr(result, "stdout", "")
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    if not isinstance(output, str):
        return False
    properties = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    if properties.get("ActiveState") in {"active", "activating"}:
        return True
    return (
        properties.get("Result") == "success"
        and properties.get("ExecMainStatus") == "0"
    )


def collect_system_check(root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run) -> Dict[str, Any]:
    """Collect operational checks without reading or returning secrets."""

    root = Path(root)
    paths = _runtime_paths(root)
    install = _read_json(paths["install"], {})
    if not isinstance(install, Mapping):
        install = {}
    front = _front_mode(install)
    units = {}
    runtime_units = ["adguardhome-doh.service",
                     "adguardhome-doh-nginx.service" if front == "mtproxyl" else "nginx.service",
                     "adguardhome-doh-health.timer"]
    if front == "mtproxyl":
        runtime_units.append("mtproxyl-pq-nginx.service")
    for unit in runtime_units:
        units[unit] = _command_ok(["systemctl", "is-active", "--quiet", unit], runner)
    units["adguardhome-doh-health.service"] = _oneshot_last_run_ok(
        "adguardhome-doh-health.service", runner
    )
    domain = str(install.get("domain", "")) if isinstance(install, Mapping) else ""
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        health_state = {}
    policy = _read_json(paths["health_policy"], {})
    active_ids = _active_probe_ids(paths, policy)
    tracked = (health_state.values() if active_ids is None else
               (health_state.get(service_id) for service_id in active_ids))
    healthy = sum(1 for item in tracked if isinstance(item, Mapping) and item.get("healthy", False))
    endpoints = _endpoint_files(root, paths, domain)
    report = {
        "front": front,
        "units": units,
        "nginx": _command_ok(
            ["/usr/sbin/nginx", "-t", "-c", PRIVATE_NGINX_CONFIG]
            if front == "mtproxyl" else ["nginx", "-t"], runner,
        ),
        "adguard_config": _command_ok(["/opt/AdGuardHome/AdGuardHome", "--check-config",
                                        "-c", str(paths["agh"]),
                                        "-w", str(under_root(root, "/var/lib/AdGuardHome"))], runner),
        "certificate": endpoints["certificate"],
        "endpoints": {
            "admin": bool(domain),
            "doh": bool(domain and paths["token"].is_file()),
            "mobileconfig": endpoints["profile"],
        },
        "health_state": {
            "services": len(health_state) if active_ids is None else len(active_ids),
            "healthy": healthy,
            "probe_uncertain": _probe_uncertain(health_state, active_ids),
        },
        "active_domain_count": _active_domain_count(policy, health_state),
    }
    if front == "mtproxyl":
        try:
            verified = _verify_mtproxyl_active_config(root, runner, allow_private=True, include_config=True)
            config = verified[1] if verified is not None else MTPROXY_NGINX_CONFIG
            report["mtproxyl_config"] = _command_ok(
                [MTPROXY_NGINX_BINARY, "-t", "-c", config], runner,
            )
        except RuntimeError:
            report["mtproxyl_config"] = False
    return report


def _unhealthy_service_names(root: Path = Path("/")) -> list[str]:
    paths = _runtime_paths(Path(root))
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        return []
    policy = _read_json(paths["health_policy"], {})
    active_ids = _active_probe_ids(paths, policy)
    unhealthy_ids = {
        str(service_id)
        for service_id, state in health_state.items()
        if (active_ids is None or service_id in active_ids)
        and isinstance(state, Mapping) and not state.get("healthy", False)
    }
    if not unhealthy_ids:
        return []
    try:
        catalog = _load_catalog(paths["catalog"])
    except (OSError, RuntimeError, ValueError):
        return sorted(unhealthy_ids)
    names = [
        service.name_ru for service in catalog.services
        if service.id in unhealthy_ids
    ]
    known_ids = {service.id for service in catalog.services}
    names.extend(sorted(unhealthy_ids - known_ids))
    return names


def _render_system_check(
    report: Mapping[str, Any], output: TextIO,
    unhealthy_services: Sequence[str] = (),
) -> None:
    width = _terminal_width(output)
    _section_title("ДИАГНОСТИКА СИСТЕМЫ", output, width)
    front = str(report.get("front", "standard"))
    nginx_unit = "adguardhome-doh-nginx.service" if front == "mtproxyl" else "nginx.service"
    checks = [
        ("AdGuard Home", report["units"].get("adguardhome-doh.service", False), "готов", "ошибка"),
        ("nginx DoH" if front == "mtproxyl" else "nginx", report["units"].get(nginx_unit, False), "готов", "ошибка"),
        ("Health service", report["units"].get("adguardhome-doh-health.service", False),
         "последняя проверка успешна", "последняя проверка: ошибка"),
        ("Health timer", report["units"].get("adguardhome-doh-health.timer", False), "готов", "ошибка"),
        ("Конфигурация AdGuard Home", report["adguard_config"], "готов", "ошибка"),
        ("Конфигурация nginx DoH" if front == "mtproxyl" else "Конфигурация nginx", report["nginx"], "готов", "ошибка"),
        ("Сертификат", report["certificate"], "готов", "ошибка"),
        ("Панель администратора", report["endpoints"].get("admin", False), "готов", "ошибка"),
        ("Private DoH", report["endpoints"].get("doh", False), "готов", "ошибка"),
        ("Apple-профиль", report["endpoints"].get("mobileconfig", False), "готов", "ошибка"),
    ]
    if front == "mtproxyl":
        checks.extend([
            ("MTProxy front", report["units"].get("mtproxyl-pq-nginx.service", False), "готов", "ошибка"),
            ("Конфигурация MTProxy", report.get("mtproxyl_config", False), "готов", "ошибка"),
        ])
    for label, ok, success_text, error_text in checks:
        text, tone = _status_value(bool(ok), success_text, error_text)
        if label == "Health service" and ok and report["health_state"].get("probe_uncertain") is True:
            text, tone = "! результат неопределён", ANSI_YELLOW
        prefix = "%-30s " % (label + ":")
        if len(prefix) + len(text) <= width:
            print(prefix + _style(text, tone, output), file=output)
        else:
            print(label + ":", file=output)
            print("  " + _style(text, tone, output), file=output)
    print(file=output)
    uncertain = report["health_state"].get("probe_uncertain") is True
    if uncertain:
        _print_wrapped("! ", "Текущее состояние неизвестно. Прежние DNS-правила сохранены.", output, width)
        _print_wrapped("", "Здоровые по прежней оценке: %d/%d" % (
            report["health_state"].get("healthy", 0), report["health_state"].get("services", 0),
        ), output, width)
    else:
        print("Здоровые сервисы: %d/%d" % (
            report["health_state"].get("healthy", 0),
            report["health_state"].get("services", 0),
        ), file=output)
    if unhealthy_services:
        _print_wrapped(
            "Требуют внимания: ", ", ".join(unhealthy_services), output, width
        )
    print(("Домены по прежней оценке: %d" if uncertain else "Активные домены: %d")
          % report.get("active_domain_count", 0), file=output)


def print_system_check(root: Path = Path("/"), output: TextIO = sys.stdout) -> None:
    _render_system_check(
        collect_system_check(root), output, _unhealthy_service_names(root)
    )


def parse_service_selection(value: str, catalog: Any) -> Sequence[str]:
    value = value.strip().lower()
    if value in ("d", "default", "defaults", "по-умолчанию"):
        return list(catalog.default_service_ids)
    services = list(catalog.services)
    if value in ("a", "all", "standard", "стандартные", "все", "выбрать все"):
        return [service.id for service in services if service.risk_level == "standard"]
    if value in ("x", "experimental", "экспериментальные"):
        return [service.id for service in services if service.risk_level == "experimental"]
    selected = []
    for token in value.replace(",", " ").split():
        if "-" in token and token.replace("-", "", 1).isdigit():
            first, last = (int(item) for item in token.split("-", 1))
            if first > last:
                first, last = last, first
            indexes = range(first, last + 1)
        elif token.isdigit():
            indexes = (int(token),)
        else:
            indexes = ()
            if token not in {service.id for service in services}:
                raise ValueError("неизвестный сервис: %s" % token)
            selected.append(token)
        for index in indexes:
            if index < 1 or index > len(services):
                raise ValueError("неверный номер сервиса: %s" % index)
            selected.append(services[index - 1].id)
    unique = []
    for service_id in selected:
        if service_id not in unique:
            unique.append(service_id)
    if not unique:
        raise ValueError("выберите хотя бы один сервис")
    return unique


def print_service_catalog(catalog: Any, selected: Iterable[str], output: TextIO = sys.stdout) -> None:
    selected_ids = set(selected)
    current_category = None
    for index, service in enumerate(catalog.services, 1):
        category = "%s (%s)" % (
            service.category,
            "экспериментальные и рискованные" if service.risk_level == "experimental" else "стандартные",
        )
        if category != current_category:
            print("\n%s" % category, file=output)
            current_category = category
        mark = "x" if service.id in selected_ids else " "
        print("[%s] %2d. %-24s %s" % (mark, index, service.id, service.name_ru), file=output)


def _selector_categories(catalog: Any) -> list[str]:
    categories = []
    for service in catalog.services:
        if service.category not in categories:
            categories.append(service.category)
    return categories


def _selector_services(catalog: Any, category: Optional[str] = None, query: Optional[str] = None) -> list[Any]:
    services = list(catalog.services)
    if category is not None:
        services = [service for service in services if service.category == category]
    if query is not None:
        query = query.casefold()
        services = [service for service in services
                    if query in service.name_ru.casefold() or query in service.id.casefold()]
    return services


def _print_selector_summary(
    catalog: Any, selected: set[str], output: TextIO,
    *, width: Optional[int] = None,
) -> None:
    width = width or _terminal_width(output)
    domains = _domain_set(catalog, selected)
    names = [service.name_ru for service in catalog.services if service.id in selected]
    selected_tone = ANSI_GREEN if selected else ANSI_YELLOW
    print(_style(
        "Выбрано сервисов: %d/%d" % (len(selected), len(catalog.services)),
        selected_tone, output,
    ), file=output)
    print(_style(
        "Активных уникальных доменов: %d" % len(domains),
        ANSI_CYAN, output,
    ), file=output)
    if names:
        _print_wrapped("Сервисы: ", ", ".join(names), output, width)


def _selector_category_cell(
    number: int, category: str, selected: int, total: int,
    output: TextIO, width: int,
) -> str:
    prefix = "[%d] " % number
    suffix = " %d/%d" % (selected, total)
    label = _clip(category, max(1, width - len(prefix) - len(suffix)))
    plain = prefix + label + suffix
    padding = " " * max(0, width - len(plain))
    tone = (
        ANSI_YELLOW if category == "Экспериментальные"
        else ANSI_GREEN if selected else ANSI_CYAN
    )
    return _style(prefix + label + suffix + padding, tone, output)


def _selector_service_line(
    number: int, service: Any, selected: set[str],
    output: TextIO, width: int,
) -> str:
    prefix = "[%d] " % number
    checked = service.id in selected
    marker = "[✓]" if checked else "[ ]"
    suffix = " (%s)" % service.id
    available = width - len(prefix) - len(marker) - 1 - len(suffix)
    if available < 8:
        suffix = ""
        available = width - len(prefix) - len(marker) - 1
    name = _clip(service.name_ru, max(1, available))
    marker_tone = ANSI_GREEN if checked else ANSI_DIM
    return (
        _style(prefix, ANSI_CYAN, output)
        + _style(marker, marker_tone, output)
        + " " + name
        + _style(suffix, ANSI_DIM, output)
    )


def _print_selector_categories(
    catalog: Any, selected: set[str], output: TextIO,
    *, width: Optional[int] = None,
) -> list[str]:
    width = width or _terminal_width(output)
    categories = _selector_categories(catalog)
    print(file=output)
    print(_style("Категории:", ANSI_BOLD, output), file=output)
    cells = []
    for number, category in enumerate(categories, 1):
        services = _selector_services(catalog, category=category)
        count = sum(service.id in selected for service in services)
        cells.append((number, category, count, len(services)))
    if width >= 72:
        column_width = (width - 2) // 2
        rows = (len(cells) + 1) // 2
        for row in range(rows):
            left = _selector_category_cell(*cells[row], output, column_width)
            right_index = row + rows
            right = (
                _selector_category_cell(*cells[right_index], output, column_width)
                if right_index < len(cells) else ""
            )
            print(left + ("  " + right if right else ""), file=output)
    else:
        for cell in cells:
            print(_selector_category_cell(*cell, output, width), file=output)
    print(file=output)
    if width >= 44:
        print("Команды: номер — открыть, /текст — поиск", file=output)
    else:
        print("Команды: номер — открыть", file=output)
        print("/текст — поиск", file=output)
    defaults = "%s Стандартные" % _style("[D]", ANSI_CYAN, output)
    experimental = "%s Экспериментальные" % _style("[X]", ANSI_YELLOW, output)
    finish = "%s Итог" % _style("[Y]", ANSI_GREEN, output)
    cancel = "%s Отмена" % _style("[C]", ANSI_RED, output)
    if width >= 72:
        print("  ".join((defaults, experimental, finish, cancel)), file=output)
    else:
        print(defaults + "  " + experimental, file=output)
        print(finish + "  " + cancel, file=output)
    return categories


def _print_selector_view(
    title: str, services: list[Any], selected: set[str], output: TextIO,
    *, width: Optional[int] = None,
) -> None:
    width = width or _terminal_width(output)
    print(file=output)
    print(_style("%s:" % title, ANSI_BOLD, output), file=output)
    print("Выбрано сервисов: %d" % len(selected), file=output)
    for number, service in enumerate(services, 1):
        print(_selector_service_line(number, service, selected, output, width), file=output)
    print(file=output)
    print("Команды: номера — переключить", file=output)
    select_all = "%s Все" % _style("[A]", ANSI_GREEN, output)
    select_none = "%s Снять все" % _style("[N]", ANSI_YELLOW, output)
    back = "%s Назад" % _style("[B]", ANSI_CYAN, output)
    cancel = "%s Отмена" % _style("[C]", ANSI_RED, output)
    if width >= 56:
        print("  ".join((select_all, select_none, back, cancel)), file=output)
    else:
        print(select_all + "  " + select_none, file=output)
        print(back + "  " + cancel, file=output)


def select_services_interactive(
    catalog: Any,
    current: Iterable[str],
    input_stream: TextIO = sys.stdin,
    output: TextIO = sys.stdout,
) -> Optional[list[str]]:
    """Use the same category/search selector as the installer for service changes."""

    selected = {str(item) for item in current}
    categories = _selector_categories(catalog)
    while True:
        _clear_screen(output)
        width = _terminal_width(output)
        _section_title("СЕРВИСЫ И ДОМЕНЫ", output, width)
        _print_selector_summary(catalog, selected, output, width=width)
        _print_selector_categories(catalog, selected, output, width=width)
        print("\nКатегория: ", end="", file=output, flush=True)
        raw = input_stream.readline()
        if not raw:
            return None
        answer = raw.strip().casefold()
        if answer in {"c", "q", "cancel", "отмена"}:
            print(_style("Выбор отменён.", ANSI_YELLOW, output), file=output)
            return None
        if answer in {"d", "default", "defaults", "по-умолчанию"}:
            selected = set(catalog.default_service_ids)
            continue
        if answer in {"x", "experimental", "экспериментальные"}:
            services = [service for service in catalog.services if service.risk_level == "experimental"]
            title = "Экспериментальные сервисы"
            result = _select_services_view(services, selected, title, input_stream, output)
            if result is None:
                return None
            selected = result
            continue
        if answer in {"y", "yes", "итог", "применить"}:
            if not selected:
                print(_style("ошибка: выберите хотя бы один сервис", ANSI_RED, output), file=output)
                continue
            _print_selector_summary(catalog, selected, output, width=width)
            print("Применить выбор? [y/N]: ", end="", file=output, flush=True)
            if _is_yes_answer(input_stream.readline()):
                return [service.id for service in catalog.services if service.id in selected]
            print("Выбор не применён.", file=output)
            continue
        if answer.startswith("/"):
            services = _selector_services(catalog, query=answer[1:])
            if not services:
                print(_style("ошибка: ничего не найдено", ANSI_RED, output), file=output)
                continue
            result = _select_services_view(services, selected, "Результаты поиска", input_stream, output)
            if result is None:
                return None
            selected = result
            continue
        if answer.isdigit() and 1 <= int(answer) <= len(categories):
            category = categories[int(answer) - 1]
            services = _selector_services(catalog, category=category)
            result = _select_services_view(services, selected, category, input_stream, output)
            if result is None:
                return None
            selected = result
            continue
        print(_style(
            "ошибка: введите номер категории, /поиск, D, X, Y или C",
            ANSI_RED, output,
        ), file=output)


def _select_services_view(
    services: list[Any], selected: set[str], title: str,
    input_stream: TextIO, output: TextIO,
) -> Optional[set[str]]:
    while True:
        _clear_screen(output)
        width = _terminal_width(output)
        _section_title("СЕРВИСЫ И ДОМЕНЫ", output, width)
        _print_selector_view(title, services, selected, output, width=width)
        print("\nВыбор: ", end="", file=output, flush=True)
        raw = input_stream.readline()
        if not raw:
            return None
        answer = raw.strip().casefold()
        if answer in {"b", "back", "назад"}:
            return selected
        if answer in {"c", "q", "cancel", "отмена"}:
            print(_style("Выбор отменён.", ANSI_YELLOW, output), file=output)
            return None
        if answer in {"a", "all", "все"}:
            selected.update(service.id for service in services)
            continue
        if answer in {"n", "none", "снять"}:
            selected.difference_update(service.id for service in services)
            continue
        tokens = answer.replace(",", " ").split()
        if not tokens or any(not token.isdigit() for token in tokens):
            print(_style("ошибка: введите номера сервисов или команду", ANSI_RED, output), file=output)
            continue
        numbers = [int(token) for token in tokens]
        if any(number < 1 or number > len(services) for number in numbers):
            print(_style("ошибка: неверный номер сервиса", ANSI_RED, output), file=output)
            continue
        for number in numbers:
            service_id = services[number - 1].id
            if service_id in selected:
                selected.remove(service_id)
            else:
                selected.add(service_id)


def _current_install_state(root: Path) -> Mapping[str, Any]:
    state = _read_json(_runtime_paths(Path(root))["install"], {})
    if not isinstance(state, Mapping) or not state.get("domain"):
        raise RuntimeError("данные установки не найдены")
    return state


def _service_change_install_snapshot(root: Path) -> Tuple[Mapping[str, Any], bool, Optional[str], Any]:
    """Capture the relay and any individual policy shown by the menu."""

    state = _current_install_state(root)
    for field in ("domain", "public_ip"):
        if not isinstance(state.get(field), str) or not state[field].strip():
            raise RuntimeError("данные установки неполны или повреждены")
    for field in ("relay", "policy"):
        if field in state and (not isinstance(state[field], str) or not state[field].strip()):
            raise RuntimeError("данные установки повреждены")
    if not state.get("relay") and not state.get("policy"):
        return state, False, None, None

    path = _runtime_paths(root)["health_policy"]
    try:
        content = path.read_bytes()
        policy = json.loads(content)
        validated = _load_healthcheck(root).load_policy(path)
        if policy != validated:
            raise ValueError("policy changed during validation")
    except (OSError, ValueError, RuntimeError, AttributeError) as exc:
        raise RuntimeError("политика доменов недоступна или повреждена") from exc
    # Older compatibility installs may have no install.json policy field.
    legacy = (isinstance(policy, Mapping) and policy.get("services", {}) in ({}, [])
              and bool(policy.get("domains"))) or (isinstance(policy, list) and bool(policy))
    return state, bool(state.get("policy") or legacy), hashlib.sha256(content).hexdigest(), policy


def _validate_relay_service_policy(
    state: Mapping[str, Any], individual_policy: bool, policy: Any,
    catalog: Any, current: Sequence[str],
) -> None:
    """Do not preview catalog removals against a different active policy."""

    if not state.get("relay") or individual_policy:
        return
    services = policy.get("services", {}) if isinstance(policy, Mapping) else {}
    if isinstance(services, Mapping):
        policy_services = set(services)
    else:
        policy_services = {item.get("id", item.get("service_id")) for item in services}
    rows = policy.get("domains", []) if isinstance(policy, Mapping) else policy
    actual = {}
    for row in rows:
        owners = row.get("services", row.get("service_ids"))
        if owners is None and row.get("service_id") is not None:
            owners = [row["service_id"]]
        if isinstance(owners, str):
            owners = [owners]
        key = (row["domain"].lower(), row["kind"])
        actual.setdefault(key, set()).update(owners or [])
    selected = set(current)
    expected = {
        (row.domain, row.kind): set(catalog.associations[row.domain]) & selected
        for row in catalog.enabled_policy(current)
    }
    if policy_services != selected or actual != expected:
        raise RuntimeError("политика доменов не совпадает с активными сервисами")


def _installed_project_version(root: Path, state: Mapping[str, Any]) -> Any:
    """Read the adguardhome-doh version, never the bundled AdGuard version."""

    paths = _runtime_paths(Path(root))
    raw = ""
    try:
        raw = paths["manager_version"].read_text(encoding="utf-8").strip()
    except OSError:
        raw = str(state.get("version", "0.0.0"))
    try:
        return _load_releases().parse_semver(raw or "0.0.0")
    except ValueError:
        return _load_releases().parse_semver("0.0.0")


def update_status(root: Path = Path("/"), release_loader: Optional[Callable[[], Any]] = None) -> Dict[str, Any]:
    state = _current_install_state(Path(root))
    repository = str(state.get("repository", "evgenykhripach/AdguardHomeDoH"))
    releases = _load_releases()
    current = _installed_project_version(root, state)
    latest = (release_loader or (lambda: releases.latest_release(repository)))()
    if latest is None:
        return {"available": False, "reason": "нет стабильного релиза", "current": current.text()}
    return {"available": latest.version > current, "current": current.text(),
            "latest": latest.version.text(), "release": latest}


def _safe_extract(archive: Path, destination: Path) -> Path:
    import tarfile
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        root_path = destination.resolve()
        for member in members:
            target = (destination / member.name).resolve()
            if target != root_path and root_path not in target.parents:
                raise RuntimeError("release archive contains path traversal")
        stream.extractall(destination, members=members)
    roots = [item for item in destination.iterdir()
             if item.is_dir() and not item.name.startswith("._")]
    if len(roots) != 1 or not (roots[0] / "deploy" / "install.sh").is_file():
        raise RuntimeError("release archive has invalid layout")
    return roots[0]


def install_update(
    *, root: Path = Path("/"), release: Any = None,
    downloader: Optional[Callable[[str, Path], None]] = None,
    runner: Callable[..., Any] = subprocess.run,
    output: TextIO = sys.stdout,
) -> bool:
    """Download, verify, and run a stable release installer preserving state."""

    root = Path(root)
    paths = _runtime_paths(root)
    state = _current_install_state(root)
    front = _front_mode(state)
    if front == "mtproxyl":
        raise RuntimeError("обновление с общим front MTProxyL временно отключено: интеграция ещё не завершена")
    releases = _load_releases()
    release = release or releases.latest_release(str(state.get("repository", "evgenykhripach/AdguardHomeDoH")))
    if release is None:
        return False
    current = _installed_project_version(root, state)
    if release.version <= current:
        return False
    with health_lock(root):
        _check_incomplete_transactions(root)
    with tempfile.TemporaryDirectory(prefix=".adguardhome-doh-update-") as directory:
        work = Path(directory)
        archive = work / releases.ARCHIVE_NAME
        checksum = work / releases.CHECKSUM_NAME
        fetch = downloader or (lambda url, path: path.write_bytes(releases.download(url, timeout=30)))
        fetch(release.archive_url, archive)
        fetch(release.checksum_url, checksum)
        releases.verify_archive(archive, checksum, version=release.version.text())
        source = _safe_extract(archive, work / "source")
        catalog = _load_catalog(source / "config")
        try:
            previous_catalog = _load_catalog(paths["catalog"])
            added_domains = ({row.domain for row in catalog.full_policy()}
                             - {row.domain for row in previous_catalog.full_policy()})
        except (OSError, ValueError, RuntimeError):
            added_domains = None
        old_services = _read_json(paths["enabled"], list(catalog.default_service_ids))
        if not isinstance(old_services, list):
            old_services = list(catalog.default_service_ids)
        known = {service.id for service in catalog.services}
        selected = [str(item) for item in old_services if str(item) in known]
        if not selected:
            selected = list(catalog.default_service_ids)
        command = ["bash", str(source / "deploy" / "install.sh"),
                   "--domain", str(state["domain"]), "--public-ip", str(state["public_ip"]),
                   "--email", str(state.get("email", "admin@example.com")),
                   "--yes", "--update"]
        if state.get("policy"):
            policy = str(state["policy"])
            if policy != "/etc/adguardhome-doh/compat-policy.csv":
                raise RuntimeError("saved compatibility policy path is invalid")
            policy_path = under_root(root, policy)
            if not policy_path.is_file():
                raise RuntimeError("saved compatibility policy is missing")
            command.extend(["--policy", str(policy_path)])
        else:
            command.extend(["--services", ",".join(selected)])
        if front == "mtproxyl":
            command.extend(["--front", "mtproxyl"])
        if state.get("relay"):
            command.extend(["--relay", str(state["relay"])])
        for item in state.get("local_sites") or []:
            command.extend(["--local-site", str(item)])
        environment = os.environ.copy()
        environment["ADGUARDHOME_DOH_REPOSITORY"] = str(
            state.get("repository", "evgenykhripach/AdguardHomeDoH")
        )
        environment["ADGUARDHOME_DOH_MANAGER_UPDATE"] = "1"
        # The installer acquires the shared lock and creates/restores its own
        # snapshot. Holding the lock around the child would deadlock it.
        result = runner(command, check=False, env=environment)
        if getattr(result, "returncode", 1) != 0:
            raise RuntimeError("обновление не прошло активацию; проверьте журнал установщика")
        if added_domains:
            print("В каталоге появились новые домены. Скачайте и заново установите "
                  "Apple-профиль на устройствах, чтобы они использовали DoH для этих доменов.",
                  file=output)
        elif added_domains is None:
            print("Не удалось сравнить домены профиля. Проверьте необходимость повторной "
                  "установки Apple-профиля на устройствах.", file=output)
    return True


def _rollback_front_map_changed(root: Path, backup_dir: Path,
                                entries: Sequence[Tuple[str, str, bool]],
                                runner: Callable[..., Any]) -> bool:
    paths = _runtime_paths(root)
    current = _read_json(paths["install"], {})
    if not isinstance(current, Mapping):
        raise RuntimeError("install state is unavailable")
    current_front = _front_mode(current)
    by_path = {relative: (Path(backup_dir) / name, present) for relative, name, present in entries}
    saved_install, present = by_path.get("/var/lib/adguardhome-doh/install.json", (None, False))
    saved_state = _read_json(saved_install, None) if present else None
    saved_front = _front_mode(saved_state) if isinstance(saved_state, Mapping) else None
    if current_front == "mtproxyl" and saved_front != "mtproxyl":
        raise RuntimeError("снимок несовместим с общим MTProxy front; требуется ручной переход")
    if current_front != "mtproxyl" and saved_front == "mtproxyl":
        raise RuntimeError("снимок требует MTProxy front; требуется ручной переход")
    if current_front != "mtproxyl":
        return False
    if saved_state.get("domain") != current.get("domain"):
        raise RuntimeError("домен снимка несовместим с текущим MTProxy front")
    _require_front_files(root)
    for relative in (PRIVATE_NGINX_CONFIG, PRIVATE_NGINX_UNIT,
                     "/opt/AdGuardHome/AdGuardHome", "/opt/AdGuardHome/AdGuardHome.yaml",
                     "/var/lib/adguardhome-doh/doh-token", "/usr/local/libexec/adguardhome-doh/healthcheck.py") + FRONT_OVERLAY_FILES + FRONT_SITE_FILES:
        saved, saved_present = by_path.get(relative, (None, False))
        if not saved_present or saved is None or not saved.is_file() or saved.is_symlink():
            raise RuntimeError("снимок не содержит необходимые файлы DoH для MTProxy: %s" % relative)
    saved_map, map_present = by_path.get(MT_PROXY_SNI_MAP, (None, False))
    current_map = under_root(root, MT_PROXY_SNI_MAP)
    if (not map_present or saved_map is None or not saved_map.is_file() or saved_map.is_symlink()
            or not current_map.is_file() or current_map.is_symlink()):
        raise RuntimeError("снимок или текущая карта MTProxy отсутствует или небезопасна")
    changed = saved_map.read_bytes() != current_map.read_bytes()
    if Path(root) == Path("/"):
        _load_healthcheck(root)
        if changed:
            nginx_binary = under_root(root, MTPROXY_NGINX_BINARY)
            nginx_config = under_root(root, MTPROXY_NGINX_CONFIG)
            if not nginx_binary.is_file() or not os.access(nginx_binary, os.X_OK) or not nginx_config.is_file():
                raise RuntimeError("проверка MTProxy недоступна; откат карты невозможен")
        _verify_mtproxyl_active_config(root, runner)
    return changed


def rollback_last(root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run,
                  *, selected: Optional[Path] = None) -> bool:
    root = Path(root)
    with operation_lock(root), health_lock(root):
        _check_incomplete_transactions(root)
        selected = Path(selected) if selected is not None else _latest_valid_backup(root)
        if selected is None:
            return False
        entries = _validated_backup_manifest(selected)
        if _backup_operation(selected) != "update":
            raise RuntimeError("backup is not an update snapshot")
        map_changed = _rollback_front_map_changed(root, selected, entries, runner)
        domain = ""
        if root == Path("/"):
            domain = str(_current_install_state(root)["domain"])
        try:
            _stop_adguard(root, runner=runner)
            restore_backup_runtime(selected, root, domain, runner=runner,
                                   restart_on_failure=False, reload_front_map=map_changed)
        except BaseException as original:
            _recover_runtime_after_failure(root, domain, original, runner=runner)
            raise
        return True


def _load_enabled(paths: Mapping[str, Path], catalog: Any, *, strict: bool = False) -> list:
    value = _read_json(paths["enabled"], None)
    if strict:
        known = {service.id for service in catalog.services}
        if (not isinstance(value, list)
                or any(not isinstance(item, str) or item not in known for item in value)
                or len(value) != len(set(value))):
            raise RuntimeError("список активных сервисов недоступен или повреждён")
        return value
    if isinstance(value, list) and value:
        return [str(item) for item in value]
    return list(catalog.default_service_ids)


def print_access_data(root: Path = Path("/"), output: TextIO = sys.stdout) -> None:
    paths = _runtime_paths(Path(root))
    _section_title("ДАННЫЕ ДОСТУПА", output)
    print(_style(
        "Конфиденциально: не публикуйте пароль и приватные URL.",
        ANSI_YELLOW, output,
    ), file=output)
    print(file=output)
    credentials = _read_json(paths["credentials"], {})
    token = paths["token"].read_text(encoding="utf-8").strip() if paths["token"].is_file() else ""
    install = _read_json(paths["install"], {})
    if isinstance(credentials, Mapping):
        url = credentials.get("url", "")
        if isinstance(install, Mapping) and "admin_host" in install:
            try:
                admin_host = _service_change_admin_host(install, _load_catalog(paths["catalog"]))
                url = "https://%s/" % admin_host
            except (OSError, ValueError, RuntimeError, AttributeError, TypeError):
                url = "не определён: имя панели не подтверждено"
        print("URL: %s" % url, file=output)
        print("Логин: %s" % credentials.get("login", ""), file=output)
        print("Пароль: %s" % credentials.get("password", ""), file=output)
    domain = install.get("domain", "") if isinstance(install, Mapping) else ""
    if domain and token:
        print("DoH URL: https://%s/doh/%s" % (domain, token), file=output)
        print("mobileconfig URL: https://%s/%s.mobileconfig" % (domain, token), file=output)
    print("Данные хранятся в режиме 0600.", file=output)


def _pause(input_stream: TextIO, output: TextIO) -> None:
    if not (_stream_is_tty(input_stream) and _stream_is_tty(output)):
        return
    print(file=output)
    print(_style("Enter — назад", ANSI_DIM, output), end="", file=output, flush=True)
    input_stream.readline()


def _fallback_menu_status(root: Path) -> Dict[str, Any]:
    paths = _runtime_paths(Path(root))
    install = _read_json(paths["install"], {})
    if not isinstance(install, Mapping):
        install = {}
    try:
        front = _front_mode(install)
    except RuntimeError:
        front = "unknown"
    return {
        "version": _installed_version_text(paths, install),
        "domain": str(install.get("domain", "")),
        "front": front,
        "units": {},
        "overall": "stopped",
        "enabled_services": 0,
        "healthy_services": 0,
        "active_domain_count": 0,
        "certificate": False,
        "profile": False,
        "rollback_available": _latest_valid_backup(root) is not None,
    }


def _service_display_names(catalog: Any, service_ids: Iterable[str]) -> list[str]:
    wanted = {str(item) for item in service_ids}
    return [service.name_ru for service in catalog.services if service.id in wanted]


def _print_service_change_preview(
    catalog: Any, preview: Mapping[str, Any], output: TextIO,
) -> None:
    _section_title("ПРЕДПРОСМОТР ИЗМЕНЕНИЙ", output)
    print("Домены: %d → %d" % (
        preview["old_domains"], preview["new_domains"],
    ), file=output)
    print("Добавлено доменов: %d" % preview["added_domains"], file=output)
    print("Удалено доменов: %d" % preview["removed_domains"], file=output)
    added = _service_display_names(catalog, preview["added_services"])
    removed = _service_display_names(catalog, preview["removed_services"])
    if added:
        _print_wrapped("+ Сервисы: ", ", ".join(added), output)
    if removed:
        _print_wrapped("− Сервисы: ", ", ".join(removed), output)
    if not added and not removed:
        print(_style("Состав сервисов не изменился.", ANSI_DIM, output), file=output)


def run_menu(root: Path = Path("/"), input_stream: TextIO = sys.stdin, output: TextIO = sys.stdout) -> int:
    paths = _runtime_paths(Path(root))
    try:
        catalog = _load_catalog(paths["catalog"])
    except Exception as exc:
        print("Не удалось загрузить каталог: %s" % type(exc).__name__, file=output)
        return 1
    notice = ""
    try:
        while True:
            _clear_screen(output)
            try:
                status = collect_menu_status(root, catalog)
            except Exception:
                status = _fallback_menu_status(Path(root))
                if not notice:
                    notice = "Не удалось полностью собрать состояние системы."
            render_main_screen(status, output, notice=notice)
            notice = ""
            print(file=output)
            print("Выбор: ", end="", file=output, flush=True)
            answer = input_stream.readline()
            if not answer:
                return 0
            choice = answer.strip()
            if choice == "1":
                _clear_screen(output)
                print_access_data(root, output)
                _pause(input_stream, output)
            elif choice == "2":
                try:
                    catalog = _load_catalog(paths["catalog"])
                    state, individual_policy, policy_hash, policy = _service_change_install_snapshot(Path(root))
                    _service_change_admin_host(state, catalog)
                    current = _load_enabled(paths, catalog, strict=True)
                    _validate_relay_service_policy(state, individual_policy, policy, catalog, current)
                    selected = select_services_interactive(
                        catalog, current, input_stream, output
                    )
                    if selected is None:
                        notice = "Изменения сервисов отменены."
                        continue
                    preview = preview_service_change(catalog, current, selected)
                    _clear_screen(output)
                    _print_service_change_preview(catalog, preview, output)
                    relay_risk = bool(state.get("relay") and
                                      (individual_policy or preview["removed_domains"]))
                    if relay_risk:
                        if individual_policy:
                            _print_wrapped(
                                "! ", "Предпросмотр не учитывает индивидуальную политику. "
                                "Выбор из каталога заменит её и может удалить SNI-маршруты сразу.",
                                output,
                            )
                        else:
                            _print_wrapped(
                                "! ", "SNI-маршруты удаляемых доменов на relay исчезнут сразу.",
                                output,
                            )
                        _print_wrapped(
                            "! ", "Клиенты с IP relay в DNS-кеше могут потерять доступ "
                            "к этим доменам.", output,
                        )
                    print("Во время применения AdGuard Home остановится; DoH временно недоступен.",
                          file=output)
                    print("Применить изменения? [y/N]: ", end="", file=output, flush=True)
                    if not _is_yes_answer(input_stream.readline()):
                        notice = "Изменения отменены."
                        continue
                    if relay_risk:
                        print("Подтвердить риск для клиентов relay? [y/N]: ",
                              end="", file=output, flush=True)
                        if not _is_yes_answer(input_stream.readline()):
                            notice = "Изменения отменены."
                            continue
                    print(_style("Применяем конфигурацию…", ANSI_CYAN, output),
                          file=output, flush=True)
                    apply_service_change(
                        selected, root=root, catalog=catalog, expected_services=current,
                        expected_relay=state.get("relay"), expected_policy=state.get("policy"),
                        expected_policy_hash=policy_hash, expected_admin_host=state.get("admin_host"),
                    )
                    notice = "Сервисы активированы."
                except Exception as exc:
                    detail = _process_error_detail(exc)
                    suffix = ": " + detail.splitlines()[-1] if detail else ""
                    notice = "Изменения не применены: %s%s" % (
                        str(exc) or type(exc).__name__, suffix,
                    )
            elif choice == "3":
                _clear_screen(output)
                _section_title("ДИАГНОСТИКА СИСТЕМЫ", output)
                try:
                    print(_style("Выполняется полная проверка…", ANSI_CYAN, output),
                          file=output, flush=True)
                    _clear_screen(output)
                    print_system_check(root, output)
                except Exception as exc:
                    print(_style(
                        "Диагностика не выполнена: %s" % type(exc).__name__,
                        ANSI_RED, output,
                    ), file=output)
                _pause(input_stream, output)
            elif choice == "4":
                _clear_screen(output)
                _section_title("ОБНОВЛЕНИЕ", output)
                try:
                    print(_style("Проверяем стабильный GitHub Release…", ANSI_CYAN, output),
                          file=output, flush=True)
                    update = update_status(root)
                    if not update.get("available"):
                        print("Обновлений нет: %s" % update.get(
                            "reason", "версия актуальна"
                        ), file=output)
                    else:
                        print("Доступна версия %s (текущая %s)." % (
                            update["latest"], update["current"],
                        ), file=output)
                        print("Во время обновления AdGuard Home остановится; DoH временно недоступен.",
                              file=output)
                        print("Установить? [y/N]: ", end="", file=output, flush=True)
                        if _is_yes_answer(input_stream.readline()):
                            print(_style("Скачиваем и проверяем обновление…", ANSI_CYAN, output),
                                  file=output, flush=True)
                            if install_update(root=root, output=output):
                                print(
                                    "Обновление установлено. Запустите менеджер заново "
                                    "для применения нового интерфейса.",
                                    file=output,
                                )
                                return 0
                            print("Обновление не требуется или не выполнено.", file=output)
                        else:
                            print("Обновление отменено.", file=output)
                except Exception as exc:
                    print(_style(
                        "Обновление не применено: %s" % (str(exc) or type(exc).__name__),
                        ANSI_RED, output,
                    ), file=output)
                _pause(input_stream, output)
            elif choice == "5":
                _clear_screen(output)
                _section_title("ОТКАТ ОБНОВЛЕНИЯ", output)
                try:
                    selected = _latest_valid_backup(root)
                    if selected is None:
                        print("Резервная копия обновления не найдена.", file=output)
                        _pause(input_stream, output)
                        continue
                    manifest = _read_json(selected / "manifest.json", None)
                    print("Снимок обновления: %s" % selected, file=output)
                    if isinstance(manifest, Mapping):
                        print("Версии: %s → %s" % (
                            manifest.get("version_before") or "неизвестна",
                            manifest.get("version_after") or "неизвестна",
                        ), file=output)
                    else:
                        print("Старый снимок без контрольных сумм; тип операции "
                              "определён по расположению.", file=output)
                        if not any(item.get("path") == "/opt/AdGuardHome/AdGuardHome"
                                   for item in manifest if isinstance(item, Mapping)):
                            print("В снимке нет бинарника AdGuard; текущий бинарник "
                                  "останется на месте.", file=output)
                    print("Во время отката AdGuard Home остановится; DoH временно недоступен.",
                          file=output)
                    print("Продолжить откат? [y/N]: ", end="", file=output, flush=True)
                    if _is_yes_answer(input_stream.readline()):
                        print(_style("Восстанавливаем резервную копию…", ANSI_CYAN, output),
                              file=output, flush=True)
                        print(
                            "Откат выполнен."
                            if rollback_last(root, selected=selected)
                            else "Резервная копия не найдена.",
                            file=output,
                        )
                    else:
                        print("Откат отменён.", file=output)
                except Exception as exc:
                    print(_style(
                        "Откат не применён: %s" % (str(exc) or type(exc).__name__),
                        ANSI_RED, output,
                    ), file=output)
                _pause(input_stream, output)
            elif choice in {"0", "6"}:
                return 0
            else:
                notice = "Введите номер пункта от 0 до 5."
    except KeyboardInterrupt:
        print(file=output)
        print(_style("Выход прерван.", ANSI_YELLOW, output), file=output)
        if _color_enabled(output):
            print(ANSI_RESET, end="", file=output)
        return 130


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--help", action="store_true")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--create-update-backup", action="store_true")
    operation.add_argument("--restore-update-backup", type=Path)
    operation.add_argument("--finalize-update-backup", type=Path)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--domain", default="")
    parser.add_argument("--target-version", default="")
    parser.add_argument("--snapshot-operation", choices=("update", "recovery"), default="update")
    parser.add_argument("--files-only", action="store_true")
    parser.add_argument("--preserve-new-certbot-lineage", action="store_true")
    parser.add_argument("--preserve-system-nginx", action="store_true")
    parser.add_argument("--reload-shared-front", action="store_true")
    args = parser.parse_args(argv)
    if args.help:
        print("adguardhome-doh: root-only interactive manager")
        return 0
    if args.preserve_system_nginx and (not args.restore_update_backup or not args.files_only):
        print("ошибка: --preserve-system-nginx требует --restore-update-backup и --files-only", file=sys.stderr)
        return 1
    if args.reload_shared_front and (not args.restore_update_backup or not args.files_only
                                     or not args.preserve_system_nginx):
        print("ошибка: --reload-shared-front требует --restore-update-backup, --files-only "
              "и --preserve-system-nginx", file=sys.stderr)
        return 1
    if args.create_update_backup or args.restore_update_backup or args.finalize_update_backup:
        if not args.root.is_absolute():
            print("ошибка: root должен быть абсолютным путём", file=sys.stderr)
            return 1
        if args.root == Path("/") and getattr(os, "geteuid", lambda: 1)() != 0:
            print("ошибка: команда доступна только root", file=sys.stderr)
            return 1
        try:
            if args.create_update_backup:
                # Caller owns the shared lock; acquiring it again here would
                # deadlock the installer holding a separate file descriptor.
                _check_incomplete_transactions(args.root)
                print(create_backup(args.root, operation=args.snapshot_operation,
                                    target_version=args.target_version, domain=args.domain))
            elif args.finalize_update_backup:
                finalize_update_backup(args.finalize_update_backup, args.root, args.domain)
            else:
                selected = _snapshot_under_root(args.root, args.restore_update_backup)
                restore_backup_runtime(
                    selected, args.root, args.domain, files_only=args.files_only,
                    preserve_new_certbot_lineage=args.preserve_new_certbot_lineage,
                    preserve_system_nginx=args.preserve_system_nginx,
                    reload_shared_front=args.reload_shared_front,
                )
            return 0
        except (Exception, KeyboardInterrupt) as exc:
            print("ошибка резервной копии: %s" % (str(exc) or type(exc).__name__), file=sys.stderr)
            return 1
    if getattr(os, "geteuid", lambda: 1)() != 0:
        print("ошибка: команда доступна только root", file=sys.stderr)
        return 1
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("ошибка: интерактивное меню требует TTY", file=sys.stderr)
        return 1
    try:
        return run_menu(Path(os.environ.get("ADGUARDHOME_DOH_ROOT", "/")))
    except KeyboardInterrupt:
        print(file=sys.stdout)
        print(_style("Выход прерван.", ANSI_YELLOW, sys.stdout), file=sys.stdout)
        if _color_enabled(sys.stdout):
            print(ANSI_RESET, end="", file=sys.stdout)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
