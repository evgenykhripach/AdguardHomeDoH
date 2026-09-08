#!/usr/bin/env python3
"""Root-only interactive manager for the neutral AdGuard Home deployment."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
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
MANAGED_FILES = (
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
        os.chmod(path, 0o600)
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


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def create_backup(root: Path = Path("/"), backup_dir: Optional[Path] = None) -> Path:
    """Copy every managed file and record absent paths before activation."""

    root = Path(root)
    if backup_dir is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_dir = under_root(root, "/var/backups/adguardhome-doh") / timestamp
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = []
    for index, relative in enumerate(MANAGED_FILES):
        source = under_root(root, relative)
        destination = backup_dir / ("%03d-%s" % (index, Path(relative).name))
        present = source.exists() or source.is_symlink()
        manifest.append({"path": relative, "backup": destination.name, "present": present})
        if present:
            _copy_path(source, destination)
    _write_json(backup_dir / "manifest.json", manifest)
    return backup_dir


def _validated_backup_manifest(backup_dir: Path) -> list[Tuple[str, str, bool]]:
    manifest_path = Path(backup_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("backup manifest is missing")
    manifest = _read_json(manifest_path, None)
    if not isinstance(manifest, list) or not manifest:
        raise RuntimeError("backup manifest is invalid")

    entries = []
    seen_paths = set()
    seen_backups = set()
    for item in manifest:
        if not isinstance(item, Mapping):
            raise RuntimeError("backup manifest is invalid")
        relative = item.get("path")
        if (
            not isinstance(relative, str)
            or relative not in MANAGED_FILES
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
        entries.append((relative, backup_name, present))
    if seen_paths != set(MANAGED_FILES):
        raise RuntimeError("backup manifest is incomplete")
    return entries


def _restore_backup(backup_dir: Path, root: Path = Path("/")) -> None:
    entries = _validated_backup_manifest(backup_dir)
    for relative, backup_name, present in entries:
        target = under_root(root, relative)
        backup = Path(backup_dir) / backup_name
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
        shutil.copy2(source, temporary_path)
        os.replace(temporary_path, target)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def activate_transaction(
    targets: Mapping[Path, Path],
    backup_dir: Path,
    *,
    validate: Optional[Callable[[], None]] = None,
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
    _write_json(
        backup_dir / "transaction.json",
        [{"target": str(target), "backup": backup.name, "present": present}
         for target, _stage, backup, present in entries],
    )
    try:
        for target, stage, _backup, _present in entries:
            _atomic_copy(stage, target)
        if validate is not None:
            validate()
    except Exception:
        for target, _stage, backup, present in reversed(entries):
            if present:
                _remove_path(target)
                _copy_path(backup, target)
            else:
                _remove_path(target)
        raise
    return backup_dir


def smoke_https_sni(
    domain: str, *, runner: Callable[..., Any] = subprocess.run,
    attempts: int = 3, delay: int = 2,
) -> None:
    """Verify the local public TLS path using the installation domain as SNI."""

    command = [
        "curl", "--fail", "--silent", "--show-error",
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
    runner(["systemctl", "restart", "adguardhome-doh"], check=True)
    runner(["systemctl", "reload", "nginx"], check=True)
    smoke_https_sni(
        domain, runner=runner, attempts=smoke_attempts, delay=smoke_delay
    )


def restore_backup_runtime(
    backup_dir: Path, root: Path, domain: str,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    """Restore managed files and load the restored runtime configuration."""

    root = Path(root)
    backup_dir = Path(backup_dir)
    _restore_backup(backup_dir, root)
    if root != Path("/"):
        return
    runner(["systemctl", "daemon-reload"], check=False)
    runner(
        [
            "/opt/AdGuardHome/AdGuardHome", "--check-config",
            "-c", "/opt/AdGuardHome/AdGuardHome.yaml",
            "-w", "/var/lib/AdGuardHome",
        ],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    runner(["nginx", "-t"], check=True)
    reload_runtime_services(root, domain, runner=runner)
    runner(["systemctl", "restart", "adguardhome-doh-health.timer"], check=True)


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


def _load_catalog(catalog_dir: Path) -> Any:
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
            return module.Catalog.load(Path(catalog_dir))
    raise RuntimeError("catalog renderer is unavailable")


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
            return manifest_dir
    return None


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
    enabled = _load_enabled(paths, catalog) if catalog is not None else []
    if catalog is not None:
        known = {service.id for service in catalog.services}
        enabled = [item for item in enabled if item in known]
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        health_state = {}
    policy = _read_json(paths["health_policy"], {})
    units = {}
    for unit in (
        "adguardhome-doh.service",
        "nginx.service",
        "adguardhome-doh-health.timer",
    ):
        units[unit] = _command_ok(
            ["systemctl", "is-active", "--quiet", unit], runner
        )
    if all(units.values()):
        overall = "running"
    elif units["adguardhome-doh.service"] or units["nginx.service"]:
        overall = "attention"
    else:
        overall = "stopped"
    endpoints = _endpoint_files(root, paths, domain)
    return {
        "version": _installed_version_text(paths, install),
        "domain": domain,
        "units": units,
        "overall": overall,
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
    nginx = _status_value(bool(units.get("nginx.service")))
    timer = _status_value(bool(units.get("adguardhome-doh-health.timer")))
    enabled = int(status.get("enabled_services", 0) or 0)
    healthy = int(status.get("healthy_services", 0) or 0)
    if enabled > 0 and healthy == enabled:
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
        ("nginx", nginx[0], nginx[1]),
        ("Health timer", timer[0], timer[1]),
        ("Сервисы", "%d / %d здоровы" % (enabled, healthy), service_tone),
        ("Домены", "%d активны" % active_domains,
         ANSI_GREEN if active_domains else ANSI_YELLOW),
        ("Сертификат", certificate[0], certificate[1]),
        ("Профиль", profile[0], profile[1]),
        ("Откат", rollback[0], rollback[1]),
    ]
    if width >= 72:
        cell_width = (width - 2) // 2
        for index in range(0, len(metrics), 2):
            left = _metric_cell(*metrics[index], output, cell_width)
            right = _metric_cell(*metrics[index + 1], output, cell_width)
            print(left + "  " + right, file=output)
    else:
        for metric in metrics:
            print(_metric_cell(*metric, output, width), file=output)
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
) -> Path:
    """Render selected services to staging, validate, then atomically activate."""

    root = Path(root)
    paths = _runtime_paths(root)
    catalog = catalog or _load_catalog(paths["catalog"])
    state = _read_json(paths["install"], {})
    if not isinstance(state, Mapping):
        raise RuntimeError("install state is unavailable")
    token = paths["token"].read_text(encoding="utf-8").strip()
    old_yaml = paths["agh"].read_text(encoding="utf-8")
    password_hash = ""
    for line in old_yaml.splitlines():
        if line.strip().startswith("password:"):
            password_hash = line.split(":", 1)[1].strip()
            break
    if not password_hash:
        raise RuntimeError("AdGuard administrator hash is unavailable")
    stage = Path(tempfile.mkdtemp(prefix=".services.", dir=str(paths["config"])))
    try:
        if renderer is None:
            runtime = PROJECT_ROOT / "deploy" / "lib" / "render_runtime.py"
            if not runtime.is_file():
                runtime = Path("/usr/local/libexec/adguardhome-doh/render_runtime.py")
            command = [sys.executable, str(runtime), "--config-dir", str(paths["catalog"]),
                       "--services", ",".join(selected), "--public-ip", str(state["public_ip"]),
                       "--doh-host", str(state["domain"]), "--doh-token", token,
                       "--password-hash", password_hash,
                       "--certificate-root", "/etc/letsencrypt/live/%s" % state["domain"],
                       "--webroot", str(paths["webroot"]), "--output", str(stage)]
            # A relay host forwards routed services to one exit host; the
            # stream map has to keep doing so after a service change.
            if state.get("relay"):
                command.extend(["--relay", str(state["relay"])])
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
        enabled_stage = stage / "enabled-services.json"
        _write_json(enabled_stage, list(selected))
        targets = {
            paths["agh"]: stage / "AdGuardHome.yaml",
            paths["nginx_stream"]: stage / "nginx-stream.conf",
            paths["health_policy"]: stage / "health-policy.json",
            paths["enabled"]: enabled_stage,
        }
        backup_dir = paths["backup"] / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        full_backup = create_backup(root, backup_dir / "full")

        def validate() -> None:
            if validator is not None:
                validator()
                return
            subprocess.run(["/opt/AdGuardHome/AdGuardHome", "--check-config",
                            "-c", str(paths["agh"]),
                            "-w", str(under_root(root, "/var/lib/AdGuardHome"))], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["nginx", "-t"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            activated = activate_transaction(targets, backup_dir, validate=validate, root=root)
            reload_runtime_services(root, str(state["domain"]))
            return activated
        except Exception:
            try:
                restore_backup_runtime(full_backup, root, str(state["domain"]))
            except Exception:
                pass
            raise
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
    units = {}
    for unit in ("adguardhome-doh.service", "nginx.service",
                 "adguardhome-doh-health.timer"):
        units[unit] = _command_ok(["systemctl", "is-active", "--quiet", unit], runner)
    units["adguardhome-doh-health.service"] = _oneshot_last_run_ok(
        "adguardhome-doh-health.service", runner
    )
    install = _read_json(paths["install"], {})
    domain = str(install.get("domain", "")) if isinstance(install, Mapping) else ""
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        health_state = {}
    policy = _read_json(paths["health_policy"], {})
    endpoints = _endpoint_files(root, paths, domain)
    report = {
        "units": units,
        "nginx": _command_ok(["nginx", "-t"], runner),
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
            "services": len(health_state) if isinstance(health_state, Mapping) else 0,
            "healthy": sum(1 for item in health_state.values()
                            if isinstance(item, Mapping) and item.get("healthy", False))
            if isinstance(health_state, Mapping) else 0,
        },
        "active_domain_count": _active_domain_count(policy, health_state),
    }
    return report


def _unhealthy_service_names(root: Path = Path("/")) -> list[str]:
    paths = _runtime_paths(Path(root))
    health_state = _read_json(paths["health_state"], {})
    if not isinstance(health_state, Mapping):
        return []
    unhealthy_ids = {
        str(service_id)
        for service_id, state in health_state.items()
        if isinstance(state, Mapping) and not state.get("healthy", False)
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
    checks = (
        ("AdGuard Home", report["units"].get("adguardhome-doh.service", False), "готов", "ошибка"),
        ("nginx", report["units"].get("nginx.service", False), "готов", "ошибка"),
        ("Health service", report["units"].get("adguardhome-doh-health.service", False),
         "последняя проверка успешна", "последняя проверка: ошибка"),
        ("Health timer", report["units"].get("adguardhome-doh-health.timer", False), "готов", "ошибка"),
        ("Конфигурация AdGuard Home", report["adguard_config"], "готов", "ошибка"),
        ("Конфигурация nginx", report["nginx"], "готов", "ошибка"),
        ("Сертификат", report["certificate"], "готов", "ошибка"),
        ("Панель администратора", report["endpoints"].get("admin", False), "готов", "ошибка"),
        ("Private DoH", report["endpoints"].get("doh", False), "готов", "ошибка"),
        ("Apple-профиль", report["endpoints"].get("mobileconfig", False), "готов", "ошибка"),
    )
    for label, ok, success_text, error_text in checks:
        text, tone = _status_value(bool(ok), success_text, error_text)
        prefix = "%-30s " % (label + ":")
        if len(prefix) + len(text) <= width:
            print(prefix + _style(text, tone, output), file=output)
        else:
            print(label + ":", file=output)
            print("  " + _style(text, tone, output), file=output)
    print(file=output)
    print("Здоровые сервисы: %d/%d" % (
        report["health_state"].get("healthy", 0),
        report["health_state"].get("services", 0),
    ), file=output)
    if unhealthy_services:
        _print_wrapped(
            "Требуют внимания: ", ", ".join(unhealthy_services), output, width
        )
    print("Активные домены: %d" % report.get("active_domain_count", 0), file=output)


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
) -> bool:
    """Download, verify, and run a stable release installer preserving state."""

    root = Path(root)
    paths = _runtime_paths(root)
    state = _current_install_state(root)
    releases = _load_releases()
    release = release or releases.latest_release(str(state.get("repository", "evgenykhripach/AdguardHomeDoH")))
    if release is None:
        return False
    current = _installed_project_version(root, state)
    if release.version <= current:
        return False
    backup_dir = create_backup(root)
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
                   "--services", ",".join(selected), "--yes", "--update"]
        if state.get("relay"):
            command.extend(["--relay", str(state["relay"])])
        try:
            result = runner(command, check=False)
            if getattr(result, "returncode", 1) != 0:
                raise RuntimeError("обновление не прошло активацию")
        except Exception:
            restore_backup_runtime(
                backup_dir, root, str(state["domain"]), runner=runner
            )
            raise
    return True


def rollback_last(root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run) -> bool:
    root = Path(root)
    selected = _latest_valid_backup(root)
    if selected is None:
        return False

    domain = ""
    if root == Path("/"):
        domain = str(_current_install_state(root)["domain"])
    restore_backup_runtime(selected, root, domain, runner=runner)
    return True


def _load_enabled(paths: Mapping[str, Path], catalog: Any) -> list:
    value = _read_json(paths["enabled"], None)
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
    if isinstance(credentials, Mapping):
        print("URL: %s" % credentials.get("url", ""), file=output)
        print("Логин: %s" % credentials.get("login", ""), file=output)
        print("Пароль: %s" % credentials.get("password", ""), file=output)
    install = _read_json(paths["install"], {})
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
    return {
        "version": _installed_version_text(paths, install),
        "domain": str(install.get("domain", "")),
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
                current = _load_enabled(paths, catalog)
                try:
                    selected = select_services_interactive(
                        catalog, current, input_stream, output
                    )
                    if selected is None:
                        notice = "Изменения сервисов отменены."
                        continue
                    preview = preview_service_change(catalog, current, selected)
                    _clear_screen(output)
                    _print_service_change_preview(catalog, preview, output)
                    print("Применить изменения? [y/N]: ", end="", file=output, flush=True)
                    if not _is_yes_answer(input_stream.readline()):
                        notice = "Изменения отменены."
                        continue
                    print(_style("Применяем конфигурацию…", ANSI_CYAN, output),
                          file=output, flush=True)
                    apply_service_change(selected, root=root, catalog=catalog)
                    notice = "Сервисы активированы."
                except Exception as exc:
                    detail = _process_error_detail(exc)
                    suffix = ": " + detail.splitlines()[-1] if detail else ""
                    notice = "Изменения не применены: %s%s" % (
                        type(exc).__name__, suffix,
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
                        print("Установить? [y/N]: ", end="", file=output, flush=True)
                        if _is_yes_answer(input_stream.readline()):
                            print(_style("Скачиваем и проверяем обновление…", ANSI_CYAN, output),
                                  file=output, flush=True)
                            if install_update(root=root):
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
                        "Обновление не применено: %s" % type(exc).__name__,
                        ANSI_RED, output,
                    ), file=output)
                _pause(input_stream, output)
            elif choice == "5":
                _clear_screen(output)
                _section_title("ОТКАТ ОБНОВЛЕНИЯ", output)
                print(_style(
                    "Будет восстановлена последняя корректная резервная копия.",
                    ANSI_RED, output,
                ), file=output)
                try:
                    print("Продолжить откат? [y/N]: ", end="", file=output, flush=True)
                    if _is_yes_answer(input_stream.readline()):
                        print(_style("Восстанавливаем резервную копию…", ANSI_CYAN, output),
                              file=output, flush=True)
                        print(
                            "Откат выполнен."
                            if rollback_last(root)
                            else "Резервная копия не найдена.",
                            file=output,
                        )
                    else:
                        print("Откат отменён.", file=output)
                except Exception as exc:
                    print(_style(
                        "Откат не применён: %s" % type(exc).__name__,
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
    args = parser.parse_args(argv)
    if args.help:
        print("adguardhome-doh: root-only interactive manager")
        return 0
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
