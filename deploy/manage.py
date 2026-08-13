#!/usr/bin/env python3
"""Root-only interactive manager for the neutral AdGuard Home deployment."""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, TextIO, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_RELEASES_MODULE = None
MENU_ENTRIES = (
    "Доступ к данным",
    "Изменить сервисы",
    "Проверка системы",
    "Проверить и установить обновление",
    "Откатить последнее обновление",
    "Выход",
)
YES_ANSWERS = {"y", "yes", "д", "да"}
INVISIBLE_INPUT = "\ufeff\u200b\u200c\u200d\u2060\u2066\u2067\u2068\u2069"


def _is_yes_answer(value: str) -> bool:
    """Accept y/да regardless of terminal CR, case, or pasted invisibles."""

    normalized = str(value).strip().replace("\r", "")
    normalized = normalized.replace("\x1b[200~", "").replace("\x1b[201~", "")
    normalized = "".join(char for char in normalized if char not in INVISIBLE_INPUT)
    return normalized.casefold() in YES_ANSWERS
MANAGED_FILES = (
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


def _restore_backup(backup_dir: Path, root: Path = Path("/")) -> None:
    manifest = _read_json(Path(backup_dir) / "manifest.json", [])
    if not isinstance(manifest, list):
        raise RuntimeError("backup manifest is invalid")
    for item in manifest:
        if not isinstance(item, Mapping):
            continue
        target = under_root(root, str(item.get("path", "")))
        backup = Path(backup_dir) / str(item.get("backup", ""))
        if item.get("present"):
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


def reload_runtime_services(
    root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run
) -> None:
    """Load newly activated AdGuard and nginx configuration on a live host."""

    if Path(root) != Path("/"):
        return
    runner(["systemctl", "restart", "adguardhome-doh"], check=True)
    runner(["systemctl", "reload", "nginx"], check=True)


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
            reload_runtime_services(root)
            return activated
        except Exception:
            _restore_backup(full_backup, root)
            if root == Path("/"):
                try:
                    reload_runtime_services(root)
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


def collect_system_check(root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run) -> Dict[str, Any]:
    """Collect operational checks without reading or returning secrets."""

    root = Path(root)
    paths = _runtime_paths(root)
    units = {}
    for unit in ("adguardhome-doh.service", "nginx.service",
                 "adguardhome-doh-health.service", "adguardhome-doh-health.timer"):
        units[unit] = _command_ok(["systemctl", "is-active", "--quiet", unit], runner)
    install = _read_json(paths["install"], {})
    domain = str(install.get("domain", "")) if isinstance(install, Mapping) else ""
    health_state = _read_json(paths["health_state"], {})
    policy = _read_json(paths["health_policy"], {})
    domains = policy.get("domains", []) if isinstance(policy, Mapping) else policy
    active = 0
    if isinstance(domains, list):
        for row in domains:
            if not isinstance(row, Mapping):
                continue
            ids = row.get("services", row.get("service_ids", []))
            if isinstance(ids, str):
                ids = [ids]
            if ids and any(health_state.get(str(item), {}).get("healthy", False) for item in ids):
                active += 1
    certificate_root = Path("/etc/letsencrypt/live") / domain if domain else Path("/")
    certificate = under_root(root, str(certificate_root)) / "fullchain.pem"
    report = {
        "units": units,
        "nginx": _command_ok(["nginx", "-t"], runner),
        "adguard_config": _command_ok(["/opt/AdGuardHome/AdGuardHome", "--check-config",
                                        "-c", str(paths["agh"]),
                                        "-w", str(under_root(root, "/var/lib/AdGuardHome"))], runner),
        "certificate": certificate.is_file() and (certificate.with_name("privkey.pem")).is_file(),
        "endpoints": {
            "admin": bool(domain),
            "doh": bool(domain and paths["token"].is_file()),
            "mobileconfig": bool(domain and paths["token"].is_file()),
        },
        "health_state": {
            "services": len(health_state) if isinstance(health_state, Mapping) else 0,
            "healthy": sum(1 for item in health_state.values()
                            if isinstance(item, Mapping) and item.get("healthy", False))
            if isinstance(health_state, Mapping) else 0,
        },
        "active_domain_count": active,
    }
    return report


def print_system_check(root: Path = Path("/"), output: TextIO = sys.stdout) -> None:
    report = collect_system_check(root)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True), file=output)


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


def _print_selector_summary(catalog: Any, selected: set[str], output: TextIO) -> None:
    domains = _domain_set(catalog, selected)
    names = [service.name_ru for service in catalog.services if service.id in selected]
    print("Выбрано сервисов: %d" % len(selected), file=output)
    print("Активных уникальных доменов: %d" % len(domains), file=output)
    if names:
        print("Сервисы: %s" % ", ".join(names), file=output)


def _print_selector_categories(catalog: Any, selected: set[str], output: TextIO) -> list[str]:
    categories = _selector_categories(catalog)
    print("\nКатегории:", file=output)
    for number, category in enumerate(categories, 1):
        services = _selector_services(catalog, category=category)
        count = sum(service.id in selected for service in services)
        print("%2d) %-24s %d/%d" % (number, category, count, len(services)), file=output)
    print("\nКоманды: номер — открыть категорию, /текст — поиск, D — стандартные, "
          "X — экспериментальные, Y — итог, C — отмена", file=output)
    return categories


def _print_selector_view(title: str, services: list[Any], selected: set[str], output: TextIO) -> None:
    print("\n%s:" % title, file=output)
    for number, service in enumerate(services, 1):
        marker = "x" if service.id in selected else " "
        print("%2d) [%s] %-28s (%s)" % (number, marker, service.name_ru, service.id), file=output)
    print("\nКоманды: номера через пробел — включить/выключить, A — все, "
          "N — снять все, B — назад, C — отмена", file=output)


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
        _print_selector_categories(catalog, selected, output)
        _print_selector_summary(catalog, selected, output)
        print("\nКатегория: ", end="", file=output, flush=True)
        raw = input_stream.readline()
        if not raw:
            return None
        answer = raw.strip().casefold()
        if answer in {"c", "q", "cancel", "отмена"}:
            print("Выбор отменён.", file=output)
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
                print("ошибка: выберите хотя бы один сервис", file=output)
                continue
            _print_selector_summary(catalog, selected, output)
            print("Применить выбор? [y/N]: ", end="", file=output, flush=True)
            if _is_yes_answer(input_stream.readline()):
                return [service.id for service in catalog.services if service.id in selected]
            print("Выбор не применён.", file=output)
            continue
        if answer.startswith("/"):
            services = _selector_services(catalog, query=answer[1:])
            if not services:
                print("ошибка: ничего не найдено", file=output)
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
        print("ошибка: введите номер категории, /поиск, D, X, Y или C", file=output)


def _select_services_view(
    services: list[Any], selected: set[str], title: str,
    input_stream: TextIO, output: TextIO,
) -> Optional[set[str]]:
    while True:
        _print_selector_view(title, services, selected, output)
        print("\nВыбор: ", end="", file=output, flush=True)
        raw = input_stream.readline()
        if not raw:
            return None
        answer = raw.strip().casefold()
        if answer in {"b", "back", "назад"}:
            return selected
        if answer in {"c", "q", "cancel", "отмена"}:
            print("Выбор отменён.", file=output)
            return None
        if answer in {"a", "all", "все"}:
            selected.update(service.id for service in services)
            continue
        if answer in {"n", "none", "снять"}:
            selected.difference_update(service.id for service in services)
            continue
        tokens = answer.replace(",", " ").split()
        if not tokens or any(not token.isdigit() for token in tokens):
            print("ошибка: введите номера сервисов или команду", file=output)
            continue
        numbers = [int(token) for token in tokens]
        if any(number < 1 or number > len(services) for number in numbers):
            print("ошибка: неверный номер сервиса", file=output)
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
        try:
            result = runner(command, check=False)
            if getattr(result, "returncode", 1) != 0:
                raise RuntimeError("обновление не прошло активацию")
        except Exception:
            _restore_backup(backup_dir, root)
            raise
    return True


def rollback_last(root: Path = Path("/"), runner: Callable[..., Any] = subprocess.run) -> bool:
    root = Path(root)
    backup_root = _runtime_paths(root)["backup"]
    candidates = sorted((item for item in backup_root.iterdir() if item.is_dir()), reverse=True) if backup_root.is_dir() else []
    if not candidates:
        return False
    _restore_backup(candidates[0], root)
    if root == Path("/"):
        runner(["systemctl", "daemon-reload"], check=False)
        runner(["nginx", "-t"], check=True)
        for unit in ("adguardhome-doh.service", "adguardhome-doh-health.timer", "nginx.service"):
            runner(["systemctl", "restart", unit], check=False)
    return True


def _load_enabled(paths: Mapping[str, Path], catalog: Any) -> list:
    value = _read_json(paths["enabled"], None)
    if isinstance(value, list) and value:
        return [str(item) for item in value]
    return list(catalog.default_service_ids)


def print_access_data(root: Path = Path("/"), output: TextIO = sys.stdout) -> None:
    paths = _runtime_paths(Path(root))
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


def run_menu(root: Path = Path("/"), input_stream: TextIO = sys.stdin, output: TextIO = sys.stdout) -> int:
    paths = _runtime_paths(Path(root))
    try:
        catalog = _load_catalog(paths["catalog"])
    except Exception as exc:
        print("Не удалось загрузить каталог: %s" % type(exc).__name__, file=output)
        return 1
    while True:
        print("\nМенеджер adguardhome-doh", file=output)
        for index, entry in enumerate(MENU_ENTRIES, 1):
            print("%d. %s" % (index, entry), file=output)
        print("Выбор: ", end="", file=output, flush=True)
        answer = input_stream.readline()
        if not answer:
            return 0
        choice = answer.strip()
        if choice == "1":
            print_access_data(root, output)
        elif choice == "2":
            current = _load_enabled(paths, catalog)
            try:
                selected = select_services_interactive(catalog, current, input_stream, output)
                if selected is None:
                    continue
                preview = preview_service_change(catalog, current, selected)
                print("Домены: %d -> %d; добавлено %d; удалено %d" % (
                    preview["old_domains"], preview["new_domains"],
                    preview["added_domains"], preview["removed_domains"]), file=output)
                print("Применить изменения? [y/N]: ", end="", file=output, flush=True)
                if not _is_yes_answer(input_stream.readline()):
                    print("Изменения отменены.", file=output)
                    continue
                apply_service_change(selected, root=root, catalog=catalog)
                print("Сервисы активированы.", file=output)
            except Exception as exc:
                detail = _process_error_detail(exc)
                suffix = ": " + detail.splitlines()[-1] if detail else ""
                print("Изменения не применены: %s%s" % (type(exc).__name__, suffix), file=output)
        elif choice == "3":
            print_system_check(root, output)
        elif choice == "4":
            try:
                status = update_status(root)
                if not status.get("available"):
                    print("Обновлений нет: %s" % status.get("reason", "версия актуальна"), file=output)
                else:
                    print("Доступна версия %s (текущая %s)." % (status["latest"], status["current"]), file=output)
                    print("Установить? [y/N]: ", end="", file=output, flush=True)
                    if _is_yes_answer(input_stream.readline()):
                        if install_update(root=root):
                            print("Обновление установлено. Запустите менеджер заново для применения нового интерфейса.", file=output)
                            return 0
                        else:
                            print("Обновление не требуется или не выполнено.", file=output)
                    else:
                        print("Обновление отменено.", file=output)
            except Exception as exc:
                print("Обновление не применено: %s" % type(exc).__name__, file=output)
        elif choice == "5":
            try:
                print("Откатить последнюю резервную копию? [y/N]: ", end="", file=output, flush=True)
                if _is_yes_answer(input_stream.readline()):
                    print("Откат выполнен." if rollback_last(root) else "Резервная копия не найдена.", file=output)
            except Exception as exc:
                print("Откат не применён: %s" % type(exc).__name__, file=output)
        elif choice == "6":
            return 0
        else:
            print("Введите номер пункта от 1 до 6.", file=output)


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
    return run_menu(Path(os.environ.get("ADGUARDHOME_DOH_ROOT", "/")))


if __name__ == "__main__":
    raise SystemExit(main())
