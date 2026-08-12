#!/usr/bin/env python3
"""Root-only interactive manager for the neutral AdGuard Home deployment."""

from __future__ import annotations

import argparse
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
MENU_ENTRIES = (
    "Доступ к данным",
    "Изменить сервисы",
    "Проверка системы",
    "Проверить и установить обновление",
    "Откатить последнее обновление",
    "Выход",
)
MANAGED_FILES = (
    "/opt/AdGuardHome/AdGuardHome.yaml",
    "/etc/nginx/sites-enabled/adguardhome-doh",
    "/etc/nginx/stream.d/adguardhome-doh.conf",
    "/etc/adguardhome-doh/health-policy.json",
    "/etc/adguardhome-doh/runtime.env",
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
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
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
            spec.loader.exec_module(module)
            return module.Catalog.load(Path(catalog_dir))
    raise RuntimeError("catalog renderer is unavailable")


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
        backup_dir = paths["backup"] / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        def validate() -> None:
            if validator is not None:
                validator()
                return
            subprocess.run(["/opt/AdGuardHome/AdGuardHome", "--check-config",
                            "-c", str(paths["agh"])], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["nginx", "-t"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return activate_transaction(targets, backup_dir, validate=validate, root=root)
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
                                        "-c", str(paths["agh"])], runner),
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
    if value in ("a", "all", "standard", "стандартные"):
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
            print("Текущие сервисы: %s" % ", ".join(current), file=output)
            print("Новый выбор (ID, номера, диапазон, default, standard, experimental): ", end="", file=output, flush=True)
            raw = input_stream.readline()
            try:
                selected = list(parse_service_selection(raw, catalog))
                preview = preview_service_change(catalog, current, selected)
                print("Домены: %d -> %d; добавлено %d; удалено %d" % (
                    preview["old_domains"], preview["new_domains"],
                    preview["added_domains"], preview["removed_domains"]), file=output)
                print("Применить изменения? [y/N]: ", end="", file=output, flush=True)
                if input_stream.readline().strip().lower() not in ("y", "yes", "д", "да"):
                    print("Изменения отменены.", file=output)
                    continue
                apply_service_change(selected, root=root, catalog=catalog)
                print("Сервисы активированы.", file=output)
            except Exception as exc:
                print("Изменения не применены: %s" % type(exc).__name__, file=output)
        elif choice == "3":
            print_system_check(root, output)
        elif choice == "4":
            print("Проверка стабильного обновления пока недоступна.", file=output)
        elif choice == "5":
            print("Откат последнего обновления пока недоступен.", file=output)
        elif choice == "6":
            return 0
        else:
            print("Введите номер пункта от 1 до 6.", file=output)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--help", action="store_true")
    args, _unknown = parser.parse_known_args(argv)
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
