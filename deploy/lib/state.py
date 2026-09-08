#!/usr/bin/env python3
"""Strict, mode-0600 JSON state files for adguardhome-doh.

The installer and future management command share these small helpers so state
never needs to be sourced as shell code.  Files are replaced atomically after
validation and are always private to the administrator.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping


MODE = 0o600
INSTALL_FIELDS = ("domain", "public_ip", "email", "version", "repository")
# A relay host forwards routed services to one exit host instead of the real
# sites; the field is absent on ordinary installations.
OPTIONAL_INSTALL_FIELDS = ("relay", "local_sites")
LOCAL_SITE_RE = re.compile(r"^(\*|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)=(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    try:
        if (path.stat().st_mode & 0o777) != MODE:
            raise ValueError("state file must have mode 0600: %s" % path)
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("cannot read state file %s: %s" % (path, exc)) from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON state file: %s" % path) from exc


def _atomic_write(path: Path, value: Any) -> None:
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


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % field)
    return value


def _validate_install_state(value: Any) -> dict[str, str]:
    required = set(INSTALL_FIELDS)
    allowed = required | set(OPTIONAL_INSTALL_FIELDS)
    if not isinstance(value, dict) or not required <= set(value) or not set(value) <= allowed:
        raise ValueError(
            "install.json fields must be: %s and optionally %s"
            % (",".join(INSTALL_FIELDS), ",".join(OPTIONAL_INSTALL_FIELDS))
        )
    result = {field: _string(value[field], field) for field in INSTALL_FIELDS}
    domain = result["domain"].lower()
    if not HOSTNAME_RE.fullmatch(domain):
        raise ValueError("invalid install domain: %s" % result["domain"])
    try:
        address = ipaddress.ip_address(result["public_ip"])
    except ValueError as exc:
        raise ValueError("invalid install public_ip: %s" % result["public_ip"]) from exc
    if address.version != 4:
        raise ValueError("public_ip must be IPv4")
    if not EMAIL_RE.fullmatch(result["email"]):
        raise ValueError("invalid install email: %s" % result["email"])
    result["domain"] = domain
    result["email"] = result["email"]
    if "relay" in value:
        relay = _string(value["relay"], "relay")
        try:
            relay_address = ipaddress.ip_address(relay)
        except ValueError as exc:
            raise ValueError("invalid install relay: %s" % relay) from exc
        if relay_address.version != 4:
            raise ValueError("relay must be IPv4")
        if str(relay_address) == result["public_ip"]:
            raise ValueError("relay must differ from public_ip")
        result["relay"] = str(relay_address)
    if "local_sites" in value:
        sites = value["local_sites"]
        if not isinstance(sites, list) or not sites:
            raise ValueError("local_sites must be a non-empty JSON array")
        cleaned = []
        for item in sites:
            item = _string(item, "local site").strip().lower()
            match = LOCAL_SITE_RE.fullmatch(item)
            if not match or not 1 <= int(match.group(3)) <= 65535 or int(match.group(3)) == 443:
                raise ValueError("invalid local site: %s" % item)
            if item in cleaned:
                raise ValueError("duplicate local site: %s" % item)
            cleaned.append(item)
        result["local_sites"] = cleaned
    return result


def _validate_services(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("enabled-services.json must contain a JSON array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError("enabled-services.json must contain only non-empty strings")
    if any(not SERVICE_ID_RE.fullmatch(item) for item in value):
        raise ValueError("enabled-services.json contains an invalid service ID")
    if len(set(value)) != len(value):
        raise ValueError("enabled-services.json contains duplicate service IDs")
    return list(value)


def save_install_state(
    path: Path,
    *,
    domain: str,
    public_ip: str,
    email: str,
    version: str,
    repository: str,
    relay: str | None = None,
    local_sites: Iterable[str] | None = None,
) -> dict[str, str]:
    """Validate and atomically save installer metadata."""

    raw = {
        "domain": domain,
        "public_ip": public_ip,
        "email": email,
        "version": version,
        "repository": repository,
    }
    if relay:
        raw["relay"] = relay
    sites = [item for item in (local_sites or ()) if item]
    if sites:
        raw["local_sites"] = sites
    value = _validate_install_state(raw)
    _atomic_write(Path(path), value)
    return value


def load_install_state(path: Path) -> dict[str, str]:
    """Read and validate an install.json object."""

    return _validate_install_state(_read_json(Path(path)))


def save_enabled_services(path: Path, services: Iterable[str]) -> list[str]:
    """Validate and atomically save the selected service IDs."""

    value = _validate_services(list(services))
    _atomic_write(Path(path), value)
    return value


def load_enabled_services(path: Path) -> list[str]:
    """Read and validate an enabled-services.json array."""

    return _validate_services(_read_json(Path(path)))


# Explicit aliases make call sites self-documenting while keeping one parser.
write_install_state = save_install_state
write_enabled_services = save_enabled_services
read_install_state = load_install_state
read_enabled_services = load_enabled_services


if __name__ == "__main__":
    raise SystemExit("state.py is a library; invoke deploy/install.sh")
