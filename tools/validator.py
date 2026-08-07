#!/usr/bin/env python3
"""Validate Smart DNS deployment data without external dependencies.

The validator intentionally consumes data rather than deployment files.  This
keeps checks useful in unit tests and lets deployment tooling render its own
templates before handing the resulting values to this module.

Canonical data shapes are small mappings:

* inventory: ``{"hostname": str, "ipv4": str, "publication": {…}}``;
* sniproxy: ``{"listeners": [{"protocol", "port", "interface"}],
  "closed": [{"protocol", "port"}]}``;
* domain CSV: one ``fqdn,mode`` record per line, with ``prefix``, ``suffix``,
  or ``fqdn`` mode.  Domains are lowercase ASCII/Punycode and omit a trailing
  dot in their canonical form;
* Apple profile: XML plist containing the expected outer and DNS Settings
  payload identifiers, HTTPS DoH URL, and IPv4 server address.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import io
import json
import plistlib
import re
import string
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


EXPECTED_HOSTNAME = "dns.pressroll.ru"
EXPECTED_IPV4 = "203.0.113.10"
EXPECTED_DOH_URL = "https://dns.pressroll.ru/dns-query"
EXPECTED_OUTER_PAYLOAD_IDENTIFIER = "ru.pressroll.dns.profile"
EXPECTED_INNER_PAYLOAD_IDENTIFIER = "ru.pressroll.dns.settings"
EXPECTED_INNER_PAYLOAD_TYPE = "com.apple.dnsSettings.managed"
VALID_DOMAIN_MODES = frozenset({"prefix", "suffix", "fqdn"})
REQUIRED_LISTENERS = frozenset(
    {
        ("udp", 53),
        ("tcp", 53),
        ("tcp", 443),
        ("tcp", 853),
    }
)
REQUIRED_NGINX_LISTENERS = frozenset({("tcp", 80)})
REQUIRED_CLOSED = frozenset({("udp", 443), ("udp", 853)})

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TEMPLATE_TOKEN = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}|\$\{([^{}]+?)\}")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _is_nonempty(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (bytes, bytearray)):
        return bool(value)
    if isinstance(value, Mapping | Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return bool(value)
    return True


def _ipv4(value: Any) -> ipaddress.IPv4Address | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv4Address) else None


def _fqdn_error(value: Any, *, trailing_dot: bool = False) -> str | None:
    if not isinstance(value, str) or not value:
        return "hostname is missing or not a string"
    if value != value.strip() or any(character.isspace() for character in value):
        return "hostname contains whitespace"
    if value.endswith("."):
        if not trailing_dot:
            return "hostname is not normalized (trailing dot is not allowed)"
        value = value[:-1]
    if not value or len(value) > 253:
        return "hostname is not a valid FQDN"
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return "hostname must use lowercase ASCII/Punycode labels"
    labels = value.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return "hostname is not a valid FQDN"
    if value.lower() != value:
        return "hostname is not normalized (use lowercase labels)"
    return None


def _walk_publication(value: Any, path: str = "publication") -> list[str]:
    """Find non-empty AAAA/IPv6 publication markers in nested data."""

    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in {"aaaa", "ipv6", "ipv6_addresses", "aaaa_records"}:
                if _is_nonempty(child):
                    errors.append(f"{child_path}: IPv6/AAAA publication is disabled")
                continue
            errors.extend(_walk_publication(child, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            errors.extend(_walk_publication(child, f"{path}[{index}]"))
    return errors


def validate_inventory(
    inventory: Mapping[str, Any], expected_hostname: str = EXPECTED_HOSTNAME
) -> list[str]:
    """Return invariant violations for an IPv4-only deployment inventory."""

    errors: list[str] = []
    if not isinstance(inventory, Mapping):
        return ["inventory must be a mapping"]

    hostname = inventory.get("hostname")
    hostname_error = _fqdn_error(hostname)
    if hostname_error:
        errors.append(f"hostname: {hostname_error}")
    # ``None`` cannot disable the fixed deployment invariant accidentally.
    if expected_hostname is None:
        expected_hostname = EXPECTED_HOSTNAME
    if hostname != expected_hostname:
        errors.append(f"hostname must equal {expected_hostname!r}")

    ipv4_value = inventory.get("ipv4")
    ipv4 = _ipv4(ipv4_value)
    if ipv4 is None:
        errors.append("ipv4: missing or invalid IPv4 address")

    for key in ("ipv6", "aaaa", "ipv6_addresses", "aaaa_records"):
        if key in inventory and _is_nonempty(inventory[key]):
            errors.append(f"{key}: IPv6/AAAA publication is disabled")
    if "publication" in inventory:
        errors.extend(_walk_publication(inventory["publication"]))

    if isinstance(inventory.get("publication"), Mapping) and ipv4 is not None:
        publication = inventory["publication"]
        a_records = publication.get("A", publication.get("a"))
        if a_records is not None:
            if isinstance(a_records, str):
                a_records = [a_records]
            if not isinstance(a_records, Sequence) or isinstance(a_records, (bytes, bytearray)):
                errors.append("publication.A must be a list of IPv4 addresses")
            else:
                parsed_a = [_ipv4(record) for record in a_records]
                if any(address is None for address in parsed_a):
                    errors.append("publication.A contains an invalid or IPv6 address")
                elif parsed_a != [ipv4]:
                    errors.append("publication.A must contain inventory ipv4 only")
    return errors


def _domain_error(domain: Any) -> str | None:
    if not isinstance(domain, str) or not domain:
        return "domain is missing or not a string"
    if domain != domain.strip() or any(character.isspace() for character in domain):
        return "domain is not normalized (whitespace is not allowed)"
    if domain.endswith(".."):
        return "domain is not normalized (multiple trailing dots are not allowed)"
    canonical = domain[:-1] if domain.endswith(".") else domain
    return _fqdn_error(canonical)


def _domain_rows(records: Any) -> tuple[list[tuple[int, Any, Any]], list[str]]:
    errors: list[str] = []
    rows: list[tuple[int, Any, Any]] = []
    if isinstance(records, Path):
        try:
            records = records.read_text(encoding="utf-8")
        except OSError as exc:
            return [], [f"domain CSV cannot be read: {exc}"]
    if isinstance(records, bytes):
        try:
            records = records.decode("utf-8")
        except UnicodeDecodeError:
            return [], ["domain CSV is not valid UTF-8"]
    if isinstance(records, str):
        reader = csv.reader(io.StringIO(records, newline=""))
        for line_number, row in enumerate(reader, 1):
            if not row:
                rows.append((line_number, None, None))
            elif len(row) != 2:
                errors.append(f"domain CSV line {line_number}: expected fqdn.,mode")
            else:
                rows.append((line_number, row[0], row[1]))
        return rows, errors
    if not isinstance(records, Iterable):
        return [], ["domain CSV must be text or an iterable of records"]
    for line_number, row in enumerate(records, 1):
        if isinstance(row, Mapping):
            rows.append((line_number, row.get("domain", row.get("fqdn")), row.get("mode")))
        elif isinstance(row, Sequence) and not isinstance(row, (str, bytes, bytearray)) and len(row) == 2:
            rows.append((line_number, row[0], row[1]))
        else:
            errors.append(f"domain CSV line {line_number}: expected fqdn.,mode")
    return rows, errors


def validate_domain_csv(records: Any, *, allow_comments: bool = False, allow_blank: bool = False) -> list[str]:
    """Return violations for headerless ``fqdn,mode`` domain records."""

    errors: list[str] = []
    rows, row_errors = _domain_rows(records)
    errors.extend(row_errors)
    seen: set[str] = set()
    for line_number, domain, mode in rows:
        if domain is None and mode is None:
            if not allow_blank:
                errors.append(f"domain CSV line {line_number}: blank records are not allowed")
            continue
        if isinstance(domain, str) and domain.startswith("#") and mode in (None, ""):
            if not allow_comments:
                errors.append(f"domain CSV line {line_number}: comments are not allowed")
            continue
        domain_error = _domain_error(domain)
        if domain_error:
            errors.append(f"domain CSV line {line_number}: {domain_error}")
        if isinstance(domain, str):
            canonical = domain[:-1] if domain.endswith(".") else domain
            normalized = canonical.lower()
            # Keep duplicate detection independent of case-normalization errors.
            if _fqdn_error(normalized) is None:
                if domain != normalized:
                    errors.append(f"domain CSV line {line_number}: domain is not normalized")
                if normalized in seen:
                    errors.append(f"domain CSV line {line_number}: duplicate domain {normalized}")
                seen.add(normalized)
        if not isinstance(mode, str) or mode != mode.strip() or mode.lower() not in VALID_DOMAIN_MODES:
            errors.append(f"domain CSV line {line_number}: invalid mode {mode!r}")
        elif mode != mode.lower():
            errors.append(f"domain CSV line {line_number}: mode is not normalized")
    return errors


def _listener_rows(config: Mapping[str, Any]) -> tuple[list[tuple[str, Mapping[str, Any]]], list[str]]:
    raw = config.get("listeners")
    if raw is None:
        return [], ["sniproxy listeners are missing"]
    if isinstance(raw, Mapping):
        result: list[tuple[str, Mapping[str, Any]]] = []
        errors: list[str] = []
        for name, spec in raw.items():
            if not isinstance(spec, Mapping):
                errors.append(f"listener {name!r}: specification must be a mapping")
                continue
            result.append((str(name), spec))
        return result, errors
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return [], ["sniproxy listeners must be a list or mapping"]
    result = []
    errors = []
    for index, spec in enumerate(raw, 1):
        if not isinstance(spec, Mapping):
            errors.append(f"listener {index}: specification must be a mapping")
            continue
        result.append((str(spec.get("name", index)), spec))
    return result, errors


def _endpoint(spec: Mapping[str, Any], label: str) -> tuple[str | None, int | None, str | None]:
    protocol = spec.get("protocol")
    protocol = protocol.lower() if isinstance(protocol, str) else None
    port = spec.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        port = None
    interface = spec.get("interface", spec.get("bind", spec.get("address")))
    if not isinstance(interface, str) or _ipv4(interface) is None:
        return protocol, port, f"{label}: interface must be an IPv4 address"
    if protocol not in {"tcp", "udp"}:
        return protocol, port, f"{label}: protocol must be tcp or udp"
    if port is None:
        return protocol, port, f"{label}: port must be an integer from 1 to 65535"
    return protocol, port, None


def _public_listener_interface(address: ipaddress.IPv4Address, expected_ipv4: str | None) -> bool:
    if address.is_unspecified:
        return True
    expected = _ipv4(expected_ipv4)
    return expected is not None and address == expected


def validate_sniproxy(config: Mapping[str, Any], expected_ipv4: str | None = None) -> list[str]:
    """Return port, protocol, interface, and metrics-binding violations."""

    if not isinstance(config, Mapping):
        return ["sniproxy config must be a mapping"]
    errors: list[str] = []
    listeners, listener_errors = _listener_rows(config)
    errors.extend(listener_errors)
    found: set[tuple[str, int]] = set()
    interfaces: dict[tuple[str, int], ipaddress.IPv4Address] = {}
    for name, spec in listeners:
        label = f"listener {name!r}"
        protocol, port, endpoint_error = _endpoint(spec, label)
        if endpoint_error:
            errors.append(endpoint_error)
            continue
        assert protocol is not None and port is not None
        key = (protocol, port)
        if key in found:
            errors.append(f"{label}: duplicate {protocol.upper()} {port} listener")
        found.add(key)
        interface = spec.get("interface", spec.get("bind", spec.get("address")))
        assert isinstance(interface, str)
        parsed_interface = _ipv4(interface)
        assert parsed_interface is not None
        interfaces[key] = parsed_interface
        loopback = parsed_interface.is_loopback
        lowered_name = name.lower()
        if "prometheus" in lowered_name or "metrics" in lowered_name or port == 9090:
            if not loopback:
                errors.append(f"{label}: Prometheus must bind loopback only")
        if protocol == "udp" and port in {443, 853}:
            errors.append(f"{label}: UDP {port} must remain closed")

    for required in sorted(REQUIRED_LISTENERS):
        if required not in found:
            errors.append(f"required {required[0].upper()} {required[1]} listener is missing")
        elif not _public_listener_interface(interfaces[required], expected_ipv4):
            errors.append(f"required {required[0].upper()} {required[1]} listener must use a public interface")

    closed = config.get("closed", [])
    closed_keys: set[tuple[str, int]] = set()
    if isinstance(closed, Mapping):
        closed = [closed]
    if not isinstance(closed, Sequence) or isinstance(closed, (str, bytes, bytearray)):
        errors.append("sniproxy closed endpoints must be a list")
    else:
        for index, spec in enumerate(closed, 1):
            if not isinstance(spec, Mapping):
                errors.append(f"closed endpoint {index}: specification must be a mapping")
                continue
            protocol = spec.get("protocol")
            protocol = protocol.lower() if isinstance(protocol, str) else None
            port = spec.get("port")
            if protocol not in {"tcp", "udp"}:
                errors.append(f"closed endpoint {index}: protocol must be tcp or udp")
                continue
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                errors.append(f"closed endpoint {index}: port must be an integer from 1 to 65535")
                continue
            closed_keys.add((protocol, port))
    for required in sorted(REQUIRED_CLOSED):
        if required not in closed_keys:
            errors.append(f"closed {required[0].upper()} {required[1]} endpoint is missing")
    return errors


def _validate_required_service_listeners(
    config: Mapping[str, Any],
    service: str,
    required: Iterable[tuple[str, int]],
    expected_ipv4: str | None = None,
) -> list[str]:
    if not isinstance(config, Mapping):
        return [f"{service} config must be a mapping"]
    errors: list[str] = []
    listeners, listener_errors = _listener_rows(config)
    errors.extend(listener_errors)
    found: set[tuple[str, int]] = set()
    interfaces: dict[tuple[str, int], ipaddress.IPv4Address] = {}
    for name, spec in listeners:
        label = f"{service} listener {name!r}"
        protocol, port, endpoint_error = _endpoint(spec, label)
        if endpoint_error:
            errors.append(endpoint_error)
            continue
        assert protocol is not None and port is not None
        key = (protocol, port)
        if key in found:
            errors.append(f"{label}: duplicate {protocol.upper()} {port} listener")
        found.add(key)
        interface = spec.get("interface", spec.get("bind", spec.get("address")))
        assert isinstance(interface, str)
        parsed_interface = _ipv4(interface)
        assert parsed_interface is not None
        interfaces[key] = parsed_interface
    for listener in required:
        if listener not in found:
            errors.append(f"required {service} {listener[0].upper()} {listener[1]} listener is missing")
        elif not _public_listener_interface(interfaces[listener], expected_ipv4):
            errors.append(
                f"required {service} {listener[0].upper()} {listener[1]} listener must use a public interface"
            )
    return errors


def validate_nginx(config: Mapping[str, Any], expected_ipv4: str | None = None) -> list[str]:
    """Validate nginx-owned public HTTP listener(s), currently TCP 80."""

    return _validate_required_service_listeners(config, "nginx", REQUIRED_NGINX_LISTENERS, expected_ipv4)


def validate_deployment_ports(services: Mapping[str, Any], expected_ipv4: str | None = None) -> list[str]:
    """Validate service ownership: sniproxy excludes nginx's TCP 80 listener."""

    if not isinstance(services, Mapping):
        return ["deployment services must be a mapping"]
    errors: list[str] = []
    if "sniproxy" not in services:
        errors.append("deployment sniproxy config is missing")
    else:
        errors.extend(
            f"sniproxy: {error}"
            for error in validate_sniproxy(services["sniproxy"], expected_ipv4=expected_ipv4)
        )
    if "nginx" not in services:
        errors.append("deployment nginx config is missing (TCP 80 ownership)")
    else:
        errors.extend(
            f"nginx: {error}"
            for error in validate_nginx(services["nginx"], expected_ipv4=expected_ipv4)
        )
    return errors


def _load_plist(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Path):
        value = value.read_bytes()
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        return None
    parsed = plistlib.loads(bytes(value))
    return parsed if isinstance(parsed, Mapping) else None


def _valid_uuid(value: Any) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def validate_mobileconfig(xml: Any, *, expected_ipv4: str | None = None) -> list[str]:
    """Return semantic violations for an unsigned Apple DNS Settings plist."""

    errors: list[str] = []
    try:
        profile = _load_plist(xml)
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        profile = None
    if profile is None:
        return ["mobileconfig is not a valid XML plist dictionary"]
    if profile.get("PayloadType") != "Configuration":
        errors.append("mobileconfig outer PayloadType must be Configuration")
    if profile.get("PayloadVersion") != 1:
        errors.append("mobileconfig outer PayloadVersion must be 1")
    if not _valid_uuid(profile.get("PayloadUUID")):
        errors.append("mobileconfig outer PayloadUUID must be a valid UUID")
    if profile.get("PayloadIdentifier") != EXPECTED_OUTER_PAYLOAD_IDENTIFIER:
        errors.append("mobileconfig outer PayloadIdentifier is invalid")
    content = profile.get("PayloadContent")
    if (
        not isinstance(content, Sequence)
        or isinstance(content, (str, bytes, bytearray))
        or len(content) != 1
        or not isinstance(content[0], Mapping)
    ):
        return errors + ["mobileconfig PayloadContent must contain exactly one mapping"]
    payload = content[0]
    if payload.get("PayloadType") != EXPECTED_INNER_PAYLOAD_TYPE:
        errors.append("mobileconfig inner PayloadType is invalid")
    if payload.get("PayloadVersion") != 1:
        errors.append("mobileconfig inner PayloadVersion must be 1")
    if not _valid_uuid(payload.get("PayloadUUID")):
        errors.append("mobileconfig inner PayloadUUID must be a valid UUID")
    if payload.get("PayloadIdentifier") != EXPECTED_INNER_PAYLOAD_IDENTIFIER:
        errors.append("mobileconfig inner PayloadIdentifier is invalid")
    settings = payload.get("DNSSettings")
    if not isinstance(settings, Mapping):
        return errors + ["mobileconfig DNSSettings dictionary is missing"]
    if settings.get("DNSProtocol") != "HTTPS":
        errors.append("mobileconfig DNSProtocol must be HTTPS")
    if settings.get("ServerURL") != EXPECTED_DOH_URL:
        errors.append("mobileconfig ServerURL is invalid")
    if "SupplementalMatchDomains" in settings:
        errors.append("mobileconfig must not restrict SupplementalMatchDomains")
    addresses = settings.get("ServerAddresses")
    if not isinstance(addresses, Sequence) or isinstance(addresses, (str, bytes, bytearray)) or not addresses:
        errors.append("mobileconfig ServerAddresses must contain IPv4 address")
    else:
        parsed_addresses = [_ipv4(address) for address in addresses]
        if any(address is None for address in parsed_addresses):
            errors.append("mobileconfig ServerAddresses must contain IPv4 addresses only")
        if expected_ipv4 is not None and _ipv4(expected_ipv4) not in parsed_addresses:
            errors.append("mobileconfig ServerAddresses must include inventory ipv4")
    return errors


def render_template(template: str, inventory: Mapping[str, Any]) -> str:
    """Render only simple inventory tokens and reject unresolved placeholders."""

    inventory_errors = validate_inventory(inventory)
    if inventory_errors:
        raise ValueError("cannot render with invalid inventory: " + "; ".join(inventory_errors))
    if not isinstance(template, str):
        raise TypeError("template must be text")

    values = {"hostname": str(inventory["hostname"]), "ipv4": str(inventory["ipv4"])}

    def replace(match: re.Match[str]) -> str:
        token = (match.group(1) or match.group(2) or "").strip()
        if token.startswith("inventory."):
            token = token.removeprefix("inventory.")
        if token not in values:
            raise ValueError(f"template contains unsupported token {token!r}")
        return values[token]

    rendered = _TEMPLATE_TOKEN.sub(replace, template)
    try:
        rendered = string.Template(rendered).substitute(values)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"template contains unresolved token: {exc}") from exc
    if any(marker in rendered for marker in ("${", "{{", "}}")):
        raise ValueError("template contains unresolved marker")
    return rendered


def validate_templates(templates: Mapping[str, str] | Iterable[str], inventory: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    entries = templates.items() if isinstance(templates, Mapping) else enumerate(templates, 1)
    for name, template in entries:
        try:
            render_template(template, inventory)
        except (TypeError, ValueError) as exc:
            errors.append(f"template {name!r}: {exc}")
    return errors


def validate_artifacts(
    *,
    inventory: Mapping[str, Any],
    domain_csv: Any,
    sniproxy: Mapping[str, Any],
    mobileconfig: Any,
    templates: Mapping[str, str] | Iterable[str] | None = None,
) -> list[str]:
    """Validate all local artifacts and return a flat, human-readable report."""

    errors = [f"inventory: {error}" for error in validate_inventory(inventory)]
    errors.extend(f"domain CSV: {error}" for error in validate_domain_csv(domain_csv))
    expected_ipv4 = inventory.get("ipv4") if isinstance(inventory, Mapping) else None
    errors.extend(
        f"sniproxy: {error}"
        for error in validate_sniproxy(sniproxy, expected_ipv4=expected_ipv4)
    )
    errors.extend(
        f"mobileconfig: {error}"
        for error in validate_mobileconfig(mobileconfig, expected_ipv4=expected_ipv4)
    )
    if templates is not None:
        errors.extend(validate_templates(templates, inventory))
    return errors


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="inventory JSON path")
    parser.add_argument("--domains", required=True, help="headerless domain CSV path")
    parser.add_argument("--sniproxy", required=True, help="sniproxy JSON path")
    parser.add_argument("--mobileconfig", required=True, help="Apple mobileconfig XML path")
    parser.add_argument("--template", action="append", default=[], help="template text path (repeatable)")
    parser.add_argument("--expected-hostname", default=EXPECTED_HOSTNAME)
    args = parser.parse_args(argv)
    try:
        inventory = _read_json(args.inventory)
        sniproxy = _read_json(args.sniproxy)
        errors = [
            f"inventory: {error}"
            for error in validate_inventory(inventory, expected_hostname=args.expected_hostname)
        ]
        errors.extend(f"domain CSV: {error}" for error in validate_domain_csv(Path(args.domains)))
        expected_ipv4 = inventory.get("ipv4") if isinstance(inventory, Mapping) else None
        errors.extend(
            f"sniproxy: {error}"
            for error in validate_sniproxy(sniproxy, expected_ipv4=expected_ipv4)
        )
        errors.extend(
            f"mobileconfig: {error}"
            for error in validate_mobileconfig(Path(args.mobileconfig), expected_ipv4=expected_ipv4)
        )
        if args.template:
            templates = {path: Path(path).read_text(encoding="utf-8") for path in args.template}
            errors.extend(validate_templates(templates, inventory))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: deployment artifacts valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
