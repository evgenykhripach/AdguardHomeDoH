#!/usr/bin/env python3
"""Render a deterministic, self-contained DoHDNS deployment staging tree.

The renderer intentionally uses only Python's standard library.  It validates
the fixed public inventory through :mod:`tools.validator`, expands a small
allow-listed template vocabulary, and writes a manifest containing hashes for
every generated artifact.  It never downloads inputs or invokes host tools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

try:
    from tools.validator import validate_inventory, validate_nginx, validate_sniproxy
except ModuleNotFoundError:  # direct ``python tools/render_deployment.py`` invocation
    from validator import validate_inventory, validate_nginx, validate_sniproxy


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = ROOT / "deploy" / "templates"
SCRIPT_ROOT = ROOT / "deploy" / "bin"
EXPECTED = {
    "version": "v2.3.0",
    "commit": "5be8145042cb3a87b76993d43187b07daa254dff",
    "source_url": "https://codeload.github.com/mosajjal/sniproxy/tar.gz/5be8145042cb3a87b76993d43187b07daa254dff",
    "source_sha256": "3197a443f29e1e4de992d2a78283ce504090d3a35242afa343e3cddbaf938c1a",
    "go_version": "1.26.0",
    "go_url": "https://go.dev/dl/go1.26.0.linux-amd64.tar.gz",
    "go_sha256": "aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235",
}
_MARKER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return dict(value)


def _validate_pinned(inventory: Mapping[str, Any]) -> None:
    sniproxy = _as_dict(inventory.get("sniproxy"), "sniproxy")
    for key, expected in EXPECTED.items():
        if sniproxy.get(key) != expected:
            raise ValueError(f"sniproxy.{key} must equal pinned value {expected!r}")
    for key in ("source_sha256", "go_sha256"):
        value = sniproxy.get(key)
        if not isinstance(value, str) or _HASH.fullmatch(value) is None:
            raise ValueError(f"sniproxy.{key} must be a lowercase SHA256 hash")

    geoip = _as_dict(inventory.get("geoip"), "geoip")
    for key in ("database_url", "sha256_url"):
        if not isinstance(geoip.get(key), str) or not geoip[key].startswith("https://"):
            raise ValueError(f"geoip.{key} must be an HTTPS URL")
    rates = _as_dict(inventory.get("rates"), "rates")
    for key in ("dns_packets_per_second", "dns_burst", "tcp_new_connections_per_second", "tcp_burst"):
        value = rates.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"rates.{key} must be a positive integer")


def validate_inventory_for_render(inventory: Mapping[str, Any], *, register_unsafely_without_email: bool = False) -> None:
    errors = validate_inventory(inventory)
    if errors:
        raise ValueError("invalid inventory: " + "; ".join(errors))
    _validate_pinned(inventory)
    acme = _as_dict(inventory.get("acme", {}), "acme")
    if not register_unsafely_without_email:
        email = acme.get("email")
        if not isinstance(email, str) or "@" not in email or not email.strip():
            raise ValueError("acme.email is required (or use --register-unsafely-without-email)")


def _safe_output(path: Path) -> Path:
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()
    forbidden = {
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/var"),
        Path("/tmp"),
        Path("/private/tmp"),
        ROOT.resolve(),
    }
    if path in forbidden:
        raise ValueError(f"refusing unsafe staging root {path}")
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing symlink staging root {path}")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"refusing non-empty staging root {path}")
    if path.name in {"", ".", ".."}:
        raise ValueError(f"refusing unsafe staging root {path}")
    return path


def _render_template(text: str, context: Mapping[str, Any], name: str) -> str:
    seen = False

    def replace(match: re.Match[str]) -> str:
        nonlocal seen
        seen = True
        key = match.group(1).strip()
        if key not in context:
            raise ValueError(f"template {name!r} contains unknown marker {key!r}")
        value = context[key]
        if isinstance(value, (dict, list, tuple)):
            raise ValueError(f"template {name!r} marker {key!r} is not scalar")
        return str(value)

    rendered = _MARKER.sub(replace, text)
    if ("{{" in rendered or "}}" in rendered) and not seen:
        raise ValueError(f"template {name!r} contains unresolved marker")
    if "{{" in rendered or "}}" in rendered:
        raise ValueError(f"template {name!r} contains unresolved marker")
    return rendered


def _write(path: Path, content: str | bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    if mode is not None:
        path.chmod(mode)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _listeners(inventory: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    # Keep listener JSON in the validator's public shape.  0.0.0.0 is used for
    # direct public binds so the kernel preserves the connecting source IP.
    sniproxy = {
        "listeners": [
            {"name": "dns-udp", "protocol": "udp", "port": 53, "interface": "0.0.0.0"},
            {"name": "dns-tcp", "protocol": "tcp", "port": 53, "interface": "0.0.0.0"},
            {"name": "dot", "protocol": "tcp", "port": 853, "interface": "0.0.0.0"},
            {"name": "sni-proxy", "protocol": "tcp", "port": 443, "interface": "0.0.0.0"},
            {"name": "prometheus", "protocol": "tcp", "port": 9090, "interface": "127.0.0.1"},
        ],
        "closed": [
            {"protocol": "udp", "port": 443},
            {"protocol": "udp", "port": 853},
        ],
    }
    nginx = {"listeners": [{"name": "acme-http", "protocol": "tcp", "port": 80, "interface": "0.0.0.0"}]}
    expected = inventory.get("ipv4")
    errors = validate_sniproxy(sniproxy, expected_ipv4=expected)
    errors.extend(validate_nginx(nginx, expected_ipv4=expected))
    if errors:
        raise ValueError("renderer listener invariant failed: " + "; ".join(errors))
    return sniproxy, nginx


def render_deployment(
    inventory: Mapping[str, Any],
    output: str | os.PathLike[str],
    *,
    domain_csv: str | os.PathLike[str] | None = None,
    register_unsafely_without_email: bool = False,
) -> dict[str, Any]:
    """Render *inventory* into *output* and return its deterministic manifest."""

    validate_inventory_for_render(inventory, register_unsafely_without_email=register_unsafely_without_email)
    output_path = _safe_output(Path(output))
    bind_public = str(inventory["ipv4"])
    rates = _as_dict(inventory["rates"], "rates")
    sniproxy = _as_dict(inventory["sniproxy"], "sniproxy")
    geoip = _as_dict(inventory["geoip"], "geoip")
    context: dict[str, Any] = {
        "hostname": inventory["hostname"],
        "ipv4": inventory["ipv4"],
        "bind_public": bind_public,
        "interface": inventory.get("interface", "eth0"),
        "dns_rate": rates["dns_packets_per_second"],
        "dns_burst": rates["dns_burst"],
        "tcp_rate": rates["tcp_new_connections_per_second"],
        "tcp_burst": rates["tcp_burst"],
        "sniproxy_version": sniproxy["version"],
        "sniproxy_commit": sniproxy["commit"],
        "geoip_database_url": geoip["database_url"],
        "geoip_sha256_url": geoip["sha256_url"],
    }

    temporary_parent = output_path.parent
    temporary_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(mkdtemp(prefix=f".{output_path.name}.", dir=str(temporary_parent)))
    try:
        template_targets = {
            "sniproxy.yaml.tmpl": "etc/sniproxy/sniproxy.yaml",
            "nginx-site.conf.tmpl": "etc/nginx/sites-available/dohdns.conf",
            "resolved.conf": "etc/systemd/resolved.conf.d/dohdns.conf",
            "nftables.nft.tmpl": "etc/nftables.d/dohdns.nft",
            "sniproxy.service.tmpl": "etc/systemd/system/sniproxy.service",
            "dohdns-geoip-update.service.tmpl": "etc/systemd/system/dohdns-geoip-update.service",
            "dohdns-geoip-update.timer": "etc/systemd/system/dohdns-geoip-update.timer",
            "dohdns-nftables.service.tmpl": "etc/systemd/system/dohdns-nftables.service",
            "certbot-deploy-hook.sh.tmpl": "etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh",
        }
        for source_name, target_name in template_targets.items():
            source = TEMPLATE_ROOT / source_name
            if not source.is_file():
                raise ValueError(f"missing deployment template {source}")
            rendered = _render_template(source.read_text(encoding="utf-8"), context, source_name)
            mode = 0o755 if source_name.endswith("hook.sh.tmpl") else None
            _write(temporary / target_name, rendered, mode)

        # Task 3 supplies policy rows.  An empty deterministic file keeps the
        # v2.3.0 config path valid without inventing any domain allowlist here.
        if domain_csv is not None:
            source = Path(domain_csv)
            if not source.is_file():
                raise ValueError(f"domain CSV does not exist: {source}")
            _write(temporary / "etc/sniproxy/domains.csv", source.read_bytes())
        else:
            _write(temporary / "etc/sniproxy/domains.csv", b"")

        sniproxy_listeners, nginx_listeners = _listeners(inventory)
        _write(temporary / "sniproxy-listeners.json", json.dumps(sniproxy_listeners, indent=2, sort_keys=True) + "\n")
        _write(temporary / "nginx-listeners.json", json.dumps(nginx_listeners, indent=2, sort_keys=True) + "\n")

        # Ship helper scripts into the staging tree.  The source tree is fixed
        # relative to this renderer, so no caller-controlled path is copied.
        for script in sorted(SCRIPT_ROOT.glob("*.sh")):
            if script.is_file():
                _write(temporary / "usr/local/libexec/dohdns" / script.name, script.read_bytes(), 0o755)

        # Keep a read-only renderer/template bundle with the installed helper
        # scripts. This makes update.sh functional after the source checkout is
        # gone while remaining deterministic and credential-free.
        app_root = temporary / "usr/local/libexec/dohdns"
        _write(app_root / "tools/render_deployment.py", (ROOT / "tools/render_deployment.py").read_bytes(), 0o755)
        _write(app_root / "tools/validator.py", (ROOT / "tools/validator.py").read_bytes(), 0o644)
        for template in sorted(TEMPLATE_ROOT.iterdir()):
            if template.is_file():
                _write(app_root / "deploy/templates" / template.name, template.read_bytes(), 0o644)
        for script in sorted(SCRIPT_ROOT.glob("*.sh")):
            if script.is_file():
                _write(app_root / "deploy/bin" / script.name, script.read_bytes(), 0o755)

        relative_files = sorted(
            str(path.relative_to(temporary))
            for path in temporary.rglob("*")
            if path.is_file()
        )
        file_hashes = {name: _hash_file(temporary / name) for name in relative_files}
        manifest_core = {
            "schema": 1,
            "hostname": inventory["hostname"],
            "ipv4": inventory["ipv4"],
            "interface": inventory.get("interface", "eth0"),
            "sniproxy": {key: sniproxy[key] for key in EXPECTED},
            "geoip": geoip,
            "rates": rates,
            "files": file_hashes,
        }
        generation = "gen-" + hashlib.sha256(
            json.dumps(manifest_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16]
        manifest = {**manifest_core, "generation": generation}
        _write(temporary / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        if output_path.exists():
            if output_path.is_symlink() or not output_path.is_dir():
                raise ValueError(f"refusing to replace non-directory output {output_path}")
            shutil.rmtree(output_path)
        temporary.rename(output_path)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _load_inventory(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("inventory JSON must contain an object")
    return dict(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--domain-csv", type=Path)
    parser.add_argument("--register-unsafely-without-email", action="store_true")
    args = parser.parse_args(argv)
    try:
        inventory = _load_inventory(args.inventory)
        domain_csv = args.domain_csv
        if domain_csv is None and isinstance(inventory.get("domain_csv"), str):
            candidate = Path(inventory["domain_csv"])
            if not candidate.is_absolute():
                candidate = args.inventory.parent / candidate
            if candidate.is_file():
                domain_csv = candidate
        manifest = render_deployment(
            inventory,
            args.output,
            domain_csv=domain_csv,
            register_unsafely_without_email=args.register_unsafely_without_email,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"rendered {manifest['generation']} to {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
