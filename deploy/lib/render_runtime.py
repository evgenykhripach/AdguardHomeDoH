#!/usr/bin/env python3
"""Render all runtime files for one Smart DNS activation."""

import argparse
import json
import sys
from copy import deepcopy
from ipaddress import IPv4Address
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from tools.render_config import (  # noqa: E402
        Catalog,
        load_policy,
        render_adguard_yaml,
        render_mobileconfig,
        render_mtproxyl_sni_map,
        render_nginx_http,
        render_nginx_stream,
        render_rewrites,
    )
except ModuleNotFoundError:
    # The manager runs this file after it has been installed outside the
    # source tree.  In that layout render_config.py is copied next to it.
    import importlib.util

    renderer_path = Path(__file__).with_name("render_config.py")
    spec = importlib.util.spec_from_file_location("adguardhome_doh_render_config", renderer_path)
    if spec is None or spec.loader is None:
        raise
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    Catalog = renderer.Catalog
    load_policy = renderer.load_policy
    render_adguard_yaml = renderer.render_adguard_yaml
    render_mobileconfig = renderer.render_mobileconfig
    render_mtproxyl_sni_map = renderer.render_mtproxyl_sni_map
    render_nginx_http = renderer.render_nginx_http
    render_nginx_stream = renderer.render_nginx_stream
    render_rewrites = renderer.render_rewrites


def render_service_health_policy(catalog, selected, rows):
    """Render service probes plus selected-domain ownership metadata.

    nginx is generated from the complete selected-service union.  The health
    worker uses this separate service map to gate rewrites without removing
    nginx SNI entries while a service is warming up.
    """

    selected = list(selected)
    selected_set = set(selected)
    associations = catalog.associations
    services = {}
    for service_id in selected:
        associated = [
            domain for domain, service_ids in associations.items()
            if service_id in service_ids
        ]
        # Every service gets one stable main endpoint.  ChatGPT additionally
        # keeps its explicit upload endpoint from service-probes.csv.
        main = "chatgpt.com" if service_id == "chatgpt" and "chatgpt.com" in associated else (sorted(associated)[0] if associated else "")
        probes = [main] if main else []
        for probe in catalog.service_probes:
            if probe.service_id == service_id and probe.hostname not in probes:
                probes.append(probe.hostname)
        services[service_id] = probes

    domains = []
    for row in rows:
        owners = [
            service_id for service_id in associations.get(row.domain, ())
            if service_id in selected_set
        ]
        domains.append({
            "domain": row.domain,
            "kind": row.kind,
            "probe": row.probe,
            "services": owners,
        })
    return {
        "enabled_services": selected,
        "services": services,
        "domains": domains,
    }


def load_existing_adguard(path):
    """Read the current config without executing YAML tags or losing keys."""
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("python3-yaml is required to preserve existing settings") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in result
                except TypeError as exc:
                    raise ValueError("existing configuration contains an invalid mapping key") from exc
                if duplicate:
                    raise ValueError("existing configuration contains a duplicate key: %s" % key)
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        config = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError, UnicodeError) as exc:
        raise ValueError("cannot safely read existing AdGuard configuration") from exc
    if not isinstance(config, dict):
        raise ValueError("existing AdGuard configuration must be a YAML mapping")
    users = config.get("users")
    if not isinstance(users, list):
        raise ValueError("existing AdGuard configuration has no valid users list")
    admins = [user for user in users if isinstance(user, dict) and user.get("name") == "admin"]
    if len(admins) != 1 or not isinstance(admins[0].get("password"), str) or not admins[0]["password"]:
        raise ValueError("existing AdGuard configuration must contain exactly one admin password hash")
    return config, admins[0]["password"]


def _merge_mapping(default, existing):
    """Use project defaults only for values absent from the current config."""
    result = deepcopy(default)
    for key, value in existing.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_mapping(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _managed_domain_names(rows):
    domains = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid existing health policy domain")
        domain, kind = row.get("domain"), row.get("kind")
        if not isinstance(domain, str) or not domain or kind not in ("fqdn", "suffix"):
            raise ValueError("invalid existing health policy domain")
        domains.add(domain)
        if kind == "suffix":
            domains.add("*." + domain)
    return domains


def merge_existing_adguard(existing, rendered, rows, seeded_rewrites, old_policy, public_ip, old_public_ip):
    """Preserve user settings while replacing only project-owned rewrites."""
    import yaml

    defaults = yaml.safe_load(rendered)
    merged = _merge_mapping(defaults, existing)
    # These settings are part of the application transport and security
    # contract, rather than ordinary user-editable filtering settings.
    for section, key in (("http", "address"), ("http", "doh"),
                         ("dns", "bind_hosts"), ("dns", "port")):
        if not isinstance(merged.get(section), dict):
            raise ValueError("existing AdGuard %s configuration must be a mapping" % section)
        merged[section][key] = deepcopy(defaults[section][key])
    for key in ("auth_attempts", "block_auth_min"):
        merged[key] = defaults[key]

    filtering = merged.get("filtering")
    old_filtering = existing.get("filtering", {})
    if not isinstance(filtering, dict) or not isinstance(old_filtering, dict):
        raise ValueError("existing AdGuard filtering configuration must be a mapping")
    old_rewrites = old_filtering.get("rewrites", [])
    if old_rewrites is None:
        old_rewrites = []
    if not isinstance(old_rewrites, list) or any(not isinstance(item, dict) for item in old_rewrites):
        raise ValueError("existing AdGuard rewrites must be a list of mappings")
    names = _managed_domain_names(old_policy)
    names.update(_managed_domain_names([{"domain": row.domain, "kind": row.kind} for row in rows]))
    managed_answers = {str(public_ip), str(old_public_ip), "127.0.0.1", "127.0.0.1:53"}
    preserved = [deepcopy(item) for item in old_rewrites
                 if not (item.get("domain") in names and str(item.get("answer", "")) in managed_answers)]
    filtering["rewrites"] = preserved + deepcopy(seeded_rewrites)
    filtering["rewrites_enabled"] = True
    return yaml.safe_dump(merged, allow_unicode=True, sort_keys=False, default_flow_style=False)


def load_previous_policy(path):
    if path is None:
        return []
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("cannot safely read existing health policy") from exc
    rows = policy.get("domains") if isinstance(policy, dict) else policy
    if not isinstance(rows, list):
        raise ValueError("existing health policy has no domains list")
    _managed_domain_names(rows)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--front", choices=("standard", "mtproxyl"), default="standard")
    parser.add_argument("--services", help="comma-separated service IDs")
    parser.add_argument("--healthy-services", help="comma-separated healthy service IDs")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--relay", help="forward routed services to this exit host")
    parser.add_argument("--local-site", action="append", default=[],
                        help="HOST=IPV4:PORT served behind the stream listener; * sets the default")
    parser.add_argument("--doh-host", required=True)
    token_args = parser.add_mutually_exclusive_group(required=True)
    token_args.add_argument("--doh-token")
    token_args.add_argument("--doh-token-file", type=Path)
    hash_args = parser.add_mutually_exclusive_group()
    hash_args.add_argument("--password-hash")
    hash_args.add_argument("--password-hash-file", type=Path)
    parser.add_argument("--existing-config", type=Path)
    parser.add_argument("--existing-policy", type=Path)
    parser.add_argument("--existing-public-ip")
    parser.add_argument("--certificate-root", required=True)
    parser.add_argument("--webroot", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.policy is None and args.config_dir is None:
        parser.error("one of --policy or --config-dir is required")
    if args.policy is not None and args.config_dir is not None and args.front == "standard":
        parser.error("--policy and --config-dir are mutually exclusive")
    if args.front == "mtproxyl" and args.config_dir is None:
        parser.error("--front mtproxyl requires --config-dir for the complete SNI map")
    if args.policy is not None and args.services is not None:
        parser.error("--services cannot be combined with --policy")

    doh_token = (args.doh_token_file.read_text(encoding="utf-8").strip()
                 if args.doh_token_file else args.doh_token)
    password_hash = (args.password_hash_file.read_text(encoding="utf-8").strip()
                     if args.password_hash_file else args.password_hash)
    existing = None
    if args.existing_config is not None:
        existing, old_admin_hash = load_existing_adguard(args.existing_config)
        if not password_hash:
            password_hash = old_admin_hash
    if not password_hash:
        parser.error("--password-hash, --password-hash-file or --existing-config is required")
    if args.existing_public_ip:
        try:
            old_public_ip = str(IPv4Address(args.existing_public_ip))
        except ValueError:
            parser.error("--existing-public-ip must be IPv4")
    else:
        old_public_ip = args.public_ip
    old_policy = load_previous_policy(args.existing_policy)

    def split_services(value):
        if value is None:
            return None
        return [service_id.strip() for service_id in value.split(",") if service_id.strip()]

    catalog = None
    selected = []
    healthy = split_services(args.healthy_services)
    seeded_rewrites = []
    full_catalog = Catalog.load(args.config_dir) if args.config_dir is not None else None
    if args.policy is None:
        catalog = full_catalog
        selected = catalog.default_service_ids
        if args.services is not None:
            selected = split_services(args.services)
        # nginx must retain the full enabled-service union.  Health state is
        # applied later by the service-level gate to AdGuard rewrites.
        rows = catalog.enabled_policy(selected)
        if healthy:
            # Activation restarts AdGuard Home with this file, discarding the
            # rewrites the gate had added over the API.  Services that were
            # already healthy are written back immediately, so no client
            # resolves a routed service to its real address in between.
            seeded_rewrites = render_rewrites(
                catalog.enabled_policy(selected, healthy), args.public_ip
            )
    else:
        rows = load_policy(args.policy)
        if healthy:
            healthy_domains = set(healthy)
            seeded_rewrites = render_rewrites(
                [row for row in rows if row.domain in healthy_domains], args.public_ip
            )
    front_map = None
    if args.front == "mtproxyl":
        front_map = render_mtproxyl_sni_map(
            [*full_catalog.full_policy(), *(rows if args.policy is not None else [])],
            args.doh_host,
        )
    stream_config = render_nginx_stream(
        rows, args.doh_host, relay=args.relay, local_sites=args.local_site, front=args.front
    )
    adguard_config = render_adguard_yaml(rows, password_hash, rewrites=seeded_rewrites)
    if existing is not None:
        adguard_config = merge_existing_adguard(
            existing, adguard_config, rows, seeded_rewrites, old_policy, args.public_ip, old_public_ip
        )
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.output / "AdGuardHome.yaml").write_text(adguard_config, encoding="utf-8")
    (args.output / "nginx-http.conf").write_text(
        render_nginx_http(args.doh_host, doh_token,
                          args.certificate_root, args.webroot, front=args.front), encoding="utf-8"
    )
    # The profile scopes DoH to the whole catalog rather than to the selected
    # services, so changing the selection never requires reinstalling it.
    if catalog is not None:
        match_domains = {row.domain for row in catalog.full_policy()}
    else:
        match_domains = {row.domain for row in rows}
    (args.output / (args.doh_host + ".mobileconfig")).write_text(
        render_mobileconfig(
            args.doh_host, doh_token, args.public_ip,
            match_domains=sorted(match_domains),
        ),
        encoding="utf-8",
    )
    (args.output / "nginx-stream.conf").write_text(
        stream_config, encoding="utf-8",
    )
    if front_map is not None:
        (args.output / "mtproxyl-sni.map").write_text(front_map, encoding="utf-8")
    if catalog is None:
        health_policy = {
            "enabled_services": [],
            "services": {},
            "domains": [
                {"domain": row.domain, "kind": row.kind, "probe": row.probe, "services": []}
                for row in rows
            ],
        }
    else:
        health_policy = render_service_health_policy(catalog, selected, rows)
    (args.output / "health-policy.json").write_text(
        json.dumps(health_policy, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
