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


def load_healthcheck():
    """Use the installed health gate's policy and state validation rules."""

    import importlib.util

    source = Path(__file__).with_name("healthcheck.py")
    if not source.is_file():
        source = Path(__file__).resolve().parents[1] / "templates" / "healthcheck.py"
    spec = importlib.util.spec_from_file_location("adguardhome_doh_healthcheck", source)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load health state validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError) as exc:
        raise ValueError("cannot load health state validator") from exc
    if not hasattr(module, "_health_record") or not hasattr(module, "_rules_by_health"):
        raise ValueError("health state validator is incompatible")
    return module


def merge_existing_adguard(existing, rendered, rows, seeded_rewrites, old_policy, public_ip, old_public_ip,
                           unknown_names=None):
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
    old_names = _managed_domain_names(old_policy)
    names = old_names | _managed_domain_names([{"domain": row.domain, "kind": row.kind} for row in rows])
    managed_answers = {str(public_ip), str(old_public_ip), "127.0.0.1", "127.0.0.1:53"}
    if unknown_names is not None:
        return _merge_unknown_rewrites(
            merged, old_filtering, old_rewrites, seeded_rewrites, old_names, names,
            managed_answers, unknown_names, public_ip, old_public_ip,
        )
    preserved = [deepcopy(item) for item in old_rewrites
                 if not (item.get("domain") in names and str(item.get("answer", "")) in managed_answers)]
    filtering["rewrites"] = preserved + deepcopy(seeded_rewrites)
    filtering["rewrites_enabled"] = True
    return yaml.safe_dump(merged, allow_unicode=True, sort_keys=False, default_flow_style=False)


def _merge_unknown_rewrites(merged, old_filtering, old_rewrites, seeded_rewrites,
                            old_names, names, managed_answers, unknown_names, public_ip, old_public_ip):
    """Preserve only existing rules whose selected owners are still unknown."""

    import yaml

    global_enabled = old_filtering.get("rewrites_enabled", True)
    if not isinstance(global_enabled, bool):
        raise ValueError("cannot determine whether rewrites are globally enabled")
    seeded = {(item["domain"], str(item["answer"])): deepcopy(item) for item in seeded_rewrites}
    preserved = []
    retained = {}
    seen_unknown = set()
    for item in old_rewrites:
        domain = item.get("domain")
        answer = str(item.get("answer", ""))
        key = (domain, answer)
        if domain not in names or answer not in managed_answers:
            preserved.append(deepcopy(item))
            continue
        if domain not in unknown_names:
            continue
        if key in seen_unknown:
            raise ValueError("cannot safely preserve duplicate unknown rewrites")
        seen_unknown.add(key)

        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("cannot determine whether an unknown rewrite is enabled")
        was_managed = domain in old_names
        if answer == old_public_ip and old_public_ip != public_ip:
            if global_enabled and enabled:
                raise ValueError("cannot change public IP while an active rewrite has unknown health")
            if not was_managed:
                raise ValueError("cannot identify ownership of an old public IP rewrite")
        if not was_managed and answer != public_ip:
            raise ValueError("cannot identify ownership of a rewrite for a newly selected domain")
        if answer != public_ip:
            continue
        if not was_managed and global_enabled is False and enabled:
            raise ValueError("cannot preserve an enabled user rewrite while rewrites are globally disabled")
        if (global_enabled and enabled) or (not was_managed and not enabled and key not in seeded):
            retained[key] = deepcopy(item)

    # A healthy shared owner can seed the same key. Keep the original metadata
    # when the existing enabled rule is also protected by an unknown owner.
    for key, item in retained.items():
        seeded[key] = item
    merged["filtering"]["rewrites"] = preserved + list(seeded.values())
    merged["filtering"]["rewrites_enabled"] = True
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


def load_validated_previous_policy(path, healthcheck):
    """Validate policy and reject ambiguous duplicate keys before rendering."""

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        validated = healthcheck.load_policy(path)
        if parsed != validated:
            raise ValueError("policy changed during validation")
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("cannot safely read existing health policy") from exc
    return validated["domains"] if isinstance(validated, dict) else validated


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--front", choices=("standard", "mtproxyl"), default="standard")
    parser.add_argument("--services", help="comma-separated service IDs")
    parser.add_argument("--healthy-services", help="comma-separated healthy service IDs")
    parser.add_argument("--health-state", type=Path)
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--relay", help="forward routed services to this exit host")
    parser.add_argument("--local-site", action="append", default=[],
                        help="HOST=IPV4:PORT served behind the stream listener; * sets the default")
    parser.add_argument("--doh-host", required=True)
    parser.add_argument("--admin-host")
    parser.add_argument("--admin-certificate-root")
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
    if (args.admin_host is None) != (args.admin_certificate_root is None):
        parser.error("--admin-host and --admin-certificate-root must be provided together")
    if args.admin_host is not None and args.front != "mtproxyl":
        parser.error("--admin-host requires --front mtproxyl")
    if args.policy is not None and args.services is not None:
        parser.error("--services cannot be combined with --policy")
    if args.health_state is not None and args.existing_config is not None and args.existing_policy is None:
        parser.error("existing health policy (--existing-policy) is required with --health-state and --existing-config")

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
    healthcheck = load_healthcheck() if args.health_state is not None else None
    if healthcheck is not None and existing is not None:
        old_policy = load_validated_previous_policy(args.existing_policy, healthcheck)
    else:
        old_policy = load_previous_policy(args.existing_policy)
    health_state = healthcheck.load_json(args.health_state, {}) if healthcheck is not None else None
    if healthcheck is not None and not isinstance(health_state, dict):
        health_state = {}

    def split_services(value):
        if value is None:
            return None
        return [service_id.strip() for service_id in value.split(",") if service_id.strip()]

    catalog = None
    selected = []
    healthy = split_services(args.healthy_services)
    if healthcheck is not None:
        known_healthy = {str(key) for key, value in health_state.items()
                         if healthcheck._health_record(value)[0] is True}
        healthy = sorted(known_healthy) if healthy is None else [item for item in healthy if item in known_healthy]
    seeded_rewrites = []
    full_catalog = Catalog.load(args.config_dir) if args.config_dir is not None else None
    if args.policy is None:
        catalog = full_catalog
        selected = catalog.default_service_ids
        if args.services is not None:
            selected = split_services(args.services)
        if healthcheck is not None:
            healthy = [service_id for service_id in healthy if service_id in selected]
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
    front_map = None
    if args.front == "mtproxyl":
        front_map = render_mtproxyl_sni_map(
            [*full_catalog.full_policy(), *(rows if args.policy is not None else [])],
            args.doh_host,
            admin_host=args.admin_host,
        )
    stream_config = render_nginx_stream(
        rows, args.doh_host, relay=args.relay, local_sites=args.local_site, front=args.front,
        admin_host=args.admin_host,
    )
    http_config = render_nginx_http(
        args.doh_host, doh_token, args.certificate_root, args.webroot, front=args.front,
        admin_host=args.admin_host, admin_certificate_root=args.admin_certificate_root,
    )
    adguard_config = render_adguard_yaml(rows, password_hash, rewrites=seeded_rewrites)
    if existing is not None:
        unknown_names = None
        if healthcheck is not None:
            _, unknown = healthcheck._rules_by_health(health_policy, health_state, args.public_ip)
            unknown_names = {domain for domain, _answer in unknown}
        adguard_config = merge_existing_adguard(
            existing, adguard_config, rows, seeded_rewrites, old_policy, args.public_ip, old_public_ip,
            unknown_names,
        )
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.output / "AdGuardHome.yaml").write_text(adguard_config, encoding="utf-8")
    (args.output / "nginx-http.conf").write_text(http_config, encoding="utf-8")
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
    (args.output / "health-policy.json").write_text(
        json.dumps(health_policy, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
