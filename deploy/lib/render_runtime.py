#!/usr/bin/env python3
"""Render all runtime files for one Smart DNS activation."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.render_config import (  # noqa: E402
    Catalog,
    load_policy,
    render_adguard_yaml,
    render_nginx_http,
    render_nginx_stream,
)


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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--services", help="comma-separated service IDs")
    parser.add_argument("--healthy-services", help="comma-separated healthy service IDs")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--doh-host", required=True)
    parser.add_argument("--doh-token", required=True)
    parser.add_argument("--password-hash", required=True)
    parser.add_argument("--certificate-root", required=True)
    parser.add_argument("--webroot", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.policy is None and args.config_dir is None:
        parser.error("one of --policy or --config-dir is required")
    if args.policy is not None and args.config_dir is not None:
        parser.error("--policy and --config-dir are mutually exclusive")

    def split_services(value):
        if value is None:
            return None
        return [service_id.strip() for service_id in value.split(",") if service_id.strip()]

    catalog = None
    selected = []
    if args.config_dir is not None:
        catalog = Catalog.load(args.config_dir)
        selected = catalog.default_service_ids
        if args.services is not None:
            selected = split_services(args.services)
        # nginx must retain the full enabled-service union.  Health state is
        # applied later by the service-level gate to AdGuard rewrites.
        rows = catalog.enabled_policy(selected)
    else:
        if args.services is not None or args.healthy_services is not None:
            parser.error("--services and --healthy-services require --config-dir")
        rows = load_policy(args.policy)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.output / "AdGuardHome.yaml").write_text(
        render_adguard_yaml(rows, args.password_hash), encoding="utf-8"
    )
    (args.output / "nginx-http.conf").write_text(
        render_nginx_http(args.doh_host, args.doh_token,
                          args.certificate_root, args.webroot), encoding="utf-8"
    )
    (args.output / "nginx-stream.conf").write_text(
        render_nginx_stream(rows, args.doh_host), encoding="utf-8"
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
    (args.output / "health-policy.json").write_text(
        json.dumps(health_policy, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
