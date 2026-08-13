#!/usr/bin/env python3
"""Render the canonical Smart DNS policy into runtime configuration."""

import argparse
import csv
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Collection, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class PolicyRow:
    domain: str
    kind: str
    probe: str


@dataclass(frozen=True)
class ServiceRow:
    id: str
    name_ru: str
    category: str
    default_enabled: bool
    risk_level: str


@dataclass(frozen=True)
class DomainRow:
    domain: str
    kind: str


@dataclass(frozen=True)
class ServiceDomainRow:
    service_id: str
    domain: str


@dataclass(frozen=True)
class ServiceProbeRow:
    service_id: str
    hostname: str


class Catalog:
    """Validated product/service/domain catalog used by all renderers."""

    _CSV_HEADERS = {
        "services.csv": ["id", "name_ru", "category", "default_enabled", "risk_level"],
        "domains.csv": ["domain", "kind"],
        "service-domains.csv": ["service_id", "domain"],
        "service-probes.csv": ["service_id", "hostname"],
    }

    def __init__(
        self,
        services: Sequence[ServiceRow],
        domains: Sequence[DomainRow],
        service_domains: Sequence[ServiceDomainRow],
        service_probes: Sequence[ServiceProbeRow],
    ):
        self.services = tuple(services)
        self.domains = tuple(domains)
        self.service_domains = tuple(service_domains)
        self.service_probes = tuple(service_probes)
        self._service_ids = {service.id for service in self.services}
        self._domain_ids = {domain.domain for domain in self.domains}
        associations: Dict[str, List[str]] = {domain.domain: [] for domain in self.domains}
        for row in self.service_domains:
            associations[row.domain].append(row.service_id)
        self._associations = {
            domain: tuple(sorted(service_ids))
            for domain, service_ids in associations.items()
        }
        probes: Dict[str, List[str]] = {service.id: [] for service in self.services}
        for row in self.service_probes:
            probes[row.service_id].append(row.hostname)
        self._probes = {
            service_id: tuple(sorted(hostnames))
            for service_id, hostnames in probes.items()
        }

    @property
    def default_service_ids(self) -> Tuple[str, ...]:
        return tuple(service.id for service in self.services if service.default_enabled)

    @property
    def associations(self) -> Mapping[str, Tuple[str, ...]]:
        return self._associations

    @classmethod
    def _read_rows(cls, config_dir: Path, filename: str) -> List[dict]:
        path = config_dir / filename
        try:
            stream = path.open("r", encoding="utf-8", newline="")
        except OSError as exc:
            raise ValueError("cannot read %s: %s" % (path, exc)) from exc
        with stream:
            reader = csv.DictReader(stream)
            expected = cls._CSV_HEADERS[filename]
            if reader.fieldnames != expected:
                raise ValueError(
                    "%s header must be exactly: %s"
                    % (filename, ",".join(expected))
                )
            return [
                raw
                for raw in reader
                if raw and any((value or "").strip() for value in raw.values())
            ]

    @staticmethod
    def _identifier(value: str, field: str) -> str:
        value = (value or "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", value):
            raise ValueError("%s must be a normalized identifier: %r" % (field, value))
        return value

    @classmethod
    def load(cls, config_dir: Path) -> "Catalog":
        config_dir = Path(config_dir)
        service_rows = cls._read_rows(config_dir, "services.csv")
        domain_rows = cls._read_rows(config_dir, "domains.csv")
        relation_rows = cls._read_rows(config_dir, "service-domains.csv")
        probe_rows = cls._read_rows(config_dir, "service-probes.csv")

        services: List[ServiceRow] = []
        service_ids = set()
        for line_number, raw in enumerate(service_rows, 2):
            service_id = cls._identifier(raw.get("id", ""), "service id")
            if service_id in service_ids:
                raise ValueError("services.csv line %d: duplicate service %s" % (line_number, service_id))
            name_ru = (raw.get("name_ru") or "").strip()
            category = (raw.get("category") or "").strip()
            if not name_ru or not category:
                raise ValueError("services.csv line %d: name_ru and category are required" % line_number)
            default_value = (raw.get("default_enabled") or "").strip().lower()
            if default_value not in ("true", "false"):
                raise ValueError(
                    "services.csv line %d: default_enabled must be true or false" % line_number
                )
            risk_level = (raw.get("risk_level") or "").strip().lower()
            if risk_level not in ("standard", "experimental"):
                raise ValueError(
                    "services.csv line %d: risk_level must be standard or experimental" % line_number
                )
            if default_value == "true" and risk_level == "experimental":
                raise ValueError(
                    "services.csv line %d: experimental service cannot be default-enabled" % line_number
                )
            services.append(
                ServiceRow(service_id, name_ru, category, default_value == "true", risk_level)
            )
            service_ids.add(service_id)
        if not services:
            raise ValueError("services.csv is empty")

        domains: List[DomainRow] = []
        domain_ids = set()
        for line_number, raw in enumerate(domain_rows, 2):
            domain = _hostname(raw.get("domain", ""), "domain")
            kind = (raw.get("kind") or "").strip().lower()
            if kind not in ("fqdn", "suffix"):
                raise ValueError("domains.csv line %d: kind must be fqdn or suffix" % line_number)
            if domain in domain_ids:
                raise ValueError("domains.csv line %d: duplicate domain %s" % (line_number, domain))
            domains.append(DomainRow(domain, kind))
            domain_ids.add(domain)
        if not domains:
            raise ValueError("domains.csv is empty")

        service_domains: List[ServiceDomainRow] = []
        relation_ids = set()
        for line_number, raw in enumerate(relation_rows, 2):
            service_id = cls._identifier(raw.get("service_id", ""), "service_id")
            domain = _hostname(raw.get("domain", ""), "domain")
            if service_id not in service_ids:
                raise ValueError(
                    "service-domains.csv line %d: unknown service %s" % (line_number, service_id)
                )
            if domain not in domain_ids:
                raise ValueError(
                    "service-domains.csv line %d: unknown domain %s" % (line_number, domain)
                )
            key = (service_id, domain)
            if key in relation_ids:
                raise ValueError(
                    "service-domains.csv line %d: duplicate relation %s/%s"
                    % (line_number, service_id, domain)
                )
            service_domains.append(ServiceDomainRow(service_id, domain))
            relation_ids.add(key)
        if not service_domains:
            raise ValueError("service-domains.csv is empty")

        service_probes: List[ServiceProbeRow] = []
        probe_ids = set()
        for line_number, raw in enumerate(probe_rows, 2):
            service_id = cls._identifier(raw.get("service_id", ""), "service_id")
            hostname = _hostname(raw.get("hostname", ""), "hostname")
            if service_id not in service_ids:
                raise ValueError(
                    "service-probes.csv line %d: unknown service %s" % (line_number, service_id)
                )
            associated_domains = [
                row.domain for row in service_domains if row.service_id == service_id
            ]
            if not any(
                hostname == domain or hostname.endswith("." + domain)
                for domain in associated_domains
            ):
                raise ValueError(
                    "service-probes.csv line %d: hostname %s is not associated with service %s"
                    % (line_number, hostname, service_id)
                )
            key = (service_id, hostname)
            if key in probe_ids:
                raise ValueError(
                    "service-probes.csv line %d: duplicate probe %s/%s"
                    % (line_number, service_id, hostname)
                )
            service_probes.append(ServiceProbeRow(service_id, hostname))
            probe_ids.add(key)

        service_domain_ids = {row.service_id for row in service_domains}
        if missing := service_ids - service_domain_ids:
            raise ValueError("services without domains: %s" % ",".join(sorted(missing)))
        domain_service_ids = {row.domain for row in service_domains}
        if missing := domain_ids - domain_service_ids:
            raise ValueError("domains without services: %s" % ",".join(sorted(missing)))

        return cls(services, domains, service_domains, service_probes)

    def enabled_policy(
        self,
        service_ids: Collection[str],
        healthy_service_ids: Optional[Collection[str]] = None,
    ) -> List[PolicyRow]:
        selected = {self._identifier(service_id, "service id") for service_id in service_ids}
        unknown = selected - self._service_ids
        if unknown:
            raise ValueError("unknown services: %s" % ",".join(sorted(unknown)))
        if healthy_service_ids is None:
            active = selected
        else:
            healthy = {self._identifier(service_id, "healthy service id") for service_id in healthy_service_ids}
            unknown = healthy - self._service_ids
            if unknown:
                raise ValueError("unknown healthy services: %s" % ",".join(sorted(unknown)))
            active = selected & healthy

        rows: List[PolicyRow] = []
        for domain in self.domains:
            associated = [service_id for service_id in self._associations[domain.domain] if service_id in active]
            if not associated:
                continue
            probe = domain.domain
            for service_id in associated:
                for hostname in self._probes[service_id]:
                    if hostname == domain.domain or hostname.endswith("." + domain.domain):
                        probe = hostname
                        break
                if probe != domain.domain:
                    break
            rows.append(PolicyRow(domain.domain, domain.kind, probe))
        return rows

    def full_policy(self) -> List[PolicyRow]:
        return self.enabled_policy(self._service_ids)


def _hostname(value: str, field: str, allow_empty: bool = False) -> str:
    value = value.strip().lower()
    if not value and allow_empty:
        return ""
    if value.endswith(".") or not HOST_RE.fullmatch(value):
        raise ValueError("%s must be a normalized hostname: %r" % (field, value))
    return value


def load_policy(path: Path) -> List[PolicyRow]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        expected = ["domain", "kind", "probe"]
        if reader.fieldnames != expected:
            raise ValueError("policy header must be exactly: domain,kind,probe")
        rows = []
        seen = set()
        for line_number, raw in enumerate(reader, 2):
            if not raw or all(not (value or "").strip() for value in raw.values()):
                continue
            domain = _hostname(raw.get("domain", ""), "domain")
            kind = (raw.get("kind") or "").strip().lower()
            if kind not in ("fqdn", "suffix"):
                raise ValueError("line %d: kind must be fqdn or suffix" % line_number)
            probe = _hostname(raw.get("probe", ""), "probe", allow_empty=True) or domain
            key = (domain, kind)
            if key in seen:
                raise ValueError("line %d: duplicate policy row %s/%s" % (line_number, domain, kind))
            seen.add(key)
            rows.append(PolicyRow(domain, kind, probe))
    if not rows:
        raise ValueError("policy is empty")
    return sorted(rows, key=lambda row: (row.domain, row.kind))


def _public_ipv4(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise ValueError("public-ip must be IPv4")
    return str(address)


def _ordered_rows(rows: Iterable[PolicyRow]) -> List[PolicyRow]:
    return sorted(rows, key=lambda row: (row.domain, row.kind))


def render_rewrites(rows: Sequence[PolicyRow], public_ip: str):
    public_ip = _public_ipv4(public_ip)
    output = []
    for row in _ordered_rows(rows):
        names = [row.domain]
        if row.kind == "suffix":
            names.append("*." + row.domain)
        for name in names:
            output.append({"domain": name, "answer": public_ip, "enabled": True})
    return output


def render_rewrites_yaml(rows: Sequence[PolicyRow], public_ip: str) -> str:
    lines = ["rewrites:"]
    for item in render_rewrites(rows, public_ip):
        lines.extend([
            "  - domain: '%s'" % item["domain"],
            "    answer: %s" % item["answer"],
            "    enabled: true",
        ])
    return "\n".join(lines) + "\n"


def render_adguard_yaml(rows: Sequence[PolicyRow], password_hash: str, upstreams=None) -> str:
    upstreams = list(upstreams or [
        "https://dns10.quad9.net/dns-query",
        "https://dns.cloudflare.com/dns-query",
        "https://dns.google/dns-query",
    ])
    if not password_hash or "\n" in password_hash:
        raise ValueError("password hash is required")
    lines = [
        "http:",
        "  pprof:",
        "    port: 6060",
        "    enabled: false",
        "  doh:",
        "    routes:",
        "      - GET /dns-query",
        "      - POST /dns-query",
        "      - GET /dns-query/{ClientID}",
        "      - POST /dns-query/{ClientID}",
        "    insecure_enabled: true",
        "  address: 127.0.0.1:3001",
        "  session_ttl: 30d",
        "users:",
        "  - name: admin",
        "    password: %s" % password_hash,
        "auth_attempts: 5",
        "block_auth_min: 15",
        "http_proxy: \"\"",
        "language: ru",
        "theme: auto",
        "dns:",
        "  bind_hosts:",
        "    - 127.0.0.1",
        "  port: 53",
        "  anonymize_client_ip: true",
        "  ratelimit: 20",
        "  ratelimit_subnet_len_ipv4: 24",
        "  ratelimit_subnet_len_ipv6: 56",
        "  ratelimit_whitelist: []",
        "  refuse_any: true",
        "  upstream_dns:",
    ]
    lines.extend("    - %s" % upstream for upstream in upstreams)
    lines.extend([
        "  upstream_dns_file: \"\"",
        "  bootstrap_dns:",
        "    - 9.9.9.10",
        "    - 149.112.112.10",
        "  fallback_dns: []",
        "  upstream_mode: parallel",
        "  fastest_timeout: 1s",
        "  allowed_clients: []",
        "  disallowed_clients: []",
        "  blocked_hosts:",
        "    - version.bind",
        "    - id.server",
        "    - hostname.bind",
        "  trusted_proxies:",
        "    - 127.0.0.0/8",
        "    - ::1/128",
        "  cache_enabled: true",
        "  cache_size: 4194304",
        "  cache_ttl_min: 0",
        "  cache_ttl_max: 0",
        "  cache_optimistic: false",
        "  bogus_nxdomain: []",
        "  aaaa_disabled: false",
        "  enable_dnssec: true",
        "  edns_client_subnet:",
        "    custom_ip: \"\"",
        "    enabled: false",
        "    use_custom: false",
        "  max_goroutines: 300",
        "  handle_ddr: true",
        "  ipset: []",
        "  ipset_file: \"\"",
        "  bootstrap_prefer_ipv6: false",
        "  upstream_timeout: 10s",
        "  private_networks: []",
        "  use_private_ptr_resolvers: true",
        "  local_ptr_upstreams: []",
        "  use_dns64: false",
        "  dns64_prefixes: []",
        "  serve_http3: false",
        "  use_http3_upstreams: false",
        "  serve_plain_dns: true",
        "  hostsfile_enabled: true",
        "  pending_requests:",
        "    enabled: true",
        "tls:",
        "  enabled: false",
        "  server_name: \"\"",
        "  force_https: false",
        "  port_https: 0",
        "  port_dns_over_tls: 0",
        "  port_dns_over_quic: 0",
        "  port_dnscrypt: 0",
        "  certificate_chain: \"\"",
        "  private_key: \"\"",
        "  certificate_path: \"\"",
        "  private_key_path: \"\"",
        "querylog:",
        "  dir_path: \"\"",
        "  interval: 1d",
        "  size_memory: 1000",
        "  enabled: true",
        "  file_enabled: true",
        "statistics:",
        "  dir_path: \"\"",
        "  interval: 1d",
        "  enabled: true",
        "filters: []",
        "whitelist_filters: []",
        "user_rules: []",
        "dhcp:",
        "  enabled: false",
        "  interface_name: \"\"",
        "filtering:",
        "  blocking_mode: default",
        "  blocking_ipv4: \"\"",
        "  blocking_ipv6: \"\"",
        "  rewrites: []",
    ])
    lines.extend([
        "  rewrites_enabled: true",
        "  filtering_enabled: true",
        "  protection_enabled: true",
        "clients:",
        "  runtime_sources:",
        "    whois: true",
        "    arp: true",
        "    rdns: true",
        "    dhcp: true",
        "    hosts: true",
        "  persistent: []",
        "log:",
        "  enabled: true",
        "  file: \"\"",
        "  max_backups: 0",
        "  max_size: 100",
        "  max_age: 3",
        "  compress: false",
        "  local_time: false",
        "  verbose: false",
        "os:",
        "  group: \"\"",
        "  user: \"\"",
        "  rlimit_nofile: 0",
        "schema_version: 34",
        "",
    ])
    return "\n".join(lines)


def render_mobileconfig(doh_host: str, doh_token: str) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    if not re.fullmatch(r"[a-f0-9]{32,64}", doh_token):
        raise ValueError("doh-token must be lowercase hexadecimal")
    profile_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "adguardhome-doh-profile:" + doh_host))
    payload_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "adguardhome-doh-payload:" + doh_host))
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict><key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>https://{host}/doh/{token}</string></dict>
<key>PayloadDisplayName</key><string>{host}</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.{payload_id}</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadType</key><string>com.apple.dnsSettings.managed</string><key>PayloadUUID</key><string>{payload_id}</string><key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>{host}</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.{profile_id}</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadScope</key><string>System</string><key>PayloadRemovalDisallowed</key><false/><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>{profile_id}</string><key>PayloadVersion</key><integer>1</integer>
</dict></plist>
""".format(host=doh_host, token=doh_token, payload_id=payload_id, profile_id=profile_id)


def render_nginx_http(doh_host: str, doh_token: str, certificate_root: str, webroot: str) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    if not re.fullmatch(r"[a-f0-9]{32,64}", doh_token):
        raise ValueError("doh-token must be lowercase hexadecimal")
    lines = [
        "server {",
        "    listen 80;",
        "    listen [::]:80;",
        "    server_name %s;" % doh_host,
        "    location ^~ /.well-known/acme-challenge/ {",
        "        root %s;" % webroot,
        "        default_type text/plain;",
        "        try_files $uri =404;",
        "    }",
        "    location / { return 301 https://$host$request_uri; }",
        "}",
        "server {",
        "    listen 127.0.0.1:4443 ssl;",
        "    server_name %s;" % doh_host,
        "    ssl_certificate %s/fullchain.pem;" % certificate_root,
        "    ssl_certificate_key %s/privkey.pem;" % certificate_root,
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        "    ssl_session_timeout 1d;",
        "    add_header Strict-Transport-Security \"max-age=31536000\" always;",
        "    client_max_body_size 2m;",
        "    location = /%s.mobileconfig {" % doh_token,
        "        root %s;" % webroot,
        "        default_type application/x-apple-aspen-config;",
        "        add_header Content-Disposition \"attachment; filename=%s.mobileconfig\" always;" % doh_host,
        "        add_header Cache-Control \"no-store\" always;",
        "        try_files /%s.mobileconfig =404;" % doh_host,
        "    }",
        "    location = /dns-query { return 404; }",
        "    location = /doh/%s {" % doh_token,
        "        proxy_pass http://127.0.0.1:3001/dns-query;",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Forwarded-For $remote_addr;",
        "        proxy_set_header X-Forwarded-Proto https;",
        "        proxy_buffering off;",
        "        proxy_read_timeout 30s;",
        "    }",
        "    location / {",
        "        proxy_pass http://127.0.0.1:3001;",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Forwarded-For $remote_addr;",
        "        proxy_set_header X-Forwarded-Proto https;",
        "        proxy_buffering off;",
        "        proxy_read_timeout 30s;",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def render_nginx_stream(rows: Sequence[PolicyRow], doh_host: str) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    lines = [
        "stream {",
        "    map_hash_bucket_size 128;",
        "    map $ssl_preread_server_name $adguardhome_doh_backend {",
        "        hostnames;",
        "        default 127.0.0.1:9;",
        "        %s 127.0.0.1:4443;" % doh_host,
    ]
    for row in _ordered_rows(rows):
        name = "." + row.domain if row.kind == "suffix" else row.domain
        lines.append("        %s $ssl_preread_server_name:443;" % name)
    lines.extend([
        "    }",
        "    resolver 9.9.9.10 149.112.112.10 valid=60s ipv4=on ipv6=off;",
        "    server {",
        "        listen 443;",
        "        proxy_connect_timeout 5s;",
        "        proxy_timeout 10m;",
        "        proxy_pass $adguardhome_doh_backend;",
        "        ssl_preread on;",
        "        access_log off;",
        "        error_log /var/log/adguardhome-doh/nginx-stream.error.log warn;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def render_health_policy(rows: Iterable[PolicyRow]) -> str:
    payload = [
        {"domain": row.domain, "kind": row.kind, "probe": row.probe}
        for row in _ordered_rows(rows)
    ]
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def render(
    output: Path,
    policy: Optional[Path] = None,
    public_ip: str = "",
    doh_host: str = "",
    *,
    config_dir: Optional[Path] = None,
    service_ids: Optional[Collection[str]] = None,
    healthy_service_ids: Optional[Collection[str]] = None,
) -> None:
    if config_dir is not None:
        catalog = Catalog.load(config_dir)
        selected = catalog.default_service_ids if service_ids is None else service_ids
        rows = catalog.enabled_policy(selected, healthy_service_ids)
    elif policy is not None:
        rows = load_policy(policy)
    else:
        raise ValueError("either policy or config-dir is required")
    output.mkdir(parents=True, exist_ok=True)
    (output / "nginx-stream.conf").write_text(
        render_nginx_stream(rows, doh_host), encoding="utf-8"
    )
    (output / "rewrites.yaml").write_text(
        render_rewrites_yaml(rows, public_ip), encoding="utf-8"
    )
    (output / "rewrites.json").write_text(
        json.dumps(render_rewrites(rows, public_ip), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "health-policy.json").write_text(
        render_health_policy(rows), encoding="utf-8"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--services", help="comma-separated service IDs")
    parser.add_argument("--healthy-services", help="comma-separated healthy service IDs")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--doh-host", required=True)
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

    render(
        args.output,
        args.policy,
        args.public_ip,
        args.doh_host,
        config_dir=args.config_dir,
        service_ids=split_services(args.services),
        healthy_service_ids=split_services(args.healthy_services),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
