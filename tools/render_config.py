#!/usr/bin/env python3
"""Render the canonical Smart DNS policy into runtime configuration."""

import argparse
import csv
import ipaddress
import json
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Collection, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
NGINX_VERSION_RE = re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)")

# Encrypted upstreams keep queries private.  The IP-addressed fallbacks need no
# bootstrap resolution and are used only when every upstream stops answering:
# an Apple client with an installed DoH profile has no plain-DNS fallback of
# its own, so a server-side dead end takes the whole device offline.
DEFAULT_UPSTREAM_DNS = (
    "https://dns10.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query",
    "https://dns.google/dns-query",
)
DEFAULT_BOOTSTRAP_DNS = ("9.9.9.10", "149.112.112.10", "1.1.1.1", "8.8.8.8")
DEFAULT_FALLBACK_DNS = ("tls://1.1.1.1", "tls://8.8.8.8", "1.1.1.1", "8.8.8.8")
# nginx stream cannot route SNI without a working resolver, so the list spans
# three operators instead of one.
DEFAULT_STREAM_RESOLVERS = ("9.9.9.10", "149.112.112.10", "1.1.1.1", "8.8.8.8")
# nginx 1.25.1 replaced the "listen ... http2" parameter with a directive.
HTTP2_DIRECTIVE_VERSION = (1, 25, 1)


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


def render_adguard_yaml(
    rows: Sequence[PolicyRow],
    password_hash: str,
    upstreams=None,
    *,
    bootstrap=None,
    fallbacks=None,
    rewrites: Optional[Sequence[Mapping[str, Any]]] = None,
) -> str:
    upstreams = list(upstreams or DEFAULT_UPSTREAM_DNS)
    bootstrap = list(bootstrap or DEFAULT_BOOTSTRAP_DNS)
    fallbacks = list(fallbacks or DEFAULT_FALLBACK_DNS)
    if not password_hash or "\n" in password_hash:
        raise ValueError("password hash is required")
    lines = [
        "http:",
        "  pprof:",
        "    port: 6060",
        "    enabled: false",
        "  doh:",
        "    routes:",
        # Only the tokenized nginx location reaches these routes.  The
        # ClientID variants are deliberately absent: they would answer on
        # /dns-query/<anything>, which no token protects.
        "      - GET /dns-query",
        "      - POST /dns-query",
        "    insecure_enabled: true",
        "  address: 127.0.0.1:3001",
        "  session_ttl: 30d",
        "users:",
        "  - name: admin",
        "    password: %s" % password_hash,
        # AdGuard Home keys its login lockout on the TCP peer address and
        # deliberately ignores forwarded headers, so behind nginx every client
        # shares the 127.0.0.1 counter: five failed attempts from anyone on the
        # internet would lock the panel - and the local health worker - for
        # every client at once.  Brute force is throttled in nginx instead,
        # per the limit_req zone in the generated site configuration.
        "auth_attempts: 0",
        "block_auth_min: 0",
        "http_proxy: \"\"",
        "language: ru",
        "theme: auto",
        "dns:",
        "  bind_hosts:",
        "    - 127.0.0.1",
        "  port: 53",
        "  anonymize_client_ip: true",
        "  ratelimit: 0",
        "  ratelimit_subnet_len_ipv4: 24",
        "  ratelimit_subnet_len_ipv6: 56",
        "  ratelimit_whitelist: []",
        "  refuse_any: true",
        "  upstream_dns:",
    ]
    lines.extend("    - %s" % upstream for upstream in upstreams)
    lines.append("  upstream_dns_file: \"\"")
    lines.append("  bootstrap_dns:")
    lines.extend("    - %s" % server for server in bootstrap)
    lines.append("  fallback_dns:")
    lines.extend("    - %s" % server for server in fallbacks)
    lines.extend([
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
        # A short upstream TTL must not turn a brief upstream outage into a
        # dead client: answers are held for a minute and stale entries are
        # still served while they are refreshed in the background.
        "  cache_ttl_min: 60",
        "  cache_ttl_max: 0",
        "  cache_optimistic: true",
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
        # Apple's resolver gives up well before ten seconds; a shorter budget
        # leaves room for the fallback servers to answer instead.
        "  upstream_timeout: 4s",
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
        # Rewritten answers carry this TTL; since schema 23 the key lives
        # under "filtering", and AdGuard Home silently drops it anywhere
        # else when it rewrites the file.  The default of ten seconds makes
        # a phone re-ask for every routed domain six times a minute; on a
        # cellular path each round trip is a chance to stall, and the answer
        # cannot change between two gate cycles anyway.
        "  blocked_response_ttl: 300",
    ])
    # Activation replaces this file wholesale and restarts AdGuard Home, which
    # drops the rewrites the health gate had added through the API.  Until the
    # next gate cycle re-adds them, clients would resolve routed services to
    # their real addresses and cache that answer for the upstream TTL - an
    # update would cause exactly the outage this project exists to avoid.
    # Seeding the file with the rewrites that were already healthy closes that
    # window; the gate then finds them in place and changes nothing.
    rewrites = list(rewrites or [])
    if not rewrites:
        lines.append("  rewrites: []")
    else:
        lines.append("  rewrites:")
        for item in rewrites:
            lines.extend([
                "    - domain: '%s'" % item["domain"],
                "      answer: %s" % item["answer"],
                "      enabled: %s" % ("true" if item.get("enabled", True) else "false"),
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


def render_mobileconfig(
    doh_host: str,
    doh_token: str,
    public_ip: str,
    *,
    match_domains: Optional[Iterable[str]] = None,
    allow_failover: bool = True,
) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    public_ip = _public_ipv4(public_ip)
    if not re.fullmatch(r"[a-f0-9]{32,64}", doh_token):
        raise ValueError("doh-token must be lowercase hexadecimal")
    profile_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "adguardhome-doh-profile:" + doh_host))
    payload_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, "adguardhome-doh-payload:" + doh_host))
    # Without SupplementalMatchDomains the profile sends every query of the
    # device here, and Apple offers no plain-DNS fallback: any hiccup on the
    # path from a phone to this host - carrier NAT, a network hand-over, a
    # throttled hosting range - takes the whole device offline, not just the
    # routed services.  Scoped to the catalog, an unreachable server costs
    # exactly the domains it exists to route.  Apple matches a bare domain
    # against itself and every subdomain.  AllowFailover (iOS 26+) lets the
    # device fall back to the system resolver on top of that.
    domains = sorted({_hostname(item, "match-domain") for item in (match_domains or ())})
    supplemental = ""
    if domains:
        supplemental = (
            "<key>SupplementalMatchDomains</key><array>"
            + "".join("<string>%s</string>" % item for item in domains)
            + "</array>"
        )
    failover = "<key>AllowFailover</key><%s/>" % ("true" if allow_failover else "false")
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict>{failover}<key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>https://{host}/doh/{token}</string><key>ServerAddresses</key><array><string>{public_ip}</string></array>{supplemental}</dict>
<key>PayloadDisplayName</key><string>{host}</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.{payload_id}</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadType</key><string>com.apple.dnsSettings.managed</string><key>PayloadUUID</key><string>{payload_id}</string><key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>{host}</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.{profile_id}</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadScope</key><string>System</string><key>PayloadRemovalDisallowed</key><false/><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>{profile_id}</string><key>PayloadVersion</key><integer>1</integer>
</dict></plist>
""".format(
        host=doh_host,
        token=doh_token,
        public_ip=public_ip,
        payload_id=payload_id,
        profile_id=profile_id,
        failover=failover,
        supplemental=supplemental,
    )


def nginx_version(runner=subprocess.run) -> Optional[Tuple[int, int, int]]:
    """Return the locally installed nginx version, or None when unknown."""

    try:
        result = runner(
            ["nginx", "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = getattr(result, "stdout", b"") or b""
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    match = NGINX_VERSION_RE.search(output)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def use_http2_directive(version: Optional[Tuple[int, int, int]] = None, runner=subprocess.run) -> bool:
    """Decide which HTTP/2 syntax the installed nginx accepts.

    nginx 1.25.1 introduced ``http2 on;`` and deprecated the ``listen ...
    http2`` parameter; older releases (Ubuntu 24.04 ships nginx 1.24) only
    understand the parameter and reject the directive outright.  An unknown
    version falls back to the parameter, which every supported release still
    accepts.
    """

    if version is None:
        version = nginx_version(runner)
    if version is None:
        return False
    return version >= HTTP2_DIRECTIVE_VERSION


def render_nginx_http(
    doh_host: str,
    doh_token: str,
    certificate_root: str,
    webroot: str,
    *,
    http2_directive: Optional[bool] = None,
) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    if not re.fullmatch(r"[a-f0-9]{32,64}", doh_token):
        raise ValueError("doh-token must be lowercase hexadecimal")
    if http2_directive is None:
        http2_directive = use_http2_directive()
    listen_tls = "    listen 127.0.0.1:4443 ssl%s;" % ("" if http2_directive else " http2")
    lines = [
        # Every request reaches this server through the stream listener, so the
        # peer address is always 127.0.0.1 and the zone is a deliberate global
        # budget rather than a per-client one.  It exists so that unattended
        # brute force cannot flood AdGuard Home's login endpoint.
        "limit_req_zone $binary_remote_addr zone=adguardhome_doh_login:1m rate=30r/m;",
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
        listen_tls,
    ]
    if http2_directive:
        lines.append("    http2 on;")
    lines.extend([
        "    server_name %s;" % doh_host,
        "    ssl_certificate %s/fullchain.pem;" % certificate_root,
        "    ssl_certificate_key %s/privkey.pem;" % certificate_root,
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        # Without a cache the session timeout resumes nothing; Apple clients
        # reconnect constantly, so resumption keeps the handshake cost down.
        "    ssl_session_cache shared:adguardhome_doh:10m;",
        "    ssl_session_timeout 1d;",
        "    add_header Strict-Transport-Security \"max-age=31536000\" always;",
        "    client_max_body_size 2m;",
        # Apple multiplexes every query of the device over one HTTP/2
        # connection; closing it after the default thousand requests forces
        # a reconnect in the middle of a burst of lookups.
        "    keepalive_requests 100000;",
        "    location = /%s.mobileconfig {" % doh_token,
        "        root %s;" % webroot,
        "        default_type application/x-apple-aspen-config;",
        "        add_header Content-Disposition \"attachment; filename=%s.mobileconfig\" always;" % doh_host,
        "        add_header Cache-Control \"no-store\" always;",
        "        access_log off;",
        "        try_files /%s.mobileconfig =404;" % doh_host,
        "    }",
        # The prefix form also covers /dns-query/<ClientID>, which AdGuard
        # Home serves as an untokenized DoH endpoint; an exact match left
        # that path open to anyone on the internet.
        "    location ^~ /dns-query { return 404; }",
        "    location = /doh/%s {" % doh_token,
        "        proxy_pass http://127.0.0.1:3001/dns-query;",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Forwarded-For $remote_addr;",
        "        proxy_set_header X-Forwarded-Proto https;",
        "        proxy_buffering off;",
        "        proxy_read_timeout 30s;",
        "        access_log off;",
        "    }",
        "    location = /control/login {",
        "        limit_req zone=adguardhome_doh_login burst=5 nodelay;",
        "        limit_req_status 429;",
        "        proxy_pass http://127.0.0.1:3001;",
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
    ])
    return "\n".join(lines)


def render_nginx_stream(
    rows: Sequence[PolicyRow], doh_host: str, relay: Optional[str] = None
) -> str:
    doh_host = _hostname(doh_host, "doh-host")
    # A relay host sits where clients can reach it and hands every routed
    # service to one exit host that can reach the real sites.  The TLS bytes
    # are forwarded untouched, so the exit host routes them by the same SNI
    # and the real certificate still reaches the client.  The DoH host and
    # the drop target for unknown names stay local either way.
    if relay:
        address = ipaddress.ip_address(relay)
        if address.version != 4:
            raise ValueError("relay must be IPv4")
        target = "%s:443" % address
    else:
        target = "$ssl_preread_server_name:443"
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
        lines.append("        %s %s;" % (name, target))
    lines.extend([
        "    }",
        # Clients report stalls while this host looks healthy, so every
        # connection leaves one line: whether a ClientHello ever arrived
        # (in=0 means the TCP handshake completed and the TLS record was
        # then swallowed on the path), how the upstream connect went and how
        # long the session lived.  The client address is truncated to its
        # /24, the same privacy level as the anonymized query log.
        "    map $remote_addr $adguardhome_doh_client {",
        "        ~^(?<adguardhome_doh_net>[0-9]+[.][0-9]+[.][0-9]+)[.][0-9]+$ $adguardhome_doh_net.0;",
        "        default anon;",
        "    }",
        "    log_format adguardhome_doh_stream '$time_iso8601 client=$adguardhome_doh_client'",
        "        ' sni=$ssl_preread_server_name status=$status session=$session_time'",
        "        ' in=$bytes_received out=$bytes_sent upstream=$upstream_addr'",
        "        ' connect=$upstream_connect_time';",
        "    resolver %s valid=60s ipv4=on ipv6=off;" % " ".join(DEFAULT_STREAM_RESOLVERS),
        "    resolver_timeout 5s;",
        "    server {",
        # Carrier NAT drops idle mappings silently.  Keepalive probes from
        # this side keep the mapping alive while a phone's HTTP/2 connection
        # idles, and detect a vanished peer within a minute instead of
        # holding a dead slot for the whole proxy_timeout.
        "        listen 443 so_keepalive=30s:10s:3;",
        "        listen [::]:443 so_keepalive=30s:10s:3;",
        "        proxy_socket_keepalive on;",
        "        proxy_connect_timeout 5s;",
        # Long-lived streaming responses (chat completions, websockets) idle
        # for minutes at a time; ten minutes cut them mid-answer.
        "        proxy_timeout 1h;",
        "        proxy_pass $adguardhome_doh_backend;",
        "        ssl_preread on;",
        "        access_log /var/log/adguardhome-doh/nginx-stream.access.log"
        " adguardhome_doh_stream buffer=32k flush=5s;",
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
