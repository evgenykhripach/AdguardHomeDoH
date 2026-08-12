#!/usr/bin/env python3
"""Render the canonical Smart DNS policy into runtime configuration."""

import argparse
import csv
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class PolicyRow:
    domain: str
    kind: str
    probe: str


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


def render_rewrites(rows: Sequence[PolicyRow], public_ip: str):
    public_ip = _public_ipv4(public_ip)
    output = []
    for row in rows:
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
        "  rewrites:",
    ])
    for item in render_rewrites(rows, "127.0.0.1"):
        lines.extend([
            "    - domain: '%s'" % item["domain"],
            "      answer: %s" % item["answer"],
            "      enabled: false",
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
        "        add_header Content-Disposition \"attachment; filename=dns.pressroll.mobileconfig\" always;",
        "        add_header Cache-Control \"no-store\" always;",
        "        try_files $uri =404;",
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
        "    map $ssl_preread_server_name $pressroll_smart_dns_backend {",
        "        hostnames;",
        "        default 127.0.0.1:9;",
        "        %s 127.0.0.1:4443;" % doh_host,
    ]
    for row in rows:
        name = "." + row.domain if row.kind == "suffix" else row.domain
        lines.append("        %s $ssl_preread_server_name:443;" % name)
    lines.extend([
        "    }",
        "    resolver 9.9.9.10 149.112.112.10 valid=60s ipv4=on;",
        "    server {",
        "        listen 443;",
        "        proxy_connect_timeout 5s;",
        "        proxy_timeout 10m;",
        "        proxy_pass $pressroll_smart_dns_backend;",
        "        ssl_preread on;",
        "        access_log off;",
        "        error_log /var/log/nginx/pressroll-smart-dns-stream.error.log warn;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def render_health_policy(rows: Iterable[PolicyRow]) -> str:
    payload = [
        {"domain": row.domain, "kind": row.kind, "probe": row.probe}
        for row in rows
    ]
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def render(output: Path, policy: Path, public_ip: str, doh_host: str) -> None:
    rows = load_policy(policy)
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
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--doh-host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    render(args.output, args.policy, args.public_ip, args.doh_host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
