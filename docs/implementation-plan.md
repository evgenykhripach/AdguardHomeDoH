# Smart DNS implementation plan

## Global constraints

- Hostname: `dns.pressroll.ru`.
- Target: Ubuntu 24.04, public IPv4 only.
- Core: native `mosajjal/sniproxy` v2.3.0 under systemd; no Docker.
- Client protocols: plain DNS UDP/TCP 53, DoH `https://dns.pressroll.ru/dns-query`, DoT TCP 853.
- Traffic proxy: TCP 443 SNI passthrough, no TLS interception.
- TCP 80: nginx ACME webroot and HTTPS redirect only.
- Upstream resolver: `https://cloudflare-dns.com/dns-query`.
- Access: Russian source IPs, domain allowlist, nftables rate limits; no activation.
- IPv6/AAAA publication is disabled. UDP 443/853 is closed.
- Query logs are disabled; Prometheus is loopback-only.
- Beget credentials are never stored or requested by automation.
- Deployment must be idempotent and must not replace existing SSH firewall policy.

## Task 1: Test harness and artifact validator

Create a dependency-free Python validator and unit tests. It must render/check templates against a deployment inventory, reject missing/invalid IPv4 and hostname values, verify port/interface invariants, validate domain CSV records, and validate Apple mobileconfig XML. Tests must be written first and observed failing.

## Task 2: Ubuntu deployment bundle

Add native sniproxy configuration, systemd units, nginx/Certbot configuration, nftables include, GeoIP updater, install/update/rollback scripts, and inventory example. Use pinned v2.3.0 download URLs and SHA256 input. Preserve the real client IP, hard-fail if GeoIP is missing/invalid, avoid a DNS loop, and keep existing SSH firewall rules untouched. Add behavior tests first for render, install dry-run, firewall invariants, rollback, and idempotence.

## Task 3: Domain policy, Apple profile, and operator documentation

Add grouped allowlist entries for the planned AI/work/game services, an unsigned Apple DNS Settings mobileconfig template, client setup/removal instructions, deployment runbook, verification checklist, service discovery workflow, privacy/limitations, and rollback. Add tests first for domain normalization/duplicates, required service coverage, profile semantics, and absence of secrets.

## Task 4: Integration verification

Run the full local suite, shell syntax checks, template rendering with documentation-only sample values, static security checks, and a clean-install dry run. Review all plan requirements and document commands for live VPS and Russian-network acceptance testing. No claim of live deployment until SSH access, DNS A record, certificate issuance, and external network tests are actually performed.
