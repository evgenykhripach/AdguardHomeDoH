# Current Smart DNS Deployment Design

## Goal

Replace the obsolete `sniproxy` deployment bundle with the currently running
AdGuard Home + nginx stream/SNI Smart DNS stack. A clean Ubuntu 24.04 server
must be installable and recoverable from one documented command, without
committing private DoH tokens, passwords, certificates, or server-specific
inventory to GitHub.

## Scope

The repository becomes the source of truth for:

- an idempotent bootstrap/install/update/rollback workflow;
- AdGuard Home as the DNS and private DoH endpoint;
- nginx stream SNI forwarding for selected HTTPS domains;
- the health-gated rewrite policy and generated nginx SNI map;
- domain policy files for the active AI and Fitbit services;
- generated Apple client profiles and operator runbooks.

All old `sniproxy` scripts, templates, patches, inventories, and related
documentation are removed from the repository rather than kept as the primary
implementation. Git history remains available through normal Git history.

## Architecture

The installer accepts a server domain, public IPv4 address, and administrator
email. It validates a clean Ubuntu 24.04 host, installs pinned/runtime
dependencies, installs a pinned AdGuard Home release, configures nginx TLS and
stream SNI forwarding, and registers systemd units for health checks and
reconciliation.

One canonical policy source is rendered into both:

1. AdGuard Home rewrites, which return the server IPv4 for selected FQDNs;
2. nginx's `stream` SNI map, which forwards those same names to their original
   TLS destinations.

The renderer must fail on malformed policy rows and must not emit a wildcard
for a domain marked `fqdn`. The health gate keeps a domain disabled until its
TLS probe succeeds three times and disables it after two consecutive failures.
The `oaiusercontent.com` suffix uses a concrete upload host for probing.

## Security and secrets

The repository contains no live password, private key, certificate, DoH token,
or production inventory. The installer generates a random private DoH path and
stores it with mode `0600` on the server. Client profiles are rendered locally
from that generated path. Existing files are backed up before replacement, and
first install refuses to overwrite unrelated listeners or state paths.

On first install the installer also generates a random AdGuard Home admin
password for the fixed administrator login `admin`. After a successful install
it prints the admin URL, login, and password once to the invoking terminal and
writes the same values to a server-only credentials file with mode `0600`.
Dry-run and update operations never print credentials; update preserves the
existing password.

## User-facing workflow

The README documents a command equivalent to:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/DoHDNS/main/bootstrap.sh \
  | sudo bash -s -- --domain dns.example.com --public-ip 203.0.113.10 \
      --email admin@example.com
```

The command supports `--dry-run`, explicit policy selection, an update mode,
and a rollback mode. It prints generated profile paths and verification results
without printing secrets, except for the one-time first-install display of the
generated AdGuard administrator credentials described above.

## Verification

The repository includes deterministic renderer tests, shell syntax checks,
policy validation, bootstrap dry-run tests, and an isolated-root install test.
The release checklist also verifies `nginx -t`, AdGuard configuration validity,
systemd unit presence, DoH HTTP status, DNS answers for policy and ordinary
domains, and TLS SNI forwarding.
