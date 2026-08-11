# Pressroll AdGuard Home DoH Smart DNS

One-command deployment of the current personal Smart DNS stack:

- AdGuard Home v0.107.78 for DNS and private DoH;
- nginx HTTP/TLS termination plus stream SNI forwarding;
- one canonical policy rendered into AdGuard rewrites and the nginx SNI map;
- health-gated activation with automatic reconciliation and rollback backups;
- OpenAI upload hosts, Google AI, Claude, Copilot, Perplexity, Grok, Midjourney,
  and Fitbit policy rows included.

This is selective Smart DNS, not a VPN. HTTPS is not decrypted; nginx only
uses TLS SNI to forward the selected host to its original HTTPS destination.

## One-command installation

Point the DNS A record at the VPS first, then run as root on a clean Ubuntu
24.04 server:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | sudo bash -s -- \
      --domain dns.example.com \
      --public-ip 203.0.113.10 \
      --email admin@example.com
```

The first successful install generates an `admin` password for AdGuard Home and
prints the URL, login, and password once. It also saves them in:

```text
URL: https://dns.example.com/
Login: admin
Password: <generated value>
```

```text
/var/lib/pressroll-smart-dns/admin-credentials  (mode 0600)
```

Updates preserve the existing password and do not print it. `--dry-run` never
changes the host and never generates credentials.

## Operations

```bash
# Validate without touching the host.
./deploy/install.sh --domain dns.example.com --public-ip 203.0.113.10 \
  --email admin@example.com --dry-run

# Update policy/runtime while preserving credentials.
./deploy/install.sh --domain dns.example.com --public-ip 203.0.113.10 \
  --email admin@example.com --update

# Restore the most recent backup.
./deploy/install.sh --domain dns.example.com --public-ip 203.0.113.10 \
  --email admin@example.com --rollback
```

See [operations](docs/operations.md) for client DoH profiles, service checks,
backups, and troubleshooting. The policy source is
[`config/policy.csv`](config/policy.csv).

## Development checks

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_release.py
bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh
```
