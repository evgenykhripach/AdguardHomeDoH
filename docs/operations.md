# Operations

## Required DNS and firewall state

Before installation, publish an A record for the chosen hostname and allow
TCP/UDP 53, TCP 80, and TCP 443. TCP 80 is used by Certbot HTTP-01; after
certificate issuance, nginx redirects ordinary HTTP to HTTPS.

The generated private DoH endpoint is:

```text
https://HOST/doh/<random-token>
```

The public `/dns-query` path intentionally returns 404. The token is generated
on the server and is never stored in GitHub.

## Admin access

The admin UI is available at `https://HOST/`. The first installation prints:

```text
URL: https://HOST/
Login: admin
Password: <generated value>
```

The same values are stored in
`/var/lib/pressroll-smart-dns/admin-credentials` with mode `0600`. Use
`sudo chmod 600` if an operator accidentally changes its permissions. Updates
preserve this password.

## Health-gated policy

The timer runs every minute. A policy row becomes active after three successful
TLS probes and is disabled after two consecutive failures. The
`oaiusercontent.com` suffix probes `files.oaiusercontent.com`, because its apex
is not an upload TLS endpoint. AdGuard rewrites and nginx SNI entries are
generated from the same CSV, preventing the previous configuration drift.

Check status:

```bash
systemctl status AdGuardHome nginx pressroll-smart-dns-health.timer
journalctl -u pressroll-smart-dns-health.service -n 80 --no-pager
cat /var/lib/pressroll-smart-dns/health-state.json
```

## Update and rollback

Run the same bootstrap command with `--update`, or execute the local installer.
Before activation, the installer stores the previous AdGuard and nginx files in
`/var/backups/pressroll-smart-dns/<UTC timestamp>/`. `--rollback` restores the
newest complete backup after validating nginx configuration.

## Client setup

Use the generated DoH URL in the operating system or browser's custom DoH
settings. If the client has cached the previous DNS answer, flush its DNS cache
and restart the browser. Do not copy the server credential or DoH token into a
public issue or chat.

