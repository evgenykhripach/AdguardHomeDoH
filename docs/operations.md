# Operations

## Required DNS and firewall state

Before installation, publish an A record for the chosen hostname and allow
TCP 80 and TCP 443. TCP 80 stays open permanently: HTTP-01 renewal is answered
from the webroot nginx serves there, so nginx is never stopped for the ACME
exchange. Port 53 does not need to be reachable from the internet - AdGuard
Home binds DNS to loopback only and is published exclusively as DoH.

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
`/var/lib/adguardhome-doh/admin-credentials.json` with mode `0600`. Use
`sudo chmod 600` if an operator accidentally changes its permissions. Updates
preserve this password.

AdGuard Home's own login lockout is disabled (`auth_attempts: 0`) on purpose.
It keys failed attempts on the TCP peer address and deliberately ignores
forwarded headers, so behind nginx every client shares one `127.0.0.1` counter:
five failed attempts by any internet scanner would lock out the operator *and*
the local health worker for fifteen minutes at a time. Brute force is throttled
in nginx instead, where `location = /control/login` is capped at 30 requests
per minute. The generated password has 192 bits of entropy, so an online guess
rate of one attempt every two seconds is not a threat.

## Interactive service selection

The installer opens a compact category selector instead of printing every
service at once. Enter a category number, then toggle local service numbers with
spaces. `A` selects all services in the category, `N` clears it, `B` goes back,
and `/text` searches names and service IDs. `D` selects the standard set; `X`
opens the experimental category explicitly. Use `Y` to review the selected
service/domain counts and confirm with `y`. The non-interactive `--services`
flag remains available for CI.

## Health-gated policy

The timer runs every minute. A service becomes active after three successful TLS
probes and is withdrawn after five consecutive failures. Withdrawal is not free:
it sends clients to the real address of a service they reach through this server
on purpose, and the client then caches that answer for the upstream TTL, so a
brief blip must not trigger it.

When *every* probed service fails in the same cycle the gate holds its previous
state and reports `global_failure=1`. Services do not all break at the same
second; a clean sweep means the fault is local - nginx down, resolver dead,
uplink gone - and withdrawing every rewrite would make that outage worse and
outlast it.

The `oaiusercontent.com` suffix probes `files.oaiusercontent.com`, because its
apex is not an upload TLS endpoint. AdGuard rewrites and nginx SNI entries are
generated from the same catalog, preventing configuration drift.

## Staying reachable

An Apple client with an installed DoH profile has no plain-DNS fallback of its
own: if this server stops answering, the device has no DNS at all, for every
domain. The deployment therefore keeps several independent recovery paths:

- `fallback_dns` holds IP-addressed resolvers used when every DoH upstream
  stops answering, and `bootstrap_dns` spans three operators so one of them
  failing cannot strand the upstream hostnames;
- `upstream_timeout` is 4s, well inside the client's own patience, leaving room
  for the fallbacks to answer;
- `cache_optimistic` serves stale entries while refreshing them, so a short
  upstream outage is invisible to clients;
- the nginx stream `resolver` spans three operators as well, because SNI
  routing dies with it;
- AdGuard Home restarts unconditionally (`Restart=always`, no give-up limit)
  and nginx gets a `Restart=on-failure` drop-in;
- activation writes the rewrites of already-healthy services straight into
  `AdGuardHome.yaml`, because restarting AdGuard Home discards the ones the
  gate keeps over the API - without it, an update or a service change let
  clients resolve routed services to their real addresses and cache that;
- `worker_connections` is raised to 8192: one DoH connection occupies a stream
  slot, an internal TLS slot and an upstream slot at once, and when the limit
  is reached nginx stops accepting *everything* - DNS, panel and SNI alike.

If clients lose DNS periodically, check these first:

```bash
grep -cE 'worker_connections are not enough|Too many open files' /var/log/nginx/error.log
journalctl -u adguardhome-doh.service --since -1day | grep -c 'Started\|Stopped'
journalctl -u adguardhome-doh-health.service --since -1h | grep global_failure
```

Check status:

```bash
systemctl status adguardhome-doh.service nginx adguardhome-doh-health.timer
journalctl -u adguardhome-doh-health.service -n 80 --no-pager
cat /var/lib/adguardhome-doh/health-state.json
```

## Update and rollback

Run the same bootstrap command with `--update`, or execute the local installer.
Before activation, the installer stores the previous AdGuard and nginx files in
`/var/backups/adguardhome-doh/<UTC timestamp>/`. The manager restores the
newest complete backup after validating nginx configuration.

## Client setup

Use the generated DoH URL in the operating system or browser's custom DoH
settings. The generated Apple profile pins the server's public IPv4 address;
regenerate and reinstall the profile whenever that address changes. If the
client has cached the previous DNS answer, flush its DNS cache and restart the
browser. Do not copy the server credential or DoH token into a public issue or
chat.
