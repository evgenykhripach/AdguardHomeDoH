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

The public `/dns-query` path, including the `/dns-query/<ClientID>` variant,
intentionally returns 404. The token is generated on the server and is never
stored in GitHub.

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
own before iOS 26: if this server stops answering, every domain the profile
covers is dead on the device. The profile therefore covers only the catalog
domains (`SupplementalMatchDomains`) and asks iOS 26+ for `AllowFailover`, and
the deployment keeps several independent recovery paths:

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
  is reached nginx stops accepting *everything* - DNS, panel and SNI alike;
- `blocked_response_ttl` is 300 instead of AdGuard Home's default 10: routed
  answers are re-asked once in five minutes rather than six times a minute
  over a cellular path;
- `so_keepalive` on the stream listener and `proxy_socket_keepalive` keep
  carrier NAT mappings alive under the phone's single HTTP/2 connection and
  drop vanished peers within a minute; `keepalive_requests` is raised so that
  connection is not closed mid-burst;
- `net.ipv4.tcp_mtu_probing=1` (and BBR where the module loads) survives
  cellular paths that filter ICMP "fragmentation needed";
- the health gate resolves one name through the public DoH path every cycle
  and logs `doh_ok=1` or `doh_ok=0`; `-1` means the probe is not configured.

If clients lose DNS periodically, check these first:

```bash
grep -cE 'worker_connections are not enough|Too many open files' /var/log/nginx/error.log
journalctl -u adguardhome-doh.service --since -1day | grep -c 'Started\|Stopped'
journalctl -u adguardhome-doh-health.service --since -1h | grep global_failure
journalctl -u adguardhome-doh-health.service --since -1h | grep -c doh_ok=0
```

Check status:

```bash
systemctl status adguardhome-doh.service nginx adguardhome-doh-health.timer
journalctl -u adguardhome-doh-health.service -n 80 --no-pager
cat /var/lib/adguardhome-doh/health-state.json
```

## Relay mode

When `adguardhome-doh-diag` shows `no_clienthello` from the client network
and the client probe shows TCP connecting but TLS never completing, the
client's path filters this address and no setting on this host can help.
Split the deployment instead: a **relay** host on a network the clients reach
cleanly, and the existing host as the **exit**. Install the relay with the
ordinary command plus `--relay <exit IPv4>`. The relay runs DoH, AdGuard Home,
the health gate and serves the profile; its stream map forwards every catalog
domain to the exit host instead of the real site, and the exit host routes the
untouched TLS bytes by the same SNI. Enable the same services on both hosts,
because the exit drops SNIs it does not know. The relay's health gate probes
the whole chain, so `healthy_services` there means the path through the exit
works. The value is stored in `install.json` and carried through updates and
service changes automatically; the relay must not equal the host's own address.

## Diagnosing stalls

A client that sees `HOST` and the routed services hang at the same time while
ping still answers is looking at TCP 443 on this address, which everything
shares. The host and the client each keep one record so the two can be laid
side by side.

On the host, nginx writes one line per stream connection to
`/var/log/adguardhome-doh/nginx-stream.access.log` (client address truncated
to its /24, SNI, status, session time, bytes in and out, upstream address and
connect time; buffered, so lines appear within five seconds; rotated daily,
seven copies). Summarize a window with:

```bash
sudo adguardhome-doh-diag --minutes 60
```

`no_clienthello` counts sessions that completed the TCP handshake and then
received no byte at all: the path swallowed the TLS record, which is what DPI
throttling looks like. `upstream_failures` means this host could not reach the
target site. Zero connections during a reported stall means the client's
packets never arrived.

On the client, run the probe on the network where the stalls happen, for
example a laptop tethered to the phone's hotspot with every VPN switched off:

```bash
DOH_URL='https://HOST/doh/<token>' tools/client-probe.sh HOST chatgpt.com 10
```

Each line records ping, then TCP connect, TLS handshake, total time and HTTP
code for the host itself, for a routed site, for the DoH endpoint and for a
control host. `rc=28` with `connect=0` is an unanswered SYN, `rc=28` with a
connect time but `tls=0` is a swallowed ClientHello, `rc=35` is a reset
handshake. `site_ip` shows whether the routed site actually resolves to this
host on that network. A stall on the host with the control host healthy and
nothing in the host log at that time is a path problem between the client
and this address, not a fault of the deployment.

## Update and rollback

Run the same bootstrap command with `--update`, or execute the local installer.
Before activation, the installer stores the previous AdGuard and nginx files in
`/var/backups/adguardhome-doh/<UTC timestamp>/`. The manager restores the
newest complete backup after validating nginx configuration.

## Client setup

Use the generated DoH URL in the operating system or browser's custom DoH
settings. The generated Apple profile pins the server's public IPv4 address and lists
the catalog domains; regenerate and reinstall the profile whenever that address
changes and after updating from a release older than v1.1.1. If the
client has cached the previous DNS answer, flush its DNS cache and restart the
browser. Do not copy the server credential or DoH token into a public issue or
chat.
