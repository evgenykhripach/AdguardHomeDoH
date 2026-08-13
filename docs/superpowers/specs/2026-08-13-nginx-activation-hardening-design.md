# Nginx Activation Hardening Design

## Goal

Prevent transient loss of the public AdGuard Home panel and DoH endpoint during installs, updates, and service-list changes.

## Design

The generated nginx stream resolver will explicitly disable IPv6 resolution because supported hosts are IPv4-only and the observed VPS has no IPv6 route. Runtime activation will restart AdGuard Home, perform exactly one nginx reload after the final HTTP and stream configuration is present, and then verify the complete local public path through `127.0.0.1:443` using the installation domain as TLS SNI.

The smoke check will retry three times with a short delay. It must validate both the TLS handshake and an HTTP response from the panel path. Manager transactions will include this check in their post-activation validation so an exception triggers the existing full-backup restore. The installer will fail before writing its completion marker if the same check cannot pass.

## Error handling

- `nginx -t` remains mandatory before reload.
- A failed reload or failed post-reload smoke check is fatal.
- Manager service changes restore the existing full backup on failure.
- The installer does not report `100%` or write the completion marker before the smoke check passes.
- No external network monitor or new dependency is introduced; provider-path monitoring remains an operational concern.

## Verification

- Renderer test proves `ipv6=off` is emitted.
- Installer contract test proves only one nginx reload occurs after final config installation and that the SNI smoke check precedes completion.
- Manager unit tests prove reload calls the smoke check and propagates failure.
- Full unit, release-contract, shell syntax, diff, and neutral-name checks run before release.

