# Installer Address Output Design

## Goal

Make the first installation self-documenting: print the private DoH URL and
the Apple `mobileconfig` URL together, then document a safe repeatable command
for retrieving the current addresses after the installer output is gone.

## Scope

- Change only the first-install success output in `deploy/install.sh`.
- Keep the existing random token and URL formats unchanged:
  - `https://HOST/doh/<token>`
  - `https://HOST/<token>.mobileconfig`
- Keep update behavior unchanged: existing AdGuard credentials are preserved;
  addresses are not printed by the update path.
- Add README instructions in Russian for installation, address retrieval, and
  credential retrieval.
- Add a contract test that prevents either address line from disappearing.

## Address recovery

The repeat command reads the active domain and DoH token from the nginx config
already used by the running service. It does not require the source checkout or
the installer script to remain on the VPS. The token is a private credential;
the README warns not to publish either URL.

## Acceptance criteria

1. Initial install output contains `DoH URL:` and `mobileconfig:` lines using
   the same generated token.
2. README is Russian and includes the one-command installer, both URL formats,
   one repeat command for both addresses, and the credentials file command.
3. Existing tests remain green; a new test fails before the output change and
   passes after it.
