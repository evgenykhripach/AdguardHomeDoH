# Domain-based mobileconfig naming

## Goal

For an installation whose configured domain is `dns.example.com`, the generated
Apple configuration profile must be stored and downloaded as
`dns.example.com.mobileconfig`, and both Apple payload display names must be
`dns.example.com`.

## Security contract

The existing private download URL remains tokenized:
`https://dns.example.com/<token>.mobileconfig`. The domain must not replace the
token in the public URL. Nginx maps this private URL to the domain-named file and
sends `Content-Disposition` with `filename="dns.example.com.mobileconfig"`.

The private DoH token, DoH URL, credentials, and installation state are not
changed.

## Implementation

- The installer writes the profile to
  `/var/www/adguardhome-doh/<domain>.mobileconfig`.
- Both `PayloadDisplayName` values in the profile equal the configured domain.
- The generated nginx HTTP configuration serves that file from the existing
  tokenized location and advertises the same domain-based download filename.
- Manager diagnostics verify the domain-named profile file.
- Existing token-named profile files are left untouched during updates. They are
  no longer referenced by the generated nginx configuration.

## Verification

- Unit tests assert the generated profile path and both payload display names.
- Renderer tests assert the tokenized URL location, domain file mapping, and
  domain-based `Content-Disposition` filename.
- Manager tests assert diagnostics use the domain-named path.
- The Ubuntu smoke contract checks the domain-named file while downloading it
  through the private tokenized URL.
- The full unit suite, release contract, shell syntax, neutral-name grep, and
  `git diff --check` must pass.
