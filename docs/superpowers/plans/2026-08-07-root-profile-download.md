# Root Apple Profile Download Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `https://dns.pressroll.ru/` download the versioned Apple DNS profile directly while preserving DoH at `/dns-query` and every existing DNS/SNI security property.

**Architecture:** Keep `sniproxy` as the sole TCP 443 owner and apply a small checksum-pinned patch to its embedded DoH HTTP mux. The renderer places the profile in every generation, systemd passes its active path through `SNIPROXY_APPLE_PROFILE`, and the patched server fails startup if that configured file is unusable.

**Tech Stack:** Python 3 standard library renderer/tests, Bash deployment scripts, Go 1.26.0, `mosajjal/sniproxy` v2.3.0 at commit `5be8145042cb3a87b76993d43187b07daa254dff`, systemd, curl/OpenSSL, Ubuntu 24.04.

## Global Constraints

- TCP 443 remains owned only by `sniproxy`; do not add a reverse proxy or public listener.
- `GET` and `POST https://dns.pressroll.ru/dns-query` keep their existing DoH behavior.
- `GET /` returns the exact versioned profile with `application/x-apple-aspen-config` and attachment headers; `HEAD /` returns no body.
- Unknown paths remain `404`; methods other than `GET` and `HEAD` on `/` return `405` with `Allow: GET, HEAD`.
- Missing, empty, or unreadable configured profile prevents `sniproxy` startup.
- Preserve GeoIP ACL, IPv4-only proxy answers, nftables limits, end-to-end TLS for target sites, disabled query logs, transactional generations, and rollback.
- Verify the upstream source archive, the repository patch, and the resulting binary by SHA-256.
- Do not add credentials, the VPS root password, private keys, or certificates to Git.

---

### Task 1: Make the Apple profile generation-owned

**Files:**
- Modify: `tests/test_deployment_bundle.py:68-205`
- Modify: `tools/render_deployment.py:30-41,180-301`
- Modify: `deploy/templates/sniproxy.service.tmpl:8-16`

**Interfaces:**
- Consumes: repository file `profiles/dns.pressroll.ru.mobileconfig`.
- Produces: rendered file `etc/sniproxy/dns.pressroll.ru.mobileconfig`, installed helper copy `profiles/dns.pressroll.ru.mobileconfig`, manifest SHA-256 entry, and `SNIPROXY_APPLE_PROFILE=/etc/sniproxy/current/dns.pressroll.ru.mobileconfig`.

- [ ] **Step 1: Write failing renderer and installed-update tests**

Add these assertions to `DeploymentBundleTests`:

```python
def test_rendered_generation_contains_exact_apple_profile(self) -> None:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "staging"
        manifest = render_deployment(self.inventory, output)
        source = ROOT / "profiles/dns.pressroll.ru.mobileconfig"
        rendered = output / "etc/sniproxy/dns.pressroll.ru.mobileconfig"
        bundled = output / "usr/local/libexec/dohdns/profiles/dns.pressroll.ru.mobileconfig"
        self.assertEqual(source.read_bytes(), rendered.read_bytes())
        self.assertEqual(source.read_bytes(), bundled.read_bytes())
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            manifest["files"]["etc/sniproxy/dns.pressroll.ru.mobileconfig"],
        )

def test_sniproxy_service_configures_active_profile_path(self) -> None:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "staging"
        render_deployment(self.inventory, output)
        service = (output / "etc/systemd/system/sniproxy.service").read_text()
        self.assertIn(
            "Environment=SNIPROXY_APPLE_PROFILE=/etc/sniproxy/current/dns.pressroll.ru.mobileconfig",
            service,
        )
        self.assertNotIn(str(ROOT), service)
```

Extend `test_installed_update_has_renderer_resources_and_uses_root_inventory` with:

```python
self.assertEqual(
    (ROOT / "profiles/dns.pressroll.ru.mobileconfig").read_bytes(),
    (app / "profiles/dns.pressroll.ru.mobileconfig").read_bytes(),
)
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
python3 -m unittest \
  tests.test_deployment_bundle.DeploymentBundleTests.test_rendered_generation_contains_exact_apple_profile \
  tests.test_deployment_bundle.DeploymentBundleTests.test_sniproxy_service_configures_active_profile_path \
  tests.test_deployment_bundle.DeploymentBundleTests.test_installed_update_has_renderer_resources_and_uses_root_inventory -v
```

Expected: failures because neither rendered profile, helper profile, nor systemd environment entry exists.

- [ ] **Step 3: Copy the profile through the deterministic renderer**

In `tools/render_deployment.py`, define the trusted fixed source:

```python
PROFILE_PATH = ROOT / "profiles" / "dns.pressroll.ru.mobileconfig"
```

After rendering `domains.csv`, reject a missing or empty source and copy it into both required destinations:

```python
if not PROFILE_PATH.is_file() or PROFILE_PATH.stat().st_size == 0:
    raise ValueError(f"Apple profile missing or empty: {PROFILE_PATH}")
profile_bytes = PROFILE_PATH.read_bytes()
_write(temporary / "etc/sniproxy/dns.pressroll.ru.mobileconfig", profile_bytes, 0o640)
_write(app_root / "profiles/dns.pressroll.ru.mobileconfig", profile_bytes, 0o640)
```

Place the helper copy after `app_root` is defined. Keep both paths under renderer-controlled roots so caller input cannot select an arbitrary file.

- [ ] **Step 4: Pass the active generation path to sniproxy**

Add to `deploy/templates/sniproxy.service.tmpl` immediately after `Environment=NO_COLOR=true`:

```ini
Environment=SNIPROXY_APPLE_PROFILE=/etc/sniproxy/current/dns.pressroll.ru.mobileconfig
```

- [ ] **Step 5: Run the focused and full test suites**

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/*.py
bash -n deploy/bin/*.sh
git diff --check
```

Expected: all tests pass and no syntax/diff errors are reported.

- [ ] **Step 6: Commit the generation contract**

```bash
git add tools/render_deployment.py deploy/templates/sniproxy.service.tmpl tests/test_deployment_bundle.py
git commit -m "feat: make Apple profile generation-owned"
```

---

### Task 2: Patch and attest the embedded DoH server

**Files:**
- Create: `patches/sniproxy-v2.3.0-root-profile.patch`
- Modify: `tests/test_deployment_bundle.py:100-175`
- Modify: `deploy/bin/build-sniproxy.sh:8-94`
- Modify: `tools/render_deployment.py:30-60`
- Modify: `inventory.example.json:10-18`
- Modify: `inventory.production.json:10-18`

**Interfaces:**
- Consumes: `SNIPROXY_APPLE_PROFILE` and the generation-owned profile from Task 1.
- Produces: a patched `sniproxy` binary whose embedded DoH server implements the root-download HTTP contract and whose build fails on source or patch drift.

- [ ] **Step 1: Write failing patch/build contract tests**

Add a `PATCH` constant and tests to `tests/test_deployment_bundle.py`:

```python
PATCH = ROOT / "patches/sniproxy-v2.3.0-root-profile.patch"

def test_pinned_profile_patch_is_required_by_source_build(self) -> None:
    patch = PATCH.read_text(encoding="utf-8")
    build = BUILD.read_text(encoding="utf-8")
    self.assertIn("SNIPROXY_APPLE_PROFILE", patch)
    self.assertIn('HandleFunc("/"', patch)
    self.assertIn("application/x-apple-aspen-config", patch)
    self.assertIn("Content-Disposition", patch)
    self.assertIn("StatusMethodNotAllowed", patch)
    self.assertIn("profile is empty", patch)
    self.assertIn("PATCH_SHA256=", build)
    self.assertIn('dohdns_sha256 "$PATCH_PATH"', build)
    self.assertIn("--fuzz=0", build)
    self.assertIn('go test ./pkg/doh', build)

def test_inventories_pin_the_profile_patch_checksum(self) -> None:
    actual = hashlib.sha256(PATCH.read_bytes()).hexdigest()
    for path in (ROOT / "inventory.example.json", ROOT / "inventory.production.json"):
        inventory = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(actual, inventory["sniproxy"]["patch_sha256"])
```

- [ ] **Step 2: Run focused tests and confirm they fail**

Run:

```bash
python3 -m unittest \
  tests.test_deployment_bundle.DeploymentBundleTests.test_pinned_profile_patch_is_required_by_source_build \
  tests.test_deployment_bundle.DeploymentBundleTests.test_inventories_pin_the_profile_patch_checksum -v
```

Expected: failures because the patch and inventory checksum do not exist.

- [ ] **Step 3: Create the minimal upstream patch**

Patch `pkg/doh/server.go` in the pinned upstream tree. The implementation must read the configured file once during `NewServer`, fail on missing/empty content, and register `/` without replacing the more-specific `/dns-query` handler:

```go
func appleProfileHandler(profile []byte, filename string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
            http.NotFound(w, r)
            return
        }
        if r.Method != http.MethodGet && r.Method != http.MethodHead {
            w.Header().Set("Allow", "GET, HEAD")
            http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
            return
        }
        w.Header().Set("Content-Type", "application/x-apple-aspen-config")
        w.Header().Set("Content-Disposition", mime.FormatMediaType(
            "attachment", map[string]string{"filename": filename},
        ))
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("Content-Length", strconv.Itoa(len(profile)))
        if r.Method == http.MethodHead {
            return
        }
        _, _ = w.Write(profile)
    }
}
```

Register it after the existing DoH handler:

```go
s.servemux.HandleFunc(conf.Path, s.handlerFunc)
if profilePath := os.Getenv("SNIPROXY_APPLE_PROFILE"); profilePath != "" {
    profile, err := os.ReadFile(profilePath)
    if err != nil {
        return nil, fmt.Errorf("read Apple profile: %w", err)
    }
    if len(profile) == 0 {
        return nil, fmt.Errorf("Apple profile is empty: %s", profilePath)
    }
    s.servemux.HandleFunc("/", appleProfileHandler(profile, filepath.Base(profilePath)))
}
```

The patch must also add upstream Go tests covering `GET`, `HEAD`, `POST`, an unknown path, missing file, and empty file. Use `t.Setenv`, `httptest.NewRecorder`, and `httptest.NewRequest`; do not use external networking.

Add `mime`, `path/filepath`, and `strconv` to `pkg/doh/server.go` imports. The
download filename must come from `filepath.Base(profilePath)` and
`mime.FormatMediaType`; the upstream patch must not hardcode
`dns.pressroll.ru`.

- [ ] **Step 4: Pin and enforce the patch checksum**

Run:

```bash
sha256sum patches/sniproxy-v2.3.0-root-profile.patch
```

Copy the resulting lowercase 64-character hash into `sniproxy.patch_sha256` in both inventories and into `PATCH_SHA256` in `deploy/bin/build-sniproxy.sh`.

Define the patch path relative to either the checked-out project or the
installed self-contained helper bundle:

```bash
PATCH_PATH="$DOHDNS_PROJECT_ROOT/patches/sniproxy-v2.3.0-root-profile.patch"
if [[ -f "$SCRIPT_DIR/patches/sniproxy-v2.3.0-root-profile.patch" ]]; then
    PATCH_PATH="$SCRIPT_DIR/patches/sniproxy-v2.3.0-root-profile.patch"
fi
[[ -f "$PATCH_PATH" ]] || dohdns_die "sniproxy profile patch missing: $PATCH_PATH"
[[ "$(dohdns_sha256 "$PATCH_PATH")" == "$PATCH_SHA256" ]] || dohdns_die "sniproxy profile patch SHA256 mismatch"
```

After extracting the verified source and before running Go tests/build:

```bash
(cd "$source_dir" && patch --batch --forward --fuzz=0 -p1 <"$PATCH_PATH")
(cd "$source_dir" && "$go_cmd" test ./pkg/doh)
```

Add `patch` to the Ubuntu package list in `deploy/bin/install.sh`. Copy the repository `patches/` directory into the installed helper bundle in `tools/render_deployment.py`, then add `patch_sha256` to `EXPECTED` and its lowercase SHA-256 validation.

Extend the existing hash-validation tuple exactly as follows:

```python
for key in ("source_sha256", "go_sha256", "patch_sha256"):
    value = sniproxy.get(key)
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ValueError(f"sniproxy.{key} must be a lowercase SHA256 hash")
```

Use this renderer loop for the installed patch copy:

```python
PATCH_ROOT = ROOT / "patches"
for patch in sorted(PATCH_ROOT.glob("*.patch")):
    if patch.is_file():
        _write(app_root / "patches" / patch.name, patch.read_bytes(), 0o644)
```

- [ ] **Step 5: Verify patch application against the exact upstream commit**

Use a temporary checkout of commit `5be8145042cb3a87b76993d43187b07daa254dff`:

```bash
git -C /tmp/dohdns-sniproxy-source reset --hard 5be8145042cb3a87b76993d43187b07daa254dff
patch --batch --forward --fuzz=0 -d /tmp/dohdns-sniproxy-source -p1 < patches/sniproxy-v2.3.0-root-profile.patch
(cd /tmp/dohdns-sniproxy-source && go test ./pkg/doh)
```

Expected: patch applies without offsets/fuzz and the new handler tests pass.

- [ ] **Step 6: Run repository verification**

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/*.py
bash -n deploy/bin/*.sh
git diff --check
```

Expected: all checks pass.

- [ ] **Step 7: Commit the patched build contract**

```bash
git add patches deploy/bin/build-sniproxy.sh deploy/bin/install.sh tools/render_deployment.py \
  inventory.example.json inventory.production.json tests/test_deployment_bundle.py
git commit -m "feat: serve Apple profile from DoH root"
```

---

### Task 3: Document the direct installation URL

**Files:**
- Modify: `tests/test_policy_docs.py:90-103`
- Modify: `docs/client-setup.md:3-12`
- Modify: `README.md:20-29`

**Interfaces:**
- Consumes: production HTTP contract from Task 2.
- Produces: a single primary installation URL, `https://dns.pressroll.ru`, with platform-specific instructions and removal guidance.

- [ ] **Step 1: Write the failing documentation acceptance test**

Add:

```python
def test_client_setup_uses_direct_profile_download_as_primary_apple_path(self) -> None:
    text = (ROOT / "docs/client-setup.md").read_text(encoding="utf-8")
    apple = text.split("## Android", 1)[0]
    self.assertIn("https://dns.pressroll.ru", apple)
    self.assertIn("Safari", apple)
    self.assertIn("Профиль загружен", apple)
    self.assertIn("неподпис", apple.lower())
    self.assertIn("VPN и управление устройством", apple)
    self.assertIn("Управление устройством", apple)
```

- [ ] **Step 2: Run the focused test and confirm it fails**

```bash
python3 -m unittest \
  tests.test_policy_docs.PolicyAndDocumentationTests.test_client_setup_uses_direct_profile_download_as_primary_apple_path -v
```

Expected: failure because the direct production URL is absent.

- [ ] **Step 3: Replace the Apple installation section**

Document these exact user flows:

- iPhone/iPad: open `https://dns.pressroll.ru` in Safari, allow download, open Settings → Profile Downloaded, or General → VPN & Device Management, then Install.
- macOS: open the downloaded file, then System Settings → General → Device Management → Pressroll Smart DNS → Install.
- Explain that the unsigned-profile warning is expected and that the payload sets global DoH to `https://dns.pressroll.ru/dns-query`.
- Keep the existing removal steps and cache-refresh guidance.
- Mention the repository profile path only as a diagnostic fallback, not the primary installation route.

Add a short direct-profile link to the README client section.

- [ ] **Step 4: Run documentation and full tests**

```bash
python3 -m unittest tests.test_policy_docs -v
python3 -m unittest discover -s tests -v
git diff --check
```

Expected: all tests pass.

- [ ] **Step 5: Commit the user documentation**

```bash
git add docs/client-setup.md README.md tests/test_policy_docs.py
git commit -m "docs: publish direct Apple profile URL"
```

---

### Task 4: Build, deploy, verify, and publish

**Files:**
- Verify only: entire repository and production VPS.
- Update only if verification exposes a defect, with a new regression test before the fix.

**Interfaces:**
- Consumes: the complete source tree from Tasks 1-3 and VPS `89.125.113.107`.
- Produces: active production generation serving the profile, preserved DoH/DNS/SNI behavior, and GitHub `main` at the verified commit.

- [ ] **Step 1: Run the complete local verification gate**

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/*.py
bash -n deploy/bin/*.sh
verify_root=$(mktemp -d /tmp/dohdns-root-profile.XXXXXX)
python3 tools/render_deployment.py \
  --inventory inventory.production.json \
  --domain-csv domains/domains.csv \
  --output "$verify_root/rendered" \
  --register-unsafely-without-email
git diff --check
git status --short
```

Expected: every test/check passes; rendered manifest includes the profile hash; only intended committed changes exist.

- [ ] **Step 2: Transfer an immutable source archive to the VPS**

Create `git archive` from the verified commit, calculate SHA-256, upload it with
`scp`, then verify the same hash on the VPS before extraction. Do not copy
`.git`, credentials, certificates, or local temporary files:

```bash
commit=$(git rev-parse --short=12 HEAD)
archive="/tmp/dohdns-$commit.tar.gz"
git archive --format=tar.gz --output "$archive" HEAD
shasum -a 256 "$archive"
scp "$archive" root@89.125.113.107:/tmp/
ssh root@89.125.113.107 "sha256sum /tmp/dohdns-$commit.tar.gz"
```

The local and remote SHA-256 values must be identical. On the VPS extract to a
new explicit directory:

```bash
install -d -m 0700 "/root/DoHDNS-$commit"
tar -xzf "/tmp/dohdns-$commit.tar.gz" -C "/root/DoHDNS-$commit"
cd "/root/DoHDNS-$commit"
```

- [ ] **Step 3: Validate and build on Ubuntu 24.04 before activation**

In the extracted directory on the VPS:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/*.py
bash -n deploy/bin/*.sh
deploy/bin/install.sh \
  --inventory inventory.production.json \
  --domain-csv domains/domains.csv \
  --register-unsafely-without-email \
  --dry-run
```

Then run the source build through the transactional updater, without an external prebuilt:

```bash
deploy/bin/update.sh \
  --inventory inventory.production.json \
  --domain-csv domains/domains.csv \
  --register-unsafely-without-email \
  --force-new-generation
```

Expected: source and patch hashes verify, patched Go tests pass, a new generation activates, and rollback state names the prior generation.

- [ ] **Step 4: Verify the root download contract externally from Russia**

```bash
curl --fail --silent --show-error --dump-header /tmp/profile.headers \
  --output /tmp/dns.pressroll.ru.mobileconfig https://dns.pressroll.ru/
sha256sum /tmp/dns.pressroll.ru.mobileconfig profiles/dns.pressroll.ru.mobileconfig
curl --fail --silent --show-error --head https://dns.pressroll.ru/
```

Expected: `200`, exact matching hashes, expected content type/disposition, `no-store`, `nosniff`, and no body for `HEAD`.

Verify method and unknown-path behavior:

```bash
curl --silent --output /dev/null --write-out '%{http_code}\n' -X POST https://dns.pressroll.ru/
curl --silent --output /dev/null --write-out '%{http_code}\n' https://dns.pressroll.ru/not-found
```

Expected: `405` then `404`.

- [ ] **Step 5: Re-run the existing service acceptance tests**

Check externally and on the VPS:

```bash
curl --fail --silent --show-error --http2 \
  -H 'accept: application/dns-json' \
  'https://dns.pressroll.ru/dns-query?name=openai.com&type=A'
printf 'EjQBAAABAAAAAAAABm9wZW5haQNjb20AAAEAAQ==' | \
  openssl base64 -d -A -out /tmp/doh-wire-query.bin
curl --fail --silent --show-error --http2 \
  -H 'content-type: application/dns-message' \
  -H 'accept: application/dns-message' \
  --data-binary @/tmp/doh-wire-query.bin \
  --output /tmp/doh-wire-response.bin \
  https://dns.pressroll.ru/dns-query
test "$(xxd -p -l 2 /tmp/doh-wire-response.bin)" = 1234
dig @89.125.113.107 openai.com A +short
dig @89.125.113.107 example.com A +short
dig @89.125.113.107 openai.com AAAA +short
printf '' | openssl s_client -connect dns.pressroll.ru:853 \
  -servername dns.pressroll.ru -verify_return_error -brief
echo | openssl s_client -connect 89.125.113.107:443 \
  -servername openai.com -showcerts 2>/dev/null | \
  openssl x509 -noout -subject -issuer -ext subjectAltName
```

Expected: DoH and DoT verify; allowlisted A is `89.125.113.107`; ordinary A remains upstream; proxied AAAA is empty; target certificate is for `openai.com` rather than `dns.pressroll.ru`.

On the VPS verify services, listeners, GeoIP rejection, logs, and rollback metadata:

```bash
systemctl is-active sniproxy dohdns-nftables.service dohdns-geoip-update.timer nginx certbot.timer
systemctl show sniproxy -p NRestarts -p ActiveState -p SubState
ss -lntup
nft list table inet dohdns
journalctl -u sniproxy --since '-10 minutes' --no-pager
cat /var/lib/dohdns/active-generation
cat /var/lib/dohdns/previous-generation
```

Expected: services active, restart counter stable, no DNS query names/profile content in logs, Prometheus only on loopback, UDP 443/853 drop rules present, and both generation names are valid.

- [ ] **Step 6: Verify rollback without leaving production rolled back**

Record the new active generation, execute `/usr/local/libexec/dohdns/rollback.sh`, confirm the previous generation restores the old `404` root while DoH still works, then run the updater again to reactivate the new profile generation. Repeat the full root/DoH/service smoke checks after reactivation.

- [ ] **Step 7: Push the verified commit to GitHub main**

```bash
git status --short
git push origin HEAD:main
git ls-remote --heads origin main
```

Expected: local `HEAD` and `refs/heads/main` have the same commit hash, and `docs/client-setup.md` on GitHub contains `https://dns.pressroll.ru`.
