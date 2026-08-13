# Domain Mobileconfig Naming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate, serve, download, and diagnose the Apple configuration profile using the configured installation domain as its filename and display name while preserving the private tokenized URL.

**Architecture:** Extend the existing Python renderer so staging contains a domain-named profile and nginx maps the tokenized request to that file. The installer copies the rendered profile into the webroot. Update the manager and smoke contracts to inspect the new path.

**Tech Stack:** Bash, Python 3 standard library, nginx configuration, Apple mobileconfig plist, Python `unittest`.

## Global Constraints

- The private URL remains `https://<domain>/<token>.mobileconfig`.
- The stored and downloaded filename is `<domain>.mobileconfig`.
- Both `PayloadDisplayName` values are exactly the configured domain.
- DoH token, DoH URL, credentials, and installation state remain unchanged.
- Existing token-named files are not deleted during updates.

---

### Task 1: Profile generation and nginx delivery

**Files:**
- Modify: `tests/test_install_cli.py`
- Modify: `tests/test_render_config.py`
- Modify: `deploy/install.sh`
- Modify: `deploy/lib/render_runtime.py`
- Modify: `tools/render_config.py`

**Interfaces:**
- Consumes: `DOMAIN`, `DOH_TOKEN`, and `WEBROOT` from the existing installer.
- Produces: `render_mobileconfig(doh_host, doh_token) -> str` and `render_nginx_http(doh_host, doh_token, certificate_root, webroot) -> str` with a tokenized location mapped to `<webroot>/<doh_host>.mobileconfig`.

- [ ] **Step 1: Add failing rendered-profile behavior tests**

Render runtime files for `dns.example.com`; assert the staged file is named `dns.example.com.mobileconfig`, contains the tokenized DoH URL, and contains exactly two `PayloadDisplayName` elements whose value is `dns.example.com`.

- [ ] **Step 2: Add failing renderer behavior tests**

For `dns.example.com` and a 48-character token, assert that the output still contains `location = /<token>.mobileconfig`, maps it to `/var/www/html/dns.example.com.mobileconfig`, and sends `filename="dns.example.com.mobileconfig"`.

- [ ] **Step 3: Run focused tests and observe RED**

Run:

```bash
rtk python3 -m unittest tests.test_install_cli tests.test_render_config -v
```

Expected: failures because staging has no mobileconfig and nginx still uses the requested token path and static download filename.

- [ ] **Step 4: Implement the minimal installer and renderer changes**

Add `render_mobileconfig()` with both display names set to the validated domain. Make `render_runtime.py` stage `<domain>.mobileconfig`. Replace the installer heredoc with an `install` from staging. In `render_nginx_http`, preserve the tokenized exact-match location, map it internally to the domain-named file using an exact `try_files /<domain>.mobileconfig =404`, and set the matching `Content-Disposition` filename.

- [ ] **Step 5: Run focused tests and observe GREEN**

Run:

```bash
rtk python3 -m unittest tests.test_install_cli tests.test_render_config -v
```

Expected: all focused tests pass.

### Task 2: Manager diagnostics and end-to-end smoke contract

**Files:**
- Modify: `tests/test_manager.py`
- Modify: `deploy/manage.py`
- Modify: `tests/ubuntu_26_04_smoke.sh`

**Interfaces:**
- Consumes: installation domain from `/var/lib/adguardhome-doh/install.json` and webroot from `_runtime_paths()`.
- Produces: `collect_system_check()` reports `mobileconfig=true` only when `<webroot>/<domain>.mobileconfig` exists.

- [ ] **Step 1: Add a failing manager diagnostic test**

Build a temporary root with installation state for `dns.example.com`, create `dns.example.com.mobileconfig`, and assert `collect_system_check(root)["endpoints"]["mobileconfig"]` is true without creating a token-named profile.

- [ ] **Step 2: Run the manager test and observe RED**

Run:

```bash
rtk python3 -m unittest tests.test_manager -v
```

Expected: the mobileconfig endpoint is false because diagnostics still check only for the token state file.

- [ ] **Step 3: Implement the domain-path diagnostic**

Compute `profile = paths["webroot"] / (domain + ".mobileconfig")` and use `profile.is_file()` for the `mobileconfig` endpoint. Keep the DoH endpoint tied to the token state file.

- [ ] **Step 4: Update the Ubuntu smoke assertions**

Check `/var/www/adguardhome-doh/$DOMAIN.mobileconfig`, retain the tokenized download URL, assert the downloaded `Content-Disposition` filename is domain-based, and assert both payload display-name occurrences equal `$DOMAIN`.

- [ ] **Step 5: Run focused manager tests and shell syntax**

Run:

```bash
rtk python3 -m unittest tests.test_manager -v
rtk bash -n deploy/install.sh tests/ubuntu_26_04_smoke.sh
```

Expected: tests and syntax checks pass.

### Task 3: Full verification

**Files:**
- Verify only: all changed files and repository contracts.

**Interfaces:**
- Consumes: completed Tasks 1 and 2.
- Produces: release-ready local change with no legacy branding regression.

- [ ] **Step 1: Run the full unit suite**

```bash
rtk python3 -m unittest discover -s tests -v
```

- [ ] **Step 2: Run release and source checks**

```bash
rtk python3 tools/check_release.py
rtk bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh deploy/lib/ui.sh tests/ubuntu_26_04_smoke.sh
rtk git diff --check
rtk git grep -n -i pressroll
```

Expected: unit suite and release checks pass; shell syntax and diff checks exit zero; branding grep has no matches and exits one.

- [ ] **Step 3: Review the diff against the approved design**

Confirm the URL remains tokenized, the stored/downloaded filename is the domain, both payload display names are the domain, diagnostics use the new file, and no profile files are deleted.
