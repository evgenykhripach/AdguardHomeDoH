# Nginx Activation Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make nginx activation survive transient reload failures and prevent IPv6 upstream selection on IPv4-only hosts.

**Architecture:** Reuse the existing renderer, shell common library, installer activation flow, and manager transaction rollback. Add one shared shell smoke helper for installation and one Python manager helper with equivalent behavior; do not add dependencies or services.

**Tech Stack:** Bash, Python 3 standard library/subprocess, nginx stream, unittest.

## Global Constraints

- Ubuntu 24.04+ and IPv4-only public deployment remain the supported environment.
- Preserve the existing `adguardhome-doh` paths, Russian interface, credentials, token, and selected services.
- Do not broaden domain policy or change health probes.
- Release version is `1.0.23`.

---

### Task 1: Renderer IPv4-only resolver

**Files:**
- Modify: `tests/test_render_config.py`
- Modify: `tools/render_config.py`

**Interfaces:**
- Consumes: `render_nginx_stream(rows, doh_host) -> str`
- Produces: nginx resolver directive containing `ipv4=on ipv6=off`

- [ ] Add a failing assertion that rendered stream configuration disables IPv6 resolution.
- [ ] Run the focused renderer test and confirm it fails because `ipv6=off` is absent.
- [ ] Add `ipv6=off` to the existing resolver directive.
- [ ] Run renderer tests and confirm they pass.

### Task 2: Installer final activation smoke check

**Files:**
- Modify: `tests/test_install_cli.py`
- Modify: `deploy/lib/common.sh`
- Modify: `deploy/install.sh`

**Interfaces:**
- Produces: `adguardhome_doh_smoke_https_sni HOST [ATTEMPTS]`, returning nonzero unless local port 443 completes TLS and returns an HTTP status.

- [ ] Add failing source/behavior tests for one final nginx reload and a smoke check before the completion marker.
- [ ] Run focused installer tests and confirm expected failures.
- [ ] Implement the retrying curl `--resolve HOST:443:127.0.0.1` smoke helper without logging private paths.
- [ ] Remove the pre-certificate nginx reload; keep one reload after final HTTP config installation.
- [ ] Call the smoke helper before health activation and the completion marker.
- [ ] Run installer tests and shell syntax checks.

### Task 3: Manager activation validation

**Files:**
- Modify: `tests/test_manager.py`
- Modify: `deploy/manage.py`

**Interfaces:**
- Produces: `smoke_https_sni(domain, runner=subprocess.run, attempts=3, delay=2) -> None`
- Changes: `reload_runtime_services(root, runner, domain)` reloads once and validates the local SNI path.

- [ ] Add failing tests that verify the domain-aware smoke command and error propagation.
- [ ] Run focused manager tests and confirm expected failures.
- [ ] Implement the retrying smoke helper and pass the installation domain from service-change activation.
- [ ] Run manager tests and confirm transaction rollback tests remain green.

### Task 4: Release and verification

**Files:**
- Modify: `VERSION`

- [ ] Set `VERSION` to `1.0.23`.
- [ ] Run all unit tests, release contract, shell syntax, `git diff --check`, and neutral-name grep.
- [ ] Commit the implementation and push `main`.
- [ ] Create and push annotated tag `v1.0.23`.
- [ ] Verify stable release workflow, asset SHA-256, archive `VERSION`, and required files.

