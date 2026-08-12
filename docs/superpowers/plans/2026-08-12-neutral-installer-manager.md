# Neutral AdGuard Home DoH Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Every behavior change follows TDD.

**Goal:** Deliver a Russian interactive installer and root-only management menu for a neutral `adguardhome-doh` deployment with a 205-domain product catalog and stable GitHub Release updates.

**Architecture:** Keep Bash as the installation orchestrator and ANSI UI, with Python modules for strict catalog/state parsing, rendering, health reconciliation, and release metadata. One selected-service state generates AdGuard Home, nginx stream, and health runtime files. All activation is staged, validated, backed up, and rolled back on failure.

**Tech Stack:** Bash, Python 3 standard library, AdGuard Home 0.107.78, nginx stream, systemd, Certbot, GitHub REST Releases API.

## Global Constraints

- Target checkout: `/Users/evgeny/Project/DNS/neutral-installer-manager`.
- Public product/system name: `adguardhome-doh`; environment prefix: `ADGUARDHOME_DOH_`.
- Russian ANSI interface only; no dialog, whiptail, curses, or management subcommands.
- Clean Ubuntu 24.04+ only; no legacy migration and no Git-history rewrite.
- Existing AdGuard Home DNS remains loopback-only; only HTTPS admin, private tokenized DoH, and mobileconfig are published.
- Never log credentials, DoH tokens, or private URLs. Managed state and logs containing operational data use mode 0600.
- Preserve noninteractive installer flags for CI: `--domain`, `--public-ip`, `--email`, `--services`, `--dry-run`, `--root`.
- No push, GitHub Release publication, or VPS change.

---

### Task 1: Catalog and neutral rendering foundation

**Files:**
- Replace: `config/policy.csv`
- Create: `config/services.csv`, `config/domains.csv`, `config/service-domains.csv`, `config/service-probes.csv`
- Modify: `tools/render_config.py`, `deploy/lib/render_runtime.py`
- Test: `tests/test_catalog.py`, `tests/test_render_config.py`

**Interfaces:**
- `Catalog.load(config_dir: Path) -> Catalog` validates all four CSV files.
- `Catalog.enabled_policy(service_ids: Collection[str], healthy_service_ids: Collection[str] | None) -> list[PolicyRow]` returns a deduplicated domain union.
- `services.csv`: `id,name_ru,category,default_enabled,risk_level`.
- `domains.csv`: `domain,kind` where kind is `fqdn` or `suffix`.
- `service-domains.csv`: `service_id,domain`.
- `service-probes.csv`: `service_id,hostname`; all configured probes are required.

**Requirements:**
- Import all 178 unique attachment domains plus all current policy domains: exactly 205 unique domains.
- Retain current kind choices and the ChatGPT upload probe `files.oaiusercontent.com`.
- Default service IDs are exactly `chatgpt`, `claude`, `gemini`, `microsoft_copilot`, `github_copilot`, `grok`.
- Product-level selectable groups cover every ordinary domain. Shared Google/OpenAI/CDN domains have multiple associations.
- Unidentified, infrastructure-only, and sensitive domains are associated only with services whose `risk_level=experimental`; no experimental service is default-enabled.
- Effective domains are active while any associated selected and healthy service remains active.
- Existing AdGuard, nginx HTTP/stream, and health-policy rendering remains deterministic.

**Verification:** catalog count/foreign-key/orphan tests; shared-domain union tests; renderer tests; full unit suite.

---

### Task 2: Interactive installer, progress, neutral state and final summary

**Files:**
- Modify: `bootstrap.sh`, `deploy/install.sh`, `deploy/lib/common.sh`, `deploy/lib/credentials.py`
- Create: `deploy/lib/ui.sh`, `deploy/lib/state.py`, `VERSION`
- Test: `tests/test_install_cli.py`, `tests/test_interactive_installer.py`, `tests/test_state.py`

**Interfaces:**
- Missing required flags are read in order from `/dev/tty`: domain, IPv4, email, service selection, confirmation.
- `--services` accepts comma-separated stable service IDs; omission uses the six default IDs.
- `install.json` stores `domain`, `public_ip`, `email`, `version`, `repository`; `enabled-services.json` stores a JSON string array.
- Credentials are JSON containing `url`, `login`, `password`; strict Python parsing replaces shell sourcing.

**Requirements:**
- Validate/retry one prompt at a time. Non-TTY missing input fails clearly rather than hanging.
- ANSI selector supports category display, numbered toggles/ranges, standard-all, defaults, experimental section, confirm, and cancel.
- Progress milestones are exactly 0, 5, 20, 35, 50, 65, 75, 85, 95, 100. Non-TTY output is `[NN%]` lines.
- Full command output goes to `/var/log/adguardhome-doh/install-<UTC>.log` mode 0600. Secrets bypass the log.
- Preflight validates clean-host assumptions, DNS A match, and required listener availability before certificate activation.
- Final summary always prints admin URL/login/password, DoH URL, mobileconfig URL, credentials path, log path, and `sudo adguardhome-doh`.
- All paths, units, identifiers, variables, profile metadata, and nginx names use the neutral contract.

**Verification:** pseudo-TTY red/green tests; monotonic progress tests; secret-redaction tests; dry-run and summary tests; full unit suite.

---

### Task 3: Interactive manager and service-level health gate

**Files:**
- Create: `deploy/manage.py`
- Modify: `deploy/templates/healthcheck.py`, health systemd templates, runtime renderer and installer activation
- Test: `tests/test_manager.py`, `tests/test_healthcheck.py`, `tests/test_render_config.py`

**Interfaces:**
- Installed command `/usr/local/sbin/adguardhome-doh` opens the menu only when root and attached to a TTY.
- Menu entries: access data; edit services; system check; check/install update; rollback last update; exit.
- Health state is keyed by service ID. Up to eight probes execute concurrently; all probes for a service must pass.

**Requirements:**
- Service changes preview counts, require confirmation, create a full backup, render into staging, validate AdGuard/nginx, atomically activate, and automatically restore on failure.
- nginx includes the union of enabled services; AdGuard rewrites are reconciled from enabled and healthy services.
- Health gate keeps 3-success enable and 2-failure disable thresholds, uses a non-overlap lock, and clears AdGuard cache after changes.
- System check reports units, nginx, AdGuard config, certificate, local admin/DoH/mobileconfig endpoints, health state, and active-domain count without leaking tokens into logs.

**Verification:** selector/menu integration tests; shared-domain behavior; probe concurrency/threshold/lock tests; transactional activation/rollback tests.

---

### Task 4: Stable update, backup/rollback, and release artifact contract

**Files:**
- Create: `deploy/lib/releases.py`, `.github/workflows/release.yml`
- Modify: `bootstrap.sh`, `deploy/manage.py`, `deploy/install.sh`, `tools/check_release.py`
- Test: `tests/test_releases.py`, `tests/test_repository_contract.py`, installer/manager tests

**Interfaces:**
- Current version comes from `VERSION=1.0.0`.
- Query `GET /repos/evgenykhripach/AdguardHomeDoH/releases/latest` with GitHub JSON/API-version headers.
- Stable asset names: `adguardhome-doh.tar.gz` and `adguardhome-doh.tar.gz.sha256`.

**Requirements:**
- A 404 means no stable release. Accept only `vMAJOR.MINOR.PATCH`, compare semantic integer tuples, and require archive VERSION to match the tag.
- Verify SHA-256 and required files before invoking update.
- Back up all managed config/state, nginx, systemd, webroot, and AdGuard YAML. Preserve credentials, token, and existing service IDs; newly introduced services remain disabled.
- Activation failure restores the complete backup and restarts the prior working services.
- Bootstrap downloads only the latest stable fixed-name release asset and checksum; it does not install runtime from the main branch archive.
- Release workflow builds/checks the fixed-name archive on `v*` tags but local implementation does not publish a tag or Release.

**Verification:** mocked 404/current/new/malformed API cases; corrupt checksum; mismatched VERSION; failed update rollback; release-contract tests.

---

### Task 5: Documentation, neutrality, full smoke and release readiness

**Files:**
- Rewrite: `README.md`, `docs/operations.md`
- Modify: all tests/workflows and obsolete internal plan documents containing the legacy brand
- Test: `tests/ubuntu_26_04_smoke.sh`, repository contract

**Requirements:**
- Document interactive installation, clean-host boundary, default/experimental services, menu, links, stable update, rollback, and loopback DNS network contract.
- Current tracked tree contains zero case-insensitive occurrences of the legacy brand.
- Smoke installs twice on Ubuntu 26.04, validates real AdGuard config and context-correct nginx HTTP/stream config, retrieves mobileconfig over HTTPS, tests menu-managed selection, and proves secret files have mode 0600.
- Prepare repository state for a separately authorized first `v1.0.0` release; do not push, tag, publish, or deploy.

**Verification:** full unit suite; shell syntax; repository/release contract; neutrality scan; `git diff --check`; Ubuntu 26.04 Docker smoke.
