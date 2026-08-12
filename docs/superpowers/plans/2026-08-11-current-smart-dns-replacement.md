# Current Smart DNS Replacement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the obsolete `sniproxy` repository with a one-command Ubuntu 24.04 installer for the live AdGuard Home + nginx SNI Smart DNS stack.

**Architecture:** A root `bootstrap.sh` downloads the versioned repository archive and executes `deploy/install.sh`. A Python standard-library renderer consumes one canonical CSV policy and emits AdGuard rewrite data, nginx stream SNI map, and health-check metadata. The installer performs safe first install/update/rollback, creates a random AdGuard admin password, prints it once on first install, and stores it mode `0600` on the server.

**Tech Stack:** Bash, Python 3 standard library, AdGuard Home v0.107.78, nginx stream module, systemd, OpenSSL, curl, jq-free JSON/YAML rendering.

## Global Constraints

- Target platform is Ubuntu 24.04 with systemd and IPv4.
- No password, DoH token, certificate, private key, or production inventory is committed.
- First install refuses to overwrite unrelated listeners or existing generation-owned state.
- Updates are idempotent, create backups, preserve the existing AdGuard password, and support rollback.
- The canonical policy must render identical AdGuard rewrites and nginx SNI-map entries.
- `oaiusercontent.com` uses a concrete upload hostname for health probing.
- The first successful install prints `admin` and the generated AdGuard password once; dry-run/update never print credentials.

---

### Task 1: Replace the repository tree and policy source

**Files:**
- Delete: `deploy/`, `domains/`, `patches/`, old `inventory*.json`, old `docs/client-setup.md`, `docs/domain-policy.md`, `docs/privacy-and-limitations.md`, `docs/runbook.md`, `docs/service-discovery.md`, and old `tests/` files tied to `sniproxy`.
- Create: `config/policy.csv` with normalized `domain,kind,probe` rows for the active AI, OpenAI upload, Google AI, Claude, Copilot, Perplexity, Grok, Midjourney, and Fitbit endpoints.
- Create: `config/defaults.env.example` with non-secret defaults.
- Modify: `README.md` to document the one-command workflow and credential output.
- Create: `docs/operations.md` with install/update/rollback and client profile instructions.

**Interfaces:**
- `config/policy.csv` is consumed by the renderer as UTF-8 CSV; `kind` is `fqdn` or `suffix`; `probe` is the TLS hostname or empty for the row domain.
- The policy must include `oaiusercontent.com,suffix,files.oaiusercontent.com` and the four Fitbit FQDN rows.

- [ ] **Step 1: Add the normalized policy and defaults example.**
- [ ] **Step 2: Remove all old sniproxy-owned files from the working tree.**
- [ ] **Step 3: Update README and operations documentation with the actual command and generated credential path.**
- [ ] **Step 4: Run `git diff --check` and scan the tree for `sniproxy` references; only historical/specification references may remain.**
- [ ] **Step 5: Commit `docs: replace legacy sniproxy repository surface`.**

### Task 2: Implement deterministic policy rendering

**Files:**
- Create: `tools/render_config.py`.
- Create: `tests/test_render_config.py`.

**Interfaces:**
- `load_policy(path: Path) -> list[PolicyRow]` validates normalized FQDNs, kinds, duplicate rows, and probe hosts.
- `render_nginx_stream(rows: Sequence[PolicyRow], doh_host: str) -> str` emits the complete `stream` block with default `127.0.0.1:9`.
- `render_rewrites(rows: Sequence[PolicyRow], public_ip: str) -> list[dict[str, object]]` emits one FQDN rule or two suffix rules.
- CLI: `python3 tools/render_config.py --policy config/policy.csv --public-ip 203.0.113.10 --doh-host dns.example.com --output DIR`.

- [ ] **Step 1: Write failing tests for normalization, duplicate rejection, fqdn-vs-suffix expansion, and the oaiusercontent probe.**
- [ ] **Step 2: Implement the dataclass/parser and deterministic sorting.**
- [ ] **Step 3: Implement nginx and AdGuard renderers with shell/YAML-safe escaping.**
- [ ] **Step 4: Run `python3 -m unittest tests.test_render_config -v` and verify all tests pass.**
- [ ] **Step 5: Commit `feat: add canonical policy renderer`.**

### Task 3: Build the server installer and credential handling

**Files:**
- Create: `bootstrap.sh`.
- Create: `deploy/install.sh`.
- Create: `deploy/lib/common.sh`.
- Create: `deploy/lib/credentials.py`.
- Create: `tests/test_install_cli.py`.

**Interfaces:**
- Bootstrap command: `curl --fail --silent --show-error --location https://raw.githubusercontent.com/evgenykhripach/DoHDNS/main/bootstrap.sh | sudo bash -s -- --domain dns.example.com --public-ip 203.0.113.10 --email admin@example.com`.
- Installer flags: `--domain`, `--public-ip`, `--email`, `--policy`, `--dry-run`, `--update`, `--rollback`, `--root`.
- Credential file: `/var/lib/adguardhome-doh/admin-credentials.json` mode `0600`, with JSON login, password, and URL fields.
- First install generates `admin` plus `openssl rand -hex 24`; update reads and preserves the existing password.

- [ ] **Step 1: Write failing CLI tests for required flags, dry-run no-write behavior, one-time credential output, and update password preservation.**
- [ ] **Step 2: Implement bootstrap archive download with a temporary directory and `exec` into `deploy/install.sh`.**
- [ ] **Step 3: Implement root/sandbox preflight, package installation, pinned AdGuard Home download, user creation, and directory ownership.**
- [ ] **Step 4: Implement credential generation/storage and print the URL/login/password only after successful first activation.**
- [ ] **Step 5: Run `bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh` and `python3 -m unittest tests.test_install_cli -v`.**
- [ ] **Step 6: Commit `feat: add one-command installer and admin credentials`.**

### Task 4: Render and activate AdGuard, nginx, TLS, DoH, and health-gate units

**Files:**
- Create: `deploy/templates/AdGuardHome.yaml.tmpl`.
- Create: `deploy/templates/nginx-http.conf.tmpl`.
- Create: `deploy/templates/healthcheck.py.tmpl`.
- Create: `deploy/templates/healthcheck.service`.
- Create: `deploy/templates/healthcheck.timer`.
- Create: `deploy/templates/rollback.service`.
- Modify: `deploy/install.sh` to stage, validate, atomically activate, reload, and rollback.

**Interfaces:**
- AdGuard listens on `127.0.0.1:53` and `127.0.0.1:3001`; nginx terminates the DoH/admin TLS listener on loopback `127.0.0.1:4443` and exposes the SNI stream listener on public `:443`.
- `/dns-query` returns 404; only the generated random `/doh/<token>` path proxies to AdGuard `/dns-query`.
- Nginx validates with `nginx -t`; AdGuard validates with its `--check-config` command before activation.

- [ ] **Step 1: Add template tests for loopback binding, no public admin listener, exact DoH path, and generated SNI entries.**
- [ ] **Step 2: Implement staged rendering under `/var/lib/adguardhome-doh/staging`.**
- [ ] **Step 3: Implement certificate issuance/renewal hook and secure file modes.**
- [ ] **Step 4: Implement health state, three-success/two-failure gating, and automatic rewrite reconciliation.**
- [ ] **Step 5: Implement atomic activation with backup and rollback on failed validation/reload.**
- [ ] **Step 6: Run the template/unit tests and a sandbox install with `--root`.**
- [ ] **Step 7: Commit `feat: activate adguard nginx and health gate`.**

### Task 5: Add release validation and GitHub-ready documentation

**Files:**
- Create: `tests/test_repository_contract.py`.
- Create: `tools/check_release.py`.
- Modify: `README.md`, `docs/operations.md`.

- [ ] **Step 1: Test that no secret-like files, production inventory, or legacy sniproxy executable/config remains.**
- [ ] **Step 2: Test that the bootstrap URL, admin credential behavior, Fitbit rows, and OpenAI upload probe are documented.**
- [ ] **Step 3: Run the full suite: `python3 -m unittest discover -s tests -v`.**
- [ ] **Step 4: Run `python3 tools/check_release.py`, `bash -n` on all shell files, and `git diff --check`.**
- [ ] **Step 5: Commit `test: validate one-command release contract`.**

### Task 6: Publish the replacement

**Files:**
- Git branch: `feat/smart-dns`.

- [ ] **Step 1: Review `git status -sb`, `git diff --stat`, and the release validation output.**
- [ ] **Step 2: Run `gh --version` and `gh auth status`; stop if GitHub authentication is unavailable.**
- [ ] **Step 3: Push with tracking to `origin/feat/smart-dns`.**
- [ ] **Step 4: Open a draft PR targeting the repository default branch with the replacement summary and verification evidence.**
- [ ] **Step 5: Report branch, commit, PR, and the exact one-command install invocation.**
