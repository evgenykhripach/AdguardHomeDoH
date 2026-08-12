# Installer Address Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Print private DoH and Apple `mobileconfig` URLs on first install and document repeat retrieval commands in Russian.

**Architecture:** Keep URL generation unchanged in `deploy/install.sh`; extend only the first-install output block. Add a source-level installer contract test because a full first install requires a real Ubuntu 24.04 host and mutates system services. Rewrite the top-level README to describe the public bootstrap and post-install operations.

**Tech Stack:** Bash installer, Python `unittest`, Markdown, GitHub raw/codeload bootstrap.

## Global Constraints

- URL formats remain `https://HOST/doh/<token>` and `https://HOST/<token>.mobileconfig`.
- Initial install prints both URLs; update path does not print regenerated addresses.
- The token is private and must not be committed or pasted into public issues/chats.
- Credentials remain in `/var/lib/pressroll-smart-dns/admin-credentials` with mode `0600`.

---

### Task 1: Lock the first-install output contract

**Files:**
- Modify: `tests/test_install_cli.py`
- Modify: `deploy/install.sh:229-238`

**Interfaces:**
- Test consumes installer source text and asserts the user-visible labels.
- Installer produces `DoH URL:` and `mobileconfig:` lines using `$DOMAIN` and
  `$DOH_TOKEN` only inside the `FIRST_INSTALL` branch.

- [ ] **Step 1: Write the failing test**

Add:

```python
    def test_first_install_prints_doh_and_mobileconfig_urls(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn('printf \'DoH URL: https://%s/doh/%s\\n\'', source)
        self.assertIn('printf \'mobileconfig: https://%s/%s.mobileconfig\\n\'', source)
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/pressroll-smart-dns-pycache python3 -m unittest tests.test_install_cli.InstallerCliTests.test_first_install_prints_doh_and_mobileconfig_urls -v
```

Expected: failure because the current installer prints only `Apple profile:`.

- [ ] **Step 3: Implement minimal output change**

Inside `if ((FIRST_INSTALL)); then`, retain the admin credential lines and
replace the old profile line with:

```bash
    printf 'DoH URL: https://%s/doh/%s\n' "$DOMAIN" "$DOH_TOKEN"
    printf 'mobileconfig: https://%s/%s.mobileconfig\n' "$DOMAIN" "$DOH_TOKEN"
```

- [ ] **Step 4: Run focused test and full test suite**

Run:

```bash
PYTHONPYCACHEPREFIX=/tmp/pressroll-smart-dns-pycache python3 -m unittest tests.test_install_cli.InstallerCliTests.test_first_install_prints_doh_and_mobileconfig_urls -v
PYTHONPYCACHEPREFIX=/tmp/pressroll-smart-dns-pycache python3 -m unittest discover -s tests -v
```

Expected: focused test and all repository tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_install_cli.py deploy/install.sh
git commit -m "feat: print private dns endpoints on first install"
```

### Task 2: Rewrite Russian README and publish

**Files:**
- Modify: `README.md`

**Interfaces:**
- Documentation consumes the exact installer arguments and output labels from
  Task 1.
- Documentation produces copy-pasteable install, repeat-address, credential,
  status, update, and rollback commands.

- [ ] **Step 1: Rewrite README in Russian**

Include sections for purpose, prerequisites, one-command install, first-install
output, repeat address retrieval, credential retrieval, client setup, supported
policy domains, health gate, update/rollback, and security notes. Use the
public bootstrap URL under `evgenykhripach/AdguardHomeDoH/main`.

- [ ] **Step 2: Validate documentation and shell snippets**

Run:

```bash
git diff --check
bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh
python3 tools/check_release.py
```

Expected: no diff whitespace errors, shell syntax success, and `release contract: ok`.

- [ ] **Step 3: Commit README**

```bash
git add README.md
git commit -m "docs: rewrite readme in russian"
```

- [ ] **Step 4: Push and verify anonymous GitHub content**

Run:

```bash
git push origin feat/smart-dns
git push origin HEAD:main
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/README.md \
  | grep -Fq 'Установка одной командой'
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | grep -Fq 'PRESSROLL_REPOSITORY=evgenykhripach/AdguardHomeDoH'
```

Expected: both pushes succeed and anonymous raw checks return success.
