#!/usr/bin/env python3
"""Validate the public repository contract before publishing."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def tracked_files():
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, check=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line]


def main():
    required = [
        ROOT / "bootstrap.sh",
        ROOT / "VERSION",
        ROOT / "deploy/install.sh",
        ROOT / "deploy/manage.py",
        ROOT / "deploy/lib/releases.py",
        ROOT / "config/policy.csv",
        ROOT / "config/services.csv",
        ROOT / "config/domains.csv",
        ROOT / "config/service-domains.csv",
        ROOT / "config/service-probes.csv",
        ROOT / "tools/render_config.py",
        ROOT / "deploy/templates/healthcheck.py",
        ROOT / "tests/ubuntu_26_04_smoke.sh",
        ROOT / ".github/workflows/release.yml",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("missing release files: " + ", ".join(missing))
    smoke_test = ROOT / "tests/ubuntu_26_04_smoke.sh"
    if not smoke_test.stat().st_mode & 0o111:
        raise SystemExit("Ubuntu 26.04 smoke test is not executable")
    forbidden = [
        "deploy/bin/",
        "deploy/templates/sniproxy",
        "tools/render_deployment.py",
        "tools/validator.py",
        "inventory.production.json",
        "profiles/dns.adguardhome-doh.mobileconfig",
    ]
    tracked = [str(path.relative_to(ROOT)) for path in tracked_files()]
    leftovers = [path for path in tracked if any(path.startswith(item) or path == item for item in forbidden)]
    if leftovers:
        raise SystemExit("legacy release files remain: " + ", ".join(leftovers))
    policy = (ROOT / "config/policy.csv").read_text(encoding="utf-8")
    for required_row in (
        "oaiusercontent.com,suffix,files.oaiusercontent.com",
        "api.fitbit.com,fqdn,",
        "fitbit-pa.googleapis.com,fqdn,",
    ):
        if required_row not in policy:
            raise SystemExit("required policy row missing: " + required_row)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for phrase in ("adguardhome-doh", "admin-credentials", "Password:"):
        if phrase not in readme:
            raise SystemExit("README missing: " + phrase)
    for shell_file in (
        ROOT / "bootstrap.sh",
        ROOT / "deploy/install.sh",
        ROOT / "deploy/lib/common.sh",
        ROOT / "tests/ubuntu_26_04_smoke.sh",
    ):
        subprocess.run(["bash", "-n", str(shell_file)], check=True)
    print("release contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
