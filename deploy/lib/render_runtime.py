#!/usr/bin/env python3
"""Render all runtime files for one Smart DNS activation."""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.render_config import (  # noqa: E402
    load_policy,
    render_adguard_yaml,
    render_health_policy,
    render_nginx_http,
    render_nginx_stream,
)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--doh-host", required=True)
    parser.add_argument("--doh-token", required=True)
    parser.add_argument("--password-hash", required=True)
    parser.add_argument("--certificate-root", required=True)
    parser.add_argument("--webroot", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    rows = load_policy(args.policy)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.output / "AdGuardHome.yaml").write_text(
        render_adguard_yaml(rows, args.password_hash), encoding="utf-8"
    )
    (args.output / "nginx-http.conf").write_text(
        render_nginx_http(args.doh_host, args.doh_token,
                          args.certificate_root, args.webroot), encoding="utf-8"
    )
    (args.output / "nginx-stream.conf").write_text(
        render_nginx_stream(rows, args.doh_host), encoding="utf-8"
    )
    (args.output / "health-policy.json").write_text(
        render_health_policy(rows), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
