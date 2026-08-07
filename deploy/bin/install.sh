#!/usr/bin/env bash
set -eEuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# Installed bundles carry their own renderer/templates so update.sh remains
# usable without the original checkout. Source-tree invocation keeps the
# repository root discovered by common.sh.
if [[ -f "$SCRIPT_DIR/tools/render_deployment.py" ]]; then
    DOHDNS_PROJECT_ROOT="$SCRIPT_DIR"
fi

ROOT=/
INVENTORY=
DOMAIN_CSV=
DRY_RUN=0
FORCE_NEW=0
REGISTER_UNSAFELY=0
UPDATE_MODE=0
PREBUILT_BINARY=
PREBUILT_SHA256=

usage() {
    printf 'usage: %s --inventory PATH [--domain-csv PATH] [--root PATH] [--prebuilt-binary PATH --prebuilt-sha256 HEX] [--dry-run] [--force-new-generation] [--register-unsafely-without-email]\n' "$0"
}

while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --inventory) INVENTORY="$2"; shift 2 ;;
        --domain-csv) DOMAIN_CSV="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --force-new-generation) FORCE_NEW=1; shift ;;
        --register-unsafely-without-email) REGISTER_UNSAFELY=1; shift ;;
        --prebuilt-binary) PREBUILT_BINARY="$2"; shift 2 ;;
        --prebuilt-sha256) PREBUILT_SHA256="$2"; shift 2 ;;
        --update) UPDATE_MODE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; dohdns_die "unknown argument: $1" ;;
    esac
done

ROOT="$(dohdns_abs_root "$ROOT")"
if [[ -z "$INVENTORY" ]]; then
    if [[ "$ROOT" == "/" ]]; then
        INVENTORY="$DOHDNS_PROJECT_ROOT/inventory.example.json"
    else
        INVENTORY="$(dohdns_under_root "$ROOT" /etc/dohdns/inventory.json)"
    fi
fi
[[ -f "$INVENTORY" ]] || dohdns_die "inventory file missing: $INVENTORY"
if [[ -n "$PREBUILT_BINARY" || -n "$PREBUILT_SHA256" ]]; then
    [[ -n "$PREBUILT_BINARY" && -n "$PREBUILT_SHA256" ]] || \
        dohdns_die "--prebuilt-binary and --prebuilt-sha256 must be provided together"
fi
if [[ -z "$DOMAIN_CSV" && "$ROOT" != "/" ]]; then
    existing_domains="$(dohdns_under_root "$ROOT" /etc/sniproxy/current/domains.csv)"
    if [[ -f "$existing_domains" ]]; then DOMAIN_CSV="$existing_domains"; fi
fi

if ((DRY_RUN)); then
    # Validation imports no host-facing modules and writes nothing. Keep this
    # branch before locks, mkdir, root checks, package managers, or networks.
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$DOHDNS_PROJECT_ROOT" python3 - "$INVENTORY" "$REGISTER_UNSAFELY" <<'PY'
import json
import sys
from pathlib import Path
from tools.render_deployment import validate_inventory_for_render

inventory = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
validate_inventory_for_render(inventory, register_unsafely_without_email=sys.argv[2] == "1")
PY
    printf 'DRY-RUN validate inventory: %s\n' "$INVENTORY"
    printf 'DRY-RUN render deterministic staging tree\n'
    printf 'DRY-RUN verify pinned source and Go SHA256 inputs\n'
    printf 'DRY-RUN prepare versioned binary/config generation\n'
    printf 'DRY-RUN activate nginx, resolver, GeoIP, TLS, firewall, and systemd in order\n'
    exit 0
fi

dohdns_require_root_for_host "$ROOT"
LOCK_PATH="$(dohdns_under_root "$ROOT" /var/lock/dohdns-install.lock)"
dohdns_lock_acquire "$LOCK_PATH"

STATE_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns)"
GEN_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/generations)"
STAGE_DIR=""
dohdns_mkdir "$STATE_DIR" 0750
dohdns_mkdir "$GEN_DIR" 0750

if [[ "$ROOT" == "/" ]]; then
    # Host-only operations. Sandbox mode deliberately skips every one.
    command -v apt-get >/dev/null 2>&1 || dohdns_die "apt-get is required on Ubuntu 24.04"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl nginx certbot nftables mmdb-bin openssl tar xz-utils
    if ! getent group sniproxy >/dev/null 2>&1; then groupadd --system sniproxy; fi
    if ! id sniproxy >/dev/null 2>&1; then useradd --system --gid sniproxy --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sniproxy; fi
    chown root:sniproxy -- "$STATE_DIR" "$GEN_DIR"
fi

STAGE_DIR="$(mktemp -d "$STATE_DIR/.render.XXXXXX")"
cleanup_stage() {
    [[ -z "$STAGE_DIR" ]] || rm -rf -- "$STAGE_DIR"
    if [[ -n "${DOHDNS_LOCK_DIR:-}" ]]; then
        rmdir -- "$DOHDNS_LOCK_DIR" 2>/dev/null || true
    fi
}
trap cleanup_stage EXIT
render_args=(--inventory "$INVENTORY" --output "$STAGE_DIR")
if [[ -n "$DOMAIN_CSV" ]]; then render_args+=(--domain-csv "$DOMAIN_CSV"); fi
if ((REGISTER_UNSAFELY)); then render_args+=(--register-unsafely-without-email); fi
PYTHONPATH="$DOHDNS_PROJECT_ROOT" python3 "$DOHDNS_PROJECT_ROOT/tools/render_deployment.py" "${render_args[@]}"

manifest_generation() {
    python3 - "$1" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["generation"])
PY
}

base_generation="$(manifest_generation "$STAGE_DIR/manifest.json")"
generation="$base_generation"
if ((FORCE_NEW)); then
    suffix=2
    while [[ -e "$GEN_DIR/$generation" ]]; do
        generation="${base_generation}-${suffix}"
        suffix=$((suffix + 1))
    done
fi
generation_path="$GEN_DIR/$generation"

# Build pinned source on real /; sandbox receives a deterministic executable
# stand-in from build-sniproxy.sh and performs no network operation.
build_args=(--root "$ROOT")
if [[ -n "$PREBUILT_BINARY" ]]; then
    build_args+=(--prebuilt-binary "$PREBUILT_BINARY" --prebuilt-sha256 "$PREBUILT_SHA256")
fi
"$SCRIPT_DIR/build-sniproxy.sh" "${build_args[@]}"
binary_path="$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/v2.3.0/sniproxy)"
[[ -x "$binary_path" ]] || dohdns_die "sniproxy build did not produce executable binary"

if [[ ! -e "$generation_path" ]]; then
    temporary_generation="$(mktemp -d "$GEN_DIR/.generation.XXXXXX")"
    cp -a -- "$STAGE_DIR/." "$temporary_generation/"
    dohdns_mkdir "$temporary_generation/usr/local/libexec/sniproxy" 0755
    install -m 0755 -- "$binary_path" "$temporary_generation/usr/local/libexec/sniproxy/sniproxy"
    mv -- "$temporary_generation" "$generation_path"
fi
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown -R root:sniproxy -- "$generation_path"
    find "$generation_path" -type d -exec chmod 0750 {} +
fi

active_file="$STATE_DIR/active-generation"
previous_file="$STATE_DIR/previous-generation"
old_generation=""
if [[ -f "$active_file" ]]; then old_generation="$(tr -d '\n' <"$active_file")"; fi

generation_config_restore() {
    local selected="$1" relative
    if [[ -z "$selected" || ! -d "$GEN_DIR/$selected" ]]; then
        rm -f -- "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)" \
            "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"
        return 0
    fi
    dohdns_mkdir "$(dohdns_under_root "$ROOT" /etc/sniproxy)" 0750 || true
    dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy)" 0755 || true
    dohdns_atomic_symlink "../../var/lib/dohdns/generations/$selected/etc/sniproxy" \
        "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)" || true
    dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$selected/usr/local/libexec/sniproxy" \
        "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)" || true
    for relative in \
        etc/systemd/system/sniproxy.service \
        etc/systemd/system/dohdns-geoip-update.service \
        etc/systemd/system/dohdns-geoip-update.timer \
        etc/systemd/system/dohdns-nftables.service \
        etc/systemd/resolved.conf.d/dohdns.conf \
        etc/nftables.d/dohdns.nft \
        etc/nginx/sites-available/dohdns.conf \
        etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh; do
        if [[ -f "$GEN_DIR/$selected/$relative" ]]; then
            dohdns_copy_mode "$GEN_DIR/$selected/$relative" "$(dohdns_under_root "$ROOT" "/$relative")" 0644 || true
        fi
    done
    chmod 0755 "$(dohdns_under_root "$ROOT" /etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh)" 2>/dev/null || true
    if [[ -d "$GEN_DIR/$selected/usr/local/libexec/dohdns" ]]; then
        dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)" 0755 || true
        cp -a -- "$GEN_DIR/$selected/usr/local/libexec/dohdns/." \
            "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)/" || true
    fi
}

activation_started=0
rollback_activation() {
    local status="$1"
    ((activation_started)) || return 0
    generation_config_restore "$old_generation"
    if [[ "$ROOT" == "/" ]]; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl try-restart sniproxy >/dev/null 2>&1 || true
    fi
    printf 'installation failed; restored generation %s\n' "${old_generation:-none}" >&2
    return "$status"
}
trap 'status=$?; set +e; rollback_activation "$status"; exit "$status"' ERR
activation_started=1

# Expose selected generation through atomic relative symlinks. Relative
# targets resolve inside a sandbox as well as on the real root filesystem.
dohdns_mkdir "$(dohdns_under_root "$ROOT" /etc/sniproxy)" 0750
dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy)" 0755
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown root:sniproxy -- "$(dohdns_under_root "$ROOT" /etc/sniproxy)"
fi
dohdns_atomic_symlink "../../var/lib/dohdns/generations/$generation/etc/sniproxy" \
    "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)"
dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$generation/usr/local/libexec/sniproxy" \
    "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"
if [[ "${DOHDNS_TEST_FAIL_AFTER_ACTIVATION:-0}" == "1" ]]; then
    printf 'error: test failure after generation activation\n' >&2
    false
fi

# Install generated units/configuration and helper scripts. All paths are
# beneath caller-selected root.
for relative in \
    etc/systemd/system/sniproxy.service \
    etc/systemd/system/dohdns-geoip-update.service \
    etc/systemd/system/dohdns-geoip-update.timer \
    etc/systemd/system/dohdns-nftables.service \
    etc/systemd/resolved.conf.d/dohdns.conf \
    etc/nftables.d/dohdns.nft \
    etc/nginx/sites-available/dohdns.conf \
    etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh; do
    dohdns_copy_mode "$generation_path/$relative" "$(dohdns_under_root "$ROOT" "/$relative")" 0644
done
chmod 0755 "$(dohdns_under_root "$ROOT" /etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh)"
dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)" 0755
cp -a -- "$generation_path/usr/local/libexec/dohdns/." "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)/"
install -m 0640 -- "$generation_path/manifest.json" "$STATE_DIR/manifest.json"
dohdns_mkdir "$(dohdns_under_root "$ROOT" /etc/dohdns)" 0750
inventory_destination="$(dohdns_under_root "$ROOT" /etc/dohdns/inventory.json)"
if [[ "$INVENTORY" != "$inventory_destination" ]]; then
    install -m 0640 -- "$INVENTORY" "$inventory_destination"
fi

if [[ "$ROOT" == "/" ]]; then
    # HTTP ACME listener must be live before certificate issuance. Resolver is
    # switched away from local listeners before any remote download.
    install -d -m 0755 -- /var/www/acme /etc/nginx/sites-enabled
    ln -sfn -- /etc/nginx/sites-available/dohdns.conf /etc/nginx/sites-enabled/dohdns.conf
    nginx -t
    systemctl enable --now nginx
    systemctl restart systemd-resolved
    ln -sfn -- /run/systemd/resolve/resolv.conf /etc/resolv.conf

    "$SCRIPT_DIR/update-geoip.sh" --root /
    acme_email="$(python3 - "$INVENTORY" <<'PY'
import json
import sys
from pathlib import Path
inventory = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(inventory.get("acme", {}).get("email", ""))
PY
)"
    certbot_args=(certonly --webroot --webroot-path /var/www/acme --domain dns.pressroll.ru --non-interactive --agree-tos)
    if [[ -n "$acme_email" ]]; then certbot_args+=(--email "$acme_email"); else certbot_args+=(--register-unsafely-without-email); fi
    certbot "${certbot_args[@]}"
    "$SCRIPT_DIR/sync-cert.sh" --root /
    "$SCRIPT_DIR/apply-nftables.sh" --root / --rules /etc/nftables.d/dohdns.nft
    systemctl daemon-reload
    systemctl enable --now dohdns-nftables.service
    systemctl enable --now dohdns-geoip-update.timer
    systemctl enable --now sniproxy
fi

if [[ -n "$old_generation" && "$old_generation" != "$generation" && -d "$GEN_DIR/$old_generation" ]]; then
    printf '%s\n' "$old_generation" >"$previous_file"
fi
printf '%s\n' "$generation" >"$active_file"
activation_started=0
trap - ERR

printf 'installed generation %s under %s\n' "$generation" "$ROOT"
