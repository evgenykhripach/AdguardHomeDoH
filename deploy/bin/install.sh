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
BUILD_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/build)"
BUILD_OUTPUT_DIR="$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/v2.3.0)"
ACME_DIR="$(dohdns_under_root "$ROOT" /var/www/acme)"
TLS_DIR="$(dohdns_under_root "$ROOT" /etc/sniproxy/tls)"
GEOIP_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/geoip)"
HELPER_DIR="$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)"
active_file="$STATE_DIR/active-generation"
previous_file="$STATE_DIR/previous-generation"
inventory_destination="$(dohdns_under_root "$ROOT" /etc/dohdns/inventory.json)"
STAGE_DIR=""
ROLLBACK_DIR=""
generation_path=""
generation_created=0
activation_started=0

old_generation=""
if [[ -L "$STATE_DIR" || -L "$GEN_DIR" || -L "$active_file" || -L "$previous_file" ]]; then
    dohdns_die "refusing symlinked generation state path"
fi
if [[ -f "$active_file" ]]; then
    candidate_active="$(tr -d '\n' <"$active_file")"
    dohdns_require_generation_name "$candidate_active"
    [[ -d "$GEN_DIR/$candidate_active" && ! -L "$GEN_DIR/$candidate_active" ]] || \
        dohdns_die "active generation directory is missing or unsafe: $candidate_active"
    old_generation="$candidate_active"
fi

DOHDNS_PREVIOUS_STATE_DIR=0
DOHDNS_PREVIOUS_GEN_DIR=0
DOHDNS_PREVIOUS_BUILD_DIR=0
DOHDNS_PREVIOUS_BUILD_OUTPUT=0
DOHDNS_PREVIOUS_ACME=0
DOHDNS_PREVIOUS_TLS=0
DOHDNS_PREVIOUS_GEOIP=0
[[ -d "$STATE_DIR" ]] && DOHDNS_PREVIOUS_STATE_DIR=1
[[ -d "$GEN_DIR" ]] && DOHDNS_PREVIOUS_GEN_DIR=1
[[ -d "$BUILD_DIR" ]] && DOHDNS_PREVIOUS_BUILD_DIR=1
[[ -e "$BUILD_OUTPUT_DIR" || -L "$BUILD_OUTPUT_DIR" ]] && DOHDNS_PREVIOUS_BUILD_OUTPUT=1
[[ -e "$ACME_DIR" || -L "$ACME_DIR" ]] && DOHDNS_PREVIOUS_ACME=1
[[ -e "$TLS_DIR" || -L "$TLS_DIR" ]] && DOHDNS_PREVIOUS_TLS=1
[[ -e "$GEOIP_DIR" || -L "$GEOIP_DIR" ]] && DOHDNS_PREVIOUS_GEOIP=1

systemd_unit_exists() {
    local unit="$1"
    systemctl list-unit-files --all --no-legend "$unit" 2>/dev/null | \
        awk -v expected="$unit" '$1 == expected { found=1 } END { exit found ? 0 : 1 }'
}

assert_clean_first_install() {
    [[ -n "$old_generation" ]] && return 0
    local relative path unit
    for relative in \
        var/lib/dohdns \
        etc/dohdns/inventory.json \
        etc/sniproxy/current \
        etc/sniproxy/tls \
        usr/local/libexec/sniproxy/current \
        usr/local/libexec/sniproxy/v2.3.0 \
        etc/systemd/system/sniproxy.service \
        etc/systemd/system/dohdns-geoip-update.service \
        etc/systemd/system/dohdns-geoip-update.timer \
        etc/systemd/system/dohdns-nftables.service \
        etc/systemd/resolved.conf.d/dohdns.conf \
        etc/nftables.d/dohdns.nft \
        etc/nginx/sites-available/dohdns.conf \
        etc/nginx/sites-enabled/dohdns.conf \
        var/www/acme \
        etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh \
        etc/letsencrypt/live/dns.pressroll.ru \
        etc/letsencrypt/archive/dns.pressroll.ru \
        etc/letsencrypt/renewal/dns.pressroll.ru.conf \
        usr/local/libexec/dohdns; do
        path="$(dohdns_under_root "$ROOT" "/$relative")"
        if [[ -e "$path" || -L "$path" ]]; then
            dohdns_die "refusing first install over existing generation-owned path: $path"
        fi
    done
    if [[ "$ROOT" == "/" ]]; then
        command -v systemctl >/dev/null 2>&1 || dohdns_die "systemctl is required for first-install preflight"
        for unit in \
            sniproxy.service \
            dohdns-geoip-update.service \
            dohdns-geoip-update.timer \
            dohdns-nftables.service; do
            if systemd_unit_exists "$unit"; then
                dohdns_die "refusing first install over existing systemd unit: $unit"
            fi
        done
        if command -v nft >/dev/null 2>&1 && nft list table inet dohdns >/dev/null 2>&1; then
            dohdns_die "refusing first install over existing nft table inet dohdns"
        fi
    fi
}

assert_safe_update_state() {
    [[ -n "$old_generation" ]] || return 0
    local relative path
    # These are generation-owned regular files. Refuse tampered symlinks before
    # package, render, build, or activation work instead of following or silently
    # replacing an attacker/user-controlled target.
    for relative in \
        etc/dohdns/inventory.json \
        etc/systemd/system/sniproxy.service \
        etc/systemd/system/dohdns-geoip-update.service \
        etc/systemd/system/dohdns-geoip-update.timer \
        etc/systemd/system/dohdns-nftables.service \
        etc/systemd/resolved.conf.d/dohdns.conf \
        etc/nftables.d/dohdns.nft \
        etc/nginx/sites-available/dohdns.conf \
        etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh; do
        path="$(dohdns_under_root "$ROOT" "/$relative")"
        if [[ -L "$path" ]]; then
            dohdns_die "refusing update with symlinked generation-owned path: $path"
        fi
    done
}

DOHDNS_PREVIOUS_NGINX_ACTIVE=0
DOHDNS_PREVIOUS_NGINX_ENABLED=0
DOHDNS_PREVIOUS_RESOLVED_ACTIVE=0
DOHDNS_RUNTIME_SNAPSHOT_READY=0
capture_runtime_preflight() {
    [[ "$ROOT" == "/" ]] || return 0
    command -v systemctl >/dev/null 2>&1 || dohdns_die "systemctl is required for runtime preflight"
    if systemctl is-active --quiet nginx; then DOHDNS_PREVIOUS_NGINX_ACTIVE=1; fi
    if systemctl is-enabled --quiet nginx; then DOHDNS_PREVIOUS_NGINX_ENABLED=1; fi
    if systemctl is-active --quiet systemd-resolved; then DOHDNS_PREVIOUS_RESOLVED_ACTIVE=1; fi
    DOHDNS_RUNTIME_SNAPSHOT_READY=1
}

restore_runtime_preflight() {
    [[ "$ROOT" == "/" && "$DOHDNS_RUNTIME_SNAPSHOT_READY" == "1" ]] || return 0
    local restore_status=0
    if ((DOHDNS_PREVIOUS_NGINX_ENABLED)); then
        if ! systemctl enable nginx >/dev/null 2>&1; then restore_status=1; fi
    elif systemd_unit_exists nginx.service; then
        if ! systemctl disable nginx >/dev/null 2>&1; then restore_status=1; fi
    fi
    if ((DOHDNS_PREVIOUS_NGINX_ACTIVE)); then
        if ! systemctl is-active --quiet nginx && ! systemctl start nginx >/dev/null 2>&1; then
            restore_status=1
        fi
    elif systemd_unit_exists nginx.service; then
        if ! systemctl stop nginx >/dev/null 2>&1; then restore_status=1; fi
    fi
    if ((DOHDNS_PREVIOUS_RESOLVED_ACTIVE)); then
        if ! systemctl restart systemd-resolved >/dev/null 2>&1; then restore_status=1; fi
    elif systemd_unit_exists systemd-resolved.service; then
        if ! systemctl stop systemd-resolved >/dev/null 2>&1; then restore_status=1; fi
    fi
    return "$restore_status"
}

cleanup_created_artifacts() {
    [[ -z "$old_generation" ]] || return 0
    local cleanup_status=0
    if (( !DOHDNS_PREVIOUS_ACME )) && [[ -e "$ACME_DIR" || -L "$ACME_DIR" ]]; then
        if ! rm -rf -- "$ACME_DIR"; then cleanup_status=1; fi
    fi
    if (( !DOHDNS_PREVIOUS_TLS )) && [[ -e "$TLS_DIR" || -L "$TLS_DIR" ]]; then
        if ! rm -rf -- "$TLS_DIR"; then cleanup_status=1; fi
    fi
    if (( !DOHDNS_PREVIOUS_GEOIP )) && [[ -e "$GEOIP_DIR" || -L "$GEOIP_DIR" ]]; then
        if ! rm -rf -- "$GEOIP_DIR"; then cleanup_status=1; fi
    fi
    if (( !DOHDNS_PREVIOUS_BUILD_OUTPUT )) && [[ -e "$BUILD_OUTPUT_DIR" || -L "$BUILD_OUTPUT_DIR" ]]; then
        if ! rm -rf -- "$BUILD_OUTPUT_DIR"; then cleanup_status=1; fi
    fi
    if (( !DOHDNS_PREVIOUS_BUILD_DIR )) && [[ -e "$BUILD_DIR" || -L "$BUILD_DIR" ]]; then
        if ! rm -rf -- "$BUILD_DIR"; then cleanup_status=1; fi
    fi
    if [[ -e "$HELPER_DIR" || -L "$HELPER_DIR" ]]; then
        if ! rm -rf -- "$HELPER_DIR"; then cleanup_status=1; fi
    fi
    if [[ "$generation_created" == "1" && -n "$generation_path" && -e "$generation_path" ]]; then
        if ! rm -rf -- "$generation_path"; then cleanup_status=1; fi
    fi
    if (( !DOHDNS_PREVIOUS_GEN_DIR )) && [[ -d "$GEN_DIR" ]]; then
        rmdir -- "$GEN_DIR" 2>/dev/null || true
    fi
    if (( !DOHDNS_PREVIOUS_STATE_DIR )) && [[ -d "$STATE_DIR" ]]; then
        if ! rm -rf -- "$STATE_DIR"; then cleanup_status=1; fi
    fi
    return "$cleanup_status"
}

assert_clean_first_install
assert_safe_update_state
capture_runtime_preflight

dohdns_mkdir "$STATE_DIR" 0750
dohdns_mkdir "$GEN_DIR" 0750
ROLLBACK_DIR="$(mktemp -d "$STATE_DIR/.rollback.XXXXXX")"
cleanup_stage() {
    [[ -z "$STAGE_DIR" ]] || rm -rf -- "$STAGE_DIR"
    [[ -z "$ROLLBACK_DIR" ]] || rm -rf -- "$ROLLBACK_DIR"
    if [[ -n "${DOHDNS_LOCK_DIR:-}" ]]; then
        rmdir -- "$DOHDNS_LOCK_DIR" 2>/dev/null || true
    fi
}
trap cleanup_stage EXIT

early_failure_cleanup() {
    local status="$1" restore_status=0
    if ! restore_runtime_preflight; then restore_status=1; fi
    if ! cleanup_created_artifacts; then restore_status=1; fi
    if ((restore_status)); then
        printf 'error: installation pre-activation restore failed; operator recovery may be required\n' >&2
        return 1
    fi
    return "$status"
}
trap 'status=$?; set +e; early_failure_cleanup "$status"; exit "$status"' ERR

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
dohdns_require_generation_name "$base_generation"
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
    generation_created=1
fi
# Generations created by older bundle revisions did not carry the inventory;
# make the policy generation-owned before exposing it through /etc.
if [[ ! -f "$generation_path/etc/dohdns/inventory.json" ]]; then
    dohdns_copy_mode "$STAGE_DIR/etc/dohdns/inventory.json" \
        "$generation_path/etc/dohdns/inventory.json" 0640
fi
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown -R root:sniproxy -- "$generation_path"
    find "$generation_path" -type d -exec chmod 0750 {} +
fi

DOHDNS_PREVIOUS_INVENTORY_KIND=absent
DOHDNS_PREVIOUS_INVENTORY_TARGET=
DOHDNS_PREVIOUS_INVENTORY_BACKUP=
DOHDNS_PREVIOUS_RESOLV_KIND=absent
DOHDNS_PREVIOUS_RESOLV_TARGET=
DOHDNS_PREVIOUS_RESOLV_BACKUP=
DOHDNS_PREVIOUS_NGINX_SITE_KIND=absent
DOHDNS_PREVIOUS_NGINX_SITE_TARGET=
DOHDNS_PREVIOUS_NGINX_SITE_BACKUP=
DOHDNS_PREVIOUS_NGINX_LINK_KIND=absent
DOHDNS_PREVIOUS_NGINX_LINK_TARGET=
DOHDNS_PREVIOUS_NGINX_LINK_BACKUP=

capture_previous_inventory() {
    if [[ -z "$ROLLBACK_DIR" ]]; then
        ROLLBACK_DIR="$(mktemp -d "$STATE_DIR/.rollback.XXXXXX")"
    fi
    if [[ -L "$inventory_destination" ]]; then
        DOHDNS_PREVIOUS_INVENTORY_KIND=symlink
        DOHDNS_PREVIOUS_INVENTORY_TARGET="$(readlink "$inventory_destination")"
    elif [[ -f "$inventory_destination" ]]; then
        DOHDNS_PREVIOUS_INVENTORY_KIND=file
        DOHDNS_PREVIOUS_INVENTORY_BACKUP="$ROLLBACK_DIR/inventory.json"
        cp -a -- "$inventory_destination" "$DOHDNS_PREVIOUS_INVENTORY_BACKUP"
    elif [[ -e "$inventory_destination" ]]; then
        dohdns_die "refusing to replace non-file inventory path: $inventory_destination"
    fi
}

capture_previous_host_state() {
    local path
    path=/etc/resolv.conf
    if [[ -L "$path" ]]; then
        DOHDNS_PREVIOUS_RESOLV_KIND=symlink
        DOHDNS_PREVIOUS_RESOLV_TARGET="$(readlink "$path")"
    elif [[ -f "$path" ]]; then
        DOHDNS_PREVIOUS_RESOLV_KIND=file
        DOHDNS_PREVIOUS_RESOLV_BACKUP="$ROLLBACK_DIR/resolv.conf"
        cp -a -- "$path" "$DOHDNS_PREVIOUS_RESOLV_BACKUP"
    elif [[ -e "$path" ]]; then
        dohdns_die "refusing to replace non-file resolver path: $path"
    fi

    path=/etc/nginx/sites-available/dohdns.conf
    if [[ -L "$path" ]]; then
        DOHDNS_PREVIOUS_NGINX_SITE_KIND=symlink
        DOHDNS_PREVIOUS_NGINX_SITE_TARGET="$(readlink "$path")"
    elif [[ -f "$path" ]]; then
        DOHDNS_PREVIOUS_NGINX_SITE_KIND=file
        DOHDNS_PREVIOUS_NGINX_SITE_BACKUP="$ROLLBACK_DIR/nginx-site.conf"
        cp -a -- "$path" "$DOHDNS_PREVIOUS_NGINX_SITE_BACKUP"
    elif [[ -e "$path" ]]; then
        dohdns_die "refusing to replace non-file nginx site: $path"
    fi

    path=/etc/nginx/sites-enabled/dohdns.conf
    if [[ -L "$path" ]]; then
        DOHDNS_PREVIOUS_NGINX_LINK_KIND=symlink
        DOHDNS_PREVIOUS_NGINX_LINK_TARGET="$(readlink "$path")"
    elif [[ -f "$path" ]]; then
        DOHDNS_PREVIOUS_NGINX_LINK_KIND=file
        DOHDNS_PREVIOUS_NGINX_LINK_BACKUP="$ROLLBACK_DIR/nginx-site-enabled.conf"
        cp -a -- "$path" "$DOHDNS_PREVIOUS_NGINX_LINK_BACKUP"
    elif [[ -e "$path" ]]; then
        dohdns_die "refusing to replace non-file nginx site link: $path"
    fi
}

restore_previous_inventory() {
    local restore_status=0
    dohdns_mkdir "$(dirname -- "$inventory_destination")" 0750 || restore_status=1
    case "$DOHDNS_PREVIOUS_INVENTORY_KIND" in
        symlink)
            rm -f -- "$inventory_destination" || restore_status=1
            ln -s -- "$DOHDNS_PREVIOUS_INVENTORY_TARGET" "$inventory_destination" || restore_status=1
            ;;
        file)
            rm -f -- "$inventory_destination" || restore_status=1
            cp -a -- "$DOHDNS_PREVIOUS_INVENTORY_BACKUP" "$inventory_destination" || restore_status=1
            ;;
        absent)
            rm -f -- "$inventory_destination" || restore_status=1
            ;;
        *)
            restore_status=1
            ;;
    esac
    return "$restore_status"
}

restore_previous_resolver() {
    local path=/etc/resolv.conf restore_status=0
    case "$DOHDNS_PREVIOUS_RESOLV_KIND" in
        symlink)
            rm -f -- "$path" || restore_status=1
            ln -s -- "$DOHDNS_PREVIOUS_RESOLV_TARGET" "$path" || restore_status=1
            ;;
        file)
            rm -f -- "$path" || restore_status=1
            cp -a -- "$DOHDNS_PREVIOUS_RESOLV_BACKUP" "$path" || restore_status=1
            ;;
        absent)
            rm -f -- "$path" || restore_status=1
            ;;
        *)
            restore_status=1
            ;;
    esac
    return "$restore_status"
}

restore_previous_nginx_site() {
    local path=/etc/nginx/sites-available/dohdns.conf restore_status=0
    install -d -m 0755 -- "$(dirname -- "$path")" || restore_status=1
    case "$DOHDNS_PREVIOUS_NGINX_SITE_KIND" in
        symlink)
            rm -f -- "$path" || restore_status=1
            ln -s -- "$DOHDNS_PREVIOUS_NGINX_SITE_TARGET" "$path" || restore_status=1
            ;;
        file)
            rm -f -- "$path" || restore_status=1
            cp -a -- "$DOHDNS_PREVIOUS_NGINX_SITE_BACKUP" "$path" || restore_status=1
            ;;
        absent)
            rm -f -- "$path" || restore_status=1
            ;;
        *)
            restore_status=1
            ;;
    esac
    return "$restore_status"
}

restore_previous_nginx_link() {
    local path=/etc/nginx/sites-enabled/dohdns.conf restore_status=0
    install -d -m 0755 -- "$(dirname -- "$path")" || restore_status=1
    case "$DOHDNS_PREVIOUS_NGINX_LINK_KIND" in
        symlink)
            rm -f -- "$path" || restore_status=1
            ln -s -- "$DOHDNS_PREVIOUS_NGINX_LINK_TARGET" "$path" || restore_status=1
            ;;
        file)
            rm -f -- "$path" || restore_status=1
            cp -a -- "$DOHDNS_PREVIOUS_NGINX_LINK_BACKUP" "$path" || restore_status=1
            ;;
        absent)
            rm -f -- "$path" || restore_status=1
            ;;
        *)
            restore_status=1
            ;;
    esac
    return "$restore_status"
}

capture_previous_inventory
if [[ "$ROOT" == "/" ]]; then
    capture_previous_host_state
fi

generation_config_restore() {
    local selected="$1" relative restore_status=0
    if [[ -z "$selected" || ! -d "$GEN_DIR/$selected" ]]; then
        for relative in \
            etc/sniproxy/current \
            usr/local/libexec/sniproxy/current \
            etc/systemd/system/sniproxy.service \
            etc/systemd/system/dohdns-geoip-update.service \
            etc/systemd/system/dohdns-geoip-update.timer \
            etc/systemd/system/dohdns-nftables.service \
            etc/systemd/resolved.conf.d/dohdns.conf \
            etc/nftables.d/dohdns.nft \
            etc/nginx/sites-available/dohdns.conf \
            etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh \
            etc/dohdns/inventory.json; do
            if ! rm -f -- "$(dohdns_under_root "$ROOT" "/$relative")"; then
                restore_status=1
            fi
        done
        return "$restore_status"
    fi
    if ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /etc/sniproxy)" 0750; then restore_status=1; fi
    if ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy)" 0755; then restore_status=1; fi
    if ! dohdns_atomic_symlink "../../var/lib/dohdns/generations/$selected/etc/sniproxy" \
        "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)"; then restore_status=1; fi
    if ! dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$selected/usr/local/libexec/sniproxy" \
        "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"; then restore_status=1; fi
    for relative in \
        etc/systemd/system/sniproxy.service \
        etc/systemd/system/dohdns-geoip-update.service \
        etc/systemd/system/dohdns-geoip-update.timer \
        etc/systemd/system/dohdns-nftables.service \
        etc/systemd/resolved.conf.d/dohdns.conf \
        etc/nftables.d/dohdns.nft \
        etc/nginx/sites-available/dohdns.conf \
        etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh; do
        if [[ ! -f "$GEN_DIR/$selected/$relative" ]] || \
            ! dohdns_copy_mode "$GEN_DIR/$selected/$relative" "$(dohdns_under_root "$ROOT" "/$relative")" 0644; then
            restore_status=1
        fi
    done
    if ! chmod 0755 "$(dohdns_under_root "$ROOT" /etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh)"; then
        restore_status=1
    fi
    if [[ ! -f "$GEN_DIR/$selected/etc/dohdns/inventory.json" ]] || \
        ! dohdns_copy_mode "$GEN_DIR/$selected/etc/dohdns/inventory.json" "$inventory_destination" 0640; then
        restore_status=1
    fi
    if [[ ! -d "$GEN_DIR/$selected/usr/local/libexec/dohdns" ]]; then
        restore_status=1
    elif ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)" 0755 || \
        ! cp -a -- "$GEN_DIR/$selected/usr/local/libexec/dohdns/." \
            "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)/"; then
        restore_status=1
    fi
    return "$restore_status"
}

activation_started=0
rollback_activation() {
    local status="$1" restore_status=0
    ((activation_started)) || return 0
    if ! generation_config_restore "$old_generation"; then restore_status=1; fi
    if [[ -z "$old_generation" ]]; then
        if ! restore_previous_inventory; then restore_status=1; fi
    fi
    if [[ "$ROOT" == "/" ]]; then
        if [[ -z "$old_generation" ]]; then
            if systemctl is-active --quiet dohdns-nftables.service || \
                systemctl is-enabled --quiet dohdns-nftables.service; then
                if ! systemctl stop dohdns-nftables.service >/dev/null 2>&1; then restore_status=1; fi
                if ! systemctl disable dohdns-nftables.service >/dev/null 2>&1; then restore_status=1; fi
            fi
            if systemctl is-active --quiet dohdns-geoip-update.timer || \
                systemctl is-enabled --quiet dohdns-geoip-update.timer; then
                if ! systemctl stop dohdns-geoip-update.timer >/dev/null 2>&1; then restore_status=1; fi
                if ! systemctl disable dohdns-geoip-update.timer >/dev/null 2>&1; then restore_status=1; fi
            fi
            if systemctl is-active --quiet sniproxy || systemctl is-enabled --quiet sniproxy; then
                if ! systemctl stop sniproxy >/dev/null 2>&1; then restore_status=1; fi
                if ! systemctl disable sniproxy >/dev/null 2>&1; then restore_status=1; fi
            fi
            if ! command -v nft >/dev/null 2>&1; then
                restore_status=1
            elif nft list table inet dohdns >/dev/null 2>&1; then
                if ! nft delete table inet dohdns >/dev/null 2>&1; then restore_status=1; fi
            fi
            if ! restore_previous_nginx_site; then restore_status=1; fi
        else
            # The old generation's nft include was restored above; apply it as
            # one isolated transaction before restarting dependent services.
            if ! "$SCRIPT_DIR/apply-nftables.sh" --root / --rules /etc/nftables.d/dohdns.nft; then
                restore_status=1
            fi
        fi
        if ! restore_previous_resolver; then restore_status=1; fi
        if ! restore_previous_nginx_link; then restore_status=1; fi
        if ! nginx -t >/dev/null 2>&1; then restore_status=1; fi
        if ((DOHDNS_PREVIOUS_NGINX_ACTIVE)) && ! systemctl reload nginx >/dev/null 2>&1; then
            restore_status=1
        fi
        if ! systemctl daemon-reload >/dev/null 2>&1; then restore_status=1; fi
        if [[ -n "$old_generation" ]] && ! systemctl try-restart sniproxy >/dev/null 2>&1; then
            restore_status=1
        fi
        if ! restore_runtime_preflight; then restore_status=1; fi
    fi
    if ! cleanup_created_artifacts; then restore_status=1; fi
    if ((restore_status)); then
        printf 'error: installation restore failed; original generation may need operator recovery\n' >&2
        return 1
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
install -m 0640 -- "$generation_path/etc/dohdns/inventory.json" "$inventory_destination"

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
