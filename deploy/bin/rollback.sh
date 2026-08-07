#!/usr/bin/env bash
set -eEuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --help|-h)
            printf 'usage: %s [--root PATH]\n' "$0"
            exit 0
            ;;
        *) dohdns_die "unknown argument: $1" ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
dohdns_require_root_for_host "$ROOT"
STATE_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns)"
GEN_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/generations)"
LOCK_PATH="$(dohdns_under_root "$ROOT" /var/lock/dohdns-install.lock)"
dohdns_lock_acquire "$LOCK_PATH"
active_file="$STATE_DIR/active-generation"
previous_file="$STATE_DIR/previous-generation"
inventory_file="$(dohdns_under_root "$ROOT" /etc/dohdns/inventory.json)"
if [[ -L "$STATE_DIR" || -L "$GEN_DIR" || -L "$active_file" || -L "$previous_file" ]]; then
    dohdns_die "refusing symlinked generation state path"
fi
[[ -f "$active_file" ]] || { printf 'rollback: no active generation\n'; exit 0; }
active="$(tr -d '\n' <"$active_file")"
dohdns_require_generation_name "$active"
[[ -d "$GEN_DIR/$active" && ! -L "$GEN_DIR/$active" ]] || \
    dohdns_die "active generation directory is missing or unsafe: $active"
candidate=""
if [[ -f "$previous_file" ]]; then candidate="$(tr -d '\n' <"$previous_file")"; fi
if [[ -n "$candidate" ]]; then dohdns_require_generation_name "$candidate"; fi
if [[ -z "$candidate" || "$candidate" == "$active" || ! -d "$GEN_DIR/$candidate" || -L "$GEN_DIR/$candidate" ]]; then
    printf 'rollback: no previous generation; active remains %s\n' "$active"
    exit 0
fi

restore_generation() {
    local selected="$1" relative restore_status=0
    if [[ -z "$selected" || ! -d "$GEN_DIR/$selected" ]]; then
        if ! rm -f -- "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)" \
            "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"; then
            restore_status=1
        fi
        return "$restore_status"
    fi
    if ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /etc/sniproxy)" 0750; then restore_status=1; fi
    if ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy)" 0755; then restore_status=1; fi
    if ! dohdns_atomic_symlink "../../var/lib/dohdns/generations/$selected/etc/sniproxy" \
        "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)"; then restore_status=1; fi
    if ! dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$selected/usr/local/libexec/sniproxy" \
        "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"; then restore_status=1; fi
    # Restore all generation-owned configuration alongside the binary so
    # rollback cannot pair a previous executable with newer policy.
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
    if ! dohdns_copy_mode "$GEN_DIR/$selected/etc/dohdns/inventory.json" "$inventory_file" 0640; then
        restore_status=1
    fi
    if [[ ! -d "$GEN_DIR/$selected/usr/local/libexec/dohdns" ]]; then
        restore_status=1
    elif ! dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)" 0755 || \
        ! cp -a -- "$GEN_DIR/$selected/usr/local/libexec/dohdns/." "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)/"; then
        restore_status=1
    fi
    if [[ ! -f "$GEN_DIR/$selected/manifest.json" ]] || \
        ! install -m 0640 -- "$GEN_DIR/$selected/manifest.json" "$STATE_DIR/manifest.json"; then
        restore_status=1
    fi
    return "$restore_status"
}

original_active="$active"
original_previous_exists=0
original_previous=
if [[ -f "$previous_file" ]]; then
    original_previous_exists=1
    original_previous="$(cat -- "$previous_file")"
fi

restore_original() {
    local status="$1" restore_status=0
    if ! restore_generation "$original_active"; then restore_status=1; fi
    if ((original_previous_exists)); then
        if ! printf '%s\n' "$original_previous" >"$previous_file"; then restore_status=1; fi
    elif ! rm -f -- "$previous_file"; then
        restore_status=1
    fi
    if ! printf '%s\n' "$original_active" >"$active_file"; then restore_status=1; fi
    if [[ "$ROOT" == "/" ]]; then
        if ! "$SCRIPT_DIR/apply-nftables.sh" --root / --rules /etc/nftables.d/dohdns.nft; then restore_status=1; fi
        if ! nginx -t || ! systemctl reload nginx; then restore_status=1; fi
        if ! systemctl restart systemd-resolved; then restore_status=1; fi
        if ! systemctl daemon-reload; then restore_status=1; fi
        if ! systemctl try-restart sniproxy; then restore_status=1; fi
    fi
    if ((restore_status)); then
        printf 'error: rollback restore failed; original generation may need operator recovery\n' >&2
        return 1
    fi
    printf 'rollback failure restored generation %s\n' "$original_active" >&2
    return "$status"
}

rollback_started=1
trap 'status=$?; set +e; restore_original "$status"; exit "$status"' ERR
dohdns_atomic_symlink "../../var/lib/dohdns/generations/$candidate/etc/sniproxy" \
    "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)"
dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$candidate/usr/local/libexec/sniproxy" \
    "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"
if [[ "${DOHDNS_TEST_FAIL_ROLLBACK_AFTER_ACTIVATION:-0}" == "1" ]]; then
    printf 'error: test failure after rollback activation\n' >&2
    false
fi
restore_generation "$candidate"

if [[ "$ROOT" == "/" ]]; then
    "$SCRIPT_DIR/apply-nftables.sh" --root / --rules /etc/nftables.d/dohdns.nft
    nginx -t && systemctl reload nginx
    systemctl restart systemd-resolved
    systemctl daemon-reload
    systemctl restart sniproxy
fi

# Commit state only after every pointer, config, firewall, and service step
# succeeds. A failure before this point leaves original active/previous files.
printf '%s\n' "$candidate" >"$active_file"
printf '%s\n' "" >"$previous_file"
rollback_started=0
trap - ERR
printf 'rolled back to generation %s\n' "$candidate"
