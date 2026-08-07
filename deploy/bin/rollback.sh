#!/usr/bin/env bash
set -euo pipefail

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
[[ -f "$active_file" ]] || { printf 'rollback: no active generation\n'; exit 0; }
active="$(tr -d '\n' <"$active_file")"
candidate=""
if [[ -f "$previous_file" ]]; then candidate="$(tr -d '\n' <"$previous_file")"; fi
if [[ -z "$candidate" || "$candidate" == "$active" || ! -d "$GEN_DIR/$candidate" ]]; then
    printf 'rollback: no previous generation; active remains %s\n' "$active"
    exit 0
fi

printf '%s\n' "$candidate" >"$active_file"
dohdns_atomic_symlink "../../var/lib/dohdns/generations/$candidate/etc/sniproxy" \
    "$(dohdns_under_root "$ROOT" /etc/sniproxy/current)"
dohdns_atomic_symlink "../../../../var/lib/dohdns/generations/$candidate/usr/local/libexec/sniproxy" \
    "$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/current)"
# Restore all generation-owned configuration alongside the binary so rollback
# cannot leave a previous executable paired with a newer policy.
for relative in \
    etc/systemd/system/sniproxy.service \
    etc/systemd/system/dohdns-geoip-update.service \
    etc/systemd/system/dohdns-geoip-update.timer \
    etc/systemd/system/dohdns-nftables.service \
    etc/systemd/resolved.conf.d/dohdns.conf \
    etc/nftables.d/dohdns.nft \
    etc/nginx/sites-available/dohdns.conf \
    etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh; do
    dohdns_copy_mode "$GEN_DIR/$candidate/$relative" "$(dohdns_under_root "$ROOT" "/$relative")" 0644
done
chmod 0755 "$(dohdns_under_root "$ROOT" /etc/letsencrypt/renewal-hooks/deploy/dohdns-sync-cert.sh)"
if [[ -d "$GEN_DIR/$candidate/usr/local/libexec/dohdns" ]]; then
    dohdns_mkdir "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)" 0755
    cp -a -- "$GEN_DIR/$candidate/usr/local/libexec/dohdns/." "$(dohdns_under_root "$ROOT" /usr/local/libexec/dohdns)/"
fi
if [[ -f "$GEN_DIR/$candidate/manifest.json" ]]; then
    install -m 0640 -- "$GEN_DIR/$candidate/manifest.json" "$STATE_DIR/manifest.json"
fi
printf '%s\n' "" >"$previous_file"

if [[ "$ROOT" == "/" ]]; then
    "$SCRIPT_DIR/apply-nftables.sh" --root / --rules /etc/nftables.d/dohdns.nft
    nginx -t && systemctl reload nginx
    systemctl restart systemd-resolved
    systemctl daemon-reload
    systemctl restart sniproxy
fi
printf 'rolled back to generation %s\n' "$candidate"
