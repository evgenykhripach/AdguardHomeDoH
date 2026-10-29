#!/usr/bin/env bash
# Shared validation, filesystem, logging, and preflight helpers.

set -euo pipefail

adguardhome_doh_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

adguardhome_doh_require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || adguardhome_doh_die "run as root (or use --root for dry-run tests)"
}

adguardhome_doh_require_ubuntu() {
    local os_release="${1:-/etc/os-release}" version major minor
    [[ -r "$os_release" ]] || adguardhome_doh_die "Ubuntu 24.04 or newer is required"
    # shellcheck disable=SC1090
    . "$os_release"
    [[ "${ID:-}" == ubuntu ]] || adguardhome_doh_die "Ubuntu 24.04 or newer is required"
    version="${VERSION_ID:-}"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)$ ]] || adguardhome_doh_die "Ubuntu 24.04 or newer is required"
    major="${BASH_REMATCH[1]#0}"; minor="${BASH_REMATCH[2]#0}"
    [[ -n "$major" ]] || major=0
    [[ -n "$minor" ]] || minor=0
    (( major > 24 || (major == 24 && minor >= 4) )) || \
        adguardhome_doh_die "Ubuntu 24.04 or newer is required"
}

adguardhome_doh_required_packages() {
    printf '%s\n' \
        ca-certificates curl nginx libnginx-mod-stream certbot openssl \
        apache2-utils tar gzip python3 python3-yaml
}

adguardhome_doh_missing_packages() {
    local package status
    for package in "$@"; do
        status=
        if ! status="$(LC_ALL=C dpkg-query --show \
            --showformat='${db:Status-Abbrev}' "$package" 2>/dev/null)" || \
            [[ "$status" != "ii " ]]; then
            printf '%s\n' "$package"
        fi
    done
}

adguardhome_doh_ensure_nginx_stream_include() {
    local nginx_conf="${1:-/etc/nginx/nginx.conf}" include_line='include /etc/nginx/stream.d/*.conf;' rendered
    [[ -f "$nginx_conf" ]] || adguardhome_doh_die "nginx.conf is missing: $nginx_conf"
    rendered="$(mktemp)"
    if ! awk -v include_line="$include_line" '
        /^[[:space:]]*include[[:space:]]+\/etc\/nginx\/stream[.]d\/[*][.]conf;[[:space:]]*$/ { next }
        !inserted && /^[[:space:]]*http[[:space:]]*\{/ { print include_line; inserted = 1 }
        { print }
        END { if (!inserted) exit 42 }
    ' "$nginx_conf" > "$rendered"; then
        rm -f -- "$rendered"
        adguardhome_doh_die "nginx.conf has no top-level http block"
    fi
    cat "$rendered" > "$nginx_conf"
    rm -f -- "$rendered"
}

adguardhome_doh_ensure_nginx_worker_limits() {
    # One DoH connection occupies a stream slot, an internal TLS slot and an
    # upstream slot at the same time, and the SNI listener carries the whole
    # HTTPS traffic of every routed service on top of that.  Ubuntu's default
    # of 768 connections per worker is reached long before the host is busy,
    # and once it is, nginx stops accepting *everything*: DNS, the panel and
    # SNI forwarding all fail together until connections drain.
    #
    # This is a capacity improvement, not an activation requirement: an
    # unfamiliar nginx.conf is left exactly as it is and reported, never
    # half-edited, and never a reason to fail an update.
    local nginx_conf="${1:-/etc/nginx/nginx.conf}"
    local connections="${2:-8192}" nofile="${3:-65535}" rendered has_rlimit
    [[ -f "$nginx_conf" ]] || {
        printf 'warning: nginx.conf is missing, worker limits unchanged: %s\n' "$nginx_conf" >&2
        return 1
    }
    [[ "$connections" =~ ^[1-9][0-9]*$ ]] || adguardhome_doh_die "invalid worker_connections: $connections"
    [[ "$nofile" =~ ^[1-9][0-9]*$ ]] || adguardhome_doh_die "invalid worker_rlimit_nofile: $nofile"
    has_rlimit=0
    grep -qE '^[[:space:]]*worker_rlimit_nofile[[:space:]]' "$nginx_conf" && has_rlimit=1
    rendered="$(mktemp)"
    if ! awk -v connections="$connections" -v nofile="$nofile" -v has_rlimit="$has_rlimit" '
        /^[[:space:]]*worker_rlimit_nofile[[:space:]]/ {
            print "worker_rlimit_nofile " nofile ";"; rlimit_done = 1; next
        }
        !events_seen && /^[[:space:]]*events[[:space:]]*\{/ && /\}/ {
            line = $0
            if (line ~ /worker_connections[[:space:]]+[0-9]+;/) {
                sub(/worker_connections[[:space:]]+[0-9]+;/, "worker_connections " connections ";", line)
            } else {
                sub(/\}[[:space:]]*$/, "worker_connections " connections "; }", line)
            }
            if (!has_rlimit && !rlimit_done) { print "worker_rlimit_nofile " nofile ";"; rlimit_done = 1 }
            print line; events_seen = 1; connections_done = 1; next
        }
        !events_seen && /^[[:space:]]*events[[:space:]]*\{/ {
            if (!has_rlimit && !rlimit_done) { print "worker_rlimit_nofile " nofile ";"; rlimit_done = 1 }
            print; events_seen = 1; in_events = 1; next
        }
        in_events && /^[[:space:]]*worker_connections[[:space:]]/ {
            print "\tworker_connections " connections ";"; connections_done = 1; next
        }
        in_events && /^[[:space:]]*\}/ {
            if (!connections_done) { print "\tworker_connections " connections ";"; connections_done = 1 }
            in_events = 0; print; next
        }
        { print }
        END { if (!rlimit_done || !connections_done) exit 42 }
    ' "$nginx_conf" > "$rendered"; then
        rm -f -- "$rendered"
        printf 'warning: unrecognised nginx.conf layout, worker limits unchanged: %s\n' \
            "$nginx_conf" >&2
        return 1
    fi
    cat "$rendered" > "$nginx_conf"
    rm -f -- "$rendered"
}

adguardhome_doh_install_nginx_restart_dropin() {
    # nginx ships without a restart policy on Ubuntu, so a worker crash or an
    # OOM kill leaves the whole endpoint down until somebody logs in.
    local root="${1:-/}" directory
    directory="$(adguardhome_doh_under_root "$root" /etc/systemd/system/nginx.service.d)"
    mkdir -p "$directory"
    cat > "$directory/adguardhome-doh.conf" <<'UNIT'
[Service]
Restart=on-failure
RestartSec=2s
LimitNOFILE=65535
UNIT
    chmod 644 "$directory/adguardhome-doh.conf"
}

adguardhome_doh_bbr_available() {
    local root="${1:-/}" available=/proc/sys/net/ipv4/tcp_available_congestion_control
    [[ "$root" == / ]] || return 1
    modprobe tcp_bbr >/dev/null 2>&1 || true
    [[ -r "$available" ]] && grep -qw bbr "$available"
}

adguardhome_doh_install_sysctl() {
    # Phones sit behind carrier NAT on paths that often filter ICMP
    # "fragmentation needed": without MTU probing a TLS handshake whose
    # certificate chain exceeds the path MTU just stalls, which reads as
    # "works on Wi-Fi, hangs on LTE".  BBR keeps throughput up over the lossy
    # cellular hop and is optional because its module is not loaded
    # everywhere.  Neither setting may block an activation.
    local root="${1:-/}" path modules bbr=0
    path="$(adguardhome_doh_under_root "$root" /etc/sysctl.d/90-adguardhome-doh.conf)"
    modules="$(adguardhome_doh_under_root "$root" /etc/modules-load.d/adguardhome-doh.conf)"
    adguardhome_doh_bbr_available "$root" && bbr=1
    mkdir -p "$(dirname "$path")"
    {
        printf '# Managed by adguardhome-doh: mobile clients behind carrier NAT.\n'
        printf 'net.ipv4.tcp_mtu_probing = 1\n'
        if (( bbr )); then
            printf 'net.core.default_qdisc = fq\n'
            printf 'net.ipv4.tcp_congestion_control = bbr\n'
        fi
    } > "$path"
    chmod 644 "$path"
    if (( bbr )); then
        mkdir -p "$(dirname "$modules")"
        printf 'tcp_bbr\n' > "$modules"
        chmod 644 "$modules"
    fi
    if [[ "$root" == / && "${ADGUARDHOME_DOH_DEFER_SYSCTL:-0}" != 1 ]]; then
        sysctl -q -p "$path" >/dev/null 2>&1 || \
            printf 'warning: kernel parameters were written but not applied: %s\n' "$path" >&2
    fi
}

adguardhome_doh_install_logrotate() {
    # nginx's own logrotate profile covers /var/log/nginx only; the stream
    # logs live in the private directory and would otherwise grow forever.
    # USR1 makes nginx reopen its files, nothing is restarted.
    local root="${1:-/}" path
    path="$(adguardhome_doh_under_root "$root" /etc/logrotate.d/adguardhome-doh)"
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<'ROTATE'
/var/log/adguardhome-doh/nginx-stream.access.log /var/log/adguardhome-doh/nginx-stream.error.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0600 root root
    sharedscripts
    postrotate
        if [ -s /run/nginx.pid ]; then kill -USR1 "$(cat /run/nginx.pid)"; fi
    endscript
}
ROTATE
    chmod 644 "$path"
}

adguardhome_doh_migrate_certbot_renewal() {
    # The caller must take a recovery snapshot before modifying a managed hook.
    local root="${1:-/}" domain="$2" webroot="$3" project_root="$4" front="${5:-standard}" profile helper hook_dir
    profile="$(adguardhome_doh_under_root "$root" "/etc/letsencrypt/renewal/$domain.conf")"
    helper="$project_root/deploy/lib/certbot_renewal.py"
    [[ -f "$helper" ]] || helper=/usr/local/libexec/adguardhome-doh/certbot_renewal.py
    [[ -f "$profile" && -f "$helper" ]] || { printf 'missing Certbot renewal profile or migration helper\n' >&2; return 1; }
    hook_dir="$(adguardhome_doh_under_root "$root" /etc/letsencrypt/renewal-hooks/deploy)"
    case "$front" in
        standard) python3 "$helper" --path "$profile" --domain "$domain" --webroot "$webroot" --hook-dir "$hook_dir" ;;
        mtproxyl) python3 "$helper" --path "$profile" --domain "$domain" --webroot "$webroot" --hook-dir "$hook_dir" --front mtproxyl ;;
        *) printf 'invalid front for Certbot renewal hook\n' >&2; return 1 ;;
    esac
}

adguardhome_doh_load_or_create_doh_token() {
    local token_file="$1" token temporary old_umask
    if [[ -f "$token_file" ]]; then
        token="$(tr -d '\r\n' < "$token_file")"
        [[ "$token" =~ ^[a-f0-9]{48}$ ]] || adguardhome_doh_die "invalid saved DoH token: $token_file"
    else
        mkdir -p "$(dirname "$token_file")"
        token="$(openssl rand -hex 24)"
        temporary="${token_file}.tmp.$$"
        old_umask="$(umask)"
        umask 077
        printf '%s\n' "$token" > "$temporary"
        umask "$old_umask"
        chmod 600 "$temporary"
        mv -f -- "$temporary" "$token_file"
    fi
    printf '%s\n' "$token"
}

adguardhome_doh_certbot_contact_args() {
    local email="$1" domain
    adguardhome_doh_validate_email "$email" || adguardhome_doh_die "invalid email: $email"
    domain="${email##*@}"
    domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')"
    case "$domain" in
        example.com|example.net|example.org)
            printf 'warning: %s is a reserved example address; Certbot will register without an email contact\n' "$email" >&2
            printf '%s\n' --register-unsafely-without-email
            ;;
        *) printf '%s\n' --email "$email" ;;
    esac
}

adguardhome_doh_hash_password() {
    printf '%s\n' "$1" | htpasswd -niBC 10 admin | tr -d '\r' | cut -d: -f2-
}

adguardhome_doh_validate_email() {
    [[ "${1:-}" =~ ^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$ ]]
}

adguardhome_doh_validate_hostname() {
    python3 - "${1:-}" "${BASH_SOURCE[0]}" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[2]).resolve().parents[2]))
from tools.render_config import _hostname
try:
    if _hostname(sys.argv[1], "hostname") != sys.argv[1]:
        raise ValueError("hostname is not normalized")
except ValueError:
    raise SystemExit(1)
PY
}

adguardhome_doh_validate_ipv4() {
    local address="${1:-}" octet
    local -a octets
    IFS=. read -r -a octets <<< "$address"
    [[ "${#octets[@]}" -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

adguardhome_doh_require_valid_input() {
    local domain="${1:-}" public_ip="${2:-}" email="${3:-}"
    adguardhome_doh_validate_hostname "$domain" || adguardhome_doh_die "invalid hostname: $domain"
    adguardhome_doh_validate_ipv4 "$public_ip" || adguardhome_doh_die "invalid IPv4: $public_ip"
    adguardhome_doh_validate_email "$email" || adguardhome_doh_die "invalid email: $email"
}

adguardhome_doh_find_checksum() {
    local checksums_file="$1" archive="$2"
    awk -v name="$archive" '$2 == name || $2 == "./" name || $2 == "*" name { print $1; exit }' "$checksums_file"
}

adguardhome_doh_find_binary() {
    local root="$1"
    find "$root" -type f -path '*/AdGuardHome/AdGuardHome' -perm -u+x -print -quit
}

adguardhome_doh_should_install_binary() {
    local target="$1" managed_update="${2:-0}"
    [[ "$managed_update" == 1 || ! -x "$target" ]]
}

adguardhome_doh_activate_binary() {
    local source="$1" target="$2" target_dir temporary
    target_dir="$(dirname "$target")"
    mkdir -p "$target_dir"
    temporary="$(mktemp "$target_dir/.AdGuardHome.XXXXXX")"
    if ! install -m 755 "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! mv -f -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
}

adguardhome_doh_acquire_operation_lock() {
    local path="${ADGUARDHOME_DOH_OPERATION_LOCK_PATH:-/run/lock/adguardhome-doh-operations.lock}"
    command -v flock >/dev/null 2>&1 || { printf 'flock is required for installation\n' >&2; return 1; }
    exec 8>>"$path" || return 1
    if ! flock -x 8; then exec 8>&-; return 1; fi
    ADGUARDHOME_DOH_OPERATION_LOCK_HELD=1
}

adguardhome_doh_release_operation_lock() {
    if [[ "${ADGUARDHOME_DOH_OPERATION_LOCK_HELD:-0}" == 1 ]]; then
        flock -u 8 || return 1
        exec 8>&-
        ADGUARDHOME_DOH_OPERATION_LOCK_HELD=0
    fi
}

adguardhome_doh_acquire_front_lock() {
    local path=/run/adguardhome-doh/front.lock
    [[ -d /run/adguardhome-doh && ! -L /run/adguardhome-doh && ! -L "$path" ]] || return 1
    exec 7>>"$path" || return 1
    if ! flock -x 7; then exec 7>&-; return 1; fi
    ADGUARDHOME_DOH_FRONT_LOCK_HELD=1
}

adguardhome_doh_release_front_lock() {
    if [[ "${ADGUARDHOME_DOH_FRONT_LOCK_HELD:-0}" == 1 ]]; then
        flock -u 7 || return 1
        exec 7>&-
        ADGUARDHOME_DOH_FRONT_LOCK_HELD=0
    fi
}

adguardhome_doh_acquire_health_lock() {
    local path="${ADGUARDHOME_DOH_LOCK_PATH:-/run/lock/adguardhome-doh-health.lock}"
    command -v flock >/dev/null 2>&1 || { printf 'flock is required for installation\n' >&2; return 1; }
    exec 9>>"$path" || return 1
    if ! flock -x 9; then
        exec 9>&-
        return 1
    fi
    ADGUARDHOME_DOH_LOCK_HELD=1
}

adguardhome_doh_release_health_lock() {
    if [[ "${ADGUARDHOME_DOH_LOCK_HELD:-0}" == 1 ]]; then
        flock -u 9 || return 1
        exec 9>&-
        ADGUARDHOME_DOH_LOCK_HELD=0
    fi
}

adguardhome_doh_capture_directory_permissions() {
    local values line
    values="$(python3 - "$@" <<'PY'
import os
import stat
import sys
for path in sys.argv[1:]:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        continue
    if stat.S_ISDIR(metadata.st_mode):
        print("\t".join(map(str, (path, metadata.st_dev, metadata.st_ino,
                                    stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid))))
PY
)" || return 1
    ADGUARDHOME_DOH_DIRECTORY_PERMISSIONS=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && ADGUARDHOME_DOH_DIRECTORY_PERMISSIONS+=("$line")
    done <<< "$values"
    return 0
}

adguardhome_doh_restore_directory_permissions() {
    python3 - ${ADGUARDHOME_DOH_DIRECTORY_PERMISSIONS[@]+"${ADGUARDHOME_DOH_DIRECTORY_PERMISSIONS[@]}"} <<'PY'
import os
import sys
failed = False
for record in sys.argv[1:]:
    path, device, inode, mode, uid, gid = record.split("\t")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if (metadata.st_dev, metadata.st_ino) != (int(device), int(inode)):
                raise RuntimeError("directory was replaced after snapshot")
            if (metadata.st_uid, metadata.st_gid) != (int(uid), int(gid)):
                os.fchown(fd, int(uid), int(gid))
            os.fchmod(fd, int(mode))
        finally:
            os.close(fd)
    except (OSError, RuntimeError) as exc:
        print("cannot restore directory permissions %s: %s" % (path, exc), file=sys.stderr)
        failed = True
raise SystemExit(1 if failed else 0)
PY
}

adguardhome_doh_capture_runtime() {
    ADGUARDHOME_DOH_NGINX_UNIT=nginx
    [[ "${ADGUARDHOME_DOH_SHARED_UPDATE:-0}" == 1 ]] && ADGUARDHOME_DOH_NGINX_UNIT=adguardhome-doh-nginx
    ADGUARDHOME_DOH_NGINX_ACTIVE="$(systemctl is-active "$ADGUARDHOME_DOH_NGINX_UNIT" 2>/dev/null || true)"
    ADGUARDHOME_DOH_NGINX_ENABLED="$(systemctl is-enabled "$ADGUARDHOME_DOH_NGINX_UNIT" 2>/dev/null || true)"
    ADGUARDHOME_DOH_AGH_ACTIVE="$(systemctl is-active adguardhome-doh 2>/dev/null || true)"
    ADGUARDHOME_DOH_AGH_ENABLED="$(systemctl is-enabled adguardhome-doh 2>/dev/null || true)"
    ADGUARDHOME_DOH_TIMER_ACTIVE="$(systemctl is-active adguardhome-doh-health.timer 2>/dev/null || true)"
    ADGUARDHOME_DOH_TIMER_ENABLED="$(systemctl is-enabled adguardhome-doh-health.timer 2>/dev/null || true)"
    ADGUARDHOME_DOH_HEALTH_ACTIVE="$(systemctl is-active adguardhome-doh-health.service 2>/dev/null || true)"
}

adguardhome_doh_stop_loaded_unit() {
    local unit="$1" load_state
    ADGUARDHOME_DOH_STOPPED_LOADED_UNIT=0
    if ! load_state="$(systemctl show --property=LoadState --value "$unit" 2>/dev/null)"; then
        [[ "$load_state" == not-found ]] || return 1
    fi
    case "$load_state" in
        not-found) ;;
        '') printf 'cannot determine systemd load state for %s\n' "$unit" >&2; return 1 ;;
        *) systemctl stop "$unit" || return 1; ADGUARDHOME_DOH_STOPPED_LOADED_UNIT=1 ;;
    esac
}

adguardhome_doh_pause_health() {
    # Old workers read the policy before taking the health lock. Stop both the
    # timer and worker even while a oneshot is activating or has a queued job.
    ADGUARDHOME_DOH_HEALTH_PAUSED=1
    adguardhome_doh_stop_loaded_unit adguardhome-doh-health.timer || return 1
    adguardhome_doh_stop_loaded_unit adguardhome-doh-health.service || return 1
}

adguardhome_doh_restore_enablement() {
    local unit="$1" original="$2" current
    current="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    case "$original:$current" in
        enabled:enabled|disabled:disabled|*:static|*:masked) return 0 ;;
        enabled:*) systemctl enable "$unit" >/dev/null ;;
        disabled:enabled|not-found:enabled|:enabled) systemctl disable "$unit" >/dev/null ;;
    esac
}

adguardhome_doh_restore_runtime() {
    local failed=0 agh_was_running=0 nginx_unit="${ADGUARDHOME_DOH_NGINX_UNIT:-nginx}"
    case "${ADGUARDHOME_DOH_AGH_ACTIVE:-}" in
        active|activating|reloading) agh_was_running=1 ;;
    esac
    # Stop only units which the installer started and which were not active at
    # capture time. Existing nginx sites keep their previous running service.
    if [[ "${ADGUARDHOME_DOH_TIMER_ACTIVE:-}" != active ]] && systemctl is-active --quiet adguardhome-doh-health.timer; then
        systemctl stop adguardhome-doh-health.timer >/dev/null 2>&1 || failed=1
    fi
    if ((agh_was_running == 0)) && systemctl is-active --quiet adguardhome-doh; then
        systemctl stop adguardhome-doh >/dev/null 2>&1 || failed=1
    fi
    if [[ "${ADGUARDHOME_DOH_NGINX_ACTIVE:-}" != active ]] && systemctl is-active --quiet "$nginx_unit"; then
        systemctl stop "$nginx_unit" >/dev/null 2>&1 || failed=1
    fi
    systemctl daemon-reload >/dev/null || failed=1
    adguardhome_doh_restore_enablement "$nginx_unit" "${ADGUARDHOME_DOH_NGINX_ENABLED:-}" || failed=1
    adguardhome_doh_restore_enablement adguardhome-doh "${ADGUARDHOME_DOH_AGH_ENABLED:-}" || failed=1
    adguardhome_doh_restore_enablement adguardhome-doh-health.timer "${ADGUARDHOME_DOH_TIMER_ENABLED:-}" || failed=1
    if ((agh_was_running)); then
        systemctl start adguardhome-doh >/dev/null || failed=1
    fi
    if [[ "${ADGUARDHOME_DOH_NGINX_ACTIVE:-}" == active ]]; then
        local -a nginx_check=(nginx -t)
        [[ "${ADGUARDHOME_DOH_SHARED_UPDATE:-0}" == 1 ]] && \
            nginx_check=(/usr/sbin/nginx -t -c /etc/adguardhome-doh/mtproxyl-nginx.conf)
        if "${nginx_check[@]}" >/dev/null 2>&1; then
            if systemctl is-active --quiet "$nginx_unit"; then
                systemctl reload "$nginx_unit" >/dev/null || failed=1
            else
                systemctl start "$nginx_unit" >/dev/null || failed=1
            fi
        else
            failed=1
        fi
    fi
    if [[ "${ADGUARDHOME_DOH_SHARED_UPDATE:-0}" == 1 ]]; then
        systemctl reload mtproxyl-pq-nginx >/dev/null || failed=1
    fi
    ((failed == 0))
}

adguardhome_doh_completed_transaction_fingerprint() {
    # The manager writes a prepared marker before touching managed files.
    # An unreadable, unrecognised, or unfinished marker makes recovery uncertain.
    python3 - "$1" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

backup_root = Path(sys.argv[1]) / "var/backups/adguardhome-doh"
if backup_root.exists() and not backup_root.is_dir():
    raise SystemExit(1)
digest = hashlib.sha256()
try:
    for marker in sorted(backup_root.glob("*/transaction.json")):
        contents = marker.read_bytes()
        value = json.loads(contents)
        if not isinstance(value, list) and (
            not isinstance(value, dict) or value.get("version") != 1
            or value.get("state") not in ("committed", "restored")
        ):
            raise ValueError("unfinished transaction")
        name = str(marker.relative_to(backup_root)).encode("utf-8")
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(contents).to_bytes(8, "big") + contents)
except (OSError, ValueError, TypeError):
    raise SystemExit(1)
print(digest.hexdigest())
PY
}

adguardhome_doh_install_exit() {
    local status=$? restore_failed=0 stopped_adguard=0 restore_cli_failed=0 early_refusal=0
    local marker_before= marker_after= marker_before_valid=0
    local -a restore_args=()
    trap - EXIT
    if [[ -n "${ADGUARDHOME_DOH_WORK_DIR:-}" ]]; then
        rm -rf -- "$ADGUARDHOME_DOH_WORK_DIR"
    fi
    if [[ -n "${ADGUARDHOME_DOH_STAGE:-}" && -d "$ADGUARDHOME_DOH_STAGE" ]]; then
        rm -rf -- "$ADGUARDHOME_DOH_STAGE"
    fi
    if [[ -n "${ADGUARDHOME_DOH_MOBILECONFIG_TEMP:-}" ]]; then
        rm -f -- "$ADGUARDHOME_DOH_MOBILECONFIG_TEMP"
    fi
    if [[ -n "${ADGUARDHOME_DOH_NGINX_TEMP:-}" ]]; then
        rm -f -- "$ADGUARDHOME_DOH_NGINX_TEMP"
    fi
    if [[ -n "${ADGUARDHOME_DOH_LEGACY_POLICY_TEMP:-}" ]]; then
        rm -f -- "$ADGUARDHOME_DOH_LEGACY_POLICY_TEMP"
    fi
    if ((status != 0)) && [[ -n "${ADGUARDHOME_DOH_SNAPSHOT:-}" && "${ADGUARDHOME_DOH_MUTATIONS:-0}" == 1 ]]; then
        if [[ "${ADGUARDHOME_DOH_LOCK_HELD:-0}" != 1 ]]; then
            adguardhome_doh_acquire_health_lock || restore_failed=1
        fi
        if ((restore_failed == 0)) && [[ "${ADGUARDHOME_DOH_HEALTH_PAUSED:-0}" == 1 ]]; then
            adguardhome_doh_pause_health || restore_failed=1
        fi
        if ((restore_failed == 0)) && [[ "${ADGUARDHOME_DOH_SHARED_UPDATE:-0}" == 1 && "${ADGUARDHOME_DOH_FRONT_LOCK_HELD:-0}" != 1 ]]; then
            adguardhome_doh_acquire_front_lock || restore_failed=1
        fi
        # AdGuard may save its live state on shutdown. Stop it before restoring
        # the YAML, otherwise a later restart can overwrite the restored file.
        if ((restore_failed == 0)) && [[ "${ADGUARDHOME_DOH_RUNTIME_TOUCHED:-0}" == 1 ]]; then
            if adguardhome_doh_stop_loaded_unit adguardhome-doh >/dev/null; then
                stopped_adguard="$ADGUARDHOME_DOH_STOPPED_LOADED_UNIT"
            else
                restore_failed=1
                printf 'failed to stop AdGuard; files were not restored\n' >&2
            fi
        fi
        if ((restore_failed == 0)); then
            [[ "${ADGUARDHOME_DOH_NEW_CERTBOT_LINEAGE:-0}" == 1 ]] && \
                restore_args=(--preserve-new-certbot-lineage)
            if marker_before="$(adguardhome_doh_completed_transaction_fingerprint "$ROOT")"; then
                marker_before_valid=1
            fi
            if ! python3 "$PROJECT_ROOT/deploy/manage.py" --restore-update-backup "$ADGUARDHOME_DOH_SNAPSHOT" \
                --root "$ROOT" --domain "$DOMAIN" --files-only \
                ${restore_args[@]+"${restore_args[@]}"}; then
                restore_failed=1
                restore_cli_failed=1
                if ((marker_before_valid)) && \
                   marker_after="$(adguardhome_doh_completed_transaction_fingerprint "$ROOT")" && \
                   [[ "$marker_before" == "$marker_after" ]]; then
                    early_refusal=1
                fi
            fi
        fi
        adguardhome_doh_release_front_lock || restore_failed=1
        if ((restore_failed == 0)) && [[ "${ADGUARDHOME_DOH_RUNTIME_TOUCHED:-0}" == 1 ]]; then
            adguardhome_doh_restore_runtime || restore_failed=1
        fi
        if ((restore_failed)); then
            printf 'automatic restoration failed; snapshot retained at %s\n' "$ADGUARDHOME_DOH_SNAPSHOT" >&2
            if ((stopped_adguard && restore_cli_failed && early_refusal)); then
                case "${ADGUARDHOME_DOH_AGH_ACTIVE:-}" in
                    active|activating|reloading)
                        systemctl start adguardhome-doh >/dev/null || \
                            printf 'failed to restart AdGuard after an early restoration refusal\n' >&2 ;;
                esac
            elif ((restore_cli_failed && !early_refusal)); then
                if ((stopped_adguard)); then
                    printf 'AdGuard left stopped: file restoration may be incomplete; inspect the transaction marker and snapshot\n' >&2
                else
                    printf 'AdGuard was not restarted: file restoration may be incomplete; inspect the transaction marker and snapshot\n' >&2
                fi
            fi
        fi
    elif ((status != 0)) && [[ "${ADGUARDHOME_DOH_RUNTIME_TOUCHED:-0}" == 1 ]]; then
        adguardhome_doh_release_front_lock || restore_failed=1
        adguardhome_doh_restore_runtime || restore_failed=1
        printf 'package changes are not reverted; verify installed packages and services\n' >&2
    elif ((status != 0)) && [[ -f "${ADGUARDHOME_DOH_BINARY_BACKUP:-}" ]]; then
        adguardhome_doh_activate_binary \
            "$ADGUARDHOME_DOH_BINARY_BACKUP" \
            "$ADGUARDHOME_DOH_BINARY_TARGET" || restore_failed=1
        if ((restore_failed)); then
            printf 'failed to restore previous AdGuard Home binary\n' >&2
        fi
    fi
    if ((status != 0)) && [[ "${ADGUARDHOME_DOH_DIRECTORY_CAPTURED:-0}" == 1 ]]; then
        adguardhome_doh_restore_directory_permissions || \
            printf 'failed to restore one or more directory permissions\n' >&2
    fi
    adguardhome_doh_release_front_lock || printf 'failed to release front lock\n' >&2
    adguardhome_doh_release_health_lock || printf 'failed to release health lock\n' >&2
    if ((status != 0 && restore_failed == 0)) && \
       [[ "${ADGUARDHOME_DOH_RUNTIME_TOUCHED:-0}" == 1 || "${ADGUARDHOME_DOH_HEALTH_PAUSED:-0}" == 1 ]]; then
        case "${ADGUARDHOME_DOH_TIMER_ACTIVE:-}" in
            active|activating|reloading)
                systemctl start adguardhome-doh-health.timer >/dev/null || \
                    printf 'failed to restore previous health timer state\n' >&2 ;;
        esac
    fi
    if ((status != 0 && restore_failed == 0)) && [[ "${ADGUARDHOME_DOH_HEALTH_PAUSED:-0}" == 1 ]]; then
        case "${ADGUARDHOME_DOH_HEALTH_ACTIVE:-}" in
            active|activating|reloading)
                systemctl start adguardhome-doh-health.service >/dev/null || \
                    printf 'failed to restore previous health service state\n' >&2 ;;
        esac
    fi
    adguardhome_doh_release_operation_lock || printf 'failed to release operation lock\n' >&2
    exit "$status"
}

adguardhome_doh_install_health_templates() {
    local project_root="$1" root="${2:-/}" templates libexec systemd manager
    templates="$project_root/deploy/templates"
    libexec="$(adguardhome_doh_under_root "$root" /usr/local/libexec/adguardhome-doh)"
    systemd="$(adguardhome_doh_under_root "$root" /etc/systemd/system)"
    [[ -f "$templates/healthcheck.py" ]] || adguardhome_doh_die "healthcheck.py template is missing"
    [[ -f "$templates/healthcheck.service" ]] || adguardhome_doh_die "healthcheck.service template is missing"
    [[ -f "$templates/healthcheck.timer" ]] || adguardhome_doh_die "healthcheck.timer template is missing"
    [[ -f "$templates/diag.py" ]] || adguardhome_doh_die "diag.py template is missing"
    [[ -f "$project_root/deploy/manage.py" ]] || adguardhome_doh_die "manage.py is missing"
    [[ -f "$project_root/tools/render_config.py" ]] || adguardhome_doh_die "render_config.py is missing"
    [[ -f "$project_root/deploy/lib/render_runtime.py" ]] || adguardhome_doh_die "render_runtime.py is missing"
    [[ -f "$project_root/deploy/lib/releases.py" ]] || adguardhome_doh_die "releases.py is missing"
    [[ -f "$project_root/deploy/lib/certbot_renewal.py" ]] || adguardhome_doh_die "certbot_renewal.py is missing"
    [[ -f "$project_root/VERSION" ]] || adguardhome_doh_die "VERSION is missing"
    mkdir -p "$libexec" "$systemd"
    chmod 700 "$libexec"
    cp "$templates/healthcheck.py" "$libexec/healthcheck.py"
    chmod 755 "$libexec/healthcheck.py"
    cp "$templates/healthcheck.service" "$systemd/adguardhome-doh-health.service"
    cp "$templates/healthcheck.timer" "$systemd/adguardhome-doh-health.timer"
    chmod 644 "$systemd/adguardhome-doh-health.service" "$systemd/adguardhome-doh-health.timer"
    manager="$(adguardhome_doh_under_root "$root" /usr/local/sbin/adguardhome-doh)"
    mkdir -p "$(dirname "$manager")"
    install -m 755 "$project_root/deploy/manage.py" "$manager"
    install -m 755 "$templates/diag.py" "$(dirname "$manager")/adguardhome-doh-diag"
    install -m 755 "$project_root/tools/render_config.py" "$libexec/render_config.py"
    install -m 755 "$project_root/deploy/lib/render_runtime.py" "$libexec/render_runtime.py"
    install -m 755 "$project_root/deploy/lib/releases.py" "$libexec/releases.py"
    install -m 755 "$project_root/deploy/lib/certbot_renewal.py" "$libexec/certbot_renewal.py"
    if [[ "${ADGUARDHOME_DOH_SHARED_UPDATE:-0}" == 1 ]]; then
        local helper
        for helper in mtproxyl_front.py mtproxyl_runtime.py mtproxyl_controller.py mtproxyl_reload.py; do
            [[ -f "$project_root/deploy/lib/$helper" && ! -L "$project_root/deploy/lib/$helper" ]] || \
                adguardhome_doh_die "shared front helper is missing: $helper"
            install -m 755 "$project_root/deploy/lib/$helper" "$libexec/$helper"
        done
    fi
    install -m 644 "$project_root/VERSION" "$libexec/VERSION"
}

adguardhome_doh_abs_root() {
    local value="${1:-/}"
    [[ "$value" == /* ]] || adguardhome_doh_die "root must be absolute"
    [[ "$value" != *"/../"* && "$value" != */.. && "$value" != *"/./"* ]] || \
        adguardhome_doh_die "root contains traversal"
    value="${value%/}"; [[ -n "$value" ]] || value=/
    printf '%s\n' "$value"
}

adguardhome_doh_under_root() {
    local root="$1" path="$2"
    [[ "$root" == / ]] && printf '%s\n' "$path" || printf '%s\n' "$root/${path#/}"
}

adguardhome_doh_arch() {
    case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
        amd64|x86_64) printf 'amd64\n' ;;
        arm64|aarch64) printf 'arm64\n' ;;
        armhf|armv7l) printf 'armv7\n' ;;
        i386|i686) printf '386\n' ;;
        *) adguardhome_doh_die "unsupported CPU architecture" ;;
    esac
}

adguardhome_doh_backup() {
    local source="$1" destination="$2"
    if [[ -e "$source" || -L "$source" ]]; then
        install -d -m 700 "$(dirname "$destination")"
        cp -a -- "$source" "$destination"
    fi
}

adguardhome_doh_init_log() {
    local root="$1" timestamp
    ADGUARDHOME_DOH_LOG_DIR="$(adguardhome_doh_under_root "$root" /var/log/adguardhome-doh)"
    mkdir -p "$ADGUARDHOME_DOH_LOG_DIR"
    chmod 700 "$ADGUARDHOME_DOH_LOG_DIR"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    ADGUARDHOME_DOH_LOG_PATH="$ADGUARDHOME_DOH_LOG_DIR/install-${timestamp}.log"
    (umask 077; : > "$ADGUARDHOME_DOH_LOG_PATH")
    chmod 600 "$ADGUARDHOME_DOH_LOG_PATH"
}

adguardhome_doh_redact() {
    local text="$1" secret
    for secret in "${ADGUARDHOME_DOH_ADMIN_PASSWORD:-}" \
        "${ADGUARDHOME_DOH_DOH_TOKEN:-}" "${ADGUARDHOME_DOH_ADMIN_HASH:-}"; do
        [[ -n "$secret" ]] && text="${text//$secret/[REDACTED]}"
    done
    printf '%s\n' "$text"
}

adguardhome_doh_run_logged() {
    local output status
    if output="$("$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi
    if [[ -n "${ADGUARDHOME_DOH_LOG_PATH:-}" ]]; then
        adguardhome_doh_redact "$output" >> "$ADGUARDHOME_DOH_LOG_PATH"
    fi
    if [[ "$status" -ne 0 ]]; then
        adguardhome_doh_redact "$output" >&2
        return "$status"
    fi
}

adguardhome_doh_smoke_https_sni() {
    local host="$1" attempts="${2:-3}" delay="${3:-2}" port="${4:-443}" attempt url
    adguardhome_doh_validate_hostname "$host" || return 1
    [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$delay" =~ ^[0-9]+$ ]] || return 1
    [[ "$port" =~ ^[0-9]+$ ]] && ((port > 0 && port <= 65535)) || return 1
    url="https://$host/"
    [[ "$port" != 443 ]] && url="https://$host:$port/"
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if curl --fail --silent --show-error --noproxy '*' \
            --resolve "$host:$port:127.0.0.1" \
            --connect-timeout 3 --max-time 8 \
            --output /dev/null "$url"; then
            return 0
        fi
        (( attempt < attempts )) && sleep "$delay"
    done
    printf 'HTTPS/SNI smoke check failed for %s after %s attempts\n' "$host" "$attempts" >&2
    return 1
}

adguardhome_doh_managed_nginx_update_allowed() {
    local root="$1" domain="$2" listeners="$3"
    local site stream line endpoint port found=0
    site="$(adguardhome_doh_under_root "$root" /etc/nginx/sites-enabled/adguardhome-doh)"
    stream="$(adguardhome_doh_under_root "$root" /etc/nginx/stream.d/adguardhome-doh.conf)"
    [[ -f "$site" && -f "$stream" ]] || return 1
    grep -Fq "server_name $domain;" "$site" || return 1
    grep -Eq '(^|[[:space:]])listen[[:space:]]+443([;[:space:]]|$)' "$stream" || return 1
    while IFS= read -r line; do
        endpoint="$(awk '{print $4}' <<< "$line")"
        port="${endpoint##*:}"
        case "$port" in
            80|443)
                found=1
                [[ "$line" == *'users:(("nginx"'* ]] || return 1
                ;;
        esac
    done <<< "$listeners"
    (( found ))
}

adguardhome_doh_nginx_owns_listeners() {
    # True when every listener on 80 and 443 belongs to nginx: the stream
    # layer can then take 443 over and hand existing sites their SNI back on
    # internal ports.  Any other owner is a real conflict.
    local listeners="$1" line endpoint port found=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        endpoint="$(awk '{print $4}' <<< "$line")"
        port="${endpoint##*:}"
        case "$port" in
            80|443)
                found=1
                [[ "$line" == *'users:(("nginx"'* ]] || return 1
                ;;
        esac
    done <<< "$listeners"
    (( found ))
}

adguardhome_doh_system_nginx_owns_listeners() {
    # A different service may also run a process named nginx.  Only take over
    # listeners from the active system nginx unit whose cgroup owns every PID.
    local listeners="$1" proc_root="${2:-/proc}" group line endpoint port rest pid found=0
    systemctl is-active --quiet nginx || return 1
    group="$(systemctl show --property=ControlGroup --value nginx 2>/dev/null)" || return 1
    [[ "$group" == /* ]] || return 1
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        endpoint="$(awk '{print $4}' <<< "$line")"
        port="${endpoint##*:}"
        [[ "$port" == 80 || "$port" == 443 ]] || continue
        [[ "$line" == *'users:(("nginx"'* && "$line" == *'pid='* ]] || return 1
        rest="$line"
        while [[ "$rest" =~ pid=([0-9]+) ]]; do
            pid="${BASH_REMATCH[1]}"
            [[ -r "$proc_root/$pid/cgroup" ]] || return 1
            awk -F: -v group="$group" '
                $3 == group || (group == "/" && substr($3, 1, 1) == "/") ||
                    (group != "/" && index($3, group "/") == 1) { found = 1 }
                END { exit !found }
            ' "$proc_root/$pid/cgroup" || return 1
            found=1
            rest="${rest#*pid=$pid}"
        done
    done <<< "$listeners"
    (( found ))
}

adguardhome_doh_shared_verify_listener_snapshot() {
    # Check one ss -H -ltnp snapshot against service cgroups.  This is only
    # listener evidence: it neither reserves ports nor verifies master/config
    # identity, and cannot authorize activation without the lifecycle checks.
    local listeners="$1" proc_root="$2" mtproxy_group="$3" previous_front="$4"
    local private_group="$5" public_ip="$6" line endpoint address port rest pid fd group
    local found_pid found80=0 found443=0 found4443=0 found24443=0
    local pid_pattern='^([0-9]+),fd=([0-9]+)([),[:space:]]|$)'
    adguardhome_doh_validate_ipv4 "$public_ip" || return 1
    [[ "$mtproxy_group" == /* && "$mtproxy_group" == */mtproxyl-pq-nginx.service && "$mtproxy_group" != *'/../'* &&
       "$mtproxy_group" != *'/./'* && "$mtproxy_group" != *'//'* ]] || return 1
    case "$previous_front" in
        standard) ;;
        mtproxyl)
            [[ "$private_group" == /* && "$private_group" == */adguardhome-doh-nginx.service && "$private_group" != *'/../'* &&
               "$private_group" != *'/./'* && "$private_group" != *'//'* ]] || return 1
            ;;
        *) return 1 ;;
    esac
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        endpoint="$(awk '{print $4}' <<< "$line")"
        [[ "$endpoint" == *:* ]] || return 1
        address="${endpoint%:*}"
        port="${endpoint##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || return 1
        case "$port" in
            80|443)
                group="$mtproxy_group"
                if [[ "$address" == 0.0.0.0 || "$address" == "$public_ip" ]]; then
                    if [[ "$port" == 80 ]]; then found80=1; else found443=1; fi
                fi
                ;;
            4443|24443)
                [[ "$previous_front" == mtproxyl && "$address" == 127.0.0.1 ]] || return 1
                group="$private_group"
                if [[ "$port" == 4443 ]]; then found4443=1; else found24443=1; fi
                ;;
            *) continue ;;
        esac
        [[ "$line" == *'users:(('* && "$line" == *'pid='* ]] || return 1
        found_pid=0
        rest="$line"
        while [[ "$rest" == *'pid='* ]]; do
            rest="${rest#*pid=}"
            [[ "$rest" =~ $pid_pattern ]] || return 1
            pid="${BASH_REMATCH[1]}"
            fd="${BASH_REMATCH[2]}"
            [[ -r "$proc_root/$pid/cgroup" ]] || return 1
            awk -F: -v group="$group" '
                $3 == group || index($3, group "/") == 1 { found = 1 }
                END { exit !found }
            ' "$proc_root/$pid/cgroup" || return 1
            found_pid=1
            rest="${rest#"$pid,fd=$fd"}"
        done
        [[ "$found_pid" == 1 ]] || return 1
    done <<< "$listeners"
    [[ "$found80" == 1 && "$found443" == 1 ]] || return 1
    [[ "$previous_front" == standard || ( "$found4443" == 1 && "$found24443" == 1 ) ]]
}

adguardhome_doh_shared_preflight_listeners() {
    # Run immediately before private listeners are started, after the lifecycle
    # has safely handled any conflicting system unit.  A free snapshot is not
    # a reservation; systemd state and verified process identity are separate
    # prerequisites, and bind/start errors must still abort the transaction.
    local public_ip="$1" previous_front="$2" proc_root="${3:-/proc}"
    local mtproxy_group private_group="" listeners
    command -v ss >/dev/null 2>&1 || { printf 'ss is required for shared listener preflight\n' >&2; return 1; }
    systemctl is-active --quiet mtproxyl-pq-nginx.service || {
        printf 'MTProxyL must be active for shared listener preflight\n' >&2; return 1;
    }
    mtproxy_group="$(systemctl show --property=ControlGroup --value mtproxyl-pq-nginx.service 2>/dev/null)" || return 1
    if [[ "$previous_front" == mtproxyl ]]; then
        systemctl is-active --quiet adguardhome-doh-nginx.service || return 1
        private_group="$(systemctl show --property=ControlGroup --value adguardhome-doh-nginx.service 2>/dev/null)" || return 1
    fi
    listeners="$(ss -H -ltnp 2>/dev/null)" || { printf 'could not inspect listener ports\n' >&2; return 1; }
    adguardhome_doh_shared_verify_listener_snapshot "$listeners" "$proc_root" "$mtproxy_group" \
        "$previous_front" "$private_group" "$public_ip" || {
        printf 'shared listener ports are missing, in use by another service, or have unknown owners\n' >&2; return 1;
    }
}

adguardhome_doh_validate_local_site() {
    # HOST=IPV4:PORT, or *=IPV4:PORT for the default target; 443 stays ours.
    local value="${1:-}" host addr ip port
    host="${value%%=*}"; addr="${value#*=}"
    [[ "$value" == *=* && -n "$host" && -n "$addr" ]] || return 1
    [[ "$host" == '*' ]] || adguardhome_doh_validate_hostname "$host" || return 1
    ip="${addr%:*}"; port="${addr##*:}"
    [[ "$addr" == *:* ]] || return 1
    adguardhome_doh_validate_ipv4 "$ip" || return 1
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 && port != 443 ))
}

adguardhome_doh_preflight() {
    local root="$1" domain="$2" public_ip="$3" allow_managed_update="${4:-0}" fronting="${5:-0}" os_release managed_path
    adguardhome_doh_require_valid_input "$domain" "$public_ip" "preflight@example.com"
    os_release="$(adguardhome_doh_under_root "$root" /etc/os-release)"
    adguardhome_doh_require_ubuntu "$os_release"
    # Several writes below use shell redirection or cp. Following an existing
    # symlink would modify its target while the snapshot saves only the link.
    for managed_path in \
        /etc/nginx/nginx.conf /etc/nginx/stream.d/adguardhome-doh.conf \
        /etc/systemd/system/nginx.service.d/adguardhome-doh.conf \
        /etc/systemd/system/adguardhome-doh.service \
        /etc/systemd/system/adguardhome-doh-health.service \
        /etc/systemd/system/adguardhome-doh-health.timer \
        /etc/sysctl.d/90-adguardhome-doh.conf /etc/modules-load.d/adguardhome-doh.conf \
        /etc/logrotate.d/adguardhome-doh /etc/adguardhome-doh/runtime.env \
        /etc/adguardhome-doh/health-policy.json /etc/adguardhome-doh/compat-policy.csv \
        /etc/adguardhome-doh/catalog/services.csv /etc/adguardhome-doh/catalog/domains.csv \
        /etc/adguardhome-doh/catalog/service-domains.csv /etc/adguardhome-doh/catalog/service-probes.csv \
        /usr/local/libexec/adguardhome-doh/healthcheck.py \
        /usr/local/libexec/adguardhome-doh/render_config.py \
        /usr/local/libexec/adguardhome-doh/render_runtime.py \
        /usr/local/libexec/adguardhome-doh/releases.py \
        /usr/local/libexec/adguardhome-doh/certbot_renewal.py \
        /usr/local/libexec/adguardhome-doh/VERSION \
        /usr/local/sbin/adguardhome-doh /usr/local/sbin/adguardhome-doh-diag; do
        [[ ! -L "$(adguardhome_doh_under_root "$root" "$managed_path")" ]] || \
            adguardhome_doh_die "managed file is a symlink; refusing to overwrite: $managed_path"
    done
    if [[ "$root" == / ]]; then
        command -v ss >/dev/null 2>&1 || adguardhome_doh_die "ss is required for listener preflight"
        local listeners
        listeners="$(ss -H -ltn 2>/dev/null || true)"
        # A clean host must expose no listener on ports required by activation.
        if awk '
            {
                endpoint = $4
                sub(/^.*:/, "", endpoint)
                if (endpoint == "80" || endpoint == "443") found = 1
            }
            END { exit !found }
        ' <<< "$listeners"; then
            local listeners_with_process
            listeners_with_process="$(ss -H -ltnp 2>/dev/null || true)"
            if (( allow_managed_update )) && adguardhome_doh_managed_nginx_update_allowed / "$domain" "$listeners_with_process" && \
                adguardhome_doh_system_nginx_owns_listeners "$listeners_with_process"; then
                :
            elif (( fronting )) && adguardhome_doh_nginx_owns_listeners "$listeners_with_process" && \
                adguardhome_doh_system_nginx_owns_listeners "$listeners_with_process"; then
                # Existing sites keep running behind the stream listener.
                :
            else
                adguardhome_doh_die "required listener ports 80/443 are already in use"
            fi
        fi
        local resolved
        resolved="$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true)"
        grep -qx "$public_ip" <<< "$resolved" || adguardhome_doh_die "DNS A record does not match public IPv4"
    fi
}

# A shared update must keep the existing MTProxy-owned public listeners.  Do
# not use the standard preflight, which expects system nginx to own them.
adguardhome_doh_preflight_shared_update() {
    local project_root="$1" domain="$2" public_ip="$3" admin_host="$4"
    [[ -n "$admin_host" ]] || adguardhome_doh_die "shared update requires an admin host"
    grep -qx 'RuntimeDirectoryPreserve=yes' "$project_root/deploy/templates/healthcheck.service" || \
        adguardhome_doh_die "shared health unit must preserve the MTProxy runtime directory"
    python3 - "$project_root" "$domain" "$public_ip" "$admin_host" <<'PY'
import importlib.util
import subprocess
import sys
from pathlib import Path

root, domain, public_ip, admin = sys.argv[1:]
spec = importlib.util.spec_from_file_location('doh_shared_update_manager', Path(root) / 'deploy/manage.py')
manager = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = manager
spec.loader.exec_module(manager)
try:
    state = manager._current_install_state(Path('/'))
    if (manager._front_mode(state) != 'mtproxyl' or state.get('domain') != domain
            or state.get('public_ip') != public_ip or state.get('admin_host') != admin):
        raise ValueError('shared installation settings changed')
    manager._require_front_files(Path('/'))
    manager._verify_mtproxyl_active_config(Path('/'), subprocess.run, allow_private=True)
    for relative in manager.FRONT_V5_FILES:
        path = Path(relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError('shared update file is unavailable')
    for host in (domain, admin):
        base = Path('/etc/letsencrypt/live') / host
        if not (base / 'fullchain.pem').is_file() or not (base / 'privkey.pem').is_file():
            raise ValueError('shared certificate is unavailable')
    for unit in ('adguardhome-doh.service', 'adguardhome-doh-nginx.service'):
        subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
    print('shared update preflight failed', file=sys.stderr)
    raise SystemExit(1)
PY
}

adguardhome_doh_validate_services() {
    local project_root="$1" value="${2:-}"
    [[ -n "$value" ]] || return 1
    python3 - "$project_root" "$value" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.render_config import Catalog

catalog = Catalog.load(Path(sys.argv[1]) / "config")
values = [item.strip() for item in sys.argv[2].split(",") if item.strip()]
if not values:
    raise SystemExit(2)
try:
    selected = {catalog._identifier(item, "service id") for item in values}
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)
unknown = selected - {service.id for service in catalog.services}
if unknown:
    print("unknown services: " + ",".join(sorted(unknown)), file=sys.stderr)
    raise SystemExit(2)
print(",".join(item for item in (service.id for service in catalog.services) if item in selected))
PY
}
