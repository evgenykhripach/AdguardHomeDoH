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
        apache2-utils tar gzip python3
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

adguardhome_doh_validate_email() {
    [[ "${1:-}" =~ ^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$ ]]
}

adguardhome_doh_validate_hostname() {
    [[ "${1:-}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
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

adguardhome_doh_install_health_templates() {
    local project_root="$1" root="${2:-/}" templates libexec systemd manager
    templates="$project_root/deploy/templates"
    libexec="$(adguardhome_doh_under_root "$root" /usr/local/libexec/adguardhome-doh)"
    systemd="$(adguardhome_doh_under_root "$root" /etc/systemd/system)"
    [[ -f "$templates/healthcheck.py" ]] || adguardhome_doh_die "healthcheck.py template is missing"
    [[ -f "$templates/healthcheck.service" ]] || adguardhome_doh_die "healthcheck.service template is missing"
    [[ -f "$templates/healthcheck.timer" ]] || adguardhome_doh_die "healthcheck.timer template is missing"
    [[ -f "$project_root/deploy/manage.py" ]] || adguardhome_doh_die "manage.py is missing"
    [[ -f "$project_root/tools/render_config.py" ]] || adguardhome_doh_die "render_config.py is missing"
    [[ -f "$project_root/deploy/lib/render_runtime.py" ]] || adguardhome_doh_die "render_runtime.py is missing"
    [[ -f "$project_root/deploy/lib/releases.py" ]] || adguardhome_doh_die "releases.py is missing"
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
    install -m 755 "$project_root/tools/render_config.py" "$libexec/render_config.py"
    install -m 755 "$project_root/deploy/lib/render_runtime.py" "$libexec/render_runtime.py"
    install -m 755 "$project_root/deploy/lib/releases.py" "$libexec/releases.py"
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

adguardhome_doh_preflight() {
    local root="$1" domain="$2" public_ip="$3" allow_managed_update="${4:-0}" os_release
    adguardhome_doh_require_valid_input "$domain" "$public_ip" "preflight@example.com"
    os_release="$(adguardhome_doh_under_root "$root" /etc/os-release)"
    adguardhome_doh_require_ubuntu "$os_release"
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
            if (( allow_managed_update )) && adguardhome_doh_managed_nginx_update_allowed / "$domain" "$listeners_with_process"; then
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

adguardhome_doh_validate_services() {
    local project_root="$1" value="${2:-}"
    [[ -n "$value" ]] || return 1
    if ! command -v python3 >/dev/null 2>&1; then
        awk -F, -v wanted="$value" '
            BEGIN {
                count = split(wanted, items, ",")
                for (i = 1; i <= count; i++) {
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", items[i])
                    if (items[i] !~ /^[a-z][a-z0-9_]*$/) {
                        printf "invalid service id: %s\n", items[i] > "/dev/stderr"
                        invalid = 1
                    }
                    requested[items[i]] = 1
                }
            }
            NR > 1 && ($1 in requested) {
                found[$1] = 1
                if (result != "") result = result ","
                result = result $1
            }
            END {
                if (invalid) exit 2
                for (i = 1; i <= count; i++) {
                    if (!(items[i] in found)) {
                        printf "unknown services: %s\n", items[i] > "/dev/stderr"
                        invalid = 1
                    }
                }
                if (invalid || result == "") exit 2
                print result
            }' "$project_root/config/services.csv"
        return
    fi
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
