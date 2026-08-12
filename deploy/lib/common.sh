#!/usr/bin/env bash
set -euo pipefail

pressroll_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

pressroll_require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || pressroll_die "run as root (or use --root for dry-run tests)"
}

pressroll_require_ubuntu() {
    local os_release="${1:-/etc/os-release}"
    local version major minor
    [[ -r "$os_release" ]] || pressroll_die "Ubuntu 24.04 or newer is required"
    # shellcheck disable=SC1090
    . "$os_release"
    [[ "${ID:-}" == "ubuntu" ]] || pressroll_die "Ubuntu 24.04 or newer is required"
    version="${VERSION_ID:-}"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)$ ]] || pressroll_die "Ubuntu 24.04 or newer is required"
    major="${BASH_REMATCH[1]#0}"
    minor="${BASH_REMATCH[2]#0}"
    [[ -n "$major" ]] || major=0
    [[ -n "$minor" ]] || minor=0
    (( major > 24 || (major == 24 && minor >= 4) )) || \
        pressroll_die "Ubuntu 24.04 or newer is required"
}

pressroll_required_packages() {
    printf '%s\n' \
        ca-certificates \
        curl \
        nginx \
        libnginx-mod-stream \
        certbot \
        openssl \
        apache2-utils \
        tar \
        gzip \
        python3
}

pressroll_ensure_nginx_stream_include() {
    local nginx_conf="${1:-/etc/nginx/nginx.conf}"
    local include_line='include /etc/nginx/stream.d/*.conf;'
    local rendered
    [[ -f "$nginx_conf" ]] || pressroll_die "nginx.conf is missing: $nginx_conf"
    rendered="$(mktemp)"
    if ! awk -v include_line="$include_line" '
        /^[[:space:]]*include[[:space:]]+\/etc\/nginx\/stream[.]d\/[*][.]conf;[[:space:]]*$/ { next }
        !inserted && /^[[:space:]]*http[[:space:]]*\{/ { print include_line; inserted = 1 }
        { print }
        END { if (!inserted) exit 42 }
    ' "$nginx_conf" > "$rendered"; then
        rm -f -- "$rendered"
        pressroll_die "nginx.conf has no top-level http block"
    fi
    cat "$rendered" > "$nginx_conf"
    rm -f -- "$rendered"
}

pressroll_load_or_create_doh_token() {
    local token_file="$1" token old_umask temporary
    if [[ -f "$token_file" ]]; then
        token="$(tr -d '\r\n' < "$token_file")"
        [[ "$token" =~ ^[a-f0-9]{48}$ ]] || \
            pressroll_die "invalid saved DoH token: $token_file"
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

pressroll_certbot_contact_args() {
    local email="$1" domain
    pressroll_validate_email "$email"
    domain="${email##*@}"
    domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')"
    case "$domain" in
        example.com|example.net|example.org)
            printf 'warning: %s is a reserved example address; Certbot will register without an email contact\n' \
                "$email" >&2
            printf '%s\n' --register-unsafely-without-email
            ;;
        *)
            printf '%s\n' --email "$email"
            ;;
    esac
}

pressroll_validate_email() {
    [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$ ]] || \
        pressroll_die "invalid email: $1"
}

pressroll_find_checksum() {
    local checksums_file="$1" archive="$2"
    awk -v name="$archive" \
        '$2 == name || $2 == "./" name || $2 == "*" name { print $1; exit }' \
        "$checksums_file"
}

pressroll_find_adguard_binary() {
    local root="$1"
    find "$root" -type f -path '*/AdGuardHome/AdGuardHome' -perm -u+x -print -quit
}

pressroll_install_health_templates() {
    local project_root="$1" root="${2:-/}"
    local templates="$project_root/deploy/templates"
    local libexec systemd
    libexec="$(pressroll_under_root "$root" /usr/local/libexec/pressroll-smart-dns)"
    systemd="$(pressroll_under_root "$root" /etc/systemd/system)"
    [[ -f "$templates/healthcheck.py" ]] || pressroll_die "healthcheck.py template is missing"
    [[ -f "$templates/healthcheck.service" ]] || pressroll_die "healthcheck.service template is missing"
    [[ -f "$templates/healthcheck.timer" ]] || pressroll_die "healthcheck.timer template is missing"
    mkdir -p "$libexec" "$systemd"
    chmod 700 "$libexec"
    install -m 755 "$templates/healthcheck.py" "$libexec/healthcheck.py"
    install -m 644 "$templates/healthcheck.service" "$systemd/pressroll-smart-dns-health.service"
    install -m 644 "$templates/healthcheck.timer" "$systemd/pressroll-smart-dns-health.timer"
}

pressroll_validate_hostname() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || \
        pressroll_die "invalid hostname: $1"
}

pressroll_validate_ipv4() {
    local address="$1" octet
    local -a octets
    IFS=. read -r -a octets <<< "$address"
    [[ "${#octets[@]}" -eq 4 ]] || pressroll_die "invalid IPv4: $address"
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || \
            pressroll_die "invalid IPv4: $address"
        ((10#$octet <= 255)) || pressroll_die "invalid IPv4: $address"
    done
}

pressroll_abs_root() {
    local value="${1:-/}"
    [[ "$value" == /* ]] || pressroll_die "root must be absolute"
    [[ "$value" != *"/../"* && "$value" != */.. && "$value" != *"/./"* ]] || \
        pressroll_die "root contains traversal"
    value="${value%/}"
    [[ -n "$value" ]] || value=/
    printf '%s\n' "$value"
}

pressroll_under_root() {
    local root="$1" path="$2"
    [[ "$root" == "/" ]] && printf '%s\n' "$path" || printf '%s\n' "$root/${path#/}"
}

pressroll_arch() {
    case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
        amd64|x86_64) printf 'amd64\n' ;;
        arm64|aarch64) printf 'arm64\n' ;;
        armhf|armv7l) printf 'armv7\n' ;;
        i386|i686) printf '386\n' ;;
        *) pressroll_die "unsupported CPU architecture" ;;
    esac
}

pressroll_backup() {
    local source="$1" destination="$2"
    if [[ -e "$source" || -L "$source" ]]; then
        install -d -m 700 "$(dirname "$destination")"
        cp -a -- "$source" "$destination"
    fi
}
