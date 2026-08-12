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
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    if ipaddress.ip_address(sys.argv[1]).version != 4:
        raise ValueError
except ValueError:
    raise SystemExit("invalid IPv4")
PY
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
