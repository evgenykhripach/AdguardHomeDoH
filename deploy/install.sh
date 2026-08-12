#!/usr/bin/env bash
set -eEuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ADGUARD_VERSION="${ADGUARD_VERSION:-0.107.78}"
ROOT=/
DOMAIN=
PUBLIC_IP=
EMAIL=
POLICY="$PROJECT_ROOT/config/policy.csv"
DRY_RUN=0
UPDATE=0
ROLLBACK=0

usage() {
    cat <<'EOF'
usage: install.sh --domain HOST --public-ip IPV4 --email EMAIL [options]
  --policy PATH       canonical policy CSV (default: config/policy.csv)
  --root PATH         isolated root for dry-run tests
  --dry-run           validate and print the activation plan without writing
  --update            preserve existing credentials and update runtime files
  --rollback          restore the latest backup instead of installing
EOF
}

while (($#)); do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --public-ip) PUBLIC_IP="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        --policy) POLICY="$2"; shift 2 ;;
        --root) ROOT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --update) UPDATE=1; shift ;;
        --rollback) ROLLBACK=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; pressroll_die "unknown argument: $1" ;;
    esac
done

[[ -n "$DOMAIN" ]] || { usage >&2; pressroll_die "--domain is required"; }
[[ -n "$PUBLIC_IP" ]] || { usage >&2; pressroll_die "--public-ip is required"; }
[[ -n "$EMAIL" ]] || { usage >&2; pressroll_die "--email is required"; }
pressroll_validate_hostname "$DOMAIN"
pressroll_validate_ipv4 "$PUBLIC_IP"
pressroll_validate_email "$EMAIL"
[[ -f "$POLICY" ]] || pressroll_die "policy not found: $POLICY"

ROOT="$(pressroll_abs_root "$ROOT")"
STATE_DIR="$(pressroll_under_root "$ROOT" /var/lib/pressroll-smart-dns)"
CONFIG_DIR="$(pressroll_under_root "$ROOT" /etc/pressroll-smart-dns)"
CREDENTIALS_FILE="$STATE_DIR/admin-credentials"
DOH_TOKEN_FILE="$STATE_DIR/doh-token"
INSTALL_COMPLETE_FILE="$STATE_DIR/install-complete"
BACKUP_ROOT="$(pressroll_under_root "$ROOT" /var/backups/pressroll-smart-dns)"
WEBROOT="$(pressroll_under_root "$ROOT" /var/www/pressroll-smart-dns)"
PRINT_INSTALL_SUMMARY=0
[[ -f "$INSTALL_COMPLETE_FILE" ]] || PRINT_INSTALL_SUMMARY=1

if ((DRY_RUN)); then
    python3 "$PROJECT_ROOT/tools/render_config.py" \
        --policy "$POLICY" --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN" \
        --output "$(mktemp -d)"
    printf 'DRY-RUN valid: domain=%s public_ip=%s policy=%s\n' "$DOMAIN" "$PUBLIC_IP" "$POLICY"
    printf 'DRY-RUN would install AdGuard Home v%s, nginx, certbot and health-gate\n' "$ADGUARD_VERSION"
    printf 'DRY-RUN would preserve credentials at %s\n' "$CREDENTIALS_FILE"
    exit 0
fi

pressroll_require_root
[[ "$ROOT" == "/" ]] || pressroll_die "non-root installation only supports --dry-run"
command -v systemctl >/dev/null || pressroll_die "systemd is required"
pressroll_require_ubuntu

if ((ROLLBACK)); then
    latest="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort | tail -1 || true)"
    [[ -n "$latest" ]] || pressroll_die "no backup is available for rollback"
    systemctl stop pressroll-smart-dns-health.timer pressroll-smart-dns-health.service AdGuardHome nginx || true
    [[ ! -e "$latest/AdGuardHome.yaml" ]] || install -m 640 "$latest/AdGuardHome.yaml" /opt/AdGuardHome/AdGuardHome.yaml
    [[ ! -e "$latest/nginx-http.conf" ]] || install -m 644 "$latest/nginx-http.conf" /etc/nginx/sites-enabled/pressroll-smart-dns
    [[ ! -e "$latest/nginx-stream.conf" ]] || install -m 644 "$latest/nginx-stream.conf" /etc/nginx/stream.d/pressroll-smart-dns.conf
    nginx -t
    systemctl daemon-reload
    systemctl start AdGuardHome nginx pressroll-smart-dns-health.timer
    printf 'rollback restored %s\n' "$latest"
    exit 0
fi

apt-get update
mapfile -t required_packages < <(pressroll_required_packages)
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    "${required_packages[@]}"

mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT" "$WEBROOT" /etc/nginx/stream.d
chmod 700 "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT"
chmod 755 "$WEBROOT"
if ! id adguardhome >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/AdGuardHome --create-home --shell /usr/sbin/nologin adguardhome
fi

if [[ ! -x /opt/AdGuardHome/AdGuardHome ]]; then
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    arch="$(pressroll_arch)"
    archive="AdGuardHome_linux_${arch}.tar.gz"
    curl --fail --silent --show-error --location \
        "https://github.com/AdguardTeam/AdGuardHome/releases/download/v${ADGUARD_VERSION}/${archive}" \
        -o "$work/$archive"
    curl --fail --silent --show-error --location \
        "https://github.com/AdguardTeam/AdGuardHome/releases/download/v${ADGUARD_VERSION}/checksums.txt" \
        -o "$work/checksums.txt"
    checksum="$(pressroll_find_checksum "$work/checksums.txt" "$archive")"
    [[ "$checksum" =~ ^[0-9a-fA-F]{64}$ ]] || pressroll_die "AdGuard checksum missing for $archive"
    printf '%s  %s\n' "$checksum" "$work/$archive" | sha256sum -c -
    tar -xzf "$work/$archive" -C "$work"
    adguard_binary="$(pressroll_find_adguard_binary "$work")"
    [[ -n "$adguard_binary" ]] || pressroll_die "AdGuard binary missing after extraction"
    mkdir -p /opt/AdGuardHome
    chmod 755 /opt/AdGuardHome
    install -m 755 "$adguard_binary" /opt/AdGuardHome/AdGuardHome
fi

if [[ -f "$CREDENTIALS_FILE" ]]; then
    # shellcheck source=/dev/null
    source <(sed -n 's/^\(url\|login\|password\)=/PRESSROLL_CRED_\1=/p' "$CREDENTIALS_FILE")
    ADMIN_PASSWORD="$PRESSROLL_CRED_password"
    FIRST_INSTALL=0
else
    ADMIN_PASSWORD="$(openssl rand -hex 24)"
    FIRST_INSTALL=1
fi
ADMIN_HASH="$(htpasswd -bnBC 10 admin "$ADMIN_PASSWORD" | tr -d '\r' | cut -d: -f2-)"
DOH_TOKEN="$(pressroll_load_or_create_doh_token "$DOH_TOKEN_FILE")"
CERT_ROOT="/etc/letsencrypt/live/$DOMAIN"
PROFILE_ID="$(openssl rand -hex 4)-$(openssl rand -hex 2)-4$(openssl rand -hex 1)-a$(openssl rand -hex 1)-$(openssl rand -hex 6)"
PAYLOAD_ID="$(openssl rand -hex 4)-$(openssl rand -hex 2)-4$(openssl rand -hex 1)-b$(openssl rand -hex 1)-$(openssl rand -hex 6)"
stage="$(mktemp -d "$STATE_DIR/.stage.XXXXXX")"
backup="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"
chmod 700 "$backup"
pressroll_backup /opt/AdGuardHome/AdGuardHome.yaml "$backup/AdGuardHome.yaml"
pressroll_backup /etc/nginx/sites-enabled/pressroll-smart-dns "$backup/nginx-http.conf"
pressroll_backup /etc/nginx/stream.d/pressroll-smart-dns.conf "$backup/nginx-stream.conf"

python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py" \
    --policy "$POLICY" --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN" \
    --doh-token "$DOH_TOKEN" --password-hash "$ADMIN_HASH" \
    --certificate-root "$CERT_ROOT" --webroot "$WEBROOT" --output "$stage"

install -m 640 "$stage/AdGuardHome.yaml" /opt/AdGuardHome/AdGuardHome.yaml
install -m 644 "$stage/nginx-stream.conf" /etc/nginx/stream.d/pressroll-smart-dns.conf
cat > "$WEBROOT/$DOH_TOKEN.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict><key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>https://$DOMAIN/doh/$DOH_TOKEN</string></dict>
<key>PayloadDisplayName</key><string>Pressroll Smart DNS</string><key>PayloadIdentifier</key><string>com.pressroll.smartdns.$PAYLOAD_ID</string><key>PayloadOrganization</key><string>Pressroll</string><key>PayloadType</key><string>com.apple.dnsSettings.managed</string><key>PayloadUUID</key><string>$PAYLOAD_ID</string><key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>Pressroll Smart DNS</string><key>PayloadIdentifier</key><string>com.pressroll.smartdns.$PROFILE_ID</string><key>PayloadOrganization</key><string>Pressroll</string><key>PayloadRemovalDisallowed</key><false/><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>$PROFILE_ID</string><key>PayloadVersion</key><integer>1</integer>
</dict></plist>
EOF
pressroll_ensure_nginx_stream_include
cat > /etc/nginx/sites-enabled/pressroll-smart-dns <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type text/plain;
        try_files \$uri =404;
    }
    location / { return 404; }
}
EOF

cat > /etc/systemd/system/AdGuardHome.service <<'UNIT'
[Unit]
Description=AdGuard Home DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /var/lib/AdGuardHome
Restart=on-failure
User=root
NoNewPrivileges=true
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=/opt/AdGuardHome /var/lib/AdGuardHome

[Install]
WantedBy=multi-user.target
UNIT
pressroll_install_health_templates "$PROJECT_ROOT"
install -m 640 "$stage/health-policy.json" "$CONFIG_DIR/health-policy.json"
cat > /etc/pressroll-smart-dns/runtime.env <<EOF
PRESSROLL_AGH_URL=http://127.0.0.1:3001
PRESSROLL_POLICY=$CONFIG_DIR/health-policy.json
PRESSROLL_STATE=$STATE_DIR/health-state.json
PRESSROLL_CREDENTIALS=$CREDENTIALS_FILE
PRESSROLL_PUBLIC_IP=$PUBLIC_IP
PRESSROLL_SUCCESS_THRESHOLD=3
PRESSROLL_FAILURE_THRESHOLD=2
EOF
chmod 600 /etc/pressroll-smart-dns/runtime.env

if ((FIRST_INSTALL)); then
    python3 "$SCRIPT_DIR/lib/credentials.py" --path "$CREDENTIALS_FILE" \
        --url "https://$DOMAIN/" --password "$ADMIN_PASSWORD" >/dev/null
fi
systemctl daemon-reload
nginx -t
systemctl enable --now AdGuardHome nginx
systemctl reload nginx
if [[ ! -f "$CERT_ROOT/fullchain.pem" ]]; then
    mapfile -t certbot_contact_args < <(pressroll_certbot_contact_args "$EMAIL")
    certbot certonly --standalone -d "$DOMAIN" \
        "${certbot_contact_args[@]}" \
        --pre-hook "systemctl stop nginx" \
        --post-hook "systemctl start nginx" \
        --agree-tos --non-interactive --keep-until-expiring
fi
install -m 644 "$stage/nginx-http.conf" /etc/nginx/sites-enabled/pressroll-smart-dns
nginx -t
systemctl reload nginx
systemctl enable --now pressroll-smart-dns-health.timer
systemctl start pressroll-smart-dns-health.service || true
rm -rf -- "$stage"
install -m 600 /dev/null "$INSTALL_COMPLETE_FILE"

if ((PRINT_INSTALL_SUMMARY)); then
    printf '\nAdGuard Home admin credentials (save them now):\n'
    printf 'URL: https://%s/\nLogin: admin\nPassword: %s\n' "$DOMAIN" "$ADMIN_PASSWORD"
    printf 'Saved locally: %s (mode 0600)\n' "$CREDENTIALS_FILE"
    printf 'DoH URL: https://%s/doh/%s\n' "$DOMAIN" "$DOH_TOKEN"
    printf 'mobileconfig: https://%s/%s.mobileconfig\n' "$DOMAIN" "$DOH_TOKEN"
else
    printf 'Updated Smart DNS; existing AdGuard credentials were preserved.\n'
fi
