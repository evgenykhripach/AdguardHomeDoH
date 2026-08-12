#!/usr/bin/env bash
set -eEuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/ui.sh
source "$SCRIPT_DIR/lib/ui.sh"

ADGUARD_VERSION="${ADGUARDHOME_DOH_ADGUARD_VERSION:-0.107.78}"
REPOSITORY="${ADGUARDHOME_DOH_REPOSITORY:-evgenykhripach/AdguardHomeDoH}"
ROOT=/
DOMAIN=
PUBLIC_IP=
EMAIL=
SERVICES=
POLICY="$PROJECT_ROOT/config/policy.csv"
POLICY_ARGUMENT=0
DRY_RUN=0
YES=0
UPDATE=0
ROLLBACK=0
INTERACTIVE_INPUT=0
SERVICES_ARGUMENT=0

usage() {
    cat <<'EOF'
usage: install.sh [options]
  --domain HOST       public DNS hostname (prompted when omitted)
  --public-ip IPV4    public IPv4 address (prompted when omitted)
  --email EMAIL       certificate contact (prompted when omitted)
  --services IDS      comma-separated stable service IDs
  --policy PATH       compatibility policy CSV (default: catalog rendering)
  --root PATH         isolated root for dry-run tests
  --dry-run           validate and print activation plan without writing
  --yes               skip confirmation when all required values are flags
  --update            reserved for the management command
  --rollback          reserved for the management command
EOF
}

while (($#)); do
    case "$1" in
        --domain)
            (($# >= 2)) || adguardhome_doh_die "--domain requires a value"
            DOMAIN="$2"; shift 2 ;;
        --public-ip)
            (($# >= 2)) || adguardhome_doh_die "--public-ip requires a value"
            PUBLIC_IP="$2"; shift 2 ;;
        --email)
            (($# >= 2)) || adguardhome_doh_die "--email requires a value"
            EMAIL="$2"; shift 2 ;;
        --services)
            (($# >= 2)) || adguardhome_doh_die "--services requires a value"
            SERVICES="$2"; SERVICES_ARGUMENT=1; shift 2 ;;
        --policy)
            (($# >= 2)) || adguardhome_doh_die "--policy requires a value"
            POLICY="$2"; POLICY_ARGUMENT=1; shift 2 ;;
        --root)
            (($# >= 2)) || adguardhome_doh_die "--root requires a value"
            ROOT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes) YES=1; shift ;;
        --update) UPDATE=1; shift ;;
        --rollback) ROLLBACK=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; adguardhome_doh_die "unknown argument: $1" ;;
    esac
done

ROOT="$(adguardhome_doh_abs_root "$ROOT")"
STATE_DIR="$(adguardhome_doh_under_root "$ROOT" /var/lib/adguardhome-doh)"
CONFIG_DIR="$(adguardhome_doh_under_root "$ROOT" /etc/adguardhome-doh)"
CREDENTIALS_FILE="$STATE_DIR/admin-credentials.json"
DOH_TOKEN_FILE="$STATE_DIR/doh-token"
INSTALL_STATE_FILE="$STATE_DIR/install.json"
ENABLED_SERVICES_FILE="$STATE_DIR/enabled-services.json"
INSTALL_COMPLETE_FILE="$STATE_DIR/install-complete"
BACKUP_ROOT="$(adguardhome_doh_under_root "$ROOT" /var/backups/adguardhome-doh)"
WEBROOT="$(adguardhome_doh_under_root "$ROOT" /var/www/adguardhome-doh)"
LOG_PATH="$(adguardhome_doh_under_root "$ROOT" /var/log/adguardhome-doh/install-$(date -u +%Y%m%dT%H%M%SZ).log)"
VERSION_FILE="$PROJECT_ROOT/VERSION"

adguardhome_doh_default_services() {
    python3 - "$PROJECT_ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.render_config import Catalog
print(",".join(Catalog.load(Path(sys.argv[1]) / "config").default_service_ids))
PY
}

adguardhome_doh_confirm_install() {
    local answer
    while :; do
        adguardhome_doh_read_tty answer $'\nПродолжить установку? [y/N]: ' || return $?
        answer="$ADGUARDHOME_DOH_READ_VALUE"
        answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
        case "$answer" in
            y|yes|д|да) return 0 ;;
            n|no|н|нет|c|q|cancel|отмена) adguardhome_doh_ui_error "установка отменена"; return 2 ;;
            *) adguardhome_doh_ui_error "введите y или n" ;;
        esac
    done
}

adguardhome_doh_prompt_missing_values() {
    if [[ -z "$DOMAIN" ]]; then
        adguardhome_doh_prompt_value DOMAIN $'Домен (например, dns.example.com): ' adguardhome_doh_validate_hostname || return $?
        INTERACTIVE_INPUT=1
    else
        adguardhome_doh_validate_hostname "$DOMAIN" || adguardhome_doh_die "invalid hostname: $DOMAIN"
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        adguardhome_doh_prompt_value PUBLIC_IP $'Публичный IPv4: ' adguardhome_doh_validate_ipv4 || return $?
        INTERACTIVE_INPUT=1
    else
        adguardhome_doh_validate_ipv4 "$PUBLIC_IP" || adguardhome_doh_die "invalid IPv4: $PUBLIC_IP"
    fi
    if [[ -z "$EMAIL" ]]; then
        adguardhome_doh_prompt_value EMAIL $'Email для сертификата: ' adguardhome_doh_validate_email || return $?
        INTERACTIVE_INPUT=1
    else
        adguardhome_doh_validate_email "$EMAIL" || adguardhome_doh_die "invalid email: $EMAIL"
    fi
}

adguardhome_doh_prepare_services() {
    local selected
    if ((SERVICES_ARGUMENT)); then
        SERVICES="$(adguardhome_doh_validate_services "$PROJECT_ROOT" "$SERVICES")" ||             adguardhome_doh_die "invalid --services selection"
    elif ((INTERACTIVE_INPUT)) && adguardhome_doh_ui_tty; then
        selected="$(adguardhome_doh_select_services "$PROJECT_ROOT/config")" || {
            local status=$?
            (( status == 2 )) && exit 2
            adguardhome_doh_die "service selection failed"
        }
        SERVICES="$selected"
    else
        SERVICES="$(adguardhome_doh_default_services)"
    fi
}

adguardhome_doh_summary() {
    local log_path="$1" token="$2" password="$3" credentials="$4"
    printf '\nAdGuard Home DoH installation summary:\n'
    printf 'Admin URL: https://%s/\n' "$DOMAIN"
    printf 'Login: admin\n'
    printf 'Password: %s\n' "$password"
    printf 'DoH URL: https://%s/doh/%s\n' "$DOMAIN" "$token"
    printf 'mobileconfig URL: https://%s/%s.mobileconfig\n' "$DOMAIN" "$token"
    printf 'Credentials path: %s\n' "$credentials"
    printf 'Install log: %s\n' "$log_path"
    printf 'Management: sudo adguardhome-doh\n'
}

adguardhome_doh_render_dry_run() {
    local output status
    output="$(mktemp -d)"
    if ((POLICY_ARGUMENT)); then
        if python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"             --policy "$POLICY" --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN"             --doh-token "$(printf '%048d' 0 | tr 0 a)" --password-hash 'dry-run-hash'             --certificate-root "/etc/letsencrypt/live/$DOMAIN" --webroot "$WEBROOT" --output "$output"; then
            status=0
        else
            status=$?
        fi
    else
        if python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"             --config-dir "$PROJECT_ROOT/config" --services "$SERVICES"             --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN"             --doh-token "$(printf '%048d' 0 | tr 0 a)" --password-hash 'dry-run-hash'             --certificate-root "/etc/letsencrypt/live/$DOMAIN" --webroot "$WEBROOT" --output "$output"; then
            status=0
        else
            status=$?
        fi
    fi
    rm -rf -- "$output"
    return "$status"
}

adguardhome_doh_progress 0 'проверка параметров'
adguardhome_doh_prompt_missing_values || exit $?
if ((POLICY_ARGUMENT && SERVICES_ARGUMENT)); then
    adguardhome_doh_die "--policy and --services cannot be combined"
fi
adguardhome_doh_prepare_services
if ((POLICY_ARGUMENT)); then
    [[ -f "$POLICY" ]] || adguardhome_doh_die "policy not found: $POLICY"
fi
adguardhome_doh_progress 5 'параметры приняты'

if ((INTERACTIVE_INPUT)) && ((SERVICES_ARGUMENT)); then
    adguardhome_doh_confirm_install || exit $?
elif ((INTERACTIVE_INPUT == 0 && YES == 0 && DRY_RUN == 0)) && adguardhome_doh_ui_tty; then
    adguardhome_doh_confirm_install || exit $?
fi

if ((DRY_RUN)); then
    adguardhome_doh_progress 20 'проверка каталога сервисов'
    adguardhome_doh_render_dry_run
    adguardhome_doh_progress 35 'проверка конфигурации'
    adguardhome_doh_progress 50 'планирование пакетов'
    adguardhome_doh_progress 65 'планирование AdGuard Home'
    adguardhome_doh_progress 75 'планирование nginx'
    adguardhome_doh_progress 85 'планирование сертификата'
    adguardhome_doh_progress 95 'подготовка итогов'
    adguardhome_doh_progress 100 'dry-run завершён'
    adguardhome_doh_summary "$LOG_PATH" 'dry-run-token-not-created' 'dry-run-password-not-created' "$CREDENTIALS_FILE"
    exit 0
fi

if ((YES == 0)) && ! adguardhome_doh_ui_tty; then
    adguardhome_doh_die "non-interactive installation requires --yes"
fi

((ROLLBACK)) && adguardhome_doh_die "rollback is available through sudo adguardhome-doh"
adguardhome_doh_require_root
[[ "$ROOT" == / ]] || adguardhome_doh_die "non-root installation only supports --dry-run"
command -v systemctl >/dev/null 2>&1 || adguardhome_doh_die "systemd is required"
adguardhome_doh_require_ubuntu
adguardhome_doh_init_log /
LOG_PATH="$ADGUARDHOME_DOH_LOG_PATH"
adguardhome_doh_run_logged adguardhome_doh_preflight / "$DOMAIN" "$PUBLIC_IP"
adguardhome_doh_progress 20 'предварительная проверка завершена'

adguardhome_doh_run_logged apt-get update
mapfile -t required_packages < <(adguardhome_doh_required_packages)
adguardhome_doh_run_logged env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${required_packages[@]}"
adguardhome_doh_progress 35 'зависимости установлены'

mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT" "$WEBROOT" /etc/nginx/stream.d /etc/adguardhome-doh
chmod 700 "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT"
chmod 755 "$WEBROOT"
mkdir -p "$CONFIG_DIR/catalog"
for catalog_file in services.csv domains.csv service-domains.csv service-probes.csv; do
    install -m 640 "$PROJECT_ROOT/config/$catalog_file" "$CONFIG_DIR/catalog/$catalog_file"
done
if ! id adguardhome >/dev/null 2>&1; then
    adguardhome_doh_run_logged useradd --system --home-dir /var/lib/AdGuardHome --create-home --shell /usr/sbin/nologin adguardhome
fi

if [[ ! -x /opt/AdGuardHome/AdGuardHome ]]; then
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    arch="$(adguardhome_doh_arch)"
    archive="AdGuardHome_linux_${arch}.tar.gz"
    adguardhome_doh_run_logged curl --fail --silent --show-error --location         "https://github.com/AdguardTeam/AdGuardHome/releases/download/v${ADGUARD_VERSION}/${archive}"         -o "$work/$archive"
    adguardhome_doh_run_logged curl --fail --silent --show-error --location         "https://github.com/AdguardTeam/AdGuardHome/releases/download/v${ADGUARD_VERSION}/checksums.txt"         -o "$work/checksums.txt"
    checksum="$(adguardhome_doh_find_checksum "$work/checksums.txt" "$archive")"
    [[ "$checksum" =~ ^[0-9a-fA-F]{64}$ ]] || adguardhome_doh_die "AdGuard checksum missing for $archive"
    adguardhome_doh_run_logged sh -c "printf '%s  %s\\n' '$checksum' '$work/$archive' | sha256sum -c -"
    adguardhome_doh_run_logged tar -xzf "$work/$archive" -C "$work"
    adguard_binary="$(adguardhome_doh_find_binary "$work")"
    [[ -n "$adguard_binary" ]] || adguardhome_doh_die "AdGuard binary missing after extraction"
    mkdir -p /opt/AdGuardHome
    chmod 755 /opt/AdGuardHome
    install -m 755 "$adguard_binary" /opt/AdGuardHome/AdGuardHome
fi
adguardhome_doh_progress 50 'AdGuard Home подготовлен'

if [[ -f "$CREDENTIALS_FILE" ]]; then
    ADMIN_PASSWORD="$(python3 "$SCRIPT_DIR/lib/credentials.py" --path "$CREDENTIALS_FILE" --read --field password)"
else
    ADMIN_PASSWORD="$(openssl rand -hex 24)"
fi
ADGUARDHOME_DOH_ADMIN_PASSWORD="$ADMIN_PASSWORD"
ADMIN_HASH="$(htpasswd -bnBC 10 admin "$ADMIN_PASSWORD" | tr -d '\r' | cut -d: -f2-)"
ADGUARDHOME_DOH_ADMIN_HASH="$ADMIN_HASH"
DOH_TOKEN="$(adguardhome_doh_load_or_create_doh_token "$DOH_TOKEN_FILE")"
ADGUARDHOME_DOH_DOH_TOKEN="$DOH_TOKEN"
CERT_ROOT="/etc/letsencrypt/live/$DOMAIN"
PROFILE_ID="$(openssl rand -hex 4)-$(openssl rand -hex 2)-4$(openssl rand -hex 1)-a$(openssl rand -hex 1)-$(openssl rand -hex 6)"
PAYLOAD_ID="$(openssl rand -hex 4)-$(openssl rand -hex 2)-4$(openssl rand -hex 1)-b$(openssl rand -hex 1)-$(openssl rand -hex 6)"
stage="$(mktemp -d "$STATE_DIR/.stage.XXXXXX")"
backup="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"; chmod 700 "$backup"
adguardhome_doh_backup /opt/AdGuardHome/AdGuardHome.yaml "$backup/AdGuardHome.yaml"
adguardhome_doh_backup /etc/nginx/sites-enabled/adguardhome-doh "$backup/nginx-http.conf"
adguardhome_doh_backup /etc/nginx/stream.d/adguardhome-doh.conf "$backup/nginx-stream.conf"

if ((POLICY_ARGUMENT)); then
    adguardhome_doh_run_logged python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"         --policy "$POLICY" --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN"         --doh-token "$DOH_TOKEN" --password-hash "$ADMIN_HASH"         --certificate-root "$CERT_ROOT" --webroot "$WEBROOT" --output "$stage"
else
    adguardhome_doh_run_logged python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"         --config-dir "$PROJECT_ROOT/config" --services "$SERVICES"         --public-ip "$PUBLIC_IP" --doh-host "$DOMAIN"         --doh-token "$DOH_TOKEN" --password-hash "$ADMIN_HASH"         --certificate-root "$CERT_ROOT" --webroot "$WEBROOT" --output "$stage"
fi
adguardhome_doh_progress 65 'конфигурация подготовлена'

install -m 640 "$stage/AdGuardHome.yaml" /opt/AdGuardHome/AdGuardHome.yaml
install -m 644 "$stage/nginx-stream.conf" /etc/nginx/stream.d/adguardhome-doh.conf
cat > "$WEBROOT/$DOH_TOKEN.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict><key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>https://$DOMAIN/doh/$DOH_TOKEN</string></dict>
<key>PayloadDisplayName</key><string>AdGuard Home DoH</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.$PAYLOAD_ID</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadType</key><string>com.apple.dnsSettings.managed</string><key>PayloadUUID</key><string>$PAYLOAD_ID</string><key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>AdGuard Home DoH</string><key>PayloadIdentifier</key><string>com.adguardhome.doh.$PROFILE_ID</string><key>PayloadOrganization</key><string>AdGuard Home DoH</string><key>PayloadRemovalDisallowed</key><false/><key>PayloadType</key><string>Configuration</string><key>PayloadUUID</key><string>$PROFILE_ID</string><key>PayloadVersion</key><integer>1</integer>
</dict></plist>
EOF
adguardhome_doh_ensure_nginx_stream_include
cat > /etc/nginx/sites-enabled/adguardhome-doh <<EOF
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

cat > /etc/systemd/system/adguardhome-doh.service <<'UNIT'
[Unit]
Description=AdGuard Home DoH DNS
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
adguardhome_doh_run_logged adguardhome_doh_install_health_templates / "$PROJECT_ROOT"
install -m 640 "$stage/health-policy.json" "$CONFIG_DIR/health-policy.json"
cat > /etc/adguardhome-doh/runtime.env <<EOF
ADGUARDHOME_DOH_AGH_URL=http://127.0.0.1:3001
ADGUARDHOME_DOH_POLICY=$CONFIG_DIR/health-policy.json
ADGUARDHOME_DOH_STATE=$STATE_DIR/health-state.json
ADGUARDHOME_DOH_CREDENTIALS=$CREDENTIALS_FILE
ADGUARDHOME_DOH_PUBLIC_IP=$PUBLIC_IP
ADGUARDHOME_DOH_SUCCESS_THRESHOLD=3
ADGUARDHOME_DOH_FAILURE_THRESHOLD=2
EOF
chmod 600 /etc/adguardhome-doh/runtime.env

if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    python3 "$SCRIPT_DIR/lib/credentials.py" --path "$CREDENTIALS_FILE"         --url "https://$DOMAIN/" --password "$ADMIN_PASSWORD" >/dev/null
fi
python3 - "$SCRIPT_DIR/lib/state.py" "$INSTALL_STATE_FILE" "$DOMAIN" "$PUBLIC_IP" "$EMAIL" "$ADGUARD_VERSION" "$REPOSITORY" "$ENABLED_SERVICES_FILE" "$SERVICES" <<'PY'
import importlib.util
import sys
from pathlib import Path

module_path, install_path, domain, public_ip, email, version, repository, services_path, services = sys.argv[1:]
spec = importlib.util.spec_from_file_location("adguardhome_doh_state", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.save_install_state(Path(install_path), domain=domain, public_ip=public_ip, email=email,
                          version=version, repository=repository)
module.save_enabled_services(Path(services_path), [item for item in services.split(",") if item])
PY
adguardhome_doh_progress 75 'состояние и профили сохранены'

adguardhome_doh_run_logged systemctl daemon-reload
adguardhome_doh_run_logged nginx -t
adguardhome_doh_run_logged systemctl enable adguardhome-doh nginx
adguardhome_doh_run_logged systemctl restart adguardhome-doh
adguardhome_doh_run_logged systemctl start nginx
adguardhome_doh_run_logged systemctl reload nginx
adguardhome_doh_progress 85 'службы запущены'
if [[ ! -f "$CERT_ROOT/fullchain.pem" ]]; then
    mapfile -t certbot_contact_args < <(adguardhome_doh_certbot_contact_args "$EMAIL")
    adguardhome_doh_run_logged certbot certonly --standalone -d "$DOMAIN"         "${certbot_contact_args[@]}" --pre-hook 'systemctl stop nginx'         --post-hook 'systemctl start nginx' --agree-tos --non-interactive --keep-until-expiring
fi
install -m 644 "$stage/nginx-http.conf" /etc/nginx/sites-enabled/adguardhome-doh
adguardhome_doh_run_logged nginx -t
adguardhome_doh_run_logged systemctl reload nginx
adguardhome_doh_run_logged systemctl enable --now adguardhome-doh-health.timer
adguardhome_doh_run_logged systemctl start adguardhome-doh-health.service
rm -rf -- "$stage"
install -m 600 /dev/null "$INSTALL_COMPLETE_FILE"
adguardhome_doh_progress 95 'сертификат и DoH активированы'
adguardhome_doh_progress 100 'установка завершена'
adguardhome_doh_summary "$LOG_PATH" "$DOH_TOKEN" "$ADMIN_PASSWORD" "$CREDENTIALS_FILE"
