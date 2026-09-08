#!/usr/bin/env bash
set -eEuo pipefail

PROJECT_ROOT="${1:-/repo}"
DOMAIN=dns.example.com
PUBLIC_IP=203.0.113.10
MOCK_BIN=/tmp/adguardhome-doh-smoke-bin

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }

# The production entrypoint requires Python for release metadata and `ss` for
# the listener preflight.  A bare Ubuntu container omits both cloud-host tools.
if ! command -v python3 >/dev/null 2>&1 || ! command -v ss >/dev/null 2>&1; then
    apt-get update
    env DEBIAN_FRONTEND=noninteractive apt-get \
        -o Dpkg::Use-Pty=0 \
        install -y --no-install-recommends python3 iproute2
fi

mkdir -p "$MOCK_BIN"

cat > /usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 755 /usr/sbin/policy-rc.d

cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/adguardhome-doh-systemctl.log
stop_adguardhome() {
    local pid
    [[ -s /tmp/adguardhome-doh.pid ]] || return 0
    pid="$(</tmp/adguardhome-doh.pid)"
    kill "$pid" >/dev/null 2>&1 || true
    rm -f /tmp/adguardhome-doh.pid
}
start_adguardhome() {
    stop_adguardhome
    nohup /opt/AdGuardHome/AdGuardHome \
        -c /opt/AdGuardHome/AdGuardHome.yaml \
        -w /var/lib/AdGuardHome \
        >/tmp/adguardhome-doh-smoke.log 2>&1 &
    printf '%s\n' "$!" > /tmp/adguardhome-doh.pid
}
nginx_running() {
    [[ -s /run/nginx.pid ]] && kill -0 "$(</run/nginx.pid)" 2>/dev/null
}
case "$*" in
    "restart adguardhome-doh")
        start_adguardhome
        ;;
    "start nginx")
        nginx -t
        nginx_running || nginx
        ;;
    "stop nginx")
        if nginx_running; then
            nginx -s quit
            for _ in {1..50}; do
                nginx_running || break
                sleep 0.1
            done
        fi
        ;;
    "reload nginx")
        nginx -t
        if nginx_running; then
            nginx -s reload
        else
            nginx
        fi
        ;;
esac
if [[ "$*" == "start adguardhome-doh-health.service" ]]; then
    if [[ -e /tmp/adguardhome-doh-force-health-failure ]]; then
        exit 1
    fi
    grep -Fq 'restart adguardhome-doh' /tmp/adguardhome-doh-systemctl.log || exit 1
    touch /tmp/adguardhome-doh-health-started
fi
exit 0
EOF
chmod 755 "$MOCK_BIN/systemctl"

cat > "$MOCK_BIN/getent" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == ahostsv4 && "\${2:-}" == "$DOMAIN" ]]; then
    printf '%s STREAM %s\n' '$PUBLIC_IP' '$DOMAIN'
    exit 0
fi
exec /usr/bin/getent "\$@"
EOF
chmod 755 "$MOCK_BIN/getent"

cat > "$MOCK_BIN/certbot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
domain=
webroot=
webroot_path=
deploy_hook=
while (($#)); do
    case "$1" in
        -d) domain="$2"; shift 2 ;;
        --webroot) webroot=1; shift ;;
        --webroot-path) webroot_path="$2"; shift 2 ;;
        --deploy-hook) deploy_hook="$2"; shift 2 ;;
        --standalone|--pre-hook|--post-hook)
            printf 'certbot must not stop nginx to answer the challenge\n' >&2
            exit 1 ;;
        *) shift ;;
    esac
done
[[ -n "$domain" ]]
[[ "$webroot" == 1 ]]
[[ "$webroot_path" == /var/www/adguardhome-doh ]]
[[ "$deploy_hook" == "systemctl reload nginx" ]]
# The challenge directory has to be writable and served while nginx keeps
# running; a real HTTP-01 exchange fails otherwise.
mkdir -p "$webroot_path/.well-known/acme-challenge"
printf 'token\n' > "$webroot_path/.well-known/acme-challenge/smoke-token"
certificate_root="/etc/letsencrypt/live/$domain"
mkdir -p "$certificate_root"
/usr/bin/openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -subj "/CN=$domain" \
    -addext "subjectAltName=DNS:$domain" \
    -keyout "$certificate_root/privkey.pem" \
    -out "$certificate_root/fullchain.pem" >/dev/null 2>&1
install -m 644 "$certificate_root/fullchain.pem" \
    /usr/local/share/ca-certificates/adguardhome-doh-smoke.crt
update-ca-certificates >/dev/null
mkdir -p /etc/letsencrypt/renewal
cat > "/etc/letsencrypt/renewal/$domain.conf" <<PROFILE
version = 2.9.0
archive_dir = /etc/letsencrypt/archive/$domain
[renewalparams]
account = 0123456789abcdef
authenticator = standalone
pre_hook = systemctl stop nginx
post_hook = systemctl start nginx
PROFILE
EOF
chmod 755 "$MOCK_BIN/certbot"

export PATH="$MOCK_BIN:$PATH"
cd /root

# Existing servers may have a private default webroot.  The installer must not
# depend on or relax its permissions to serve the generated profile.
mkdir -p /var/www/html
chmod 700 /var/www/html

install_once() {
    "$PROJECT_ROOT/deploy/install.sh" \
        --domain "$DOMAIN" \
        --public-ip "$PUBLIC_IP" \
        --email admin@example.com \
        --yes
}

active_token() {
    grep -oE 'location = /doh/[a-f0-9]{32,64}' \
        /etc/nginx/sites-enabled/adguardhome-doh |
        sed 's#location = /doh/##'
}

install_once | tee /tmp/adguardhome-doh-first-install.out
test -e /tmp/adguardhome-doh-health-started
nginx -t
/opt/AdGuardHome/AdGuardHome --check-config \
    -c /opt/AdGuardHome/AdGuardHome.yaml \
    -w /var/lib/AdGuardHome
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -s /var/lib/adguardhome-doh/admin-credentials.json
test -f /var/lib/adguardhome-doh/install-complete
test "$(stat -c '%a' /var/www/adguardhome-doh)" = 755
first_token="$(active_token)"
test -n "$first_token"
test -s "/var/www/adguardhome-doh/$DOMAIN.mobileconfig"
grep -Fq 'Admin URL:' /tmp/adguardhome-doh-first-install.out

systemctl stop nginx
rm /var/lib/adguardhome-doh/install-complete
install_once | tee /tmp/adguardhome-doh-recovered-install.out
nginx -t
second_token="$(active_token)"
test "$second_token" = "$first_token"
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -f /var/lib/adguardhome-doh/install-complete
grep -Fq 'Admin URL:' /tmp/adguardhome-doh-recovered-install.out
grep -Fq "DoH URL: https://$DOMAIN/doh/$second_token" /tmp/adguardhome-doh-recovered-install.out
grep -Fq "mobileconfig URL: https://$DOMAIN/$second_token.mobileconfig" /tmp/adguardhome-doh-recovered-install.out

if [[ ! -s /run/nginx.pid ]]; then
    nginx
fi
trap 'nginx -s quit >/dev/null 2>&1 || true; if [[ -s /tmp/adguardhome-doh.pid ]]; then kill "$(</tmp/adguardhome-doh.pid)" >/dev/null 2>&1 || true; fi' EXIT
curl --fail --silent --show-error --insecure \
    --resolve "$DOMAIN:443:127.0.0.1" \
    --dump-header /tmp/adguardhome-doh-mobileconfig.headers \
    "https://$DOMAIN/$second_token.mobileconfig" \
    -o /tmp/adguardhome-doh.mobileconfig
grep -Fiq "Content-Disposition: attachment; filename=$DOMAIN.mobileconfig" \
    /tmp/adguardhome-doh-mobileconfig.headers
grep -Fq "https://$DOMAIN/doh/$second_token" /tmp/adguardhome-doh.mobileconfig
test "$(grep -Foc "<key>PayloadDisplayName</key><string>$DOMAIN</string>" \
    /tmp/adguardhome-doh.mobileconfig)" -eq 2
grep -Fq '<key>SupplementalMatchDomains</key>' /tmp/adguardhome-doh.mobileconfig
grep -Fq '<string>chatgpt.com</string>' /tmp/adguardhome-doh.mobileconfig
grep -Fq '<key>AllowFailover</key><true/>' /tmp/adguardhome-doh.mobileconfig
# The ClientID variant of the public path must be closed as well.
test "$(curl --silent --insecure --resolve "$DOMAIN:443:127.0.0.1" \
    --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/dns-query/smoke?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")" = 404
# Every connection above must have left a line in the stream access log, and
# the summary command must read it back.
grep -Fq 'nginx-stream.access.log' /etc/nginx/stream.d/adguardhome-doh.conf
test -f /etc/logrotate.d/adguardhome-doh
test -x /usr/local/sbin/adguardhome-doh-diag
sleep 7
/usr/local/sbin/adguardhome-doh-diag --minutes 5 | tee /tmp/adguardhome-doh-diag.out
grep -Eq '^connections=[1-9]' /tmp/adguardhome-doh-diag.out
grep -Fq "sni=$DOMAIN status=200" /var/log/adguardhome-doh/nginx-stream.access.log
! grep -Eq 'client=127\.0\.0\.1' /var/log/adguardhome-doh/nginx-stream.access.log
touch /tmp/adguardhome-doh-force-health-failure
if install_once >/tmp/adguardhome-doh-failed-health.out 2>&1; then
    printf 'installer ignored a failed health-check\n' >&2
    exit 1
fi
renewal_profile="/etc/letsencrypt/renewal/$DOMAIN.conf"
grep -Fq 'authenticator = webroot' "$renewal_profile"
grep -Fq "$DOMAIN = /var/www/adguardhome-doh" "$renewal_profile"
! grep -Fq 'pre_hook' "$renewal_profile"
! grep -Fq 'post_hook' "$renewal_profile"
test -f "$renewal_profile.pre-webroot"
grep -Eq '^[[:space:]]*worker_connections 8192;' /etc/nginx/nginx.conf
grep -Fq 'worker_rlimit_nofile 65535;' /etc/nginx/nginx.conf
grep -Fq 'Restart=on-failure' /etc/systemd/system/nginx.service.d/adguardhome-doh.conf
grep -Fq 'limit_req_zone $binary_remote_addr zone=adguardhome_doh_login' \
    /etc/nginx/sites-enabled/adguardhome-doh
grep -Fq 'auth_attempts: 0' /opt/AdGuardHome/AdGuardHome.yaml
grep -Fq 'cache_optimistic: true' /opt/AdGuardHome/AdGuardHome.yaml
grep -Fq 'upstream_timeout: 4s' /opt/AdGuardHome/AdGuardHome.yaml
grep -Fq 'blocked_response_ttl: 300' /opt/AdGuardHome/AdGuardHome.yaml
grep -Fq 'so_keepalive=30s:10s:3' /etc/nginx/stream.d/adguardhome-doh.conf
grep -Fq 'net.ipv4.tcp_mtu_probing = 1' /etc/sysctl.d/90-adguardhome-doh.conf
grep -Fq 'ADGUARDHOME_DOH_DOMAIN=dns.example.com' /etc/adguardhome-doh/runtime.env

# Relay mode renders and validates like an ordinary installation.
"$PROJECT_ROOT/deploy/install.sh" --domain "$DOMAIN" --public-ip "$PUBLIC_IP" \
    --email admin@example.com --relay 203.0.113.99 \
    --root /tmp/adguardhome-doh-relay --dry-run > /tmp/adguardhome-doh-relay.out
grep -Fq 'dry-run завершён' /tmp/adguardhome-doh-relay.out
"$PROJECT_ROOT/deploy/install.sh" --domain "$DOMAIN" --public-ip "$PUBLIC_IP" \
    --email admin@example.com --local-site app.example.org=127.0.0.1:9443 \
    --local-site '*=127.0.0.1:9443' --root /tmp/adguardhome-doh-front --dry-run \
    > /tmp/adguardhome-doh-front.out
grep -Fq 'dry-run завершён' /tmp/adguardhome-doh-front.out

printf 'ubuntu 26.04 install smoke: ok\n'
