#!/usr/bin/env bash
set -eEuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/ui.sh
source "$SCRIPT_DIR/lib/ui.sh"

ADGUARD_VERSION="${ADGUARDHOME_DOH_ADGUARD_VERSION:-0.107.79}"
REPOSITORY="${ADGUARDHOME_DOH_REPOSITORY:-evgenykhripach/AdguardHomeDoH}"
REPOSITORY_ARGUMENT=0
[[ -n "${ADGUARDHOME_DOH_REPOSITORY+x}" ]] && REPOSITORY_ARGUMENT=1
ROOT=/
FRONT=standard
FRONT_ARGUMENT=0
SAVED_FRONT=standard
DOMAIN=
ADMIN_HOST=
ADMIN_HOST_ARGUMENT=0
ADMIN_HOST_ARGS=()
PUBLIC_IP=
RELAY=
RELAY_ARGUMENT=0
RELAY_ARGS=()
LOCAL_SITES=()
LOCAL_SITE_ARGUMENT=0
LOCAL_SITE_ARGS=()
EMAIL=
SERVICES=
POLICY="$PROJECT_ROOT/config/policy.csv"
POLICY_ARGUMENT=0
POLICY_INHERITED=0
POLICY_LEGACY_RECOVERED=0
DRY_RUN=0
YES=0
UPDATE=0
ROLLBACK=0
INTERACTIVE_INPUT=0
SERVICES_ARGUMENT=0
ADGUARDHOME_DOH_WORK_DIR=
ADGUARDHOME_DOH_BINARY_BACKUP=
ADGUARDHOME_DOH_BINARY_TARGET=/opt/AdGuardHome/AdGuardHome
ADGUARDHOME_DOH_LOCK_PATH=/run/lock/adguardhome-doh-health.lock
ADGUARDHOME_DOH_OPERATION_LOCK_PATH=/run/lock/adguardhome-doh-operations.lock
ADGUARDHOME_DOH_OPERATION_LOCK_HELD=0
ADGUARDHOME_DOH_LOCK_HELD=0
ADGUARDHOME_DOH_SNAPSHOT=
ADGUARDHOME_DOH_MUTATIONS=0
ADGUARDHOME_DOH_RUNTIME_TOUCHED=0
ADGUARDHOME_DOH_DIRECTORY_CAPTURED=0
ADGUARDHOME_DOH_STAGE=
ADGUARDHOME_DOH_MOBILECONFIG_TEMP=
ADGUARDHOME_DOH_NGINX_TEMP=
ADGUARDHOME_DOH_NEW_CERTBOT_LINEAGE=0
ADGUARDHOME_DOH_HEALTH_PAUSED=0
ADGUARDHOME_DOH_LEGACY_POLICY_TEMP=
trap adguardhome_doh_install_exit EXIT

usage() {
    cat <<'EOF'
usage: install.sh [options]
  --domain HOST       public DNS hostname (prompted when omitted)
  --public-ip IPV4    public IPv4 address (prompted when omitted)
  --relay IPV4        forward routed services to this exit host instead of the sites
  --local-site H=A    serve an existing site behind the listener: HOST=IPV4:PORT,
                      repeatable; *=IPV4:PORT sets the target for unknown SNI
  --front MODE       listener front: standard or mtproxyl
  --admin-host HOST  separate admin hostname (mtproxyl only)
  --repository REPO   GitHub repository for releases (owner/name)
  --email EMAIL       certificate contact (prompted when omitted)
  --services IDS      comma-separated stable service IDs
  --policy PATH       compatibility policy CSV (default: catalog rendering)
  --root PATH         isolated root for dry-run tests
  --dry-run           validate and print activation plan without writing
  --yes               skip confirmation when all required values are flags
  --update            preserve existing installation settings while updating
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
        --front)
            (($# >= 2)) || adguardhome_doh_die "--front requires a value"
            case "$2" in standard|mtproxyl) FRONT="$2" ;; *) adguardhome_doh_die "invalid --front: $2" ;; esac
            FRONT_ARGUMENT=1; shift 2 ;;
        --admin-host)
            (($# >= 2)) || adguardhome_doh_die "--admin-host requires a value"
            ADMIN_HOST="$2"; ADMIN_HOST_ARGUMENT=1; shift 2 ;;
        --relay)
            (($# >= 2)) || adguardhome_doh_die "--relay requires a value"
            RELAY="$2"; RELAY_ARGUMENT=1; shift 2 ;;
        --local-site)
            (($# >= 2)) || adguardhome_doh_die "--local-site requires a value"
            LOCAL_SITES+=("$2"); LOCAL_SITE_ARGUMENT=1; shift 2 ;;
        --repository)
            (($# >= 2)) || adguardhome_doh_die "--repository requires a value"
            REPOSITORY="$2"; REPOSITORY_ARGUMENT=1; shift 2 ;;
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

# A manager supplies a historical copy of these flags while downloading the
# release. Its sentinel makes the on-disk state authoritative instead.
if ((UPDATE)) && [[ "${ADGUARDHOME_DOH_MANAGER_UPDATE:-0}" == 1 ]]; then
    REPOSITORY_ARGUMENT=0
    RELAY_ARGUMENT=0
    LOCAL_SITE_ARGUMENT=0
    POLICY_ARGUMENT=0
    SERVICES_ARGUMENT=0
    FRONT_ARGUMENT=0
    ADMIN_HOST_ARGUMENT=0
    POLICY="$PROJECT_ROOT/config/policy.csv"
fi

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
PROJECT_VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$PROJECT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || adguardhome_doh_die "invalid project VERSION: $PROJECT_VERSION"

adguardhome_doh_update_input_digest() {
    python3 - "$INSTALL_STATE_FILE" "$ENABLED_SERVICES_FILE" "$CONFIG_DIR/health-policy.json" <<'PY'
import hashlib
import sys
from pathlib import Path
digest = hashlib.sha256()
for name in sys.argv[1:]:
    try:
        value = Path(name).read_bytes()
    except FileNotFoundError:
        value = None
    if value is None:
        digest.update(b"missing\0")
    else:
        digest.update(b"file\0" + len(value).to_bytes(8, "big") + value)
print(digest.hexdigest())
PY
}

adguardhome_doh_load_update_options() {
    local values value
    local -a saved
    ((UPDATE)) || return 0
    if [[ ! -e "$INSTALL_STATE_FILE" && ! -L "$INSTALL_STATE_FILE" ]]; then
        [[ "${ADGUARDHOME_DOH_MANAGER_UPDATE:-0}" != 1 ]] || \
            adguardhome_doh_die "manager update requires existing installation state"
        return 0
    fi
    values="$(python3 - "$SCRIPT_DIR/lib/state.py" "$INSTALL_STATE_FILE" <<'PY'
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("installer_state", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    state = module.load_install_state(Path(sys.argv[2]))
    fields = [state["repository"], state.get("relay", ""), state["public_ip"], state.get("policy", ""),
              state["domain"], state["email"], state.get("front", "standard"), state.get("admin_host", ""),
              *state.get("local_sites", [])]
    if any("\n" in item or "\r" in item for item in fields):
        raise ValueError("invalid newline in saved installation settings")
    print("\n".join(fields))
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
PY
)" || adguardhome_doh_die "cannot load existing installation settings"
    saved=()
    while IFS= read -r value; do saved+=("$value"); done <<< "$values"
    ((REPOSITORY_ARGUMENT)) || REPOSITORY="${saved[0]}"
    ((RELAY_ARGUMENT)) || RELAY="${saved[1]}"
    EXISTING_PUBLIC_IP="${saved[2]}"
    SAVED_FRONT="${saved[6]}"
    ((FRONT_ARGUMENT)) || FRONT="$SAVED_FRONT"
    ((ADMIN_HOST_ARGUMENT)) || ADMIN_HOST="${saved[7]:-}"
    if [[ "${ADGUARDHOME_DOH_MANAGER_UPDATE:-0}" == 1 ]]; then
        DOMAIN="${saved[4]}"
        PUBLIC_IP="${saved[2]}"
        EMAIL="${saved[5]}"
    fi
    if ((POLICY_ARGUMENT == 0)) && [[ -n "${saved[3]:-}" ]]; then
        POLICY="$(adguardhome_doh_under_root "$ROOT" "${saved[3]}")"
        POLICY_ARGUMENT=1
        POLICY_INHERITED=1
        SERVICES_ARGUMENT=0
    fi
    ((LOCAL_SITE_ARGUMENT)) || LOCAL_SITES=("${saved[@]:8}")
}

EXISTING_PUBLIC_IP=
ADGUARDHOME_DOH_UPDATE_INPUT_DIGEST=
if ((UPDATE)); then
    ADGUARDHOME_DOH_UPDATE_INPUT_DIGEST="$(adguardhome_doh_update_input_digest)" || \
        adguardhome_doh_die "cannot read existing update settings"
fi
adguardhome_doh_load_update_options

# Until the shared-front activation is implemented, also refuse replacing an
# existing shared installation via a direct, non-update standard invocation.
if ((UPDATE == 0 && DRY_RUN == 0)) && [[ -e "$INSTALL_STATE_FILE" || -L "$INSTALL_STATE_FILE" ]]; then
    SAVED_FRONT="$(python3 - "$SCRIPT_DIR/lib/state.py" "$INSTALL_STATE_FILE" <<'PY'
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("installer_state", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    print(module.load_install_state(Path(sys.argv[2])).get("front", "standard"))
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
PY
)" || adguardhome_doh_die "cannot load existing installation settings"
fi
if ((DRY_RUN == 0)) && [[ "$FRONT" == mtproxyl || "$SAVED_FRONT" == mtproxyl ]]; then
    adguardhome_doh_die "совместный front MTProxyL ещё не активирован; доступен только --dry-run"
fi

POLICY_CATALOG_ARGS=()
[[ "$FRONT" == mtproxyl ]] && POLICY_CATALOG_ARGS=(--config-dir "$PROJECT_ROOT/config")

adguardhome_doh_load_legacy_policy() {
    local found
    ((UPDATE && POLICY_ARGUMENT == 0)) || return 0
    [[ -f "$CONFIG_DIR/health-policy.json" ]] || return 0
    ADGUARDHOME_DOH_LEGACY_POLICY_TEMP="$(mktemp "${TMPDIR:-/tmp}/adguardhome-doh-legacy-policy.XXXXXX")"
    found="$(python3 - "$CONFIG_DIR/health-policy.json" "$ADGUARDHOME_DOH_LEGACY_POLICY_TEMP" "$PROJECT_ROOT" <<'PY'
import csv
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from tools.render_config import load_policy
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        policy = json.load(stream)
    if not isinstance(policy, dict) or policy.get("services") != {}:
        raise SystemExit(0)
    rows = policy.get("domains")
    if not isinstance(rows, list) or not rows:
        raise ValueError("legacy policy has no domains")
    with open(sys.argv[2], "w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("domain", "kind", "probe"))
        for row in rows:
            if not isinstance(row, dict) or any(not isinstance(row.get(key), str)
                                                for key in ("domain", "kind", "probe")):
                raise ValueError("invalid legacy policy domain")
            writer.writerow((row["domain"], row["kind"], row["probe"]))
    load_policy(Path(sys.argv[2]))
    print("legacy")
except (OSError, ValueError, TypeError) as exc:
    print("cannot recover existing policy: %s" % exc, file=sys.stderr)
    raise SystemExit(1)
PY
)" || adguardhome_doh_die "cannot recover legacy compatibility policy"
    if [[ "$found" == legacy ]]; then
        POLICY="$ADGUARDHOME_DOH_LEGACY_POLICY_TEMP"
        POLICY_ARGUMENT=1
        POLICY_INHERITED=1
        POLICY_LEGACY_RECOVERED=1
        SERVICES_ARGUMENT=0
    else
        rm -f -- "$ADGUARDHOME_DOH_LEGACY_POLICY_TEMP"
        ADGUARDHOME_DOH_LEGACY_POLICY_TEMP=
    fi
}

adguardhome_doh_load_legacy_policy

adguardhome_doh_load_saved_services() {
    # A direct update must preserve the selected services too.  An explicit
    # --services option still overrides the saved selection.
    ((UPDATE && POLICY_ARGUMENT == 0 && SERVICES_ARGUMENT == 0)) || return 0
    if [[ -e "$ENABLED_SERVICES_FILE" || -L "$ENABLED_SERVICES_FILE" ]]; then
        SERVICES="$(python3 - "$SCRIPT_DIR/lib/state.py" "$ENABLED_SERVICES_FILE" <<'PY'
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("installer_state", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    print(",".join(module.load_enabled_services(Path(sys.argv[2]))))
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
PY
)" || adguardhome_doh_die "cannot load current enabled services"
    else
        SERVICES=
    fi
    [[ -n "$SERVICES" ]] || SERVICES="$(adguardhome_doh_default_services)"
    SERVICES_ARGUMENT=1
}

adguardhome_doh_default_services() {
    python3 - "$PROJECT_ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.render_config import Catalog
print(",".join(Catalog.load(Path(sys.argv[1]) / "config").default_service_ids))
PY
}

adguardhome_doh_healthy_services() {
    # Services the gate had already proven healthy before this activation.
    local state_file="$1"
    [[ -f "$state_file" ]] || return 0
    python3 - "$state_file" <<'HEALTHY' || true
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        state = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(0)
if not isinstance(state, dict):
    raise SystemExit(0)
print(",".join(
    str(service_id)
    for service_id, item in sorted(state.items())
    if isinstance(item, dict) and item.get("healthy") is True
))
HEALTHY
}

adguardhome_doh_confirm_install() {
    local answer
    printf '\nПараметры установки:\n'
    printf 'Домен: %s\nПубличный IPv4: %s\nEmail: %s\n' "$DOMAIN" "$PUBLIC_IP" "$EMAIL"
    printf 'Relay: %s\n' "${RELAY:-нет}"
    printf 'Front: %s\n' "$FRONT"
    [[ -z "$ADMIN_HOST" ]] || printf 'Admin URL: https://%s/\n' "$ADMIN_HOST"
    printf 'Локальные сайты: %s\n' "${LOCAL_SITES_CSV:-нет}"
    if ((POLICY_LEGACY_RECOVERED)); then
        printf 'Политика: восстановлена из предыдущей установки\n'
    elif ((POLICY_ARGUMENT)); then
        printf 'Политика: %s\n' "$POLICY"
    else
        printf 'Сервисы: %s\n' "$SERVICES"
    fi
    printf 'Репозиторий: %s\n' "$REPOSITORY"
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
        DOMAIN="$(printf '%s' "$DOMAIN" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
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
    if ((POLICY_ARGUMENT)); then
        SERVICES="$(adguardhome_doh_default_services)"
    elif ((SERVICES_ARGUMENT)); then
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
    printf 'Front: %s\n' "$FRONT"
    printf 'Admin URL: https://%s/\n' "${ADMIN_HOST:-$DOMAIN}"
    printf 'Login: admin\n'
    printf 'Password: %s\n' "$password"
    printf 'DoH URL: https://%s/doh/%s\n' "$DOMAIN" "$token"
    printf 'mobileconfig URL: https://%s/%s.mobileconfig\n' "$DOMAIN" "$token"
    printf 'Credentials path: %s\n' "$credentials"
    printf 'Install log: %s\n' "$log_path"
    printf 'Management: sudo adguardhome-doh\n'
}

adguardhome_doh_update_summary() {
    local log_path="$1"
    printf '\nОбновление adguardhome-doh завершено.\n'
    [[ -z "$ADMIN_HOST" ]] || printf 'Admin URL: https://%s/\n' "$ADMIN_HOST"
    printf 'Данные доступа: пункт 1 меню менеджера.\n'
    printf 'Install log: %s\n' "$log_path"
    printf 'Management: sudo adguardhome-doh\n'
    printf 'Если в каталоге появились новые домены, скачайте и переустановите Apple-профиль.\n'
}

adguardhome_doh_render_dry_run() {
    local output status use_existing="${1:-0}"
    local -a existing_args=()
    if ((use_existing && UPDATE)) && [[ -f "$(adguardhome_doh_under_root "$ROOT" /opt/AdGuardHome/AdGuardHome.yaml)" ]]; then
        existing_args=(--existing-config "$(adguardhome_doh_under_root "$ROOT" /opt/AdGuardHome/AdGuardHome.yaml)" \
                       --health-state "$STATE_DIR/health-state.json")
        [[ -f "$CONFIG_DIR/health-policy.json" ]] && existing_args+=(--existing-policy "$CONFIG_DIR/health-policy.json")
        [[ -n "$EXISTING_PUBLIC_IP" ]] && existing_args+=(--existing-public-ip "$EXISTING_PUBLIC_IP")
    fi
    output="$(mktemp -d)"
    if ((POLICY_ARGUMENT)); then
        if python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"             --policy "$POLICY" ${POLICY_CATALOG_ARGS[@]+"${POLICY_CATALOG_ARGS[@]}"} --front "$FRONT" ${ADMIN_HOST_ARGS[@]+"${ADMIN_HOST_ARGS[@]}"} --public-ip "$PUBLIC_IP" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"} ${LOCAL_SITE_ARGS[@]+"${LOCAL_SITE_ARGS[@]}"} ${existing_args[@]+"${existing_args[@]}"} --doh-host "$DOMAIN"             --doh-token "$(printf '%048d' 0 | tr 0 a)" --password-hash 'dry-run-hash'             --certificate-root "/etc/letsencrypt/live/$DOMAIN" --webroot "$WEBROOT" --output "$output"; then
            status=0
        else
            status=$?
        fi
    else
        if python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"             --config-dir "$PROJECT_ROOT/config" --services "$SERVICES" --front "$FRONT" ${ADMIN_HOST_ARGS[@]+"${ADMIN_HOST_ARGS[@]}"}             --public-ip "$PUBLIC_IP" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"} ${LOCAL_SITE_ARGS[@]+"${LOCAL_SITE_ARGS[@]}"} ${existing_args[@]+"${existing_args[@]}"} --doh-host "$DOMAIN"             --doh-token "$(printf '%048d' 0 | tr 0 a)" --password-hash 'dry-run-hash'             --certificate-root "/etc/letsencrypt/live/$DOMAIN" --webroot "$WEBROOT" --output "$output"; then
            status=0
        else
            status=$?
        fi
    fi
    rm -rf -- "$output"
    return "$status"
}

adguardhome_doh_progress 0 'проверка параметров'
adguardhome_doh_load_saved_services
[[ -n "$REPOSITORY" && "$REPOSITORY" != *$'\n'* && "$REPOSITORY" != *$'\r'* ]] || \
    adguardhome_doh_die "invalid repository"
adguardhome_doh_prompt_missing_values || exit $?
if ((ADMIN_HOST_ARGUMENT)) || [[ -n "$ADMIN_HOST" ]]; then
    ADMIN_HOST="$(printf '%s' "$ADMIN_HOST" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
    adguardhome_doh_validate_hostname "$ADMIN_HOST" || adguardhome_doh_die "invalid --admin-host"
    [[ "$FRONT" == mtproxyl ]] || adguardhome_doh_die "--admin-host requires --front mtproxyl"
    [[ "$ADMIN_HOST" != "$DOMAIN" && "$ADMIN_HOST" != "web.$DOMAIN" ]] || \
        adguardhome_doh_die "--admin-host conflicts with an existing MTProxyL route"
    ADMIN_HOST_ARGS=(--admin-host "$ADMIN_HOST" --admin-certificate-root "/etc/letsencrypt/live/$ADMIN_HOST")
fi
if [[ -n "$RELAY" ]]; then
    # The relay is an exit host that can reach the real sites; forwarding to
    # ourselves would loop every routed connection back into this listener.
    adguardhome_doh_validate_ipv4 "$RELAY" || adguardhome_doh_die "invalid relay IPv4: $RELAY"
    [[ "$RELAY" != "$PUBLIC_IP" ]] || adguardhome_doh_die "relay must differ from the public IPv4"
    RELAY_ARGS=(--relay "$RELAY")
fi
LOCAL_SITES_CSV=
for local_site in ${LOCAL_SITES[@]+"${LOCAL_SITES[@]}"}; do
    adguardhome_doh_validate_local_site "$local_site" || \
        adguardhome_doh_die "invalid local site (expected HOST=IPV4:PORT, port not 443): $local_site"
    LOCAL_SITE_ARGS+=(--local-site "$local_site")
    LOCAL_SITES_CSV+="${LOCAL_SITES_CSV:+,}$local_site"
done
if ((POLICY_ARGUMENT && SERVICES_ARGUMENT)); then
    adguardhome_doh_die "--policy and --services cannot be combined"
fi
adguardhome_doh_prepare_services
if ((POLICY_ARGUMENT)); then
    [[ -f "$POLICY" ]] || adguardhome_doh_die "policy not found: $POLICY"
fi
adguardhome_doh_render_dry_run
adguardhome_doh_progress 5 'параметры приняты'

if ((INTERACTIVE_INPUT)); then
    adguardhome_doh_confirm_install || exit $?
elif ((INTERACTIVE_INPUT == 0 && YES == 0 && DRY_RUN == 0)) && adguardhome_doh_ui_tty; then
    adguardhome_doh_confirm_install || exit $?
fi

if ((DRY_RUN)); then
    adguardhome_doh_progress 20 'проверка каталога сервисов'
    adguardhome_doh_render_dry_run 1
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
adguardhome_doh_acquire_operation_lock || adguardhome_doh_die "cannot acquire operation lock"
adguardhome_doh_acquire_health_lock || adguardhome_doh_die "cannot acquire health lock"
if ((UPDATE)) && [[ "$(adguardhome_doh_update_input_digest)" != "$ADGUARDHOME_DOH_UPDATE_INPUT_DIGEST" ]]; then
    adguardhome_doh_die "existing update settings changed during preflight; run the installer again"
fi
if ((UPDATE)) && [[ "${ADGUARDHOME_DOH_MANAGER_UPDATE:-0}" == 1 ]]; then
    SERVICES_ARGUMENT=0
    adguardhome_doh_load_saved_services
    adguardhome_doh_prepare_services
    adguardhome_doh_render_dry_run
fi
adguardhome_doh_capture_runtime
adguardhome_doh_pause_health || adguardhome_doh_die "cannot stop the previous health worker"
adguardhome_doh_capture_directory_permissions "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT" "$WEBROOT" \
    /usr/local/libexec/adguardhome-doh /opt/AdGuardHome /var/log/adguardhome-doh || \
    adguardhome_doh_die "cannot capture existing directory permissions"
ADGUARDHOME_DOH_DIRECTORY_CAPTURED=1
adguardhome_doh_init_log /
LOG_PATH="$ADGUARDHOME_DOH_LOG_PATH"
adguardhome_doh_run_logged adguardhome_doh_preflight / "$DOMAIN" "$PUBLIC_IP" "$UPDATE" "${#LOCAL_SITES[@]}"
adguardhome_doh_progress 20 'предварительная проверка завершена'

snapshot_args=()
# A backup is eligible for manual update rollback only after activation succeeds.
snapshot_args=(--snapshot-operation recovery)
((UPDATE)) && snapshot_args=(--snapshot-operation update)
snapshot_result="$(python3 "$PROJECT_ROOT/deploy/manage.py" --create-update-backup \
    --root "$ROOT" --target-version "$PROJECT_VERSION" --domain "$DOMAIN" \
    ${snapshot_args[@]+"${snapshot_args[@]}"})" || adguardhome_doh_die "cannot create installation snapshot"
[[ "$snapshot_result" == /* && -f "$snapshot_result/manifest.json" ]] || \
    adguardhome_doh_die "invalid installation snapshot"
ADGUARDHOME_DOH_SNAPSHOT="$snapshot_result"
ADGUARDHOME_DOH_RELEASE_SNAPSHOT="$snapshot_result"

mapfile -t required_packages < <(adguardhome_doh_required_packages)
mapfile -t missing_packages < <(adguardhome_doh_missing_packages "${required_packages[@]}")
if ((${#missing_packages[@]})); then
    # Package scripts may start nginx; record that runtime may need restoring.
    ADGUARDHOME_DOH_RUNTIME_TOUCHED=1
    # A pre-apt snapshot must not remove files installed by the package manager.
    ADGUARDHOME_DOH_SNAPSHOT=
    adguardhome_doh_progress 25 'обновление индекса пакетов; это может занять несколько минут'
    adguardhome_doh_run_logged apt-get \
        -o Acquire::Retries=3 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
        update
    adguardhome_doh_progress 30 'установка недостающих зависимостей'
    adguardhome_doh_run_logged env DEBIAN_FRONTEND=noninteractive apt-get \
        -o Dpkg::Use-Pty=0 \
        install -y --no-install-recommends "${missing_packages[@]}"
    adguardhome_doh_progress 35 'зависимости установлены'
else
    adguardhome_doh_progress 35 'зависимости уже установлены; apt пропущен'
fi

# Existing YAML is parsed only after python3-yaml is available, but still
# before replacing any application binary, configuration, or runtime unit.
adguardhome_doh_render_dry_run 1

# The live service may save UI changes while stopping. Capture and render only
# after it has stopped, so neither the snapshot nor the render is stale.
ADGUARDHOME_DOH_SNAPSHOT=
ADGUARDHOME_DOH_STOPPED_LOADED_UNIT=0
if ! adguardhome_doh_stop_loaded_unit adguardhome-doh; then
    ADGUARDHOME_DOH_RUNTIME_TOUCHED=1
    adguardhome_doh_die "cannot stop existing AdGuard before preserving settings"
fi
if [[ "$ADGUARDHOME_DOH_STOPPED_LOADED_UNIT" == 1 ]]; then
    ADGUARDHOME_DOH_RUNTIME_TOUCHED=1
fi
adguardhome_doh_render_dry_run 1
if ((UPDATE)); then
    snapshot_result="$(python3 "$PROJECT_ROOT/deploy/manage.py" --create-update-backup \
        --root "$ROOT" --target-version "$PROJECT_VERSION" --domain "$DOMAIN" \
        --snapshot-operation update)" || adguardhome_doh_die "cannot create settled update snapshot"
    [[ "$snapshot_result" == /* && -f "$snapshot_result/manifest.json" ]] || \
        adguardhome_doh_die "invalid settled update snapshot"
    ADGUARDHOME_DOH_RELEASE_SNAPSHOT="$snapshot_result"
fi
snapshot_result="$(python3 "$PROJECT_ROOT/deploy/manage.py" --create-update-backup \
    --root "$ROOT" --target-version "$PROJECT_VERSION" --domain "$DOMAIN" \
    --snapshot-operation recovery)" || adguardhome_doh_die "cannot create recovery snapshot"
[[ "$snapshot_result" == /* && -f "$snapshot_result/manifest.json" ]] || \
    adguardhome_doh_die "invalid recovery snapshot"
ADGUARDHOME_DOH_SNAPSHOT="$snapshot_result"

ADGUARDHOME_DOH_MUTATIONS=1
mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT" "$WEBROOT" /etc/nginx/stream.d /etc/adguardhome-doh
chmod 700 "$STATE_DIR" "$CONFIG_DIR" "$BACKUP_ROOT"
# AdGuard runs as root but requires its work directory to exist.  Preserve the
# ownership and permissions of an existing directory from earlier releases.
[[ -d /var/lib/AdGuardHome ]] || install -d -m 700 /var/lib/AdGuardHome
nginx_user="$(awk '$1 == "user" {gsub(/;/, "", $2); print $2; exit}' /etc/nginx/nginx.conf)"
nginx_group="$(awk '{sub(/#.*/, "")} $1 == "user" {gsub(/;/, "", $3); print $3; exit}' /etc/nginx/nginx.conf)"
nginx_user="${nginx_user:-www-data}"
[[ -n "$nginx_group" ]] || nginx_group="$(id -gn "$nginx_user")"
chown "root:$nginx_group" "$WEBROOT"
chmod 750 "$WEBROOT"
mkdir -p "$CONFIG_DIR/catalog"
for catalog_file in services.csv domains.csv service-domains.csv service-probes.csv; do
    install -m 640 "$PROJECT_ROOT/config/$catalog_file" "$CONFIG_DIR/catalog/$catalog_file"
done
if adguardhome_doh_should_install_binary /opt/AdGuardHome/AdGuardHome "$UPDATE"; then
    work="$(mktemp -d)"
    ADGUARDHOME_DOH_WORK_DIR="$work"
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
    binary_backup="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-AdGuardHome"
    adguardhome_doh_backup /opt/AdGuardHome/AdGuardHome "$binary_backup"
    if [[ -f "$binary_backup" ]]; then
        ADGUARDHOME_DOH_BINARY_BACKUP="$binary_backup"
    fi
    adguardhome_doh_run_logged adguardhome_doh_activate_binary \
        "$adguard_binary" /opt/AdGuardHome/AdGuardHome
fi
adguardhome_doh_progress 50 'AdGuard Home подготовлен'

if [[ -f "$CREDENTIALS_FILE" ]]; then
    ADMIN_PASSWORD="$(python3 "$SCRIPT_DIR/lib/credentials.py" --path "$CREDENTIALS_FILE" --read --field password)"
else
    ADMIN_PASSWORD="$(openssl rand -hex 24)"
fi
ADGUARDHOME_DOH_ADMIN_PASSWORD="$ADMIN_PASSWORD"
ADMIN_HASH="$(adguardhome_doh_hash_password "$ADMIN_PASSWORD")"
ADGUARDHOME_DOH_ADMIN_HASH="$ADMIN_HASH"
DOH_TOKEN="$(adguardhome_doh_load_or_create_doh_token "$DOH_TOKEN_FILE")"
ADGUARDHOME_DOH_DOH_TOKEN="$DOH_TOKEN"
CERT_ROOT="/etc/letsencrypt/live/$DOMAIN"
stage="$(mktemp -d "$STATE_DIR/.stage.XXXXXX")"
ADGUARDHOME_DOH_STAGE="$stage"
install -m 600 /dev/null "$stage/password-hash"
printf '%s' "$ADMIN_HASH" > "$stage/password-hash"
backup="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"; chmod 700 "$backup"
adguardhome_doh_backup /opt/AdGuardHome/AdGuardHome.yaml "$backup/AdGuardHome.yaml"
adguardhome_doh_backup /etc/nginx/sites-enabled/adguardhome-doh "$backup/nginx-http.conf"
adguardhome_doh_backup /etc/nginx/stream.d/adguardhome-doh.conf "$backup/nginx-stream.conf"

existing_args=()
if ((UPDATE)) && [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]]; then
    existing_args=(--existing-config /opt/AdGuardHome/AdGuardHome.yaml \
                   --health-state "$STATE_DIR/health-state.json")
    [[ -f "$CONFIG_DIR/health-policy.json" ]] && existing_args+=(--existing-policy "$CONFIG_DIR/health-policy.json")
    [[ -n "$EXISTING_PUBLIC_IP" ]] && existing_args+=(--existing-public-ip "$EXISTING_PUBLIC_IP")
fi
HEALTHY_SERVICES="$(adguardhome_doh_healthy_services "$STATE_DIR/health-state.json")"
healthy_args=()
[[ -n "$HEALTHY_SERVICES" ]] && healthy_args=(--healthy-services "$HEALTHY_SERVICES")
if ((POLICY_ARGUMENT)); then
    adguardhome_doh_run_logged python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py"         --policy "$POLICY" ${POLICY_CATALOG_ARGS[@]+"${POLICY_CATALOG_ARGS[@]}"} --front "$FRONT" ${ADMIN_HOST_ARGS[@]+"${ADMIN_HOST_ARGS[@]}"} ${healthy_args[@]+"${healthy_args[@]}"} --public-ip "$PUBLIC_IP" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"} ${LOCAL_SITE_ARGS[@]+"${LOCAL_SITE_ARGS[@]}"} ${existing_args[@]+"${existing_args[@]}"} --doh-host "$DOMAIN"         --doh-token-file "$DOH_TOKEN_FILE" --password-hash-file "$stage/password-hash"         --certificate-root "$CERT_ROOT" --webroot "$WEBROOT" --output "$stage"
else
    adguardhome_doh_run_logged python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py" \
        --config-dir "$PROJECT_ROOT/config" --services "$SERVICES" --front "$FRONT" \
        ${ADMIN_HOST_ARGS[@]+"${ADMIN_HOST_ARGS[@]}"} \
        ${healthy_args[@]+"${healthy_args[@]}"} \
        ${existing_args[@]+"${existing_args[@]}"} \
        --public-ip "$PUBLIC_IP" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"} ${LOCAL_SITE_ARGS[@]+"${LOCAL_SITE_ARGS[@]}"} --doh-host "$DOMAIN" \
        --doh-token-file "$DOH_TOKEN_FILE" --password-hash-file "$stage/password-hash" \
        --certificate-root "$CERT_ROOT" --webroot "$WEBROOT" --output "$stage"
fi
adguardhome_doh_progress 65 'конфигурация подготовлена'

install -m 640 "$stage/AdGuardHome.yaml" /opt/AdGuardHome/AdGuardHome.yaml
install -m 644 "$stage/nginx-stream.conf" /etc/nginx/stream.d/adguardhome-doh.conf
ADGUARDHOME_DOH_MOBILECONFIG_TEMP="$(mktemp "$WEBROOT/.mobileconfig.XXXXXX")"
install -m 640 -o root -g "$nginx_group" "$stage/$DOMAIN.mobileconfig" "$ADGUARDHOME_DOH_MOBILECONFIG_TEMP"
mv -f -- "$ADGUARDHOME_DOH_MOBILECONFIG_TEMP" "$WEBROOT/$DOMAIN.mobileconfig"
ADGUARDHOME_DOH_MOBILECONFIG_TEMP=
adguardhome_doh_ensure_nginx_stream_include
# Capacity tuning must never block an activation: a warning is enough.
adguardhome_doh_ensure_nginx_worker_limits || true
adguardhome_doh_install_nginx_restart_dropin /
ADGUARDHOME_DOH_DEFER_SYSCTL=1 adguardhome_doh_install_sysctl / || true
adguardhome_doh_install_logrotate /
ADGUARDHOME_DOH_NGINX_TEMP="$(mktemp /etc/nginx/sites-enabled/.adguardhome-doh.XXXXXX)"
cat > "$ADGUARDHOME_DOH_NGINX_TEMP" <<EOF
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
chmod 600 "$ADGUARDHOME_DOH_NGINX_TEMP"
mv -f -- "$ADGUARDHOME_DOH_NGINX_TEMP" /etc/nginx/sites-enabled/adguardhome-doh
ADGUARDHOME_DOH_NGINX_TEMP=

cat > /etc/systemd/system/adguardhome-doh.service <<'UNIT'
[Unit]
Description=AdGuard Home DoH DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /var/lib/AdGuardHome
# Clients with an installed DoH profile have no DNS at all while this process
# is down, so it is restarted unconditionally and without a give-up limit.
Restart=always
RestartSec=2s
StartLimitIntervalSec=0
LimitNOFILE=65535
User=root
NoNewPrivileges=true
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=/opt/AdGuardHome /var/lib/AdGuardHome

[Install]
WantedBy=multi-user.target
UNIT
adguardhome_doh_run_logged adguardhome_doh_install_health_templates "$PROJECT_ROOT" /
install -m 640 "$stage/health-policy.json" "$CONFIG_DIR/health-policy.json"
cat > /etc/adguardhome-doh/runtime.env <<EOF
ADGUARDHOME_DOH_AGH_URL=http://127.0.0.1:3001
ADGUARDHOME_DOH_POLICY=$CONFIG_DIR/health-policy.json
ADGUARDHOME_DOH_STATE=$STATE_DIR/health-state.json
ADGUARDHOME_DOH_CREDENTIALS=$CREDENTIALS_FILE
ADGUARDHOME_DOH_PUBLIC_IP=$PUBLIC_IP
ADGUARDHOME_DOH_DOMAIN=$DOMAIN
ADGUARDHOME_DOH_TOKEN_FILE=$DOH_TOKEN_FILE
ADGUARDHOME_DOH_LOCK=/run/lock/adguardhome-doh-health.lock
ADGUARDHOME_DOH_SUCCESS_THRESHOLD=3
ADGUARDHOME_DOH_FAILURE_THRESHOLD=5
EOF
chmod 600 /etc/adguardhome-doh/runtime.env

if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    printf '%s' "$ADMIN_PASSWORD" | python3 "$SCRIPT_DIR/lib/credentials.py" --path "$CREDENTIALS_FILE"         --url "https://${ADMIN_HOST:-$DOMAIN}/" --password-stdin >/dev/null
fi
SAVED_POLICY=
if ((POLICY_ARGUMENT)); then
    SAVED_POLICY="$CONFIG_DIR/compat-policy.csv"
    if [[ ! -e "$SAVED_POLICY" || ! "$POLICY" -ef "$SAVED_POLICY" ]]; then
        install -m 600 -- "$POLICY" "$SAVED_POLICY"
    else
        chmod 600 "$SAVED_POLICY"
    fi
fi
python3 - "$SCRIPT_DIR/lib/state.py" "$INSTALL_STATE_FILE" "$DOMAIN" "$PUBLIC_IP" "$EMAIL" "$PROJECT_VERSION" "$REPOSITORY" "$ENABLED_SERVICES_FILE" "$SERVICES" "$RELAY" "$LOCAL_SITES_CSV" "$SAVED_POLICY" "$FRONT" "$ADMIN_HOST" <<'PY'
import importlib.util
import sys
from pathlib import Path

module_path, install_path, domain, public_ip, email, version, repository, services_path, services, relay, local_sites, policy, front, admin_host = sys.argv[1:]
spec = importlib.util.spec_from_file_location("adguardhome_doh_state", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.save_install_state(Path(install_path), domain=domain, public_ip=public_ip, email=email,
                          version=version, repository=repository, relay=relay or None,
                          local_sites=[item for item in local_sites.split(",") if item], policy=policy or None,
                          front=front if front == "mtproxyl" else None, admin_host=admin_host or None)
module.save_enabled_services(Path(services_path), [item for item in services.split(",") if item])
PY
adguardhome_doh_progress 75 'состояние и профили сохранены'

ADGUARDHOME_DOH_RUNTIME_TOUCHED=1
adguardhome_doh_run_logged systemctl daemon-reload
adguardhome_doh_run_logged nginx -t
adguardhome_doh_run_logged systemctl enable adguardhome-doh nginx
adguardhome_doh_run_logged systemctl restart adguardhome-doh
adguardhome_doh_run_logged systemctl start nginx
# A package-started or pre-existing nginx is still running its old
# configuration: without this reload the ACME challenge below would be
# answered by whatever served port 80 before, and a fronted site would keep
# 443 while the stream listener waits to take it over.
adguardhome_doh_run_logged systemctl reload nginx
adguardhome_doh_progress 85 'службы запущены'
if [[ ! -f "$CERT_ROOT/fullchain.pem" ]]; then
    # HTTP-01 is answered from the webroot nginx already serves on port 80, so
    # issuance and every later renewal keep DNS, the panel and SNI forwarding
    # online instead of stopping nginx for the length of the ACME exchange.
    renewal_profile="/etc/letsencrypt/renewal/$DOMAIN.conf"
    if [[ ! -e "$renewal_profile" && ! -L "$renewal_profile" ]]; then
        ADGUARDHOME_DOH_NEW_CERTBOT_LINEAGE=1
    fi
    mapfile -t certbot_contact_args < <(adguardhome_doh_certbot_contact_args "$EMAIL")
    adguardhome_doh_run_logged certbot certonly --webroot --webroot-path "$WEBROOT" \
        -d "$DOMAIN" "${certbot_contact_args[@]}" --deploy-hook 'systemctl reload nginx' \
        --agree-tos --non-interactive --keep-until-expiring
else
    adguardhome_doh_run_logged adguardhome_doh_migrate_certbot_renewal \
        / "$DOMAIN" "$WEBROOT" "$PROJECT_ROOT"
fi
ADGUARDHOME_DOH_NGINX_TEMP="$(mktemp /etc/nginx/sites-enabled/.adguardhome-doh.XXXXXX)"
install -m 600 "$stage/nginx-http.conf" "$ADGUARDHOME_DOH_NGINX_TEMP"
mv -f -- "$ADGUARDHOME_DOH_NGINX_TEMP" /etc/nginx/sites-enabled/adguardhome-doh
ADGUARDHOME_DOH_NGINX_TEMP=
adguardhome_doh_run_logged nginx -t
adguardhome_doh_run_logged systemctl reload nginx
adguardhome_doh_run_logged adguardhome_doh_smoke_https_sni "$DOMAIN"
install -m 600 /dev/null "$INSTALL_COMPLETE_FILE"
adguardhome_doh_release_health_lock
adguardhome_doh_run_logged systemctl enable --now adguardhome-doh-health.timer
adguardhome_doh_run_logged systemctl start adguardhome-doh-health.service
rm -rf -- "$stage"
if ((UPDATE)); then
    adguardhome_doh_acquire_health_lock || adguardhome_doh_die "cannot reacquire health lock"
    python3 "$PROJECT_ROOT/deploy/manage.py" --finalize-update-backup "$ADGUARDHOME_DOH_RELEASE_SNAPSHOT" \
        --root "$ROOT" --domain "$DOMAIN"
    adguardhome_doh_release_health_lock
fi
sysctl -q -p /etc/sysctl.d/90-adguardhome-doh.conf >/dev/null 2>&1 || \
    printf 'warning: kernel parameters could not be applied\n' >&2
adguardhome_doh_release_operation_lock
adguardhome_doh_progress 95 'сертификат и DoH активированы'
adguardhome_doh_progress 100 'установка завершена'
if ((UPDATE)); then
    adguardhome_doh_update_summary "$LOG_PATH"
else
    adguardhome_doh_summary "$LOG_PATH" "$DOH_TOKEN" "$ADMIN_PASSWORD" "$CREDENTIALS_FILE"
fi
