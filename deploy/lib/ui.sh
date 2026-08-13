#!/usr/bin/env bash
set -euo pipefail

ADGUARDHOME_DOH_LAST_PROGRESS=-1
ADGUARDHOME_DOH_PROGRESS_MILESTONES=(0 5 20 35 50 65 75 85 95 100)

adguardhome_doh_ui_tty() {
    [[ "${ADGUARDHOME_DOH_TTY_FD:-}" == 0 ]] && return 0
    [[ -r /dev/tty ]] || return 1
    [[ -w /dev/tty ]] && return 0
    [[ -t 0 || -t 1 ]]
}

adguardhome_doh_ui_error() { printf 'ошибка: %s\n' "$*" >&2; }

adguardhome_doh_progress() {
    local percent="$1" message="${2:-}" milestone allowed=0
    for milestone in "${ADGUARDHOME_DOH_PROGRESS_MILESTONES[@]}"; do [[ "$percent" == "$milestone" ]] && allowed=1; done
    (( allowed )) || { adguardhome_doh_ui_error "invalid progress milestone: $percent"; return 1; }
    (( percent >= ADGUARDHOME_DOH_LAST_PROGRESS )) || { adguardhome_doh_ui_error "progress moved backwards: $percent"; return 1; }
    ADGUARDHOME_DOH_LAST_PROGRESS="$percent"
    if [[ "${ADGUARDHOME_DOH_TEXT_PROGRESS:-0}" == 1 ]] || ! adguardhome_doh_ui_tty || (( percent == 0 )); then printf '[%02d%%] %s\n' "$percent" "$message"; else printf '\r\033[2K[%02d%%] %s' "$percent" "$message"; fi
}

adguardhome_doh_trim_input() {
    local value="$1"
    value="${value//$'\e[200~'/}"
    value="${value//$'\e[201~'/}"
    value="${value//$'\r'/}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

adguardhome_doh_read_tty() {
    local variable="$1" prompt="$2" value
    adguardhome_doh_ui_tty || { adguardhome_doh_ui_error "interactive input requires a TTY (/dev/tty)"; return 2; }
    ADGUARDHOME_DOH_READ_VALUE=
    if [[ "${ADGUARDHOME_DOH_TTY_FD:-}" == 0 ]]; then
        printf '%s' "$prompt" >&2
        IFS= read -r value || { adguardhome_doh_ui_error "input cancelled or unavailable on /dev/tty"; return 2; }
    elif [[ -r /dev/tty && -w /dev/tty ]]; then
        printf '%s' "$prompt" > /dev/tty 2>/dev/null || {
            adguardhome_doh_ui_error "input terminal is unavailable"; return 2;
        }
        IFS= read -r value < /dev/tty || {
            adguardhome_doh_ui_error "input cancelled or unavailable on /dev/tty"; return 2;
        }
    else
        printf '%s' "$prompt" >&2
        IFS= read -r value || { adguardhome_doh_ui_error "input cancelled or unavailable on /dev/tty"; return 2; }
    fi
    ADGUARDHOME_DOH_READ_VALUE="$(adguardhome_doh_trim_input "$value")"
}

adguardhome_doh_prompt_value() {
    local variable="$1" prompt="$2" validator="$3" value
    while :; do
        adguardhome_doh_read_tty value "$prompt" || return $?
        value="$ADGUARDHOME_DOH_READ_VALUE"
        if [[ "$validator" == adguardhome_doh_validate_hostname ]]; then
            value="$(printf '%s' "$value" | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C tr -cd 'a-z0-9.-')"
        fi
        if "$validator" "$value" >/dev/null 2>&1; then printf -v "$variable" '%s' "$value"; return 0; fi
        adguardhome_doh_ui_error "значение не прошло проверку, повторите ввод"
    done
}

adguardhome_doh_load_service_catalog() {
    local config_dir="$1" id name category default_enabled risk
    ADGUARDHOME_DOH_SERVICE_IDS=(); ADGUARDHOME_DOH_SERVICE_NAMES=(); ADGUARDHOME_DOH_SERVICE_CATEGORIES=(); ADGUARDHOME_DOH_SERVICE_DEFAULTS=(); ADGUARDHOME_DOH_SERVICE_RISKS=()
    [[ -r "$config_dir/services.csv" ]] || { adguardhome_doh_ui_error "catalog not found: $config_dir/services.csv"; return 1; }
    while IFS=, read -r id name category default_enabled risk; do
        [[ "$id" == id || -z "$id" ]] && continue
        ADGUARDHOME_DOH_SERVICE_IDS[${#ADGUARDHOME_DOH_SERVICE_IDS[@]}]="$id"
        ADGUARDHOME_DOH_SERVICE_NAMES[${#ADGUARDHOME_DOH_SERVICE_NAMES[@]}]="$name"
        ADGUARDHOME_DOH_SERVICE_CATEGORIES[${#ADGUARDHOME_DOH_SERVICE_CATEGORIES[@]}]="$category"
        ADGUARDHOME_DOH_SERVICE_DEFAULTS[${#ADGUARDHOME_DOH_SERVICE_DEFAULTS[@]}]="$default_enabled"
        ADGUARDHOME_DOH_SERVICE_RISKS[${#ADGUARDHOME_DOH_SERVICE_RISKS[@]}]="$risk"
    done < "$config_dir/services.csv"
    ((${#ADGUARDHOME_DOH_SERVICE_IDS[@]} > 0)) || { adguardhome_doh_ui_error "catalog has no services"; return 1; }
}

adguardhome_doh_selector_contains() {
    local selected="$1" wanted="$2" item
    IFS=',' read -r -a selected_items <<< "$selected"
    for item in "${selected_items[@]-}"; do [[ "$item" == "$wanted" ]] && return 0; done
    return 1
}

adguardhome_doh_selector_add() {
    local selected="$1" id="$2"
    if adguardhome_doh_selector_contains "$selected" "$id"; then ADGUARDHOME_DOH_SELECTOR_SELECTED="$selected"
    elif [[ -n "$selected" ]]; then ADGUARDHOME_DOH_SELECTOR_SELECTED="$selected,$id"
    else ADGUARDHOME_DOH_SELECTOR_SELECTED="$id"; fi
}

adguardhome_doh_selector_remove() {
    local selected="$1" wanted="$2" item result=
    IFS=',' read -r -a selected_items <<< "$selected"
    for item in "${selected_items[@]-}"; do
        [[ -z "$item" || "$item" == "$wanted" ]] && continue
        [[ -n "$result" ]] && result="$result,"
        result="$result$item"
    done
    ADGUARDHOME_DOH_SELECTOR_SELECTED="$result"
}

adguardhome_doh_selector_ids() {
    local selected="$1" id result=
    for id in "${ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        if adguardhome_doh_selector_contains "$selected" "$id"; then [[ -n "$result" ]] && result="$result,"; result="$result$id"; fi
    done
    [[ -n "$result" ]] || return 1
    printf '%s\n' "$result"
}

adguardhome_doh_selector_emit() {
    if [[ -w /dev/tty ]]; then printf '%s\n' "$1" > /dev/tty; else printf '%s\n' "$1" >&2; fi
}

adguardhome_doh_selector_count_selected() {
    local count=0 id
    for id in "${ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id" && ((count += 1))
    done
    printf '%s\n' "$count"
}

adguardhome_doh_selector_category_init() {
    local index category found
    ADGUARDHOME_DOH_SELECTOR_CATEGORIES=()
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        category="${ADGUARDHOME_DOH_SERVICE_CATEGORIES[index]}"; found=0
        for item in "${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[@]-}"; do [[ "$item" == "$category" ]] && found=1; done
        (( found )) || ADGUARDHOME_DOH_SELECTOR_CATEGORIES+=("$category")
    done
}

adguardhome_doh_selector_category_indices() {
    local category="$1" index
    ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES=()
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        [[ "${ADGUARDHOME_DOH_SERVICE_CATEGORIES[index]}" == "$category" ]] && ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES+=("$index")
    done
}

adguardhome_doh_selector_search_indices() {
    local query="$1" index haystack
    ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES=()
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        haystack="${ADGUARDHOME_DOH_SERVICE_NAMES[index]} ${ADGUARDHOME_DOH_SERVICE_IDS[index]}"
        printf '%s\n' "$haystack" | grep -Fqi -- "$query" && ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES+=("$index")
    done
}

adguardhome_doh_selector_domain_count() {
    if ! command -v python3 >/dev/null 2>&1; then
        awk -F, -v selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED" '
            BEGIN {
                count = split(selected, items, ",")
                for (i = 1; i <= count; i++) wanted[items[i]] = 1
            }
            NR > 1 && ($1 in wanted) { domains[$2] = 1 }
            END {
                total = 0
                for (domain in domains) total += 1
                print total
            }' "$1/config/service-domains.csv"
        return
    fi
    python3 - "$1" "$ADGUARDHOME_DOH_SELECTOR_SELECTED" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.render_config import Catalog
catalog = Catalog.load(Path(sys.argv[1]) / "config")
selected = {item for item in sys.argv[2].split(",") if item}
print(sum(1 for services in catalog.associations.values() if selected.intersection(services)))
PY
}

adguardhome_doh_selector_summary() {
    local config_dir="$1" count domains names id
    count="$(adguardhome_doh_selector_count_selected)"
    domains="$(adguardhome_doh_selector_domain_count "$(cd -- "$config_dir/.." && pwd -P)")"
    adguardhome_doh_selector_emit "Выбрано сервисов: $count"
    adguardhome_doh_selector_emit "Активных уникальных доменов: $domains"
    names=
    for id in "${ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id" || continue
        [[ -n "$names" ]] && names="$names, "
        for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
            [[ "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" == "$id" ]] && names="$names${ADGUARDHOME_DOH_SERVICE_NAMES[index]}"
        done
    done
    [[ -n "$names" ]] && adguardhome_doh_selector_emit "Сервисы: $names"
}

adguardhome_doh_selector_print_categories() {
    local number category total selected
    adguardhome_doh_selector_emit ""
    adguardhome_doh_selector_emit "Категории:"
    for number in "${!ADGUARDHOME_DOH_SELECTOR_CATEGORIES[@]}"; do
        category="${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[number]}"; total=0; selected=0
        for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
            [[ "${ADGUARDHOME_DOH_SERVICE_CATEGORIES[index]}" == "$category" ]] || continue
            ((total += 1)); adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" && ((selected += 1))
        done
        adguardhome_doh_selector_emit " $((number + 1))) $category ($selected/$total)"
    done
    adguardhome_doh_selector_emit ""
    adguardhome_doh_selector_emit "Команды: номер — открыть категорию, /текст — поиск, D — стандартные, X — экспериментальные, Y — итог, C — отмена"
}

adguardhome_doh_selector_print_view() {
    local title="$1" number index marker
    adguardhome_doh_selector_emit ""
    [[ "$title" == *: ]] || title="$title:"
    adguardhome_doh_selector_emit "$title"
    for number in "${!ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]}"; do
        index="${ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[number]}"; marker=' '
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" && marker='*'
        adguardhome_doh_selector_emit " $((number + 1))) [$marker] ${ADGUARDHOME_DOH_SERVICE_NAMES[index]} (${ADGUARDHOME_DOH_SERVICE_IDS[index]})"
    done
    adguardhome_doh_selector_emit ""
    adguardhome_doh_selector_emit "Команды: номера через пробел — включить/выключить, A — все, N — снять все, B — назад, C — отмена"
}

adguardhome_doh_selector_apply_view_tokens() {
    local answer="$1" token number index id
    IFS=', ' read -r -a tokens <<< "$answer"
    for token in "${tokens[@]}"; do
        [[ "$token" =~ ^[0-9]+$ ]] || return 1
        number=$((token - 1)); (( number >= 0 && number < ${#ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]} )) || return 1
        index="${ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[number]}"; id="${ADGUARDHOME_DOH_SERVICE_IDS[index]}"
        if adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id"; then adguardhome_doh_selector_remove "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id"; else adguardhome_doh_selector_add "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id"; fi
        ADGUARDHOME_DOH_SELECTOR_SELECTED="$ADGUARDHOME_DOH_SELECTOR_SELECTED"
    done
}

adguardhome_doh_selector_view() {
    local title="$1" answer normalized
    while :; do
        adguardhome_doh_selector_print_view "$title"
        adguardhome_doh_read_tty answer $'\nВыбор: ' || return $?
        normalized="$ADGUARDHOME_DOH_READ_VALUE"; normalized="$(printf '%s' "$normalized" | tr '[:upper:]' '[:lower:]')"
        case "$normalized" in
            b|back|назад) return 0 ;;
            c|q|cancel|отмена) return 2 ;;
            a|all)
                for index in "${ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]}"; do adguardhome_doh_selector_add "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; ADGUARDHOME_DOH_SELECTOR_SELECTED="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
            n|none|снять) for index in "${ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]}"; do adguardhome_doh_selector_remove "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; ADGUARDHOME_DOH_SELECTOR_SELECTED="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
            *) adguardhome_doh_selector_apply_view_tokens "$normalized" || adguardhome_doh_ui_error "введите номера сервисов или команду" ;;
        esac
    done
}

adguardhome_doh_selector_confirm() {
    local answer
    while :; do
        adguardhome_doh_read_tty answer $'\nПодтвердить выбор? [y/N]: ' || return $?
        answer="$ADGUARDHOME_DOH_READ_VALUE"; answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
        case "$answer" in y|yes|д|да) return 0 ;; n|no|н|нет) return 1 ;; c|q|cancel|отмена) return 2 ;; *) adguardhome_doh_ui_error "введите y, n или c" ;; esac
    done
}

adguardhome_doh_select_services() {
    local config_dir="$1" initial="${2:-}" answer normalized category_number category title
    adguardhome_doh_load_service_catalog "$config_dir"
    ADGUARDHOME_DOH_SELECTOR_SELECTED="$initial"
    adguardhome_doh_selector_category_init
    while :; do
        adguardhome_doh_selector_print_categories
        adguardhome_doh_selector_summary "$config_dir"
        adguardhome_doh_read_tty answer $'\nКатегория: ' || return $?
        normalized="$ADGUARDHOME_DOH_READ_VALUE"; normalized="$(printf '%s' "$normalized" | tr '[:upper:]' '[:lower:]')"
        case "$normalized" in
            c|q|cancel|отмена) adguardhome_doh_ui_error "выбор отменён"; return 2 ;;
            d|default|defaults|по-умолчанию)
                ADGUARDHOME_DOH_SELECTOR_SELECTED=
                for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do [[ "${ADGUARDHOME_DOH_SERVICE_DEFAULTS[index]}" == true ]] || continue; adguardhome_doh_selector_add "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; ADGUARDHOME_DOH_SELECTOR_SELECTED="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done
                adguardhome_doh_selector_summary "$config_dir"
                adguardhome_doh_selector_confirm && adguardhome_doh_selector_ids "$ADGUARDHOME_DOH_SELECTOR_SELECTED" && return 0
                ;;
            x|experimental|экспериментальные)
                category='Экспериментальные'; adguardhome_doh_selector_category_indices "$category"; adguardhome_doh_selector_view "$category" || return $? ;;
            y|yes|итог|применить)
                [[ "$(adguardhome_doh_selector_count_selected)" != 0 ]] || { adguardhome_doh_ui_error "выберите хотя бы один сервис"; continue; }
                adguardhome_doh_selector_summary "$config_dir"; adguardhome_doh_selector_confirm && adguardhome_doh_selector_ids "$ADGUARDHOME_DOH_SELECTOR_SELECTED" && return 0
                ;;
            /*)
                adguardhome_doh_selector_search_indices "${normalized#/}"; ((${#ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]})) || { adguardhome_doh_ui_error "ничего не найдено"; continue; }
                adguardhome_doh_selector_view "Результаты поиска: ${normalized#/}" || return $? ;;
            *)
                [[ "$normalized" =~ ^[0-9]+$ ]] || { adguardhome_doh_ui_error "введите номер категории, /поиск, D, X, Y или C"; continue; }
                category_number=$((normalized - 1)); (( category_number >= 0 && category_number < ${#ADGUARDHOME_DOH_SELECTOR_CATEGORIES[@]} )) || { adguardhome_doh_ui_error "нет такой категории"; continue; }
                category="${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[category_number]}"; adguardhome_doh_selector_category_indices "$category"; adguardhome_doh_selector_view "$category" || return $? ;;
        esac
    done
}
