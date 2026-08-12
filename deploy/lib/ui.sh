#!/usr/bin/env bash
set -euo pipefail

ADGUARDHOME_DOH_LAST_PROGRESS=-1
ADGUARDHOME_DOH_PROGRESS_MILESTONES=(0 5 20 35 50 65 75 85 95 100)

adguardhome_doh_ui_tty() {
    [[ "${ADGUARDHOME_DOH_TTY_FD:-}" == 0 ]] || [[ -r /dev/tty && ( -t 0 || -t 1 ) ]]
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

adguardhome_doh_service_number_for_id() {
    local wanted="$1" index
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        [[ "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" == "$wanted" ]] && { printf '%s\n' "$((index + 1))"; return 0; }
    done
    return 1
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

adguardhome_doh_selector_print() {
    local selected="$1" index category last_category= marker section=standard
    if ( : > /dev/tty ) 2>/dev/null; then exec 3>/dev/tty; else exec 3>&2; fi
    printf '\nВыберите сервисы (номер, диапазон; A/S — все стандартные; D — настройки по умолчанию; X — экспериментальные; C — отмена):\n' >&3
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        if [[ "${ADGUARDHOME_DOH_SERVICE_RISKS[index]}" == experimental && "$section" != experimental ]]; then section=experimental; printf '  Экспериментальные сервисы (отключены по умолчанию):\n' >&3; fi
        category="${ADGUARDHOME_DOH_SERVICE_CATEGORIES[index]}"
        if [[ "$category" != "$last_category" ]]; then printf '  %s:\n' "$category" >&3; last_category="$category"; fi
        marker=' '; adguardhome_doh_selector_contains "$selected" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" && marker='*'
        printf '  %2d) [%s] %s (%s)\n' "$((index + 1))" "$marker" "${ADGUARDHOME_DOH_SERVICE_NAMES[index]}" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" >&3
    done
    exec 3>&-
}

adguardhome_doh_selector_ids() {
    local selected="$1" id result=
    for id in "${ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        if adguardhome_doh_selector_contains "$selected" "$id"; then [[ -n "$result" ]] && result="$result,"; result="$result$id"; fi
    done
    [[ -n "$result" ]] || return 1
    printf '%s\n' "$result"
}

adguardhome_doh_selector_apply_token() {
    local token="$1" selected="$2" start end number id index
    token="${token//[[:space:]]/}"; [[ -n "$token" ]] || return 0
    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"; (( start <= end )) || return 1
        for ((number = start; number <= end; number++)); do adguardhome_doh_selector_apply_token "$number" "$selected" || return 1; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done
        ADGUARDHOME_DOH_SELECTOR_SELECTED="$selected"; return 0
    fi
    [[ "$token" =~ ^[0-9]+$ ]] || return 1; (( token >= 1 && token <= ${#ADGUARDHOME_DOH_SERVICE_IDS[@]} )) || return 1
    index=$((token - 1)); id="${ADGUARDHOME_DOH_SERVICE_IDS[index]}"
    if adguardhome_doh_selector_contains "$selected" "$id"; then adguardhome_doh_selector_remove "$selected" "$id"; else adguardhome_doh_selector_add "$selected" "$id"; fi
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
    local config_dir="$1" initial="${2:-}" answer token id index selected=
    adguardhome_doh_load_service_catalog "$config_dir"
    if [[ -n "$initial" ]]; then
        IFS=',' read -r -a initial_ids <<< "$initial"
        for id in "${initial_ids[@]}"; do
            index="$(adguardhome_doh_service_number_for_id "$id")" || { adguardhome_doh_ui_error "unknown service: $id"; return 1; }
            adguardhome_doh_selector_add "$selected" "${ADGUARDHOME_DOH_SERVICE_IDS[index-1]}"; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"
        done
    fi
    while :; do
        adguardhome_doh_selector_print "$selected"
        adguardhome_doh_read_tty answer $'\nСервисы: ' || return $?
        answer="$ADGUARDHOME_DOH_READ_VALUE"; answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
        case "$answer" in
            c|q|cancel|отмена) adguardhome_doh_ui_error "выбор отменён"; return 2 ;;
            d|default|defaults|по-умолчанию)
                selected=
                for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do [[ "${ADGUARDHOME_DOH_SERVICE_DEFAULTS[index]}" == true ]] || continue; adguardhome_doh_selector_add "$selected" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
            a|all|s|standard|standard-all|all-standard|стандартные)
                selected=
                for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do [[ "${ADGUARDHOME_DOH_SERVICE_RISKS[index]}" == standard ]] || continue; adguardhome_doh_selector_add "$selected" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
            x|experimental|all-experimental|экспериментальные)
                selected=
                for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do [[ "${ADGUARDHOME_DOH_SERVICE_RISKS[index]}" == experimental ]] || continue; adguardhome_doh_selector_add "$selected" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}"; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
            *)
                selected=
                IFS=', ' read -r -a tokens <<< "$answer"
                for token in "${tokens[@]}"; do adguardhome_doh_selector_apply_token "$token" "$selected" || { adguardhome_doh_ui_error "неверный номер или диапазон: $token"; selected=; continue 2; }; selected="$ADGUARDHOME_DOH_SELECTOR_SELECTED"; done ;;
        esac
        [[ "$(adguardhome_doh_selector_ids "$selected" 2>/dev/null || true)" ]] || { adguardhome_doh_ui_error "выберите хотя бы один сервис"; continue; }
        if adguardhome_doh_selector_confirm; then adguardhome_doh_selector_ids "$selected"; return 0; fi
        case "$?" in 2) adguardhome_doh_ui_error "выбор отменён"; return 2 ;; *) continue ;; esac
    done
}
