#!/usr/bin/env bash
set -euo pipefail

ADGUARDHOME_DOH_LAST_PROGRESS=-1
ADGUARDHOME_DOH_PROGRESS_MILESTONES=(0 5 20 25 30 35 50 65 75 85 95 100)

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

adguardhome_doh_selector_color_enabled() {
    [[ "${NO_COLOR+x}" == x ]] && return 1
    [[ "${TERM:-}" == dumb ]] && return 1
    if [[ "${ADGUARDHOME_DOH_TTY_FD:-}" == 0 ]]; then
        [[ -t 0 || -t 1 || -t 2 ]] || return 1
    else
        adguardhome_doh_ui_tty || return 1
    fi
}

adguardhome_doh_selector_style() {
    local color="$1" text="$2" code
    case "$color" in
        cyan) code='36' ;;
        green) code='32' ;;
        yellow) code='33' ;;
        red) code='31' ;;
        dim) code='2' ;;
        *) printf '%s' "$text"; return 0 ;;
    esac
    if adguardhome_doh_selector_color_enabled; then
        printf '\033[%sm%s\033[0m' "$code" "$text"
    else
        printf '%s' "$text"
    fi
}

adguardhome_doh_selector_clear() {
    adguardhome_doh_selector_color_enabled || return 0
    if [[ -w /dev/tty ]]; then
        printf '\033[2J\033[H' > /dev/tty 2>/dev/null || printf '\033[2J\033[H' >&2
    else
        printf '\033[2J\033[H' >&2
    fi
    return 0
}

adguardhome_doh_selector_terminal_width() {
    local width="${ADGUARDHOME_DOH_SELECTOR_WIDTH:-${ADGUARDHOME_DOH_TERMINAL_WIDTH:-${COLUMNS:-}}}" tty_size
    if ([[ ! "$width" =~ ^[0-9]+$ ]] || ((width < 1))) && [[ -t 0 || -t 1 || -t 2 ]]; then
        tty_size="$(stty size 2>/dev/null || true)"
        read -r _ width <<< "$tty_size" || true
    fi
    [[ "$width" =~ ^[0-9]+$ ]] || width=80
    ((width > 0)) || width=80
    printf '%s\n' "$width"
}

adguardhome_doh_selector_print_header() {
    local width line line_width
    width="$(adguardhome_doh_selector_terminal_width)"
    line_width=24
    ((line_width > width)) && line_width="$width"
    printf -v line '%*s' "$line_width" ''
    line="${line// /─}"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style cyan 'СЕРВИСЫ И ДОМЕНЫ')"
    adguardhome_doh_selector_emit "$line"
    return 0
}

adguardhome_doh_selector_truncate() {
    local value="$1" width="$2"
    ((width > 0)) || return 0
    if (( ${#value} <= width )); then
        printf '%s' "$value"
    elif ((width == 1)); then
        printf '…'
    else
        printf '%s…' "${value:0:width-1}"
    fi
}

adguardhome_doh_selector_pad() {
    local value="$1" width="$2" padding
    value="$(adguardhome_doh_selector_truncate "$value" "$width")"
    padding=$((width - ${#value}))
    printf '%s' "$value"
    ((padding > 0)) && printf '%*s' "$padding" ''
    return 0
}

adguardhome_doh_selector_emit_wrapped() {
    local prefix="$1" value="$2" width="$3" color="${4:-plain}"
    local continuation line word separator candidate available chunk
    local -a words=()
    ((width > 0)) || return 0
    continuation="$(printf '%*s' "${#prefix}" '')"
    line="$prefix"
    read -r -a words <<< "$value"
    for word in "${words[@]-}"; do
        separator=' '
        [[ "$line" == "$prefix" || "$line" == "$continuation" ]] && separator=''
        candidate="$line$separator$word"
        if ((${#candidate} <= width)); then
            line="$candidate"
            continue
        fi
        if [[ "$line" != "$prefix" && "$line" != "$continuation" ]]; then
            adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$color" "$line")"
            line="$continuation"
        fi
        available=$((width - ${#line}))
        if ((available < 1)); then
            adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$color" "$line")"
            line=
            available="$width"
        fi
        while ((${#word} > available)); do
            chunk="${word:0:available}"
            adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$color" "$line$chunk")"
            word="${word:available}"
            line="$continuation"
            available=$((width - ${#line}))
            if ((available < 1)); then
                line=
                available="$width"
            fi
        done
        line="$line$word"
    done
    if [[ -n "$line" ]]; then
        adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$color" "$line")"
    fi
    return 0
}

adguardhome_doh_selector_emit() {
    if [[ -w /dev/tty ]]; then
        printf '%s\n' "$1" > /dev/tty 2>/dev/null || printf '%s\n' "$1" >&2
    else
        printf '%s\n' "$1" >&2
    fi
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
    local config_dir="$1" count domains names id status_color width summary
    count="$(adguardhome_doh_selector_count_selected)"
    domains="$(adguardhome_doh_selector_domain_count "$(cd -- "$config_dir/.." && pwd -P)")"
    width="$(adguardhome_doh_selector_terminal_width)"
    if ((count > 0)); then
        status_color=green
    else
        status_color=yellow
    fi
    summary="$(adguardhome_doh_selector_truncate "Выбрано сервисов: $count/${#ADGUARDHOME_DOH_SERVICE_IDS[@]}" "$width")"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$status_color" "$summary")"
    summary="$(adguardhome_doh_selector_truncate "Активных уникальных доменов: $domains" "$width")"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style cyan "$summary")"
    names=
    for id in "${ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "$id" || continue
        [[ -n "$names" ]] && names="$names, "
        for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
            [[ "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" == "$id" ]] && names="$names${ADGUARDHOME_DOH_SERVICE_NAMES[index]}"
        done
    done
    [[ -n "$names" ]] && adguardhome_doh_selector_emit_wrapped "Сервисы: " "$names" "$width"
    return 0
}

adguardhome_doh_selector_category_line() {
    local number="$1" category="$2" total="$3" selected="$4" width="$5"
    local line
    line="[$number] $category $selected/$total"
    line="$(adguardhome_doh_selector_truncate "$line" "$width")"
    printf '%s' "$line"
    return 0
}

adguardhome_doh_selector_category_color() {
    local category="$1" selected="$2"
    if [[ "$category" == 'Экспериментальные' ]]; then
        printf 'yellow'
    elif ((selected > 0)); then
        printf 'green'
    else
        printf 'cyan'
    fi
    return 0
}

adguardhome_doh_selector_category_totals() {
    local category="$1" index
    ADGUARDHOME_DOH_SELECTOR_CATEGORY_TOTAL=0
    ADGUARDHOME_DOH_SELECTOR_CATEGORY_SELECTED=0
    for index in "${!ADGUARDHOME_DOH_SERVICE_IDS[@]}"; do
        [[ "${ADGUARDHOME_DOH_SERVICE_CATEGORIES[index]}" == "$category" ]] || continue
        ((ADGUARDHOME_DOH_SELECTOR_CATEGORY_TOTAL += 1))
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" && ((ADGUARDHOME_DOH_SELECTOR_CATEGORY_SELECTED += 1))
    done
    return 0
}

adguardhome_doh_selector_emit_commands() {
    local width="$1" first="$2" first_color="$3" second="$4" second_color="$5"
    local third="$6" third_color="$7" fourth="$8" fourth_color="$9"
    local all_length pair_one_length pair_two_length
    all_length=$((${#first} + ${#second} + ${#third} + ${#fourth} + 6))
    pair_one_length=$((${#first} + ${#second} + 2))
    pair_two_length=$((${#third} + ${#fourth} + 2))
    if ((all_length <= width)); then
        adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$first_color" "$first")  $(adguardhome_doh_selector_style "$second_color" "$second")  $(adguardhome_doh_selector_style "$third_color" "$third")  $(adguardhome_doh_selector_style "$fourth_color" "$fourth")"
    elif ((pair_one_length <= width && pair_two_length <= width)); then
        adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$first_color" "$first")  $(adguardhome_doh_selector_style "$second_color" "$second")"
        adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$third_color" "$third")  $(adguardhome_doh_selector_style "$fourth_color" "$fourth")"
    else
        adguardhome_doh_selector_emit_wrapped "" "$first" "$width" "$first_color"
        adguardhome_doh_selector_emit_wrapped "" "$second" "$width" "$second_color"
        adguardhome_doh_selector_emit_wrapped "" "$third" "$width" "$third_color"
        adguardhome_doh_selector_emit_wrapped "" "$fourth" "$width" "$fourth_color"
    fi
    return 0
}

adguardhome_doh_selector_print_categories() {
    local number category total selected width column_width first second first_color second_color
    local categories_count rows left_index right_index
    width="$(adguardhome_doh_selector_terminal_width)"
    adguardhome_doh_selector_emit ""
    adguardhome_doh_selector_emit "Категории:"
    categories_count="${#ADGUARDHOME_DOH_SELECTOR_CATEGORIES[@]}"
    if ((width >= 72)); then
        column_width=$(( (width - 2) / 2 ))
        rows=$(( (categories_count + 1) / 2 ))
        for ((number = 0; number < rows; number += 1)); do
            left_index="$number"
            right_index=$((number + rows))
            category="${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[left_index]}"
            adguardhome_doh_selector_category_totals "$category"
            total="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_TOTAL"
            selected="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_SELECTED"
            first="$(adguardhome_doh_selector_category_line "$((left_index + 1))" "$category" "$total" "$selected" "$column_width")"
            first_color="$(adguardhome_doh_selector_category_color "$category" "$selected")"
            if ((right_index < categories_count)); then
                category="${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[right_index]}"
                adguardhome_doh_selector_category_totals "$category"
                total="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_TOTAL"
                selected="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_SELECTED"
                second="$(adguardhome_doh_selector_category_line "$((right_index + 1))" "$category" "$total" "$selected" "$column_width")"
                second_color="$(adguardhome_doh_selector_category_color "$category" "$selected")"
                first="$(adguardhome_doh_selector_pad "$first" "$column_width")"
                first="$(adguardhome_doh_selector_style "$first_color" "$first")"
                second="$(adguardhome_doh_selector_style "$second_color" "$second")"
                adguardhome_doh_selector_emit "$first  $second"
            else
                adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$first_color" "$first")"
            fi
        done
    else
        for ((number = 0; number < categories_count; number += 1)); do
            category="${ADGUARDHOME_DOH_SELECTOR_CATEGORIES[number]}"
            adguardhome_doh_selector_category_totals "$category"
            total="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_TOTAL"
            selected="$ADGUARDHOME_DOH_SELECTOR_CATEGORY_SELECTED"
            first="$(adguardhome_doh_selector_category_line "$((number + 1))" "$category" "$total" "$selected" "$width")"
            first_color="$(adguardhome_doh_selector_category_color "$category" "$selected")"
            adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style "$first_color" "$first")"
        done
    fi
    adguardhome_doh_selector_emit ""
    first="$(adguardhome_doh_selector_truncate 'Команды: номер — открыть, /текст — поиск' "$width")"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style cyan "$first")"
    adguardhome_doh_selector_emit_commands "$width" \
        '[D] Стандартные' cyan '[X] Экспериментальные' yellow \
        '[Y] Итог' green '[C] Отмена' red
}

adguardhome_doh_selector_view_line() {
    local number="$1" marker_color="$2" name="$3" service_id="$4" width="$5"
    local marker='[ ]' number_prefix suffix name_width line colored_marker colored_number
    [[ "$marker_color" == green ]] && marker='[✓]'
    number_prefix="[$number] "
    suffix=" ($service_id)"
    name_width=$((width - ${#number_prefix} - ${#marker} - 1 - ${#suffix}))
    if ((name_width < 1)); then
        suffix=""
        name_width=$((width - ${#number_prefix} - ${#marker} - 1))
    fi
    if ((name_width < 1)); then
        line="$(adguardhome_doh_selector_truncate "$number_prefix$marker" "$width")"
        printf '%s' "$line"
        return 0
    fi
    name="$(adguardhome_doh_selector_truncate "$name" "$name_width")"
    colored_marker="$(adguardhome_doh_selector_style "$marker_color" "$marker")"
    colored_number="$(adguardhome_doh_selector_style cyan "$number_prefix")"
    printf '%s%s %s%s' "$colored_number" "$colored_marker" "$name" "$suffix"
}

adguardhome_doh_selector_print_view() {
    local title="$1" number index marker_color width
    width="$(adguardhome_doh_selector_terminal_width)"
    adguardhome_doh_selector_emit ""
    [[ "$title" == *: ]] || title="$title:"
    title="$(adguardhome_doh_selector_truncate "$title" "$width")"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style cyan "$title")"
    for number in "${!ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[@]}"; do
        index="${ADGUARDHOME_DOH_SELECTOR_VIEW_INDICES[number]}"; marker_color=dim
        adguardhome_doh_selector_contains "$ADGUARDHOME_DOH_SELECTOR_SELECTED" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" && marker_color=green
        adguardhome_doh_selector_emit "$(adguardhome_doh_selector_view_line "$((number + 1))" "$marker_color" "${ADGUARDHOME_DOH_SERVICE_NAMES[index]}" "${ADGUARDHOME_DOH_SERVICE_IDS[index]}" "$width")"
    done
    adguardhome_doh_selector_emit ""
    title="$(adguardhome_doh_selector_truncate 'Команды: номера — переключить' "$width")"
    adguardhome_doh_selector_emit "$(adguardhome_doh_selector_style cyan "$title")"
    adguardhome_doh_selector_emit_commands "$width" \
        '[A] Все' green '[N] Снять все' yellow \
        '[B] Назад' cyan '[C] Отмена' red
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
        adguardhome_doh_selector_clear
        adguardhome_doh_selector_print_header
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
        adguardhome_doh_selector_clear
        adguardhome_doh_selector_print_header
        adguardhome_doh_selector_summary "$config_dir"
        adguardhome_doh_selector_print_categories
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
