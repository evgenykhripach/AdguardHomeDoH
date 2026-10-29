#!/usr/bin/env bash
# Disposable Linux systemd experiment only. Does not touch application services.
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
script="$project_root/tests/fixtures/recovery/maintenance_timer_probe.py"
[[ "$EUID" == 0 && "$(cat /proc/1/comm)" == systemd ]] || { echo 'Requires isolated root systemd runner.' >&2; exit 1; }
[[ "$(systemctl --version | awk 'NR == 1 {print $2}')" == 255 ]] || { echo 'Requires systemd 255.' >&2; exit 1; }
scratch="$(mktemp -d /tmp/doh-maintenance-lab.XXXXXXXX)"
chmod 700 "$scratch"
printf 'original' > "$scratch/target"
chmod 600 "$scratch/target"
id="$(/usr/bin/python3 "$script" prepare "$scratch" --candidate candidate)"
[[ "$id" =~ ^[a-f0-9]{32}$ ]] || exit 1
unit="doh-maintenance-lab-$id"
caller=
cleanup() {
    local original=$? state description transient
    trap - EXIT
    if [[ -n "$caller" ]] && kill -0 "$caller" 2>/dev/null; then
        kill -KILL "$caller" 2>/dev/null || true
        wait "$caller" 2>/dev/null || true
    fi
    state="$(systemctl show "$unit.timer" -p LoadState --value 2>/dev/null || true)"
    if [[ "$state" != not-found && -n "$state" ]]; then
        description="$(systemctl show "$unit.timer" -p Description --value 2>/dev/null || true)"
        transient="$(systemctl show "$unit.timer" -p Transient --value 2>/dev/null || true)"
        if [[ "$description" != "DoHDNS lab $id" || "$transient" != yes ]]; then
            echo "Unknown timer identity; retained $scratch" >&2
            exit 1
        fi
        systemctl stop "$unit.timer" || { echo "Timer stop failed; retained $scratch" >&2; exit 1; }
    fi
    rm -rf -- "$scratch"
    exit "$original"
}
trap cleanup EXIT
(
    /usr/bin/python3 "$script" arm "$scratch" --delay 10
    /usr/bin/python3 "$script" publish "$scratch"
    : > "$scratch/published"
    exec sleep 120
) &
caller=$!
for ((i=0; i<100; i++)); do
    [[ -f "$scratch/published" ]] && break
    kill -0 "$caller" 2>/dev/null || { wait "$caller"; exit 1; }
    sleep 0.1
done
[[ -f "$scratch/published" && "$(cat "$scratch/target")" == candidate ]]
kill -KILL "$caller"
wait "$caller" 2>/dev/null || true
for ((i=0; i<200; i++)); do
    if [[ "$(cat "$scratch/target")" == original ]] && \
       /usr/bin/python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["state"] == "restored"' "$scratch/plan.json"; then
        echo 'PASS: independent systemd timer restored disposable target after caller SIGKILL.'
        echo 'Not tested: reboot, application services, concurrent vendor writers or production recovery.'
        exit 0
    fi
    sleep 0.1
done
systemctl status "$unit.timer" "$unit.service" --no-pager >&2 || true
exit 1
