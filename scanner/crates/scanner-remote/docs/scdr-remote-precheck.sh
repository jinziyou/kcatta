#!/usr/bin/env bash
# scdr-remote-precheck.sh
#
# Run on the cyber-posture scan TARGET host as the account that scanner-remote
# will SSH into (e.g. `scdr`). Verifies every prerequisite for MVP-1:
# commands, kernel, dm-snapshot, sudoers NOPASSWD whitelist, LVM free space,
# qemu-nbd version.
#
# Usage:  ./scdr-remote-precheck.sh [-h|--help]
# Exit:   0 if all required checks pass, 1 otherwise.

set -u

usage() {
    cat <<'EOF'
Usage: scdr-remote-precheck.sh [-h|--help]

Run as the SSH account scanner-remote authenticates with (e.g. `scdr`).
Checks: command availability, kernel >= 3.x, dm-snapshot support, sudoers
NOPASSWD whitelist (via `sudo -nl`), LVM volume-group free space, qemu-nbd
version. Exits 0 on success.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

is_tty=0; [ -t 1 ] && is_tty=1
c_ok=''; c_warn=''; c_miss=''; c_info=''; c_off=''
if [ "$is_tty" = 1 ]; then
    c_ok=$'\033[32m'; c_warn=$'\033[33m'
    c_miss=$'\033[31m'; c_info=$'\033[36m'; c_off=$'\033[0m'
fi

FAIL=0
ok()   { printf '  %sOK%s   %s\n' "$c_ok"   "$c_off" "$1"; }
warn() { printf '  %sWARN%s %s\n' "$c_warn" "$c_off" "$1"; }
miss() { printf '  %sMISS%s %s\n' "$c_miss" "$c_off" "$1"; FAIL=1; }
info() { printf '  %sINFO%s %s\n' "$c_info" "$c_off" "$1"; }
section() { printf '\n[%s] %s\n' "$1" "$2"; }

# 1. required commands -----------------------------------------------------
section 1 "required commands"
for c in lvcreate lvremove lvs fsfreeze qemu-nbd ss kill pkill bash base64 awk nohup sudo; do
    if p=$(command -v "$c" 2>/dev/null); then
        ok "$c -> $p"
    else
        miss "$c not found in PATH"
    fi
done

# 2. kernel + dm-snapshot --------------------------------------------------
section 2 "kernel & modules"
krel=$(uname -r)
kmaj=${krel%%.*}
if [ "${kmaj:-0}" -ge 3 ] 2>/dev/null; then
    ok "kernel $krel"
else
    miss "kernel $krel (need >= 3.x)"
fi

if modinfo dm-snapshot >/dev/null 2>&1; then
    ok "dm-snapshot module available"
elif grep -q '^dm_snapshot ' /proc/modules 2>/dev/null \
        || [ -d /sys/module/dm_snapshot ]; then
    ok "dm-snapshot loaded / built-in"
else
    warn "dm-snapshot not detected (may be compiled into kernel; lvcreate -s will tell)"
fi

# 3. sudoers whitelist -----------------------------------------------------
section 3 "sudoers NOPASSWD whitelist (via sudo -nl)"
if sudoers=$(sudo -nl 2>/dev/null); then
    while IFS= read -r need; do
        [ -z "$need" ] && continue
        if printf '%s' "$sudoers" | grep -qF "$need"; then
            ok "whitelisted: $need"
        else
            miss "missing in sudoers: $need"
        fi
    done <<'EOF'
lvcreate -s -n scdr-snap-
lvremove -f /dev/*/scdr-snap-
lvs --noheadings --units b --nosuffix -o lv_size
fsfreeze -f
fsfreeze -u
qemu-nbd --read-only --bind=127.0.0.1
pkill -f qemu-nbd
ss -ltn
EOF
else
    miss "sudo -nl failed (no NOPASSWD rules? install /etc/sudoers.d/scdr-scan first)"
fi

# 4. LVM free space (informational; vgs is not in the default sudoers) ----
section 4 "LVM free space (informational)"
if vg_out=$(sudo -n vgs --units b --nosuffix --noheadings -o vg_name,vg_free 2>/dev/null); then
    if [ -n "$vg_out" ]; then
        printf '%s\n' "$vg_out" | while read -r name free _rest; do
            [ -z "$name" ] && continue
            free=${free%B}
            if [ "${free:-0}" -ge 536870912 ] 2>/dev/null; then
                info "VG $name free=$((free / 1024 / 1024))MiB (>=512MiB OK)"
            else
                warn "VG $name free=$((free / 1024 / 1024))MiB (< 512MiB; snapshots may fail under write pressure)"
            fi
        done
    else
        warn "no LVM volume groups found on this host"
    fi
else
    info "skipped (vgs not in default sudoers; run 'sudo vgs' manually to verify)"
fi

# 5. qemu-nbd version ------------------------------------------------------
section 5 "qemu-nbd version (recommend >= 5.0)"
if v=$(qemu-nbd --version 2>/dev/null | head -1); then
    ok "$v"
    qv=$(printf '%s' "$v" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    qmaj=${qv%%.*}
    if [ -n "$qmaj" ] && [ "$qmaj" -lt 5 ] 2>/dev/null; then
        warn "qemu-nbd $qv is older than 5.0; --persistent / --bind behaviour may differ"
    fi
else
    miss "qemu-nbd not runnable"
fi

# summary ------------------------------------------------------------------
printf '\n'
if [ "$FAIL" = 0 ]; then
    printf '%sPASS%s -- target is ready for scanner-remote.\n' "$c_ok" "$c_off"
else
    printf '%sFAIL%s -- fix the MISS items above before scanning.\n' "$c_miss" "$c_off"
fi
exit $FAIL
