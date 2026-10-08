#!/usr/bin/env bash
#
# kerbtime.sh - Sync Kali's clock to a lab Domain Controller (or reset to normal NTP).
#
# Kerberos rejects tickets when the client/KDC clock skew exceeds ~5 minutes
# (KRB_AP_ERR_SKEW). In a lab the DC is the time authority, so this script
# syncs Kali's UTC clock to the DC. When you're done, reset puts Kali back
# on real-world NTP time.
#
# Usage:
#   sudo ./kerbtime.sh <DC_IP>     Sync Kali's clock to the DC
#   sudo ./kerbtime.sh -r          Reset Kali's clock back to NTP (real time)
#   ./kerbtime.sh -h               Show this help
#

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

# --- help -------------------------------------------------------------------
usage() {
    cat <<EOF
$SCRIPT_NAME - sync Kali's clock to a lab DC, or reset it to normal NTP time.

USAGE:
    sudo ./$SCRIPT_NAME <DC_IP>     Sync Kali's clock to the given DC IP
    sudo ./$SCRIPT_NAME -r          Reset Kali's clock back to NTP (real time)
    ./$SCRIPT_NAME -h               Show this help message

EXAMPLES:
    sudo ./$SCRIPT_NAME 10.0.2.9    # fix clock skew before a Kerberos request
    sudo ./$SCRIPT_NAME -r          # put the clock back to real time when done

NOTES:
    * Must be run with sudo/root (except -h).
    * Syncing stops systemd-timesyncd so the manual time holds. It does NOT
      persist across a reboot - just re-run it at the start of each session.
    * rdate syncs the absolute UTC instant, which is what Kerberos checks.
      Ignore what the DC's GUI wall-clock shows; trust the sync.
EOF
}

# --- helpers ----------------------------------------------------------------
err() { printf 'Error: %s\n' "$1" >&2; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "This action needs root. Re-run with: sudo ./$SCRIPT_NAME $*"
        exit 1
    fi
}

valid_ip() {
    # Basic IPv4 sanity check (four 0-255 octets).
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra octets <<< "$ip"
    for o in "${octets[@]}"; do
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}

# --- actions ----------------------------------------------------------------
sync_to_dc() {
    local dc_ip="$1"

    if ! valid_ip "$dc_ip"; then
        err "'$dc_ip' is not a valid IPv4 address."
        exit 1
    fi

    if ! command -v rdate >/dev/null 2>&1; then
        err "rdate is not installed. Install it with: sudo apt install rdate"
        exit 1
    fi

    echo "[*] Current Kali time : $(date)"
    echo "[*] Target DC         : $dc_ip"

    echo "[*] Disabling automatic NTP (set-ntp false)..."
    timedatectl set-ntp false

    echo "[*] Stopping systemd-timesyncd so it doesn't override the sync..."
    systemctl stop systemd-timesyncd 2>/dev/null || true

    echo "[*] Syncing clock to DC via rdate..."
    if ! rdate -n "$dc_ip"; then
        err "rdate failed to reach $dc_ip. Is the DC up and reachable?"
        err "Re-enabling NTP so you're not left on a bad clock."
        timedatectl set-ntp true
        systemctl start systemd-timesyncd 2>/dev/null || true
        exit 1
    fi

    echo "[+] Done. Kali time is now: $(date)"
    echo "[i] This may look wrong (shifted hours) - that's expected."
    echo "[i] It matches the DC's UTC clock, which is what Kerberos checks."
    echo "[i] Run 'sudo ./$SCRIPT_NAME -r' when you're finished to go back to real time."
}

reset_time() {
    echo "[*] Re-enabling automatic NTP (set-ntp true)..."
    timedatectl set-ntp true

    echo "[*] Starting systemd-timesyncd..."
    systemctl start systemd-timesyncd 2>/dev/null || true

    echo "[*] Waiting a moment for the clock to resync..."
    sleep 3

    echo "[+] Done. Kali time is now: $(date)"
    echo "[i] Clock is back on real-world NTP time."
}

# --- argument parsing -------------------------------------------------------
if [[ $# -eq 0 ]]; then
    err "No arguments given."
    echo
    usage
    exit 1
fi

case "$1" in
    -h|--help)
        usage
        exit 0
        ;;
    -r|--reset)
        require_root "$@"
        reset_time
        ;;
    -*)
        err "Unknown option: $1"
        echo
        usage
        exit 1
        ;;
    *)
        require_root "$@"
        sync_to_dc "$1"
        ;;
esac
