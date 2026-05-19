#!/bin/bash
# smb_enum.sh — SMB enumeration wrapper
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./smb_enum.sh -t 10.10.10.5
#   ./smb_enum.sh -t 10.10.10.5 -u guest -p ""
#   ./smb_enum.sh -t 10.10.10.5 -u user -p password -d DOMAIN

TARGET=""; USER=""; PASS=""; DOMAIN="WORKGROUP"; OUTDIR=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
die()    { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
vuln()   { echo -e "${RED}${BOLD}[VULN] $*${RESET}"; }
header() { echo -e "\n${BOLD}$(printf '=%.0s' {1..60})${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}$(printf '=%.0s' {1..60})${RESET}"; }

usage() {
    cat <<USAGE
smb_enum.sh — SMB enumeration (shares, users, policy, signing)

  -t <ip>       Target IP (required)
  -u <user>     Username (default: empty / null session)
  -p <pass>     Password (default: empty)
  -d <domain>   Domain or workgroup (default: WORKGROUP)
  -o <dir>      Output directory
  -h            Help

Examples:
  $0 -t 10.10.10.5
  $0 -t 10.10.10.5 -u guest -p ""
  $0 -t 10.10.10.5 -u administrator -p Password123 -d CORP
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET="$2";  shift 2 ;;
        -u) USER="$2";    shift 2 ;;
        -p) PASS="$2";    shift 2 ;;
        -d) DOMAIN="$2";  shift 2 ;;
        -o) OUTDIR="$2";  shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$TARGET" ]] && { warn "Target required (-t)"; usage; }
[[ -z "$OUTDIR" ]] && OUTDIR="./smb_enum_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

LOG="$OUTDIR/smb_enum.log"
echo "smb_enum.sh — $(date) — $TARGET" > "$LOG"

# Auth string helpers
cme_auth() {
    if [[ -n "$USER" ]]; then echo "-u '$USER' -p '$PASS' -d '$DOMAIN'"
    else echo "-u '' -p ''"; fi
}
smbclient_auth() {
    if [[ -n "$USER" ]]; then echo "-U '${DOMAIN}\\${USER}%${PASS}'"
    else echo "-N"; fi
}

# ── Connectivity check ────────────────────────────────────────────────────────
header "PORT CHECK"
info "Checking SMB ports on $TARGET..."
for port in 139 445; do
    if nc -zw3 "$TARGET" "$port" 2>/dev/null; then
        good "Port $port open"
    else
        warn "Port $port closed"
    fi
done

# ── nmap SMB scripts ──────────────────────────────────────────────────────────
header "NMAP SMB SCRIPTS"
if command -v nmap &>/dev/null; then
    info "Running nmap SMB NSE scripts..."
    nmap_out="$OUTDIR/nmap_smb.txt"
    nmap -p 139,445 --script \
        smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,\
smb-vuln-ms08-067,smb-enum-shares,smb-enum-users,smb-os-discovery \
        "$TARGET" -oN "$nmap_out" 2>/dev/null
    cat "$nmap_out"

    # Flag EternalBlue
    if grep -q "VULNERABLE\|ms17-010" "$nmap_out" 2>/dev/null; then
        vuln "MS17-010 (EternalBlue) detected! Check: searchsploit ms17-010"
    fi
    # Flag signing disabled
    if grep -qi "message_signing: disabled\|signing: false\|signing not required" "$nmap_out" 2>/dev/null; then
        vuln "SMB signing DISABLED — relay attacks possible (ntlmrelayx)"
    fi
else
    warn "nmap not found — skipping NSE scripts"
fi

# ── crackmapexec ──────────────────────────────────────────────────────────────
header "CRACKMAPEXEC — HOST INFO"
if command -v crackmapexec &>/dev/null || command -v cme &>/dev/null; then
    CME=$(command -v crackmapexec || command -v cme)
    eval "$CME smb '$TARGET' $(cme_auth)" 2>/dev/null | tee "$OUTDIR/cme_host.txt"

    header "CRACKMAPEXEC — SHARES"
    eval "$CME smb '$TARGET' $(cme_auth) --shares" 2>/dev/null | tee "$OUTDIR/cme_shares.txt"

    header "CRACKMAPEXEC — USERS"
    eval "$CME smb '$TARGET' $(cme_auth) --users" 2>/dev/null | tee "$OUTDIR/cme_users.txt"

    header "CRACKMAPEXEC — GROUPS"
    eval "$CME smb '$TARGET' $(cme_auth) --groups" 2>/dev/null | tee "$OUTDIR/cme_groups.txt"

    header "CRACKMAPEXEC — PASSWORD POLICY"
    eval "$CME smb '$TARGET' $(cme_auth) --pass-pol" 2>/dev/null | tee "$OUTDIR/cme_passpol.txt"

    header "CRACKMAPEXEC — LOGGED ON USERS"
    eval "$CME smb '$TARGET' $(cme_auth) --loggedon-users" 2>/dev/null | tee "$OUTDIR/cme_loggedon.txt"
else
    warn "crackmapexec not found: sudo apt install crackmapexec"
fi

# ── enum4linux ────────────────────────────────────────────────────────────────
header "ENUM4LINUX"
if command -v enum4linux &>/dev/null; then
    info "Running enum4linux -a (full enumeration)..."
    if [[ -n "$USER" ]]; then
        enum4linux -a -u "$USER" -p "$PASS" "$TARGET" 2>/dev/null | tee "$OUTDIR/enum4linux.txt"
    else
        enum4linux -a "$TARGET" 2>/dev/null | tee "$OUTDIR/enum4linux.txt"
    fi

    # Extract user list
    grep "user:\[" "$OUTDIR/enum4linux.txt" 2>/dev/null | awk -F'[][]' '{print $2}' \
        | sort -u > "$OUTDIR/users.txt"
    local_count=$(wc -l < "$OUTDIR/users.txt")
    [[ "$local_count" -gt 0 ]] && good "Extracted $local_count users → $OUTDIR/users.txt"
else
    warn "enum4linux not found: sudo apt install enum4linux"
fi

# ── smbclient share listing & browsing ───────────────────────────────────────
header "SMBCLIENT — SHARE LIST"
if command -v smbclient &>/dev/null; then
    eval "smbclient -L '//$TARGET' $(smbclient_auth) 2>/dev/null" | tee "$OUTDIR/smbclient_shares.txt"

    # Try to list contents of common interesting shares
    for share in Users Backup backup ADMIN$ C$ IPC$ wwwroot www html Share share Public public; do
        result=$(eval "smbclient '//$TARGET/$share' $(smbclient_auth) -c 'ls' 2>/dev/null" || true)
        if [[ -n "$result" && ! "$result" =~ "NT_STATUS_ACCESS_DENIED" && ! "$result" =~ "NT_STATUS_BAD_NETWORK_NAME" ]]; then
            good "Share accessible: $share"
            echo "=== $share ===" >> "$OUTDIR/share_contents.txt"
            echo "$result"       >> "$OUTDIR/share_contents.txt"
        fi
    done
else
    warn "smbclient not found: sudo apt install smbclient"
fi

# ── smbmap ────────────────────────────────────────────────────────────────────
header "SMBMAP — SHARE PERMISSIONS"
if command -v smbmap &>/dev/null; then
    if [[ -n "$USER" ]]; then
        smbmap -H "$TARGET" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | tee "$OUTDIR/smbmap.txt"
    else
        smbmap -H "$TARGET" 2>/dev/null | tee "$OUTDIR/smbmap.txt"
    fi
    # Flag writable shares
    grep -i "READ, WRITE\|READ/WRITE" "$OUTDIR/smbmap.txt" 2>/dev/null | while read -r line; do
        vuln "WRITABLE SHARE: $line"
    done
else
    warn "smbmap not found: sudo apt install smbmap"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "SUMMARY"
good "Output saved to: $OUTDIR"
echo ""
info "Files created:"
ls -lh "$OUTDIR/" | awk '{print "  " $0}'
echo ""
info "Next steps:"
echo "  • Check share_contents.txt for sensitive files"
echo "  • Use users.txt with password_spray.sh"
echo "  • If signing disabled: ntlmrelayx.py -tf targets.txt -smb2support"
echo "  • If MS17-010: use exploit/windows/smb/ms17_010_eternalblue in msfconsole"
