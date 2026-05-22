#!/bin/bash
# ldap_enum.sh — LDAP / Active Directory enumeration
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./ldap_enum.sh -t 10.10.10.5 -d domain.local
#   ./ldap_enum.sh -t 10.10.10.5 -d domain.local -u user -p password

TARGET=""; DOMAIN=""; USER=""; PASS=""; OUTDIR=""; DC_BASE=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
die()    { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
vuln()   { echo -e "${RED}${BOLD}[VULN] $*${RESET}"; }
header() { echo -e "\n${BOLD}$(printf '=%.0s' {1..60})${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}$(printf '=%.0s' {1..60})${RESET}"; }

usage() {
    echo -e "ldap_enum.sh — LDAP / Active Directory enumeration"
    echo -e ""
    echo -e "  -t <ip>       Target DC IP (required)"
    echo -e "  -d <domain>   Domain (e.g. domain.local) (required)"
    echo -e "  -u <user>     Username (omit for null/anonymous bind)"
    echo -e "  -p <pass>     Password"
    echo -e "  -o <dir>      Output directory"
    echo -e "  -h            Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.5 -d domain.local"
    echo -e "  $0 -t 10.10.10.5 -d domain.local -u ldapuser -p Password123"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET="$2";  shift 2 ;;
        -d) DOMAIN="$2";  shift 2 ;;
        -u) USER="$2";    shift 2 ;;
        -p) PASS="$2";    shift 2 ;;
        -o) OUTDIR="$2";  shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$TARGET" ]] && { warn "Target required (-t)"; usage; }
[[ -z "$DOMAIN" ]] && { warn "Domain required (-d)"; usage; }
[[ -z "$OUTDIR" ]] && OUTDIR="./ldap_enum_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

# Build DC base from domain (domain.local → DC=domain,DC=local)
DC_BASE=$(echo "$DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":"")}')
info "Domain   : $DOMAIN"
info "DC Base  : $DC_BASE"
info "Target   : $TARGET"
info "Output   : $OUTDIR"

# ldapsearch auth args
ldap_auth() {
    if [[ -n "$USER" ]]; then
        echo "-D '${USER}@${DOMAIN}' -w '${PASS}'"
    else
        echo "-x"   # anonymous bind
    fi
}

run_ldap() {
    local label="$1" filter="$2" attrs="$3" outfile="$OUTDIR/${label}.txt"
    info "Querying: $label"
    eval "ldapsearch -x -H ldap://$TARGET $(ldap_auth) -b '$DC_BASE' '$filter' $attrs 2>/dev/null" \
        | tee "$outfile" || warn "Query failed: $label"
}

command -v ldapsearch &>/dev/null || die "ldapsearch not found: sudo apt install ldap-utils"

# ── Anonymous / null bind test ────────────────────────────────────────────────
header "ANONYMOUS BIND TEST"
anon_result=$(ldapsearch -x -H "ldap://$TARGET" -b "$DC_BASE" "(objectClass=*)" dn 2>/dev/null | head -5)
if [[ -n "$anon_result" ]]; then
    vuln "Anonymous/null LDAP bind successful — no credentials needed!"
else
    info "Anonymous bind failed — credentials required"
fi

# ── Domain info ───────────────────────────────────────────────────────────────
header "DOMAIN INFO"
run_ldap "domain_info" "(objectClass=domain)" "dc description whenCreated"

# ── Users ─────────────────────────────────────────────────────────────────────
header "DOMAIN USERS"
run_ldap "all_users" "(objectClass=person)" \
    "sAMAccountName displayName description memberOf pwdLastSet lastLogon userAccountControl"

# Extract clean user list
grep "sAMAccountName:" "$OUTDIR/all_users.txt" 2>/dev/null \
    | awk '{print $2}' | sort -u > "$OUTDIR/usernames.txt"
count=$(wc -l < "$OUTDIR/usernames.txt")
good "Extracted $count usernames → $OUTDIR/usernames.txt"

# Flag accounts with descriptions (often contain passwords)
header "USER DESCRIPTIONS (check for passwords)"
grep -A1 "sAMAccountName:\|description:" "$OUTDIR/all_users.txt" 2>/dev/null \
    | grep -B1 "description:" | grep -v "^--$" \
    | tee "$OUTDIR/user_descriptions.txt"

# ── Password policy ───────────────────────────────────────────────────────────
header "PASSWORD POLICY"
run_ldap "password_policy" "(objectClass=domainDNS)" \
    "minPwdLength maxPwdAge lockoutThreshold lockoutDuration pwdHistoryLength pwdProperties"
info "Check lockoutThreshold before password spraying!"

# ── Privileged groups ─────────────────────────────────────────────────────────
header "PRIVILEGED GROUPS"
for group in "Domain Admins" "Enterprise Admins" "Schema Admins" "Administrators" \
             "Account Operators" "Backup Operators" "Remote Desktop Users" "DNSAdmins"; do
    result=$(eval "ldapsearch -x -H ldap://$TARGET $(ldap_auth) -b '$DC_BASE' \
        '(&(objectClass=group)(cn=${group}))' member 2>/dev/null" | grep "^member:")
    if [[ -n "$result" ]]; then
        good "Members of '$group':"
        echo "$result" | sed 's/member: /  /' | while read -r dn; do
            # Extract CN from DN
            echo "$dn" | grep -oP 'CN=\K[^,]+'
        done
        echo ""
    fi
done | tee "$OUTDIR/privileged_groups.txt"

# ── Kerberoastable accounts (SPN set) ─────────────────────────────────────────
header "KERBEROASTABLE ACCOUNTS (SPNs)"
run_ldap "kerberoastable" \
    "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))" \
    "sAMAccountName servicePrincipalName memberOf"
kcount=$(grep "sAMAccountName:" "$OUTDIR/kerberoastable.txt" 2>/dev/null | wc -l)
[[ "$kcount" -gt 0 ]] && vuln "$kcount Kerberoastable account(s) found — run GetUserSPNs.py"

# ── AS-REP roastable (no pre-auth required) ───────────────────────────────────
header "AS-REP ROASTABLE ACCOUNTS"
# userAccountControl flag 4194304 = DONT_REQUIRE_PREAUTH
run_ldap "asrep_roastable" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    "sAMAccountName userAccountControl"
acount=$(grep "sAMAccountName:" "$OUTDIR/asrep_roastable.txt" 2>/dev/null | wc -l)
[[ "$acount" -gt 0 ]] && vuln "$acount AS-REP roastable account(s) — run GetNPUsers.py"

# ── Computers ─────────────────────────────────────────────────────────────────
header "DOMAIN COMPUTERS"
run_ldap "computers" "(objectClass=computer)" \
    "cn dNSHostName operatingSystem operatingSystemVersion lastLogon"
grep "sAMAccountName:\|operatingSystem:" "$OUTDIR/computers.txt" 2>/dev/null \
    | grep -v "^--" | tee "$OUTDIR/computer_list.txt"

# ── windapsearch (bonus if available) ────────────────────────────────────────
if command -v windapsearch &>/dev/null; then
    header "WINDAPSEARCH"
    windapsearch --dc "$TARGET" -d "$DOMAIN" \
        ${USER:+-u "$USER"} ${PASS:+-p "$PASS"} \
        --users 2>/dev/null | tee "$OUTDIR/windapsearch_users.txt"
    windapsearch --dc "$TARGET" -d "$DOMAIN" \
        ${USER:+-u "$USER"} ${PASS:+-p "$PASS"} \
        --privileged-users 2>/dev/null | tee "$OUTDIR/windapsearch_privileged.txt"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "SUMMARY"
good "Output saved to: $OUTDIR"
echo ""
info "Key files:"
echo "  $OUTDIR/usernames.txt           ← user list for spraying"
echo "  $OUTDIR/user_descriptions.txt   ← check for plaintext passwords"
echo "  $OUTDIR/privileged_groups.txt   ← high-value targets"
echo "  $OUTDIR/kerberoastable.txt      ← accounts to Kerberoast"
echo "  $OUTDIR/asrep_roastable.txt     ← accounts to AS-REP roast"
echo ""
info "Next steps:"
echo "  Kerberoast:   GetUserSPNs.py $DOMAIN/user:pass -dc-ip $TARGET -request -outputfile tgs.txt"
echo "  AS-REP roast: GetNPUsers.py $DOMAIN/ -usersfile $OUTDIR/usernames.txt -dc-ip $TARGET -no-pass"
echo "  Spray:        ./password_spray.sh -t $TARGET -u $OUTDIR/usernames.txt -p 'Password123' -d $DOMAIN"
