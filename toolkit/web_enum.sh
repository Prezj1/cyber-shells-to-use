#!/bin/bash
# web_enum.sh — Web technology fingerprinting and enumeration
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./web_enum.sh -t 10.10.10.5
#   ./web_enum.sh -t 10.10.10.5 -p 8080
#   ./web_enum.sh -u "http://10.10.10.5:8080/app"

TARGET=""; PORT="80"; USE_HTTPS=0; CUSTOM_URL=""; OUTDIR=""; COOKIE=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
vuln()   { echo -e "${RED}${BOLD}[!] $*${RESET}"; }
header() { echo -e "\n${BOLD}$(printf '=%.0s' {1..60})${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}$(printf '=%.0s' {1..60})${RESET}"; }

usage() {
    echo -e "web_enum.sh — Web fingerprinting (headers, whatweb, nikto, robots, common paths)"
    echo -e ""
    echo -e "  -t <ip>       Target IP or hostname"
    echo -e "  -p <port>     Port (default: 80)"
    echo -e "  -s            Use HTTPS"
    echo -e "  -u <url>      Full URL (overrides -t/-p/-s)"
    echo -e "  -c <cookie>   Cookie string"
    echo -e "  -o <dir>      Output directory"
    echo -e "  -h            Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.5"
    echo -e "  $0 -t 10.10.10.5 -p 8080"
    echo -e "  $0 -t 10.10.10.5 -s -p 443"
    echo -e "  $0 -u \"http://10.10.10.5:8080/app\""
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET="$2";     shift 2 ;;
        -p) PORT="$2";       shift 2 ;;
        -s) USE_HTTPS=1;     shift ;;
        -u) CUSTOM_URL="$2"; shift 2 ;;
        -c) COOKIE="$2";     shift 2 ;;
        -o) OUTDIR="$2";     shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

# Build base URL
if [[ -n "$CUSTOM_URL" ]]; then
    BASE_URL="$CUSTOM_URL"
    TARGET=$(echo "$CUSTOM_URL" | grep -oP '(?<=://)[^:/]+')
else
    [[ -z "$TARGET" ]] && { warn "Target required (-t or -u)"; usage; }
    SCHEME="http"; [[ "$USE_HTTPS" -eq 1 ]] && SCHEME="https"
    BASE_URL="${SCHEME}://${TARGET}:${PORT}"
fi

[[ -z "$OUTDIR" ]] && OUTDIR="./web_enum_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

CURL_ARGS=(-sk --max-time 10 -A "Mozilla/5.0")
[[ -n "$COOKIE" ]] && CURL_ARGS+=(-b "$COOKIE")

header "WEB ENUMERATION — $BASE_URL"
info "Output: $OUTDIR"

# ── Response headers ──────────────────────────────────────────────────────────
header "HTTP RESPONSE HEADERS"
info "Fetching headers from $BASE_URL..."
curl "${CURL_ARGS[@]}" -I "$BASE_URL" 2>/dev/null | tee "$OUTDIR/headers.txt"

# Flag interesting / missing security headers
echo ""
info "Security header analysis:"
HEADERS=$(curl "${CURL_ARGS[@]}" -I "$BASE_URL" 2>/dev/null)

check_header() {
    local name="$1" present_msg="$2" missing_msg="$3"
    if echo "$HEADERS" | grep -qi "^$name:"; then
        good "$name: $(echo "$HEADERS" | grep -i "^$name:" | head -1 | cut -d: -f2- | xargs)"
    else
        warn "MISSING: $missing_msg"
    fi
}

# Server banner
SERVER=$(echo "$HEADERS" | grep -i "^Server:" | head -1 | cut -d: -f2- | xargs)
[[ -n "$SERVER" ]] && { vuln "Server banner exposed: $SERVER"; echo "  → searchsploit \"$SERVER\""; }

X_POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1 | cut -d: -f2- | xargs)
[[ -n "$X_POWERED" ]] && vuln "X-Powered-By exposed: $X_POWERED"

check_header "Strict-Transport-Security" "" "HSTS not set"
check_header "X-Frame-Options"           "" "X-Frame-Options missing (clickjacking)"
check_header "X-Content-Type-Options"    "" "X-Content-Type-Options missing"
check_header "Content-Security-Policy"   "" "CSP not set"

# ── whatweb ───────────────────────────────────────────────────────────────────
header "WHATWEB — TECHNOLOGY FINGERPRINTING"
if command -v whatweb &>/dev/null; then
    whatweb -a 3 "$BASE_URL" 2>/dev/null | tee "$OUTDIR/whatweb.txt"
    # Suggest searchsploit for any version strings found
    grep -oP '[A-Za-z\-]+/[\d.]+' "$OUTDIR/whatweb.txt" 2>/dev/null | while read -r ver; do
        echo "  → searchsploit $(echo "$ver" | tr '/' ' ')"
    done
else
    warn "whatweb not found: sudo apt install whatweb"
fi

# ── robots.txt and sitemap ────────────────────────────────────────────────────
header "ROBOTS.TXT / SITEMAP"
for path in robots.txt sitemap.xml sitemap_index.xml security.txt .well-known/security.txt; do
    result=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/$path" 2>/dev/null)
    if [[ "$result" == "200" ]]; then
        good "Found: $BASE_URL/$path"
        curl "${CURL_ARGS[@]}" "$BASE_URL/$path" 2>/dev/null | tee "$OUTDIR/$(echo "$path" | tr '/' '_')"
    else
        warn "Not found: /$path ($result)"
    fi
done

# ── Common admin / sensitive paths ───────────────────────────────────────────
header "COMMON INTERESTING PATHS"
PATHS=(
    admin administrator admin.php admin.html login login.php
    wp-admin wp-login.php xmlrpc.php
    manager/html console phpmyadmin pma
    .git/HEAD .git/config .env .env.bak
    backup backup.zip db.sql database.sql
    config.php config.bak wp-config.php
    api/v1 api/v2 swagger swagger-ui.html api-docs
    server-status server-info info.php phpinfo.php
    upload uploads files
)

for path in "${PATHS[@]}"; do
    code=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/$path" 2>/dev/null)
    case "$code" in
        200) vuln "200 OK  : $BASE_URL/$path" ;;
        301|302) good "REDIRECT: $BASE_URL/$path → $code" ;;
        401|403) warn "AUTH REQ: $BASE_URL/$path ($code) — still interesting" ;;
        *) [[ "$code" != "404" ]] && info "$code : $BASE_URL/$path" ;;
    esac
done | tee "$OUTDIR/common_paths.txt"

# ── nikto ─────────────────────────────────────────────────────────────────────
header "NIKTO VULNERABILITY SCAN"
if command -v nikto &>/dev/null; then
    info "Running nikto (this may take a few minutes)..."
    nikto -h "$BASE_URL" ${COOKIE:+-C "$COOKIE"} -o "$OUTDIR/nikto.txt" -Format txt 2>/dev/null \
        | tee "$OUTDIR/nikto_live.txt"
else
    warn "nikto not found: sudo apt install nikto"
fi

# ── CMS detection ─────────────────────────────────────────────────────────────
header "CMS DETECTION"
PAGE=$(curl "${CURL_ARGS[@]}" "$BASE_URL" 2>/dev/null)

declare -A CMS_SIGS=(
    ["WordPress"]="wp-content|wp-includes|wordpress"
    ["Joomla"]="Joomla|/components/com_|/templates/system"
    ["Drupal"]="Drupal|/sites/default/files|drupal.js"
    ["Magento"]="Mage.Cookies|/skin/frontend|Magento"
    ["CUPS"]="CUPS|IPP|print-service"
)

for cms in "${!CMS_SIGS[@]}"; do
    if echo "$PAGE" | grep -qiE "${CMS_SIGS[$cms]}"; then
        vuln "CMS Detected: $cms"
        case "$cms" in
            WordPress)
                info "  WPScan: wpscan --url $BASE_URL --enumerate u,p,t"
                # Try to get WP version
                VER=$(curl "${CURL_ARGS[@]}" "$BASE_URL/?feed=rss2" 2>/dev/null | grep -oP 'WordPress \K[\d.]+' | head -1)
                [[ -n "$VER" ]] && { vuln "  WordPress version: $VER"; echo "  searchsploit wordpress $VER"; }
                ;;
            Joomla)
                info "  Joomscan: joomscan -u $BASE_URL"
                ;;
            Drupal)
                info "  Droopescan: droopescan scan drupal -u $BASE_URL"
                ;;
        esac
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
header "SUMMARY"
good "Output saved to: $OUTDIR"
echo ""
info "Files created:"
ls -lh "$OUTDIR/" | awk 'NR>1{print "  "$NF, "("$5")"}'
echo ""
info "Suggested next steps:"
echo "  Directory fuzzing : ./dir_fuzz.sh -t $TARGET -p $PORT"
echo "  LFI/RFI testing   : ./lfi_rfi_tester.sh -u \"$BASE_URL/page.php?file=FUZZ\""
echo "  Exploit lookup    : searchsploit \"<version from headers/whatweb>\""
