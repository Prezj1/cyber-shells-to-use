#!/usr/bin/env bash
# snmp_searchsploit.sh
# Parse nmap SNMP scan output and query searchsploit for known exploits.
#
# USAGE:
#   ./snmp_searchsploit.sh -f <nmap_output_file>   # from saved nmap output
#   ./snmp_searchsploit.sh -t <target>              # run nmap live then search
#   ./snmp_searchsploit.sh -h                       # help
#
# NMAP FORMATS SUPPORTED:
#   Normal output (-oN), grepable (-oG), XML (-oX)
#   Or pipe nmap output directly:
#     nmap -sU -p 161 --script snmp-info,snmp-sysdescr <target> | ./snmp_searchsploit.sh -f -
#
# REQUIREMENTS:
#   - searchsploit (from exploitdb)
#   - nmap (if using -t)
#   - xmllint (optional, for XML parsing)

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
die()  { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info() { echo -e "${CYAN}[*] $*${RESET}"; }
good() { echo -e "${GREEN}[+] $*${RESET}"; }
warn() { echo -e "${YELLOW}[-] $*${RESET}"; }
sep()  { echo -e "${BOLD}$(printf '─%.0s' {1..60})${RESET}"; }

usage() {
    echo -e "${BOLD}snmp_searchsploit.sh${RESET} — correlate nmap SNMP output with searchsploit"
    echo -e ""
    echo -e "  ${CYAN}-f <file>${RESET}      nmap output file (use '-' for stdin)"
    echo -e "  ${CYAN}-t <target>${RESET}    run nmap SNMP scan against target, then search"
    echo -e "  ${CYAN}-c <community>${RESET} SNMP community string (default: public)"
    echo -e "  ${CYAN}-o <file>${RESET}      write results to file"
    echo -e "  ${CYAN}-j${RESET}             also output JSON summary"
    echo -e "  ${CYAN}-v${RESET}             verbose: show searchsploit output even when empty"
    echo -e "  ${CYAN}-h${RESET}             this help"
    echo -e ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  $0 -f scan.nmap"
    echo -e "  $0 -t 192.168.1.0/24"
    echo -e "  nmap -sU -p 161 --script snmp-info 10.0.0.1 | $0 -f -"
    exit 0
}

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in searchsploit grep sed awk; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [[ ${#missing[@]} -gt 0 ]] && die "Missing dependencies: ${missing[*]}"
}

# ── Run live nmap scan ────────────────────────────────────────────────────────
run_nmap() {
    local target="$1" community="$2"
    command -v nmap &>/dev/null || die "nmap not found; install it or use -f with saved output"
    info "Running nmap SNMP scan against: $target"
    nmap -sU -p 161,162 \
        --script snmp-info,snmp-sysdescr,snmp-brute,snmp-win32-software,snmp-processes \
        --script-args "snmp-brute.communitiesdb=/dev/null,snmp.community=$community" \
        -T4 "$target" 2>/dev/null
}

# ── Extract interesting strings from nmap output ─────────────────────────────
# Returns one search term per line
extract_terms() {
    local input="$1"

    # Patterns we care about in SNMP output:
    #   sysDescr lines (e.g. "Cisco IOS Software, Version 12.4")
    #   Hardware/OS strings
    #   Software names from snmp-win32-software
    #   SNMP engine IDs / vendor OIDs (less useful for sploit search but included)

    grep -Eoi \
        '(Cisco IOS[^,\n]*|Juniper[^,\n]*|Windows[^,\n]*|Linux [0-9][^\s,\n]*|Net-SNMP [0-9][^\s,\n]*|OpenSSH [0-9][^\s,\n]*|IIS [0-9][^\s,\n]*|Apache [0-9][^\s,\n]*|vsftpd [0-9][^\s,\n]*|ProFTPD [0-9][^\s,\n]*|Postfix [0-9][^\s,\n]*|SNMP Agent [^\n]*|HP [^\n,]*|Huawei [^\n,]*)' \
        "$input" 2>/dev/null | sort -u || true

    # Also grab bare version strings that follow "Version" or "v" keywords
    grep -Eoi 'Version[[:space:]]+[0-9][0-9a-z._-]*' "$input" 2>/dev/null \
        | awk '{print $2}' | sort -u || true

    # Grab software names listed by snmp-win32-software (indented list items)
    grep -E '^\s+\|_\s+' "$input" 2>/dev/null \
        | sed 's/.*|_\s*//' | awk '{print $1, $2}' | sort -u || true
}

# ── Build tidy search terms ───────────────────────────────────────────────────
normalise_terms() {
    # Deduplicate, strip trailing punctuation, remove very short tokens
    sort -u | sed 's/[,;:]$//' | awk 'length($0) > 4'
}

# ── Query searchsploit ────────────────────────────────────────────────────────
query_searchsploit() {
    local term="$1" verbose="$2" outfile="$3" json_arr_ref="$4"
    local result

    result=$(searchsploit --colour "$term" 2>/dev/null || true)

    # searchsploit exits 0 even with no results; detect "No Results"
    if echo "$result" | grep -qi "no results"; then
        [[ "$verbose" == "1" ]] && warn "No results for: $term"
        return
    fi

    # Filter out the header/separator lines to check if real hits exist
    local hits
    hits=$(echo "$result" | grep -Ev '^(-|=|\s*$|Exploit Title|Path)' || true)
    [[ -z "$hits" ]] && return

    sep
    echo -e "${BOLD}${YELLOW}Search term:${RESET} $term"
    echo "$result"
    echo

    # Append to output file if requested
    if [[ -n "$outfile" ]]; then
        {
            echo "=== $term ==="
            echo "$result"
            echo
        } >> "$outfile"
    fi

    # Accumulate for JSON
    if [[ -n "$json_arr_ref" ]]; then
        local count
        count=$(echo "$hits" | grep -c . || true)
        # Use nameref to append to the caller's array
        eval "${json_arr_ref}+=(\"$(echo "$term" | sed 's/"/\\"/g'):$count\")"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local file="" target="" community="public" outfile="" do_json=0 verbose=0

    while getopts "f:t:c:o:jvh" opt; do
        case "$opt" in
            f) file="$OPTARG" ;;
            t) target="$OPTARG" ;;
            c) community="$OPTARG" ;;
            o) outfile="$OPTARG" ;;
            j) do_json=1 ;;
            v) verbose=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    check_deps

    [[ -z "$file" && -z "$target" ]] && usage

    local tmpfile
    tmpfile=$(mktemp /tmp/snmp_nmap_XXXXXX)
    trap 'rm -f "$tmpfile"' EXIT

    # ── Get nmap data ─────────────────────────────────────────────────────────
    if [[ -n "$target" ]]; then
        run_nmap "$target" "$community" | tee "$tmpfile"
    elif [[ "$file" == "-" ]]; then
        cat /dev/stdin > "$tmpfile"
    else
        [[ -f "$file" ]] || die "File not found: $file"
        cp "$file" "$tmpfile"
    fi

    # ── Show raw parsed terms ─────────────────────────────────────────────────
    info "Extracting SNMP version/product strings..."
    mapfile -t terms < <(extract_terms "$tmpfile" | normalise_terms)

    if [[ ${#terms[@]} -eq 0 ]]; then
        warn "No recognisable product/version strings found in SNMP output."
        warn "Check that the file contains nmap SNMP script output."
        exit 0
    fi

    good "Found ${#terms[@]} unique search terms:"
    printf '  • %s\n' "${terms[@]}"
    echo

    # ── Init output file ──────────────────────────────────────────────────────
    if [[ -n "$outfile" ]]; then
        echo "snmp_searchsploit results — $(date)" > "$outfile"
        echo "Source: ${file:-$target}" >> "$outfile"
        echo >> "$outfile"
    fi

    # ── Query searchsploit for each term ──────────────────────────────────────
    local json_hits=()
    local found=0

    info "Querying searchsploit..."
    for term in "${terms[@]}"; do
        query_searchsploit "$term" "$verbose" "$outfile" json_hits
        # Track whether anything was found
        [[ ${#json_hits[@]} -gt ${found} ]] && found=${#json_hits[@]}
    done

    sep
    if [[ ${#json_hits[@]} -eq 0 ]]; then
        warn "No exploits found for any extracted terms."
    else
        good "Done. Matches found for ${#json_hits[@]} term(s)."
        [[ -n "$outfile" ]] && good "Results written to: $outfile"
    fi

    # ── Optional JSON summary ─────────────────────────────────────────────────
    if [[ "$do_json" -eq 1 ]]; then
        local json_out="${outfile%.txt}.json"
        [[ -z "$outfile" ]] && json_out="snmp_results.json"
        {
            echo "{"
            echo "  \"source\": \"${file:-$target}\","
            echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
            echo "  \"terms_searched\": ${#terms[@]},"
            echo "  \"matches\": ["
            local i=0
            for entry in "${json_hits[@]}"; do
                local t="${entry%%:*}" c="${entry##*:}"
                ((i++))
                [[ $i -lt ${#json_hits[@]} ]] \
                    && echo "    { \"term\": \"$t\", \"exploit_count\": $c }," \
                    || echo "    { \"term\": \"$t\", \"exploit_count\": $c }"
            done
            echo "  ]"
            echo "}"
        } > "$json_out"
        good "JSON summary: $json_out"
    fi
}

main "$@"
