#!/usr/bin/env bash
# dir_fuzz.sh — Web directory and file fuzzing using ffuf
#
# !! FOR AUTHORIZED PENETRATION TESTING AND CTF USE ONLY !!
# Do not run against systems you do not own or have explicit written permission to test.
#
# USAGE:
#   ./dir_fuzz.sh -t <target>
#   ./dir_fuzz.sh -t 10.10.10.5
#   ./dir_fuzz.sh -t 10.10.10.5 -p 8080
#   ./dir_fuzz.sh -t 10.10.10.5 --https
#   ./dir_fuzz.sh -t 10.10.10.5 -m dirs
#   ./dir_fuzz.sh -t 10.10.10.5 -c "PHPSESSID=abc123"
#
# REQUIREMENTS: ffuf, jq

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

die()    { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
detail() { echo -e "${DIM}    $*${RESET}"; }
sep()    { echo -e "${BOLD}$(printf '─%.0s' {1..65})${RESET}"; }
header() { sep; echo -e "${BOLD}${CYAN}$*${RESET}"; sep; }


usage() {
    echo -e "${BOLD}dir_fuzz.sh${RESET} — Directory and file fuzzer using ffuf"
    echo -e ""
    echo -e "  ${CYAN}-t <target>${RESET}    Target IP or hostname (required)"
    echo -e "  ${CYAN}-p <port>${RESET}      Port (default: 80, or 443 with -s)"
    echo -e "  ${CYAN}-s${RESET}             Use HTTPS (default: HTTP)"
    echo -e "  ${CYAN}-m <mode>${RESET}      Mode: dirs | files | both  (default: both)"
    echo -e "  ${CYAN}-e <exts>${RESET}      Comma-separated extensions for file scan"
    echo -e "                 (default: .php,.asp,.aspx,.jsp,.html,.txt,.json)"
    echo -e "  ${CYAN}-c <cookie>${RESET}    Cookie string, e.g. \"PHPSESSID=abc123\""
    echo -e "  ${CYAN}-H <header>${RESET}    Extra header, e.g. \"Authorization: Bearer token\""
    echo -e "  ${CYAN}-T <threads>${RESET}   Threads for file scans (default: 50)"
    echo -e "  ${CYAN}-o <outdir>${RESET}    Output directory (default: ./ffuf_<target>_<timestamp>)"
    echo -e "  ${CYAN}-r <depth>${RESET}     Recursion depth (default: 1)"
    echo -e "  ${CYAN}-fc <codes>${RESET}    Filter HTTP status codes, e.g. \"404,403\""
    echo -e "  ${CYAN}-fs <size>${RESET}     Filter response size, e.g. \"1234\""
    echo -e "  ${CYAN}-q${RESET}             Quiet: suppress ffuf banner/progress"
    echo -e "  ${CYAN}-h${RESET}             This help"
    echo -e ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  $0 -t 10.10.10.5"
    echo -e "  $0 -t 10.10.10.5 -p 8080 -m dirs"
    echo -e "  $0 -t 10.10.10.5 -s -p 443"
    echo -e "  $0 -t 10.10.10.5 -c \"session=xyz\" -fc 404 -o ./results"
    echo -e "  $0 -t 10.10.10.5 -e \".php,.bak,.old\" -m files"
    exit 0
}

# ── Wordlists ─────────────────────────────────────────────────────────────────
# Each entry: "label|path"
DIR_WORDLISTS=(
    "raft-large-directories|/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
    "big|/usr/share/seclists/Discovery/Web-Content/big.txt"
    "dirbuster-medium|/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "raft-large-words|/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
)

FILE_WORDLISTS=(
    "big|/usr/share/seclists/Discovery/Web-Content/big.txt"
    "common|/usr/share/seclists/Discovery/Web-Content/common.txt"
    "raft-large-words|/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
)

# ── Check wordlist availability ───────────────────────────────────────────────
check_wordlists() {
    local mode="$1"
    local missing=0

    info "Checking wordlists..."

    if [[ "$mode" == "dirs" || "$mode" == "both" ]]; then
        for entry in "${DIR_WORDLISTS[@]}"; do
            local label="${entry%%|*}" path="${entry##*|}"
            if [[ -f "$path" ]]; then
                detail "[OK]  $label → $path"
            else
                warn "[MISSING] $label → $path"
                ((missing++))
            fi
        done
    fi

    if [[ "$mode" == "files" || "$mode" == "both" ]]; then
        for entry in "${FILE_WORDLISTS[@]}"; do
            local label="${entry%%|*}" path="${entry##*|}"
            if [[ -f "$path" ]]; then
                detail "[OK]  $label → $path"
            else
                warn "[MISSING] $label → $path"
                ((missing++))
            fi
        done
    fi

    if [[ "$missing" -gt 0 ]]; then
        warn "$missing wordlist(s) missing — those scans will be skipped."
        warn "Install SecLists:  sudo apt install seclists"
        warn "Install dirbuster: sudo apt install dirb"
    fi
    echo
}

# ── Build common ffuf args ────────────────────────────────────────────────────
build_ffuf_args() {
    local cookie="$1" extra_header="$2" filter_codes="$3" filter_size="$4" quiet="$5"
    local args=()

    [[ -n "$cookie" ]]       && args+=(-b "$cookie")
    [[ -n "$extra_header" ]] && args+=(-H "$extra_header")
    [[ -n "$filter_codes" ]] && args+=(-fc "$filter_codes")
    [[ -n "$filter_size" ]]  && args+=(-fs "$filter_size")
    [[ "$quiet" -eq 1 ]]     && args+=(-s)

    # Always output JSON for parsing; auto-calibrate off-by-default
    args+=(-of json)

    echo "${args[@]+"${args[@]}"}"
}

# ── Run one ffuf scan ─────────────────────────────────────────────────────────
run_ffuf() {
    local label="$1" url="$2" wordlist="$3" outfile="$4"
    shift 4
    local extra_args=("$@")

    [[ -f "$wordlist" ]] || { warn "Skipping $label — wordlist not found: $wordlist"; return; }

    info "[$label] Starting..."
    detail "URL:      $url"
    detail "Wordlist: $wordlist"
    detail "Output:   $outfile"
    echo

    # shellcheck disable=SC2068
    ffuf \
        -u "$url" \
        -w "$wordlist" \
        -o "$outfile" \
        ${extra_args[@]+"${extra_args[@]}"} \
        || warn "[$label] ffuf exited with non-zero status (check output)"

    if [[ -f "$outfile" ]]; then
        local hits
        hits=$(jq -r '.results | length' "$outfile" 2>/dev/null || echo "?")
        good "[$label] Done — $hits result(s) → $outfile"
    fi
    echo
}

# ── Parse and print results ───────────────────────────────────────────────────
parse_results() {
    local label="$1" outfile="$2"

    [[ -f "$outfile" ]] || return

    local hits
    hits=$(jq -r '.results | length' "$outfile" 2>/dev/null || echo 0)
    [[ "$hits" -eq 0 ]] && return

    echo -e "${BOLD}${YELLOW}[$label] $hits result(s):${RESET}"
    jq -r '.results[] | [.status, .length, .url] | @tsv' "$outfile" 2>/dev/null \
        | sort -k1,1n -k3,3 \
        | awk 'BEGIN{OFS="\t"} {
            status=$1; len=$2; url=$3
            if (status < 300)      colour="\033[0;32m"
            else if (status < 400) colour="\033[0;36m"
            else if (status < 500) colour="\033[1;33m"
            else                   colour="\033[0;31m"
            printf "%s%-3s\033[0m\t%s\t%s\n", colour, status, len, url
          }'
    echo
}

# ── Summary report ────────────────────────────────────────────────────────────
print_summary() {
    local outdir="$1"
    header "RESULTS SUMMARY"

    for f in "$outdir"/*.json; do
        [[ -f "$f" ]] || continue
        local label
        label=$(basename "$f" .json)
        parse_results "$label" "$f"
    done

    # Combined sorted view
    local all_results=()
    while IFS= read -r line; do
        all_results+=("$line")
    done < <(
        for f in "$outdir"/*.json; do
            [[ -f "$f" ]] || continue
            jq -r '.results[] | [.status, .url] | @tsv' "$f" 2>/dev/null
        done | sort -u
    )

    if [[ ${#all_results[@]} -gt 0 ]]; then
        local combined="$outdir/all_results.tsv"
        printf '%s\n' "${all_results[@]}" > "$combined"
        good "Combined results (deduplicated): $combined"
        good "Total unique URLs: ${#all_results[@]}"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local target="" port="" use_https=0 mode="both"
    local extensions=".php,.asp,.aspx,.jsp,.html,.txt,.json"
    local cookie="" extra_header="" outdir="" recursion_depth=1
    local threads=50 filter_codes="" filter_size="" quiet=0

    [[ $# -eq 0 ]] && usage

    while getopts "t:p:sm:e:c:H:T:o:r:f:z:qh" opt; do
        case "$opt" in
            t) target="$OPTARG" ;;
            p) port="$OPTARG" ;;
            s) use_https=1 ;;
            m) mode="$OPTARG" ;;
            e) extensions="$OPTARG" ;;
            c) cookie="$OPTARG" ;;
            H) extra_header="$OPTARG" ;;
            T) threads="$OPTARG" ;;
            o) outdir="$OPTARG" ;;
            r) recursion_depth="$OPTARG" ;;
            f) filter_codes="$OPTARG" ;;
            z) filter_size="$OPTARG" ;;
            q) quiet=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    # Handle --https and --fc / --fs long-style flags manually
    for arg in "$@"; do
        case "$arg" in
            --https) use_https=1 ;;
            --fc=*) filter_codes="${arg#--fc=}" ;;
            --fs=*) filter_size="${arg#--fs=}" ;;
        esac
    done

    # ── Validate ──────────────────────────────────────────────────────────────
    command -v ffuf &>/dev/null || die "ffuf not found. Install: sudo apt install ffuf"
    command -v jq   &>/dev/null || die "jq not found.   Install: sudo apt install jq"
    [[ -z "$target" ]] && die "Target is required (-t)"
    [[ "$mode" =~ ^(dirs|files|both)$ ]] || die "Invalid mode: $mode (dirs|files|both)"

    # ── Build base URL ────────────────────────────────────────────────────────
    local scheme="http"
    [[ "$use_https" -eq 1 ]] && scheme="https"
    [[ -z "$port" ]] && { [[ "$use_https" -eq 1 ]] && port=443 || port=80; }
    local base_url="${scheme}://${target}:${port}"

    # ── Output directory ──────────────────────────────────────────────────────
    if [[ -z "$outdir" ]]; then
        outdir="./ffuf_${target//./_}_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$outdir"

    # ── Banner ────────────────────────────────────────────────────────────────
    sep
    echo -e "${BOLD}  dir_fuzz.sh${RESET}"
    sep
    info "Target   : $base_url"
    info "Mode     : $mode"
    info "Recursion: depth $recursion_depth"
    info "Threads  : $threads (file scans)"
    info "Output   : $outdir"
    [[ -n "$filter_codes" ]] && info "Filter codes: $filter_codes"
    [[ -n "$filter_size"  ]] && info "Filter size:  $filter_size"
    echo

    check_wordlists "$mode"

    # ── Shared ffuf flags ─────────────────────────────────────────────────────
    read -ra COMMON_ARGS <<< "$(build_ffuf_args "$cookie" "$extra_header" "$filter_codes" "$filter_size" "$quiet")"

    # ── Directory scans ───────────────────────────────────────────────────────
    if [[ "$mode" == "dirs" || "$mode" == "both" ]]; then
        header "DIRECTORY FUZZING"

        for entry in "${DIR_WORDLISTS[@]}"; do
            local label="${entry%%|*}" wordlist="${entry##*|}"
            run_ffuf \
                "dirs-${label}" \
                "${base_url}/FUZZ" \
                "$wordlist" \
                "${outdir}/dirs-${label}.json" \
                -recursion \
                -recursion-depth "$recursion_depth" \
                "${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"}"
        done
    fi

    # ── File scans ────────────────────────────────────────────────────────────
    if [[ "$mode" == "files" || "$mode" == "both" ]]; then
        header "FILE FUZZING"

        for entry in "${FILE_WORDLISTS[@]}"; do
            local label="${entry%%|*}" wordlist="${entry##*|}"
            run_ffuf \
                "files-${label}" \
                "${base_url}/FUZZ" \
                "$wordlist" \
                "${outdir}/files-${label}.json" \
                -t "$threads" \
                -e "$extensions" \
                "${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"}"
        done
    fi

    # ── Parse and summarise ───────────────────────────────────────────────────
    print_summary "$outdir"

    sep
    good "All scans complete. Output: $outdir"
    echo
    info "Quick parse commands:"
    detail "Dirs:  cat ${outdir}/dirs-*.json | jq -r '.results[] | [.status,.url] | @tsv' | sort -u"
    detail "Files: cat ${outdir}/files-*.json | jq -r '.results[] | [.status,.url] | @tsv' | sort -u"
    detail "All:   cat ${outdir}/all_results.tsv"
}

main "$@"
