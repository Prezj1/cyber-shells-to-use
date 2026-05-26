#!/usr/bin/env bash
# nmap_sploit.sh — Correlate Nmap banners against Searchsploit

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ -z "${1:-}" ] || [ ! -f "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <nmap_output_file_or_grepable_file>${NC}"
    exit 1
fi

command -v searchsploit >/dev/null 2>&1 || { echo -e "${RED}[!] searchsploit is required but not installed.${NC}" >&2; exit 1; }

echo -e "${GREEN}[+] Analyzing Nmap entries inside: ${YELLOW}$1${NC}"
echo -e "=================================================================\n"

# Extract port, service, and version details from standard or grepable output formats
grep -E '^[0-9]+/tcp|^[0-9]+/udp|Ports:' "$1" | while read -r line; do
    # Simple check to extract banner strings from standard .nmap or grepable .gnmap files
    if [[ "$line" =~ ([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]*(.*) ]]; then
        PORT="${BASH_REMATCH[1]}"
        PROTO="${BASH_REMATCH[2]}"
        SERVICE="${BASH_REMATCH[3]}"
        VERSION="${BASH_REMATCH[4]}"
        
        # Strip trailing carriage returns or irrelevant formatting noise
        VERSION=$(echo "$VERSION" | tr -d '\r' | xargs)
        
        echo -e "${GREEN}[*] Port $PORT/$PROTO ($SERVICE) -> Version String: ${YELLOW}${VERSION:-Unknown}${NC}"
        
        # Order query optimization: try full specific version name string first, fall back to base service
        if [ -n "$VERSION" ]; then
            echo -e "Running query: searchsploit \"$SERVICE $VERSION\""
            searchsploit "$SERVICE $VERSION"
            echo "-----------------------------------------------------------------"
        else
            echo -e "Running query: searchsploit \"$SERVICE\""
            searchsploit "$SERVICE"
            echo "-----------------------------------------------------------------"
        fi
    fi
done