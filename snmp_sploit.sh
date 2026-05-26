#!/usr/bin/env bash
# snmp_sploit.sh — Check SNMP service footprints for known public exploits

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ -z "${1:-}" ] || [ ! -f "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <nmap_output_file>${NC}"
    exit 1
fi

command -v searchsploit >/dev/null 2>&1 || { echo -e "${RED}[!] searchsploit is required but not installed.${NC}" >&2; exit 1; }

echo -e "${GREEN}[+] Looking for active SNMP fingerprints inside: ${YELLOW}$1${NC}\n"

# Verify if SNMP exists within the targeted file context
if ! grep -qi "snmp" "$1"; then
    echo -e "${YELLOW}[-] No explicit SNMP signatures tracked inside the provided file context.${NC}"
    exit 0
fi

# Locate the engine/device version signature extracted via nmap NSE scripts
# (e.g., snmp-sysdescr output captures hardware architecture and OS firmware versions)
SYS_DESCR=$(grep -A 5 -i "snmp" "$1" | grep -E "sysdescr:|System details:" | head -n 1 | cut -d':' -f2- | xargs)

if [ -n "$SYS_DESCR" ]; then
    echo -e "${GREEN}[+] Extracted SNMP System Fingerprint:${NC}"
    echo -e "${YELLOW}$SYS_DESCR${NC}\n"
    
    # Isolate key indicators (e.g., "Cisco", "Linux 2.6", "Windows Version") for better search relevancy
    BASE_HARDWARE=$(echo "$SYS_DESCR" | awk '{print $1" "$2}')
    
    echo -e "${GREEN}[*] Querying hardware architecture identifiers...${NC}"
    echo "Running query: searchsploit \"snmp $BASE_HARDWARE\""
    searchsploit "snmp $BASE_HARDWARE"
    
    echo -e "\n-----------------------------------------------------------------"
    echo -e "${GREEN}[*] Running broad service fallback search profiles...${NC}"
    searchsploit "snmp"
else
    echo -e "${YELLOW}[!] Found SNMP open, but could not parse a detailed system description script output.${NC}"
    echo -e "${GREEN}[*] Falling back to standard SNMP software suite checks...${NC}\n"
    searchsploit "snmp"
fi