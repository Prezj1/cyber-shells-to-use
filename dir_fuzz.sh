#!/usr/bin/env bash
# dir_fuzz.sh — Fast automated web fuzzing wrapper

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    echo -e "${YELLOW}Usage: $0 -u <target_ip_or_domain> [-p <port>] [-s] [-o <out_dir>]${NC}"
    echo -e "  -u : Target Base (e.g., 10.10.11.50 or domain.local)"
    echo -e "  -p : Non-standard port (optional, e.g., 8080)"
    echo -e "  -s : Use HTTPS scheme instead of default HTTP"
    echo -e "  -o : Output folder destination (default: ./fuzz_results)"
    exit 1
}

SCHEME="http"
PORT=""
OUT_DIR="./fuzz_results"

while getopts "u:p:so:" opt; do
    case ${opt} in
        u ) TARGET=$OPTARG ;;
        p ) PORT=$OPTARG ;;
        s ) SCHEME="https" ;;
        o ) OUT_DIR=$OPTARG ;;
        * ) usage ;;
    esac
done

if [ -z "${TARGET:-}" ]; then usage; fi
command -v gobuster >/dev/null 2>&1 || { echo -e "${RED}[!] gobuster is required but not installed.${NC}" >&2; exit 1; }

# Build Target URL string safely
TARGET=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's/\/$//')
if [ -n "$PORT" ]; then
    BASE_URL="${SCHEME}://${TARGET}:${PORT}/"
else
    BASE_URL="${SCHEME}://${TARGET}/"
fi

mkdir -p "$OUT_DIR"
echo -e "${GREEN}[+] Directing Gobuster target matrix to: ${YELLOW}$BASE_URL${NC}"
echo -e "${GREEN}[+] Saving raw logs to: ${YELLOW}$OUT_DIR/${NC}\n"

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

# 1. Execute Directory Discovery
echo -e "${GREEN}--- Stage 1: Running Directory Fuzzing Profiles ---${NC}"
for entry in "${DIR_WORDLISTS[@]}"; do
    NAME="${entry%%|*}"
    WPATH="${entry#*|}"
    
    if [ -f "$WPATH" ]; then
        echo -e "[*] Fuzzing directories with profile: ${YELLOW}$NAME${NC}"
        gobuster dir -u "$BASE_URL" -w "$WPATH" -q -z -o "$OUT_DIR/dir_${NAME}.txt"
    else
        echo -e "${RED}[!] Skipping $NAME: File not found at $WPATH${NC}"
    fi
done

# 2. Execute File Extension Discovery
echo -e "\n${GREEN}--- Stage 2: Running File-Specific Extension Profiles ---${NC}"
# Standard OSCP web discovery extensions matrix
EXTENSIONS="php,txt,html,bak,zip,pdf,config"

for entry in "${FILE_WORDLISTS[@]}"; do
    NAME="${entry%%|*}"
    WPATH="${entry#*|}"
    
    if [ -f "$WPATH" ]; then
        echo -e "[*] Fuzzing extensions ($EXTENSIONS) via profile: ${YELLOW}$NAME${NC}"
        gobuster dir -u "$BASE_URL" -w "$WPATH" -x "$EXTENSIONS" -q -z -o "$OUT_DIR/files_${NAME}.txt"
    else
        echo -e "${RED}[!] Skipping $NAME: File not found at $WPATH${NC}"
    fi
done

echo -e "\n${GREEN}[+] All active enumeration cycles successfully saved to '$OUT_DIR'.${NC}"