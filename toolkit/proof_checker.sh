#!/bin/bash
# proof_checker.sh — Grab proof.txt / local.txt from owned boxes for OSCP reporting
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./proof_checker.sh -t 10.10.10.5 -u root -k ~/.ssh/id_rsa
#   ./proof_checker.sh -l targets.txt -u root -p password

TARGETS=()
TARGET_FILE=""
SSH_USER=""
SSH_PASS=""
SSH_KEY=""
SSH_PORT=22
OUTDIR="./proof_$(date +%Y%m%d_%H%M%S)"
OUTFILE=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
good()  { echo -e "${GREEN}[+] $*${RESET}"; }
info()  { echo -e "${CYAN}[*] $*${RESET}"; }
warn()  { echo -e "${YELLOW}[-] $*${RESET}"; }
vuln()  { echo -e "${RED}${BOLD}[PROOF] $*${RESET}"; }
sep()   { echo -e "${BOLD}$(printf '=%.0s' {1..65})${RESET}"; }
header(){ sep; echo -e "${BOLD}${CYAN}  $*${RESET}"; sep; }

usage() {
    echo -e "proof_checker.sh — Collect OSCP proof files from owned machines"
    echo -e ""
    echo -e "  -t <ip>       Single target IP"
    echo -e "  -l <file>     File with one IP per line"
    echo -e "  -u <user>     SSH username"
    echo -e "  -p <pass>     SSH password (uses sshpass)"
    echo -e "  -k <keyfile>  SSH private key"
    echo -e "  -P <port>     SSH port (default: 22)"
    echo -e "  -o <dir>      Output directory (default: ./proof_<timestamp>)"
    echo -e "  -h            Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.5 -u root -k ~/.ssh/id_rsa"
    echo -e "  $0 -t 10.10.10.5 -u root -p toor"
    echo -e "  $0 -l owned.txt -u administrator -p Password123"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGETS+=("$2");    shift 2 ;;
        -l) TARGET_FILE="$2";   shift 2 ;;
        -u) SSH_USER="$2";      shift 2 ;;
        -p) SSH_PASS="$2";      shift 2 ;;
        -k) SSH_KEY="$2";       shift 2 ;;
        -P) SSH_PORT="$2";      shift 2 ;;
        -o) OUTDIR="$2";        shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$SSH_USER" ]]                          && { warn "SSH user required (-u)"; usage; }
[[ ${#TARGETS[@]} -eq 0 && -z "$TARGET_FILE" ]] && { warn "Target required (-t or -l)"; usage; }

# Load target file
if [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || { warn "Target file not found: $TARGET_FILE"; exit 1; }
    mapfile -t FILE_TARGETS < <(grep -v '^\s*#\|^\s*$' "$TARGET_FILE")
    TARGETS+=("${FILE_TARGETS[@]}")
fi

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.txt"
echo "OSCP Proof Summary — $(date)" > "$SUMMARY"
echo "======================================" >> "$SUMMARY"

# ── Build SSH command prefix ──────────────────────────────────────────────────
build_ssh() {
    local ip="$1"
    local opts=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$SSH_PORT")

    if [[ -n "$SSH_KEY" ]]; then
        opts+=(-i "$SSH_KEY")
        echo "ssh ${opts[*]} ${SSH_USER}@${ip}"
    elif [[ -n "$SSH_PASS" ]]; then
        command -v sshpass &>/dev/null || { warn "sshpass not found: sudo apt install sshpass"; return 1; }
        echo "sshpass -p '$SSH_PASS' ssh ${opts[*]} ${SSH_USER}@${ip}"
    else
        echo "ssh ${opts[*]} ${SSH_USER}@${ip}"
    fi
}

# ── Remote command runner ─────────────────────────────────────────────────────
run_remote() {
    local ip="$1"
    local cmd="$2"
    local ssh_cmd
    ssh_cmd=$(build_ssh "$ip")
    eval "$ssh_cmd" "$cmd" 2>/dev/null
}

# ── Process one target ────────────────────────────────────────────────────────
check_target() {
    local ip="$1"
    local target_dir="$OUTDIR/$ip"
    mkdir -p "$target_dir"

    header "TARGET: $ip"

    # Test connectivity
    if ! ping -c1 -W2 "$ip" &>/dev/null; then
        warn "$ip — host unreachable (ping)"
    fi

    # Test SSH
    local ssh_cmd
    ssh_cmd=$(build_ssh "$ip")

    if ! eval "$ssh_cmd" "echo connected" &>/dev/null; then
        warn "$ip — SSH connection failed"
        echo "[$ip] SSH FAILED" >> "$SUMMARY"
        return
    fi

    good "$ip — SSH connected as $SSH_USER"

    # ── Collect proof context ─────────────────────────────────────────────────
    info "Collecting identity info..."
    WHOAMI=$(run_remote "$ip" "whoami")
    ID_OUT=$(run_remote "$ip" "id")
    HOSTNAME=$(run_remote "$ip" "hostname")
    IP_OUT=$(run_remote "$ip" "hostname -I 2>/dev/null || ip a | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \$2}'")

    echo "Target  : $ip"      | tee -a "$target_dir/proof_context.txt"
    echo "User    : $WHOAMI"   | tee -a "$target_dir/proof_context.txt"
    echo "ID      : $ID_OUT"   | tee -a "$target_dir/proof_context.txt"
    echo "Hostname: $HOSTNAME" | tee -a "$target_dir/proof_context.txt"
    echo "IP(s)   : $IP_OUT"   | tee -a "$target_dir/proof_context.txt"
    echo "Date    : $(date)"   | tee -a "$target_dir/proof_context.txt"

    # ── Hunt for proof files ──────────────────────────────────────────────────
    info "Searching for proof files..."

    # OSCP standard locations
    PROOF_PATHS=(
        "/root/proof.txt"
        "/root/root.txt"
        "/home/*/proof.txt"
        "/home/*/user.txt"
        "/home/*/local.txt"
        "/Documents/proof.txt"
        "C:/Users/Administrator/Desktop/proof.txt"
        "C:/Users/Administrator/Desktop/root.txt"
    )

    local found_any=0
    for path in "${PROOF_PATHS[@]}"; do
        # Use glob expansion on remote (via find for safety)
        local content
        content=$(run_remote "$ip" "cat $path 2>/dev/null" || true)
        if [[ -n "$content" ]]; then
            vuln "FOUND: $path"
            echo "  Hash: $content"
            echo ""
            echo "[$ip] $path : $content" >> "$SUMMARY"
            echo "$content" > "$target_dir/$(basename "$path")"
            found_any=1
        fi
    done

    # Broader search if nothing found yet
    if [[ "$found_any" -eq 0 ]]; then
        info "Standard locations empty — searching broadly..."
        FOUND=$(run_remote "$ip" "find / -name 'proof.txt' -o -name 'root.txt' -o -name 'user.txt' -o -name 'local.txt' 2>/dev/null | head -10")
        if [[ -n "$FOUND" ]]; then
            warn "Found files at non-standard paths:"
            echo "$FOUND" | while read -r f; do
                content=$(run_remote "$ip" "cat '$f' 2>/dev/null")
                [[ -n "$content" ]] && vuln "$f → $content"
                echo "[$ip] $f : $content" >> "$SUMMARY"
            done
        else
            warn "$ip — No proof files found"
            echo "[$ip] NO PROOF FILES FOUND" >> "$SUMMARY"
        fi
    fi

    # ── Save screenshot-ready summary ─────────────────────────────────────────
    {
        echo "========================================"
        echo "TARGET   : $ip"
        echo "USER     : $WHOAMI"
        echo "ID       : $ID_OUT"
        echo "HOSTNAME : $HOSTNAME"
        run_remote "$ip" "cat /root/proof.txt /root/root.txt /home/*/proof.txt /home/*/user.txt 2>/dev/null | head -5" || true
        echo "========================================"
    } > "$target_dir/screenshot_block.txt"

    good "Saved to: $target_dir"
    echo "" >> "$SUMMARY"
}

# ── Run all targets ───────────────────────────────────────────────────────────
for target in "${TARGETS[@]}"; do
    check_target "$target"
done

# ── Final summary ─────────────────────────────────────────────────────────────
header "SUMMARY"
cat "$SUMMARY"
sep
good "All done. Output: $OUTDIR"
info "Submit proof hashes and screenshot_block.txt contents in your exam report."
