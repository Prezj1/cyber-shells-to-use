#!/bin/bash
# screenshot_notes.sh — Create OSCP exam folder structure and note templates
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./screenshot_notes.sh -t 10.10.10.5
#   ./screenshot_notes.sh -l targets.txt
#   ./screenshot_notes.sh -t 10.10.10.5 -n "Lame" -o ./exam

TARGETS=(); TARGET_FILE=""; OUTDIR="./exam_$(date +%Y%m%d)"; NAME=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
good()  { echo -e "${GREEN}[+] $*${RESET}"; }
info()  { echo -e "${CYAN}[*] $*${RESET}"; }
header(){ echo -e "\n${BOLD}$(printf '=%.0s' {1..60})${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}$(printf '=%.0s' {1..60})${RESET}"; }

usage() {
    echo -e "screenshot_notes.sh — Create exam folder structure and note templates"
    echo -e ""
    echo -e "  -t <ip>      Single target IP"
    echo -e "  -l <file>    File with one IP per line (optionally \"IP name\" per line)"
    echo -e "  -n <name>    Machine name label (e.g. \"Lame\", \"Legacy\")"
    echo -e "  -o <dir>     Base output directory (default: ./exam_<date>)"
    echo -e "  -h           Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.5"
    echo -e "  $0 -t 10.10.10.5 -n \"Legacy\" -o ./oscp_exam"
    echo -e "  $0 -l targets.txt -o ./exam"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGETS+=("$2");    shift 2 ;;
        -l) TARGET_FILE="$2";   shift 2 ;;
        -n) NAME="$2";          shift 2 ;;
        -o) OUTDIR="$2";        shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ ${#TARGETS[@]} -eq 0 && -z "$TARGET_FILE" ]] && { echo "Target required (-t or -l)"; usage; }

# Load targets file — supports "IP name" format
if [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || { echo "File not found: $TARGET_FILE"; exit 1; }
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        ip=$(echo "$line" | awk '{print $1}')
        label=$(echo "$line" | awk '{print $2}')
        TARGETS+=("${ip}${label:+|$label}")
    done < "$TARGET_FILE"
fi

mkdir -p "$OUTDIR"

create_target() {
    local entry="$1"
    local ip label dir

    # Split "IP|name" if name was provided
    ip="${entry%%|*}"
    label="${entry##*|}"
    [[ "$label" == "$ip" ]] && label=""
    [[ -n "$NAME" ]] && label="$NAME"

    dir="$OUTDIR/${ip}${label:+_$label}"

    mkdir -p "$dir"/{screenshots,scans,exploits,loot,proof}

    # ── notes.md template ─────────────────────────────────────────────────────
    cat > "$dir/notes.md" <<NOTES
# ${ip}${label:+ — $label}

**Date:** $(date +%Y-%m-%d)
**Status:** [ ] Initial Access  [ ] User  [ ] Root/Admin

---

## Open Ports

\`\`\`
nmap -sC -sV -oN scans/nmap_initial.txt $ip
nmap -p- -T4 -oN scans/nmap_allports.txt $ip
nmap -sU --top-ports 20 -oN scans/nmap_udp.txt $ip
\`\`\`

| Port | State | Service | Version |
|------|-------|---------|---------|
|      |       |         |         |

---

## Enumeration

### Web
- URL:
- Tech stack:
- Interesting directories:
- Parameters tested:

### SMB
- Shares:
- Null session:
- Users found:

### Other Services
-

---

## Exploitation

### Vulnerability
-

### Exploit Used
-

### Steps
1.
2.
3.

### Proof of Execution
\`\`\`
whoami:
id:
hostname:
\`\`\`

---

## Privilege Escalation

### Vector
-

### Steps
1.
2.
3.

---

## Proof

| File | Hash |
|------|------|
| local.txt / user.txt | \` \` |
| proof.txt / root.txt | \` \` |

**Screenshot checklist:**
- [ ] whoami / id output
- [ ] hostname / ip output
- [ ] proof.txt contents with above

---

## Loot

| Item | Value |
|------|-------|
| Credentials | |
| Hashes | |
| SSH keys | |
| Internal IPs discovered | |

---

## Notes / Rabbit Holes
-
NOTES

    # ── commands.sh cheatsheet ────────────────────────────────────────────────
    cat > "$dir/commands.sh" <<CMDS
#!/bin/bash
# Quick command reference for $ip

TARGET="$ip"
LHOST="\$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1)"

# ── Scanning ──────────────────────────────────────────────────────────────────
nmap -sC -sV -oN scans/nmap_initial.txt \$TARGET
nmap -p- -T4 --min-rate 5000 -oN scans/nmap_allports.txt \$TARGET
nmap -sU --top-ports 20 -oN scans/nmap_udp.txt \$TARGET

# ── Exploit lookup ────────────────────────────────────────────────────────────
./nmap_searchsploit.sh scans/nmap_initial.txt

# ── Web enumeration ───────────────────────────────────────────────────────────
./web_enum.sh -t \$TARGET
./dir_fuzz.sh -t \$TARGET -f 404
./lfi_rfi_tester.sh -u "http://\$TARGET/FUZZ"

# ── SMB ───────────────────────────────────────────────────────────────────────
./smb_enum.sh -t \$TARGET
enum4linux -a \$TARGET

# ── Shells ────────────────────────────────────────────────────────────────────
./rev_shell_gen.sh -i \$LHOST -p 4444
nc -lvnp 4444

# ── File transfer ─────────────────────────────────────────────────────────────
./upload_and_exec.sh -f /opt/linpeas.sh

# ── Post exploitation ─────────────────────────────────────────────────────────
# (run on target)
# ./linux_privesc_check.sh -o /tmp/privesc.txt
# ./loot.sh -o /tmp/loot

# ── Proof ─────────────────────────────────────────────────────────────────────
./proof_checker.sh -t \$TARGET -u root -k ~/.ssh/id_rsa
CMDS

    good "Created: $dir"
    info "  notes.md     — structured markdown notes template"
    info "  commands.sh  — target-specific command cheatsheet"
    info "  screenshots/ — drop .png proof screenshots here"
    info "  scans/       — nmap and ffuf output"
    info "  exploits/    — exploit files and modifications"
    info "  loot/        — credentials, hashes, keys"
    info "  proof/       — proof.txt and root.txt copies"
}

header "CREATING EXAM STRUCTURE"
info "Base directory: $OUTDIR"

for target in "${TARGETS[@]}"; do
    create_target "$target"
done

# ── Master index ──────────────────────────────────────────────────────────────
INDEX="$OUTDIR/README.md"
cat > "$INDEX" <<INDEX
# OSCP Exam Notes — $(date +%Y-%m-%d)

## Targets

| IP | Name | Status | local.txt | proof.txt |
|----|------|--------|-----------|-----------|
$(for t in "${TARGETS[@]}"; do
    ip="${t%%|*}"; label="${t##*|}"; [[ "$label" == "$ip" ]] && label=""
    echo "| $ip | ${label:-—} | [ ] | \` \` | \` \` |"
done)

## Time Log

| Time | Target | Action |
|------|--------|--------|
| $(date +%H:%M) | — | Exam started |

## Proof Hashes

\`\`\`
# Fill in as you go
\`\`\`
INDEX

good "Master index: $INDEX"

header "DONE"
good "Exam structure created in: $OUTDIR"
echo ""
info "Folder layout:"
find "$OUTDIR" -type d | sort | sed "s|$OUTDIR||;s|^|  |"
echo ""
info "Start each machine with:"
echo "  cat $OUTDIR/<IP>/notes.md"
echo "  bash $OUTDIR/<IP>/commands.sh"
