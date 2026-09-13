#!/usr/bin/env bash
set -Eeuo pipefail
usage(){ cat <<'EOF'
Usage: 01_workspace_enum.sh [options] TARGET
Create an OSCP workspace, scan all TCP ports, then enumerate services.
  -o, --output DIR  Workspace root (default: ./boxes)
  -r, --rate N      Nmap minimum rate (default: 3000)
  -h, --help        Show help
Example: ./01_workspace_enum.sh -o ~/boxes 192.168.45.100
EOF
}
die(){ printf '[-] %s\n' "$*" >&2; exit 1; }; need(){ command -v "$1" >/dev/null || die "Missing dependency: $1"; }
root=./boxes; rate=3000; target=
while (($#)); do case $1 in
  -o|--output) (($#>1))||die "$1 requires a directory"; root=$2; shift 2;;
  -r|--rate) (($#>1))||die "$1 requires a number"; rate=$2; shift 2;;
  -h|--help) usage; exit 0;; -*) die "Unknown option: $1 (try -h)";;
  *) [[ -z $target ]]||die 'Provide exactly one target'; target=$1; shift;; esac; done
[[ -n $target ]]||{ usage >&2; exit 2; }; [[ $rate =~ ^[1-9][0-9]*$ ]]||die 'Rate must be a positive integer'; need nmap
safe=${target//[^[:alnum:]._-]/_}; base="$root/$safe"; mkdir -p "$base"/{nmap,web,loot,exploits,screenshots,notes}
nmap -n -Pn -p- --min-rate "$rate" --max-retries 2 -T4 -oA "$base/nmap/allports" "$target"
ports=$(awk -F/ '/^[0-9]+\/tcp[[:space:]]+open/{print $1}' "$base/nmap/allports.nmap"|paste -sd, -)
[[ -n $ports ]]||die 'No open TCP ports found'; printf '[+] TCP ports: %s\n' "$ports"
nmap -n -Pn -sC -sV --version-all -p "$ports" -oA "$base/nmap/services" "$target"
printf '[+] Results: %s/nmap\n' "$base"
