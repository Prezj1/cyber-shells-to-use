#!/usr/bin/env bash
set -Eeuo pipefail
usage(){ cat <<'EOF'
Usage: 04_ad_enum.sh [options] TARGET
Quick unauthenticated Active Directory service enumeration.
  -o, --output DIR   Output directory (default: ./boxes/<target>/ad)
  -d, --domain NAME  AD DNS domain for DNS queries
  -h, --help         Show help
Example: ./04_ad_enum.sh -d corp.local 192.168.45.10
EOF
}
die(){ printf '[-] %s\n' "$*" >&2; exit 1; }; has(){ command -v "$1" >/dev/null 2>&1; }
target=; out=; domain=
while (($#)); do case $1 in
 -o|--output) (($#>1))||die "$1 requires a directory"; out=$2; shift 2;;
 -d|--domain) (($#>1))||die "$1 requires a name"; domain=$2; shift 2;;
 -h|--help) usage; exit 0;; -*) die "Unknown option: $1 (try -h)";;
 *) [[ -z $target ]]||die 'Provide exactly one target'; target=$1; shift;; esac; done
[[ -n $target ]]||{ usage >&2; exit 2; }; has nmap||die 'Missing dependency: nmap'
safe=${target//[^[:alnum:]._-]/_}; out=${out:-"./boxes/$safe/ad"}; mkdir -p "$out"; ports=53,88,135,139,389,445,464,636,3268,3269,5985,9389
nmap -n -Pn -sC -sV -p "$ports" --script-timeout 30s -oA "$out/ad-services" "$target"
has smbclient && smbclient -L "//$target" -N 2>&1|tee "$out/smb-null.txt"||true
has rpcclient && rpcclient -U '' -N "$target" -c 'srvinfo;enumdomusers;enumdomgroups;getdompwinfo' 2>&1|tee "$out/rpc-null.txt"||true
has enum4linux-ng && enum4linux-ng -A "$target" -oA "$out/enum4linux-ng"||true
if [[ -n $domain ]]&&has dig; then { dig +short "_ldap._tcp.dc._msdcs.$domain" SRV; dig +short "$domain" ANY; }|tee "$out/dns-domain.txt"; fi
printf '[+] Results: %s\n' "$out"
