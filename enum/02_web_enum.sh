#!/usr/bin/env bash
set -Eeuo pipefail
usage(){ cat <<'EOF'
Usage: 02_web_enum.sh [options] TARGET
Quick, non-destructive HTTP enumeration. TARGET may be host[:port] or URL.
  -u, --url URL      Base URL
  -o, --output DIR   Output directory (default: ./boxes/<target>/web)
  -w, --wordlist F   ffuf wordlist (default: dirb/common.txt)
  -h, --help         Show help
Example: ./02_web_enum.sh -u http://192.168.45.100:8080
EOF
}
die(){ printf '[-] %s\n' "$*" >&2; exit 1; }; has(){ command -v "$1" >/dev/null 2>&1; }
url=; out=; wordlist=/usr/share/wordlists/dirb/common.txt
while (($#)); do case $1 in
  -u|--url) (($#>1))||die "$1 requires a URL"; url=$2; shift 2;;
  -o|--output) (($#>1))||die "$1 requires a directory"; out=$2; shift 2;;
  -w|--wordlist) (($#>1))||die "$1 requires a file"; wordlist=$2; shift 2;;
  -h|--help) usage; exit 0;; -*) die "Unknown option: $1 (try -h)";;
  *) [[ -z $url ]]||die 'Provide one target'; url=$1; shift;; esac; done
[[ -n $url ]]||{ usage >&2; exit 2; }; [[ $url =~ ^https?:// ]]||url="http://$url"
host=${url#*://}; host=${host%%/*}; safe=${host//[^[:alnum:]._-]/_}; out=${out:-"./boxes/$safe/web"}; mkdir -p "$out"; has curl||die 'Missing dependency: curl'
printf '[+] Target: %s\n[+] Output: %s\n' "$url" "$out"
curl -ksS --connect-timeout 8 --max-time 20 -D "$out/headers.txt" -o "$out/index.html" "$url/"||printf '[!] curl request failed\n' >&2
curl -ksS --connect-timeout 8 --max-time 20 "$url/robots.txt" -o "$out/robots.txt"||true
has whatweb && whatweb -a 3 --no-errors "$url"|tee "$out/whatweb.txt"||true
has nikto && nikto -host "$url" -output "$out/nikto.txt"||true
if has ffuf; then [[ -r $wordlist ]]||die "Wordlist not readable: $wordlist"; ffuf -s -ac -u "${url%/}/FUZZ" -w "$wordlist" -mc all -fc 404 -of json -o "$out/ffuf.json"||true; fi
printf '[+] Complete: %s\n' "$out"
