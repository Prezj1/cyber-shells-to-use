#!/bin/bash
# hash_crack.sh — Detect hash type and run hashcat with the right mode
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./hash_crack.sh -f hashes.txt
#   ./hash_crack.sh -h "5f4dcc3b5aa765d61d8327deb882cf99"
#   ./hash_crack.sh -f hashes.txt -w /usr/share/wordlists/rockyou.txt -r best64

WORDLIST="/usr/share/wordlists/rockyou.txt"
RULES=""
HASH_FILE=""
SINGLE_HASH=""
OUTFILE=""
EXTRA_ARGS=""

usage() {
    echo -e "hash_crack.sh — Auto-detect hash type and crack with hashcat"
    echo -e ""
    echo -e "  -f <file>      File containing hashes (one per line)"
    echo -e "  -h <hash>      Single hash string"
    echo -e "  -w <wordlist>  Wordlist (default: rockyou.txt)"
    echo -e "  -r <rules>     Hashcat rules file (e.g. best64, dive, OneRuleToRuleThemAll)"
    echo -e "  -o <file>      Output cracked hashes to file"
    echo -e "  -x <args>      Extra hashcat args (quoted)"
    echo -e "  --help         This help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -f hashes.txt"
    echo -e "  $0 -h \"5f4dcc3b5aa765d61d8327deb882cf99\""
    echo -e "  $0 -f hashes.txt -w /usr/share/wordlists/rockyou.txt -r best64"
    echo -e "  $0 -f ntlm.txt -w rockyou.txt -x \"--force\""
    exit 0
}

# ── Hash detection ────────────────────────────────────────────────────────────
detect_mode() {
    local hash="$1"
    local len=${#hash}

    # NetNTLMv2 — username::domain:challenge:response (contains ::)
    if echo "$hash" | grep -qP '^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$'; then
        echo "5600"; return   # NetNTLMv2
    fi

    # NetNTLMv1
    if echo "$hash" | grep -qP '^[^:]+::[^:]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$'; then
        echo "5500"; return   # NetNTLMv1
    fi

    # NTLMv2 from Responder (with username:domain format)
    if echo "$hash" | grep -qP '^[^:]+:[^:]+:[a-fA-F0-9]{32}:[a-fA-F0-9]+$'; then
        echo "5600"; return
    fi

    # Kerberos 5 AS-REP ($krb5asrep)
    if echo "$hash" | grep -qiP '^\$krb5asrep\$'; then
        echo "18200"; return  # AS-REP roasting
    fi

    # Kerberos 5 TGS ($krb5tgs)
    if echo "$hash" | grep -qiP '^\$krb5tgs\$'; then
        echo "13100"; return  # Kerberoasting
    fi

    # bcrypt
    if echo "$hash" | grep -qP '^\$2[aby]\$'; then
        echo "3200"; return
    fi

    # SHA-512 crypt ($6$)
    if echo "$hash" | grep -qP '^\$6\$'; then
        echo "1800"; return
    fi

    # SHA-256 crypt ($5$)
    if echo "$hash" | grep -qP '^\$5\$'; then
        echo "7400"; return
    fi

    # MD5 crypt ($1$) / apr1
    if echo "$hash" | grep -qP '^\$1\$|\$apr1\$'; then
        echo "500"; return
    fi

    # MySQL 4.1+ (*hash)
    if echo "$hash" | grep -qP '^\*[a-fA-F0-9]{40}$'; then
        echo "300"; return
    fi

    # NTLM (32 hex, no colons) — must come before MD5 check
    # Distinguish: NTLM is 32 hex. We check for common NTLM context but
    # since MD5 is also 32 hex we label both and let user pick.
    if [[ $len -eq 32 ]] && echo "$hash" | grep -qP '^[a-fA-F0-9]{32}$'; then
        echo "1000"   # NTLM (also valid for MD5 = mode 0; noted in output)
        return
    fi

    # LM hash (32 hex in pairs, often seen as LM:NT)
    if echo "$hash" | grep -qP '^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$'; then
        echo "3000"; return   # LM
    fi

    # SHA1 — 40 hex
    if [[ $len -eq 40 ]] && echo "$hash" | grep -qP '^[a-fA-F0-9]{40}$'; then
        echo "100"; return
    fi

    # SHA-256 — 64 hex
    if [[ $len -eq 64 ]] && echo "$hash" | grep -qP '^[a-fA-F0-9]{64}$'; then
        echo "1400"; return
    fi

    # SHA-512 — 128 hex
    if [[ $len -eq 128 ]] && echo "$hash" | grep -qP '^[a-fA-F0-9]{128}$'; then
        echo "1700"; return
    fi

    # Unknown
    echo "0"
}

mode_name() {
    case "$1" in
        0)     echo "MD5" ;;
        100)   echo "SHA1" ;;
        300)   echo "MySQL4.1/SHA1" ;;
        500)   echo "md5crypt / Apache MD5" ;;
        1000)  echo "NTLM (also try -m 0 for MD5)" ;;
        1400)  echo "SHA-256" ;;
        1700)  echo "SHA-512" ;;
        1800)  echo "sha512crypt \$6\$" ;;
        3000)  echo "LM" ;;
        3200)  echo "bcrypt" ;;
        5500)  echo "NetNTLMv1" ;;
        5600)  echo "NetNTLMv2" ;;
        7400)  echo "sha256crypt \$5\$" ;;
        13100) echo "Kerberos 5 TGS (Kerberoast)" ;;
        18200) echo "Kerberos 5 AS-REP (AS-REP Roast)" ;;
        *)     echo "Unknown" ;;
    esac
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) HASH_FILE="$2";   shift 2 ;;
        -h) SINGLE_HASH="$2"; shift 2 ;;
        -w) WORDLIST="$2";    shift 2 ;;
        -r) RULES="$2";       shift 2 ;;
        -o) OUTFILE="$2";     shift 2 ;;
        -x) EXTRA_ARGS="$2";  shift 2 ;;
        --help) usage ;;
        *) echo "[-] Unknown option: $1"; usage ;;
    esac
done

command -v hashcat &>/dev/null || { echo "[-] hashcat not found: sudo apt install hashcat"; exit 1; }
[[ -z "$HASH_FILE" && -z "$SINGLE_HASH" ]] && usage
[[ -f "$WORDLIST" ]] || { echo "[-] Wordlist not found: $WORDLIST"; exit 1; }

# Build temp hash file if single hash supplied
TMPFILE=""
if [[ -n "$SINGLE_HASH" ]]; then
    TMPFILE=$(mktemp /tmp/hash_XXXXXX)
    echo "$SINGLE_HASH" > "$TMPFILE"
    HASH_FILE="$TMPFILE"
    trap 'rm -f "$TMPFILE"' EXIT
fi

[[ -f "$HASH_FILE" ]] || { echo "[-] Hash file not found: $HASH_FILE"; exit 1; }

# ── Detect mode from first non-empty hash ────────────────────────────────────
SAMPLE=$(grep -v '^\s*$' "$HASH_FILE" | head -1)
MODE=$(detect_mode "$SAMPLE")
NAME=$(mode_name "$MODE")

echo "[+] Hash file   : $HASH_FILE"
echo "[+] Sample hash : $SAMPLE"
echo "[+] Detected    : mode $MODE — $NAME"
echo "[+] Wordlist    : $WORDLIST"
[[ -n "$RULES" ]] && echo "[+] Rules       : $RULES"
echo "=================================================="

# Warn on ambiguous 32-char hex (NTLM vs MD5)
if [[ "$MODE" == "1000" ]]; then
    echo "[!] 32-char hex hash — assuming NTLM (mode 1000)."
    echo "[!] If this is an MD5 hash, rerun with: hashcat -m 0 ..."
    echo ""
fi

# ── Build hashcat command ─────────────────────────────────────────────────────
CMD=(hashcat -m "$MODE" -a 0 "$HASH_FILE" "$WORDLIST")
[[ -n "$RULES"     ]] && CMD+=(-r "/usr/share/hashcat/rules/${RULES}.rule")
[[ -n "$OUTFILE"   ]] && CMD+=(--outfile "$OUTFILE")
[[ -n "$EXTRA_ARGS" ]] && CMD+=($EXTRA_ARGS)
CMD+=(--potfile-disable)   # show results every run

echo "[*] Running: ${CMD[*]}"
echo ""

"${CMD[@]}"

echo ""
echo "=================================================="
echo "[+] Done. To show cracked hashes:"
echo "    hashcat -m $MODE $HASH_FILE --show"
[[ -n "$OUTFILE" ]] && echo "[+] Output saved to: $OUTFILE"
