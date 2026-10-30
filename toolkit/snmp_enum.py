#!/usr/bin/env python3
"""
snmp_enum.py - Parse snmpwalk / AutoRecon SNMP output and surface interesting findings.

Usage:
    python3 snmp_enum.py snmp_walk.txt
    cat snmp_walk.txt | python3 snmp_enum.py
    python3 snmp_enum.py snmp_walk.txt --all          # also dump decoded-but-boring lines
    python3 snmp_enum.py snmp_walk.txt --no-color
    python3 snmp_enum.py snmp_walk.txt --searchsploit # run searchsploit on installed software

Accepts both numeric OIDs (.1.3.6.1.2.1...) and the symbolic 'iso.3.6.1...' form
that net-snmp prints when it can't resolve the full MIB.
"""

import sys
import re
import json
import shutil
import argparse
import subprocess
from collections import defaultdict

# ---------------------------------------------------------------------------
# Known OID prefixes worth calling out. Keys are numeric OIDs *without* the
# leading dot. We match on prefix, so table rows (prefix + .index) are caught.
# category: used for grouping / severity.  loot=True means "grep this hard".
# ---------------------------------------------------------------------------
OID_MAP = {
    # --- System / identity ---
    "1.3.6.1.2.1.1.1.0":          ("System description",      "system",  False),
    "1.3.6.1.2.1.1.3.0":          ("Uptime",                  "system",  False),
    "1.3.6.1.2.1.1.4.0":          ("System contact",          "system",  True),
    "1.3.6.1.2.1.1.5.0":          ("System / host name",      "system",  True),
    "1.3.6.1.2.1.1.6.0":          ("System location",         "system",  True),

    # --- Host Resources MIB: the good stuff ---
    "1.3.6.1.2.1.25.1.6.0":       ("Number of processes",     "system",  False),
    "1.3.6.1.2.1.25.4.2.1.2":     ("Running process name",    "process", True),
    "1.3.6.1.2.1.25.4.2.1.4":     ("Process executable path", "process", True),
    "1.3.6.1.2.1.25.4.2.1.5":     ("Process command line",    "process", True),  # creds live here
    "1.3.6.1.2.1.25.6.3.1.2":     ("Installed software",      "software", True),
    "1.3.6.1.2.1.25.2.3.1.3":     ("Storage / mounted vol",   "storage", True),

    # --- User accounts (classic SNMP username leak) ---
    "1.3.6.1.4.1.77.1.2.25":      ("Windows/LanMgr username", "users",   True),
    "1.3.6.1.4.1.77.1.2.3.1.1":   ("Share name",              "shares",  True),

    # --- Network ---
    "1.3.6.1.2.1.2.2.1.2":        ("Interface description",   "network", False),
    "1.3.6.1.2.1.2.2.1.6":        ("Interface MAC address",   "network", False),
    "1.3.6.1.2.1.4.20.1.1":       ("IPv4 address (iface)",    "network", False),
    "1.3.6.1.2.1.4.22.1.2":       ("ARP cache MAC",           "network", False),
    "1.3.6.1.2.1.6.13.1.3":       ("TCP listening port",      "ports",   True),
    "1.3.6.1.2.1.6.13.1.1":       ("TCP conn state",          "ports",   False),
    "1.3.6.1.2.1.7.5.1.2":        ("UDP listening port",      "ports",   True),

    # --- IPv6 route table (your sample lives here - mostly noise) ---
    "1.3.6.1.2.1.55.1.12":        ("IPv6 route table entry",  "ipv6",    False),
    "1.3.6.1.2.1.55.1.8":         ("IPv6 address entry",      "network", False),
}

# Credential-ish patterns to hunt inside any STRING value (esp. process args).
CRED_PATTERNS = [
    re.compile(r"(?i)\bpass(word|wd)?\s*[=:]\s*\S+"),
    re.compile(r"(?i)\b-p\s+\S+"),                 # mysql -p, etc.
    re.compile(r"(?i)\b--password[= ]\S+"),
    re.compile(r"(?i)\b(secret|token|api[_-]?key|apikey|auth)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\buser(name)?\s*[=:]\s*\S+"),
    re.compile(r"(?i)\b-u\s+\S+"),
    re.compile(r"(?i)(mysql|postgres(ql)?|mongodb|redis|ftp|smb)://\S+"),
    re.compile(r"(?i)\bconnectionstring\b.*"),
    re.compile(r"(?i)\b(aws_access_key_id|aws_secret_access_key)\b.*"),
    re.compile(r"[A-Za-z0-9+/]{32,}={0,2}"),       # long base64-ish blobs
]

# Interesting software/process substrings worth flagging even without creds.
INTERESTING_PROCS = re.compile(
    r"(?i)\b(mysql|mariadb|postgres|mssql|sqlservr|mongod|redis|"
    r"tomcat|java|jenkins|apache|httpd|nginx|php|python|node|"
    r"vnc|teamviewer|anydesk|rdp|xrdp|openvpn|wireguard|"
    r"powershell|cmd\.exe|psexec|net\.exe|backup|cron|task)\b"
)


# Terms too generic to feed searchsploit (noise / FP magnets).
SS_STOPWORDS = {
    "the", "and", "for", "x86_64", "x86", "amd64", "i386", "linux", "windows",
    "update", "security", "package", "library", "runtime", "server", "client",
    "service", "tools", "common", "core", "base", "system", "microsoft",
}


def searchsploit_available() -> bool:
    return shutil.which("searchsploit") is not None


def build_query(software: str) -> str:
    """Turn a raw installed-software string into a sane searchsploit query.

    Keeps the product name plus a version number if present, drops arch/noise.
    'OpenSSH 8.2p1 Ubuntu-4ubuntu0.1' -> 'OpenSSH 8.2'
    """
    s = re.sub(r"[(),;/]", " ", software)
    tokens = s.split()

    # First pass: find a version anywhere (e.g. '8.2p1' -> 8.2, '2.4.49' -> 2.4.49).
    version = None
    for t in tokens:
        vm = re.match(r"^v?(\d+\.\d+(?:\.\d+)?)", t)
        if vm:
            version = vm.group(1)
            break

    # Second pass: product name = leading meaningful alphabetic words only.
    product = []
    for t in tokens:
        if re.match(r"^v?\d", t):          # stop at the first versiony/numeric token
            break
        low = t.lower().strip("-")
        if low in SS_STOPWORDS or len(t) <= 1:
            continue
        # drop tokens that are clearly build/distro tags (contain digits mid-word)
        if re.search(r"\d", t):
            continue
        product.append(t)
        if len(product) >= 2:              # product names rarely need >2 words
            break

    q = " ".join(product)
    if version:
        q = f"{q} {version}".strip()
    return q.strip()


def run_searchsploit(query: str, timeout: int = 30):
    """Return a list of (title, edb_id) tuples for a query, or [] on failure."""
    if not query:
        return []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", "--", query],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    out = []
    for row in data.get("RESULTS_EXPLOIT", []):
        title = row.get("Title", "").strip()
        edb = row.get("EDB-ID", "").strip()
        if title:
            out.append((title, edb))
    return out


class Color:
    RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
    CYN = "\033[96m"; MAG = "\033[95m"; DIM = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"

    @classmethod
    def disable(cls):
        for a in ("RED", "YEL", "GRN", "CYN", "MAG", "DIM", "BOLD", "END"):
            setattr(cls, a, "")


# OID = TYPE: value    (TYPE optional, value may contain '=')
LINE_RE = re.compile(r"^\s*(\S+?)\s*=\s*(?:([A-Za-z0-9\- ]+?):\s*)?(.*)$")


def normalize_oid(raw: str) -> str:
    """Turn 'iso.3.6.1...' or '.1.3.6...' into a bare '1.3.6.1...' string."""
    oid = raw.strip()
    # net-snmp prints 'iso.3.6.1.2.1...' where iso == 1, i.e. 1.3.6.1.2.1...
    if oid.startswith("iso"):
        oid = "1" + oid[3:]
    oid = oid.lstrip(".")
    # strip any trailing MIB-name noise like SNMPv2-MIB::sysDescr.0 -> leave as-is if not numeric
    return oid


def match_oid(oid: str):
    """Return (label, category, loot) for the longest matching known prefix."""
    best = None
    for prefix, meta in OID_MAP.items():
        if oid == prefix or oid.startswith(prefix + "."):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, meta)
    return best[1] if best else None


def clean_value(vtype: str, value: str) -> str:
    """Decode common SNMP value encodings into something readable."""
    value = value.strip().strip('"')
    if not vtype:
        return value
    vt = vtype.strip().upper()
    if "HEX-STRING" in vt or vt == "HEX":
        # 48 65 6C 6C 6F -> try ascii, else keep hex
        try:
            raw = bytes(int(b, 16) for b in value.split())
            txt = raw.decode("latin-1")
            if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt):
                return txt.strip()
        except Exception:
            pass
    if "TIMETICKS" in vt:
        return value  # already human-ish
    return value


def find_creds(text: str):
    hits = []
    for pat in CRED_PATTERNS:
        for m in pat.finditer(text):
            frag = m.group(0).strip()
            # skip the giant base64 rule firing on normal words
            if pat.pattern.startswith("[A-Za-z0-9+/]{32,}") and len(frag) < 40:
                continue
            hits.append(frag)
    return hits


def main():
    ap = argparse.ArgumentParser(description="Parse SNMP walk output for interesting findings.")
    ap.add_argument("file", nargs="?", help="snmpwalk/autorecon output file (default: stdin)")
    ap.add_argument("--all", action="store_true", help="also show decoded but low-value lines")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")
    ap.add_argument("--searchsploit", action="store_true",
                    help="run searchsploit against installed software + sysDescr")
    ap.add_argument("--ss-timeout", type=int, default=30,
                    help="per-query searchsploit timeout in seconds (default 30)")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Color.disable()

    src = open(args.file, encoding="utf-8", errors="replace") if args.file else sys.stdin
    with src:
        lines = src.readlines()

    findings = defaultdict(list)   # category -> list of (label, value)
    cred_hits = []                 # (where, fragment)
    proc_hits = []
    boring = []
    parsed = 0

    for raw in lines:
        if not raw.strip():
            continue
        m = LINE_RE.match(raw)
        if not m:
            continue
        oid_raw, vtype, value = m.group(1), m.group(2) or "", m.group(3) or ""
        oid = normalize_oid(oid_raw)
        parsed += 1
        val = clean_value(vtype, value)

        meta = match_oid(oid)
        label = meta[0] if meta else None
        category = meta[1] if meta else "unknown"
        loot = meta[2] if meta else False

        # Credential hunt on any non-empty string-ish value
        if val and vtype.upper().find("INTEGER") < 0 and vtype.upper().find("TIMETICKS") < 0:
            for frag in find_creds(val):
                cred_hits.append(((label or oid), frag))
            if INTERESTING_PROCS.search(val):
                proc_hits.append(((label or "value"), val))

        if label:
            findings[category].append((label, val))
            if not loot and not args.all and category in ("ipv6", "network"):
                continue
        else:
            boring.append((oid, vtype, val))

    # -------------------------- report --------------------------
    print(f"{Color.BOLD}=== SNMP Enumeration Report ==={Color.END}")
    print(f"{Color.DIM}Parsed {parsed} OID lines from "
          f"{args.file or 'stdin'}{Color.END}\n")

    # Top-priority: credentials
    if cred_hits:
        print(f"{Color.RED}{Color.BOLD}[!!] POSSIBLE CREDENTIALS / SECRETS{Color.END}")
        seen = set()
        for where, frag in cred_hits:
            key = (where, frag)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {Color.RED}{where}:{Color.END} {frag}")
        print()

    cat_order = [
        ("users",    Color.MAG, "USER ACCOUNTS"),
        ("system",   Color.CYN, "SYSTEM / IDENTITY"),
        ("process",  Color.YEL, "RUNNING PROCESSES"),
        ("software", Color.YEL, "INSTALLED SOFTWARE"),
        ("shares",   Color.MAG, "SHARES"),
        ("storage",  Color.GRN, "STORAGE / MOUNTS"),
        ("ports",    Color.GRN, "LISTENING PORTS"),
        ("network",  Color.DIM, "NETWORK"),
        ("ipv6",     Color.DIM, "IPv6 ROUTING"),
    ]

    for cat, color, title in cat_order:
        items = findings.get(cat)
        if not items:
            continue
        # de-dup while preserving order
        seen = set(); uniq = []
        for lbl, v in items:
            if (lbl, v) in seen:
                continue
            seen.add((lbl, v)); uniq.append((lbl, v))
        print(f"{color}{Color.BOLD}[+] {title}{Color.END} ({len(uniq)})")
        for lbl, v in uniq:
            shown = v if v else f"{Color.DIM}(empty){Color.END}"
            print(f"    {Color.DIM}{lbl}:{Color.END} {shown}")
        print()

    # --------------------- searchsploit ---------------------
    if args.searchsploit:
        if not searchsploit_available():
            print(f"{Color.YEL}[!] --searchsploit requested but 'searchsploit' "
                  f"is not on PATH (install exploitdb). Skipping.{Color.END}\n")
        else:
            # Candidate strings: installed software + system description.
            candidates = []
            for lbl, v in findings.get("software", []):
                if v:
                    candidates.append(v)
            for lbl, v in findings.get("system", []):
                if lbl == "System description" and v:
                    candidates.append(v)
            # dedupe by generated query
            seen_q = {}
            for raw in candidates:
                q = build_query(raw)
                if q and q.lower() not in seen_q:
                    seen_q[q.lower()] = (q, raw)

            print(f"{Color.RED}{Color.BOLD}[>>] SEARCHSPLOIT RESULTS{Color.END}  "
                  f"{Color.DIM}({len(seen_q)} queries){Color.END}")
            any_hit = False
            for q, raw in seen_q.values():
                results = run_searchsploit(q, timeout=args.ss_timeout)
                if not results:
                    print(f"    {Color.DIM}[-] {raw!r} (query: {q}) -> no results{Color.END}")
                    continue
                any_hit = True
                print(f"    {Color.RED}[+] {raw}{Color.END} "
                      f"{Color.DIM}(query: {q}) -> {len(results)} exploit(s){Color.END}")
                for title, edb in results:
                    edb_str = f"EDB-{edb}" if edb else "EDB-?"
                    print(f"        {Color.YEL}{edb_str}{Color.END}  {title}")
            if not any_hit:
                print(f"    {Color.DIM}No exploits matched. Version strings may be "
                      f"too generic; try 'searchsploit <product>' manually.{Color.END}")
            print()

    if proc_hits:
        print(f"{Color.YEL}{Color.BOLD}[>] INTERESTING SERVICE / PROCESS STRINGS{Color.END}")
        seen = set()
        for where, v in proc_hits:
            if v in seen:
                continue
            seen.add(v)
            print(f"    {Color.DIM}{where}:{Color.END} {v}")
        print()

    if args.all and boring:
        print(f"{Color.DIM}[.] OTHER DECODED OIDS ({len(boring)}){Color.END}")
        for oid, vt, v in boring:
            print(f"    {Color.DIM}{oid} = {vt}: {v}{Color.END}")
        print()

    # quick summary line
    total_interesting = sum(len(v) for k, v in findings.items()
                            if k not in ("ipv6", "network")) + len(cred_hits)
    if total_interesting == 0 and not cred_hits:
        print(f"{Color.DIM}No high-value findings. Try a fuller walk: "
              f"snmpwalk -v2c -c public <ip> .1  (or .1.3.6.1.2.1.25 for host "
              f"resources){Color.END}")


if __name__ == "__main__":
    main()
