#!/usr/bin/env bash
set -uo pipefail
usage(){ cat <<'EOF'
Usage: 03_linux_enum.sh [options]
Collect concise local Linux privilege-escalation evidence on an authorized host.
  -o, --output FILE  Report path (default: ./linux_enum.txt)
  -h, --help         Show help
Example: ./03_linux_enum.sh -o /tmp/linux_enum.txt
EOF
}
die(){ printf '[-] %s\n' "$*" >&2; exit 1; }; out=./linux_enum.txt
while (($#)); do case $1 in -o|--output) (($#>1))||die "$1 requires a file"; out=$2; shift 2;; -h|--help) usage; exit 0;; -*) die "Unknown option: $1 (try -h)";; *) [[ $out == ./linux_enum.txt ]]||die "Unexpected argument: $1"; out=$1; shift;; esac; done
mkdir -p "$(dirname "$out")"; section(){ printf '\n===== %s =====\n' "$1"; }
{
 section SYSTEM; date -Is 2>/dev/null||date; hostname; uname -a; cat /etc/os-release 2>/dev/null
 section IDENTITY; whoami; id; sudo -n -l 2>&1
 section USERS; cat /etc/passwd; cat /etc/group
 section SUID_SGID; find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null
 section CAPABILITIES; command -v getcap >/dev/null&&getcap -r / 2>/dev/null
 section PROCESSES; ps auxww
 section NETWORK; ip -brief address 2>/dev/null; ip route 2>/dev/null; ss -lntup 2>/dev/null
 section CRON; ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null
 section SSH; ls -la "$HOME/.ssh" /home/*/.ssh 2>/dev/null
 section WRITABLE_PATHS; find /etc /opt /usr/local -xdev -type f -writable -print 2>/dev/null|head -n 250
 section ENVIRONMENT; env|sed -E '/(PASS|TOKEN|SECRET|KEY)=/Id'
}|tee "$out"; printf '[+] Report saved: %s\n' "$out"
