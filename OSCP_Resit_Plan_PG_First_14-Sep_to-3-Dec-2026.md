# OSCP+ Resit Plan --- 14 September to 3 December 2026

## PG Practice-first, with PEN-200 + HTB support

### Your starting point

-   Previous attempt: **50 points + Domain Admin**
-   Second attempt: **30 points**
-   Resit target: **December 2026**
-   Computer work: **Monday--Friday**
-   Saturday/Sunday: **reading only**
-   Main objective: make standalone-machine performance consistent
    enough to reach **70+**

I have deliberately changed the previous version so that **Proving
Grounds Practice is the main box platform**. The current TJ Null list
was updated July 18, 2026 and contains a dedicated PG Practice section
with Linux, Windows and AD machines. Community reports also consistently
describe the TJ Null PG selection as particularly useful for OSCP
preparation. citeturn0search2turn0reddit22

------------------------------------------------------------------------

# 1. Platform split

## Primary --- PG Practice

Use PG Practice for approximately **65% of practical box time**.

The current TJ Null list includes these PG Practice machines:

### Linux

-   Twiggy
-   Exfiltrated
-   Pelican
-   Astronaut
-   Blackgate
-   Boolean
-   Clue
-   Cockpit
-   Codo
-   Crane
-   Levram
-   Extplorer
-   Hub
-   Image
-   Law
-   LaVita
-   PC
-   Fired
-   Press
-   Scrutiny
-   RubyDome
-   Zipper
-   Flu
-   Workaholic
-   PyLoader
-   Plum
-   SPX
-   Jordak
-   BitForge
-   Vmdak
-   Ochima
-   Nibbles
-   CVE-2023-6019
-   Sea
-   Payday
-   Snookums
-   SpiderSociety

### Windows

-   Algernon
-   Authby
-   Craft
-   Hutch
-   Internal
-   Jacko
-   Kevin
-   Resourced
-   Squid
-   DVR4
-   Hepet
-   Shenzi
-   Nickel
-   Slort
-   MedJed
-   Monster
-   Mice

### Active Directory

-   Access
-   Heist
-   Vault
-   Nagoya
-   Resourced
-   Hutch

The list is a living resource, so check availability in PG before each
week. citeturn1view0

------------------------------------------------------------------------

# 2. Secondary --- PEN-200 labs

Use PEN-200 labs for:

-   techniques you repeatedly miss
-   AD sets
-   tunnelling
-   exploit modification
-   course-specific challenges
-   exam methodology
-   reporting

Do not substitute random HTB boxes for the PEN-200 labs when the course
already contains the exact technique.

------------------------------------------------------------------------

# 3. Secondary --- HTB

HTB is now deliberately limited.

Use it for:

-   extra Linux/Windows practice
-   web depth
-   AD depth
-   pivoting
-   difficult problem-solving
-   revisiting a weakness exposed by a PG box

Recommended HTB machines are included only where they add something that
PG/PEN-200 is not already covering.

------------------------------------------------------------------------

# 4. Rules for every box

### First 30 minutes

Pure enumeration.

### 30--90 minutes

Test obvious attack paths.

### 90--180 minutes

Initial access.

### 180--240 minutes

Privilege escalation.

### 240--300 minutes

Reassess.

If you have spent 30--45 minutes without producing **new information**,
stop and reset your methodology.

Write:

``` text
KNOWN:
UNKNOWN:
TESTED:
NOT TESTED:
CURRENT HYPOTHESIS:
ALTERNATIVE HYPOTHESIS:
```

### Hint policy

-   0--60 min: no hint
-   60--120 min: conceptual hint
-   120--180 min: stronger hint
-   180+ min: walkthrough if necessary

If you use a walkthrough, close it and reproduce the entire attack chain
yourself.

------------------------------------------------------------------------

# PHASE 1

# 14--18 September

## Enumeration reset

### Monday --- PG: Twiggy

Focus:

-   Nmap
-   service enumeration
-   web
-   basic Linux methodology

### Tuesday --- PG: Exfiltrated

Focus:

-   enumeration
-   web
-   credentials
-   Linux privesc

### Wednesday --- PG: Pelican

Focus:

-   web enumeration
-   application attack surface
-   Linux privesc

### Thursday --- PG: Astronaut

Focus:

-   CVE identification
-   public exploit use
-   SUID/privesc

### Friday

No new machine.

Re-enumerate one of Monday--Thursday's machines **from memory**.

### Weekend reading

PEN-200:

-   Information Gathering
-   Vulnerability Scanning

------------------------------------------------------------------------

# PHASE 2

# 21--25 September

## Web attack surface

### Monday --- PG: Extplorer

Focus:

-   web enumeration
-   authentication
-   file handling
-   exploit modification

### Tuesday --- PG: Press

Focus:

-   web
-   CMS/application enumeration
-   credentials
-   Linux privesc

### Wednesday --- PG: Hub

Focus:

-   web
-   service enumeration
-   credential discovery

### Thursday --- PG: Image

Focus:

-   web/application enumeration
-   file handling
-   Linux privesc

### Friday --- HTB: Nibbles

Use this as a comparison exercise.

Question:

> Did I enumerate the HTB box using the same methodology as PG?

### Weekend reading

PEN-200:

-   Introduction to Web Applications
-   Common Web Application Attacks
-   SQL Injection
-   Client-Side Attacks

------------------------------------------------------------------------

# PHASE 3

# 28 September--2 October

## Linux privilege escalation

### Monday --- PG: Cockpit

Focus:

-   Linux enumeration
-   services
-   credentials
-   privesc

### Tuesday --- PG: Codo

Focus:

-   web → Linux
-   local enumeration
-   privesc

### Wednesday --- PG: Crane

Focus:

-   Linux
-   services
-   credentials
-   privesc

### Thursday --- PG: Levram

Focus:

-   enumeration
-   exploit path
-   Linux privesc

### Friday

Build and practise your Linux privesc checklist.

Required commands:

``` bash
id
whoami
hostname
uname -a
cat /etc/os-release
sudo -l
ps aux
ss -lntup
ip addr
ip route
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
find / -writable -type f 2>/dev/null
```

### Weekend reading

PEN-200:

-   Linux Privilege Escalation

------------------------------------------------------------------------

# PHASE 4

# 5--9 October

## Windows exploitation + privesc

### Monday --- PG: Algernon

Focus:

-   Windows enumeration
-   service enumeration
-   initial access
-   privesc

### Tuesday --- PG: Authby

Focus:

-   Windows
-   authentication
-   credentials
-   privilege escalation

### Wednesday --- PG: Craft

Focus:

-   Windows enumeration
-   web/service interaction
-   credentials

### Thursday --- PG: Hutch

Focus:

-   Windows
-   service enumeration
-   credential discovery
-   privesc

### Friday

No new box.

Practise from memory:

``` text
whoami /all
systeminfo
ipconfig /all
net user
net localgroup
netstat -ano
tasklist
schtasks
sc query
```

### Weekend reading

PEN-200:

-   Windows Privilege Escalation

------------------------------------------------------------------------

# PHASE 5

# 12--16 October

## Exploits + credentials

### Monday --- PG: Blackgate

Focus:

-   public exploits
-   modifying PoCs
-   Linux privesc

### Tuesday --- PG: Boolean

Focus:

-   vulnerability identification
-   exploit adaptation
-   Linux privesc

### Wednesday --- PG: Clue

Focus:

-   web/service enumeration
-   credentials
-   exploitation

### Thursday --- PG: Jacko

Focus:

-   Windows exploitation
-   credentials
-   privesc

### Friday --- HTB: Armageddon

Use HTB specifically to reinforce public exploit modification and
credential handling.

### Weekend reading

PEN-200:

-   Locating Public Exploits
-   Fixing Exploits
-   Password Attacks
-   Antivirus Evasion
-   Metasploit

------------------------------------------------------------------------

# PHASE 6

# 19--23 October

## Mixed standalone machines

This is where your preparation starts becoming exam-like.

### Monday --- PG: Nibbles

### Tuesday --- PG: RubyDome

### Wednesday --- PG: Zipper

### Thursday --- PG: PyLoader

### Friday --- PG: Plum

Do not decide the technique before enumeration.

Your task is:

> Find the attack path yourself.

### Weekend reading

Review:

-   enumeration
-   exploit methodology
-   Linux/Windows privesc
-   password attacks

------------------------------------------------------------------------

# PHASE 7

# 26--30 October

## Harder standalone practice

### Monday --- PG: Scrutiny

### Tuesday --- PG: Workaholic

### Wednesday --- PG: SPX

### Thursday --- PG: BitForge

### Friday --- PG: Vmdak

These are deliberately harder than the early training machines.

### Time limit

**5 hours maximum per machine.**

If you need a walkthrough, record exactly what defeated you.

### Weekend reading

PEN-200:

-   Metasploit
-   Assembling the Pieces

------------------------------------------------------------------------

# PHASE 8

# 2--6 November

## Active Directory

You already reached Domain Admin on a previous attempt.

Therefore this is **maintenance + consistency**, not starting from zero.

### Monday --- PG: Access

Focus:

-   domain enumeration
-   SMB
-   users/groups
-   credentials
-   BloodHound

### Tuesday --- PG: Heist

Focus:

-   authentication
-   credential attacks
-   lateral movement

### Wednesday --- PG: Vault

Focus:

-   AD enumeration
-   attack paths
-   lateral movement

### Thursday --- PG: Nagoya

Focus:

-   AD
-   Windows enumeration
-   credential abuse

### Friday --- PEN-200 AD lab

Run a complete AD attack path.

### Weekend reading

PEN-200:

-   Active Directory Introduction and Enumeration
-   Attacking Active Directory Authentication

------------------------------------------------------------------------

# PHASE 9

# 9--13 November

## AD + lateral movement

### Monday --- HTB: Forest

Use HTB here because it gives you a different AD environment from PG.

### Tuesday --- HTB: Sauna

Focus:

-   enumeration
-   Kerberos
-   credentials
-   lateral movement

### Wednesday --- PG: Resourced

Treat it as a completely standalone AD engagement.

### Thursday --- PG: Hutch

Revisit the Windows/AD workflow.

### Friday

Complete an AD set from PEN-200 without walkthroughs.

### Weekend reading

PEN-200:

-   Lateral Movement in Active Directory

------------------------------------------------------------------------

# PHASE 10

# 16--20 November

## Pivoting and tunnelling

### Monday

PEN-200:

-   Port Redirection and SSH Tunnelling

Practise:

-   SSH local forwarding
-   SSH remote forwarding
-   SOCKS
-   proxychains

### Tuesday

PEN-200:

-   Advanced Tunnelling

Practise Chisel-style pivoting.

### Wednesday --- PG: Internal

Use this as a pivot/tunnelling exercise if available.

### Thursday --- HTB: a pivoting machine from your current HTB catalogue

Do not spend the whole day learning a new tool. Concentrate on
understanding the network path.

### Friday

Full pivot simulation.

Draw:

``` text
ATTACKER
   |
   v
FOOTHOLD
   |
   v
INTERNAL NETWORK
   |
   +---- INTERNAL SERVER
   |
   +---- AD/DC
```

### Weekend reading

PEN-200:

-   Advanced Tunnelling
-   Assembling the Pieces

------------------------------------------------------------------------

# PHASE 11

# 23--27 November

## Exam simulation week

### Monday

Three-machine standalone simulation.

Use **three PG machines you have never attempted**.

Suggested choices from the current TJ Null PG list:

-   Fired
-   Flu
-   Sea

If one is unavailable, replace it with:

-   Payday
-   Snookums
-   SpiderSociety

Do not use walkthroughs.

------------------------------------------------------------------------

### Tuesday

Failure analysis.

For every missed foothold/privesc:

``` text
What did I miss?
Why did I miss it?
What enumeration would have exposed it?
What assumption did I make?
How long did I waste?
```

------------------------------------------------------------------------

### Wednesday

Full AD simulation.

Use:

-   PEN-200 AD set

Treat it as the real exam.

------------------------------------------------------------------------

### Thursday

Second three-machine simulation.

Suggested PG choices:

-   Law
-   Ochima
-   Fired

Replace unavailable machines with another unused Linux/Windows box from
the TJ Null PG list.

------------------------------------------------------------------------

### Friday

Write a complete report.

Include:

-   executive summary
-   methodology
-   vulnerability
-   reproduction steps
-   evidence
-   screenshots
-   privilege escalation
-   remediation

### Weekend reading

Reporting + exam methodology only.

------------------------------------------------------------------------

# PHASE 12

# 30 November--3 December

## Final consolidation

### Monday --- 30 November

Full mock exam.

Use **three fresh PG machines**.

Suggested:

-   Payday
-   Snookums
-   SpiderSociety

If unavailable, select three unused machines from the current TJ Null PG
Practice list.

Treat it as the real exam.

No:

-   walkthroughs
-   AI
-   solution searches
-   writeups

------------------------------------------------------------------------

### Tuesday --- 1 December

Failure analysis only.

Review:

-   enumeration
-   Linux privesc
-   Windows privesc
-   web
-   credentials
-   AD
-   tunnelling
-   time management

------------------------------------------------------------------------

### Wednesday --- 2 December

Light review.

Review your own command book:

1.  Nmap
2.  Web
3.  SMB
4.  Linux
5.  Windows
6.  AD
7.  Kerberos
8.  Lateral movement
9.  Pivoting
10. Reporting

No new boxes.

------------------------------------------------------------------------

### Thursday --- 3 December

No serious learning.

Mental rehearsal.

------------------------------------------------------------------------

# 5. Exact PG box target

Your primary target is **30--35 PG Practice machines** by the end of the
programme.

## First priority

``` text
Twiggy
Exfiltrated
Pelican
Astronaut
Extplorer
Press
Hub
Image
Cockpit
Codo
Crane
Levram
Algernon
Authby
Craft
Hutch
Blackgate
Boolean
Clue
Jacko
```

## Second priority

``` text
Nibbles
RubyDome
Zipper
PyLoader
Plum
Scrutiny
Workaholic
SPX
BitForge
Vmdak
```

## Stretch / final preparation

``` text
Fired
Flu
Sea
Payday
Snookums
SpiderSociety
Law
Ochima
```

You do **not** need to complete every machine on the current list. The
purpose is to get enough high-quality repetitions that your enumeration
and exploitation methodology becomes automatic.

The current TJ Null list itself says the list is not exhaustive or a
guarantee of passing, so treat it as a curated training selection rather
than a checklist you must blindly finish. citeturn1view0

------------------------------------------------------------------------

# 6. How HTB now fits

HTB is no longer the main box stream.

Use it strategically:

  Skill                     Primary      Secondary
  ------------------------- ------------ -----------
  Enumeration               PG           HTB
  Linux privesc             PG           HTB
  Windows privesc           PG           HTB
  Web                       PG/PEN-200   HTB
  Exploit modification      PG/PEN-200   HTB
  AD                        PEN-200/PG   HTB
  Pivoting                  PEN-200/PG   HTB
  General problem solving   PG           HTB

The current TJ Null list's HTB section is also updated and includes
modern Linux, Windows and AD choices, so HTB remains useful without
becoming the centre of the programme. citeturn1view0

------------------------------------------------------------------------

# 7. Your three milestones

## 2 October

You should be able to reliably enumerate and solve easier PG machines.

## 30 October

You should be comfortable attacking medium/harder PG machines without
immediately reaching for a walkthrough.

## 20 November

You should be able to complete an AD attack chain and pivot without
step-by-step guidance.

## 30 November

You should be able to sit down with three unfamiliar machines and work
methodically for the full simulation.

------------------------------------------------------------------------

# 8. The key change from your previous attempt

You already proved:

> **You can get Domain Admin.**

So I don't want another preparation cycle where you become brilliant at
AD but inconsistent elsewhere.

Your training priority is:

**PG standalone machines → PEN-200 labs → targeted HTB → AD maintenance
→ full simulations.**

The skill we are trying to build is:

``` text
ENUMERATE
    ↓
IDENTIFY ATTACK SURFACE
    ↓
FORM HYPOTHESIS
    ↓
TEST
    ↓
INITIAL ACCESS
    ↓
ENUMERATE AGAIN
    ↓
PRIVESC
    ↓
DOCUMENT
    ↓
MOVE ON
```

That is the behaviour I want to be automatic by December.
