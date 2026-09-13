# OSCP+ Resit Plan — 14 September to 3 December 2026

## Two boxes per weekday: one Proving Grounds and one Hack The Box

### Starting point

- Previous attempt: **50 points + Domain Admin**
- Second attempt: **30 points**
- Resit target: **December 2026**
- Practical work: **Monday–Friday**
- Saturday/Sunday: **reading, notes and recovery only**
- Main objective: make standalone-machine performance consistent enough to reach **70+**

The machine assignments below come from `OSCP_Machines_Report_2026-09-13.xlsx`. Every practical day contains one unique PG machine and one unique HTB machine.

---

## Daily operating rules

Treat both boxes as timed first-pass attempts. The goal is two deliberate repetitions, not two rushed walkthroughs.

### Per-box timebox: 150 minutes

1. **0–30 min — enumerate:** ports, services, web content, users, shares and likely attack surface.
2. **30–90 min — foothold:** test the highest-confidence paths and record evidence.
3. **90–135 min — privilege escalation:** run the relevant Linux or Windows checklist.
4. **135–150 min — reset and document:** save commands, screenshots, missed clues and the next hypothesis.

Take a 30–45 minute break between boxes. Alternate which platform you attempt first each day to avoid learning a platform only when fresh.

### Hint policy

- 0–60 min: no hint
- 60–105 min: one conceptual hint
- 105–135 min: one stronger hint
- After 135 min: stop the timer, review the minimum needed, then reproduce the chain unaided during a later review block

When progress stalls for 30 minutes, write:

```text
KNOWN:
UNKNOWN:
TESTED:
NOT TESTED:
CURRENT HYPOTHESIS:
ALTERNATIVE HYPOTHESIS:
```

### Completion standard

A box counts as complete only when you can explain the foothold, privilege escalation, missed clues and a faster repeat path. If a machine is retired or unavailable, replace it with an unused machine from the same platform, category and nearest difficulty in the workbook.

---

# Phase 1: 14–18 September

## Enumeration reset

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 14 Sep | **PC** — Linux, 0.5/5 | **Shocker** — Linux, 0.3/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 15 Sep | **Astronaut** — Linux, 1/5 | **Bashed** — Linux, 0.4/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 16 Sep | **ClamAV** — Linux, 1/5 | **Lame** — Linux, 0.5/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 17 Sep | **Crane** — Linux, 1/5 | **Nibbles** — Linux, 0.6/5 | Enumeration, foothold and Linux privilege escalation |
| Fri 18 Sep | **Flu** — Linux, 1/5 | **Broker** — Linux, 0.7/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Information Gathering; Vulnerability Scanning.

**Checkpoint:** establish a repeatable enumeration sequence and keep complete command/evidence notes for all ten boxes.

---

# Phase 2: 21–25 September

## Web attack surface

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 21 Sep | **Hub** — Linux, 1/5 | **SwagShop** — Linux, 0.9/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 22 Sep | **Image** — Linux, 1/5 | **Busqueda** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 23 Sep | **Jordak** — Linux, 1/5 | **Dog** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 24 Sep | **Levram** — Linux, 1/5 | **Editor** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Fri 25 Sep | **Mantis** — Linux, 1/5 | **Knife** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Web Applications; Common Web Attacks; SQL Injection.

---

# Phase 3: 28 September–2 October

## Linux privilege escalation

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 28 Sep | **Nibbles** — Linux, 1/5 | **Planning** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 29 Sep | **Nukem** — Linux, 1/5 | **Sau** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 30 Sep | **Ochima** — Linux, 1/5 | **Usage** — Linux, 1/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 01 Oct | **Pelican** — Linux, 1/5 | **Devvortex** — Linux, 1.5/5 | Enumeration, foothold and Linux privilege escalation |
| Fri 02 Oct | **QuackerJack** — Linux, 1/5 | **Jarvis** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Linux Privilege Escalation.

**Checkpoint:** complete Linux privilege escalation without skipping manual checks when automated scripts find nothing.

---

# Phase 4: 5–9 October

## Windows exploitation and privilege escalation

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 05 Oct | **Mice** — Windows, 0.5/5 | **Legacy** — Windows, 0.1/5 | Service enumeration, credentials and Windows privilege escalation |
| Tue 06 Oct | **Algernon** — Windows, 1/5 | **Devel** — Windows, 0.2/5 | Service enumeration, credentials and Windows privilege escalation |
| Wed 07 Oct | **Authby** — Windows, 1/5 | **Jerry** — Windows, 0.8/5 | Service enumeration, credentials and Windows privilege escalation |
| Thu 08 Oct | **Craft** — Windows, 1/5 | **Bounty** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 09 Oct | **Fish** — Windows, 1/5 | **Buff** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |

**Weekend reading:** Windows Privilege Escalation.

**Checkpoint:** build a Windows checklist covering services, scheduled tasks, stored credentials, permissions and common kernel paths.

---

# Phase 5: 12–16 October

## Exploits and credentials

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 12 Oct | **Readys** — Linux, 1/5 | **Outbound** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 13 Oct | **Roquefort** — Linux, 1/5 | **Sea** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 14 Oct | **RubyDome** — Linux, 1/5 | **Snapped** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 15 Oct | **Internal** — Windows, 1/5 | **Chatterbox** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 16 Oct | **Kevin** — Windows, 1/5 | **Jeeves** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |

**Weekend reading:** Public Exploits; Fixing Exploits; Password Attacks.

---

# Phase 6: 19–23 October

## Mixed standalone machines

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 19 Oct | **Sorcerer** — Linux, 1/5 | **Solidstate** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 20 Oct | **Twiggy** — Linux, 1/5 | **Tabby** — Linux, 2/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 21 Oct | **Walla** — Linux, 1/5 | **CozyHosting** — Linux, 2.5/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 22 Oct | **Monster** — Windows, 1/5 | **Optimum** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 23 Oct | **Shenzi** — Windows, 1/5 | **Querier** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |

**Weekend reading:** Enumeration; exploitation; Linux and Windows privilege escalation.

---

# Phase 7: 26–30 October

## Harder standalone practice

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 26 Oct | **Zab** — Linux, 1/5 | **Keeper** — Linux, 2.5/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 27 Oct | **Marketing** — Linux, 1.5/5 | **LinkVortex** — Linux, 2.5/5 | Enumeration, foothold and Linux privilege escalation |
| Wed 28 Oct | **Xposedapi** — Linux, 1.5/5 | **Help** — Linux, 3/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 29 Oct | **Slort** — Windows, 1/5 | **Remote** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 30 Oct | **Squid** — Windows, 1/5 | **ServMon** — Windows, 1/5 | Service enumeration, credentials and Windows privilege escalation |

**Weekend reading:** Metasploit; Assembling the Pieces.

**Checkpoint:** reach a plausible attack path on most boxes inside 90 minutes; classify every miss by enumeration, exploitation or privilege escalation.

---

# Phase 8: 2–6 November

## Active Directory consistency

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 02 Nov | **Access** — AD, 1/5 | **Active** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Tue 03 Nov | **Hutch** — AD, 1/5 | **Cicada** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Wed 04 Nov | **Nagoya** — AD, 1.5/5 | **Forest** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Thu 05 Nov | **BitForge** — Linux, 2/5 | **Return** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Fri 06 Nov | **Resourced** — AD, 2/5 | **Sauna** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |

**Weekend reading:** AD Enumeration; Attacking AD Authentication.

---

# Phase 9: 9–13 November

## AD and lateral movement

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 09 Nov | **Heist** — AD, 3/5 | **Support** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Tue 10 Nov | **Vault** — AD, 5/5 | **Timelapse** — AD, 1/5 | AD enumeration, credentials, lateral movement and attack-path notes |
| Wed 11 Nov | **Billyboss** — Windows, 1.5/5 | **Access** — Windows, 1.5/5 | Service enumeration, credentials and Windows privilege escalation |
| Thu 12 Nov | **Cockpit** — Linux, 2/5 | **Pilgrimage** — Linux, 3/5 | Enumeration, foothold and Linux privilege escalation |
| Fri 13 Nov | **Exfiltrated** — Linux, 2/5 | **Soccer** — Linux, 3/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Lateral Movement in Active Directory.

**Checkpoint:** draw the AD attack path for each AD machine and reproduce core BloodHound, Kerberos and lateral-movement commands from memory.

---

# Phase 10: 16–20 November

## Pivoting and tunnelling

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 16 Nov | **Extplorer** — Linux, 2/5 | **Tartarsauce** — Linux, 3/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 17 Nov | **MedJed** — Windows, 1.5/5 | **Giddy** — Windows, 2/5 | Service enumeration, credentials and Windows privilege escalation |
| Wed 18 Nov | **Payday** — Linux, 2/5 | **UpDown** — Linux, 3/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 19 Nov | **Jacko** — Windows, 2/5 | **Heist** — Windows, 2/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 20 Nov | **Scrutiny** — Linux, 2/5 | **Pandora** — Linux, 3.5/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Port Redirection; SSH Tunnelling; Advanced Tunnelling.

**Checkpoint:** for suitable boxes, document how you would route traffic through a foothold with SSH, Chisel or Ligolo-ng.

---

# Phase 11: 23–27 November

## Exam simulation week

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 23 Nov | **BlackGate** — Linux, 3/5 | **Mentor** — Linux, 4/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 24 Nov | **Nickel** — Windows, 2/5 | **Love** — Windows, 2.5/5 | Service enumeration, credentials and Windows privilege escalation |
| Wed 25 Nov | **Boolean** — Linux, 3/5 | **Monitored** — Linux, 4/5 | Enumeration, foothold and Linux privilege escalation |
| Thu 26 Nov | **DVR4** — Windows, 2.5/5 | **SecNotes** — Windows, 2.5/5 | Service enumeration, credentials and Windows privilege escalation |
| Fri 27 Nov | **Clue** — Linux, 3/5 | **Intentions** — Linux, 5/5 | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Reporting; failure analysis; exam methodology.

**Simulation rule:** run each pair under exam conditions. No walkthroughs, AI or solution searches during the timer. Draft one full report this week.

---

# Phase 12: 30 November–3 December

## Final consolidation

| Date | PG box | HTB box | Daily emphasis |
|---|---|---|---|
| Mon 30 Nov | **SPX** — Linux, 3/5 | **Poison** — Linux, 5/5 | Enumeration, foothold and Linux privilege escalation |
| Tue 01 Dec | **Hepet** — Windows, 3/5 | **StreamIO** — Windows, 3.5/5 | Service enumeration, credentials and Windows privilege escalation |
| Wed 02 Dec | **Hawat** — Linux, 4/5 | **Analytics** — Linux, - | Enumeration, foothold and Linux privilege escalation |
| Thu 03 Dec | **Lavita** — Linux, 4/5 | **BoardLight** — Linux, - | Enumeration, foothold and Linux privilege escalation |

**Weekend reading:** Own notes and command book only.

**Final rule:** keep the assigned attempts controlled. Stop serious learning after 3 December and use only your own notes for final review.

---

## Milestones

| Date | Required outcome |
|---|---|
| 2 October | 30 timed attempts completed; Linux enumeration and privilege escalation checklist stable |
| 30 October | 70 timed attempts completed; reliable standalone workflow across Linux and Windows |
| 13 November | 90 timed attempts completed; AD attack-path consistency maintained |
| 27 November | 110 timed attempts completed; at least one full report produced under simulation conditions |
| 3 December | 118 timed attempts completed; weak points converted into a short final-review list |

## Daily tracking template

```text
DATE:
PG BOX / RESULT / TIME TO FOOTHOLD / TIME TO ROOT:
HTB BOX / RESULT / TIME TO FOOTHOLD / TIME TO ROOT:
HINTS USED:
MISSED CLUE:
NEW COMMAND OR TECHNIQUE:
WHAT I WILL CHANGE TOMORROW:
```

## Priority rule

If the full two-box day becomes unsustainable, keep both attempts but reduce each to a strict 90-minute foothold exercise. Do not compensate by removing sleep, weekend recovery or report practice. Consistency matters more than accumulating incomplete roots.
