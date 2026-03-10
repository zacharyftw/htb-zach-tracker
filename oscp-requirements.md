# OSCP (PEN-200) — Requirements & Exam Guide

*Last updated: March 2026*

---

## Exam Format

- **6 machines** total, proctored
- **Active Directory set (3 machines):** chained attack — starts with assumed compromise, work toward full domain takeover
- **Standalone machines (3):** each requires initial access + privilege escalation
- **Time:** 23 hours 45 minutes for hacking, then 24 hours to write the report

---

## Scoring

| Target | Points |
|---|---|
| AD Machine #1 | 10 |
| AD Machine #2 | 10 |
| AD Domain Controller | 20 |
| **AD Total** | **40** |
| Standalone #1 (low-priv + root) | 20 (10+10) |
| Standalone #2 (low-priv + root) | 20 (10+10) |
| Standalone #3 (low-priv + root) | 20 (10+10) |
| **Standalone Total** | **60** |
| **Pass Mark** | **70 / 100** |

Bonus points were **removed** as of November 2024 — score is 100% exam performance.

---

## Metasploit Restrictions

- Metasploit (exploit/auxiliary/post modules + Meterpreter) allowed on **ONE machine only**
- Once you pick that machine, no Metasploit on any other target
- Also applies to Armitage, Cobalt Strike, etc.
- **You MUST be comfortable exploiting manually** (msfvenom + nc/curl/python)

---

## Allowed Tools

**Yes:**
- nmap (+ NSE scripts)
- gobuster / feroxbuster / dirsearch
- nikto
- Burp Suite Community
- curl, wget, netcat, python scripts
- Your own notes, online resources, OffSec platform
- Any non-prohibited open-source tool

**No:**
- Nessus, OpenVAS, Nexpose (auto vuln scanners)
- SQLMap
- AI tools (ChatGPT, Copilot, etc.) — **automatic fail**
- Commercial exploitation tools

**Open book** — notes and internet allowed, just no AI.

---

## Report Requirements

- Professional pentest report is **mandatory**
- Must document **every step, command, and output** for each machine
- Must be reproducible by a technical reader
- Incomplete documentation = reduced or zero points even with correct flags
- 24 hours to write after exam ends

---

## Cost

| Item | Price |
|---|---|
| Learn One subscription (1yr course + labs + 2 exam attempts) | ~$2,199/yr |
| Individual exam retake | $249 |
| 30-day lab extension | $359 |
| OSCP to OSCP+ upgrade (existing holders) | $799 |

---

## OSCP+ (New as of Nov 2024)

- Passing the current exam earns both **OSCP** and **OSCP+**
- OSCP+ **expires after 3 years** (original OSCP was lifetime)
- Renewal: recertification exam, another OffSec cert, or CPE program

---

## PEN-200 Syllabus Topics

- Information gathering & enumeration
- Vulnerability scanning
- Web app attacks (XSS, SQLi, command injection, file upload, directory traversal)
- Password attacks
- Antivirus evasion
- Linux privilege escalation
- Windows privilege escalation
- **Active Directory attacks & lateral movement**
- Port redirection, tunneling & pivoting
- AWS cloud enumeration & attacks
- Client-side attacks
- Report writing

---

## My Progress vs OSCP Requirements

### Covered (from HTB so far)
- [x] Service enumeration (nmap, gobuster, nikto)
- [x] Default credential attacks (Tomcat, PRTG, RT)
- [x] Public exploit usage (searchsploit, CVEs)
- [x] Windows exploitation (EternalBlue, MS08-067)
- [x] File transfer techniques (FTP, SCP)
- [x] Basic web app attacks
- [x] Report writing

### Need to Learn
- [ ] **Active Directory** — worth 40% of the exam (Forest, Sauna, Active, Cascade on HTB)
- [ ] **Linux privilege escalation** — SUID, cron, sudo, kernel exploits
- [ ] **Windows privilege escalation** — token impersonation, service misconfig, unquoted paths
- [ ] **Manual exploitation without Metasploit** — msfvenom + netcat only
- [ ] **Pivoting & tunneling** — chisel, SSH tunnels, ligolo
- [ ] **Web app attacks** — SQLi, LFI/RFI, file upload bypass
- [ ] **Password attacks** — hashcat, john, credential spraying
- [ ] **Antivirus evasion**
- [ ] **AWS cloud enumeration**

### Recommended HTB Machines (TJ Null OSCP-like list)
**Linux:** Lame ✅, Shocker, Bashed, Nibbles, Beep, Cronos, Nineveh, Sense, Solidstate, Irked, Valentine, Poison, Sunday, Tartarsauce
**Windows:** Legacy ✅, Blue ✅, Jerry ✅, Netmon ✅, Keeper ✅, Active, Bastard, Bounty, Arctic, Grandpa, Granny, Optimum, Devel
**AD:** Forest, Sauna, Cascade, Resolute, Monteverde, Blackfield
