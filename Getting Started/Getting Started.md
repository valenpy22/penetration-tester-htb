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

