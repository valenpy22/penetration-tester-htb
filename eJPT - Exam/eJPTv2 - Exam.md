#

## Questions
1. What is the DMZ-facing IP address of the host that is part of both the DMZ and internal networks? Answer Format: Provide the full IP address. For example: 192.168.1.1
> 192.168.100.55

2. How many hosts exist within the DMZ network, excluding the gateway device?
3, 4, 5, 6
> 6

3. How many hosts within the DMZ network are running Linux, excluding the Kali Linux system?
1, 2, 3, 4
> 2

4. What is the IP address of the host running WordPress?
192.168.100.51, 52, 50, 54
> 192.168.100.50

5. What is the IP address of the host running the OpenSMTPD service? Answer Format: Provide the full IP address. For example: 192.168.1.1
> 192.168.100.52

6. How many hosts in the DMZ network and the internal network are running the Apache web server?
1, 2, 3, 4
> 3

7. What version of MySQL is running on the system hosting a Drupal site?
MySQL 5.5.5, MySQL 5.5.10, MySQL 5.5.3, MySQL 5.5.0
> MySQL 5.5.5

8. What is the total number of open TCP ports on the host running WordPress?
10, 12, 14, 16
> 14

9. How many hosts within the DMZ network are running a database server?
1, 2, 3, 5
> 2

10. What is the total number of hosts in the internal and DMZ networks running Windows Server 2019?

11. Which Linux distribution is running on the server hosting the Drupal site?
CentOS, Fedora, Ubuntu, Debian
> Ubuntu

12. What services does Syntex provide to companies?
Workflow Development, Cloud Hosting, Financial Services, Software Development
> Workflow Development

13. What is the name of the user account that published a blog post on the Drupal site?
mike, admin, auditor, vincenzo
> auditor

14. What is the email of the admin user on the WordPress site?
> test@test.com

15. What version of Drupal is running on the Drupal site?
7.57, 7.58, 7.54, 7.51
> 7.57

16. What is the IP address of the host that is vulnerable to an SSH brute-force attack?
192.168.100.52, 50, 51, 54
> 192.168.100.52

17. How many systems on the target network have FTP servers with anonymous access enabled?
1, 2, 3, 4
> 2

18. How many user accounts can be enumerated from the Samba service running on the system hosting Drupal?
1, 2, 3, 5
> 3

19. What type of vulnerability can be exploited to elevate your privileges on the Linux host running Drupal?
Locally Stored Credentials, Vulnerable Service, Misconfigured SUDO Permissions, Cron Job
> Locally Stored Credentials

20. What type of vulnerability can be exploited on the Drupal site?
Command Injection, Shellshock, RCE, Buffer Overflow
> RCE

21. Which Metasploit module can be used to exploit the vulnerability on the Drupal site? Provide the full module name, including its path, using the standard Metasploit module format (e.g., exploit/.../...).
> exploit/unix/webapp/drupal_drupalgeddon2

22. Which one of the following MSF modules can be used to obtain an elevated reverse shell on WINSERVER-02?

exploit/windows
/http/kaseya_uploader
/ftp/ms09_053_ftpd_nlst
/smb/smb_login
misc/hta_server

23. What is the CIDR network range of the internal network?
192.168.2.0/24
192.168.0.0/24
192.168.200.0/24
192.168.1.0/24
> 192.168.0.0/24

24. Which one of the following meterpreter commands can be used to add a network route?
arp, autoroute, netstat, route
> route

25. One of the Linux servers in the internal network is running a vulnerable service. Which port is the vulnerable service running on?
22, 80, 3389, 10000
> 10000

26. What is the password of the user account "dbadmin" on the Linux server hosting Drupal?
sayang, vincenzzo, syntex6061, qwertyuiop
> sayang

27. What is the password of the user account "mary" on WINSERVER-03?
> hotmama

28. What is the password for the user "mike" on WINSERVER-01?
superman, greenday, diamond, bonita
> diamond

29. Which host within the DMZ network can be exploited via command injection?
WINSERVER-02, WEBSERVER-02, WINSERVER-03, WINSERVER-01

30. What is the name of the vulnerable web app running on the Linux server in the internal network?
Apache Tomcat, Jenkins, Webmin, phpMyAdmin

31. What file can be used to identify the version of Drupal running on a webserver?
changelog.txt, settings.php, config.php, reports.txt
> changelog.txt

32. How many user accounts exist on the Drupal site?
1, 2, 3, 4
> 4

33. Which version of WordPress is running on WINSERVER-01?
5.6.1, 5.9.1, 5.5.9, 5.9.3
> 5.9.3

34. Which host on the DMZ network is running a database server on port 3307?
192.168.100.52, 192.168.0.100, 192.168.100.50, 192.168.100.51
> 192.168.100.50

35. How many plugins are installed on the WordPress site?
2, 3, 4, 5
> 3

36. What is the MySQL root account password on the host hosting the Drupal site?
> syntex0421

37. Excluding the built-in Guest account, how many user accounts are present on WINSERVER-01?
2, 3, 4, 5
> 4

38. What host in the DMZ network is running a web server with WebDAV enabled?
192.168.100.50, 192.168.100.53, 192.168.100.51, 192.168.100.52
> 192.168.100.51

39. Excluding the Administrator, guest and service accounts, how many user accounts are present on WINSERVER-03?
1, 2, 3, 4
> 4

40. Which user account is a member of the local Administrators group on the host WINSERVER-03?
lawrence, mike, admin, mary
> admin

41. Which one of the following user accounts is present on WINSERVER-02?
mike, lawrence, steven, admin
> steven

42. A system contains the file C:\Users\mike\Documents\flag.txt; what is the value of the flag?
> e22174e4d9c546a4891e9ed819070ad5

43. How many HotFixes are installed on WINSERVER-01?
200, 220, 245, 256
> 220

44. What is the value of the flag C:\Users\Administrator\flag.txt on WINSERVER-03?
> e8b75cc5489346afaa839321b4414027

45. Which Windows utility can be used to download files from a remote web server?
wget, certutil, mshta, netstat
> certutil

## Process
```sh
ip a
192.168.100.5/24

route -n
192.168.100.0

sudo nmap -sn 192.168.100.0/24 -oN hosts.txt

192.168.100.1 [gateway]
192.168.100.5 [atacante]

192.168.100.50
192.168.100.51
192.168.100.52
192.168.100.55
192.168.100.63
192.168.100.67
```

En total, son 6 hosts (excluyendo al atacante y el servicio de gateway).

