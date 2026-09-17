```markdown
# Writeup — Laboratorio de Pivoting (estilo eJPT) con Docker + Chisel + Proxychains

## Índice

1. [Objetivo](#objetivo)
2. [Topología](#topología)
3. [Requisitos](#requisitos)
4. [Fase 1 — Levantar el laboratorio](#fase-1--levantar-el-laboratorio)
5. [Fase 2 — Reconocimiento externo](#fase-2--reconocimiento-externo)
6. [Fase 3 — Comprometer el pivot](#fase-3--comprometer-el-pivot)
7. [Fase 4 — Subir Chisel al pivot](#fase-4--subir-chisel-al-pivot)
8. [Fase 5 — Levantar el server Chisel en el pivot](#fase-5--levantar-el-server-chisel-en-el-pivot)
9. [Fase 6 — Conectar el cliente Chisel desde el atacante](#fase-6--conectar-el-cliente-chisel-desde-el-atacante)
10. [Fase 7 — Configurar proxychains](#fase-7--configurar-proxychains)
11. [Fase 8 — Enumeración y ataque de la red interna](#fase-8--enumeración-y-ataque-de-la-red-interna)
12. [Conceptos clave](#conceptos-clave)
13. [Errores comunes y soluciones](#errores-comunes-y-soluciones)
14. [Chuleta final](#chuleta-final)

---

## Objetivo

Practicar **pivoting** en un escenario realista tipo eJPT: la máquina atacante **no tiene interfaz** en la red interna, y solo puede alcanzarla saltando a través de una máquina comprometida con doble tarjeta de red (el *pivot*).

Se usarán tres herramientas:

- **Docker Compose** — para montar la topología.
- **Chisel** — para establecer el túnel y exponer un SOCKS5 en la máquina atacante.
- **Proxychains** — para forzar a cualquier herramienta a usar ese SOCKS5.

---

## Topología

```text
[ TU KALI ]  (atacante — sin contenedor, es tu máquina)
     |
     |  publica puertos 8080 (DVWA) y 8000 (Chisel)
     v
[ PIVOT ]  172.20.0.20  (red external)
           172.21.0.20  (red internal)   <-- máquina comprometida
     |
     |  red "internal" aislada (internal: true)
     v
[ internal-ssh ]  172.21.0.30  (SSH en 2222, admin/admin123)
[ internal-smb ]  172.21.0.40  (SMB, user/password)
[ internal-web ]  172.21.0.50  (DVWA)
```

Notas importantes:

- Tu Kali **no está en ninguna red Docker**. Solo ve los puertos publicados (`localhost:8080`, `localhost:8000`).
- La red `internal` tiene `internal: true`, así que **no tiene salida a internet** ni es alcanzable desde fuera.
- El único puente entre tu Kali y la red interna es el **pivot**.

---

## Requisitos

En tu Kali:

- `docker` + `docker compose`
- `proxychains4`
- `nmap`, `netcat`, `curl`, `smbclient`, `openssh-client`
- `wget` (o `curl`) para descargar Chisel

---

## Fase 1 — Levantar el laboratorio

### `docker-compose.yml`

```yaml
services:

  pivot:
    image: vulnerables/web-dvwa
    container_name: pivot-host
    networks:
      external:
        ipv4_address: 172.20.0.20
      internal:
        ipv4_address: 172.21.0.20
    ports:
      - "8080:80"
      - "8000:8000"

  internal-ssh:
    image: linuxserver/openssh-server
    container_name: pivot-internal-ssh
    environment:
      - PUID=1000
      - PGID=1000
      - PASSWORD_ACCESS=true
      - USER_NAME=admin
      - USER_PASSWORD=admin123
    networks:
      internal:
        ipv4_address: 172.21.0.30

  internal-smb:
    image: dperson/samba
    container_name: pivot-internal-smb
    command: '-u "user;password" -s "secret;/share;yes;no;yes;all" -p'
    networks:
      internal:
        ipv4_address: 172.21.0.40

  internal-web:
    image: vulnerables/web-dvwa
    container_name: pivot-internal-web
    networks:
      internal:
        ipv4_address: 172.21.0.50

networks:
  external:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  internal:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### Levantar

```bash
mkdir -p ~/ejpt && cd ~/ejpt
# guardar el compose como docker-compose.yml
docker compose up -d
docker compose ps
```

Espera 20–30 segundos a que DVWA arranque y comprueba:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/
```

Debe devolver `200` o `302`.

---

## Fase 2 — Reconocimiento externo

Desde tu Kali, el único host alcanzable es el pivot (vía `localhost`).

```bash
nmap -sT -Pn -p 8080,8000 127.0.0.1
```

Resultado esperado:

```text
PORT     STATE SERVICE
8000/tcp open  http-alt
8080/tcp open  http-proxy
```

La red `172.21.0.0/24` **no es alcanzable**. Compruébalo:

```bash
nmap -sn 172.21.0.0/24
```

No debe encontrar hosts (o dará timeout).

---

## Fase 3 — Comprometer el pivot

En un examen real, aquí explotarías DVWA (SQLi, command injection, file upload...) para obtener ejecución de comandos en el pivot. En este lab lo simulamos entrando directamente al contenedor:

```bash
docker exec -it pivot-host bash
ip a
```

Debes ver **dos interfaces**: `172.20.0.20` (external) y `172.21.0.20` (internal). Esa doble pata es lo que convierte al pivot en puente entre redes.

---

## Fase 4 — Subir Chisel al pivot

### 4.1 Descargar Chisel en tu Kali

```bash
cd ~/ejpt
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gunzip chisel_1.10.1_linux_amd64.gz
mv chisel_1.10.1_linux_amd64 chisel
chmod +x chisel
./chisel --version
```

### 4.2 Copiarlo al pivot

```bash
docker cp ~/ejpt/chisel pivot-host:/usr/local/bin/chisel
docker exec -it pivot-host chisel --version
```

Debe imprimir `1.10.1`.

---

## Fase 5 — Levantar el server Chisel en el pivot

El server se ejecuta **en la máquina comprometida**, porque es la única que ve la red interna.

```bash
docker exec -it pivot-host pkill -9 chisel
docker exec -d pivot-host sh -c 'chisel server -p 8000 --reverse --socks5 > /tmp/chisel-server.log 2>&1'
sleep 1
docker exec -it pivot-host cat /tmp/chisel-server.log
```

Resultado esperado:

```text
server: Reverse tunnelling enabled
server: Fingerprint <...>
server: Listening on http://0.0.0.0:8000
```

### ¿Qué significa cada flag?

| Flag | Significado |
|------|-------------|
| `-p 8000` | Puerto de control (WebSocket) |
| `--reverse` | Permite que los clientes pidan listeners remotos (modo `R:`) |
| `--socks5` | Habilita que el server acepte peticiones SOCKS5 |

> **Nota:** `--verbose` **no existe** en Chisel 1.10. El flag correcto para logging detallado es `-v` (una sola letra).

---

## Fase 6 — Conectar el cliente Chisel desde el atacante

En **tu Kali**, en una terminal dedicada:

```bash
cd ~/ejpt
./chisel client -v 127.0.0.1:8000 1080:socks
```

> **Importante:** La sintaxis es `1080:socks` **sin `R:`**. Eso abre un listener SOCKS **local en tu Kali**, que es exactamente lo que proxychains necesita. Con `R:1080:socks` el listener quedaría en el pivot y proxychains no podría usarlo.

Resultado esperado en el cliente:

```text
client: Connecting to ws://127.0.0.1:8000
client: Handshaking...
client: Sending config
client: Connected (Latency ...)
client: tun: SSH connected
client: tun: proxy#127.0.0.1:1080=>socks: Listening
client: tun: Bound proxies
```

Y en el server (en otra terminal):

```bash
docker exec -it pivot-host tail -10 /tmp/chisel-server.log
```

Debe aparecer:

```text
server: session#1: Verifying configuration
server: session#1: tun: Created (SOCKS enabled)
server: session#1: tun: SSH connected
```

Verifica el listener en tu Kali:

```bash
ss -tlnp | grep 1080
```

Debe mostrar:

```text
LISTEN ... 127.0.0.1:1080 ... users:(("chisel",pid=...,fd=...))
```

**Deja esta terminal del cliente corriendo.** Si la cierras, el túnel muere.

---

## Fase 7 — Configurar proxychains

Edita `/etc/proxychains4.conf`:

```bash
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak

sudo tee /etc/proxychains4.conf > /dev/null <<'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF
```

### ¿Por qué `strict_chain` y no `dynamic_chain`?

Con un solo proxy, `strict_chain` es lo correcto. `dynamic_chain` requiere más de un proxy en la lista y falla con el mensaje `!!!need more proxies!!!` cuando solo hay uno.

### ¿Por qué `proxy_dns`?

Para que la resolución DNS viaje por el túnel. Sin esto, tu Kali intentaría resolver direcciones de la red interna localmente y fallaría.

### Verificación del túnel

```bash
proxychains4 nc -vz 172.21.0.50 80
```

Debe mostrar:

```text
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.21.0.50:80  ...  OK
172.21.0.50 [172.21.0.50] 80 (http) open
```

El `OK` confirma que el túnel funciona.

---

## Fase 8 — Enumeración y ataque de la red interna

A partir de aquí, **cualquier comando** precedido de `proxychains4` viaja por el túnel.

### 8.1 Enumeración de puertos (con `nc`, no con `nmap`)

```bash
proxychains4 nc -vz 172.21.0.30 2222     # SSH
proxychains4 nc -vz 172.21.0.40 445      # SMB
proxychains4 nc -vz 172.21.0.50 80       # HTTP
```

> **Aviso:** `nmap` a través de proxychains suele reportar todos los puertos como `closed` aunque estén abiertos, porque nmap abre muchas conexiones en paralelo y proxychains no las maneja bien. Usa `nc -vz` o `curl` para verificar puertos.

Si aun así quieres probar nmap:

```bash
proxychains4 nmap -sT -Pn --max-parallelism 1 -p 22,80,445,2222 172.21.0.30 172.21.0.40 172.21.0.50
```

### 8.2 Web interna (DVWA)

```bash
proxychains4 curl -s http://172.21.0.50/ | head -30
proxychains4 curl -s http://172.21.0.50/login.php | head
```

Para verla en navegador, configura Firefox con SOCKS5 manual:

- **Host:** `127.0.0.1`
- **Puerto:** `1080`
- **SOCKS v5:** activado
- **Proxy DNS when using SOCKS v5:** activado

Luego visita `http://172.21.0.50`.

### 8.3 SSH interno

```bash
proxychains4 ssh -o StrictHostKeyChecking=no -p 2222 admin@172.21.0.30
# contraseña: admin123
```

### 8.4 SMB interno

```bash
proxychains4 smbclient -L //172.21.0.40 -U user%password
proxychains4 smbclient //172.21.0.40/secret -U user%password
```

---

## Conceptos clave

### ¿Cómo funciona el pivoting con SOCKS?

```text
[TU KALI]                                         [PIVOT]                       [RED INTERNA]
   |                                                 |                               |
   |  herramienta (nmap, curl, ssh)                  |                               |
   |  abre TCP a 172.21.0.50:80                      |                               |
   |        |                                        |                               |
   |        v                                        |                               |
   |  proxychains (LD_PRELOAD)                       |                               |
   |  redirige a 127.0.0.1:1080                      |                               |
   |        |                                        |                               |
   |        v                                        |                               |
   |  chisel client ---- túnel WebSocket :8000 ----> chisel server                  |
   |  (SOCKS en 1080)                                |                               |
   |                                                 |  conexión TCP real            |
   |                                                 |  a 172.21.0.50:80            |
   |                                                 v                               |
   |                                            172.21.0.50:80                      |
   |                                                 |                               |
   |        respuesta                                |                               |
   |  <---- SOCKS <---- túnel <----------------------+                               |
```

**La idea central:** el pivot ve la red interna, tú no. El túnel convierte los ojos del pivot en los tuyos.

### Diferencia entre `socks` y `R:socks` en Chisel

| Comando cliente | Dónde escucha el SOCKS | ¿Sirve para proxychains en el atacante? |
|---|---|---|
| `chisel client host socks` | En el **cliente** (tu Kali) | ✅ Sí |
| `chisel client host 1080:socks` | En el **cliente** (tu Kali) | ✅ Sí |
| `chisel client host R:socks` | En el **server** (el pivot) | ❌ No |
| `chisel client host R:1080:socks` | En el **server** (el pivot) | ❌ No |

Para proxychains en tu máquina atacante, siempre **sin `R:`**.

### ¿Por qué `--reverse` en el server si no uso `R:`?

Porque `--reverse` habilita la capacidad de aceptar listeners remotos. Si en algún momento quieres usar `R:`, ya está habilitado. Si nunca lo usas, no molesta. Algunas versiones de Chisel lo requieren para ciertos flujos internos.

---

## Errores comunes y soluciones

### Error: `flag provided but not defined: -verbose`

Chisel 1.10 no acepta `--verbose`. Usa `-v`.

### Error: `server: Reverse port forwaring not enabled on server`

El server no tiene el flag `--reverse`. Relánzalo con:

```bash
chisel server -p 8000 --reverse --socks5
```

### Error: `Unable to locate package nmap` en el pivot

El pivot usa Debian stretch (EOL). Los repos están en `archive.debian.org`. Arreglo dentro del contenedor:

```bash
cat > /etc/apt/sources.list <<'EOF'
deb [trusted=yes] http://archive.debian.org/debian stretch main contrib non-free
EOF

cat > /etc/apt/apt.conf.d/99no-check <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "true";
Acquire::AllowDowngradeToInsecureRepositories "true";
APT::Get::AllowUnauthenticated "true";
EOF

apt update && apt install -y nmap iproute2 iputils-ping netcat-traditional curl
```

> Alternativa recomendada: cambia la imagen del pivot a `kalilinux/kali-rolling` si no necesitas DVWA específicamente.

### Error: `nmap -sn 172.21.0.0/24` desde el atacante devuelve `172.21.0.1`

Ese `172.21.0.1` es el gateway del bridge de Docker, no un host real. Es normal. El aislamiento funciona.

### Error: `proxychains` muestra `!!!need more proxies!!!`

Estás usando `dynamic_chain` con un solo proxy. Cambia a `strict_chain` en `/etc/proxychains4.conf`.

### Error: `nmap` por proxychains reporta todos los puertos como `closed`

Limitación conocida de proxychains con nmap. Usa `nc -vz` o `curl` en su lugar.

### Error: El cliente Chisel conecta pero no aparece el listener SOCKS

Estás usando `R:socks` (o `R:1080:socks`). Cambia a `socks` o `1080:socks` **sin `R:`**.

### Error: `docker compose down` dice `no configuration file provided`

Tu archivo no se llama `docker-compose.yml`. Usa `-f`:

```bash
docker compose -f docker-compose-pivoting.yml down
```

O renómbralo a `docker-compose.yml`.

---

## Chuleta final

### Arrancar el lab

```bash
cd ~/ejpt
docker compose up -d
docker compose ps
```

### Server Chisel en el pivot

```bash
docker exec -it pivot-host pkill -9 chisel
docker exec -d pivot-host sh -c 'chisel server -p 8000 --reverse --socks5 > /tmp/chisel-server.log 2>&1'
docker exec -it pivot-host cat /tmp/chisel-server.log
```

### Cliente Chisel en tu Kali

```bash
cd ~/ejpt
./chisel client -v 127.0.0.1:8000 1080:socks
# dejar corriendo en primer plano
```

### Verificar túnel

```bash
ss -tlnp | grep 1080
proxychains4 nc -vz 172.21.0.50 80
```

### Atacar la red interna

```bash
proxychains4 nc -vz 172.21.0.30 2222
proxychains4 nc -vz 172.21.0.40 445
proxychains4 nc -vz 172.21.0.50 80

proxychains4 curl -s http://172.21.0.50/ | head
proxychains4 ssh -o StrictHostKeyChecking=no -p 2222 admin@172.21.0.30
proxychains4 smbclient -L //172.21.0.40 -U user%password
```

### Apagar

```bash
docker compose down
```

### Regla mnemotécnica

> **Server Chisel** → en la máquina **comprometida** (la que ve la red interna).
> **Client Chisel** → en **tu máquina** (la que no ve la red interna).
> **SOCKS** → se abre en **tu máquina** (con `socks` o `1080:socks`, **sin `R:`**).
> **proxychains** → en **tu máquina**, apuntando a `127.0.0.1:1080`.

---

## Lecciones aprendidas

1. El pivoting empieza **después** de tener ejecución en la máquina de salto.
2. Chisel necesita `--reverse --socks5` en el server y `socks` (sin `R:`) en el cliente para exponer un SOCKS local en el atacante.
3. Proxychains con `strict_chain` es lo correcto para un solo proxy.
4. `nmap` por proxychains no es fiable. Usa `nc -vz` para puertos y `curl` para HTTP.
5. La red `internal: true` en Docker es un buen simulador de redes internas aisladas.
6. Los contenedores Debian EOL requieren parchear `sources.list` a `archive.debian.org` con `[trusted=yes]` y `APT::Get::AllowUnauthenticated "true"`.
```