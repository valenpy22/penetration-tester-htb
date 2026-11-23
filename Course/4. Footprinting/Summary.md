# SMB/Samba — Enumeration Commands

## 1. Initial scan with Nmap

```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

**Purpose:** Detect the SMB service, server version, and run basic recon scripts.  
**Key ports:** 139 (NetBIOS), 445 (SMB directly over TCP).

---

## 2. smbclient — Direct share interaction

### List available shares (null session)

```bash
smbclient -N -L //10.129.14.128
```

- `-N`: no password (null/anonymous session)
- `-L`: list shares on the server

### Connect to a share

```bash
smbclient //10.129.14.128/notes
```

### Commands inside smbclient

|Command|Function|
|---|---|
|`ls`|List files in the share|
|`get <file>`|Download a file|
|`!ls` / `!cat <file>`|Run local commands without leaving the session|
|`help`|Show all available commands|

---

## 3. rpcclient — Enumeration via MS-RPC

### Connect (null session)

```bash
rpcclient -U "" 10.129.14.128
```

### Useful queries inside rpcclient

|Command|What it returns|
|---|---|
|`srvinfo`|General server info (OS, version, type)|
|`enumdomains`|Domains available on the network|
|`querydominfo`|Domain info: users, groups, server role|
|`netshareenumall`|All shares with paths and comments|
|`netsharegetinfo <share>`|Detail of a specific share (permissions, ACL)|
|`enumdomusers`|Domain user list with RIDs|
|`queryuser <RID>`|Detailed info about a user (e.g. `queryuser 0x3e9`)|
|`querygroup <RID>`|Info about a group (e.g. `querygroup 0x201`)|

### RID brute force (bash loop)

```bash
for i in $(seq 500 1100); do
  rpcclient -N -U "" 10.129.14.128 \
    -c "queryuser 0x$(printf '%x\n' $i)" \
    | grep "User Name\|user_rid\|group_rid" && echo ""
done
```

**Purpose:** Enumerate valid users by iterating over RIDs without knowing them in advance.

---

## 4. Impacket — samrdump.py

```bash
samrdump.py 10.129.14.128
```

**Purpose:** Dump domain users via the SAM (Security Account Manager). Cleaner alternative to the rpcclient loop.

---

## 5. smbmap — Permission enumeration

```bash
smbmap -H 10.129.14.128
```

**Purpose:** List shares and access permissions (READ, WRITE, NO ACCESS) for the current user (anonymous by default).

---

## 6. CrackMapExec (CME) — Quick enumeration

```bash
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

- `--shares`: enumerate shares
- `-u '' -p ''`: empty credentials (null session)

**Advantage over smbmap:** Shows exact permissions (READ, WRITE) and more host details.

---

## 7. enum4linux-ng — Automated enumeration

### Installation

```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```

### Usage

```bash
./enum4linux-ng.py 10.129.14.128 -A
```

- `-A`: all checks (full enumeration)

**Purpose:** Automates most of the above queries — shares, users, groups, password policies, domain info, and supported SMB dialects.

---

## 8. smbstatus — Active session monitoring (server-side)

```bash
sudo smbstatus
```

**Purpose:** View active connections to the Samba server: which user, from which IP, and to which share. Must be run on the server itself.

---

## Tool Summary

| Tool            | Perspective       | Best at                                     |
| --------------- | ----------------- | ------------------------------------------- |
| `nmap`          | External          | Initial port/version detection              |
| `smbclient`     | External          | Direct file interaction inside a share      |
| `rpcclient`     | External          | Manual user/group/share enumeration via RPC |
| `samrdump.py`   | External          | SAM user dump                               |
| `smbmap`        | External          | Per-share permissions at a glance           |
| `crackmapexec`  | External          | Fast, verbose enumeration                   |
| `enum4linux-ng` | External          | All-in-one automated recon                  |
| `smbstatus`     | Internal (server) | View live sessions in real time             |