#!/usr/bin/env bash
#
# check-tools.sh — Verifica que las herramientas del eJPT Cheat Sheet estén
# instaladas y funcionando. Correr en el Linux de ataque (Kali/Parrot/Pwnbox).
#
#   chmod +x check-tools.sh
#   ./check-tools.sh
#

echo "###############################################"
echo "#  Verificación de herramientas — eJPT        #"
echo "###############################################"
echo

echo "=== Presencia (ruta del binario) ==="
for t in \
  nmap netdiscover masscan \
  dig dnsenum dnsrecon host \
  smbclient smbmap rpcclient enum4linux enum4linux-ng.py nbtscan \
  crackmapexec netexec nxc evil-winrm \
  ffuf gobuster feroxbuster wfuzz dirb nikto whatweb wpscan \
  hydra john hashcat cewl medusa \
  msfconsole msfvenom searchsploit \
  nc ncat socat proxychains proxychains4 \
  sqlmap mysql psql \
  snmpwalk onesixtyone showmount \
  curl wget jq openssl telnet ftp tftp \
  xfreerdp rdesktop \
  tcpdump netstat ss \
  python3 perl ruby git \
  smtp-user-enum odat.py sqlplus shodan responder; do
  if p=$(command -v "$t" 2>/dev/null); then
    echo "OK  $t -> $p"
  else
    echo "XX  $t  (NO instalado)"
  fi
done

echo
echo "=== Versiones de las principales ==="
echo "--- nmap ---";        nmap --version 2>/dev/null | head -1
echo "--- ffuf ---";        ffuf -V 2>/dev/null
echo "--- gobuster ---";    gobuster version 2>/dev/null
echo "--- hydra ---";       hydra -h 2>&1 | head -1
echo "--- john ---";        john 2>&1 | head -2
echo "--- hashcat ---";     hashcat --version 2>/dev/null
echo "--- wpscan ---";      wpscan --version 2>/dev/null | head -3
echo "--- metasploit ---";  msfconsole --version 2>/dev/null
echo "--- smbclient ---";   smbclient --version 2>/dev/null
echo "--- crackmapexec/netexec ---"; crackmapexec --version 2>/dev/null || netexec --version 2>/dev/null || nxc --version 2>/dev/null
echo "--- evil-winrm ---";  evil-winrm --version 2>/dev/null || gem list evil-winrm 2>/dev/null
echo "--- sqlmap ---";      sqlmap --version 2>/dev/null
echo "--- impacket ---";    pip show impacket 2>/dev/null | grep -i version || python3 -c "import impacket; print(impacket.__version__)" 2>/dev/null

echo
echo "=== Wordlists / recursos ==="
ls -d /usr/share/seclists 2>/dev/null && echo "SecLists OK" || echo "XX SecLists FALTA"
ls -l /usr/share/wordlists/rockyou.txt* 2>/dev/null || echo "XX rockyou FALTA (descomprime rockyou.txt.gz)"

echo
echo "Listo. Revisa las líneas 'XX' para lo que falte instalar."
