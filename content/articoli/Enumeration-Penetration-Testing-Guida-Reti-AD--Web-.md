---
title: 'Enumeration Penetration Testing: Guida Reti, AD & Web '
slug: enumeration
description: 'Enumeration offensiva 2026: host discovery, SMB, LDAP, Kerberos, BloodHound, web fuzzing e post-compromise. Da zero a domain admin.'
image: /enumeration-pentest.webp
draft: true
date: 2026-06-16T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - 'enumeration penetration testing '
  - active directory enumeration
  - pentest methodology
---

# Enumeration nel Penetration Testing: Guida Definitiva a Reti, AD, Web e Servizi

L'enumeration è la fase che separa un penetration test efficace da uno script kiddie alle prime armi. Senza una mappa completa della superficie d'attacco non sai cosa stai cercando, e quello che non cerchi non lo trovi. Credenziali esposte, servizi non patchati, share accessibili senza autenticazione, path di escalation in BloodHound — tutto dipende da quanto a fondo hai enumerato prima di passare all'exploitation.

Questa guida copre l'intera superficie: dalla scoperta degli host alla mappatura di un dominio Active Directory completo, dai servizi di rete al web, dal post-compromise fino alla pipeline di reporting.

***

## Il Principio Fondamentale: Enumerare Prima di Attaccare

La tentazione in un pentest è di saltare sull'exploit non appena si vede qualcosa di interessante. È quasi sempre un errore. Un servizio SMB con null session può sembrare banale finché non trovi le credenziali dell'amministratore in un file di configurazione in una share. Un SNMP community string `public` può sembrare basso impatto finché non rivela l'intera topologia di rete interna.

**Regola pratica:** l'80% dei vettori di attacco efficaci in ambienti enterprise emerge durante l'enumeration, non durante l'exploitation.

***

## Fase 0 — Automazione Intelligente

Prima di partire con i comandi manuali, uno scanner automatico che gira in background ti dà una baseline su cui lavorare.

### AutoRecon

```bash
# Scan completo su singolo host — lancia nmap, gobuster, nikto, enum4linux in parallelo
autorecon TARGET_IP

# Su range di IP
autorecon 192.168.1.0/24 --only-scans-dir

# Con output strutturato
autorecon TARGET_IP -o ./autorecon_output
```

AutoRecon è il punto di partenza standard nei CTF e negli engagement con time constraint. Gira tutto in parallelo e organizza l'output per protocollo.

### RustScan + Nmap Pipeline

```bash
# RustScan per discovery rapida di porte aperte (molto più veloce di nmap -p-)
rustscan -a TARGET_IP --ulimit 5000 -- -sV -sC

# Poi nmap mirato sulle porte trovate
rustscan -a TARGET_IP -b 500 --ulimit 5000 | grep "Open" | cut -d"/" -f1 | \
  xargs -I{} nmap -p{} -sV --script default TARGET_IP
```

***

## Fase 1 — Host Discovery

### Rete Locale (Layer 2)

```bash
# ARP scan — il più affidabile sulla rete locale, bypassa firewall
arp-scan -l -I eth0
arp-scan 192.168.1.0/24

# Netdiscover — passivo + attivo
netdiscover -r 192.168.1.0/24
netdiscover -i eth0  # modalità passiva
```

### Rete Remota (Layer 3)

```bash
# Ping sweep ICMP
nmap -sn 10.10.10.0/24

# Quando ICMP è bloccato — TCP/UDP probing su porte comuni
nmap -sn -PS22,80,443,445,3389,8080 10.10.10.0/24
nmap -sn -PU53,161,67 10.10.10.0/24

# Masscan per subnet grandi — molto più veloce
masscan 10.0.0.0/8 -p 80,443,22,445 --rate=10000 -oL hosts.txt
```

***

## Fase 2 — Port Scanning

### Strategia di Scan

```bash
# Step 1: scan veloce su top-1000 porte per avere risultati rapidi
nmap -sV -sC --top-ports 1000 -T4 TARGET_IP -oN quick.txt

# Step 2: scan completo TCP su tutte le 65535 porte (in background)
nmap -p- --min-rate 5000 -T4 TARGET_IP -oN full_tcp.txt

# Step 3: UDP — spesso dimenticato, goldmine
nmap -sU --top-ports 20 -T4 TARGET_IP -oN udp.txt
nmap -sU -p 53,67,69,111,123,161,162,500,514,1194 TARGET_IP

# Step 4: scan aggressivo sulle porte identificate
nmap -p PORTE_APERTE -sV -sC -A -T4 TARGET_IP -oN detailed.txt
```

**Porte AD da cercare sempre:**

```
53    DNS
88    Kerberos
135   RPC Endpoint Mapper
139   NetBIOS Session
389   LDAP
445   SMB
464   Kerberos Password Change
593   HTTP RPC
636   LDAPS
1433  MSSQL
1521  Oracle
2049  NFS
3268  Global Catalog LDAP
3269  Global Catalog LDAPS
3389  RDP
5985  WinRM HTTP
5986  WinRM HTTPS
8080  Web alt
9389  AD Web Services
```

***

## Fase 3 — DNS Enumeration

DNS è il mapping dell'infrastruttura. Spesso trovi hostname che rivelano ruoli (dc01, fileserver, vpn, backup) e IP di sistemi non direttamente raggiungibili.

```bash
# Query base
nslookup TARGET_DOMAIN DC_IP
host TARGET_DOMAIN DC_IP

# Zone transfer (spesso abilitato per errore)
dig axfr TARGET_DOMAIN @DNS_SERVER
host -l TARGET_DOMAIN DNS_SERVER

# Subdomain bruteforce
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50
dnsenum --dnsserver DC_IP --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt TARGET_DOMAIN

# dnsx — veloce, supporta wildcard detection
echo "target.com" | dnsx -a -cname -mx -ns -txt -resp

# Reverse DNS lookup su subnet
for ip in $(seq 1 254); do nslookup 192.168.1.$ip DNS_IP 2>/dev/null | grep "name ="; done

# dnsrecon — enumerazione completa
dnsrecon -d TARGET_DOMAIN -t std,brt,axfr,cache -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**In un ambiente AD, il DNS è spesso il server stesso del DC.** Zone transfer sul dominio AD può rivelare tutti gli host registrati inclusi quelli non presenti in nessuna altra lista.

***

## Fase 4 — SMB Enumeration

SMB è storicamente la fonte più ricca di informazioni in ambienti Windows. Anche senza credenziali, le null session (ancora abilitate su molti sistemi legacy) possono rivelare utenti, share, e policy.

### Null Session e Share Discovery

```bash
# NetExec — null session
nxc smb TARGET_IP -u '' -p '' --shares
nxc smb TARGET_IP -u 'guest' -p '' --shares
nxc smb 192.168.1.0/24 -u '' -p '' --shares  # sweep subnet

# smbclient
smbclient -L //TARGET_IP -N
smbclient -L //TARGET_IP -U ''%''

# smbmap — mostra permessi per share
smbmap -H TARGET_IP
smbmap -H TARGET_IP -u '' -p ''
smbmap -H TARGET_IP -u 'user' -p 'pass' -R  # ricorsivo
```

### Con Credenziali

```bash
# Enum completa
nxc smb TARGET_IP -u user -p pass --shares
nxc smb TARGET_IP -u user -p pass --users
nxc smb TARGET_IP -u user -p pass --groups
nxc smb TARGET_IP -u user -p pass --local-users
nxc smb TARGET_IP -u user -p pass --pass-pol
nxc smb TARGET_IP -u user -p pass --sessions  # sessioni attive
nxc smb TARGET_IP -u user -p pass --loggedon-users
nxc smb TARGET_IP -u user -p pass --disks

# Download ricorsivo da share
smbclient //TARGET_IP/SHARENAME -U 'domain\user%pass' -c 'recurse;prompt;mget *'

# Spider share per file interessanti
nxc smb TARGET_IP -u user -p pass -M spider_plus
```

### enum4linux-ng — Legacy ma Utile

```bash
enum4linux-ng -A TARGET_IP          # full enum
enum4linux-ng -A -u user -p pass TARGET_IP
enum4linux-ng TARGET_IP -P          # solo password policy
enum4linux-ng TARGET_IP -U          # solo utenti
```

### Script NSE Mirati

```bash
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode TARGET_IP
nmap -p 445 --script smb-vuln-ms17-010 TARGET_IP  # EternalBlue check
nmap -p 445 --script smb-enum-domains TARGET_IP
```

***

## Fase 5 — LDAP Enumeration

LDAP è la rubrica di Active Directory. Contiene utenti, computer, gruppi, policy, configurazioni ADCS, trust — praticamente tutto.

### Senza Credenziali (Accesso Anonimo)

```bash
# Null bind — funziona su molti DC non hardened
ldapsearch -H ldap://TARGET_IP -x -b "DC=corp,DC=local"
ldapsearch -H ldap://TARGET_IP -x -s base namingcontexts  # leggi naming contexts

# Dump base information
ldapsearch -H ldap://TARGET_IP -x -b "DC=corp,DC=local" \
  "(objectClass=*)" | head -100
```

### Con Credenziali

```bash
# Tutti gli utenti
ldapsearch -H ldap://TARGET_IP -x \
  -D "user@corp.local" -w 'Password123' \
  -b "DC=corp,DC=local" \
  "(objectClass=user)" sAMAccountName description pwdLastSet memberOf

# Utenti con description (spesso contiene password)
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(description=*))" sAMAccountName description

# Computer accounts
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(objectClass=computer)" dNSHostName operatingSystem

# Gruppi privilegiati
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(cn=Domain Admins)" member

# Account con AdminCount=1 (account protetti elevati)
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(adminCount=1))" sAMAccountName

# Account con SPN (Kerberoastable)
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Account senza pre-autenticazione (AS-REP Roastable)
ldapsearch -H ldap://TARGET_IP -x -D "user@corp.local" -w 'pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

### ldapdomaindump — Output HTML

```bash
ldapdomaindump -u 'corp.local\user' -p 'Password123' TARGET_IP \
  -o /tmp/ldapdump/
# Genera file HTML navigabili con tutti gli oggetti AD
```

Vedi: [ldapsearch](https://hackita.it/articoli/ldapsearch/)

***

## Fase 6 — Kerberos Enumeration

Kerberos su porta 88 permette user enumeration senza credenziali sfruttando i diversi codici di errore del KDC.

```bash
# User enumeration — KDC_ERR_PREAUTH_REQUIRED = utente valido
kerbrute userenum --dc DC_IP -d corp.local \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Con lista utenti custom
kerbrute userenum --dc DC_IP -d corp.local users.txt

# AS-REP Roasting — utenti senza pre-autenticazione
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip DC_IP -format hashcat
GetNPUsers.py corp.local/user:pass -request -dc-ip DC_IP

# Kerberoasting — TGS per SPN
GetUserSPNs.py corp.local/user:pass -dc-ip DC_IP -request -outputfile tgs.txt
```

L'enumerazione Kerberos è stealth rispetto all'enumeration SMB — i fallimenti generano Event 4771 invece del più monitorato 4625.

***

## Fase 7 — RPC Enumeration

RPC (porta 135) e rpcclient (porta 445) aprono una finestra su informazioni AD non sempre accessibili via LDAP.

```bash
# Connessione null session
rpcclient -U "" -N TARGET_IP
rpcclient -U "user%pass" TARGET_IP

# Comandi rpcclient utili
rpcclient $> enumdomusers         # lista utenti dominio
rpcclient $> enumdomgroups        # lista gruppi
rpcclient $> enumalsgroups domain # builtin groups
rpcclient $> querydominfo         # info dominio (policy, SID)
rpcclient $> getdompwinfo         # password policy
rpcclient $> querydispinfo        # display info utenti (descrizione, etc.)
rpcclient $> queryuser 0x3e8      # info su RID specifico
rpcclient $> netshareenum         # lista share
rpcclient $> netsharegetinfo SHARE # info su share specifica
rpcclient $> lsaenumsid           # SID del sistema
rpcclient $> lookupsids S-1-5-21-... # risolvi SID in nome

# Enumeration automatica del range RID
for i in $(seq 500 1100); do
  rpcclient -N -U "" TARGET_IP -c "queryuser 0x$(printf '%x\n' $i)" 2>/dev/null | \
  grep "User Name"
done
```

Vedi: [rpcclient](https://hackita.it/articoli/rpcclient/)

***

## Fase 8 — SNMP Enumeration

SNMP su UDP 161 è spesso dimenticato durante i port scan TCP-only. Community string `public` è ancora comune in ambienti mal configurati e può rivelare informazioni significative: interfacce di rete, processi in esecuzione, utenti loggati, software installato.

```bash
# Brute force community string
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP
nmap -sU -p 161 --script snmp-brute TARGET_IP

# Dump MIB completo
snmpwalk -v2c -c public TARGET_IP
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # processi
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.6.3.1.2  # software installato
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25   # utenti Windows
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.2.2         # interfacce rete

# snmp-check — output leggibile
snmp-check TARGET_IP -c public

# SNMPv3 con credenziali
snmpwalk -v3 -l authNoPriv -u snmpuser -a MD5 -A AuthPass TARGET_IP
```

Vedi: [SNMP](https://hackita.it/articoli/snmp/)

***

## Fase 9 — NFS e Servizi File

```bash
# Lista mount disponibili
showmount -e TARGET_IP
nmap -sV -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs TARGET_IP

# Mount
mkdir /mnt/nfs_target
mount -t nfs TARGET_IP:/export/share /mnt/nfs_target
mount -t nfs -o nolock TARGET_IP:/home /mnt/nfs_target

# Cerca file interessanti sul mount
find /mnt/nfs_target -name "*.key" -o -name "*.pem" -o -name "id_rsa" \
  -o -name "*.conf" -o -name "*.bak" 2>/dev/null

# Verifica permessi
ls -la /mnt/nfs_target
cat /etc/exports  # se hai accesso al server
```

**Pattern di privilege escalation via NFS:** se la share è montata con `no_root_squash`, puoi copiare una bash SUID sul mount e eseguirla come root sul server.

***

## Fase 10 — Active Directory Enumeration Avanzata

### BloodHound + SharpHound

Lo standard de facto per mappare gli attack path AD. Dopo la raccolta dati, BloodHound costruisce un grafo che mostra tutti i percorsi da qualsiasi utente a Domain Admin.

```bash
# Da Linux (bloodhound-python)
bloodhound-python -u user -p Password123 -d corp.local \
  -ns DC_IP -c All --zip

# Tutti i metodi di raccolta
bloodhound-python -u user -p Password123 -d corp.local \
  -ns DC_IP -c DCOnly,All,LoggedOn,LocalAdmin,Session,Trusts,Default

# Da Windows (SharpHound in memoria)
.\SharpHound.exe -c All --outputdirectory C:\Temp\
.\SharpHound.exe -c DCOnly,Session,LocalAdmin  # meno rumoroso

# Query BloodHound essenziali dopo import:
# - "Shortest Paths to Domain Admins"
# - "Find All Domain Admins"  
# - "Kerberoastable Users"
# - "AS-REP Roastable Users"
# - "Users with DCSync Rights"
# - "Find Computers with Constrained Delegation"
# - "Find Computers with Unconstrained Delegation"
```

Vedi: [BloodHound](https://hackita.it/articoli/bloodhound/)

### PowerView — Enumeration Granulare da Windows

```powershell
Import-Module .\PowerView.ps1

# Info di base sul dominio
Get-Domain
Get-DomainController
Get-Forest
Get-ForestTrust  # trust inter-forest

# Utenti e attributi
Get-DomainUser | select samaccountname, description, pwdlastset, logoncount
Get-DomainUser -SPN | select samaccountname, serviceprincipalname  # Kerberoastable
Get-DomainUser -PreauthNotRequired  # AS-REP Roastable
Get-DomainUser -AdminCount         # account protetti/privilegiati

# Gruppi privilegiati e membership
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins" -Recurse
Get-DomainGroupMember "Backup Operators"
Get-DomainGroupMember "Account Operators"

# Computer e OS
Get-DomainComputer | select dnshostname, operatingsystem, lastlogondate
Get-DomainComputer -Unconstrained  # unconstrained delegation — alto rischio
Get-DomainComputer -TrustedToAuth  # constrained delegation

# ACL su oggetti AD
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs | \
  Where-Object {$_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteOwner|GenericAll"}

# Share accessibili nel dominio
Invoke-ShareFinder -Verbose
Find-InterestingDomainShareFile -Include "*.txt","*.ini","*.config","*.ps1","*.bat"

# GPO
Get-DomainGPO | select displayname, gpcfilesyspath
Get-DomainGPOLocalGroup  # chi ha admin locale via GPO

# Password policy
Get-DomainPolicy | select -ExpandProperty SystemAccess
Get-DomainDefaultPasswordPolicy
```

Vedi: [PowerView](https://hackita.it/articoli/powerview/)

### Impacket per AD Enum da Linux

```bash
# Utenti del dominio
GetADUsers.py -all corp.local/user:pass -dc-ip DC_IP

# SID enumeration
lookupsid.py corp.local/user:pass@DC_IP

# Enum share
smbclient.py corp.local/user:pass@DC_IP

# Informazioni sul DC
rdap.py DC_IP  # (se disponibile)
```

### ACL Abuse Discovery

```powershell
# Trova ACL interessanti sul tuo utente
Find-InterestingDomainAcl -ResolveGUIDs | \
  Where-Object {$_.IdentityReferenceName -match "YourUser|YourGroup"}

# Trova oggetti dove hai diritti di scrittura
Get-ObjectAcl -ResolveGUIDs | \
  Where-Object {
    $_.IdentityReferenceName -eq "YourUser" -and
    $_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteOwner"
  }
```

Vedi: [ACL Abuse](https://hackita.it/articoli/acl-abuse/)

### ADCS Enumeration

```bash
# Certipy — trova template ADCS vulnerabili
certipy-ad find -u user@corp.local -p pass -dc-ip DC_IP -vulnerable -enabled

# Solo output a schermo
certipy-ad find -u user@corp.local -p pass -dc-ip DC_IP -stdout
```

Vedi: [Certipy](https://hackita.it/articoli/certipy/)

***

## Fase 11 — Web Enumeration

### Directory e File Fuzzing

```bash
# ffuf — veloce e flessibile
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,204,301,302,307,401,403 -t 50

# Con estensioni
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.txt,.bak,.old,.zip,.tar.gz,.config,.env

# Fuzzing Virtual Hosting
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0

# Gobuster
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,old,conf -t 50 -k

# feroxbuster — supporta ricorsione automatica
feroxbuster -u https://target.com -w wordlist.txt --auto-tune
```

### Technology Fingerprinting

```bash
# whatweb
whatweb https://target.com -v

# wappalyzer CLI
wappalyzer https://target.com

# httpx con fingerprint
echo "target.com" | httpx -tech-detect -status-code -title -web-server

# Analisi header
curl -I https://target.com
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|set-cookie"

# robots.txt e sitemap (sempre)
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
```

### API Discovery

```bash
# Fuzzing endpoint API
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Parameter fuzzing con arjun
arjun -u https://target.com/api/endpoint

# Analisi JavaScript per endpoint e chiavi API
cat *.js | grep -E "api\.|/api/|fetch\(|axios\.|baseURL" 
# oppure usa tool come LinkFinder
python3 linkfinder.py -i https://target.com -d -o cli
```

### Nikto — Vulnerabilità Web Comuni

```bash
nikto -h https://target.com -ssl
nikto -h target.com -port 80,443,8080,8443
```

***

## Fase 12 — Database Enumeration

### MSSQL (1433)

```bash
# Connessione e enum
mssqlclient.py corp.local/user:pass@TARGET_IP -windows-auth

# Con NetExec
nxc mssql TARGET_IP -u user -p pass --local-auth -q "SELECT @@version"
nxc mssql TARGET_IP -u user -p pass -M mssql_priv  # check privilege escalation

# Abilitare xp_cmdshell
mssqlclient.py user:pass@TARGET_IP
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

### MySQL (3306)

```bash
# Connessione diretta
mysql -u root -h TARGET_IP -p

# Enum
mysql -u root -p -e "SELECT User, Host, authentication_string FROM mysql.user;"
mysql -u root -p -e "SHOW DATABASES;"
mysql -u root -p -e "SHOW GRANTS FOR 'user'@'host';"
```

Vedi: [NetExec](https://hackita.it/articoli/netexec/)

***

## Fase 13 — Servizi Vari

### FTP (21)

```bash
# Anonymous login
ftp TARGET_IP   # user: anonymous, pass: [vuoto o email]
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst TARGET_IP

# Se anonimo funziona — download ricorsivo
wget -r ftp://TARGET_IP/ --ftp-user=anonymous --ftp-password=anon
```

### SMTP (25)

```bash
# User enumeration via VRFY/EXPN
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET_IP
smtp-user-enum -M EXPN -U users.txt -t TARGET_IP
nmap -p 25 --script smtp-enum-users,smtp-commands TARGET_IP

# Connessione manuale
nc TARGET_IP 25
EHLO hacker.com
VRFY admin
```

Vedi: [Netcat](https://hackita.it/articoli/netcat/) per connessioni manuali e banner grabbing.

### SNMP (161 UDP)

Vedi sezione dedicata sopra e [SNMP](https://hackita.it/articoli/snmp/).

### Redis (6379)

```bash
# Connessione (spesso senza auth)
redis-cli -h TARGET_IP ping
redis-cli -h TARGET_IP info server
redis-cli -h TARGET_IP keys "*"   # lista tutte le chiavi
redis-cli -h TARGET_IP get KEY    # leggi valore

# Verifica configurazione
redis-cli -h TARGET_IP config get dir
redis-cli -h TARGET_IP config get dbfilename
```

***

## Fase 14 — Post-Compromise Enumeration (Host)

Una volta ottenuto l'accesso a un host, l'enumeration ricomincia dal punto di vista locale.

### Linux

```bash
# Privesc vectors immediati
id; whoami; sudo -l; groups

# Kernel e OS
uname -a; cat /etc/os-release

# SUID e capabilities
find / -perm -4000 2>/dev/null
getcap -r / 2>/dev/null

# Cron jobs
cat /etc/crontab; ls /etc/cron.*; crontab -l

# File con credenziali
cat ~/.bash_history
find /var/www -name "*.php" | xargs grep -l "password\|DB_PASS" 2>/dev/null
find / -name ".env" 2>/dev/null

# Rete
ip addr; ip route; ss -tlnp; arp -a
```

Strumenti automatici: [LinPEAS](https://hackita.it/articoli/linpeas/), [LinEnum](https://hackita.it/articoli/linenum/), [tshark](https://hackita.it/articoli/tshark/) per analisi traffico, [Top 100 Comandi Linux](https://hackita.it/articoli/top-100-comandi-linux/) per reference.

### Windows

```cmd
systeminfo
whoami /all
net user; net localgroup administrators
ipconfig /all; route print

# Privilege check
whoami /priv

# Processi e servizi
tasklist /SVC
wmic service get name,startname,pathname

# Credenziali salvate
cmdkey /list
```

Strumenti: [WinPEAS](https://hackita.it/articoli/winpeas/), [WinEnum](https://hackita.it/articoli/winenum/), [WMIC](https://hackita.it/articoli/wmic/)

***

## Fase 15 — Network Topology e Pivot Discovery

```bash
# Interfacce multiple — host potenzialmente dual-homed
ip addr | grep "inet "
# Se hai più interfacce → pivot verso subnet interna

# ARP cache — host vicini già contattati
arp -a
cat /proc/net/arp

# Route table — subnet raggiungibili
ip route
route -n

# DNS config — rivela dominio e DC
cat /etc/resolv.conf
cat /etc/hosts
nmcli dev show | grep DNS  # Linux con NetworkManager

# File hosts Windows
type C:\Windows\System32\drivers\etc\hosts
```

***

## Trust e Multi-Domain Enumeration

In ambienti enterprise trovi spesso più domini in trust. Enumerarli è fondamentale per gli ExtraSIDs attack.

```powershell
# Da PowerView
Get-ForestTrust
Get-DomainTrust
Get-DomainTrustMapping  # mappa ricorsiva di tutti i trust

# Da Impacket
GetUserSPNs.py corp.local/user:pass -dc-ip DC_IP -target-domain child.corp.local
```

***

## Metodologia: L'Ordine che Non Sbaglia

```
SENZA CREDENZIALI:
1. Host discovery (arp-scan, nmap -sn)
2. Port scan rapido → full TCP → UDP
3. DNS (zone transfer, subdomain brute)
4. SMB null session (share, utenti, policy)
5. LDAP anonymous bind
6. Kerberos user enumeration (kerbrute)
7. SNMP community brute (UDP 161)
8. Web enumeration (dir fuzzing, tech fingerprint)
9. FTP/SMTP anonymous

CON CREDENZIALI:
10. NetExec sweep su subnet (SMB, LDAP, WinRM, MSSQL)
11. BloodHound collection
12. PowerView / Impacket enum
13. ADCS enum (certipy find)
14. Share spider (file con credenziali, config)
15. ACL enum → attack path verso DA
```

***

## Tool Reference

| Tool                                                                                              | Uso principale                      |
| ------------------------------------------------------------------------------------------------- | ----------------------------------- |
| [Nmap](https://hackita.it/articoli/nmap/)                                                         | Port scan, NSE scripts              |
| [NetExec](https://hackita.it/articoli/netexec/)                                                   | SMB/LDAP/WinRM enum con credenziali |
| [BloodHound](https://hackita.it/articoli/bloodhound/)                                             | AD attack path analysis             |
| [PowerView](https://hackita.it/articoli/powerview/)                                               | AD enum da PowerShell               |
| [ffuf](https://hackita.it/articoli/ffuf/) / [Gobuster](https://hackita.it/articoli/gobuster/)     | Web fuzzing                         |
| [Impacket](https://hackita.it/articoli/impacket/)                                                 | LDAP, Kerberos, SMB, MSSQL          |
| [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/)                                       | SMB/LDAP legacy                     |
| [LinPEAS](https://hackita.it/articoli/linpeas/) / [LinEnum](https://hackita.it/articoli/linenum/) | Post-compromise Linux               |
| [WinPEAS](https://hackita.it/articoli/winpeas/)                                                   | Post-compromise Windows             |
| [Netcat](https://hackita.it/articoli/netcat/)                                                     | Banner grab, connessioni manuali    |
| [Tshark](https://hackita.it/articoli/tshark/)                                                     | Analisi traffico di rete            |
| [SNMP tools](https://hackita.it/articoli/snmp/)                                                   | SNMP enumeration                    |

***

*MITRE ATT\&CK: T1018 (Remote System Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1046 (Network Service Discovery), T1135 (Network Share Discovery)*
