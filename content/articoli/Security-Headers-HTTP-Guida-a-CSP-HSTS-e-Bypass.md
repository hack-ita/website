---
title: 'Security Headers HTTP: Guida a CSP, HSTS e Bypass'
slug: security-headers
description: 'Scopri come testare e configurare i security headers HTTP: CSP, HSTS, X-Frame-Options, Referrer-Policy e tecniche di bypass nei pentest web.'
image: /security-headers-http-hackita.webp
draft: false
date: 2026-08-08T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - security-headers
  - content-security-policy
  - hsts
  - csp-bypass
  - x-frame-options
  - referrer-policy
  - clickjacking
  - web-pentesting
---

# Security Headers HTTP: Come Testare CSP, HSTS e Configurazioni Bypassabili

Gli **HTTP security headers** sono istruzioni che il server invia al browser per dirgli cosa può fare con la pagina: quali risorse caricare, quali script eseguire, se la pagina può finire dentro un frame, se deve usare solo HTTPS, cosa condividere nel referrer e quali funzionalità del browser (camera, microfono, geolocalizzazione...) può usare.

Se questi header mancano o sono configurati male, peggiorano l'impatto di vulnerabilità come [XSS](https://hackita.it/articoli/xss), [clickjacking](https://hackita.it/articoli/clickjacking), [MITM](https://hackita.it/articoli/man-in-the-middle) e furto di token. Ma un header mancante, da solo, **non è già una vulnerabilità sfruttabile**: va sempre verificato cosa fa quella pagina, quale funzionalità è in gioco e quale sarebbe il danno reale.

Anche gli header presenti vanno controllati, non solo quelli assenti. Una CSP con una allowlist troppo ampia può essere aggirata se, su un dominio già autorizzato, esiste uno script gadget o un endpoint che l'attaccante può controllare. E se in `script-src` c'è `'unsafe-inline'`, la protezione contro gli script inline crolla parecchio — ma le altre direttive della policy possono comunque restare valide.

OWASP include gli header mancanti o impostati su valori insicuri in **A02:2025 — Security Misconfiguration**.

### Cosa Sono gli HTTP Security Headers?

Sono le direttive HTTP con cui un server dice al browser come trattare contenuti, script, iframe, connessioni HTTPS, risorse cross-origin e funzionalità sensibili. Le principali sono CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy.

**Metodologia:** i test di questa guida uniscono analisi degli header HTTP, verifica manuale nel browser, analisi delle policy CSP e conferma che il problema sia davvero sfruttabile. Gli scanner automatici servono solo per un primo giro veloce.

***

## Security Headers HTTP: Checklist Rapida

| Header                              | A cosa serve                 | Cosa testare                                           | Possibile impatto      |
| ----------------------------------- | ---------------------------- | ------------------------------------------------------ | ---------------------- |
| CSP                                 | Mitiga XSS/content injection | nonce, hash, allowlist, `unsafe-inline`, `unsafe-eval` | XSS                    |
| HSTS                                | Forza HTTPS                  | `max-age`, `includeSubDomains`, `preload`              | MITM, SSL stripping    |
| X-Frame-Options / `frame-ancestors` | Impedisce il framing         | `DENY`, `SAMEORIGIN`, origini autorizzate              | Clickjacking           |
| X-Content-Type-Options              | Blocca il MIME sniffing      | `nosniff`                                              | MIME confusion         |
| Referrer-Policy                     | Limita le info nel referrer  | policy esplicita, leak di token nell'URL               | Information disclosure |
| Permissions-Policy                  | Limita le API del browser    | camera, microfono, geolocalizzazione                   | Superficie di attacco  |
| COOP / COEP / CORP                  | Isolamento cross-origin      | configurazione, se richiesta dall'architettura         | Cross-origin leak      |
| X-XSS-Protection                    | Header deprecato             | assente o `0`                                          | Nessuno                |
| Cache-Control                       | Controlla il caching         | `no-store` su risposte sensibili                       | Data exposure          |

Ogni riga richiede comunque il contesto descritto più avanti: la tabella è un punto di partenza, non un verdetto.

***

## Come Controllare gli HTTP Security Headers con curl (in 30 Secondi)

```bash
# Segui i redirect e mostra gli header della risposta finale
curl -skIL "https://target.com/" | grep -iE \
  "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin|x-xss-protection|cache-control"

# Controlla separatamente la risposta HTTP iniziale
curl -sI "http://target.com/"

# Tool utili
# securityheaders.com              → controllo generale e grade indicativo
# csp-evaluator.withgoogle.com     → analisi statica della CSP
# Burp Suite                       → verifica header su ogni endpoint e risposta
```

Se un header manca, chiediti prima:

```text
1. La risposta contiene HTML interattivo o dati sensibili?
2. La pagina può essere caricata in un iframe?
3. Esistono script, stili o risorse controllabili dall'utente?
4. Il sito accetta ancora traffico HTTP?
5. Nell'URL compaiono token o parametri riservati?
6. La configurazione mancante abilita un attacco riproducibile?
```

Un'API JSON, una risposta `204`, un redirect o una risorsa statica non hanno bisogno degli stessi header di una pagina autenticata dove l'utente compie azioni sensibili.

***

## Content-Security-Policy (CSP)

La **Content Security Policy** dice al browser da quali origini può caricare script, stili, immagini, font, frame e connessioni. È una misura di **defense in depth** contro XSS e content injection: aiuta, ma non sostituisce output encoding, sanitizzazione, template sicuri e validazione dell'input.

### Come Si Legge una CSP

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; frame-ancestors 'none'; base-uri 'none'
```

```text
default-src 'self'              → fallback per le direttive non dichiarate
script-src 'self' ...           → origini autorizzate a fornire JavaScript
style-src                       → origini autorizzate per CSS
img-src                         → origini autorizzate per immagini
connect-src                     → destinazioni di fetch, XHR, WebSocket e beacon
frame-src                       → origini caricabili dentro iframe
frame-ancestors                 → origini autorizzate a incorporare la pagina
form-action                     → destinazioni consentite per i form
object-src 'none'               → blocca object/embed e plugin legacy
base-uri 'none'                 → impedisce la modifica della base URL tramite <base>
```

### Debolezza 1 — `'unsafe-inline'`

Con questa policy il browser esegue script inline, event handler ed elementi tipo `javascript:`:

```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

Se c'è anche una XSS che permette di iniettare markup, un payload inline come questo può girare senza problemi:

```html
<script>alert(document.domain)</script>
<img src=x onerror="alert(document.domain)">
```

Test rapido:

```bash
curl -skI "https://target.com/" | grep -i content-security-policy
```

Non buttare via l'intera CSP solo perché c'è `'unsafe-inline'`: direttive come `frame-ancestors`, `object-src`, `form-action`, `connect-src` e `base-uri` possono continuare a proteggere. Inoltre, con policy moderne basate su nonce o hash, quanto conta davvero `'unsafe-inline'` dipende dalla combinazione di tutte le direttive e da cosa supporta il browser.

### Debolezza 2 — Origini Allowlistate con JSONP o Contenuto Controllabile

Una CSP basata solo su una lista di host fidati è fragile se un'origine autorizzata espone:

* endpoint JSONP con callback controllabile;
* file caricabili o pubblicabili dall'utente;
* CDN che consente di scegliere librerie o versioni pericolose;
* endpoint che restituiscono JavaScript controllabile;
* script gadget sfruttabili nel contesto della pagina.

Esempio concettuale:

```http
Content-Security-Policy: script-src 'self' https://api-allowlisted.example
```

```html
<script src="https://api-allowlisted.example/jsonp?callback=FUNZIONE_CONTROLLATA"></script>
```

Il bypass funziona solo se **l'origine esatta scritta in `script-src`** espone davvero un endpoint utilizzabile, e se quello che restituisce fa eseguire JavaScript nel contesto che stai testando. Endpoint pubblici e payload trovati online cambiano spesso: verifica sempre a mano la risposta, non fidarti di liste vecchie senza controllarle.

### Debolezza 3 — Script Gadget e Framework Legacy

Un'origine autorizzata può ospitare un framework vecchio o una libreria che trasforma markup controllabile dall'utente in JavaScript eseguito. AngularJS 1.x è l'esempio storico di **script gadget**, ma se funziona davvero dipende da:

* versione effettivamente caricabile;
* sintassi e sandbox di quella versione;
* presenza di `unsafe-eval` o altre direttive;
* punto di injection disponibile;
* modalità CSP del framework;
* trasformazioni applicate dal sanitizer.

```http
Content-Security-Policy: script-src 'self' https://cdn-allowlisted.example
```

Vedere il dominio del CDN nella policy non basta: durante il pentest devi dimostrare che una libreria compatibile può essere caricata e che il gadget viene davvero eseguito nel DOM della pagina.

### Debolezza 4 — Redirect, Path e Origini Autorizzate

Un **open redirect non rende automaticamente valida qualsiasi origine finale**: il browser continua ad applicare la CSP a tutta la catena di caricamento, non solo al primo salto.

I redirect diventano interessanti quando portano, dentro un'origine già autorizzata, verso endpoint JSONP, file controllabili, path normalmente esclusi o altri script gadget. Verifica quindi:

```text
- origine iniziale e origine finale;
- path consentiti dalla source expression;
- numero e tipo di redirect;
- Content-Type della risposta finale;
- comportamento reale del browser, non soltanto quello di curl.
```

Approfondimento dedicato sullo sfruttamento generale di questa classe di bug: [Open Redirect: guida completa](https://hackita.it/articoli/open-redirect).

### Debolezza 5 — Nonce Prevedibile, Riusato o Copiato su Input Non Fidato

Un nonce buono è casuale al 100%, cambia a ogni risposta e viene applicato solo agli script di cui ti fidi.

```html
<!-- Esempio corretto: nonce generato per questa risposta -->
<script nonce="RANDOM_PER_RESPONSE">inizializzaApp()</script>
```

```http
Content-Security-Policy: script-src 'nonce-RANDOM_PER_RESPONSE' 'strict-dynamic'; object-src 'none'; base-uri 'none'
```

Cosa cercare:

```text
- nonce identico tra richieste differenti;
- nonce derivato da timestamp o contatori prevedibili;
- nonce inserito automaticamente su ogni tag <script>, inclusi quelli iniettati;
- nonce esposto in un contesto che l'attaccante può leggere e riutilizzare;
- template che copiano attributi controllati dall'utente.
```

### CSP Consigliata

Una **strict CSP** basata su nonce o hash è quasi sempre più solida di una lunga lista di host autorizzati.

```http
Content-Security-Policy:
  script-src 'nonce-RANDOM_PER_RESPONSE' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  form-action 'self';
  img-src 'self' data: https:;
  style-src 'self';
  connect-src 'self';
```

Il nonce va generato dall'applicazione a ogni risposta: non può essere un valore fisso scritto nella configurazione Nginx.

Per introdurre una policy senza rompere il sito, parti da:

```http
Content-Security-Policy-Report-Only: ...
```

Raccogli le violazioni, sistema le dipendenze legittime e solo dopo passi alla policy vera e propria. `Report-Only` **non blocca nulla**: serve solo a osservare prima del rollout.

***

## Strict-Transport-Security (HSTS)

HSTS dice al browser di raggiungere quel dominio solo via HTTPS. Una volta ricevuto l'header su una connessione HTTPS valida, il browser trasforma da solo le richieste HTTP future in HTTPS e non lascia più ignorare gli errori di certificato.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

```text
max-age=31536000   → memorizza la policy per un anno
includeSubDomains  → estende HSTS ai sottodomini
preload            → dichiara l'intenzione di entrare nella preload list
```

### Come Testare HSTS

```bash
# La risposta HTTP deve reindirizzare immediatamente a HTTPS
curl -sI "http://target.com/"

# L'header HSTS deve essere presente sulla risposta HTTPS
curl -skI "https://target.com/" | grep -i strict-transport-security
```

Punti importanti:

```text
- I browser ignorano Strict-Transport-Security ricevuto tramite HTTP.
- HSTS non protegge la primissima visita HTTP, salvo preload o policy già memorizzata.
- includeSubDomains va usato solo quando tutti i sottodomini supportano HTTPS.
- preload richiede requisiti specifici e può avere conseguenze operative durature.
- un max-age breve può essere corretto durante il rollout iniziale, ma non offre protezione persistente.
```

### Configurazione Nginx e Apache

```nginx
# Attivare includeSubDomains solo dopo aver verificato tutti i sottodomini
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

Aggiungi `preload` solo dopo aver verificato i requisiti della preload list e la possibilità di tenere HTTPS su dominio e sottodomini a lungo termine.

***

## X-Frame-Options e CSP `frame-ancestors`

Questi header decidono se una pagina può finire dentro un frame. La loro assenza non è già clickjacking: la pagina deve essere davvero incorporabile e contenere azioni o dati utili all'attaccante.

```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

`ALLOW-FROM` è obsoleto e non deve essere usato. La direttiva moderna e più flessibile è:

```http
Content-Security-Policy: frame-ancestors 'none'
```

oppure:

```http
Content-Security-Policy: frame-ancestors 'self' https://trusted.example
```

### Come Verificare il Clickjacking

```bash
curl -skI "https://target.com/dashboard" | \
  grep -iE "x-frame-options|content-security-policy"
```

```bash
cat > clickjack_test.html <<'EOF_CLICKJACK'
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <style>
    iframe {
      opacity: 0.25;
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      z-index: 2;
    }
    button {
      position: absolute;
      top: 200px;
      left: 400px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <button>Azione esca</button>
  <iframe src="https://target.com/dashboard"></iframe>
</body>
</html>
EOF_CLICKJACK
```

Conferma il finding solo se:

```text
1. la pagina viene renderizzata nel frame;
2. la sessione della vittima resta utilizzabile nel frame;
3. esiste un'azione sensibile o un impatto dimostrabile;
4. eventuali cookie SameSite non bloccano lo scenario.
```

Per una difesa più solida invia entrambi:

```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none';" always;
```

Nota: il clickjacking spesso viaggia insieme a un'azione priva di protezione anti-CSRF (token mancante o controllato male) — vale la pena guardare anche quel lato: approfondimento su [CSRF](https://hackita.it/articoli/csrf).

***

## X-Content-Type-Options

```http
X-Content-Type-Options: nosniff
```

Dice al browser di fidarsi del `Content-Type` dichiarato, invece di provare a indovinare da solo un tipo eseguibile (il cosiddetto MIME sniffing).

### Come Testare X-Content-Type-Options

```bash
curl -skI "https://target.com/" | grep -i x-content-type-options
```

L'assenza dell'header non è automaticamente XSS. Serve anche una risorsa che l'utente può controllare, un `Content-Type` sbagliato e un contesto in cui il browser può leggerla come script o stile.

La difesa giusta unisce entrambe le cose:

```text
- Content-Type accurato per ogni risposta;
- X-Content-Type-Options: nosniff.
```

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

***

## Referrer-Policy

`Referrer-Policy` decide quali informazioni sull'URL corrente finiscono nell'header `Referer` quando navighi o carichi una risorsa.

Nei browser moderni il default è di solito `strict-origin-when-cross-origin`, ma conviene comunque dichiarare la policy in modo esplicito, così il comportamento resta prevedibile anche su client meno recenti.

```http
Referrer-Policy: strict-origin-when-cross-origin
```

```text
no-referrer                     → non invia il Referer
same-origin                     → lo invia solo verso la stessa origine
strict-origin                   → invia soltanto l'origine, senza downgrade HTTPS→HTTP
strict-origin-when-cross-origin → URL completo same-origin, sola origine cross-origin
unsafe-url                      → invia anche path e query; da evitare sui siti sensibili
```

### Come Analizzare la Referrer-Policy (Verifica di un Leak Reale)

```bash
curl -skI "https://target.com/" | grep -i referrer-policy
```

Nel browser:

```text
1. Apri una pagina contenente un token o identificatore nell'URL.
2. Controlla le richieste verso analytics, CDN, widget e domini esterni.
3. Verifica il valore effettivo del Referer inviato.
4. Determina se il valore esposto è ancora valido e utilizzabile.
```

Non inserire session ID, password, token di reset o altri segreti nella query string. Una Referrer-Policy restrittiva riduce il rischio, ma non ripara un'app che espone segreti negli URL.

Per pagine particolarmente sensibili puoi valutare:

```http
Referrer-Policy: no-referrer
```

Configurazione generale:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

***

## Permissions-Policy

`Permissions-Policy` limita quali funzionalità del browser — camera, microfono, geolocalizzazione, payment API — può usare la pagina principale e i frame che incorpora.

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

L'assenza dell'header non regala automaticamente l'accesso silenzioso a camera o microfono: restano validi i permessi del browser, il consenso dell'utente, il secure context e le altre policy. L'header serve però a ridurre cosa può fare uno script compromesso o un contenuto embedded.

### Come Verificare Permissions-Policy

```bash
curl -skI "https://target.com/" | grep -i permissions-policy
```

Imposta una policy basata su ciò che serve davvero:

```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
```

Non copiare una policy generica senza aver testato l'app: videoconferenze, mappe, pagamenti o iframe legittimi possono avere bisogno di permessi mirati.

***

## COOP, COEP e CORP

Gli header di cross-origin isolation separano il documento da contesti cross-origin e decidono quali risorse possono entrare nel suo processo:

```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-site
```

```text
COOP → separa il browsing context group da documenti cross-origin
COEP → richiede CORS o CORP per le risorse cross-origin incorporate
CORP → stabilisce quali origini possono includere una risorsa
```

Servono soprattutto quando l'app ha bisogno di **cross-origin isolation**, usa `SharedArrayBuffer` o gestisce scenari a rischio di cross-origin leak. Non sono obbligatori ovunque e su un'API consumata da client non-browser non hanno molto senso.

Controllare quali origini possono usare una risorsa è un'idea simile a una misconfigurazione CORS lato applicativo (header `Access-Control-Allow-Origin` troppo permissivo): approfondimento su [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration).

```bash
curl -skI "https://target.com/" | grep -iE \
  "cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy"
```

L'assenza di COOP/COEP non è già una vulnerabilità. Attivarli però può bloccare risorse di terze parti non configurate con CORS o CORP, quindi vanno progettati e testati con calma.

### Security Headers vs CORS: Qual È la Differenza?

Sono due cose spesso confuse. I security headers visti finora controllano cosa fa il browser (caricare risorse, incorporare la pagina, mandare il referrer, usare permessi); CORS invece decide quali origini possono **leggere** la risposta di una richiesta cross-origin, tramite `Access-Control-Allow-Origin` e header simili. In pratica: la CSP riguarda caricamento ed esecuzione lato client, CORS riguarda l'accesso ai dati lato server. Non si sostituiscono a vicenda — una CSP ben fatta non ripara un CORS permissivo, e viceversa. Approfondimento: [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration).

***

## X-XSS-Protection: Header Deprecato

`X-XSS-Protection` accendeva i vecchi filtri anti-XSS di Internet Explorer, Chrome e Safari. Oggi è deprecato, non protegge davvero e in certi casi storici poteva addirittura introdurre problemi.

OWASP consiglia di non impostarlo, o di disattivarlo esplicitamente:

```http
X-XSS-Protection: 0
```

```bash
curl -skI "https://target.com/" | grep -i x-xss-protection
```

Non segnalare `X-XSS-Protection: 1; mode=block` come una vulnerabilità grave. Trattalo come configurazione legacy, e verifica che la vera protezione contro XSS arrivi da encoding contestuale, sanitizzazione, Trusted Types dove possibile e una CSP solida.

***

## Cache-Control per Risposte Sensibili

`Cache-Control` non è solo un security header, ma diventa fondamentale quando una risposta contiene dati personali, token, documenti o informazioni autenticate.

Per impedire che venga salvata:

```http
Cache-Control: no-store
```

`no-cache` **non impedisce il caching**: la risposta viene comunque salvata, ma va rivalidata prima di riusarla. `private` blocca il salvataggio nelle cache condivise, ma non in quella del browser dell'utente.

```bash
curl -skI "https://target.com/dashboard" \
  -H "Cookie: session=VALID_SESSION" | grep -i cache-control
```

Valuta:

```text
- presenza di no-store sulle risposte realmente sensibili;
- caching da parte di CDN o proxy condivisi;
- direttive Vary e chiavi di cache;
- possibilità di recuperare dati dopo logout o da un altro utente;
- service worker o cache applicative che conservano contenuti riservati.
```

Configurazione indicativa:

```nginx
location /dashboard {
    add_header Cache-Control "no-store" always;
}
```

`Pragma: no-cache` è soprattutto un residuo di HTTP/1.0 e non sostituisce `Cache-Control`.

### Rischi Collegati: Cache Poisoning, Request Smuggling e Session Hijacking

Una cache mal configurata non è solo un problema di dati esposti: se il server o il reverse proxy trattano come "non parte della chiave" header che l'utente può controllare (`X-Forwarded-Host`, parametri non canonicalizzati), una risposta malevola può finire in cache e essere servita a tutti gli utenti dopo. Approfondimento dedicato: [Cache Poisoning: guida completa](https://hackita.it/articoli/cache-poisoning).

Se il target è dietro un reverse proxy/load balancer e front-end e back-end leggono in modo diverso `Content-Length`/`Transfer-Encoding`, il problema può allargarsi fino a **HTTP Request Smuggling** — bypass dei controlli di accesso e cache poisoning "a monte". Approfondimento: [HTTP Request Smuggling: guida completa](https://hackita.it/articoli/http-request-smuggling).

Infine, se un endpoint di sessione finisce cachato senza `no-store`, il rischio concreto è che il token venga servito a un altro utente: è lo stesso tipo di impatto di un classico [session hijacking](https://hackita.it/articoli/session-hijacking).

***

## Security Headers Scanner: Quali Tool Usare

Nessuno scanner sostituisce il controllo manuale, ma aiuta a fare una prima ricognizione veloce:

* **curl** — il modo più rapido per leggere gli header grezzi di un singolo endpoint, senza installare nulla (vedi comandi sopra).
* **SecurityHeaders.com** — un voto indicativo e una panoramica immediata; buono per il primo sguardo, non come report finale.
* **CSP Evaluator (Google)** — guarda solo la Content-Security-Policy: trova allowlist deboli, `unsafe-inline`/`unsafe-eval` e problemi di bypass già noti.
* **Burp Suite** — controlla gli header su ogni endpoint e risposta durante il pentest, non solo sulla homepage; indispensabile per confrontare pagine autenticate e non.
* **Nuclei** — scan automatico su larga scala con template dedicati agli header; utile per un primo triage, non per confermare l'impatto.

Per un singolo target basta curl. Per un'applicazione intera servono Burp (endpoint autenticati compresi) e uno scan Nuclei come rete di sicurezza.

***

## Come Testare Tutti gli Header in un Pentest

### Script Manuale con curl

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Uso: $0 target.com"
  exit 1
fi

HEADERS="$(curl -skIL --max-time 15 "https://$TARGET/")"
LOWER_HEADERS="$(printf '%s' "$HEADERS" | tr '[:upper:]' '[:lower:]')"

echo "=== Security Headers: $TARGET ==="
printf '%s\n' "$HEADERS" | grep -iE \
  "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin|x-xss-protection|cache-control" || true

echo
echo "=== Controlli di Presenza ==="
[[ "$LOWER_HEADERS" == *"strict-transport-security:"* ]] || echo "CHECK: HSTS assente sulla risposta HTTPS"
[[ "$LOWER_HEADERS" == *"content-security-policy:"* ]] || echo "CHECK: CSP assente"

if [[ "$LOWER_HEADERS" != *"x-frame-options:"* ]] && \
   [[ "$LOWER_HEADERS" != *"frame-ancestors"* ]]; then
  echo "CHECK: protezione anti-framing non rilevata"
fi

[[ "$LOWER_HEADERS" == *"x-content-type-options: nosniff"* ]] || echo "CHECK: nosniff non rilevato"
[[ "$LOWER_HEADERS" == *"referrer-policy:"* ]] || echo "CHECK: Referrer-Policy non dichiarata esplicitamente"
[[ "$LOWER_HEADERS" == *"permissions-policy:"* ]] || echo "CHECK: Permissions-Policy non dichiarata"

echo
echo "Nota: CHECK significa che serve analisi contestuale, non che esiste automaticamente una vulnerabilità."
```

### Come Verificare la CSP di un Sito

```text
1. Copia il valore completo di Content-Security-Policy.
2. Verifica se è enforced o soltanto Report-Only.
3. Controlla nonce, hash, strict-dynamic, unsafe-inline e unsafe-eval.
4. Mappa tutte le origini autorizzate da script-src e script-src-elem.
5. Cerca contenuti caricabili o controllabili sulle origini autorizzate.
6. Prova il comportamento nel browser e osserva la console CSP.
7. Usa Google CSP Evaluator come supporto, non come prova definitiva.
```

### Come Fare un Security Headers Scan con Nuclei

```bash
# Aggiorna prima template e binary
nuclei -update-templates

# I tag e i percorsi dei template possono cambiare tra release
nuclei -u https://target.com -tags headers -severity info,low,medium
```

Gli scanner trovano soprattutto assenze e pattern già noti. Non sostituiscono il controllo manuale dell'impatto, delle direttive duplicate, dei redirect e delle policy diverse tra endpoint.

### Come Fare un Security Headers Pentest con Burp Suite

A differenza di curl e Nuclei, Burp lavora endpoint per endpoint mentre navighi davvero l'applicazione:

```text
1. Naviga l'app con il Proxy attivo e lascia popolare la HTTP history.
2. Filtra per Content-Type text/html e confronta gli header di risposta tra pagine pubbliche e autenticate.
3. Usa Repeater per rigiocare una richiesta e osservare come cambiano gli header al variare di Host, Cookie o metodo.
4. Verifica se CSP/Cache-Control differiscono tra ambiente di staging e produzione, o tra endpoint dietro login e senza.
5. Salva le risposte con header mancanti in un progetto/nota per il report finale.
```

Il valore di Burp qui non è lo scan automatico, ma il confronto sistematico tra endpoint — cosa che a mano con curl richiederebbe troppo tempo.

***

## Security Headers Pentesting: Metodologia

Un approccio ripetibile per testare gli header durante un pentest:

1. **Enumerazione** — tira fuori tutti gli header di risposta su ogni endpoint importante, non solo sulla homepage.
2. **Analisi della configurazione** — confronta i valori con quelli attesi per quel tipo di risposta (pagina autenticata, API, redirect, risorsa statica).
3. **Individuazione delle misconfiguration** — segna cosa manca, i valori deboli (`unsafe-inline`, `max-age` basso, allowlist troppo larghe) e le differenze tra endpoint.
4. **Test manuale nel browser** — guarda cosa succede davvero (console CSP, iframe, redirect), non fermarti alla risposta di curl.
5. **Verifica dell'exploitability** — dimostra se il problema è davvero sfruttabile in quel contesto (serve un'injection? un'azione sensibile? un token esposto?).
6. **PoC** — costruisci una prova riproducibile solo dopo aver dimostrato l'impatto.
7. **Valutazione dell'impatto** — assegna la severità in base a cosa hai ottenuto, non alla sola assenza dell'header (vedi tabella più avanti).
8. **Reporting** — scrivi endpoint, header attuale, configurazione attesa, prerequisiti e PoC.

Questa sequenza evita l'errore più comune: segnalare ogni header mancante come finding critico senza aver dimostrato niente.

***

## Security Headers HTTP: Best Practice

```text
HTTPS
↓
HSTS
↓
CSP
↓
Anti-clickjacking (X-Frame-Options / frame-ancestors)
↓
X-Content-Type-Options
↓
Referrer-Policy
↓
Permissions-Policy
↓
Cache-Control
↓
COOP/COEP/CORP quando necessari
```

Non esiste una configurazione universale valida per tutti: la policy va adattata all'architettura del sito, alle risorse di terze parti, agli endpoint e al modello di minaccia dell'applicazione.

***

## Configurazione Nginx di Riferimento

Questa configurazione è un punto di partenza, non un blocco da copiare senza adattamento:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name target.com;

    # Attiva includeSubDomains/preload soltanto dopo una verifica completa
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Policy base senza script inline. Per una strict CSP reale,
    # genera nonce per-risposta nell'applicazione o usa hash mantenuti correttamente.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; upgrade-insecure-requests" always;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header X-XSS-Protection "0" always;

    # Opzionali: abilitali solo se l'applicazione richiede cross-origin isolation
    # e tutte le dipendenze cross-origin sono configurate correttamente.
    # add_header Cross-Origin-Opener-Policy "same-origin" always;
    # add_header Cross-Origin-Embedder-Policy "require-corp" always;
    # add_header Cross-Origin-Resource-Policy "same-site" always;
}
```

Per una CSP con nonce, la policy deve essere costruita nell'applicazione:

```http
Content-Security-Policy: script-src 'nonce-VALORE_CASUALE_PER_RISPOSTA' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
```

***

## Impatto nel Pentest: Come Reportare

La severità dipende da cosa riesci a dimostrare, non dal semplice fatto che l'header manchi.

| Condizione                     | Impatto da dimostrare                                         | Severità indicativa                     |
| ------------------------------ | ------------------------------------------------------------- | --------------------------------------- |
| CSP assente senza XSS          | Riduzione della defense in depth                              | Informational / Low                     |
| CSP permissiva senza injection | Policy debole, ma nessun exploit autonomo                     | Informational / Low                     |
| CSP aggirata insieme a XSS     | Esecuzione JavaScript nel contesto della vittima              | Severità della XSS risultante           |
| HSTS assente                   | SSL stripping nello scenario di prima visita o rete ostile    | Low / Medium secondo contesto           |
| Anti-framing assente           | Pagina incorporabile con azione sensibile                     | Medium; più alta solo con forte impatto |
| `nosniff` assente              | MIME confusion su contenuto controllabile                     | Low / Medium se riproducibile           |
| Referrer leak                  | Token o segreto valido inviato a terzi                        | Medium / High secondo il segreto        |
| Cache-Control errato           | Dati sensibili recuperabili da cache condivisa o altro utente | Medium / High                           |
| Permissions-Policy assente     | Nessun impatto autonomo senza abuso di feature                | Informational / Low                     |
| COOP/COEP assenti              | Nessuna vulnerabilità automatica                              | Contestuale                             |

Nel report includi sempre:

```text
- endpoint e risposta interessata;
- header attuale e configurazione attesa;
- prerequisiti dell'attacco;
- PoC riproducibile;
- browser e versione testati;
- impatto reale;
- remediation proporzionata.
```

***

## Errori Comuni nel Test dei Security Headers

1. Considerare ogni header mancante una vulnerabilità.
2. Testare solamente la homepage.
3. Confondere `no-cache` con `no-store`.
4. Considerare automaticamente `unsafe-inline` un bypass CSP.
5. Considerare ogni open redirect un bypass CSP.
6. Ignorare gli endpoint autenticati.
7. Fidarsi esclusivamente degli scanner automatici.
8. Non verificare il comportamento nel browser.
9. Non controllare redirect e risposta finale.
10. Non dimostrare l'impatto.

***

## Checklist

```text
RILEVAMENTO
☐ Redirect HTTP → HTTPS verificato
☐ HSTS presente sulla risposta HTTPS
☐ max-age e includeSubDomains valutati in base all'infrastruttura
☐ CSP enforced distinta da CSP Report-Only
☐ script-src/script-src-elem analizzati
☐ unsafe-inline, unsafe-eval, data: e wildcard verificati
☐ nonce o hash verificati per casualità, unicità e applicazione corretta
☐ Origini allowlistate controllate per JSONP, upload, gadget e contenuti utente
☐ frame-ancestors o X-Frame-Options presenti sulle pagine interattive
☐ Clickjacking verificato con sessione e azione sensibile
☐ X-Content-Type-Options: nosniff presente dove rilevante
☐ Content-Type delle risorse controllabili verificato
☐ Referrer-Policy esplicita e leak reali testati nel browser
☐ Permissions-Policy coerente con le feature necessarie
☐ COOP/COEP/CORP valutati solo se richiesti dall'architettura
☐ X-XSS-Protection assente o impostato a 0
☐ Cache-Control: no-store sulle risposte realmente sensibili

CSP
☐ Policy basata preferibilmente su nonce/hash anziché lunghe allowlist
☐ strict-dynamic valutato con attenzione
☐ object-src 'none'
☐ base-uri 'none' o 'self'
☐ frame-ancestors configurato
☐ form-action configurato
☐ Violazioni CSP controllate nella console browser
☐ Differenze tra endpoint, error page e redirect verificate

REPORTING
☐ Assenza dell'header separata dalla vulnerabilità sfruttabile
☐ PoC e impatto documentati
☐ Browser/versione annotati
☐ False positive di scanner esclusi
☐ Severità basata sul risultato dell'attacco
```

***

## FAQ

**CSP presente ma con `'unsafe-inline'`: va segnalato?**\
Va guardato con attenzione. In `script-src`, `'unsafe-inline'` permette script inline ed event handler e abbassa parecchio la protezione contro XSS. Non vuol dire però che tutte le altre direttive siano inutili. Segnala la policy come debole e alza la severità solo se dimostri un'injection sfruttabile o un bypass concreto.

**HSTS senza `preload` è una vulnerabilità?**\
Non da sola. HSTS protegge dopo che il browser ha già ricevuto la policy su HTTPS. Il preload toglie di mezzo il problema della prima visita, ma ha requisiti rigidi e non è adatto a ogni dominio. Valuta rischio, sottodomini coinvolti e se puoi mantenere HTTPS a lungo termine.

**Come verifico un possibile bypass JSONP?**\
Trova l'origine esatta che la CSP autorizza, cerca un endpoint che restituisce JavaScript con callback controllabile, controlla il `Content-Type` e prova a caricarlo nel browser. Una lista pubblica o un vecchio payload non bastano: l'endpoint deve essere ancora attivo e compatibile con la policy che stai osservando.

**Un open redirect su un dominio in allowlist bypassa la CSP?**\
Non da solo, verso qualsiasi dominio. Diventa utile in catene che finiscono su un'altra risorsa già autorizzata, o quando si combina con path e gadget presenti su origini consentite. Controlla sempre nel browser dove finisce davvero il redirect.

**`X-XSS-Protection: 1; mode=block` è ancora utile?**\
No, non come controllo moderno. È deprecato e i vecchi filtri potevano perfino creare problemi. Usa `X-XSS-Protection: 0` oppure omettilo, e affida la vera difesa a encoding contestuale, sanitizzazione e una CSP solida.

**Tutti gli header mancanti devono diventare finding separati?**\
No. Raggruppa le osservazioni senza impatto reale sotto hardening/informational. Crea un finding a parte solo quando c'è un attacco riproducibile, per esempio clickjacking su un'azione sensibile, un token valido finito a terzi o dati autenticati recuperabili da una cache condivisa.

**Quali sono i principali security headers HTTP?**\
I più importanti in un pentest sono CSP, HSTS, X-Frame-Options/`frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy e, per gli scenari cross-origin, COOP/COEP/CORP. Cache-Control a rigore non è un security header, ma va sempre controllato sulle risposte sensibili.

**Come verifico i security headers di un sito?**\
Il modo più veloce è `curl -skIL` sull'URL target con un grep sugli header che interessano (vedi lo script all'inizio dell'articolo). Per un quadro più completo aggiungi SecurityHeaders.com per un primo sguardo e Burp Suite per confrontare endpoint autenticati e non.

**Qual è il miglior security headers scanner?**\
Dipende da cosa ti serve: SecurityHeaders.com per un check veloce e leggibile, CSP Evaluator per guardare solo la CSP, Nuclei per uno scan su larga scala, Burp Suite quando devi controllare gli header endpoint per endpoint durante un pentest vero. Nessuno di questi sostituisce il controllo manuale dell'impatto.

**CSP e HSTS sono sufficienti per proteggere un sito?**\
No. Sono difese "in più strati" (defense in depth): non sostituiscono output encoding, sanitizzazione dell'input e una gestione sicura di sessioni e permessi. Una CSP permissiva o un HSTS senza preload lasciano comunque spazio a rischi che devono coprire gli altri controlli.

**Quali security headers controllare durante un penetration test?**\
Tutti quelli della checklist a inizio articolo, ma con priorità diverse a seconda del contesto: su una pagina interattiva con azioni sensibili contano di più CSP, anti-framing e Cache-Control; su un'API pura pesano soprattutto CORS (se esposta) e Cache-Control.

***

## Articoli Collegati su Hackita

* [XSS](https://hackita.it/articoli/xss)
* [Clickjacking](https://hackita.it/articoli/clickjacking)
* [Man-in-the-Middle](https://hackita.it/articoli/man-in-the-middle)
* [HTTP e HTTPS](https://hackita.it/articoli/http-https)
* [Attacchi alle Applicazioni Web](https://hackita.it/articoli/attacchi-applicazioni-web)
* [CORS Misconfiguration](https://hackita.it/articoli/cors-misconfiguration)
* [CSRF](https://hackita.it/articoli/csrf)
* [Open Redirect](https://hackita.it/articoli/open-redirect)
* [Cache Poisoning](https://hackita.it/articoli/cache-poisoning)
* [HTTP Request Smuggling](https://hackita.it/articoli/http-request-smuggling)
* [Session Hijacking](https://hackita.it/articoli/session-hijacking)

***

## Risorse Esterne

* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
* [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [Google — Strict CSP](https://web.dev/articles/strict-csp)
* [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* [Security Headers](https://securityheaders.com/)
* [ZipFlipBook — Come integrare un flipbook in WordPress](https://zipflipbook.com/blog/embed-flipbook-wordpress-guide)

***

> Un header presente non è necessariamente sicuro. Un header assente non è automaticamente una vulnerabilità. Conta la configurazione, il contesto e l'impatto dimostrato.
