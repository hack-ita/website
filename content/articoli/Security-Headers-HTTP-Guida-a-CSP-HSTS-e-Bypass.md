---
title: 'Security Headers HTTP: Guida a CSP, HSTS e Bypass'
slug: security-headers
description: 'Scopri come testare e configurare i security headers HTTP: CSP, HSTS, X-Frame-Options, Referrer-Policy e tecniche di bypass nei pentest web.'
image: /security-headers-http-hackita.webp
draft: true
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

Gli **HTTP security headers** sono direttive inviate dal server al browser per controllare il caricamento delle risorse, l'esecuzione degli script, l'embedding della pagina, l'uso esclusivo di HTTPS, la condivisione del referrer e l'accesso alle funzionalità del browser.

Quando sono assenti o configurati male possono aumentare l'impatto di vulnerabilità come [XSS](https://hackita.it/articoli/xss), [clickjacking](https://hackita.it/articoli/clickjacking), [MITM](https://hackita.it/articoli/man-in-the-middle) e leakage di token. La loro assenza, tuttavia, **non dimostra automaticamente una vulnerabilità sfruttabile**: un pentester deve sempre verificare il tipo di risposta, la funzionalità protetta e l'impatto concreto.

Anche gli header presenti devono essere analizzati. Una CSP basata su allowlist troppo ampie può essere aggirata tramite script gadget o endpoint controllabili presenti su un'origine autorizzata. La presenza di `'unsafe-inline'` in `script-src` riduce fortemente la protezione contro gli script inline, ma non annulla necessariamente tutte le altre direttive della policy.

OWASP include gli header mancanti o impostati su valori insicuri in **A02:2025 — Security Misconfiguration**.

***

## Come Testare in 30 Secondi

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

Un'API JSON, una risposta `204`, un redirect o una risorsa statica non richiedono necessariamente gli stessi header di una pagina autenticata con azioni sensibili.

***

## Content-Security-Policy (CSP)

La **Content Security Policy** limita le origini dalle quali il browser può caricare script, stili, immagini, font, frame e connessioni. È una misura di **defense in depth** contro XSS e content injection: non sostituisce output encoding, sanitizzazione, templating sicuro e validazione dell'input.

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

Una policy come questa consente script inline, event handler e URL JavaScript compatibili con il contesto:

```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

In presenza di una XSS che permette l'iniezione di markup, payload inline possono quindi essere eseguiti:

```html
<script>alert(document.domain)</script>
<img src=x onerror="alert(document.domain)">
```

Test rapido:

```bash
curl -skI "https://target.com/" | grep -i content-security-policy
```

Non classificare però automaticamente l'intera CSP come inesistente: direttive come `frame-ancestors`, `object-src`, `form-action`, `connect-src` e `base-uri` possono continuare a fornire protezione. Inoltre, nelle policy moderne basate su nonce o hash, il comportamento di `'unsafe-inline'` dipende dalla combinazione delle direttive e dal supporto CSP del browser.

### Debolezza 2 — Origini Allowlistate con JSONP o Contenuto Controllabile

Le CSP basate soltanto su host allowlist sono fragili quando un'origine autorizzata espone:

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

Il bypass è possibile soltanto se **l'origine esatta presente in `script-src`** espone realmente un endpoint utilizzabile e il contenuto restituito consente esecuzione JavaScript nel contesto testato. Endpoint pubblici e payload trovati online possono cambiare o essere rimossi: verifica sempre manualmente la risposta e non basarti su liste storiche senza conferma.

### Debolezza 3 — Script Gadget e Framework Legacy

Un'origine autorizzata può ospitare framework legacy o librerie che trasformano markup controllabile in esecuzione JavaScript. AngularJS 1.x è un esempio storico di **script gadget**, ma la fattibilità dipende da:

* versione effettivamente caricabile;
* sintassi e sandbox della versione;
* presenza di `unsafe-eval` o altre direttive;
* punto di injection disponibile;
* modalità CSP del framework;
* trasformazioni applicate dal sanitizer.

```http
Content-Security-Policy: script-src 'self' https://cdn-allowlisted.example
```

Durante il pentest non basta vedere il dominio del CDN: devi dimostrare che una libreria compatibile può essere caricata e che il gadget viene valutato nel DOM della pagina.

### Debolezza 4 — Redirect, Path e Origini Autorizzate

Un **open redirect non rende automaticamente autorizzata qualsiasi origine finale**. Il browser continua ad applicare la CSP alla catena di caricamento e alla destinazione effettiva.

I redirect diventano interessanti quando permettono di raggiungere, all'interno di origini già autorizzate, endpoint JSONP, file controllabili, path normalmente esclusi o altri script gadget. Verifica quindi:

```text
- origine iniziale e origine finale;
- path consentiti dalla source expression;
- numero e tipo di redirect;
- Content-Type della risposta finale;
- comportamento reale del browser, non soltanto quello di curl.
```

### Debolezza 5 — Nonce Prevedibile, Riusato o Copiato su Input Non Fidato

Un nonce deve essere crittograficamente casuale, diverso per ogni risposta e applicato soltanto agli script considerati affidabili.

```html
<!-- Esempio corretto: nonce generato per questa risposta -->
<script nonce="RANDOM_PER_RESPONSE">inizializzaApp()</script>
```

```http
Content-Security-Policy: script-src 'nonce-RANDOM_PER_RESPONSE' 'strict-dynamic'; object-src 'none'; base-uri 'none'
```

Problemi da cercare:

```text
- nonce identico tra richieste differenti;
- nonce derivato da timestamp o contatori prevedibili;
- nonce inserito automaticamente su ogni tag <script>, inclusi quelli iniettati;
- nonce esposto in un contesto che l'attaccante può leggere e riutilizzare;
- template che copiano attributi controllati dall'utente.
```

### CSP Consigliata

Una **strict CSP** basata su nonce o hash è generalmente più robusta di una lunga allowlist di host.

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

Il nonce deve essere generato dall'applicazione per ogni risposta; non può essere un valore statico scritto nella configurazione Nginx.

Per introdurre una policy senza rompere il sito, usa prima:

```http
Content-Security-Policy-Report-Only: ...
```

Raccogli le violazioni, correggi le dipendenze legittime e solo dopo passa alla policy enforced. `Report-Only` **non blocca** le risorse: serve per osservare e preparare il rollout.

***

## Strict-Transport-Security (HSTS)

HSTS comunica al browser che il dominio deve essere raggiunto esclusivamente tramite HTTPS. Dopo aver ricevuto l'header su una connessione HTTPS valida, il browser converte automaticamente le future richieste HTTP in HTTPS e impedisce all'utente di ignorare errori di certificato.

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

```text
max-age=31536000   → memorizza la policy per un anno
includeSubDomains  → estende HSTS ai sottodomini
preload            → dichiara l'intenzione di entrare nella preload list
```

### Cosa Verificare

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

Aggiungi `preload` soltanto dopo avere verificato i requisiti della preload list e la possibilità di mantenere HTTPS su dominio e sottodomini nel lungo periodo.

***

## X-Frame-Options e CSP `frame-ancestors`

Questi controlli determinano se una pagina può essere caricata in un frame. La loro assenza non dimostra da sola il clickjacking: la pagina deve essere realmente incorporabile e contenere azioni o informazioni utili all'attaccante.

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

### Test Pratico

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

Conferma il finding soltanto se:

```text
1. la pagina viene renderizzata nel frame;
2. la sessione della vittima resta utilizzabile nel frame;
3. esiste un'azione sensibile o un impatto dimostrabile;
4. eventuali cookie SameSite non bloccano lo scenario.
```

Per defense in depth puoi inviare entrambi:

```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none';" always;
```

***

## X-Content-Type-Options

```http
X-Content-Type-Options: nosniff
```

Indica al browser di rispettare il `Content-Type` dichiarato invece di tentare di dedurre un tipo eseguibile tramite MIME sniffing.

```bash
curl -skI "https://target.com/" | grep -i x-content-type-options
```

L'assenza dell'header non equivale automaticamente a XSS. L'impatto richiede normalmente una risorsa controllabile dall'utente, un `Content-Type` errato e un contesto in cui il browser possa interpretarla come script o stile.

La difesa corretta comprende entrambe le misure:

```text
- Content-Type accurato per ogni risposta;
- X-Content-Type-Options: nosniff.
```

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

***

## Referrer-Policy

`Referrer-Policy` controlla le informazioni dell'URL corrente inviate nell'header `Referer` durante la navigazione o il caricamento di risorse.

Nei browser moderni il default è generalmente `strict-origin-when-cross-origin`, ma è comunque opportuno dichiarare esplicitamente una policy per avere un comportamento prevedibile anche su client meno recenti.

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

### Verifica di un Leak Reale

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

Non inserire session ID, password, token di reset o segreti nella query string. Una Referrer-Policy restrittiva riduce il rischio, ma non corregge una progettazione che espone segreti negli URL.

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

`Permissions-Policy` limita l'uso di funzionalità del browser come camera, microfono, geolocalizzazione e payment API nella pagina principale e nei frame incorporati.

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

L'assenza dell'header non concede automaticamente l'accesso silenzioso a camera o microfono: continuano ad applicarsi permessi del browser, consenso dell'utente, secure context e altre policy. L'header riduce però la superficie disponibile a script compromessi e contenuti embedded.

```bash
curl -skI "https://target.com/" | grep -i permissions-policy
```

Imposta una policy basata sulle funzionalità realmente necessarie:

```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
```

Non copiare una policy generica senza testare l'applicazione: videoconferenze, mappe, pagamenti o iframe legittimi potrebbero richiedere autorizzazioni mirate.

***

## COOP, COEP e CORP

Gli header di cross-origin isolation possono separare il documento da contesti cross-origin e controllare quali risorse possono entrare nel suo processo:

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

Questi header sono importanti quando l'applicazione richiede **cross-origin isolation**, usa `SharedArrayBuffer` o gestisce scenari esposti a cross-origin leaks. Non sono obbligatori per ogni sito e non hanno normalmente senso su API consumate da client non browser.

```bash
curl -skI "https://target.com/" | grep -iE \
  "cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy"
```

L'assenza di COOP/COEP non dimostra da sola una vulnerabilità. La loro attivazione può inoltre bloccare risorse di terze parti non configurate con CORS o CORP, quindi va progettata e testata.

***

## X-XSS-Protection: Header Deprecato

`X-XSS-Protection` attivava i vecchi filtri anti-XSS di Internet Explorer, Chrome e Safari. È deprecato, non è una difesa moderna e in alcuni casi storici poteva introdurre comportamenti vulnerabili.

OWASP raccomanda di non impostarlo oppure di disabilitarlo esplicitamente:

```http
X-XSS-Protection: 0
```

```bash
curl -skI "https://target.com/" | grep -i x-xss-protection
```

Non segnalare la sola presenza di `X-XSS-Protection: 1; mode=block` come vulnerabilità grave. Indicala come configurazione legacy e verifica che la protezione reale contro XSS sia affidata a encoding contestuale, sanitizzazione, Trusted Types dove applicabile e una CSP robusta.

***

## Cache-Control per Risposte Sensibili

`Cache-Control` non è esclusivamente un security header, ma è fondamentale quando una risposta contiene dati personali, token, documenti o informazioni autenticate.

Per impedire la memorizzazione:

```http
Cache-Control: no-store
```

`no-cache` **non impedisce il caching**: permette di memorizzare la risposta, ma richiede la rivalidazione prima del riutilizzo. `private` impedisce la memorizzazione nelle cache condivise, ma consente quella nel browser dell'utente.

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

`Pragma: no-cache` è principalmente una misura legacy per HTTP/1.0 e non sostituisce `Cache-Control`.

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

### Analisi della CSP

```text
1. Copia il valore completo di Content-Security-Policy.
2. Verifica se è enforced o soltanto Report-Only.
3. Controlla nonce, hash, strict-dynamic, unsafe-inline e unsafe-eval.
4. Mappa tutte le origini autorizzate da script-src e script-src-elem.
5. Cerca contenuti caricabili o controllabili sulle origini autorizzate.
6. Prova il comportamento nel browser e osserva la console CSP.
7. Usa Google CSP Evaluator come supporto, non come prova definitiva.
```

### Nuclei e Scanner Automatici

```bash
# Aggiorna prima template e binary
nuclei -update-templates

# I tag e i percorsi dei template possono cambiare tra release
nuclei -u https://target.com -tags headers -severity info,low,medium
```

Gli scanner rilevano soprattutto assenza e pattern noti. Non sostituiscono la verifica manuale dell'impatto, delle direttive duplicate, dei redirect e delle policy differenti tra endpoint.

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

La severità dipende dall'attacco dimostrato, non dalla semplice assenza dell'header.

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
Va analizzato. In `script-src`, `'unsafe-inline'` può consentire script inline ed event handler e ridurre fortemente la mitigazione XSS. Non significa però che tutte le altre direttive siano inutili. Segnala la policy come debole e alza la severità soltanto se dimostri una injection sfruttabile o un bypass concreto.

**HSTS senza `preload` è una vulnerabilità?**\
Non automaticamente. HSTS protegge dopo che il browser ha ricevuto la policy su HTTPS. Il preload elimina il problema della prima visita, ma richiede requisiti operativi rigidi e non è adatto a ogni dominio. Valuta rischio, sottodomini e possibilità di mantenere HTTPS nel lungo periodo.

**Come verifico un possibile bypass JSONP?**\
Identifica l'origine esatta autorizzata dalla CSP, individua un endpoint che restituisce JavaScript con callback controllabile, verifica il `Content-Type` e prova il caricamento nel browser. Una lista pubblica o un payload storico non sono sufficienti: l'endpoint deve essere ancora attivo e compatibile con la policy osservata.

**Un open redirect su un dominio in allowlist bypassa la CSP?**\
Non da solo verso qualsiasi dominio. Può diventare utile in catene che terminano su un'altra risorsa già autorizzata o quando interagisce con restrizioni di path e gadget presenti su origini consentite. Verifica sempre la destinazione finale nel browser.

**`X-XSS-Protection: 1; mode=block` è ancora utile?**\
No come controllo moderno. È deprecato e i vecchi filtri potevano introdurre comportamenti indesiderati. Usa `X-XSS-Protection: 0` oppure ometti l'header e concentra la difesa su encoding contestuale, sanitizzazione e CSP.

**Tutti gli header mancanti devono diventare finding separati?**\
No. Raggruppa le osservazioni senza impatto come hardening o informational. Crea finding specifici quando esiste un attacco riproducibile, per esempio clickjacking su un'azione sensibile, leakage di un token valido o cache condivisa di dati autenticati.

***

## Risorse

* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
* [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [Google — Strict CSP](https://web.dev/articles/strict-csp)
* [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* [Security Headers](https://securityheaders.com/)

***

> Un header presente non è necessariamente sicuro. Un header assente non è automaticamente una vulnerabilità. Conta la configurazione, il contesto e l'impatto dimostrato.
