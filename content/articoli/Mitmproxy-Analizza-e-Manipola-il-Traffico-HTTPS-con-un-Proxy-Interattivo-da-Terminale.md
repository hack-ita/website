---
title: >-
  Mitmproxy: Analizza e Manipola il Traffico HTTPS con un Proxy Interattivo da
  Terminale
description: >-
  Mitmproxy è un proxy HTTP/HTTPS potente e interattivo per sniffare,
  ispezionare e modificare il traffico di rete direttamente da terminale. Ideale
  per penetration tester, sviluppatori e ethical hacker che vogliono capire cosa
  passa davvero nei pacchetti.
image: /mitmproxu.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - mitmproxy
  - mitm
  - ''
---

# mitmproxy: guida pratica per intercettare HTTP/HTTPS in lab

mitmproxy è un **intercepting proxy** capace di gestire **SSL/TLS**: ti permette di vedere, filtrare, modificare e riprodurre traffico web (HTTP/1, HTTP/2, WebSockets) tra client e server.
In lab è perfetto per capire cosa manda davvero un’app, debuggare API, analizzare autenticazione/sessioni e fare security testing **solo su target autorizzati**.

Obiettivo della guida: avvio, configurazione del client, installazione certificato, filtri “utili”, salvataggio/replay dei flow e automazione con un addon Python.

> Nota etica: usa mitmproxy **solo** su traffico tuo (browser/app/VM) o su ambienti dove hai permesso esplicito (lab, test interni autorizzati).

***

## Cos’è mitmproxy (in pratica)

Pensalo come un proxy “in mezzo”:

* il **client** parla col **proxy**
* il **proxy** parla col **server**
* tu puoi osservare/modificare i **flow** (request/response)

Quando c’è HTTPS/TLS, mitmproxy genera certificati al volo: per decifrare devi far sì che il client si fidi della **CA** di mitmproxy.

***

## I 3 strumenti: mitmproxy, mitmweb, mitmdump

Stesso motore, cambia l’interfaccia:

* **mitmproxy**: console interattiva (manuale, veloce).
* **mitmweb**: interfaccia web (comoda per visualizzare e cliccare).
* **mitmdump**: CLI “secca” (ottima per log, pipeline, automazione). È spesso descritta come “tcpdump per HTTP”.

***

## Setup rapidissimo in lab (proxy esplicito)

Di default mitmproxy ascolta su `127.0.0.1:8080`. In lab, la strada più pulita è sempre **proxy esplicito**: configuri il client (browser/app) per usare quel proxy.

Install su Kali:

```bash
sudo apt update
sudo apt install mitmproxy
```

Avvio base:

```bash
mitmproxy
```

Cambiare porta (esempio):

```bash
mitmproxy -p 2139
```

***

## HTTPS: certificato, “mitm dot it” e perché vedi errori

Per leggere HTTPS in chiaro devi installare la **CA di mitmproxy** nel trust store del device/browser. Il metodo più semplice è usare la pagina di onboarding **mitm dot it** (scritta così apposta per evitare link nel tuo editor).

Procedura “easy” (solo device tuo / lab):

1. avvia mitmproxy
2. imposta il proxy nel client (HTTP e HTTPS)
3. apri il browser del client e vai su **mitm dot it** per scaricare la CA adatta al sistema
4. installa e abilita la fiducia per la CA

Dove vive la CA dopo il primo avvio (Linux):

* cartella: `~/.mitmproxy`

### Certificate pinning (spiegato semplice)

Alcune app rifiutano certificati “non attesi” anche se la CA è installata (pinning). In quel caso l’intercettazione fallisce: è una protezione voluta.
Soluzione pratica in lab: **escludi** quel dominio/host che “rompe” e tieni pulito il resto del traffico.

Esempio (ignorare host con regex su `host:port`):

```bash
mitmproxy --ignore-hosts 'example\.com:443'
```

***

## Proxy modes: quale usare e quando

Scegliere la mode giusta ti evita il 90% dei problemi. Per iniziare usa sempre la modalità **regular** (default), cioè proxy esplicito.

* **Regular (default)**: il client è configurato per usare il proxy.
* **Reverse**: metti mitmproxy “davanti” a un server.
* **Transparent**: richiede redirezioni a livello rete (da usare solo in lab controllati, e solo se sai esattamente cosa stai facendo).

Esempio reverse (concetto da doc, utile in test specifici):

```bash
mitmproxy --mode reverse:https://example.com
```

***

## Filtri: come non annegare in 10.000 richieste

Il superpotere di mitmproxy sono le **filter expressions**: ti concentri solo su dominio, metodo, path, status, ecc.
Regola da lab: **filtra sempre** prima per dominio o endpoint, altrimenti sprechi tempo.

Esempi con `view_filter`:

```bash
mitmproxy --set view_filter="~u example.com"
mitmproxy --set view_filter="~m POST"
mitmproxy --set view_filter="~u /api/ & ~m POST"
```

Operatori utili:

* `&` = AND (devono essere vere entrambe)
* `|` = OR (basta una)

Reset del filtro (mostra tutto):

```bash
mitmproxy --set view_filter=""
```

***

## Salvare e fare replay: debugging serio senza rifare tutto a mano

Quando devi ripetere un test (API, auth, bug), salvare i flow è oro. mitmproxy supporta replay lato client (rimandi richieste) e replay lato server (rispondi con risposte salvate), a seconda del caso d’uso.

Registrare una sessione con mitmdump:

```bash
mitmdump -w lab-session
```

Poi apri la sessione in mitmproxy/mitmweb e fai replay dei flow che ti interessano (workflow tipico: selezioni → replay → confronti output).

***

## Automazione con addon Python (semplice ma “da pro”)

Gli addon reagiscono a eventi (request/response) e possono loggare, bloccare o riscrivere traffico al volo.
Se vuoi ripetibilità in lab, un addon piccolo ti fa risparmiare una marea di tempo.

Esempio minimale: loggare metodo + URL (non distruttivo).

```python
# save as hackita_log.py
from mitmproxy import http

class HackitaLog:
    def request(self, flow: http.HTTPFlow):
        print(f"{flow.request.method} {flow.request.pretty_url}")

addons = [HackitaLog()]
```

Run:

```bash
mitmdump -s hackita_log.py
```

***

## mitmproxy vs Burp Suite / ZAP / Wireshark (quando conviene cosa)

Scelta rapida da lab:

* Vuoi modificare request/response e lavorare “web-first” → **mitmproxy/mitmweb** (oppure Burp/ZAP se vuoi GUI e tool dedicati).
* Vuoi pipeline e automazione → **mitmdump + addon**.
* Vuoi analisi a livello pacchetto (frame, handshake, low-level) → **Wireshark/tcpdump**.

mitmproxy lavora ad alto livello (HTTP/TLS), Wireshark guarda pacchetti.

***

## Mini-playbook step-by-step (zero casino, subito utile)

Questo è il flusso “standard” per intercettare traffico **tuo** in lab:

**Step 1 — Avvia**

```bash
mitmproxy
```

**Step 2 — Configura il client**
Imposta proxy HTTP/HTTPS a `127.0.0.1:8080` (oppure IP della tua VM + porta).

**Step 3 — HTTPS ok**
Dal client apri **mitm dot it** e installa la CA (solo device tuo/lab).

**Step 4 — Fai focus (filtro)**

```bash
mitmproxy --set view_filter="~u /api/ & ~m POST"
```

**Step 5 — Modifica (manuale)**
Intercetta solo quello che ti serve e cambia header/body per vedere l’effetto lato server.

**Step 6 — Salva per ripetere**

```bash
mitmdump -w lab-session
```

***

## Checklist pratica (lab / esami / lavoro)

* Sto lavorando solo su traffico mio o su target autorizzato (lab/test interni consentiti).
* mitmproxy è avviato e so su che porta ascolta (default 8080).
* Il client passa davvero nel proxy (se “mitm dot it” non si apre, il traffico non sta passando).
* Ho installato la CA (altrimenti HTTPS fallisce o resta cifrato).
* Ho un `view_filter` per dominio/endpoint prima di analizzare.
* Se un’app “rompe”, valuto pinning e/o `--ignore-hosts` per non sporcare tutto.
* Se devo ripetere un test, salvo i flow con `-w`.

***

## Promemoria 80/20

| Obiettivo                | Azione pratica            | Comando/Strumento         |
| ------------------------ | ------------------------- | ------------------------- |
| Avviare subito           | start proxy default       | `mitmproxy`               |
| Rendere HTTPS leggibile  | install CA dal client     | onboarding “mitm dot it”  |
| Non annegare nel rumore  | filtra per dominio/metodo | `--set view_filter="..."` |
| Escludere roba che rompe | ignora host problematici  | `--ignore-hosts 'regex'`  |
| Salvare sessione         | registra flows            | `mitmdump -w lab-session` |
| Automatizzare            | addon Python              | `mitmdump -s addon.py`    |

***

## Concetti controintuitivi (minimo 3)

1. **“Vedo HTTP ma non HTTPS”**
   Quasi sempre manca la CA: senza fiducia, il client blocca o segnala errori TLS.
2. **“Una singola app non funziona con mitmproxy”**
   Spesso è pinning: l’app rifiuta certificati generati dal proxy. In lab, escludi quel traffico o usa build/debug controllate.
3. **“Ho messo un filtro ma non vedo nulla”**
   Di solito il client non sta passando nel proxy oppure il filtro è troppo stretto. Primo check: onboarding “mitm dot it”.
4. **“Scelgo una mode a caso e mi esplode tutto”**
   Le mode servono a scenari diversi: per iniziare e per il 90% dei lab, **regular** è quella giusta.

***

## FAQ su mitmproxy

**mitmproxy è legale?**
Sì, se lo usi su traffico tuo o su sistemi dove hai autorizzazione esplicita. Su terzi senza consenso no.

**Che differenza c’è tra mitmproxy e mitmdump?**
Stesso motore: mitmproxy è interattivo, mitmdump è CLI per log/automation.

**Cos’è il `view_filter`?**
È un filtro basato su filter expressions che riduce ciò che vedi a schermo (es. solo POST, solo `/api/`, solo un dominio).

**Cosa faccio se un’app ha pinning?**
Aspettati errori: è una protezione. In pratica, in lab spesso conviene escludere quel dominio/traffico o usare un contesto dove puoi gestire la fiducia (debug build).

**Qual è un comando “salvavita” per partire?**

```bash
mitmproxy --set view_filter="~u /api/ & ~m POST"
```

***

## Supporta HackITA e servizi

Se questa guida ti è stata utile, puoi supportarci dalla pagina **Supporta**: ci aiuta a tenere il progetto vivo e a pubblicare più contenuti pratici.

Se invece sei bloccato o vuoi accelerare sul serio:

* facciamo **formazione 1:1** (lab, OSCP-style, web testing, analisi traffico, workflow e tool).
* se hai un’**azienda** o un progetto, possiamo fare lavori su misura (assessment, hardening, review, troubleshooting e consulenze tecniche), sempre con autorizzazione e in regola.
