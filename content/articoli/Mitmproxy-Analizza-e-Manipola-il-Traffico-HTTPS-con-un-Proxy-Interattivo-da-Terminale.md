---
title: >-
  Mitmproxy: Analizza e Manipola il Traffico HTTPS con un Proxy Interattivo da
  Terminale
slug: mitmproxy
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

# Mitmproxy: Analizza e Manipola il Traffico HTTPS con un Proxy Interattivo da Terminale

Se la tua app “non passa dal proxy” o l’HTTPS ti spara errori di certificato in HTB/PG, qui configuri mitmproxy (CA + filtri) e validi subito traffico e modifiche in modo ripetibile.

## Intro

mitmproxy è un proxy MITM interattivo che intercetta traffico HTTP/HTTPS e ti permette di ispezionarlo e modificarlo al volo.

In un lab/pentest autorizzato ti serve per capire cosa manda davvero un client (browser/app), scovare leakage (token, header, parametri), e verificare se le validazioni sono server-side o solo “cosmetiche” lato client.

Cosa farai in pratica:

* Configurare client e CA per vedere anche HTTPS.
* Filtrare e intercettare solo gli endpoint interessanti.
* Modificare richieste/risposte e salvare le sessioni per replay.
* Gestire i problemi tipici (niente traffico, cert error, pinning).

Nota etica: usa tutto solo su lab/CTF/HTB/PG/VM personali o sistemi con autorizzazione esplicita.

## Cos’è mitmproxy e dove si incastra nel workflow

> **In breve:** mitmproxy sta “in mezzo” tra client e server: vedi ogni request/response e puoi manipolarla per test controllati. È ideale quando vuoi osservabilità e tampering rapido, senza riscrivere l’app.

mitmproxy è più “chirurgico” dei MITM a livello rete: lavori su HTTP(S) con un’interfaccia interattiva (mitmproxy), una UI web (mitmweb) o una CLI stile tcpdump (mitmdump).

Quando lo usi davvero in un workflow offensivo da lab:

* Dopo una prima ricognizione: hai un endpoint/feature sospetta e vuoi capire parametri, token e flussi.
* Prima di automatizzare: catturi 1–2 sessioni pulite e poi le trasformi (replay/script).
* Quando il client fa cose “strane”: header custom, websocket, HTTP/2, redirect, caching.

Se invece il tuo scenario è MITM “di rete” (ARP spoofing, sniffing L2), spesso ha più senso partire da tool dedicati come **Bettercap** e poi usare mitmproxy per la parte HTTP(S): vedi “Bettercap: Il Coltellino Svizzero del Network Hacking” su HackIta: [Bettercap (MITM, sniffing e spoofing)](https://hackita.it/articoli/bettercap/).

## Installazione e quick sanity check (Kali/Linux)

> **In breve:** su Linux puoi usare binari ufficiali o pacchetti della distro (spesso più vecchi). Prima verifica che parta e che ascolti, poi fai un test HTTP semplice.

Prima regola operativa: se ti serve una feature recente, preferisci installazione ufficiale; se ti basta “farlo andare” in lab, va bene anche il pacchetto distro (sapendo che può laggare).

**Perché:** sapere “che versione ho” ti evita bug/flag che non esistono.
**Cosa aspettarti:** un output con versione e nessun errore di import/deps.

```bash
mitmproxy --version
```

Se vuoi una UI web (comoda per review rapida):

**Perché:** mitmweb ti dà navigazione e ricerca più comode per set di flow medi.
**Cosa aspettarti:** un servizio web locale e flussi che compaiono mentre navighi.

```bash
mitmweb
```

E sanity check “sto vedendo traffico?”:

**Perché:** isolare subito se il problema è “client non punta al proxy”.
**Cosa aspettarti:** eventi tipo `client connect` / nuove flow quando navighi.

```bash
mitmproxy
```

Errore comune + fix: “parte mitmproxy ma non vedo nulla” → prima ancora dei certificati, controlla che il client stia davvero usando `127.0.0.1:8080` (o IP della macchina proxy) e che firewall/isolamento Wi-Fi non blocchino.

## Setup proxy + CA: vedere HTTPS senza impazzire

> **In breve:** configuri il client per usare il proxy, poi installi la CA di mitmproxy: senza CA vedrai solo HTTP o errori TLS.

Il 90% dei “non funziona” è qui: o il client non usa il proxy, o l’HTTPS fallisce perché la CA non è trusted.

### Step 1 – Imposta il proxy nel client

**Perché:** mitmproxy in modalità “regular” è un proxy esplicito: il client deve puntarci.
**Cosa aspettarti:** già su HTTP puro dovresti vedere flow.

Esempio (variabile d’ambiente per tool CLI in lab):

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

Esempio di output (può variare):

```text
# nessun output: sono variabili d'ambiente nel processo corrente
```

Interpretazione: ora tool come `curl` useranno il proxy (nel terminale in cui hai esportato).

Errore comune + fix: “curl ignora il proxy” → verifica che non stai usando un alias che sovrascrive opzioni, e che non stai lanciando il comando in una shell diversa.

### Step 2 – Installa la CA (HTTPS)

**Perché:** mitmproxy genera certificati al volo e firma con la sua CA; il client deve fidarsi.
**Cosa aspettarti:** dopo l’installazione, HTTPS si apre senza warning (in lab).

Quick path comodo: apri dal client la pagina di onboarding e installa la CA (di solito passando dal dominio “magico” dell’onboarding). Se non riesci, installa manualmente la CA dal path locale.

Esempio manuale (CLI in lab, usando la CA generata in `~/.mitmproxy`):

```bash
curl --proxy 127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/
```

Esempio di output (può variare):

```html
<!doctype html>
<html>
<head><title>Example Domain</title></head>
<body>Example Domain</body>
</html>
```

Interpretazione: se vedi HTML senza errori TLS, CA e proxy stanno lavorando.

Errore comune + fix: “SSL certificate problem / unknown issuer” → la CA non è installata/trustata nel contesto giusto (browser store vs sistema vs app).

## Proxy modes che usi davvero (regular, local, reverse, upstream)

> **In breve:** inizia con “regular”; usa “local capture” se vuoi catturare app locali senza configurare proxy; “reverse” per mettere mitmproxy davanti a un server; “upstream” per catena di proxy.

### Regular (default) – il più robusto

**Perché:** la configurazione è semplice e prevedibile.
**Cosa aspettarti:** il proxy ascolta e vedi flow appena il client lo usa.

```bash
mitmproxy
```

Errore comune + fix: “il browser non passa dal proxy” → ricontrolla IP/porta e che non ci sia PAC/auto-config che sovrascrive.

### Local capture – quando l’app bypassa le proxy settings

**Perché:** alcune app ignorano le impostazioni di sistema e non passano dal proxy esplicito.
**Cosa aspettarti:** vedi traffico di processi locali senza configurare proxy dentro l’app.

```bash
mitmproxy --mode local
```

Interpretazione: utile in lab per catturare tool locali “testardi”, riducendo frizione.

Errore comune + fix: “non cattura nulla” → avvia prima mitmproxy, poi l’app, e verifica permessi/OS supportati.

### Reverse – “metto mitmproxy davanti al server”

**Perché:** perfetto per testare un backend specifico senza configurare ogni client in modo complicato.
**Cosa aspettarti:** mitmproxy ascolta localmente e inoltra al server target.

```bash
mitmproxy --mode reverse:https://example.com
```

Errore comune + fix: loop o host header strani → in reverse mode alcuni header vengono riscritti; se il backend è sensibile, devi ragionare su host header e routing.

### Upstream – “mitmproxy davanti a un altro proxy”

**Perché:** utile quando devi rispettare un proxy aziendale/lab e vuoi comunque ispezionare/alterare.
**Cosa aspettarti:** tutto passa da mitmproxy e poi va al proxy upstream.

```bash
mitmdump --mode upstream:http://127.0.0.1:8081
```

Errore comune + fix: auth upstream → se l’upstream richiede credenziali, devi configurarle nelle opzioni (altrimenti vedrai connect error).

Nota: se il tuo caso d’uso è “trasparente” con routing/ARP e senza configurare client, spesso è più complesso e fragile; in quei casi, strumenti L2 come [Ettercap](https://hackita.it/articoli/ettercap/) o Bettercap sono più adatti per portare il traffico “verso” il proxy in un lab controllato.

## Intercept & modifica on-the-fly: filtri, edit, replay rapido

> **In breve:** non intercettare tutto: filtra. Intercetta solo richieste su endpoint target e modifica header/body per verificare validazioni server-side.

### Intercetta solo ciò che ti interessa (flow filter)

**Perché:** intercettare tutto ti distrugge il tempo e rende il test ingestibile.
**Cosa aspettarti:** solo alcune richieste vanno in pausa (intercepted) e puoi editarle.

Nel TUI di mitmproxy (console), entra nel prompt comandi e imposta l’intercept su URL specifiche (esempio regex) e solo request:

```text
:set intercept "~u /api/v1/.* & ~q"
```

Esempio di output (può variare):

```text
Set intercept filter to "~u /api/v1/.* & ~q"
```

Interpretazione: ora mitmproxy mette in pausa solo le richieste che matchano quel pattern.

Errore comune + fix: “non intercetta nulla” → la regex non matcha davvero; prima usa un view filter più largo, poi stringi.

### Modifica rapida di header o parametri (validazione in lab)

**Perché:** vuoi capire se un controllo è server-side o solo UI.
**Cosa aspettarti:** cambi un campo e osservi status code, body, redirect, o differenze di contenuto.

Esempio operativo (concetto): intercetta una POST di login o un’API call e prova a:

* rimuovere un header di sicurezza che il client aggiunge,
* cambiare un parametro numerico (`id=1` → `id=2`) per validare IDOR in lab,
* modificare un claim/flag lato client (se presente) e verificare se il server lo accetta.

Segnali di detection: spike di `4xx/5xx`, pattern anomalo su endpoint sensibili, mismatch tra User-Agent e device reale, sequenze ripetute su risorse protette.
Hardening: enforce authorization server-side, rate limit, audit su endpoint, token binding dove possibile, e test automatici per param tampering.

### Salva flow per analisi e replay (mitmdump)

**Perché:** vuoi ripetibilità: catturo una sessione “pulita” e la riuso.
**Cosa aspettarti:** un file di flow salvato e riutilizzabile.

```bash
mitmdump -w lab_capture.mitm
```

Esempio di output (può variare):

```text
[08:41:12.123] Proxy server listening at http://127.0.0.1:8080
```

Interpretazione: ora tutto quello che passa nel proxy viene scritto nel file.

Errore comune + fix: “file vuoto” → non sta passando traffico nel proxy; torna a verificare config client.

Replay client-side (senza bindare la porta proxy):

**Perché:** replay di richieste registrate per vedere differenze e regression.
**Cosa aspettarti:** richieste ri-eseguite e nuove flow risultanti.

```bash
mitmdump -nC lab_capture.mitm
```

Errore comune + fix: replay che fallisce per token scaduti → cattura una sessione fresca o riduci la finestra del test.

## Casi d’uso offensivi da lab + validazione e mitigazioni

> **In breve:** mitmproxy è perfetto per testare auth, sessione, e integrità dei dati: osservi token/header e provi tampering controllato per verificare controlli server-side.

### 1) Token e sessione: dove nascono e dove “scappano”

Validazione in lab:

* intercetta chiamate dopo login e identifica dove passa il token (cookie vs header `Authorization`).
* verifica `Secure`, `HttpOnly`, `SameSite` e scadenze.
* prova logout e controlla se il token viene invalidato o resta valido.

Segnali di detection: accessi da IP insoliti, sessioni multiple, token reuse, user-agent inconsistente.
Hardening: rotation token, invalidazione logout, TTL brevi, refresh token sicuri, binding a device/claims e audit trail.

### 2) Param tampering: l’API si fida del client?

Validazione in lab:

* intercetta una request “sensibile” (es. update profilo) e modifica solo 1 parametro per volta.
* osserva se il server risponde con `200` o con `403/400` e se l’output cambia davvero.

Segnali di detection: serie di tentativi su ID incrementali, pattern di 403, anomalie su endpoint admin.
Hardening: authorization check per oggetto (ABAC/RBAC), validation strict, e logging su accessi negati.

### 3) WPAD/Proxy auto-config in LAN lab (attenzione)

In lab interno, alcune reti Windows possono scoprire proxy via WPAD: è un vettore classico per forzare traffico verso un proxy e catturare auth in ambienti deboli.

Validazione in lab:

* isola un segmento di rete di test,
* simula la discovery e osserva richieste WPAD/proxy,
* verifica se credenziali/hash vengono esposti in modo non atteso.

Segnali di detection: richieste DNS/LLMNR/NBT-NS “strane”, traffico WPAD, auth NTLM verso host non attesi.
Hardening: disabilitare WPAD dove non serve, bloccare LLMNR/NBT-NS, e monitorare comportamenti anomali. Approfondimento su HackIta: [Responder (LLMNR/NBT-NS/WPAD)](https://hackita.it/articoli/responder/).

## Errori comuni e troubleshooting (no traffic, cert error, pinning)

> **In breve:** risolvi in ordine: (1) il client arriva al proxy? (2) HTTPS: CA installata? (3) pinning o bypass delle proxy settings? (4) filtri troppo stretti?

### Caso 1: “Non vedo nessun traffico”

**Perché:** è quasi sempre routing/proxy settings, non mitmproxy.
**Cosa aspettarti:** se il client arriva, nel log vedrai `client connect`.

Fix rapido:

* prova prima con un HTTP non cifrato (per escludere CA).
* verifica che non ci sia “client isolation” sulla Wi-Fi.
* se sei su rete/VM, controlla NAT/bridged.

Per confermare che i pacchetti “esistono” davvero, puoi fare un check con un capture tool e poi tornare al layer HTTP. Vedi su HackIta: [tcpdump da terminale](https://hackita.it/articoli/tcpdump/).

### Caso 2: “HTTPS dà errori di certificato”

**Perché:** la CA non è trustata nello store giusto.
**Cosa aspettarti:** dopo trust corretto, niente warning e flow completi.

Fix rapido:

* installa la CA sul dispositivo/browser usato (non solo sul sistema).
* per app mobile: spesso serve store di sistema o una build debug (dipende dall’app).

### Caso 3: “Alcune app non si lasciano intercettare (pinning)”

**Perché:** il pinning blocca MITM anche se la CA è installata.
**Cosa aspettarti:** errori TLS nell’app o richieste che non compaiono.

Fix “pulito” in contesto autorizzato:

* usa build debug/config di test senza pinning,
* chiedi ai dev un toggle di pinning per ambienti di staging,
* se ti interessa solo “ripulire la vista”, usa filtri (view\_filter) o ignora domini non target.

### Caso 4: “Intercept continua a interrompermi”

**Perché:** hai intercettato troppo largo.
**Cosa aspettarti:** con filtri stretti lavori fluido.

Fix rapido:

* intercetta solo request (`~q`) e solo URL target (`~u`), combinati con `&`.

## Hardening & detection: come ridurre l’impatto del MITM in azienda

> **In breve:** lato difesa riduci superficie: pinning dove sensato, policy su store certificati, monitor su proxy non autorizzati, e logging su anomalie di sessione.

Hardening utile (reale) contro MITM:

* Cert pinning selettivo (soprattutto su app mobile) e gestione corretta delle eccezioni in debug/staging.
* mTLS per canali davvero critici (quando gestibile).
* Policy endpoint: impedire aggiunta di root CA non autorizzate e alert su modifiche allo store certificati.
* Monitor su egress: proxy non standard, porte anomale, o pattern di “proxy chaining”.

Detection pratica:

* alert su picchi di errori TLS e su user agent “impossibili”,
* correlazione su sessioni: riuso token da contesti diversi, geo/IP inconsistente,
* controllo integrity su PAC/WPAD e DNS anomalo in LAN.

Se devi fare analisi “di pacchetto” e vuoi anche decriptare TLS per confrontare flusso HTTP vs PCAP in un lab, la combo mitmproxy + Wireshark è una strada comune: su HackIta hai una base pronta in [Wireshark in azione](https://hackita.it/articoli/wireshark/).

## Scenario pratico: mitmproxy su una macchina HTB/PG

> **In breve:** configuri proxy locale, installi CA, intercetti solo un endpoint API e validi un tampering controllato con risultato osservabile.

Ambiente:

* Attacker VM (Kali): `10.10.10.10`
* Target lab web/app: `http://10.10.10.20` (fittizio)
* Obiettivo: intercettare una richiesta API e verificare che il server validi davvero i parametri (server-side).

**Perché:** vuoi un test ripetibile con 2–4 azioni, senza “rumore”.
**Cosa aspettarti:** flow visibili, un endpoint in pausa (intercepted), e una risposta diversa (es. 400/403) quando tamperi.

```bash
mitmproxy
```

Azione 2: imposta il browser (o il tool) per usare `127.0.0.1:8080`, poi visita una pagina HTTP e conferma che compaiono flow.

Azione 3: installa la CA (onboarding) e visita un endpoint HTTPS del lab (o un dominio di test), verificando che non ci siano errori TLS.

Azione 4: intercetta solo l’API target e modifica un parametro “innocuo ma controllabile” (es. un campo di ordinamento o un ID in un lab apposta).

Risultato atteso concreto:

* vedi la request in pausa,
* dopo la modifica ottieni un `400/403` se il server valida, oppure un `200` con comportamento cambiato (se il lab è vulnerabile).

Detection + hardening (in breve): logga tentativi ripetuti su endpoint sensibili, rate limit sugli ID incrementali, e authorization check per oggetto per bloccare tampering/IDOR.

## Playbook 10 minuti: mitmproxy in un lab

> **In breve:** in 5–8 step passi da “zero” a “intercept mirato + capture + replay”, senza perdere tempo su traffico inutile.

### Step 1 – Avvia mitmproxy e verifica che ascolti

```bash
mitmproxy
```

### Step 2 – Punta il client al proxy (browser o variabili env)

Imposta proxy su `127.0.0.1:8080` e visita un sito HTTP per confermare che arrivano flow.

### Step 3 – Abilita HTTPS installando la CA

Apri l’onboarding dal client e installa la CA nello store corretto (browser/sistema, a seconda del target).

### Step 4 – Restringi la vista ai flow utili (view filter)

Usa un filtro per vedere solo ciò che ti interessa (es. solo un host o un path) e ridurre rumore.

### Step 5 – Configura intercept selettivo su endpoint target

Imposta `set intercept` con un filtro URL e solo request (`~q`), così lavori senza interruzioni inutili.

### Step 6 – Salva una sessione pulita con mitmdump

```bash
mitmdump -w lab_capture.mitm
```

### Step 7 – Replay controllato per ripetibilità

```bash
mitmdump -nC lab_capture.mitm
```

## Checklist operativa

> **In breve:** se segui questa checklist, eviti il 90% dei fail (no traffic / cert / filtri / pinning).

* Hai verificato che il client punta davvero a `127.0.0.1:8080` (o IP della VM proxy).
* Prima hai testato HTTP non cifrato per escludere problemi TLS.
* Hai installato la CA nello store giusto (browser vs sistema vs app).
* Hai limitato la vista con un filtro invece di “guardare tutto”.
* Hai intercettato solo URL target e solo request (`~q`) per non bloccarti.
* Hai salvato una sessione “pulita” prima di fare tampering pesante.
* Hai annotato status code e differenze di response per ogni singolo test.
* Hai testato un parametro alla volta (tampering controllato).
* Hai verificato effetti server-side (non solo UI).
* Hai considerato pinning/bypass proxy settings se alcune app non generano flow.
* Hai logging/detection in mente (anche in lab) per capire cosa sarebbe visibile in produzione.

## Riassunto 80/20

> **In breve:** questi sono i 6 use-case che ti danno valore subito con pochissimi comandi.

| Obiettivo               | Azione pratica                                 | Comando/Strumento                    |
| ----------------------- | ---------------------------------------------- | ------------------------------------ |
| Vedere traffico HTTP(S) | Avvia proxy e punta il client                  | `mitmproxy`                          |
| HTTPS senza errori      | Installa CA / usa CA locale                    | `~/.mitmproxy/mitmproxy-ca-cert.pem` |
| Ridurre rumore          | Filtra vista e intercetta selettivo            | `set intercept` + filtri             |
| Tampering controllato   | Modifica 1 parametro/header e osserva risposta | TUI edit flow                        |
| Salvare sessione        | Registra flow su file                          | `mitmdump -w lab_capture.mitm`       |
| Ripetibilità            | Replay richieste registrate                    | `mitmdump -nC lab_capture.mitm`      |

## Concetti controintuitivi

> **In breve:** sono i trabocchetti che fanno perdere ore, anche a chi “sa usare i proxy”.

* **“Se vedo HTTP, allora anche HTTPS funzionerà”**
  No: senza CA trustata, HTTPS fallisce o resta “opaco”. Risolvi prima la CA, poi i filtri.
* **“Intercept tutto così non mi perdo nulla”**
  Ti autodossi: intercetta solo ciò che stai testando (URL + request) e usa view filter per il resto.
* **“Se l’app non passa dal proxy, è colpa di mitmproxy”**
  Spesso è bypass delle proxy settings o pinning. In lab serve un approccio dedicato (debug build/modalità adatta).
* **“Un 200 significa che il test è riuscito”**
  Non sempre: guarda il body e l’effetto reale. Un server può rispondere 200 ma ignorare i campi.

## FAQ

> **In breve:** risposte rapide ai problemi più frequenti in lab.

D: mitmproxy non vede traffico, ma il browser naviga. Perché?

R: Il browser probabilmente non sta usando il proxy (o un PAC lo sovrascrive). Verifica IP/porta e prova un HTTP semplice prima dell’HTTPS.

D: HTTPS dà “unknown issuer” anche dopo aver installato la CA.

R: La CA non è nello store giusto (browser vs sistema) o non è stata trustata correttamente. In lab, conferma con `curl --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem`.

D: Alcune richieste non compaiono, soprattutto da app mobile.

R: Molte app bypassano proxy settings o usano pinning. In contesto autorizzato, serve modalità adatta (es. local capture) o configurazione/staging senza pinning.

D: Posso salvare e rigiocare una sessione?

R: Sì: registra con `mitmdump -w file.mitm` e fai replay con `mitmdump -nC file.mitm`. Se i token scadono, cattura una sessione più fresca.

D: Qual è la differenza tra mitmproxy e mitmweb?

R: Stesso motore, interfacce diverse: TUI vs UI web. In lab, mitmweb è comodo per review e ricerca, mitmproxy è più “tastiera-driven”.

D: Quando NON usarlo?

R: Se ti serve sniffing L2 puro o traffico non HTTP(S), usa strumenti dedicati (pcap/IDS) e poi torna a mitmproxy quando ti serve manipolare HTTP(S).

## Link utili su HackIta.it

> **In breve:** tool “spoke/child” che si incastrano bene con mitmproxy (MITM, sniffing, troubleshooting e LAN abuse in lab).

* [Bettercap (MITM, sniffing e spoofing)](https://hackita.it/articoli/bettercap/)
* [Ettercap: intercettare e manipolare traffico di rete](https://hackita.it/articoli/ettercap/)
* [tcpdump: analizzare traffico da terminale](https://hackita.it/articoli/tcpdump/)
* [TShark: analizzare traffico da terminale](https://hackita.it/articoli/tshark/)
* [Wireshark: analisi traffico e credenziali in lab](https://hackita.it/articoli/wireshark/)
* [Responder: attacco LLMNR/NBT-NS/WPAD in LAN](https://hackita.it/articoli/responder/)

Pagine istituzionali:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** due fonti primarie per modalità e gestione certificati (le parti che “rompono” più spesso in lab).

* [mitmproxy Docs — Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/). (\[docs.mitmproxy.org]\[1])
* [mitmproxy Docs — Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/). (\[docs.mitmproxy.org]\[2])

## CTA finale HackIta

> **In breve:** se questo contenuto ti fa risparmiare tempo in lab, puoi supportare il progetto e accelerare la tua crescita.

Supporta HackIta: se vuoi che pubblichi più playbook e guide operative come questa, trovi il link qui: /supporto/

Formazione 1:1: se vuoi una roadmap pratica (HTB/PG/OffSec) e sessioni mirate sui tuoi blocker, trovi tutto su: /servizi/

Servizi per aziende/assessment: per security assessment e attività di testing in contesti autorizzati (web, AD, network), trovi i dettagli su: /servizi/

(1): [https://docs.mitmproxy.org/stable/concepts/modes/](https://docs.mitmproxy.org/stable/concepts/modes/) "Proxy Modes"
(2): [https://docs.mitmproxy.org/stable/concepts/certificates/?utm\_source=chatgpt.com](https://docs.mitmproxy.org/stable/concepts/certificates/?utm_source=chatgpt.com) "Certificates"
