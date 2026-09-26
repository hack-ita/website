---
title: 'Mitmproxy: Intercettare e Analizzare Traffico HTTP/HTTPS'
slug: mitmproxy
description: 'Guida pratica a mitmproxy: configura il proxy, intercetta HTTPS, installa la CA, filtra e modifica i flow, salva sessioni e risolvi i problemi comuni.'
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
  - HTTPS
  - Proxy
  - API Security
  - Traffic Analysis
---

# Mitmproxy: Intercettare e Manipolare Traffico HTTP/HTTPS da Terminale

mitmproxy è un proxy interattivo che si posiziona tra client e server per intercettare, ispezionare e modificare traffico HTTP e HTTPS in tempo reale. Permette di analizzare cosa manda davvero un'applicazione, scovare token e header nascosti, verificare se le validazioni sono realmente server-side o solo cosmetiche lato client, e salvare sessioni per replay successivi.

In un workflow di lab/pentest autorizzato su HTB, PG o ambienti di staging, mitmproxy entra tipicamente dopo una prima ricognizione: hai un endpoint o una feature sospetta e vuoi capire flussi, parametri e comportamento reale prima di automatizzare.

Il progetto include tre interfacce sullo stesso motore: **mitmproxy** (TUI interattiva da terminale), **mitmweb** (UI web), **mitmdump** (CLI stile tcpdump, ideale per automazione e scripting).

## Cos'è mitmproxy e come funziona

Quando configuri il client per usare mitmproxy come proxy, ogni richiesta HTTP o HTTPS passa attraverso il proxy prima di raggiungere il server. mitmproxy presenta un certificato firmato con la propria CA — che dev'essere installata nel client — così da "aprire" TLS sul tratto client→proxy e ricostruirlo sul tratto proxy→server. Il risultato è accesso completo al traffico in chiaro, anche se la connessione originale usa HTTPS.

Questo lo rende diverso da uno sniffer di rete come [tcpdump](https://hackita.it/articoli/tcpdump/) o [TShark](https://hackita.it/articoli/tshark/), che catturano pacchetti ma non vedono il contenuto TLS senza le chiavi di sessione. Se invece hai bisogno di MITM a livello di rete (ARP spoofing, spoofing L2 per forzare traffico verso il proxy), strumenti come [Bettercap](https://hackita.it/articoli/bettercap/) o [Ettercap](https://hackita.it/articoli/ettercap/) si occupano del layer inferiore — mitmproxy lavora sulla parte HTTP/HTTPS.

## Installazione e sanity check su Kali Linux

Su Kali e sulla maggior parte delle distro Linux:

```bash
sudo apt update && sudo apt install -y mitmproxy
```

Per una versione più recente, usa i binari ufficiali da [mitmproxy.org](https://mitmproxy.org/). Prima di qualunque altra cosa, verifica versione e partenza:

```bash
mitmproxy --version
```

Avvia la TUI interattiva:

```bash
mitmproxy
```

Avvia la UI web (comoda per review e ricerca su set di flow medi):

```bash
mitmweb
```

Prima ancora dei certificati, verifica che il client stia davvero usando `127.0.0.1:8080` come proxy: il problema più comune non è la CA, ma che il traffico non arriva mai al proxy. Appena un client si connette, nel log vedrai `client connect` — se non compare, il routing è sbagliato, non mitmproxy.

## Setup proxy e CA: vedere HTTPS senza errori

Configurare il client e installare la CA sono i due passi che sblocano la maggior parte dei blocchi. Senza CA trustata vedrai solo HTTP o errori TLS.

### Step 1 – Imposta il proxy nel client

Per tool CLI in lab, le variabili d'ambiente sono il modo più rapido:

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

Questi valori valgono solo nel terminale in cui li esporti. Se usi un altro terminale o lanci il comando con sudo, il proxy non verrà ereditato. Per browser, configura la proxy manuale nelle impostazioni di rete su `127.0.0.1:8080`.

### Step 2 – Installa la CA per intercettare HTTPS

mitmproxy genera la propria CA al primo avvio e la salva in `~/.mitmproxy/`. Per installare la CA nei vari contesti:

**Browser (Firefox/Chrome):** apri con il browser la pagina speciale `http://mitm.it` (funziona solo se il browser usa già il proxy) per scaricare e installare il certificato guidato.

**Sistema Linux (es. Kali):** copia il certificato nel trust store del sistema e aggiornalo.

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

**Tool CLI specifico (senza installare CA a livello sistema):** usa `--cacert` per indicare la CA solo a quella singola esecuzione — non installa nulla nel sistema, vale solo per quel comando:

```bash
curl --proxy 127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/
```

Se l'output è HTML senza errori TLS, CA e proxy funzionano correttamente insieme.

Nota: Wireshark può aprire un PCAP del traffico, ma non decifra automaticamente le sessioni TLS solo perché il traffico è passato da mitmproxy — senza le chiavi di sessione (log SSLKEYLOGFILE) rimane opaco anche in un file pcap.

## Proxy modes: quale usare e quando

### Regular (default) — proxy esplicito

Il client deve configurare mitmproxy come proxy. È il modo più stabile e prevedibile:

```bash
mitmproxy
```

Errore comune: il browser non usa il proxy perché un file PAC o auto-config lo sovrascrive. Controlla nelle impostazioni del browser che non ci sia una configurazione automatica attiva.

### Local capture — cattura app che bypassano le proxy settings

Alcune app ignorano le impostazioni proxy di sistema. La modalità local capture intercetta le connessioni a livello sistema tramite reindirizzamento senza richiedere configurazione esplicita nell'app:

```bash
mitmproxy --mode local
```

Utile per tool locali che non si lasciano configurare facilmente. Avvia prima mitmproxy, poi l'applicazione da catturare. Il supporto dipende dall'OS: funziona bene su Linux, può richiedere configurazione aggiuntiva su macOS.

### Reverse — mitmproxy davanti a un server specifico

mitmproxy ascolta localmente e inoltra tutto verso un server target. Il client punta a mitmproxy invece che al server reale:

```bash
mitmproxy --mode reverse:https://example.com
```

Utile per testare un backend senza riconfigurare ogni singolo client. Attenzione all'header `Host`: in reverse mode mitmproxy riscrive l'Host in base alla destinazione, il che può creare comportamenti inattesi su backend che lo validano rigorosamente — verifica il comportamento del tuo target specifico.

### Upstream — mitmproxy in catena con un altro proxy

Tutto passa prima da mitmproxy e poi a un proxy upstream (es. un proxy aziendale o di lab):

```bash
mitmdump --mode upstream:http://127.0.0.1:8081
```

Se l'upstream richiede autenticazione, configurala nelle opzioni di mitmproxy altrimenti vedrai errori di connessione.

## View filter e intercept filter: la differenza che conta

Sono due meccanismi distinti e spesso confusi:

**View filter**: filtra quali flow *vengono mostrati* nell'interfaccia. Non influisce sul traffico che passa — il proxy intercetta tutto, ma mostra solo ciò che corrisponde al filtro. Si imposta con `f` nel TUI o con `--view-filter` da riga di comando.

**Intercept filter**: mette in *pausa* i flow che corrispondono al filtro, bloccando la richiesta finché non interagisci manualmente. Si imposta con `i` nel TUI o con `--intercept`. Intercettare tutto è quasi sempre controproducente: blocchi risorse statiche, health check, analytics — e perdi tempo su traffico irrilevante.

Esempio di intercept filter nel TUI — metti in pausa solo le POST verso endpoint API, lasciando passare il resto:

```text
:set intercept "~u /api/v1/.* & ~q"
```

La sintassi dei filtri mitmproxy:

* `~u` — match sull'URL
* `~q` — solo richieste (request)
* `~s` — solo risposte (response)
* `~m POST` — solo metodo POST
* `~h Cookie` — match su header
* `&` / `|` / `!` — AND, OR, NOT

Combinazione tipica in lab: view filter largo per avere visibilità, intercept filter stretto per agire su quello che ti interessa.

## Intercettare e modificare richieste al volo

Una volta che una richiesta è in pausa (intercepted), nel TUI puoi selezionarla, premere `e` per editarla, modificare header, parametri o body, e poi `a` per riprendere il flusso. Questo è il workflow base per verificare se un controllo è realmente server-side:

* Rimuovi un header di sicurezza che il client aggiunge e osserva se il server risponde lo stesso
* Cambia un parametro numerico (`id=1` → `id=2`) per testare IDOR
* Modifica un flag o un claim nel body della richiesta e verifica se il server lo accetta

Un `200` non significa necessariamente che il test "sia riuscito": guarda sempre il body e l'effetto reale sulla risposta — un server può rispondere 200 ignorando silenziosamente i campi modificati.

## Salvare sessioni e replay

Registra tutto quello che passa nel proxy su file:

```bash
mitmdump -w lab_capture.mitm
```

Rileggi il file in modo interattivo:

```bash
mitmdump -r lab_capture.mitm
```

Replay delle richieste registrate (senza avviare un proxy in ascolto):

```bash
mitmdump -nC lab_capture.mitm
```

Il replay è utile per ripetere un test senza dover ricreare manualmente la sessione, ma attenzione ai token scaduti: se la sessione originale è troppo vecchia, il server risponderà con 401/403. In quel caso, cattura una sessione fresca e usa quella.

## Casi d'uso in lab: cosa validare e come

### Token e sessione

Intercetta le chiamate post-login e traccia dove passa il token (cookie vs header `Authorization`). Verifica gli attributi del cookie (`Secure`, `HttpOnly`, `SameSite`) e la scadenza. Poi testa logout: il token viene realmente invalidato server-side, o continua a funzionare? Un token che non viene invalidato al logout è una vulnerabilità reale, non solo teorica.

### Param tampering e IDOR

Intercetta una richiesta sensibile (update profilo, cambio email, accesso a risorsa) e modifica un parametro alla volta. Se il server risponde 200 accettando parametri che non dovrebbe — ID di altri utenti, ruoli elevati, campi readonly — stai documentando un finding concreto.

### Verifica validazioni server-side vs client-side

Molte applicazioni eseguono validazioni in JavaScript lato client (formato email, lunghezza password, campi obbligatori) che il server non ripete. mitmproxy ti permette di inviare dati che il client non avrebbe mai trasmesso, verificando se il backend si fida ciecamente dell'input.

Segnali di detection: picchi di 4xx/5xx, pattern anomali su endpoint sensibili, serie di richieste su ID incrementali, user-agent inconsistente rispetto alla sessione.

Hardening: enforce dell'authorization server-side, rate limit, audit su accessi negati, token binding, validation strict lato server indipendente dal client.

### WPAD e proxy auto-discovery in lab

In reti Windows, alcuni client tentano di scoprire automaticamente un proxy via WPAD. Questo può forzare traffico verso un proxy non autorizzato e potenzialmente esporre autenticazioni NTLM — vettore classico abbinato a tool come [Responder](https://hackita.it/articoli/responder/). mitmproxy può ricevere quel traffico se si posiziona come destinazione WPAD in un lab controllato, ma la parte di avvelenamento DNS/LLMNR che porta il traffico lì è gestita da strumenti diversi.

Hardening: disabilitare WPAD dove non serve, bloccare LLMNR/NBT-NS, monitorare richieste DNS verso `wpad` e autenticazioni NTLM verso host insoliti.

## Troubleshooting: no traffic, cert error, pinning

### Nessun traffico visibile

Prima escludi i problemi TLS testando un endpoint HTTP puro. Se funziona, il problema è la CA. Se non funziona nemmeno l'HTTP, il client non sta usando il proxy: verifica IP/porta, assenza di configurazioni PAC che sovrascrivono le proxy settings, e che non ci sia client isolation sulla rete Wi-Fi di lab.

### Errori di certificato HTTPS

La CA non è nello store corretto. Distingui: store del browser (Firefox ha il proprio, separato dal sistema), store del sistema operativo, store specifico dell'applicazione. Installa la CA nel contesto esatto usato dall'applicazione che stai testando. `curl --cacert` vale solo per quell'esecuzione, non modifica il sistema.

### App mobile o app che bypassa proxy settings

Molte app mobile bypassano le proxy settings di sistema o implementano certificate pinning, che blocca il MITM anche con CA installata. Le opzioni in un contesto autorizzato sono: usare una build debug/staging senza pinning, richiedere agli sviluppatori un toggle di pinning per l'ambiente di test, o usare la modalità `--mode local` di mitmproxy per catturare a livello più basso. Non cercare di bypassare il pinning su app di produzione senza autorizzazione esplicita.

### HTTP/3 e QUIC

mitmproxy supporta HTTP/1, HTTP/2 e WebSocket. HTTP/3 (su QUIC/UDP) ha supporto limitato o assente nelle versioni attuali — verifica la documentazione della versione specifica che stai usando. Se il client usa HTTP/3 e vuoi forzarlo su HTTP/2 o HTTP/1 per l'intercettazione, puoi bloccare UDP verso la porta 443 per disabilitare QUIC lato client.

### Intercept che blocca tutto

Hai un intercept filter troppo largo. Stringilo: usa `~u` per URL specifiche, `~q` solo per request, `~m POST` solo per certi metodi. Usa il view filter per vedere il traffico senza fermarlo, e l'intercept solo quando sei pronto ad agire manualmente.

## Hardening contro proxy MITM

* **Certificate pinning** selettivo sulle comunicazioni critiche, specialmente app mobile
* **mTLS** per canali che richiedono autenticazione reciproca
* **Policy sul certificate store**: impedire l'aggiunta di CA non autorizzate, alert su modifiche
* **Monitoring egress**: proxy non standard, porte anomale, WPAD anomalo in LAN
* **Alert su TLS anomalo**: picchi di errori TLS, user-agent inconsistente rispetto alla sessione

mitmproxy genera traffico riconoscibile: header `Via`, pattern specifici nelle richieste verso l'endpoint di onboarding, processi `mitmproxy`/`mitmdump` in esecuzione. In un assessment, non trattarlo come invisibile.

## Scenario pratico su HTB/PG

Ambiente: Kali su `10.10.10.10`, target web su `10.10.10.20`. Obiettivo: intercettare una chiamata API e verificare se il server valida i parametri server-side.

```bash
mitmproxy
```

Configura il browser per usare `127.0.0.1:8080`, visita un endpoint HTTP del target e verifica che compaiano flow nella TUI. Installa la CA e ripeti su un endpoint HTTPS — se non ci sono errori TLS, il setup è corretto.

Imposta un intercept filter sull'endpoint API target:

```text
:set intercept "~u /api/ & ~q"
```

Genera una richiesta dall'applicazione. La richiesta si blocca — modifica un parametro (es. `id=1` → `id=2`), riprendi il flusso con `a` e osserva la risposta. Un 403 o un 400 indica validazione server-side; un 200 con dati di un altro utente indica un IDOR.

## Playbook 10 minuti: mitmproxy in lab

### Step 1 – Avvia mitmproxy e verifica che ascolti

```bash
mitmproxy
```

### Step 2 – Punta il client al proxy

Configura `127.0.0.1:8080`, visita un sito HTTP e verifica che compaiano flow.

### Step 3 – Installa la CA per HTTPS

Apri `http://mitm.it` con il browser che usi per il test, oppure installa manualmente la CA nello store corretto.

### Step 4 – Imposta un view filter per ridurre il rumore

Filtra per host o path: vedi solo ciò che ti interessa senza intercettare ancora nulla.

### Step 5 – Configura l'intercept selettivo

```text
:set intercept "~u /api/.* & ~q"
```

Solo le richieste verso quel path si bloccheranno.

### Step 6 – Salva una sessione pulita

```bash
mitmdump -w lab_capture.mitm
```

### Step 7 – Replay per ripetibilità

```bash
mitmdump -nC lab_capture.mitm
```

## Checklist operativa

* Il client punta davvero a `127.0.0.1:8080`?
* Hai testato prima un endpoint HTTP puro per escludere problemi TLS?
* Hai installato la CA nello store corretto per il client che stai usando?
* Hai distinto view filter (solo visualizzazione) da intercept filter (pausa)?
* Stai intercettando solo URL/metodo specifici, non tutto il traffico?
* Hai salvato una sessione pulita prima di fare tampering?
* Stai valutando l'effetto reale della risposta, non solo lo status code?
* Se un'app non genera flow, hai considerato bypass delle proxy settings o pinning?

## Riassunto 80/20

| Obiettivo                           | Comando/Azione                                |
| ----------------------------------- | --------------------------------------------- |
| Avvio TUI interattiva               | `mitmproxy`                                   |
| Avvio UI web                        | `mitmweb`                                     |
| Cattura in chiaro senza interazione | `mitmdump -w file.mitm`                       |
| Visualizzare solo un host           | View filter: `~d example.com`                 |
| Intercettare solo POST su /api      | Intercept: `~u /api/.* & ~q & ~m POST`        |
| Modificare una richiesta            | Seleziona flow → `e` → modifica → `a`         |
| Replay sessione salvata             | `mitmdump -nC file.mitm`                      |
| Reverse proxy verso un server       | `mitmproxy --mode reverse:https://target.com` |

## Concetti controintuitivi

**"Se l'HTTPS non funziona, è colpa di mitmproxy."** Quasi sempre è la CA: installata nel posto sbagliato (sistema vs browser vs app), o non installata affatto nel client che stai usando.

**"Intercetto tutto così non mi perdo nulla."** Ti blocchi da solo: risorse statiche, analytics, health check, CDN — tutto si mette in pausa e il sito smette di funzionare. Usa l'intercept solo su URL specifiche.

**"Un 200 in risposta significa che il test è riuscito."** Non sempre. Guarda il body e l'effetto reale. Un server può rispondere 200 ignorando silenziosamente i parametri modificati.

**"mitmproxy non è rilevabile."** Lo è: header `Via`, pattern di richieste verso l'endpoint di onboarding, processi in esecuzione, CA aggiunta al trust store. Non trattarlo come stealth per default.

**"Se l'app non passa dal proxy, è colpa di mitmproxy."** Spesso è bypass delle proxy settings o certificate pinning. Cambia approccio (local capture, build debug) invece di cercare di forzare la configurazione.

## FAQ

**Qual è la differenza tra mitmproxy, mitmweb e mitmdump?**
Stesso motore, interfacce diverse. mitmproxy è TUI interattiva da terminale, mitmweb è UI web, mitmdump è CLI senza interfaccia — ideale per scripting e automazione.

**Come vedo traffico HTTPS senza errori di certificato?**
Installa la CA di mitmproxy (`~/.mitmproxy/mitmproxy-ca-cert.pem`) nello store corretto per il client che stai usando. Il metodo di installazione dipende dal browser o dall'applicazione specifica.

**Qual è la differenza tra view filter e intercept filter?**
Il view filter filtra cosa viene mostrato nell'interfaccia senza toccare il traffico. L'intercept filter mette in pausa i flow corrispondenti finché non interagisci manualmente.

**Come salvo e replay una sessione?**
`mitmdump -w file.mitm` per salvare, `mitmdump -nC file.mitm` per replay. Se i token sono scaduti, cattura una sessione più recente.

**Alcune app non generano flow anche con proxy configurato. Perché?**
Probabilmente bypassano le proxy settings di sistema o usano certificate pinning. Prova la modalità `--mode local` o richiedi una build di test senza pinning in contesto autorizzato.

**mitmproxy supporta HTTP/3?**
Il supporto è limitato nelle versioni attuali. Se il client usa HTTP/3 su QUIC, puoi disabilitare QUIC lato client bloccando UDP sulla porta 443 per forzare HTTP/2.

**Quando conviene usare mitmweb invece di mitmproxy?**
Quando hai molti flow da navigare e ricercare — la UI web è più comoda per review e filtri visuali. mitmproxy TUI è più veloce per workflow da tastiera durante un test attivo.

## Riferimenti ufficiali

* [mitmproxy Docs – Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/)
* [mitmproxy Docs – Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)
* [mitmproxy Docs – Filter Expressions](https://docs.mitmproxy.org/stable/concepts/filters/)
