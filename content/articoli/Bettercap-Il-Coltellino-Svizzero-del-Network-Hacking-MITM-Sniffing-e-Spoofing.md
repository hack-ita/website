---
title: >-
  Bettercap: Il Coltellino Svizzero del Network Hacking (MITM, Sniffing e
  Spoofing)
slug: bettercap
description: >-
  Bettercap è uno degli strumenti più potenti per attacchi man-in-the-middle,
  sniffing e spoofing. Scopri come usarlo da terminale per dominare le reti in
  modo rapido ed efficace.
image: /BETTERCAP.webp
draft: false
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - bettercap
  - mitm
  - spoofing
---

# Bettercap: Il Coltellino Svizzero del Network Hacking (MITM, Sniffing e Spoofing)

Risolvi subito il classico “**non vedo host / non sniffa nulla**” e arrivi a un **MITM verificabile in lab** (pcap + indicatori di detection), senza uscire dal perimetro autorizzato.

## Intro

Bettercap è un framework modulare in stile console interattiva per **recon e attacchi adversary-in-the-middle (MITM)** su reti IPv4/IPv6 (oltre a moduli wireless/altro), pensato per sessioni ripetibili e automatizzabili.

In un lab ti serve perché unisce discovery, spoofing e sniffing in un unico workflow, con comandi “accendi/spegni” e parametri configurabili, senza incollarti a 10 tool diversi.

Cosa farai/imparerai:

* Identificare interfaccia/gateway/subnet senza perdere tempo.
* Fare discovery host con `net.recon` e `net.probe`.
* Eseguire un MITM “da lab” con `arp.spoof` e cattura con `net.sniff` (pcap).
* Capire quando usare proxy/UI e quando invece è meglio un tool dedicato.

Nota etica: tutto ciò che segue è **solo per lab/CTF/HTB/PG/VM personali o autorizzate**; niente uso su reti reali non consentite.

## Cos’è BETTERCAP e dove si incastra nel workflow

> **In breve:** Bettercap è una console modulare per recon + MITM: scopri host, fai spoofing e sniffi traffico in una sessione controllabile e automatizzabile.

Bettercap “rende operativo” il network hacking: entri in sessione, abiliti moduli (recon, sniff, spoof, proxy), setti parametri e leggi eventi in tempo reale. Il punto non è “il comando magico”, ma **controllare contesto**: interfaccia corretta, subnet, gateway, target.

Quando NON usarlo: se devi solo analizzare un pcap o fare ispezione profonda, vai diretto su strumenti dedicati (vedi sezione “Alternative”).

## Installazione + quick sanity check (versione e interfaccia)

> **In breve:** installa, verifica versione/build e parti sempre specificando l’interfaccia con `-iface` per evitare sessioni “vuote”.

Su Kali spesso lo installi dai repo; se hai mismatch di versione/moduli, usa la documentazione ufficiale per release/compilazione.

Perché: installare in modo ripetibile e non debug-gare mezza giornata per un binario vecchio.

Cosa aspettarti: pacchetto installato e comando `bettercap` disponibile.

Comando:

```bash
sudo apt update && sudo apt install -y bettercap
```

Esempio di output (può variare):

```text
Reading package lists... Done
Building dependency tree... Done
Setting up bettercap ...
```

Interpretazione: se l’install va a buon fine, puoi invocare `bettercap` e i moduli base saranno disponibili.

Errore comune + fix: `Unable to locate package` → repo non aggiornati o distro diversa; passa alle opzioni di installazione ufficiali (binaries/Go/source).

Perché: verificare build/versione prima di seguire guide e comandi.

Cosa aspettarti: stampa versione/build e termina.

Comando:

```bash
bettercap -version
```

Esempio di output (può variare):

```text
bettercap v2.x (build abcdef)
```

Interpretazione: se la versione è “troppo diversa” rispetto ai comandi che usi, aspettati nomi/parametri cambiati.

Errore comune + fix: `permission denied` su alcune funzioni → avvia la sessione con `sudo` quando lavori su interfacce/moduli che richiedono privilegi.

Perché: legare Bettercap all’interfaccia giusta (il 90% dei “non funziona”).

Cosa aspettarti: sessione interattiva con prompt e subnet/gateway rilevati.

Comando:

```bash
sudo bettercap -iface eth0
```

Esempio di output (può variare):

```text
bettercap v2.x
[19:21:00] [sys.log] gateway: 10.10.10.1
[19:21:00] [sys.log] interface: eth0 (10.10.10.20/24)
```

Interpretazione: se vedi IP/subnet coerenti col lab, sei pronto per discovery e moduli.

Errore comune + fix: interfaccia sbagliata (es. `wlan0` vs `eth0`) → controlla con `ip a` fuori da Bettercap e riparti con `-iface` corretto.

Per approfondire la scoperta host prima di entrare in Bettercap, in lab spesso conviene partire da [arp-scan per la discovery in LAN](/articoli/arp-scan/) (pillar “recon veloce”).

## Sessione interattiva: 3 pattern che userai sempre (set/get, concatenazione, caplets)

> **In breve:** in sessione userai sempre `set/get`, concatenazione con `;` e caplets per automatizzare.

Pattern 1: concatenare comandi con `;` per workflow rapidi (es. “clear; net.show”).

Pattern 2: `set` e `get` per parametri dei moduli.

Pattern 3: caplets (`.cap`) per ripetere sequenze identiche tra lab diversi.

Perché: installare/aggiornare caplets “pronti” e avere un baseline ripetibile.

Cosa aspettarti: download/aggiornamento caplets e ritorno al prompt.

Comando:

```bash
sudo bettercap -eval "caplets.update; q"
```

Esempio di output (può variare):

```text
[caplets] downloading caplets index ...
[caplets] updated.
```

Interpretazione: dopo l’update, puoi usare caplets di esempio e scoprire percorsi/nomi.

Errore comune + fix: proxy/rete del lab blocca download → fai update da rete consentita o usa caplets locali.

Perché: vedere cosa hai installato e dove Bettercap cerca i caplets.

Cosa aspettarti: lista di caplets e percorsi di ricerca.

Comando:

```text
caplets.show
```

Esempio di output (può variare):

```text
local-sniffer
netmon
...
```

Interpretazione: se vedi caplets noti, puoi “include” o avviarli con `-caplet`.

Errore comune + fix: “caplet not found” → controlla `caplets.paths` e percorso `/usr/local/share/bettercap/caplets/`.

Quando NON usarlo: se stai facendo un one-shot rapidissimo, i caplets possono essere overkill; vai di comandi manuali.

## Recon host: net.recon + net.probe (discovery senza impazzire)

> **In breve:** `net.recon` scopre host leggendo periodicamente la tabella ARP, `net.probe` stimola la subnet per far “uscire” host silenziosi.

Perché: popolare una lista endpoint coerente prima di qualsiasi MITM/sniff.

Cosa aspettarti: comparsa di endpoint e metadati in `net.show`.

Comando:

```text
net.recon on
```

Esempio di output (può variare):

```text
[net.recon] new endpoint 10.10.10.10 08:00:27:aa:bb:cc
```

Interpretazione: se compaiono endpoint, la tua interfaccia/subnet è corretta.

Errore comune + fix: non vedi nulla → spesso sei su rete virtuale diversa (NAT/Host-only/Bridge). Ricontrolla la NIC e riparti.

Perché: forzare discovery attiva nella subnet del lab.

Cosa aspettarti: nuovi endpoint rilevati (in combo con net.recon).

Comando:

```text
net.probe on
```

Esempio di output (può variare):

```text
[net.probe] probing 10.10.10.0/24 ...
```

Interpretazione: se dopo pochi secondi vedi host in più, la rete aveva endpoint “silenziosi”.

Errore comune + fix: “rumore” e troppi eventi → spegni `net.probe` e tieni solo `net.recon` per baseline.

Quando NON usarlo: su reti grandi o instabili (anche in lab) rischi di sporcare risultati; limita CIDR e fai probe mirato.

Se vuoi un’alternativa rapida per discovery in lab (senza sessione interattiva), puoi incrociare con [netdiscover per host discovery](/articoli/netdiscover/) (spoke “scansione leggera”).

## MITM “da lab”: arp.spoof + net.sniff (pcap e credenziali dove possibile)

> **In breve:** in lab puoi posizionarti “in mezzo” con `arp.spoof` e catturare traffico con `net.sniff` (salvando anche su pcap). Poi validi e chiudi con detection/hardening.

Qui entriamo nella parte “abuso tipico”: **ARP spoofing/MITM**. Per restare puliti:

* validazione solo in lab (VM su stessa subnet),
* detection (indicatori su ARP, log, switch),
* mitigazione (DAI/DHCP snooping, segmentazione, HTTPS/HSTS lato app).

Perché: selezionare in modo esplicito il target del lab (mai “tutta la rete” a caso).

Cosa aspettarti: parametro impostato, poi avvio spoof.

Comando:

```text
set arp.spoof.targets 10.10.10.10; arp.spoof on
```

Esempio di output (può variare):

```text
[arp.spoof] spoofing 10.10.10.10 ...
```

Interpretazione: stai tentando MITM verso il target indicato. Se il lab ha protezioni, può fallire (ed è normale).

Errore comune + fix: non passa nulla o si interrompe → rete con protezioni anti-ARP spoof (bene!); prova a validare in un lab “più semplice” o passa a scenario non-MITM.

Perché: sniffare e salvare evidenze su pcap per analisi post.

Cosa aspettarti: file pcap scritto e (se `verbose`/parsing attivo) eventi applicativi.

Comando:

```text
set net.sniff.output /tmp/lab-sniff.pcap; net.sniff on
```

Esempio di output (può variare):

```text
[net.sniff] output: /tmp/lab-sniff.pcap
[net.sniff] started
```

Interpretazione: anche se non “vedi credenziali”, la pcap è oro per validare traffico e ricostruire cosa succede.

Errore comune + fix: pcap vuota → controlla filtro e interfaccia: `get net.sniff.filter` e verifica che non stai escludendo troppo.

Perché: controllare statistiche e configurazione della sessione sniff.

Cosa aspettarti: contatori, filtro, output path.

Comando:

```text
net.sniff stats
```

Esempio di output (può variare):

```text
filter: not arp
output: /tmp/lab-sniff.pcap
packets: 1234
```

Interpretazione: se i pacchetti crescono, stai catturando. Se restano a zero, stai sniffando nel posto sbagliato.

Errore comune + fix: `packets: 0` → tipicamente interfaccia sbagliata o traffico assente (target inattivo).

Validazione in lab (a): apri la pcap con [Wireshark per analizzare traffico e indicatori](/articoli/wireshark/) (pillar “analisi”) e verifica che i flussi coincidano con il test.

Segnali di detection (b): variazioni sospette in ARP cache (MAC del gateway che cambia), burst di ARP reply, mismatch IP↔MAC ripetuti, endpoint che “perde” connettività se l’attacco degrada.

Hardening/mitigazione (c): su switch gestiti abilita **Dynamic ARP Inspection (DAI)** e **DHCP snooping**; segmenta (VLAN), riduci L2 broadcast, e lato applicazione alza la barra con TLS/HSTS (riduce downgrade e traffico in chiaro).

Quando NON usarlo: se l’obiettivo è solo “osservare” o fare troubleshooting di rete, evita MITM e resta su `net.recon` + capture passiva.

Per un confronto pratico “sniff puro” vs sessione modulare, vedi anche [tcpdump per cattura rapida da CLI](/articoli/tcpdump/) (child “sniff minimalista”).

## Proxy e UI: quando conviene (http.proxy / Web UI)

> **In breve:** i proxy di Bettercap servono quando vuoi intercettare/strumentare traffico a un livello più alto; la Web UI è comoda per visualizzare e orchestrare, ma in lab va esposta con criterio.

Perché: attivare un proxy HTTP trasparente (solo in contesto MITM autorizzato).

Cosa aspettarti: proxy in ascolto e redirezione del traffico HTTP (se combinato con spoofer/route coerenti).

Comando:

```text
http.proxy on
```

Esempio di output (può variare):

```text
[http.proxy] started on 0.0.0.0:8080
```

Interpretazione: se il lab genera traffico HTTP, ora hai un punto centrale per osservare/modificare (sempre in ambito autorizzato).

Errore comune + fix: “non vedo richieste” → molte app sono HTTPS-only; per HTTP puro, usa un servizio di lab in chiaro o passa a strumenti dedicati.

Perché: avviare la Web UI per vedere sessione/moduli in modo visuale.

Cosa aspettarti: UI attiva e raggiungibile (di default su loopback).

Comando:

```bash
sudo bettercap -eval "ui on"
```

Esempio di output (può variare):

```text
[ui] web ui running at http://127.0.0.1:8080/
```

Interpretazione: apri browser in locale sulla VM e gestisci moduli/parametri dalla UI.

Errore comune + fix: UI non raggiungibile → bind su indirizzo sbagliato o porta occupata; setta `ui.address` e `ui.port` in modo esplicito.

Quando NON usarlo: se sei in un lab “rumoroso” o remoto, la UI può essere un extra inutile; resta su CLI per ripetibilità.

Se il tuo focus è “proxy applicativo” con workflow web (request/response, replay, scripting), spesso è più efficiente usare [mitmproxy per intercettare HTTP(S)](/articoli/mitmproxy/) (spoke “proxy puro”).

## Errori comuni e troubleshooting (quello che ti blocca davvero)

> **In breve:** il 90% dei problemi è interfaccia/subnet errata, target non nel segmento L2, filtri troppo aggressivi o protezioni anti-ARP spoof nel lab.

Caso 1: `net.recon` non trova host.

* Perché succede: NIC sbagliata o rete virtuale non condivisa.
* Fix: riparti con `sudo bettercap -iface <nic>` e controlla fuori dal tool (es. `ip a`, `ip r`).

Caso 2: `net.sniff` a pacchetti zero.

* Perché succede: traffico assente, filtro errato o stai sniffando un’interfaccia senza flusso.
* Fix: imposta output pcap e verifica contatori con `net.sniff stats`; riduci filtro solo dopo aver visto pacchetti.

Caso 3: `arp.spoof` “non funziona” o si rompe la connettività.

* Perché succede: protezioni (DAI), ARP spoofing protection sul gateway, oppure configurazione fullduplex/target non coerente.
* Fix: valida in un lab semplice (switch virtuale senza protezioni) o resta su scenari non-MITM; se vuoi solo evidenze, cattura passiva.

Quando NON usarlo: se stai cercando “stabilità” e il lab è fragile, evita moduli invasivi (spoof/ban) e lavora su recon/sniff passivo.

## Alternative e tool correlati (quando preferirli)

> **In breve:** Bettercap è “all-in-one”, ma per task specifici strumenti dedicati sono più veloci o più profondi.

* Per analisi visuale e dissezione profonda: Wireshark (pillar).
* Per cattura veloce e scripting minimale: tcpdump/tshark (child).
* Per MITM “storico” e approccio diverso: Ettercap.
* Per capture di credenziali Windows via name resolution poisoning in lab AD: tool specifici (Responder/Inveigh).

Quando NON usarlo: se hai già un tool “best-in-class” per quel task e Bettercap aggiunge solo complessità.

## Hardening & detection (log, regole, alert, best practice)

> **In breve:** non “blocchi il tool”, blocchi la tecnica: controlli L2 (DAI/DHCP snooping), osservabilità ARP, e cifratura/app policy corrette.

Detection pratica in lab:

* Monitor ARP cache su client/gateway e cerca cambi MAC improvvisi per lo stesso IP.
* Cerca storm di ARP reply e incongruenze IP↔MAC ripetute.
* Se hai switch/virtual switch con feature, abilita log/alert su ARP inspection (quando disponibile).

Hardening:

* Dynamic ARP Inspection + DHCP snooping (reti gestite).
* Segmentazione L2 (VLAN), riduzione broadcast.
* TLS everywhere e policy HSTS lato web app (riduce valore di MITM sul traffico in chiaro).
* Educazione/controlli su warning certificati (utente che “accetta qualsiasi cosa” riapre scenari).

Quando NON usarlo: se il tuo obiettivo è solo “difesa web”, non fissarti su MITM L2; lavora su TLS/HSTS e sicurezza applicativa.

## Scenario pratico: BETTERCAP su una macchina HTB/PG

Ambiente: Kali attacker `10.10.10.20`, target `10.10.10.10`, gateway lab `10.10.10.1` (tutto su rete VM autorizzata).

Obiettivo: posizionarti in MITM verso il target e salvare una pcap per evidenze.

Perché: eseguire una sequenza minima (recon → spoof target → sniff → pcap).

Cosa aspettarti: endpoint rilevati, avvio spoof, file `/tmp/lab-sniff.pcap` popolato.

Comando:

```text
net.recon on; net.show
```

Esempio di output (può variare):

```text
10.10.10.10 08:00:27:aa:bb:cc
10.10.10.1  52:54:00:11:22:33
```

Interpretazione: hai target e gateway visibili: prerequisito per qualunque MITM L2.

Errore comune + fix: `net.show` vuoto → interfaccia/rete errata; riparti con `-iface`.

Perché: avviare MITM mirato sul target (non “tutta la subnet”).

Cosa aspettarti: spoof attivo verso target.

Comando:

```text
set arp.spoof.targets 10.10.10.10; arp.spoof on
```

Esempio di output (può variare):

```text
[arp.spoof] spoofing 10.10.10.10 ...
```

Interpretazione: stai tentando di inserirti tra target e gateway in questo lab.

Errore comune + fix: l’attacco fallisce su lab “protetti” → è un risultato valido; passa a evidenze passive.

Perché: catturare traffico e salvarlo in pcap.

Cosa aspettarti: pcap creata e contatori in crescita.

Comando:

```text
set net.sniff.output /tmp/lab-sniff.pcap; net.sniff on
```

Esempio di output (può variare):

```text
[net.sniff] started
```

Interpretazione: ora puoi generare traffico dal target (ping, browsing su servizio lab) e poi analizzare la pcap.

Errore comune + fix: pcap vuota → verifica `net.sniff stats` e presenza traffico reale.

Risultato atteso: file `/tmp/lab-sniff.pcap` non vuoto e flussi coerenti con l’attività del target.

Detection + hardening: in detection, cerca anomalie ARP (IP↔MAC che “slitta”) e storm ARP; in hardening, abilita DAI/DHCP snooping dove possibile e forza TLS/HSTS lato app per ridurre impatto.

## Playbook 10 minuti: BETTERCAP in un lab

### Step 1 – Fissa il perimetro e la NIC

Prima di tutto conferma che sei su VM/lab autorizzato e identifica la NIC corretta (es. `eth0`).

```bash
sudo bettercap -iface eth0
```

### Step 2 – Aggiorna caplets e baseline

Aggiorna i caplets per avere workflow ripetibili.

```bash
sudo bettercap -eval "caplets.update; q"
```

### Step 3 – Discovery passiva

Accendi discovery e verifica che emergano endpoint.

```text
net.recon on; net.show
```

### Step 4 – Discovery attiva se serve

Se vedi poco, abilita probe per far “parlare” host silenziosi.

```text
net.probe on; net.show
```

### Step 5 – MITM mirato (solo se richiesto dal lab)

Se il lab richiede MITM, seleziona target specifico e avvia spoof.

```text
set arp.spoof.targets 10.10.10.10; arp.spoof on
```

### Step 6 – Sniff e pcap come evidenza

Salva sempre su pcap: è la tua prova ripetibile.

```text
set net.sniff.output /tmp/lab-sniff.pcap; net.sniff on
```

### Step 7 – Stop pulito e note

Spegni moduli e annota risultati/detection.

```text
net.sniff off; arp.spoof off; net.probe off; net.recon off
```

## Checklist operativa

* Conferma perimetro: solo lab/CTF/HTB/PG/VM autorizzate.
* Avvia Bettercap con `-iface` esplicito (mai “auto” alla cieca).
* Verifica IP/subnet/gateway stampati a inizio sessione.
* Avvia `net.recon` e controlla `net.show` prima di tutto.
* Usa `net.probe` solo se la discovery passiva è povera.
* Se fai MITM, imposta sempre `arp.spoof.targets` (target mirato).
* Prima dello sniff, imposta `net.sniff.output` su pcap.
* Usa `net.sniff stats` per confermare contatori e filtro.
* Evita moduli invasivi se il lab è instabile (ban/deauth ecc.).
* Chiudi i moduli in ordine e ripristina (stop pulito).
* Analizza la pcap con tool dedicati quando serve.
* Scrivi detection + mitigazioni osservate (DAI/DHCP snooping/TLS).

## Riassunto 80/20

| Obiettivo                    | Azione pratica           | Comando/Strumento                         |
| ---------------------------- | ------------------------ | ----------------------------------------- |
| Entrare in sessione corretta | Lega la NIC giusta       | `sudo bettercap -iface eth0`              |
| Discovery host               | Avvia discovery passiva  | `net.recon on`                            |
| Discovery “spinta”           | Stimola la subnet        | `net.probe on`                            |
| MITM mirato (lab)            | Seleziona target e spoof | `set arp.spoof.targets ...; arp.spoof on` |
| Evidenze ripetibili          | Salva sniff su pcap      | `set net.sniff.output ...; net.sniff on`  |
| Validazione                  | Analizza pcap e flussi   | `wireshark` / `tshark`                    |

## Concetti controintuitivi

* **“Non vedo host → la rete è vuota”**
  Quasi sempre è la NIC/rete VM sbagliata. Prima correggi `-iface` e subnet, poi giudichi il tool.
* **“net.recon dovrebbe scoprire tutto”**
  `net.recon` si appoggia a ciò che l’ARP table “sa”; se vuoi far emergere host, serve `net.probe` in lab.
* **“MITM = solo roba web”**
  MITM è livello rete: se ti metti in mezzo, tutto ciò che non è protetto bene diventa osservabile/manipolabile.
* **“Basta HTTPS e sono a posto”**
  HTTPS aiuta tantissimo, ma misconfig (assenza HSTS, downgrade, utenti che accettano cert sospetti) riaprono scenari.

## FAQ

D: Bettercap è solo per attaccare?

R: No: in lab è ottimo anche per recon e osservabilità. Il problema è che include moduli MITM, quindi va usato solo in ambienti autorizzati.

D: Qual è il comando “minimo” per partire senza perdere tempo?

R: `sudo bettercap -iface eth0` e poi `net.recon on; net.show`. Se non vedi nulla, il problema è quasi sempre la rete/NIC.

D: net.recon vs net.probe: cosa cambia davvero?

R: `net.recon` è discovery “passiva” via ARP table; `net.probe` manda probe per far emergere endpoint silenziosi nella subnet.

D: Perché la pcap è più importante del “vedere credenziali”?

R: Perché la pcap è ripetibile e verificabile: dimostra flussi, timing e indicatori anche quando non c’è traffico in chiaro.

D: arp.spoof non funziona: è un bug?

R: Spesso no: molte reti (anche lab avanzati) hanno protezioni anti-ARP spoof. È un outcome valido: passa a recon/sniff passivo o cambia lab.

## Link utili su HackIta.it

* [Ettercap per MITM e sniffing in rete](/articoli/ettercap/)
* [Tshark: analisi pcap da terminale](/articoli/tshark/)
* [Wireshark: dissezione e analisi traffico](/articoli/wireshark/)
* [Responder: capture in lab Windows/AD](/articoli/responder/)
* [Inveigh: alternative Windows-centric a Responder](/articoli/inveigh/)

In coda:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

* [Bettercap – Installation (documentazione ufficiale)](https://www.bettercap.org/project/installation/) (\[bettercap]\[1])
* [Bettercap – Interactive Session (CLI, caplets, -iface/-version)](https://www.bettercap.org/usage/interactive_session/) (\[bettercap]\[2])
* [Bettercap – arp.spoof module (targets/fullduplex)](https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/) (\[bettercap]\[3])
* [Bettercap – net.sniff module (filter/output/pcap)](https://www.bettercap.org/modules/ethernet/netsniff/) (\[bettercap]\[4])
* [Bettercap – Web UI (ui on)](https://www.bettercap.org/usage/web_ui/) (\[bettercap]\[5])

## CTA finale HackITA

Se questa guida ti è stata utile, puoi supportare HackIta qui: /supporto/ — ci aiuta a pubblicare playbook aggiornati e “lab-first”.

Vuoi accelerare sul serio? Formazione 1:1 pratica (debug insieme, metodo da lab, workflow da pentest): /servizi/

Per aziende o team: assessment e hardening in contesti autorizzati (network/app, review e best practice): /servizi/

(1): [https://www.bettercap.org/project/installation/?utm\_source=chatgpt.com](https://www.bettercap.org/project/installation/?utm_source=chatgpt.com) "Installation"
(2): [https://www.bettercap.org/usage/interactive\_session/](https://www.bettercap.org/usage/interactive_session/) "Interactive Session | bettercap"
(3): [https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/](https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/) "arp.spoof | bettercap"
(4): [https://www.bettercap.org/modules/ethernet/netsniff/](https://www.bettercap.org/modules/ethernet/netsniff/) "net.sniff - net.fuzz | bettercap"
(5): [https://www.bettercap.org/usage/web\_ui/?utm\_source=chatgpt.com](https://www.bettercap.org/usage/web_ui/?utm_source=chatgpt.com) "Web UI"
