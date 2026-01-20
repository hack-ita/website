---
title: >-
  Ettercap: Intercettare, Manipolare e Snoopare il Traffico di Rete con
  Facilità"
description: >-
  Scopri come usare Ettercap per attacchi man-in-the-middle, sniffing e
  manipolazione del traffico di rete. Una guida tecnica chiara pensata per chi
  esplora le basi dell'hacking etico e dell'analisi delle comunicazioni.
image: /ettercap.webp
draft: false
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - ettercap
  - sniffing
  - mitm
---

# Ettercap: guida pratica in lab (sniffing, ARP, difese)

**Ettercap** è una suite “storica” per analisi di rete e scenari **adversary-in-the-middle** su LAN: sniffing, dissezione protocolli, log e filtri.
In questa guida lo usiamo **in ottica lab/difesa**: capire cosa fa, analizzare traffico in modo safe (anche da file `.pcap`) e soprattutto chiudere le condizioni che rendono possibili MITM come **ARP cache poisoning**.

> Nota secca: qui **non** trovi comandi “pronti” per fare ARP poisoning/MITM su reti reali. In lab, la parte che ti fa crescere davvero è **capire il pattern e difenderlo**.

***

## Cos’è Ettercap e quando ti serve davvero

Ettercap torna utile quando vuoi **trasformare traffico in evidenze**: log, `.pcap`, contesto sui protocolli e una lettura “più umana” di cosa sta succedendo in LAN.
Se il tuo obiettivo è **web testing puro** (API, cookie, JWT, CORS), in genere Burp/mitmproxy sono più comodi. Se invece stai ragionando di **LAN, ARP, posizionarsi in mezzo** e vuoi fare pratica “di rete”, Ettercap (o alternative moderne) ha senso.

***

## Il concetto chiave: ARP e perché su LAN si può fare AiTM

ARP serve a tradurre **IP → MAC** dentro una rete locale. Ogni host mantiene una **ARP cache**, cioè una tabella con associazioni del tipo: “questo IP corrisponde a quel MAC”.

Se quella tabella viene “sporcata” (cache poisoning), il traffico può finire a passare da un host non previsto. È il cuore degli scenari **Adversary-in-the-Middle** su LAN.

Spiegazione super semplice:

* **IP** = indirizzo “logico” (es. `10.10.10.5`)
* **MAC** = indirizzo “fisico” della scheda di rete
* **ARP cache** = tabella locale con “IP ↔ MAC”

Se qualcuno riesce a far associare “IP del gateway → MAC dell’attaccante”, può diventare un “ponte” involontario tra vittima e gateway (e quindi osservare o tentare manipolazioni, a seconda dei casi e delle protezioni).

***

## Installazione su Kali e modalità UI (graphical, curses, text)

Su Kali puoi installare Ettercap in versione GUI o text-only. In lab è utile conoscere anche la modalità terminale, così non dipendi dalla GUI.

Install (GUI):

```bash
sudo apt update
sudo apt install ettercap-graphical
```

Modalità utili (da pratica reale):

* `-T` = text interface
* `-C` = curses UI (menu in terminale)
* `-G` = GTK UI
* `-I` = lista interfacce disponibili

Esempi “safe”:

```bash
sudo ettercap -I
sudo ettercap -T
sudo ettercap -C
```

***

## Uso sicuro #1: analisi OFFLINE da file `.pcap` (super utile in lab)

Il modo più pulito per imparare è lavorare **offline**: dai a Ettercap un file `.pcap` e lui fa dissezione/sniffing **senza toccare la rete**.
Questo ti allena su protocolli e su dati “in chiaro” (quando presenti), senza dover fare MITM.

Leggere un pcap:

```bash
sudo ettercap -T -r capture.pcap
```

Versione più “quiet” (meno rumore):

```bash
sudo ettercap -Tq -r capture.pcap
```

***

## Uso sicuro #2: logging e “trasformare pacchetti in evidenze”

Se l’obiettivo è produrre prove (per studio, report, troubleshooting), ragiona sempre così:
**cattura → log → analisi → conclusione**

Log binari (poi li leggi con gli strumenti di Ettercap, tipo `etterlog`):

```bash
sudo ettercap -Tq -L labdump -r capture.pcap
```

Nota: l’output “serio” spesso lo fai salvando traffico e analizzandolo con strumenti dedicati (Wireshark/tcpdump/tshark), mentre Ettercap qui lo usi per **dissezione e logging**.

***

## Ettercap vs Bettercap vs Wireshark/mitmproxy (scelta rapida)

Regola pratica da lab:

* Devi ragionare su **LAN / ARP / AiTM** e vuoi log “di rete” → Ettercap / Bettercap (focus difensivo)
* Devi analizzare **pacchetti** in profondità e ricostruire conversazioni → Wireshark
* Devi lavorare su **HTTP(S) applicativo** (cookie, header, request/response) → mitmproxy / Burp

In breve: Ettercap non sostituisce Wireshark e non sostituisce Burp. È uno strumento diverso, utile quando il problema è “di LAN”.

***

## Mini-playbook operativo (difesa): scoprire e bloccare ARP poisoning

Obiettivo: anche se qualcuno prova a “mettersi in mezzo”, la rete **lo blocca** oppure l’attacco diventa **inutile**.

### Step 1 — Cerca segnali (anomalie ARP)

Indicatori tipici:

* ARP reply **non richiesti**
* cambi frequenti nelle associazioni IP↔MAC
* pattern sospetti tipo “molti IP → stesso MAC”

Comandi rapidi (Linux) per vedere vicini/cambi e osservare ARP:

```bash
ip neigh
sudo tcpdump -ni eth0 arp
```

### Step 2 — Conferma su endpoint

Se vedi che il MAC del “gateway” cambia spesso nella cache, è un red flag.

### Step 3 — Mitigazione di rete (quella vera)

Se hai switch gestiti, la difesa migliore è lato rete:

* **DHCP snooping** per costruire la tabella di binding IP↔MAC “attendibile”
* **Dynamic ARP Inspection (DAI)** per validare pacchetti ARP contro quella tabella e droppare inconsistenze

### Step 4 — Mitigazione applicativa (web)

Sul web, riduci tantissimo l’impatto di AiTM con configurazioni corrette:

* **HTTPS ovunque**
* **HSTS (Strict-Transport-Security)** per evitare downgrade a HTTP e rendere più difficile l’intercettazione “utile” lato browser

***

## Checklist pratica (lab / esami / lavoro)

* So spiegare cos’è ARP cache poisoning in 2 frasi (AiTM su LAN).
* So riconoscere segnali: ARP reply non richiesti, “molti IP → un MAC”, cambi improvvisi.
* So lavorare **offline** con `.pcap` usando `-r` (zero rischio).
* Se ho switch gestiti: valuto **DAI + DHCP snooping**.
* Per servizi web: abilito HTTPS e configuro **HSTS**.

***

## Promemoria 80/20

| Obiettivo             | Azione pratica        | Comando/Strumento                     |
| --------------------- | --------------------- | ------------------------------------- |
| Installare su Kali    | install GUI           | `sudo apt install ettercap-graphical` |
| Vedere interfacce     | lista NIC             | `sudo ettercap -I`                    |
| Imparare senza rischi | sniff offline da pcap | `sudo ettercap -T -r capture.pcap`    |
| Ridurre rumore        | quiet + offline       | `sudo ettercap -Tq -r capture.pcap`   |
| Produrre evidenze     | log files             | `-L labdump`                          |
| Bloccare AiTM su LAN  | validazione ARP       | DAI + DHCP snooping                   |
| Ridurre MITM sul web  | forza HTTPS           | HSTS                                  |

***

## Concetti controintuitivi (minimo 3)

1. **“Se uso HTTPS sono immune al MITM” → quasi, ma non sempre.**
   HTTPS fatto bene ti salva, ma se esistono downgrade/HTTP o configurazioni deboli, restano finestre. HSTS serve proprio a chiudere la porta del “torno su HTTP”.
2. **“Basta vedere traffico ARP = c’è attacco” → falso.**
   ARP è normale. Il segnale vero è l’anomalia: reply non richiesti, cambi improvvisi, pattern ripetuti.
3. **“La difesa è bloccare Ettercap” → sbagliato.**
   La difesa è strutturale: DAI + DHCP snooping sullo switch validano ARP e droppano pacchetti non coerenti.
4. **“Per imparare MITM devo farlo live” → no.**
   Spesso impari più velocemente su `.pcap` offline: ripeti, confronti, capisci protocolli senza rischi e senza “rompere” la rete.

***

## FAQ su Ettercap

**Ettercap serve ancora oggi?**
Sì, soprattutto per studio e per workflow classici di sniffing/log/filtri in LAN. Esistono alternative più moderne, ma i concetti restano gli stessi.

**Posso usarlo senza fare MITM?**
Sì: la modalità offline `-r` ti fa analizzare da file `.pcap`.

**Che cos’è un file `.pcap`?**
È una cattura pacchetti (generata ad esempio da tcpdump/Wireshark). Ettercap può leggerla con `-r`.

**Come capisco se in LAN c’è ARP poisoning?**
Osserva anomalie ARP: reply non richiesti, più IP verso lo stesso MAC, cambi frequenti nella cache, incongruenze tra quanto “dovrebbe” essere il gateway e quanto vedi.

**Qual è la mitigazione migliore in azienda?**
Su switch gestiti: **DAI + DHCP snooping**. È la difesa più solida contro ARP poisoning.

**HSTS c’entra?**
Sì: lato web riduce fortemente scenari di downgrade e rende la vita molto più dura a molte forme di intercettazione “utile” dal punto di vista dell’utente.

***

## Supporto e servizi (HackITA)

Se questa guida ti è stata utile, puoi supportare il progetto nella sezione **Supporta**: ci aiuta a pubblicare più contenuti tecnici e mantenere tutto aggiornato.

Se invece sei bloccato su un lab, un esame o vuoi accelerare davvero: facciamo **formazione 1:1** (percorsi pratici, debugging insieme, metodo).

E se hai un’azienda o un progetto reale, possiamo supportarti con lavori su misura: assessment, hardening, review e attività di sicurezza **su richiesta e in contesti autorizzati**.
