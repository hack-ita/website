---
title: 'Tcpdump per Hacker Curiosi: Analizzare il Traffico di Rete da Terminale'
description: >-
  Scopri come usare Tcpdump per analizzare il traffico di rete direttamente dal
  terminale. Una guida semplice e pratica pensata per hacker etici, curiosi e
  aspiranti professionisti della cybersecurity.
image: /tcpdump.webp
draft: true
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Tcpdump
  - ''
featured: false
---

# Tcpdump: guida pratica per catture e filtri in lab

Tcpdump è il tool “da terminale” che usi quando vuoi **vedere e salvare pacchetti** in modo rapido: cattura da un’interfaccia, filtra con espressioni **BPF/pcap-filter** e può salvare tutto in un file per analisi dopo (Wireshark/Tshark). In un lab (HTB/Proving Grounds/CTF) ti serve soprattutto per fare una cosa: **confermare cosa sta succedendo davvero**, senza supposizioni. DNS che risolve, HTTP che parla, SMB che prova autenticazioni, connessioni in uscita “strane”: lo vedi subito. Sempre e solo in ambienti autorizzati.

Link autorevoli:

* Manpage tcpdump (Debian): `https://manpages.debian.org/testing/tcpdump/tcpdump.8.en.html` (\[Debian Manpages]\[1])
* Sintassi filtri (pcap-filter): `https://manpages.debian.org/testing/libpcap0.8/pcap-filter.7.en.html` (\[man7.org]\[2])
* BPF nel kernel (per capire perché filtra “veloce”): `https://docs.kernel.org/networking/filter.html` (\[docs.kernel.org]\[3])

***

## Cos’è tcpdump (e perché è ancora il re in CLI)

**Tcpdump è “packet capture + stampa veloce”: se sai filtrare, ti dice la verità in 10 secondi.**
**Quando ti perdi, tcpdump è il sanity check: “sto vedendo traffico? dove? su quale porta?”**

In pratica tcpdump stampa i pacchetti che matchano un’espressione e può anche scrivere i pacchetti su file con `-w` oppure leggere da file con `-r`. I filtri sono quelli di libpcap/pcap-filter (la stessa “famiglia” di sintassi usata come capture filter anche in Wireshark). (\[Debian Manpages]\[1])

***

## Setup: interfacce, permessi e “perché non vedo niente”

**Se non scegli l’interfaccia giusta o non hai permessi di cattura, tcpdump sembra rotto… ma stai sniffando il nulla.**
**Prima regola da lab: lista interfacce → cattura corta → poi filtra.**

Lista interfacce catturabili:

```bash
sudo tcpdump -D
```

`-D` stampa le interfacce disponibili e i relativi nomi/ID.

Permessi: sniffare da interfaccia può richiedere privilegi; leggere un file PCAP no.

***

## I comandi base che usi sempre (senza diventare matto)

**Se impari questi 6 flag, tcpdump diventa “facile”: interfaccia, niente DNS lookup, conta, snaplen, salva/leggi file.**
**Tutto il resto è ottimizzazione e comfort.**

### Starter pack (copy/paste)

Cattura 20 pacchetti, senza risolvere nomi (più veloce/meno casino):

```bash
sudo tcpdump -i eth0 -nn -c 20
```

Salva su file (PCAP) per aprirlo dopo:

```bash
sudo tcpdump -i eth0 -nn -s 0 -w lab.pcap
```

* `-s snaplen` controlla quanti byte prendi per pacchetto; `-s 0` = prendi tutto (utile in lab).
* `-w` salva “packet data” per analisi dopo. (\[Debian Manpages]\[1])

Leggi un file salvato:

```bash
tcpdump -nn -r lab.pcap
```

`-r` legge da savefile invece che da interfaccia. (\[Debian Manpages]\[1])

Output più “parlante” (payload in ASCII o hex):

```bash
sudo tcpdump -i eth0 -nn -A -c 10
sudo tcpdump -i eth0 -nn -X -c 10
```

`-A` stampa ASCII (comodo per HTTP in chiaro), `-X` fa hex+ASCII.

***

## Filtri BPF: la sintassi che ti fa vincere i lab

**I filtri di tcpdump sono espressioni pcap-filter (BPF): “host/net/port + src/dst + proto + parentesi”.**
**Se ti incasini con le parentesi, metti tutto tra apici: eviti che la shell ti rovini l’espressione.** (\[Stack Overflow]\[4])

Cosa devi sapere (60 secondi):

* **type qualifier**: `host`, `net`, `port`, `portrange`
* **dir qualifier**: `src`, `dst`, `src or dst`, `src and dst`
* **proto qualifier**: `tcp`, `udp`, `ip`, `ip6`, `arp`, …
* operatori: `and`, `or`, `not` + parentesi `()` (quote consigliato)

Esempi utili (IP fittizi da lab):

Solo traffico verso/da una VM:

```bash
sudo tcpdump -i eth0 -nn 'host 10.10.20.5'
```

Solo DNS:

```bash
sudo tcpdump -i eth0 -nn 'udp port 53'
```

Solo HTTP/HTTPS:

```bash
sudo tcpdump -i eth0 -nn 'tcp port 80 or tcp port 443'
```

Solo SMB e niente broadcast/multicast (meno rumore):

```bash
sudo tcpdump -i eth0 -nn 'tcp port 445 and not broadcast and not multicast'
```

L’idea “not broadcast/multicast” è un trucco classico anche in esempi di capture filter: in lab tagli via rumore inutile e ti restano i pacchetti che contano.

***

## Salvare PCAP “bene”: rotazione file e compressione

`-w` salva PCAP per analisi dopo; con `-C` o `-G` ruoti i file e non distruggi il disco. **In lab serio, catturi a finestre (size/time) e poi analizzi con Wireshark/Tshark.** (\[Debian Manpages]\[1])

Salvataggio base:

```bash
sudo tcpdump -i eth0 -nn -s 0 -w cap.pcap
```

`-w` scrive i pacchetti su file; `-r` e `-V` servono per leggere uno o più file salvati.

Rotazione per dimensione (file da N “milioni di byte”):

```bash
sudo tcpdump -i eth0 -nn -w cap.pcap -C 50
```

`-C` chiude e apre un nuovo file quando supera la soglia. (\[Debian Manpages]\[1])

Rotazione per tempo (ogni X secondi) + limite numero file:

```bash
sudo tcpdump -i eth0 -nn -w cap.pcap -G 300 -W 20
```

`-G` ruota ogni `rotate_seconds`, `-W` limita il numero di file. (\[Debian Manpages]\[1])

Compressione post-rotate (pratica):

```bash
sudo tcpdump -i eth0 -nn -w cap.pcap -C 50 -z gzip
```

`-z` esegue un comando dopo ogni rotazione (es. gzip). (\[Debian Manpages]\[1])

***

## tcpdump vs Tshark/Wireshark: quando scegliere cosa

**Tcpdump è perfetto per catture veloci e filtri BPF; Tshark/Wireshark sono migliori per analisi “ricca” e filtri display avanzati.**
**In pratica: cattura con tcpdump → analizza con Wireshark/Tshark.**

Punto che confonde tutti: **capture filter ≠ display filter**. I capture filter (BPF) riducono cosa viene catturato; i display filter cambiano solo cosa vedi in analisi e puoi modificarli al volo.

***

## Mini-playbook operativo (step-by-step): “che traffico fa questa VM?”

**Playbook da lab: 1) scegli interfaccia, 2) cattura stretta con filtro, 3) riproduci l’azione (login/upload), 4) salva PCAP, 5) analizza con calma.**
**Obiettivo: passare da “boh non va” a “ecco la porta/host/protocollo che spacca tutto”.**

**Step 1 — Trova l’interfaccia giusta**

```bash
sudo tcpdump -D
```

**Step 2 — Cattura solo il minimo (esempio: target 10.10.20.5:8081)**

```bash
sudo tcpdump -i eth0 -nn -s 0 -w lab.pcap 'host 10.10.20.5 and tcp port 8081'
```

(qui usi pcap-filter: `host` + `tcp port` + `and`).

**Step 3 — Riproduci l’azione**
Apri browser/curl nel lab e fai la request (login, upload, ecc.). Poi stoppa con Ctrl+C: tcpdump ti stampa anche i contatori (captured/received/dropped).

**Step 4 — Se vedi “dropped by kernel”, aumenta buffer**

```bash
sudo tcpdump -i eth0 -nn -B 4096 -s 0 -w lab.pcap 'host 10.10.20.5'
```

`-B` setta la capture buffer size del sistema (in KiB). Se la macchina è sotto carico o il traffico è “bursty”, i drop possono aumentare: alzare buffer aiuta, ma se il sistema è saturo devi anche ridurre rumore o catturare più stretto. (\[Unix & Linux Stack Exchange]\[5])

**Step 5 — Analizza**

```bash
tcpdump -nn -r lab.pcap
```

Poi, se serve, apri in Wireshark/Tshark per display filter e follow stream.

***

## Checklist pratica (lab / esami OSCP-style)

**Questa checklist ti evita l’errore classico: “catturo tutto e poi non capisco nulla”.**
**Prima restringi, poi allarghi.**

* Ho l’autorizzazione (lab/VM/rete mia).
* Ho scelto l’interfaccia corretta ( `tcpdump -D`).
* Uso `-nn` (niente DNS/porte risolte) per velocità/leggibilità.
* Uso un filtro pcap-filter sensato ( `host/net/port`, `src/dst`, `tcp/udp`).
* Quando ci sono parentesi, metto l’espressione tra apici.
* Se devo analizzare davvero: salvo con `-w` e poi leggo con `-r`.
* Se perdo pacchetti: controllo “dropped by kernel” e aumento buffer ( `-B`).

***

## Promemoria 80/20

| Obiettivo              | Azione pratica           | Comando/Strumento                     |
| ---------------------- | ------------------------ | ------------------------------------- |
| Scegliere NIC          | lista interfacce         | `sudo tcpdump -D`                     |
| Vedere subito traffico | cattura corta, no lookup | `sudo tcpdump -i eth0 -nn -c 20`      |
| Filtrare bene          | usa pcap-filter          | `'host 10.10.20.5 and tcp port 8081'` |
| Salvare per analisi    | scrivi PCAP              | `-w lab.pcap`                         |
| Leggere dopo           | read savefile            | `tcpdump -nn -r lab.pcap`             |
| Non saturare disco     | ruota per size/time      | `-C 50` / `-G 300 -W 20`              |
| Ridurre drop           | aumenta buffer           | `-B 4096`                             |

***

## Concetti controintuitivi (minimo 3)

**Queste sono le trappole che fanno impazzire gli skiddie (e pure i junior).**
**Capiscile e diventi 10x più veloce.**

1. **“Il filtro non funziona” ma è la shell che mangia le parentesi**
   Se usi `(` `)` senza quote, spesso la shell interpreta roba e ti esplode il comando. Metti l’espressione tra apici quando usi parentesi o combinazioni complesse. (\[Stack Overflow]\[4])
2. **“Ho salvato con -w, perché non vedo testo nel file?”**
   Perché `-w` salva pacchetti raw (PCAP), non un report. Il “testo” lo vedi a schermo durante la cattura oppure lo ottieni rileggendo il file con `-r` (o aprendo in Wireshark/Tshark). (\[Debian Manpages]\[1])
3. **“Ho catturato tutto ma non posso cambiare filtro al volo”**
   Con tcpdump il filtro è un capture filter (BPF): si applica prima e decide cosa entra nella cattura. I display filter sono roba da Wireshark/Tshark in fase di analisi.
4. **“Perché BPF è così veloce?”**
   Perché i filtri vengono compilati e agganciati al kernel/socket filtering: tanti pacchetti vengono scartati prima di arrivare in user-space, quindi consumi meno risorse e l’output è più gestibile. (\[docs.kernel.org]\[3])

***

## FAQ su tcpdump

**Tcpdump è legale da usare?**
Sì, se lo usi su reti/host dove hai autorizzazione (lab, test interni, ambienti di training). Su reti altrui senza consenso è un no secco.

**Qual è la differenza tra** `-w` e `-r`?
`-w` scrive su file (savefile/PCAP), `-r` legge da file invece che sniffare live. (\[Debian Manpages]\[1])

**Come faccio a filtrare “solo DNS” o “solo SMB” velocemente?**
DNS:

```bash
sudo tcpdump -i eth0 -nn 'udp port 53'
```

SMB:

```bash
sudo tcpdump -i eth0 -nn 'tcp port 445'
```

La logica è pcap-filter: `proto + port`.

**Perché devo usare** `-nn` quasi sempre?
Per evitare risoluzioni di nomi/servizi che rendono l’output più lento e più confuso (in lab vuoi numeri chiari).

**Tcpdump o Tshark: quale scelgo?**
Tcpdump per cattura rapida e filtri BPF; Tshark/Wireshark per analisi ricca e display filter. Capture filter e display filter non sono la stessa cosa.

**Come evito di riempire il disco con catture lunghe?**
Rotazione: `-C` (size) o `-G` (time) + `-W` (limite file), e se serve compressione con `-z`.

***

## Supporta HackITA

Se questa guida ti è stata utile, puoi supportarci dalla pagina **Supporta**: anche un contributo piccolo ci aiuta a pubblicare più contenuti pratici e lab-oriented.

Se invece sei bloccato o vuoi accelerare, facciamo **formazione 1:1** (hacking etico, cybersecurity, networking, CTF/lab, metodo di analisi e troubleshooting). E se hai un’azienda o un progetto, possiamo valutare anche **lavori/consulenze** su attività di sicurezza e assessment, sempre in contesti autorizzati e concordati.
