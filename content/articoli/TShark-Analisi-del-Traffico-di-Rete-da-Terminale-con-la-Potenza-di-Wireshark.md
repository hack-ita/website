---
title: 'TShark: Analisi del Traffico di Rete da Terminale con la Potenza di Wireshark'
description: >-
  Scopri come utilizzare TShark per catturare e analizzare pacchetti di rete via
  riga di comando. Una guida tecnica accessibile, ideale per chi vuole esplorare
  il lato oscuro del traffico dati.
image: /TSHARK.webp
draft: true
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - TShark
---

# Tshark: guida pratica per catturare e filtrare PCAP

Tshark (aka **TShark**) è la versione da terminale di Wireshark: cattura pacchetti “dal filo” oppure legge file **PCAP/PCAPNG** e stampa (o esporta) solo quello che ti serve. È perfetto in lab (HTB/PG/CTF) quando vuoi confermare un’ipotesi (“sta parlando con LDAP?”), capire che traffico passa, o tirare fuori dati in modo **scriptabile** senza aprire la GUI. Sempre e solo in ambienti autorizzati. 

**Fonti autorevoli consigliate**

* Manuale `tshark(1)`
* Sintassi filtri capture (BPF / libpcap): `pcap-filter` 
* Sintassi/concetti display filter

***

## Cos’è Tshark e perché ti salva in lab

Se devi “vedere i pacchetti” ma vuoi restare in CLI, Tshark è un coltellino svizzero: cattura live o legge capture file e **decodifica con gli stessi dissector** di Wireshark. Senza opzioni particolari, si comporta molto simile a tcpdump: una riga di summary per ogni pacchetto.

Un file **PCAP/PCAPNG** è semplicemente una registrazione dei pacchetti catturati; **PCAPNG** è il formato moderno/nativo della suite Wireshark.

***

## Setup rapido: installazione, permessi, interfacce

Prima cosa: **scegli l’interfaccia giusta** e verifica che Tshark la veda. Se sbagli interfaccia, stai sniffando il nulla.

Lista interfacce:

```bash
tshark -D
```

`-D` stampa numero + nome interfaccia (utile anche su Windows dove i nomi sono lunghi).

In molti casi catturare live richiede privilegi (tipicamente `sudo`). In lab vai diretto:

```bash
sudo tshark -D
```

Tip: Tshark può leggere anche da file (`-r`) o scrivere su file (`-w`). Ricorda: **`-w` salva pacchetti raw**, non un report testuale. 

***

## Filtri: capture (`-f`) vs display (`-Y`)

Regola d’oro:

* `-f` decide **cosa catturi** (capture filter, BPF/libpcap): più leggero/efficiente
* `-Y` decide **cosa decodifichi/mostri** (display filter stile Wireshark): più potente ma più pesante 
* Nota importante da lab: usare un display filter durante una live capture può rendere più difficile stare dietro a una rete “busy” e aumentare il rischio di drop. Quando puoi, filtra prima con `-f`.

### Capture filter (BPF / libpcap) con `-f`

È la sintassi “tcpdump-style”. La grammatica è quella di libpcap/pcap-filter (host/net/port, src/dst, proto, parentesi). (\[Wireshark]\[2])

Esempi (cattura + salva PCAPNG):

```bash
# Cattura solo DNS
sudo tshark -i eth0 -f "udp port 53" -w dns.pcapng

# Cattura solo traffico verso un host lab
sudo tshark -i eth0 -f "host 10.10.20.5" -w host.pcapng
```

### Display filter (Wireshark filter engine) con `-Y`

È la sintassi dei display filter di Wireshark: puoi filtrare su protocolli e campi (es. `http.request`). (\[Wireshark]\[3])

Esempi (analisi da file):

```bash
# Leggi un file e mostra solo richieste HTTP
tshark -r web.pcapng -Y "http.request"

# Solo pacchetti dove appare quell'IP (src o dst)
tshark -r cap.pcapng -Y "ip.addr == 10.10.20.5"

# DNS query a un nome specifico
tshark -r cap.pcapng -Y 'dns.qry.name contains "lab.local"'
```

***

## Cattura live senza impazzire (interfaccia, snaplen, file output, ring buffer)

Quando catturi live vuoi 3 cose: interfaccia giusta, **file output**, e **non riempire il disco**.

### Snaplen: quanti byte “salvi” per pacchetto

Con `-s` imposti la snapshot length. In lab spesso vuoi “tutto”:

```bash
# Full packet (comodo in lab, più peso su disco)
sudo tshark -i eth0 -s 0 -w full.pcapng
```

### Output file: `-w` è RAW, non testo

`-w` scrive pacchetti su file, e quando lo usi **non stai creando un report testuale**. Se vuoi testo, *non* usare `-w`: redirigi lo stdout.

```bash
# Salva PCAPNG
sudo tshark -i eth0 -f "tcp port 80" -w http.pcapng

# Report testuale (summary) salvato su file
tshark -r cap.pcapng > report.txt
```

### Ring buffer: catture lunghe senza suicidare il disco

Con `-b` vai in modalità multi-file e puoi fare “ring buffer” (rotazione + limite file).

```bash
# 5 file da ~10MB ciascuno (ruota)
sudo tshark -i eth0 -w cap.pcapng -b filesize:10240 -b files:5
```

***

## Analisi da PCAP: trovare traffico interessante (`-r`, `-Y`, `-z`)

Flow tipico: leggi file con `-r`, filtra con `-Y`, poi scegli output (summary, verbose, statistiche).

```bash
# “Scorri” veloce una capture (summary)
tshark -r cap.pcapng

# Filtro display + dettagli completi
tshark -r cap.pcapng -Y "tcp.port == 445" -V
```

Se vuoi statistiche al volo, usa i tap `-z` (esempio HTTP):

```bash
# Conta status code e metodi HTTP (se c'è HTTP decodificato)
tshark -r cap.pcapng -z http,stat -q
```

***

## Output “da automazione”: estrarre campi e fare CSV/JSON (`-T`, `-e`, `-E`)

Se ti serve roba “da script”, evita `-V` (troppo verboso) e usa `-T fields` + `-e` per scegliere i campi. `-E` controlla formattazione (header, separatore, quote, ecc.). 

Esempio CSV pulito (copiabile):

```bash
tshark -r cap.pcapng \
  -T fields \
  -E header=y -E separator=, -E quote=d \
  -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e _ws.col.info
```

Mini glossario rapido:

* **stdin**: input standard (può arrivare da pipe)
* **stdout**: output standard (lo puoi salvare con `>`)
* **pipe `|`**: collega stdout di un comando allo stdin di un altro
* **redirect `>`**: salva stdout su file

Se stai leggendo live e vuoi output immediato (meno buffering), usa `-l`:

```bash
tshark -l -i eth0 -Y "dns" | head
```

***

## Mini-playbook operativo: dal rumore alla pista buona (web lab)

Obiettivo: in 5 minuti capisci se la VM sta facendo roba web “interessante” (login, cookie, errori), senza aprire GUI.

**Step 1: cattura solo quello che serve (meno rumore)**

```bash
sudo tshark -i eth0 -f "host 10.10.20.5 and tcp port 8081" -w web.pcapng
```

**Step 2: conferma che c’è HTTP e guarda solo le request**

```bash
tshark -r web.pcapng -Y "http.request" \
  -T fields -e frame.number -e ip.src -e http.host -e http.request.method -e http.request.uri
```

**Step 3: cerca pattern da lab (login/admin/upload)**

```bash
tshark -r web.pcapng -Y 'http.request.uri contains "login" or http.request.uri contains "admin" or http.request.uri contains "upload"' \
  -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
```

**Step 4: next move (sempre lab)**

* Se vedi endpoint interessanti: passa a Burp/mitmproxy sul tuo client controllato per manipolare request comodo.
* Se vedi traffico verso SMB/LDAP/WinRM: torna a nmap e fai enum mirata (non “sprayare tool a caso”).

***

## Tshark vs tcpdump vs Wireshark vs mitmproxy (differenze pratiche)

* **tcpdump**: catture super rapide e filtri BPF; decodifica più “grezza”.
* **tshark**: simile a tcpdump come approccio, ma con dissezione Wireshark + export campi/script.
* **Wireshark GUI**: quando vuoi analisi visuale (follow stream, timeline, ricostruzioni).
* **mitmproxy**: proxy MITM per HTTP(S) quando controlli client/cert e vuoi modificare traffico applicativo; non è uno sniffer generico.

Dritta da lab: spesso fai così → cattura con tcpdump/tshark, poi apri in Wireshark solo la parte davvero interessante.

***

## Checklist pratica + promemoria 80/20

Se ti perdi, torna qui: è la checklist “da esame” che ti rimette in carreggiata.

* `tshark -D` e scelgo l’interfaccia giusta
* Se il traffico è tanto: filtro in cattura con `-f` (BPF/libpcap)
* Salvo PCAPNG con `-w` (raw) per rianalizzare dopo
* Per catture lunghe: ring buffer `-b filesize:... -b files:...`
* In analisi: `-r file -Y "..."` (display filter)
* Per export: `-T fields -e ... -E ...` (CSV pulito)
* Se faccio pipe/live: `-l` per output immediato

| Obiettivo                    | Azione pratica          | Comando/Strumento                             |
| ---------------------------- | ----------------------- | --------------------------------------------- |
| Vedere interfacce            | Lista e scegli idx/nome | `tshark -D`                                   |
| Ridurre rumore subito        | Filtra in cattura (BPF) | `-f "host 10.10.20.5 and port 80"`            |
| Salvare per dopo             | Scrivi PCAPNG raw       | `-w cap.pcapng`                               |
| Non riempire il disco        | Ring buffer             | `-b filesize:10240 -b files:5`                |
| Cercare solo “quel” traffico | Display filter          | `-Y "dns or http.request"`                    |
| Export CSV                   | Campi + formattazione   | `-T fields -e ... -E header=y -E separator=,` |
| Stat HTTP veloce             | Tap statistiche         | `-z http,stat -q`                             |

***

## Concetti controintuitivi (e errori da skiddie)

Queste sono le 3 cose che vedo sbagliare sempre: sistemale e Tshark diventa molto più “facile”.

1. **“Uso `-w` per salvare l’output” → NO**: `-w` salva PCAP/PCAPNG raw, non testo. Se vuoi testo, redirigi stdout con `>`. 

```bash
tshark -r cap.pcapng > out.txt
```

1. **“`-Y` e `-f` sono la stessa cosa” → NO**: sono due linguaggi e due momenti diversi. `-f` (BPF/libpcap) è più efficiente; `-Y` è più potente ma può pesare di più su live capture. 
2. **“Promiscuous mode = vedo tutto in rete” → quasi mai**: su reti switched di solito vedi solo quello che passa dalla tua porta (a meno di SPAN/TAP o setup specifici).
3.

Bonus micro: se stai usando pipe/live e “non esce nulla”, spesso è buffering → prova `-l`.

***

## FAQ su Tshark

**Tshark è uguale a Wireshark?**
Stesso motore di dissezione, ma senza GUI: Tshark è pensato per terminale, script e ambienti senza interfaccia grafica. 

**Differenza tra `-f` e `-Y` in una riga?**
`-f` filtra in cattura (BPF/libpcap), `-Y` filtra in visualizzazione/analisi (display filter Wireshark).

**Come faccio un CSV pulito con le colonne che voglio?**
Usa `-T fields` + `-e` per i campi e `-E` per header/separatore/quote. 

```bash
tshark -r cap.pcapng -T fields -E header=y -E separator=, -E quote=d -e ip.src -e ip.dst
```

**Perché con `-Y` durante cattura perdo pacchetti?**
Perché il display filter è più pesante; su reti “busy” Tshark può non stare dietro. Quando puoi, filtra prima con `-f`.

**Qual è il comando più semplice per capire che protocolli ci sono?**
Parti con un display filter “macro” e poi stringi:

```bash
tshark -r cap.pcapng -Y "dns or http or smb or ldap"
```

***

## Supporta HackITA

Se questa guida ti è stata utile, puoi darci una mano dalla pagina **Supporta**: ci aiuta a tenere il progetto vivo e pubblicare più contenuti pratici da lab.

Se invece sei bloccato o vuoi accelerare sul serio: facciamo **formazione 1:1** (step-by-step, stile OSCP/PG/HTB) e, se hai un’azienda o un progetto, possiamo supportarti con attività e lavori in ambito **cybersecurity** (assessment, hardening, analisi, consulenza).
