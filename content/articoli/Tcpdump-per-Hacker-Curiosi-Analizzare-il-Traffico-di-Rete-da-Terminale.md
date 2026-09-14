---
title: 'Tcpdump: Tutorial Sniffing e Analisi del Traffico di Rete'
slug: tcpdump
description: 'Cos''è tcpdump e come funziona? Guida al network sniffing da terminale con packet capture, filtri BPF, analisi PCAP e comandi per il pentesting.'
image: /tcpdump.webp
draft: false
date: 2026-01-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Tcpdump
  - Network Sniffing
  - BPF
  - PCAP
  - Packet Capture
featured: false
---

# Tcpdump: Tutorial Sniffing e Analisi del Traffico di Rete

Tcpdump è lo strumento a riga di comando per catturare e analizzare pacchetti di rete su Linux, presente praticamente ovunque — spesso l'unica opzione disponibile su un server senza ambiente grafico.

## Cos'è Tcpdump e a cosa serve

Tcpdump usa libpcap per catturare pacchetti direttamente da un'interfaccia di rete, applicando filtri con la sintassi BPF (Berkeley Packet Filter) per restringere cosa catturare. Serve a: verificare che un traffico atteso stia davvero transitando, osservare protocolli in chiaro per capirne il contenuto, salvare evidenze in pcap per analisi successive (anche con Wireshark), e diagnosticare problemi di rete in generale.

## Installare Tcpdump su Linux e Kali Linux

Su Kali e sulla maggior parte delle distribuzioni Linux è già preinstallato; in caso contrario:

```bash
sudo apt update && sudo apt install -y tcpdump
```

Verifica versione:

```bash
tcpdump --version
```

## Tcpdump Commands: i comandi principali

| Opzione      | Funzione                                                        |
| ------------ | --------------------------------------------------------------- |
| `-D`         | Elenca le interfacce disponibili                                |
| `-i`         | Seleziona l'interfaccia di cattura                              |
| `-n` / `-nn` | Evita la risoluzione DNS/porte (output più veloce e leggibile)  |
| `-c`         | Limita il numero di pacchetti catturati                         |
| `-s`         | Imposta lo snapshot length (`-s 0` cattura il pacchetto intero) |
| `-w`         | Salva la cattura su file pcap                                   |
| `-r`         | Legge un file pcap                                              |
| `-A`         | Mostra il payload in ASCII                                      |
| `-X`         | Mostra il payload in esadecimale + ASCII                        |
| `-v` / `-vv` | Aumenta il livello di dettaglio                                 |

## Catturare il traffico di rete

Prima di tutto, identifica l'interfaccia giusta:

```bash
tcpdump -D
```

Poi una cattura minimale per confermare che il traffico atteso arrivi davvero su quell'interfaccia:

```bash
sudo tcpdump -i tun0 -nn -c 10 host 10.10.10.10
```

Se non vedi pacchetti, il problema è quasi sempre interfaccia sbagliata o routing non corretto — non dare per scontato che il target non sia raggiungibile.

Per osservare i primi byte di un servizio in chiaro senza inviare nulla di attivo:

```bash
sudo tcpdump -i tun0 -nn -s 0 -A 'tcp and host 10.10.10.10 and (port 80 or port 21)' | head -30
```

Questo mostra ciò che il servizio invia spontaneamente all'apertura della connessione — utile per capire versione e comportamento in modo passivo, senza scomodare il termine "banner grabbing" che di solito indica un probe attivo.

## Tcpdump Filters: sintassi BPF

I filtri si costruiscono componendo alcune parole chiave di base:

```text
host <ip>       # traffico da/verso un host
src / dst       # solo sorgente o solo destinazione
port <n>        # traffico su una porta
net <cidr>      # traffico su una subnet
tcp / udp / icmp
and / or / not  # combinazione logica
```

Esempi progressivi:

```bash
tcpdump -i eth0 host 192.168.1.50
tcpdump -i eth0 host 192.168.1.50 and port 80
tcpdump -i eth0 net 172.16.5.0/24 and not arp
tcpdump -i eth0 '(port 80 or port 21) and host 192.168.1.50'
```

Regola pratica: un filtro troppo largo su un segmento con molto traffico produce catture da decine di GB inutili da analizzare; stringi sempre su `host`/`port`/`net` prima di lanciare una cattura prolungata.

## Salvare e leggere file PCAP

```bash
tcpdump -i eth0 -w capture.pcap
```

```bash
tcpdump -r capture.pcap
```

```bash
tcpdump -r capture.pcap 'tcp port 80'
```

Salvare sempre su file, anche durante un'analisi rapida: è l'unica evidenza ripetibile — senza `-w` quello che hai visto a schermo non è più recuperabile.

## Analizzare HTTP, FTP e traffico locale

**HTTP in chiaro.** Un filtro BPF su porta 80 mostra il payload delle richieste, comprese eventuali form di login o parametri non cifrati:

```bash
sudo tcpdump -i eth0 -nn -s 0 -A 'tcp port 80 and host 192.168.1.50'
```

Tcpdump non "estrae credenziali" in modo automatico: cattura i pacchetti e ne mostra il payload in chiaro, se presente — la lettura resta manuale (o con un filtro testuale a valle, es. `grep`).

**FTP o Telnet.** Comandi come `USER`/`PASS` viaggiano in chiaro, leggibili anche in esadecimale:

```bash
sudo tcpdump -i eth0 -nn -s 0 -X 'tcp port 21 and host 192.168.1.50'
```

**Traffico locale su loopback.** Molte applicazioni comunicano con database locali senza cifratura sull'interfaccia `lo`, il che può rivelare query con credenziali di altri servizi:

```bash
sudo tcpdump -i lo -nn -s 0 -A 'port 3306 or port 5432' -c 20
```

**Traffico SSH.** Tcpdump non decifra una sessione SSH né ne rivela la chiave privata semplicemente osservando l'handshake — quello che puoi ottenere è analisi di metadati (timing, dimensioni dei pacchetti), utile solo in scenari molto specifici:

```bash
sudo tcpdump -i eth0 -nn -s 0 -w ssh_handshake.pcap 'tcp port 22 and host 10.10.10.5'
```

**Ricerca di pattern in un pcap già catturato:**

```bash
tcpdump -nn -r captured.pcap -A | grep -i -E "pass=|pwd=|token=|secret=|key="
```

## Tcpdump in un internal pentest e su un pivot

Da un host già raggiunto (pivot), tcpdump aiuta a verificare la connettività verso nuovi segmenti prima di lanciare attacchi diretti:

```bash
sudo tcpdump -i any -nn 'host 172.16.5.20 and not arp' -c 5
```

Nota su `-i any`: cattura su tutte le interfacce contemporaneamente, comodo per una verifica rapida, ma con un comportamento diverso (es. header di collegamento generico) rispetto a una cattura su una singola interfaccia fisica — non è un sostituto universale di `-i eth0` quando serve precisione.

Per mappare comunicazioni verso una subnet interna, ad esempio traffico SMB o WinRM utile a identificare altri target:

```bash
sudo tcpdump -i eth1 -nn 'net 172.16.5.0/24 and (port 445 or port 5985)' -w lateral_capture.pcap
```

Per un'analisi più strutturata dello stesso traffico — statistiche, estrazione campi, follow stream — [TShark](https://hackita.it/articoli/tshark/) è lo strumento più adatto quando tcpdump da solo non basta più.

## Come rilevare e mitigare lo sniffing con Tcpdump

**Indicatori per il blue team:**

* Processo `tcpdump` (o uso di `libpcap`) in esecuzione su host non autorizzati a farlo
* Interfaccia di rete impostata in modalità promiscua, verificabile con `ip link` o tool dedicati
* Picchi anomali di traffico ARP su uno switch, spesso segno di ARP spoofing propedeutico a un MITM — vedi anche [Bettercap](https://hackita.it/articoli/bettercap/) per come funziona questa tecnica lato attaccante
* Richieste sensibili nei log applicativi con IP sorgente improbabile (es. quello del gateway)

**Mitigazioni concrete:**

* Eliminare i protocolli in chiaro (HTTP, FTP, Telnet, SNMPv2) a favore di alternative cifrate
* Segmentazione di rete (VLAN, firewall di micro-segmentazione) per limitare la visibilità del traffico broadcast/unicast
* Rimuovere `sudo` per tcpdump dove non necessario, limitando la capability `CAP_NET_RAW` solo a chi ne ha davvero bisogno
* Regole IDS/IPS che alertino su avvio di sniffer o su protocolli in chiaro in reti considerate sicure

## Errori comuni

* Sniffare sull'interfaccia sbagliata (`tun0` vs `eth0`) e concludere erroneamente che il target non sia raggiungibile
* Filtri BPF troppo larghi o con parentesi mancanti in espressioni complesse, con catture da GB di traffico inutile
* Non salvare mai il pcap, perdendo l'unica evidenza ripetibile
* Interpretare un "bad checksum" come traffico corrotto, quando spesso è solo un effetto del checksum offloading della scheda di rete (disattivabile in lab con `ethtool -K eth0 tx off rx off` per verificare)
* Provare a decifrare TLS con tcpdump: non è possibile senza le chiavi di sessione — per l'ispezione di traffico HTTPS serve un proxy MITM come [mitmproxy](https://hackita.it/articoli/mitmproxy/)
* Sniffing prolungato senza rotazione dei file, fino a riempire il disco dell'host su cui si lavora

## Tcpdump Cheat Sheet

```bash
tcpdump -D
tcpdump -i eth0 -nn -c 10 host 10.10.10.10
tcpdump -i eth0 -w capture.pcap
tcpdump -r capture.pcap 'tcp port 80'
tcpdump -i eth0 -nn -A 'tcp port 80 and host 192.168.1.50'
tcpdump -i lo -nn -A 'port 3306' -c 20
tcpdump -nn -r capture.pcap -A | grep -i -E "pass=|token=|secret="
```

## FAQ

**Cos'è tcpdump?**
Uno strumento da riga di comando per catturare e analizzare pacchetti di rete, basato su libpcap e sulla sintassi di filtro BPF.

**A cosa serve tcpdump?**
A verificare traffico atteso, osservare protocolli in chiaro, salvare pcap per analisi successive e diagnosticare problemi di rete.

**Come vedo le interfacce disponibili?**
`tcpdump -D` elenca tutte le interfacce di rete disponibili per la cattura.

**Come catturo il traffico su una porta specifica?**
`tcpdump -i eth0 port 80` cattura solo il traffico su quella porta; si combina con `host`/`net` per restringere ulteriormente.

**Come salvo un pcap con tcpdump?**
Con `-w file.pcap` durante la cattura; si legge poi con `-r file.pcap`, eventualmente aggiungendo un filtro.

**Qual è la differenza tra tcpdump e Wireshark?**
Tcpdump è da riga di comando, leggero e sempre disponibile anche via SSH; Wireshark ha un'interfaccia grafica più adatta ad analisi approfondite su un pcap già catturato. [TShark](https://hackita.it/articoli/tshark/) sta nel mezzo: stesso motore di Wireshark, ma da terminale.

**Tcpdump funziona su Kali Linux?**
Sì, è preinstallato sulla maggior parte delle distribuzioni Linux, Kali incluso.

**Tcpdump può decifrare traffico HTTPS?**
No, non ha accesso alle chiavi di sessione. Per intercettare traffico cifrato serve un proxy MITM dedicato.

## Riferimenti ufficiali

* [Tcpdump – Man Page ufficiale](https://www.tcpdump.org/manpages/tcpdump.1.html)
* [pcap-filter – Sintassi BPF](https://www.tcpdump.org/manpages/pcap-filter.7.html)
