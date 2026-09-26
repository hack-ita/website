---
title: 'Bettercap: Cos''è'', MITM, ARP Spoofing e Sniffing su Kali Linux'
slug: bettercap
description: 'Cos''è Bettercap e come funziona? Scopri il framework per network hacking e MITM: tutorial su Kali Linux, ARP spoofing, sniffing, network recon, PCAP e proxy.'
image: /BETTERCAP.webp
draft: false
date: 2026-01-21T00:00:00.000Z
lastmod: 2026-09-14T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - bettercap
  - mitm
  - spoofing
---

# Bettercap: MITM, ARP Spoofing, Sniffing e Network Recon su Kali Linux

Bettercap è un framework modulare scritto in Go per network reconnaissance e attacchi adversary-in-the-middle (MITM) su reti IPv4/IPv6, con moduli aggiuntivi per Wi-Fi, BLE, HID e CAN bus. Su Kali Linux lo usi per scoprire host con `net.recon`/`net.probe`, posizionarti in mezzo al traffico con `arp.spoof` o `dns.spoof`, e catturarlo con `net.sniff` — il tutto da un'unica sessione interattiva, scriptabile tramite caplet.

Tutto quello che segue va usato solo su lab, CTF, HTB/PG o reti per cui hai autorizzazione esplicita.

## Cos'è Bettercap

Bettercap non è "un tool ARP": è un framework che copre recon, spoofing (ARP, DNS, NDP), sniffing, proxy HTTP/HTTPS, Wi-Fi, e una Web UI/API REST per orchestrare tutto. Il punto di forza non è il singolo comando, ma il controllo del contesto — interfaccia corretta, subnet, gateway, target — dentro un'unica sessione.

## A cosa serve Bettercap

* Host discovery su una LAN (passiva e attiva)
* ARP spoofing / MITM su IPv4
* NDP spoofing / MITM su IPv6
* DNS spoofing
* Packet sniffing con export in pcap
* Intercettazione HTTP/HTTPS via proxy
* Automazione di sessioni ripetibili tramite caplet
* Gestione e visualizzazione da Web UI o API REST

Quando non è la scelta giusta: se devi solo analizzare un pcap già catturato o fare ispezione protocollare approfondita, uno strumento dedicato come [Wireshark](https://hackita.it/articoli/wireshark/) è più indicato.

## Bettercap: moduli e funzionalità principali

| Modulo                       | Funzione                                        |
| ---------------------------- | ----------------------------------------------- |
| `net.recon`                  | Host discovery passiva (legge la tabella ARP)   |
| `net.probe`                  | Host discovery attiva (invia probe alla subnet) |
| `arp.spoof`                  | MITM basato su ARP (IPv4)                       |
| `ndp.spoof`                  | MITM basato su NDP (IPv6)                       |
| `dns.spoof`                  | DNS spoofing                                    |
| `net.sniff`                  | Packet sniffing, con export pcap                |
| `http.proxy` / `https.proxy` | Intercettazione/modifica traffico HTTP/HTTPS    |
| `wifi.recon`                 | Wireless reconnaissance                         |
| `ui`                         | Web UI                                          |
| `api.rest`                   | API REST                                        |
| `caplets`                    | Automazione di sequenze di comandi              |

## Prerequisiti

* Kali Linux o altra distro Linux, con privilegi di root/sudo
* Un'interfaccia di rete sulla stessa subnet del lab (VM attacker e target sullo stesso segmento L2)
* Accesso a una rete di laboratorio o comunque autorizzata
* Idealmente, una seconda VM target per generare traffico da osservare

## Installazione su Kali Linux

Su Kali è nei repository ufficiali:

```bash
sudo apt update && sudo apt install -y bettercap
```

Verifica versione prima di seguire qualunque guida (nomi e parametri dei moduli cambiano tra versioni):

```bash
bettercap -version
```

Avvia sempre specificando l'interfaccia in modo esplicito — è la causa più comune di sessioni "vuote" che sembrano non funzionare:

```bash
sudo bettercap -iface eth0
```

Output atteso:

```text
bettercap v2.x
[19:21:00] [sys.log] gateway: 10.10.10.1
[19:21:00] [sys.log] interface: eth0 (10.10.10.20/24)
```

Se gateway e subnet stampati corrispondono al lab, sei pronto. Se l'interfaccia è sbagliata (es. `wlan0` invece di `eth0`), verificalo con `ip a` fuori da Bettercap e riavvia con `-iface` corretto.

## Quick Start: il primo workflow in 3 comandi

Se vuoi solo vedere Bettercap funzionare prima di capire ogni dettaglio:

```bash
sudo bettercap -iface eth0
```

```text
net.recon on
net.show
```

Se compaiono host con IP e MAC, la sessione è impostata correttamente. Da qui puoi proseguire con la guida completa qui sotto per capire cosa succede realmente sotto al singolo comando.

## Bettercap commands: i comandi essenziali

| Comando                | Funzione                         |
| ---------------------- | -------------------------------- |
| `help`                 | Mostra l'help                    |
| `get <param>`          | Legge un parametro               |
| `set <param> <valore>` | Imposta un parametro             |
| `net.recon on`         | Avvia host discovery passiva     |
| `net.probe on`         | Avvia host discovery attiva      |
| `net.show`             | Mostra gli host rilevati         |
| `arp.spoof on`         | Avvia ARP spoofing               |
| `net.sniff on`         | Avvia packet sniffing            |
| `net.sniff stats`      | Mostra statistiche dello sniffer |
| `caplets.show`         | Mostra i caplet installati       |
| `events.show`          | Mostra gli eventi registrati     |
| `ui on`                | Avvia la Web UI                  |

## Sessione interattiva: i tre pattern che userai sempre

In sessione ricorrono sempre tre pattern: `set`/`get` per i parametri dei moduli, concatenazione di comandi con `;` (es. `clear; net.show`), e i caplet — file `.cap` che raggruppano una sequenza di comandi da riusare identica tra lab diversi.

Per aggiornare l'indice dei caplet disponibili:

```bash
sudo bettercap -eval "caplets.update; q"
```

Per vedere quali hai già installati e dove Bettercap li cerca:

```text
caplets.show
```

Se stai facendo un test rapido una tantum, i caplet sono spesso overkill: meglio comandi manuali diretti.

## Network reconnaissance: net.recon e net.probe

`net.recon` non è uno scanner completo della subnet: legge periodicamente la tabella ARP del sistema, quindi mostra solo host di cui è già arrivata una risposta ARP. Per far emergere host silenziosi serve `net.probe`, che invia probe attivi alla subnet.

```text
net.recon on
```

```text
[net.recon] new endpoint 10.10.10.10 08:00:27:aa:bb:cc
```

Se non vedi nulla, il problema è quasi sempre la rete virtuale (NAT/Host-only/Bridge) o l'interfaccia sbagliata — ricontrolla con `ip a`/`ip r` fuori da Bettercap.

```text
net.probe on
```

Se dopo l'attivazione del probe compaiono nuovi endpoint, la subnet aveva host che non rispondevano spontaneamente. Su reti grandi o instabili, anche in lab, `net.probe` può generare rumore: limita il CIDR o disattivalo dopo la baseline.

Come alternativa più mirata per la sola discovery, in lab puoi anche partire da [arp-scan](https://hackita.it/articoli/arp-scan/) o da [netdiscover](https://hackita.it/articoli/netdiscover/) prima di entrare in Bettercap.

## ARP spoofing e MITM con Bettercap

Con `arp.spoof` ti posizioni tra target e gateway a livello L2. Seleziona sempre un target esplicito, mai l'intera subnet a caso:

```text
set arp.spoof.targets 10.10.10.10; arp.spoof on
```

```text
[arp.spoof] spoofing 10.10.10.10 ...
```

Se lo spoof non parte o la connettività del target si interrompe, spesso è una protezione del lab (Dynamic ARP Inspection, ARP spoofing protection sul gateway) che sta facendo il suo lavoro correttamente — non un bug di Bettercap. In quel caso, valida su un lab senza queste protezioni o passa a evidenze puramente passive.

## Network sniffing con net.sniff e pcap

Una volta in MITM (o anche solo in ascolto), `net.sniff` cattura il traffico e può salvarlo su pcap:

```text
set net.sniff.output /tmp/lab-sniff.pcap; net.sniff on
```

```text
[net.sniff] output: /tmp/lab-sniff.pcap
[net.sniff] started
```

Per verificare che stia effettivamente catturando qualcosa:

```text
net.sniff stats
```

```text
filter: not arp
output: /tmp/lab-sniff.pcap
packets: 1234
```

Se il contatore resta a zero, o hai un filtro troppo aggressivo o stai sniffando sull'interfaccia sbagliata. Anche senza credenziali in chiaro, una pcap resta la prova più solida e ripetibile di quello che è successo — apribile con [Wireshark](https://hackita.it/articoli/wireshark/) per confermare che i flussi coincidano col test.

## DNS spoofing con Bettercap

Il modulo `dns.spoof` risponde a query DNS del target con un IP a tua scelta, invece di lasciarle andare al resolver legittimo — utile in lab per dimostrare l'impatto di un DNS in chiaro senza DNSSEC/DoH.

```text
set dns.spoof.domains target-lab.local
set dns.spoof.address 10.10.10.20
dns.spoof on
```

A differenza dell'ARP spoofing, che agisce a livello L2 su tutto il traffico verso il target, il DNS spoofing agisce selettivamente solo sulle risoluzioni dei domini che indichi — più chirurgico, ma richiede comunque di essere già in mezzo al traffico (tipicamente via `arp.spoof` attivo in parallelo).

## IPv6 e NDP spoofing

Bettercap copre anche reti IPv6: al posto dell'ARP (che esiste solo in IPv4), IPv6 usa il protocollo NDP (Neighbor Discovery Protocol) per la risoluzione degli indirizzi a livello locale. Il modulo `ndp.spoof` fa l'equivalente IPv6 dell'ARP spoofing:

```text
set ndp.spoof.targets fe80::1
ndp.spoof on
```

Molti lab e reti reali hanno ancora IPv6 attivo di default anche se il traffico "principale" è pensato per girare su IPv4: questo rende `ndp.spoof` un vettore spesso trascurato sia in attacco che in detection.

## HTTP/HTTPS proxy con Bettercap

Per intercettare traffico a livello applicativo, non solo di rete, Bettercap espone un proxy:

```text
http.proxy on
```

```text
[http.proxy] started on 0.0.0.0:8080
```

Molte applicazioni oggi sono HTTPS-only: per quel traffico serve `https.proxy`, che comporta l'installazione di un certificato sul lato client — fattibile in lab, molto più delicato (e fuori scope) su dispositivi che non controlli.

## Bettercap Web UI

Per impostazione predefinita la Web UI viene associata a `127.0.0.1:8080`:

```bash
sudo bettercap -eval "ui on"
```

```text
[ui] web ui running at http://127.0.0.1:8080/
```

Se non è raggiungibile, controlla di non avere già qualcosa sulla stessa porta e imposta esplicitamente `ui.address`/`ui.port` se ti serve un binding diverso da loopback. In un lab rumoroso o remoto, la UI è spesso un extra: per ripetibilità resta sulla CLI.

## Caplets e automazione

I caplet sono script `.cap` che raggruppano una sequenza di comandi Bettercap, caricabili con `-caplet` all'avvio o dalla sessione stessa. Sono utili quando ripeti lo stesso workflow (recon → spoof → sniff) su lab diversi e vuoi evitare di ridigitare gli stessi comandi ogni volta.

## Troubleshooting

**`net.recon` non trova host.** Quasi sempre NIC sbagliata o rete virtuale non condivisa tra le VM. Riparti con `sudo bettercap -iface <nic>` dopo aver verificato con `ip a`/`ip r`.

**`net.sniff` resta a pacchetti zero.** Traffico assente, filtro troppo stretto, o interfaccia senza flusso reale. Imposta l'output pcap e controlla i contatori con `net.sniff stats` prima di stringere il filtro.

**`arp.spoof` non funziona o rompe la connettività.** Spesso è una protezione del lab (Dynamic ARP Inspection, anti-ARP-spoofing sul gateway) o una configurazione full-duplex/target incoerente. Valida su un lab più semplice, oppure limitati a recon e cattura passiva.

## Come rilevare ARP spoofing e attività Bettercap

**Sull'endpoint:** cambi improvvisi nella cache ARP, in particolare del MAC associato al gateway; associazioni IP↔MAC duplicate o incoerenti.

**Sulla rete:** burst anomali di ARP reply, gratuitous ARP fuori pattern, mismatch ripetuti IP↔MAC.

**Sullo switch:** se gestito, abilita **Dynamic ARP Inspection (DAI)** e **DHCP snooping** — sono i controlli più efficaci contro questa classe di attacco.

**Telemetria Bettercap stessa:** la sessione espone eventi come `net.sniff.*`, `http.spoofed-request`, `http.spoofed-response`, `mod.started`/`mod.stopped`, utili se stai costruendo detection basata sui log di un lab controllato.

## Hardening contro ARP/NDP spoofing

* Dynamic ARP Inspection + DHCP snooping su switch gestiti
* Segmentazione L2 (VLAN), per ridurre la portata di un singolo dominio di broadcast
* TLS ovunque e policy HSTS lato applicazione, per ridurre il valore pratico di un MITM sul traffico intercettato
* Per IPv6, controlli equivalenti su NDP dove supportati dall'infrastruttura
* Non abituare gli utenti ad accettare warning sui certificati: è spesso l'anello debole che riapre scenari MITM anche con TLS configurato

## Bettercap vs Ettercap vs Wireshark vs mitmproxy

| Tool                                                | Punto di forza                                                                                  |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Bettercap                                           | Framework modulare, recon + spoof + sniff + proxy in un'unica sessione automatizzabile          |
| [Ettercap](https://hackita.it/articoli/ettercap/)   | MITM "storico", interfaccia e filtri diversi, più leggero per certi scenari mirati              |
| [Wireshark](https://hackita.it/articoli/wireshark/) | Analisi e dissezione approfondita dei pacchetti, non pensato per generare l'attacco             |
| [mitmproxy](https://hackita.it/articoli/mitmproxy/) | Intercettazione HTTP/HTTPS scriptabile in Python, quando il focus è solo il livello applicativo |
| [tcpdump](https://hackita.it/articoli/tcpdump/)     | Cattura rapida da riga di comando, minimale                                                     |

Se il lab richiede recon, MITM a livello di rete e sniffing nella stessa sessione, Bettercap è la scelta più naturale; se il focus è solo l'analisi approfondita di un pcap o l'intercettazione HTTP scriptabile, gli strumenti dedicati sopra sono spesso più efficienti.

## Scenario pratico: Bettercap su una macchina HTB/PG

Ambiente: attaccante Kali `10.10.10.20`, target `10.10.10.10`, gateway del lab `10.10.10.1`, tutto sulla stessa rete VM autorizzata. Obiettivo: MITM verso il target con evidenza salvata su pcap.

```text
net.recon on; net.show
```

```text
10.10.10.10 08:00:27:aa:bb:cc
10.10.10.1  52:54:00:11:22:33
```

Target e gateway visibili: prerequisito per qualunque MITM L2. Se `net.show` risulta vuoto, l'interfaccia o la rete sono sbagliate — riparti con `-iface` corretto.

```text
set arp.spoof.targets 10.10.10.10; arp.spoof on
```

```text
set net.sniff.output /tmp/lab-sniff.pcap; net.sniff on
```

Da qui genera traffico dal target (ping, navigazione su un servizio del lab) e verifica con `net.sniff stats` che i pacchetti crescano. Se l'attacco fallisce su un lab protetto, è comunque un risultato valido: documenta il comportamento e passa a evidenze passive.

## Bettercap Cheat Sheet

```text
bettercap -iface eth0
net.recon on
net.probe on
net.show
arp.spoof on
net.sniff on
net.sniff stats
dns.spoof on
ndp.spoof on
caplets.show
events.show 10
ui on
```

## Checklist operativa

* Conferma il perimetro: solo lab/CTF/HTB/PG/VM autorizzate
* Avvia sempre con `-iface` esplicito, mai in automatico alla cieca
* Verifica IP/subnet/gateway stampati all'avvio della sessione
* Avvia `net.recon` e controlla `net.show` prima di ogni altra cosa
* Usa `net.probe` solo se la discovery passiva è povera
* Per il MITM, imposta sempre un target esplicito con `arp.spoof.targets`
* Prima dello sniff, imposta `net.sniff.output` su pcap
* Usa `net.sniff stats` per confermare filtro e contatori
* Evita moduli invasivi se il lab è instabile
* Chiudi i moduli in ordine e ripristina lo stato a fine sessione
* Analizza la pcap con strumenti dedicati quando serve
* Documenta detection e mitigazioni osservate (DAI/DHCP snooping/TLS)

## FAQ

**A cosa serve Bettercap?**
A network reconnaissance, ARP/NDP/DNS spoofing, packet sniffing e intercettazione HTTP/HTTPS, il tutto orchestrato da un'unica sessione interattiva.

**Bettercap è disponibile su Kali Linux?**
Sì, è nei repository ufficiali: `sudo apt install bettercap`.

**Qual è la differenza tra net.recon e net.probe?**
`net.recon` legge periodicamente la tabella ARP (discovery passiva); `net.probe` invia probe attivi alla subnet per far emergere host silenziosi.

**Cos'è arp.spoof in Bettercap?**
Il modulo che esegue ARP spoofing per posizionarsi come man-in-the-middle tra un target e il gateway su reti IPv4.

**Cos'è net.sniff in Bettercap?**
Il modulo di packet sniffing, che può esportare il traffico catturato in un file pcap per analisi successive.

**Come avvio Bettercap?**
`sudo bettercap -iface <interfaccia>`, specificando sempre l'interfaccia corretta per la subnet del lab.

**Perché Bettercap non trova host?**
Quasi sempre per interfaccia di rete sbagliata o VM su segmenti virtuali diversi (NAT vs Bridge vs Host-only).

**Perché l'ARP spoofing con Bettercap non funziona?**
Spesso perché il lab ha protezioni anti-ARP-spoofing (Dynamic ARP Inspection) attive — è un esito valido, non un bug.

**Bettercap funziona con IPv6?**
Sì, tramite il modulo `ndp.spoof`, l'equivalente IPv6 dell'ARP spoofing.

**Bettercap può intercettare traffico HTTPS?**
Sì, con `https.proxy`, ma richiede l'installazione di un certificato lato client — fattibile in lab, non su dispositivi che non controlli.

**Cosa sono i caplet di Bettercap?**
Script `.cap` che raggruppano sequenze di comandi Bettercap, per rendere ripetibile lo stesso workflow tra lab diversi.

**Cos'è la Web UI di Bettercap?**
Un'interfaccia grafica, di default su `127.0.0.1:8080`, per visualizzare e orchestrare i moduli della sessione senza usare solo la CLI.

**Bettercap vs Ettercap: quale usare?**
Bettercap copre recon, spoof, sniff e proxy in un unico framework automatizzabile; Ettercap resta un'opzione più leggera per MITM mirati e ha un approccio diverso ai filtri.

## Riferimenti autorevoli

* [Bettercap – Overview](https://www.bettercap.org/project/introduction/)
* [Bettercap – Installation](https://www.bettercap.org/project/installation/)
* [Bettercap – Interactive Session](https://www.bettercap.org/usage/interactive_session/)
* [Bettercap – net.recon](https://www.bettercap.org/modules/ethernet/netrecon/)
* [Bettercap – arp.spoof](https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/)
* [Bettercap – net.sniff](https://www.bettercap.org/modules/ethernet/netsniff/)
* [Bettercap – dns.spoof](https://www.bettercap.org/modules/ethernet/spoofers/dnsspoof/)
* [Bettercap – Ethernet Spoofers (ndp.spoof incluso)](https://www.bettercap.org/modules/ethernet/spoofers/introduction/)
* [Bettercap – Web UI](https://www.bettercap.org/modules/core/ui/)
* [Logos Red – Man-in-the-Middle Attack: ARP Spoofing](https://logos-red.com/blog/how-to-perform-a-man-in-the-middle-attack-arp-spoofing/): walkthrough indipendente con lab Kali/Arch Linux passo dopo passo

## Link utili su HackIta

* [Ettercap per MITM e sniffing in rete](https://hackita.it/articoli/ettercap/)
* [Wireshark: dissezione e analisi del traffico](https://hackita.it/articoli/wireshark/)
* [tcpdump: cattura rapida da terminale](https://hackita.it/articoli/tcpdump/)
* [mitmproxy: intercettazione HTTP/HTTPS scriptabile](https://hackita.it/articoli/mitmproxy/)
* [arp-scan per la discovery interna](https://hackita.it/articoli/arp-scan/)
* [netdiscover per host discovery in LAN](https://hackita.it/articoli/netdiscover/)
* [Responder: capture in lab Windows/AD](https://hackita.it/articoli/responder/)
* [Inveigh: alternativa Windows-centric a Responder](https://hackita.it/articoli/inveigh/)
