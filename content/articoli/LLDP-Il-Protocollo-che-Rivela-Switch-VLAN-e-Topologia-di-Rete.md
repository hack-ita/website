---
title: 'LLDP: Il Protocollo che Rivela Switch, VLAN e Topologia di Rete'
slug: lldp
description: >-
  Scopri cos’è LLDP, come funziona e perché è utile nel pentesting: discovery
  passivo, neighbor table, VLAN, management IP, LLDP-MED, spoofing e difese.
image: /lldp.webp
draft: false
date: 2026-03-24T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - lldp
  - network-discovery
---

LLDP è il protocollo che i dispositivi di rete usano per presentarsi ai vicini. Capire cos'è LLDP e come funziona significa capire come uno switch annuncia se stesso, la propria configurazione e la topologia della rete — informazioni che in fase di reconnaissance valgono oro. In molti ambienti enterprise LLDP è attivo di default e quasi mai monitorato.

***

## Cos'è LLDP

LLDP (Link Layer Discovery Protocol) è uno standard IEEE definito nella specifica **802.1AB**. È un protocollo di discovery a livello 2 che permette ai dispositivi di rete di annunciare la propria identità e le proprie capacità ai dispositivi direttamente connessi.

Ogni dispositivo che supporta LLDP invia periodicamente frame multicast contenenti informazioni su se stesso: nome, porta, VLAN, capabilities, indirizzi IP di management, sistema operativo, e molto altro. Questi frame vengono ricevuti e memorizzati dai vicini nella propria **LLDP neighbor table**.

LLDP è lo standard aperto che ha sostituito (o affianca) protocolli proprietari equivalenti:

* **CDP (Cisco Discovery Protocol):** equivalente Cisco, proprietario
* **EDP (Extreme Discovery Protocol):** equivalente Extreme Networks
* **NDP (Nortel Discovery Protocol):** equivalente Nortel/Avaya

Dal punto di vista di un attaccante, LLDP e CDP sono equivalenti: entrambi trasmettono informazioni dettagliate sull'infrastruttura in chiaro, senza autenticazione.

***

## Come funziona LLDP

### Il meccanismo di annuncio LLDP

LLDP funziona in modo semplice e continuo:

1. Ogni dispositivo abilitato invia frame LLDP a intervalli regolari (default: 30 secondi)
2. I frame vengono inviati all'indirizzo multicast riservato `01:80:C2:00:00:0E`
3. I frame non vengono inoltrati oltre il segmento diretto (TTL a livello di protocollo, non di rete)
4. Ogni dispositivo ricevente memorizza le informazioni nella propria LLDP neighbor table
5. Le entry scadono se non vengono rinnovate entro il TTL dichiarato nel frame (default: 120 secondi)

### Struttura del frame LLDP

Un frame LLDP è un frame Ethernet con EtherType `0x88CC`. Il payload è composto da una sequenza di **TLV (Type-Length-Value)**, ciascuno dei quali trasporta un'informazione specifica.

TLV obbligatori:

| TLV           | Contenuto                                         |
| ------------- | ------------------------------------------------- |
| Chassis ID    | Identifica il dispositivo (MAC, nome, IP)         |
| Port ID       | Identifica la porta che invia il frame            |
| TTL           | Tempo di validità dell'entry nella neighbor table |
| End of LLDPDU | Marcatore di fine frame                           |

TLV opzionali (ma spesso presenti):

| TLV                 | Contenuto                        |
| ------------------- | -------------------------------- |
| Port Description    | Descrizione testuale della porta |
| System Name         | Hostname del dispositivo         |
| System Description  | OS, versione firmware, hardware  |
| System Capabilities | Router, switch, bridge, AP, ecc. |
| Management Address  | IP di management del dispositivo |

### LLDP-MED (Media Endpoint Discovery)

Estensione di LLDP pensata per dispositivi VoIP e endpoint multimediali. Aggiunge TLV specifici per:

* Identificazione di telefoni IP e dispositivi multimediali
* Assegnazione automatica di VLAN voce
* Informazioni sulla posizione fisica (E-911)
* Power over Ethernet (PoE)

LLDP-MED è particolarmente interessante per un pentester: i telefoni IP spesso annunciano la propria VLAN voce tramite LLDP-MED, rivelando la configurazione VLAN dell'infrastruttura.

***

## Dove viene usato LLDP nelle reti

LLDP è presente in qualsiasi rete enterprise moderna con switch managed:

* **LAN aziendali:** attivo di default su quasi tutti gli switch enterprise (Cisco, HP/Aruba, Juniper, Dell, Extreme)
* **Datacenter:** usato per il discovery automatico della topologia fisica tra server e switch ToR (Top of Rack)
* **Reti VoIP:** LLDP-MED è fondamentale per la configurazione automatica dei telefoni IP
* **Ambienti SDN:** controller come OpenDaylight e ONOS usano LLDP per mappare la topologia fisica della rete
* **Reti wireless:** gli access point annunciano se stessi tramite LLDP verso gli switch a cui sono connessi

In molti ambienti LLDP è attivo anche sugli host Linux e Windows attraverso demoni software, non solo sui dispositivi di rete.

***

## Perché LLDP è importante in cybersecurity

LLDP trasporta informazioni che normalmente richiederebbero ore di enumerazione attiva: hostname degli switch, versioni firmware, configurazione delle porte, VLAN, indirizzi IP di management. Tutto questo viene trasmesso **in chiaro**, **senza autenticazione**, **a chiunque sia connesso al segmento**.

Un pentester che sa leggere il traffico LLDP ottiene immediatamente:

* Mappa della topologia fisica della rete
* Hostname e versioni OS dei dispositivi di rete
* Configurazione VLAN per segmento
* Indirizzi IP dei pannelli di management
* Tipologia dei dispositivi connessi (switch, router, AP, telefoni IP)

Tutto questo senza inviare un solo pacchetto attivo. Pura reconnaissance passiva.

Per capire il livello su cui operano i frame LLDP, leggi l'articolo su [Ethernet IEEE 802.3](https://hackita.it/articoli/ethernet-ieee-802-3). Per approfondire le VLAN rivelate da LLDP-MED, vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan).

***

## LLDP in un engagement di pentesting

### Reconnaissance passiva con LLDP

La prima cosa da fare dopo aver ottenuto accesso a un segmento di rete è ascoltare. LLDP annuncia informazioni ogni 30 secondi: in meno di un minuto hai già una fotografia dell'infrastruttura circostante.

```bash
tcpdump -i eth0 -nn ether proto 0x88cc -w lldp_capture.pcap
```

Aspetta 60-90 secondi, poi analizza il file con Wireshark o con tool specifici per LLDP.

### Enumeration con lldpd e lldpcli

Su Linux, il demone **lldpd** permette di ricevere e analizzare frame LLDP in modo strutturato:

```bash
apt install lldpd
lldpd -d
lldpcli show neighbors
```

Output tipico:

```
-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface: eth0, via: LLDP
  Chassis:
    ChassisID: mac aa:bb:cc:dd:ee:ff
    SysName: core-sw-01.internal.corp
    SysDescr: Cisco IOS Software, Version 15.2(4)E7
    Capability: Bridge, on
    Capability: Router, on
  Port:
    PortID: local Gi1/0/24
    PortDescr: GigabitEthernet1/0/24
  VLAN:
    VLAN: 10 (voice)
    VLAN: 20 (data)
    VLAN: 99 (management)
  MgmtIP: 10.10.0.1
```

In una singola lettura: hostname dello switch, versione IOS, porta fisica a cui sei connesso, VLAN configurate, IP di management. Tutto senza inviare nulla.

### Fingerprinting e attack surface

Le informazioni raccolte da LLDP alimentano direttamente la fase di exploitation:

* **SysDescr** rivela OS e versione: cerca CVE pubblici per quella specifica versione
* **MgmtIP** è l'indirizzo del pannello di amministrazione: prova credenziali di default
* **VLAN IDs** rivelati: base per pianificare VLAN hopping verso segmenti più sensibili
* **PortID** identifica la porta fisica: in ambienti con port security, conoscere la porta aiuta a capire i controlli in atto

Integra questa reconnaissance con [Nmap](https://hackita.it/articoli/nmap) sugli IP di management identificati e con tecniche di [sniffing](https://hackita.it/articoli/sniffing) per catturare ulteriore traffico di gestione.

### Pivoting verso la rete di management

Gli indirizzi IP di management degli switch sono spesso in una VLAN dedicata. Conoscere quella VLAN (rivelata da LLDP) è il primo passo per tentare un accesso diretto al pannello di amministrazione o per pianificare un attacco di [VLAN hopping](https://hackita.it/articoli/vlan).

Se il pannello usa Telnet o HTTP (ancora comune in ambienti legacy), le credenziali viaggiano in chiaro e possono essere catturate con tecniche di [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle).

***

## Attacchi e abusi possibili su LLDP

### Information Disclosure passivo

Il principale "attacco" LLDP è in realtà puramente passivo: ascoltare e raccogliere. Non richiede di inviare nulla, non genera log, non è rilevabile da sistemi di detection standard che non monitorano il traffico L2.

### LLDP Spoofing (Rogue LLDP Announcements)

Un attaccante può inviare frame LLDP falsificati per avvelenare la neighbor table dei dispositivi di rete. Casi d'uso:

* **Confusione topologica:** far credere agli switch di avere vicini diversi da quelli reali
* **Impersonare un dispositivo:** annunciare se stesso come un altro switch o AP per ottenere configurazioni automatiche (es. VLAN voce tramite LLDP-MED)
* **Denial of Service:** inondare le neighbor table con entry false

Tool utilizzabile: **Scapy** per costruire frame LLDP arbitrari.

### LLDP-MED VLAN Harvesting

Un host che invia frame LLDP-MED dichiarandosi come telefono IP può ricevere in risposta la configurazione della VLAN voce. Alcuni switch rispondono automaticamente con LLDP-MED Reply contenenti la VLAN ID voce, permettendo a un attaccante di posizionarsi in quella VLAN senza conoscerla a priori.

### Denial of Service su neighbor table

Inviare continuamente frame LLDP con Chassis ID sempre diversi può saturare la neighbor table degli switch, causando comportamenti anomali o crash del processo LLDP. Rilevante su switch con risorse limitate o firmware datato.

***

## Esempi pratici con LLDP in laboratorio

### Cattura e analisi con Wireshark

Filtro per tutto il traffico LLDP:

```
lldp
```

Per vedere solo i frame con System Name:

```
lldp.tlv.type == 5
```

Per filtrare per Management Address:

```
lldp.tlv.type == 8
```

### Analisi rapida con strings

Se hai una cattura pcap e vuoi estrarre rapidamente le stringhe leggibili:

```bash
tcpdump -r lldp_capture.pcap -nn -A | grep -E "(Cisco|Juniper|HP|switch|router|vlan|mgmt)"
```

### Inviare frame LLDP custom con Scapy

```python
from scapy.all import *
from scapy.contrib.lldp import *

frame = Ether(dst="01:80:c2:00:00:0e") / \
        LLDPDU() / \
        LLDPDUChassisID(subtype=4, id=b"fakechassis") / \
        LLDPDUPortID(subtype=5, id=b"fakeport") / \
        LLDPDUTTL(ttl=120) / \
        LLDPDUSystemName(system_name=b"fake-switch-01") / \
        LLDPDUEndOfLLDPDU()

sendp(frame, iface="eth0")
```

***

## Detection e difesa LLDP

Un difensore che monitora il traffico LLDP può rilevare:

* **Frame LLDP da host non autorizzati:** workstation e server non dovrebbero inviare frame LLDP nella maggior parte delle configurazioni
* **Chassis ID o System Name non presenti nell'inventario:** dispositivi non autorizzati o spoofing in corso
* **Variazioni improvvise nelle neighbor table degli switch:** possibile attacco o dispositivo non autorizzato connesso
* **Frame LLDP-MED da host non VoIP:** possibile tentativo di VLAN harvesting

Tool utili: **Zeek** con script di analisi LLDP, syslog degli switch con logging delle variazioni nella neighbor table, **Nagios/Zabbix** con check sulla topologia LLDP.

***

## Hardening e mitigazioni LLDP

### Disabilitare LLDP dove non necessario

Su switch Cisco, disabilita LLDP globalmente e riabilitalo solo dove serve:

```
no lldp run
interface GigabitEthernet1/0/1
 lldp transmit
 lldp receive
```

Sulle porte di accesso verso gli end-user, LLDP non dovrebbe mai essere attivo in ricezione.

### Separare la rete di management

Gli IP di management rivelati da LLDP non dovrebbero essere raggiungibili dalla rete dati. Isola la rete di management in una VLAN dedicata con ACL restrittive. Vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan).

### Monitorare le neighbor table

Configura alerting sulle variazioni della neighbor table LLDP degli switch. Un nuovo vicino non atteso è un segnale da investigare.

### 802.1X per autenticare i dispositivi

Prima che un host possa connettersi alla rete e ricevere frame LLDP, autenticalo tramite 802.1X. Riduce drasticamente la superficie esposta. Vedi [Ethernet e sicurezza L2](https://hackita.it/articoli/ethernet-ieee-802-3).

***

## Errori comuni su LLDP

**"LLDP è solo per i network admin, non interessa a un attaccante"**
Falso. Le informazioni trasmesse da LLDP (hostname, versioni OS, VLAN, IP di management) sono esattamente quello che un attaccante cerca in fase di reconnaissance. È come ricevere una mappa dell'infrastruttura senza dover fare nulla.

**"LLDP è sicuro perché i frame non attraversano i router"**
Vero che i frame non vengono inoltrati oltre il segmento, ma un attaccante già dentro la LAN riceve tutti i frame LLDP del segmento locale senza problemi.

**"Disabilitare CDP è sufficiente"**
Se usi switch multi-vendor, disabilitare solo CDP lascia attivo LLDP (e viceversa). Entrambi vanno gestiti esplicitamente.

**"LLDP è cifrato"**
No. I frame LLDP viaggiano in chiaro. Non esiste autenticazione o cifratura nello standard 802.1AB base.

***

## FAQ su LLDP

**Cos'è LLDP e a cosa serve?**
LLDP (Link Layer Discovery Protocol) è un protocollo standard IEEE 802.1AB che permette ai dispositivi di rete di annunciare la propria identità e configurazione ai vicini diretti. Serve per il discovery automatico della topologia e per la configurazione automatica di dispositivi come telefoni IP.

**Qual è la differenza tra LLDP e CDP?**
CDP è il protocollo proprietario Cisco con funzionalità simili. LLDP è lo standard aperto supportato da tutti i vendor. In molte reti enterprise entrambi sono attivi contemporaneamente.

**LLDP è pericoloso per la sicurezza?**
Sì, se non gestito correttamente. Trasmette informazioni dettagliate sull'infrastruttura in chiaro e senza autenticazione, rendendolo una fonte di intelligence preziosa per un attaccante con accesso al segmento di rete.

**Come si disabilita LLDP su Linux?**
Se stai usando lldpd: `systemctl stop lldpd && systemctl disable lldpd`. Su interfacce specifiche: `lldpcli configure system interface pattern '!eth0'`.

**Come si vede la neighbor table LLDP su uno switch Cisco?**
Con il comando `show lldp neighbors detail`. Mostra hostname, porta, versione OS, VLAN e IP di management di tutti i vicini LLDP rilevati.

***

## Conclusione su LLDP

LLDP è uno di quei protocolli che nessuno pensa di attaccare perché serve "solo" per il discovery. Ma è esattamente questa percezione a renderlo interessante: è attivo di default, trasmette informazioni critiche, e quasi nessuno lo monitora.

In un engagement di internal pentesting, ascoltare il traffico LLDP per 60 secondi può darti più informazioni di un'ora di scansione attiva. Hostname degli switch, versioni firmware, configurazione VLAN, IP di management: tutto lì, in chiaro, gratis.

Usalo. E poi vai a chiudere quella superficie di attacco nel tuo report.

Approfondisci i protocolli e le tecniche correlate:

* [ARP: discovery e spoofing](https://hackita.it/articoli/arp)
* [Ethernet IEEE 802.3: il livello sottostante](https://hackita.it/articoli/ethernet-ieee-802-3)
* [VLAN e 802.1Q: segmentazione e hopping](https://hackita.it/articoli/vlan)
* [Sniffing su reti locali](https://hackita.it/articoli/sniffing)
* [Man in the Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle)
* [Nmap: reconnaissance e port scanning](https://hackita.it/articoli/nmap)
* [STP e RSTP: sicurezza dello spanning tree](https://hackita.it/articoli/stp)

Riferimento ufficiale: [IEEE 802.1AB — Station and Media Access Control Connectivity Discovery](https://standards.ieee.org/ieee/802.1AB/6047/)

***

Stai preparando una certificazione offensiva o vuoi approfondire il network pentesting con un percorso strutturato?
Su [hackita.it/servizi](https://hackita.it/servizi) trovi formazione 1:1 e servizi di penetration testing professionale.

Se il contenuto ti è stato utile e vuoi contribuire a mantenere HackITA gratuito:
[hackita.it/supporto](https://hackita.it/supporto)
