---
title: 'RARP Cos''è: il Reverse ARP che rivela reti legacy e OT'
slug: rarp
description: 'RARP cos’è, come funziona e perché conta ancora in pentest su reti legacy, OT/ICS e boot PXE: request/reply, spoofing, boot hijacking e differenze con ARP e DHCP.'
image: /rarp.webp
draft: true
date: 2026-03-25T00:00:00.000Z
categories:
  - windows
subcategories:
  - protocolli
tags:
  - rarp-spoofing
  - pxe-legacy
---

RARP è il protocollo che fa l'opposto di ARP: parte da un MAC address e cerca di ottenere un indirizzo IP. Capire cos'è RARP e come funziona è utile per chi studia la storia dei protocolli di rete, ma soprattutto per chi lavora su ambienti legacy, reti industriali OT/ICS e infrastrutture con boot PXE vecchio stile. In questi contesti RARP è ancora presente, e ignorarlo significa perdere visibilità su una parte della superficie di attacco.

***

## Cos'è RARP

RARP (Reverse Address Resolution Protocol) è definito nell'**RFC 903** del 1984. Nasce come estensione logica di ARP: se ARP traduce IP → MAC, RARP fa il contrario, traducendo **MAC → IP**.

Il caso d'uso originale era il boot di workstation diskless: macchine senza disco fisso che al boot non conoscevano il proprio indirizzo IP. L'unica cosa che sapevano era il proprio MAC address, hardcoded nella scheda di rete. RARP permetteva loro di chiedere a un server dedicato: *"Ho questo MAC, qual è il mio IP?"*

RARP opera al **livello 2 del modello OSI** (Data Link Layer), esattamente come ARP. Usa frame Ethernet broadcast e non attraversa i router, il che lo rendeva già limitato nella sua epoca e contribuì alla sua progressiva sostituzione con protocolli più flessibili.

Oggi RARP è considerato **obsoleto** e non viene implementato nei sistemi operativi moderni. Tuttavia capire come funziona è importante per:

* Analizzare reti legacy e ambienti industriali
* Comprendere l'evoluzione verso BOOTP e DHCP
* Riconoscere traffico anomalo in reti con dispositivi datati

***

## Come funziona RARP

### Il flusso di una richiesta RARP

Il meccanismo è speculare ad ARP:

1. Il client diskless si avvia e invia un **RARP Request** in broadcast Ethernet
2. Il messaggio contiene il proprio MAC address e chiede: *"Qualcuno conosce il mio IP?"*
3. Un **RARP Server** presente nel segmento riceve la richiesta
4. Il server consulta una tabella di mapping MAC → IP configurata manualmente
5. Il server invia un **RARP Reply** in unicast con l'indirizzo IP assegnato
6. Il client usa quell'IP per configurarsi e proseguire il boot

### Struttura del pacchetto RARP

RARP riusa esattamente la struttura del pacchetto ARP, con una sola differenza nel campo Opcode:

| Campo         | Dimensione | Descrizione                                     |
| ------------- | ---------- | ----------------------------------------------- |
| Hardware Type | 2 byte     | Tipo di rete (1 = Ethernet)                     |
| Protocol Type | 2 byte     | Tipo di protocollo (0x0800 = IPv4)              |
| Hardware Size | 1 byte     | Lunghezza MAC (6 byte)                          |
| Protocol Size | 1 byte     | Lunghezza IP (4 byte)                           |
| Opcode        | 2 byte     | 3 = RARP Request, 4 = RARP Reply                |
| Sender MAC    | 6 byte     | MAC del mittente                                |
| Sender IP     | 4 byte     | IP del mittente (0.0.0.0 in Request)            |
| Target MAC    | 6 byte     | MAC del destinatario (= Sender MAC in Request)  |
| Target IP     | 4 byte     | IP assegnato (compilato dal server nella Reply) |

Il campo **EtherType** nei frame che trasportano RARP è `0x8035`, diverso da ARP (`0x0806`). Questo permette di filtrare il traffico RARP specificamente in Wireshark o tcpdump.

### Limitazioni strutturali di RARP

RARP aveva problemi evidenti già alla nascita:

* **Non attraversa i router:** essendo broadcast L2, funziona solo nel segmento locale. Serviva un RARP server in ogni subnet.
* **Configurazione manuale:** la tabella MAC → IP sul server andava aggiornata a mano per ogni nuovo dispositivo.
* **Fornisce solo l'IP:** nessuna informazione su gateway, subnet mask o DNS. Il client doveva ottenerle altrove.
* **Nessuna autenticazione:** come ARP, chiunque poteva rispondere a una richiesta RARP.

Queste limitazioni portarono rapidamente allo sviluppo di **BOOTP** prima e **DHCP** poi, che risolvono tutti questi problemi e hanno sostituito RARP in qualsiasi contesto moderno.

***

## Dove viene usato RARP nelle reti

RARP è essenzialmente scomparso dalle reti moderne. I contesti in cui può ancora comparire:

* **Ambienti industriali OT/ICS legacy:** reti con PLC, SCADA e dispositivi embedded datati che non sono mai stati aggiornati. Alcuni usano ancora RARP o BOOTP per la configurazione iniziale.
* **Apparati di rete vintage:** switch e router di vecchia generazione possono usare RARP per il boot da flash esterna.
* **Laboratori di sicurezza e CTF:** a volte presenti come elemento di analisi del traffico storico.
* **Ambienti con boot PXE legacy:** alcune implementazioni vecchie di PXE usano RARP come prima fase prima di passare a TFTP. Le implementazioni moderne usano DHCP.

Se durante un engagement incontri traffico RARP, è un segnale che stai lavorando su infrastruttura vecchia. Questo ha implicazioni importanti: sistemi datati significano patch mancanti, protocolli insicuri, e configurazioni non aggiornate da anni.

***

## Perché RARP è importante in cybersecurity

Un pentester incontra RARP raramente, ma quando lo incontra il contesto è quasi sempre interessante. I sistemi che ancora usano RARP sono per definizione vecchi, spesso non aggiornati, e fanno parte di infrastrutture critiche o legacy con scarsa manutenzione della sicurezza.

Conoscere RARP permette di:

* **Riconoscere traffico anomalo** durante la fase di sniffing passivo
* **Identificare dispositivi legacy** nella rete prima ancora di fare un port scan
* **Capire l'evoluzione verso DHCP** e le sue implicazioni di sicurezza
* **Contestualizzare ambienti OT/ICS** dove protocolli obsoleti sono la norma

Per capire il livello su cui opera RARP, leggi l'articolo su [Ethernet IEEE 802.3](https://hackita.it/articoli/ethernet-ieee-802-3). Per il protocollo che ha sostituito RARP nella pratica moderna, vedi l'articolo su [DHCP](https://hackita.it/articoli/dhcp)

***

## RARP in un engagement di pentesting

### Reconnaissance passiva con RARP

In fase di sniffing passivo, rilevare traffico RARP è un segnale immediato. Un host che invia RARP Request si sta configurando: sa solo il suo MAC e non ha ancora un IP. Questo accade tipicamente durante il boot.

Catturare queste richieste con tcpdump permette di:

* Identificare il MAC address del dispositivo prima ancora che abbia un IP
* Riconoscere il vendor tramite OUI
* Capire che il sistema sta usando un meccanismo di boot legacy

```bash
tcpdump -i eth0 -nn ether proto 0x8035
```

### Enumeration di dispositivi legacy

Se in una rete trovi traffico RARP, hai un'informazione preziosa: esiste almeno un RARP server in quel segmento, configurato manualmente con una tabella MAC → IP. Quel server è un asset interessante: contiene la mappatura di dispositivi che probabilmente non appaiono nei normali inventari di rete.

Combinando l'analisi RARP con [arp-scan](https://hackita.it/articoli/arp) e [Nmap](https://hackita.it/articoli/nmap), si ottiene una visione più completa dei dispositivi presenti nel segmento, inclusi quelli che non rispondono a ICMP o TCP.

### Attack surface: impersonare un RARP server

Poiché RARP non prevede autenticazione, un attaccante nella stessa subnet può rispondere a una RARP Request prima del server legittimo, assegnando un IP arbitrario al client in boot.

Questo può portare a:

* **IP hijacking:** il dispositivo si configura con un IP già usato da un altro host, causando conflitti
* **Redirect del boot:** se il sistema usa RARP come prima fase di un boot PXE, assegnare un IP sbagliato può redirigere il boot verso un server TFTP controllato dall'attaccante
* **DoS:** rispondere con un IP non valido impedisce al dispositivo di configurarsi correttamente

Questi attacchi sono rari in ambienti moderni ma concreti in reti OT/ICS legacy dove RARP è ancora attivo.

### Pivoting e contesto OT/ICS

Trovare traffico RARP in un engagement spesso significa essere vicini a sistemi OT. In questi ambienti la segmentazione è spesso assente o mal configurata, e i dispositivi legacy hanno vulnerabilità non patchate da anni. RARP diventa un indicatore di superficie di attacco più ampia da esplorare. Integra questa analisi con tecniche di [man-in-the-middle](https://hackita.it/articoli/man-in-the-middle) e [sniffing](https://hackita.it/articoli/sniffing) per massimizzare la visibilità.

***

## Attacchi e abusi possibili su RARP

### RARP Spoofing (Rogue RARP Server)

Un attaccante può configurare un server RARP malevolo che risponde alle richieste più velocemente di quello legittimo. Assegnando indirizzi IP controllati, può:

* Causare conflitti di indirizzo sulla rete
* Forzare il client verso configurazioni di rete controllate
* Interferire con il processo di boot di dispositivi critici

### Boot Hijacking via PXE Legacy

In ambienti con boot PXE basato su RARP, il controllo dell'assegnazione IP è il primo passo per servire un'immagine di boot malevola tramite TFTP. Il flusso è: RARP Reply falso → client si connette al TFTP dell'attaccante → boot da immagine compromessa.

### Information Disclosure

Anche senza attacchi attivi, il solo fatto di osservare il traffico RARP rivela:

* MAC address dei dispositivi in boot
* Vendor e tipologia dei dispositivi (tramite OUI)
* Presenza e IP del RARP server
* Frequenza di boot (utile per capire se i dispositivi si riavviano spesso, indicatore di instabilità)

***

## Esempi pratici con RARP in laboratorio

### Catturare traffico RARP con tcpdump

```bash
tcpdump -i eth0 -nn -e ether proto 0x8035
```

Il flag `-e` mostra i MAC address sorgente e destinazione nel frame Ethernet.

### Analisi con Wireshark

Filtro diretto per tutto il traffico RARP:

```
rarp
```

Per visualizzare solo le Request (opcode 3):

```
rarp.opcode == 3
```

Per le Reply (opcode 4):

```
rarp.opcode == 4
```

### Identificare il vendor con OUI

Dal MAC address catturato in una RARP Request, si può risalire al vendor del dispositivo usando la lookup OUI:

```bash
arp-scan --localnet | grep -i "MAC_ADDRESS"
```

Oppure con un lookup diretto:

```bash
curl https://api.macvendors.com/AA:BB:CC:DD:EE:FF
```

### Simulare un ambiente RARP in lab

Per testare in laboratorio, si può usare **rarpd** (disponibile su alcune distribuzioni Linux legacy) per configurare un server RARP minimale. Utile per capire il flusso del protocollo in un ambiente controllato prima di analizzare traffico reale.

***

## Da RARP a DHCP: l'evoluzione del protocollo

Comprendere perché RARP è stato abbandonato aiuta a capire come progettare reti sicure. Il passaggio è stato graduale:

**RARP (1984):** solo IP, solo L2 broadcast, configurazione manuale, nessuna autenticazione.

**BOOTP (1985):** aggiunge gateway, subnet mask e TFTP server. Può attraversare i router tramite relay agent. Ancora statico.

**DHCP (1993):** assegnazione dinamica, lease time, rinnovamento automatico, opzioni estese. Standard attuale.

Ogni passaggio ha aggiunto funzionalità ma anche nuova superficie di attacco. DHCP ha i suoi problemi di sicurezza (DHCP starvation, rogue DHCP server) che sono direttamente collegati alla mancanza di autenticazione ereditata da RARP.

***

## Detection e difesa RARP

In ambienti dove RARP è ancora attivo:

* **Monitorare il traffico EtherType 0x8035** con IDS/IPS o un semplice tcpdump in modalità monitor
* **Rilevare RARP server non autorizzati:** qualsiasi host che invia RARP Reply non presente nella lista degli asset autorizzati è sospetto
* **Loggare le richieste RARP:** ogni dispositivo in boot lascia una traccia con il suo MAC, utile per l'inventario
* **Isolare i segmenti legacy** in VLAN dedicate per limitare la propagazione di eventuali attacchi

***

## Hardening e mitigazioni RARP

Se non puoi eliminare RARP dall'ambiente:

* **Sostituire RARP con DHCP** dove tecnicamente possibile. È la soluzione corretta.
* **Isolare in VLAN dedicate** i segmenti con dispositivi legacy che usano RARP, separandoli dal resto della rete. Vedi [VLAN e 802.1Q](https://hackita.it/articoli/vlan).
* **Monitorare il RARP server** e configurarlo per loggare tutte le richieste ricevute e le risposte inviate.
* **Limitare via ACL** il traffico EtherType 0x8035 solo alle porte dove è necessario, disabilitandolo ovunque else.
* **Inventariare i MAC address** autorizzati a fare richieste RARP e bloccare tutti gli altri a livello di port security.

***

## Errori comuni su RARP

**"RARP è morto, non serve conoscerlo"**
Falso in contesti OT/ICS e ambienti legacy. In un engagement su infrastrutture industriali o reti con apparati datati, incontrare RARP è reale. Non conoscerlo significa non capire cosa si sta osservando.

**"RARP e ARP sono la stessa cosa"**
No. ARP risolve IP → MAC, RARP risolve MAC → IP. Stessa struttura di pacchetto, direzione opposta, Opcode diverso, casi d'uso completamente diversi.

**"RARP attraversa i router"**
Falso. Come ARP, RARP usa broadcast L2 e non attraversa i router. Questo era uno dei suoi limiti principali, risolto solo con BOOTP e DHCP.

**"DHCP e RARP sono equivalenti"**
No. DHCP è enormemente più ricco: assegnazione dinamica, lease time, opzioni estese, relay agent, autenticazione opzionale. RARP fornisce solo un IP statico e nient'altro.

***

## FAQ su RARP

**Cos'è RARP e a cosa serve?**
RARP (Reverse Address Resolution Protocol) è un protocollo che permette a un host di ottenere il proprio indirizzo IP conoscendo solo il proprio MAC address. Era usato principalmente per il boot di workstation diskless e sistemi embedded. Oggi è obsoleto e sostituito da DHCP.

**Qual è la differenza tra ARP e RARP?**
ARP traduce un indirizzo IP in un MAC address. RARP fa il contrario: a partire da un MAC address, chiede quale IP gli è stato assegnato. Entrambi operano a livello 2, ma hanno usi completamente diversi.

**RARP è ancora usato oggi?**
Raramente. Lo si trova principalmente in ambienti industriali OT/ICS legacy, apparati di rete datati, e alcune implementazioni vecchie di boot PXE. Nelle reti moderne è stato completamente sostituito da DHCP.

**Perché RARP è stato abbandonato?**
Perché aveva limitazioni strutturali: funzionava solo a livello 2 (niente routing), richiedeva configurazione manuale, forniva solo l'indirizzo IP senza altre informazioni di rete, e non aveva meccanismi di autenticazione. BOOTP e poi DHCP hanno risolto tutti questi problemi.

**RARP può essere sfruttato in un attacco?**
Sì, in ambienti dove è ancora attivo. Un attaccante può configurare un RARP server malevolo che risponde alle richieste prima di quello legittimo, assegnando IP arbitrari ai client in boot. In scenari PXE legacy, questo può portare al boot hijacking.

***

## Conclusione su RARP

RARP è un protocollo storicamente significativo ma tecnicamente obsoleto. Conoscerlo non serve per attaccare reti moderne, ma è essenziale per chi lavora su ambienti legacy, infrastrutture OT/ICS, o semplicemente vuole capire come si è evoluta la gestione degli indirizzi nelle reti locali.

In un engagement, trovare traffico RARP è un segnale: stai guardando infrastruttura vecchia, probabilmente poco mantenuta, con superficie di attacco più ampia di quanto l'inventario ufficiale lasci supporre.

Studia il contesto, identifica i dispositivi, e usa quella visibilità per mappare l'intera superficie di attacco del segmento.

Approfondisci i protocolli correlati:

* [ARP: come funziona e come sfruttarlo](https://hackita.it/articoli/arp)
* [Ethernet IEEE 802.3: il livello sottostante](https://hackita.it/articoli/ethernet-ieee-802-3)
* [DHCP: sicurezza e attacchi](https://hackita.it/articoli/dhcp)
* [VLAN e 802.1Q: segmentazione e hopping](https://hackita.it/articoli/vlan)
* [Sniffing su reti locali](https://hackita.it/articoli/sniffing)
* [Man in the Middle: tecniche e tool](https://hackita.it/articoli/man-in-the-middle)
* [Nmap: reconnaissance e discovery](https://hackita.it/articoli/nmap)

Riferimento ufficiale: [RFC 903 — A Reverse Address Resolution Protocol](https://datatracker.ietf.org/doc/html/rfc903)

***

Vuoi migliorare le tue competenze in network security con percorsi 1:1 o hai bisogno
di un penetration test professionale sulla tua infrastruttura?

Visita [hackita.it/servizi](https://hackita.it/servizi).

Se HackITA ti è utile e vuoi supportare il progetto:
[hackita.it/supporto](https://hackita.it/supporto)
