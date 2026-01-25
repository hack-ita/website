---
title: 'Netdiscover: scopri dispositivi e IP nascosti nella rete LAN'
description: >-
  Netdiscover è un tool essenziale per identificare dispositivi attivi nella
  rete locale. Ideale per il recon silenzioso tramite ARP su ambienti privi di
  DNS o DHCP.
image: /NETDISCOVER.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Netdiscover
---

# Netdiscover: scoprire host in LAN con ARP (guida lab)

### 1. INTRODUZIONE

**Netdiscover** è uno strumento di discovery passivo e attivo che utilizza il protocollo ARP per mappare una rete locale. Per un attaccante, è una delle armi più silenziose ed efficaci per osservare e interrogare una LAN a cui si è appena ottenuto accesso. **A cosa serve per un attaccante**: ti permette di identificare host attivi, i loro indirizzi MAC e i vendor dei dispositivi senza necessariamente inviare traffico rilevabile da tutti gli IDS. È il passo fondamentale per comprendere l'architettura di una rete da interno.

### 2. COS'È ARP (IL FONDAMENTO)

Per capire Netdiscover, devi sapere cos'è ARP (Address Resolution Protocol). In una LAN, i dispositivi comunicano usando indirizzi MAC, non IP. ARP è il meccanismo che traduce un indirizzo IP (es. `192.168.1.10`) nel corrispondente indirizzo MAC fisico (es. `AA:BB:CC:DD:EE:FF`). Netdiscover sfrutta questo: in modalità attiva, chiede ("Chi ha questo IP?") a tutti; in modalità passiva, si siede e ascolta le conversazioni ARP altrui, imparando chi c'è.

### 3. SETUP E PRIMI PASSI

Netdiscover è solitamente preinstallato su Kali Linux. Se non lo fosse, l'installazione è immediata. Richiede privilegi di root per interagire direttamente con l'interfaccia di rete.

```bash
sudo apt update && sudo apt install -y netdiscover
```

Verifica funzionamento:

```bash
netdiscover -h
```

**Identifica la tua interfaccia di rete** prima di partire. Usa `ip a` per vedere la lista. In un lab, sarà spesso `eth0` (Ethernet) o `wlan0` (Wi-Fi). Scansionare l'interfaccia sbagliata è l'errore più comune.

### 4. TECNICHE OFFENSIVE DETTAGLIATE

**Situazione: Scansione attiva di una subnet. È il modo più veloce per avere una mappa.**

```bash
sudo netdiscover -i eth0 -r 192.168.1.0/24
```

**Output di esempio:**

```
Currently scanning: 192.168.1.0/24 | Screen View: Unique Hosts
2 Captured ARP Req/Rep packets, from 2 hosts. Total size: 120
_____________________________________________________________________________
  IP            At MAC Address     Count     Len  MAC Vendor
-----------------------------------------------------------------------------
192.168.1.1     00:1a:2b:3c:4d:5e      1      60  Cisco-Linksys, LLC
192.168.1.105   08:00:27:ab:cd:ef      1      60  PCS Systemtechnik GmbH
```

**Spiegazione offensiva:**
Con `-r` specifichi il range di rete. Netdiscover invierà richieste ARP per ogni IP in quel range. L'output è una tabella immediata: IP, MAC, quanti pacchetti ha catturato e, soprattutto, il vendor. Vedere "PCS Systemtechnik GmbH" indica quasi sempre una macchina VirtualBox/VMware, un bersaglio classico in un lab.

**Situazione: Modalità passiva. Non invii nulla, solo ascolti. Ideale per essere invisibile.**

```bash
sudo netdiscover -i eth0 -p
```

**Spiegazione offensiva:**
L'opzione `-p` (passive) fa sì che Netdiscover non invii un solo pacchetto. Si mette in ascolto e registra ogni conversazione ARP che passa sulla rete. È perfetta quando vuoi profilare la rete senza lasciare tracce o quando sei in una rete molto controllata. I risultati arriveranno più lentamente, ma saranno basati sul traffico reale.

**Situazione: Fast scan. Vuoi solo un'idea rapida di cosa c'è, senza scansionare tutto.**

```bash
sudo netdiscover -i eth0 -f
```

**Spiegazione offensiva:**
La modalità `-f` (fast) non scandisce l'intera subnet. Invece, prova solo un set predefinito di indirizzi IP comuni (come il gateway `.1`, `.100`, `.254`). È utile per una prima, rapidissima valutazione per capire se una rete è "viva" e attiva prima di impegnarsi in una scansione completa.

**Situazione: Ottenere un output pulito per salvarlo e usarlo dopo.**

```bash
sudo netdiscover -i eth0 -r 10.0.0.0/24 -P -N > netdiscover_scan.txt
```

**Spiegazione offensiva:**
`-P` produce un output in formato "parsabile", facile da leggere per altri script. `-N` rimuove l'header della tabella. Redirigendo l'output (`>`) in un file, crei un log della tua scoperta. Questo file è un punto di partenza perfetto per analisi successive o per generare una lista di target per nmap.

### 5. SCENARIO DI ATTACCO COMPLETO

**Contesto**: Hai ottenuto un accesso iniziale a un server nella rete `10.10.50.0/24`. La tua priorità è capire l'ambiente.

1. **Profilazione iniziale silenziosa** (primi minuti):

```bash
sudo netdiscover -i eth0 -p -P -N > passive_log.txt
```

Ascolti per qualche minuto, raccogliendo IP e MAC di host che comunicano.

1. **Scansione attiva mirata** (dopo aver individuato la subnet):

```bash
sudo netdiscover -i eth0 -r 10.10.50.0/24 >> active_scan.txt
```

Confermi e integri la lista dell'ascolto passivo con una scansione completa.

1. **Creazione della target list finale**:

```bash
cat passive_log.txt active_scan.txt | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > final_targets.txt
```

Estrai tutti gli IP univoci in un unico file.

1. **Transizione all'enumerazione**:

```bash
sudo nmap -sV -iL final_targets.txt -oA network_enum
```

Passi la lista a Nmap per scoprire servizi e versioni.

**Risultato**: In pochi minuti, passando da una fase di ascolto stealth a una di scansione attiva, hai una mappa completa e affidabile della rete, pronta per la fase di exploitation.

### 6. CONSIDERAZIONI FINALI PER L'OPERATORE

* **Il vantaggio tattico** di Netdiscover è la sua duplice natura. La modalità passiva è uno degli strumenti più stealth a disposizione per la ricognizione interna.
* **Usalo come sensore**. Lanciato in passivo su un host compromesso, può continuare a raccogliere informazioni per ore, rivelando dispositivi che si accendono, si spengono o nuovi server aggiunti alla rete.
* **Il limite è il perimetro**. ARP non attraversa i router. Netdiscover vedrà solo il segmento di rete locale (broadcast domain) a cui l'interfaccia è collegata. Per scoprire altre subnet, serve un pivot.
* **Integralo nel flusso**. È il compagno ideale di arp-scan. Mentre arp-scan è veloce e scriptabile, Netdiscover offre l'opzione silenziosa. Scegli in base alla situazione.

### SEZIONE FORMATIVA HACKITA:

**Pronto a Portare le Tue Competenze Offensive al Livello Successivo?**

La vera maestria in Red Teaming sta nel sapere quale strumento usare, e quando, per rimanere non rilevati. Netdiscover è un classico esempio di strumento semplice ma dal potenziale tattico immenso se usato con giudizio.

**Hackita** offre formazione pratica e avanzata:

* **Corsi di Red Teaming** con scenari di movimento laterale e ricognizione interna realistici
* **Mentorship 1:1** per perfezionare l'uso di strumenti di discovery attivo e passivo
* **Laboratori Accessibili 24/7** con reti complesse su cui esercitarsi
* **Formazione Aziendale Su Misura**

Visita la pagina dei servizi di Hackita: [https://hackita.it/servizi/](https://hackita.it/servizi/)

**Supporta la Comunità della Sicurezza Italiana**

Credi in una formazione offensive etica, pratica e di qualità? Il tuo contributo è fondamentale per mantenere viva la comunità, aggiornare i laboratori e produrre nuovi contenuti.

Supporta il progetto con una donazione: [https://hackita.it/supporto/](https://hackita.it/supporto/)

**Note Legali**
**RICORDA:** Le tecniche descritte devono essere utilizzate esclusivamente in ambienti che possiedi o per i quali hai **autorizzazione scritta esplicita**. Il loro uso non autorizzato è illegale e non etico.

**Formati. Sperimenta. Previeni.**

**Hackita - Excellence in Offensive Security**

Riferimenti Esterni (SEO):
[https://www.rfc-editor.org/rfc/rfc826.html](https://www.rfc-editor.org/rfc/rfc826.html)
