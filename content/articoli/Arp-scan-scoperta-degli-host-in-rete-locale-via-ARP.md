---
title: 'Arp-scan: scoperta degli host in rete locale via ARP'
description: >-
  Arp-scan è il tool ideale per identificare dispositivi attivi nella rete LAN.
  Usato in fase di ricognizione, bypassa firewall e filtri ICMP per scoprire
  target nascosti.
image: /arpscan.webp
draft: true
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - arp-scan
---

# Arp-scan: scoprire host in LAN con ARP (guida lab)

### 1. INTRODUZIONE

**arp-scan** è un tool che scopre dispositivi nella tua stessa rete LAN inviando richieste ARP. Per un attaccante, è il modo più affidabile per rispondere alla domanda "Chi c'è qui con me?" dopo essere entrati in una rete. A differenza di un ping, che può essere bloccato, ARP è il protocollo fondamentale che permette ai computer di parlarsi su una LAN, quindi quasi sempre funziona. **A cosa serve per un attaccante**: ti dà una lista di target vivi e reali in pochi secondi, con tanto di indirizzi MAC e produttore, ed è il primo passo per capire dove muoverti dopo.

### 2. COS'È ARP (SPIEGATO EASY)

Immagina che la tua rete LAN sia una stanza piena di persone (i computer). Ognuno ha un nome (indirizzo IP, es. 192.168.1.10) e un numero di documento unico (indirizzo MAC, es. AA:BB:CC:DD:EE:FF). ARP è come quando qualcuno in stanza urla: "Ehi, quello che si chiama 192.168.1.1, qual è il tuo numero di documento?". Solo il proprietario di quell'IP risponderà con il suo MAC. **arp-scan** fa proprio questo: urla (in broadcast) a tutti gli IP possibili nella stanza e ascolta chi risponde. Per questo funziona solo sulla LAN in cui sei fisicamente (o virtualmente) connesso.

### 3. SETUP E PRIMI PASSI

Su Kali Linux, è già installato o si installa in un comando. Serve essere root perché deve "creare" pacchetti di rete speciali.

```bash
sudo apt update && sudo apt install -y arp-scan
```

Per verificare che funzioni e vedere le opzioni:

```bash
sudo arp-scan -h
```

**Output di esempio:**

```
arp-scan 1.10.0
Usage: arp-scan [options] [hosts...]
...
```

### 4. TECNICHE OFFENSIVE DETTAGLIATE

**Situazione: Sei in una LAN sconosciuta e vuoi vedere tutto quello che c'è intorno.**

```bash
sudo arp-scan --localnet
```

**Output di esempio reale:**

```
Interface: eth0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1     00:aa:bb:cc:dd:01       RouterManufacturer
192.168.1.105   08:00:27:ab:cd:ef       PCS Systemtechnik GmbH
```

**Spiegazione offensiva:**
`--localnet` è l'opzione più semplice. Il tool prende automaticamente l'indirizzo della tua scheda di rete (es. 192.168.1.105/24) e scandisce l'intera rete di quell'interfaccia. È il primo comando da lanciare. L'output ti mostra l'IP, il MAC e spesso il produttore del dispositivo: vedi subito il router (192.168.1.1) e un altro host (probabilmente una macchina virtuale).

**Situazione: Vuoi scansionare una rete specifica, o la tua macchina ha più interfacce di rete.**

```bash
sudo arp-scan -I eth0 192.168.56.0/24
```

**Output di esempio reale:**

```
192.168.56.1    0a:11:22:33:44:55       (Unknown)
192.168.56.101  08:00:27:aa:bb:cc       PCS Systemtechnik GmbH
```

**Spiegazione offensiva:**
Con `-I` specifichi l'interfaccia (es. `eth0`, `tun0`). Poi indichi la rete da scandire in formato CIDR. Questo è fondamentale in lab con reti virtuali (es. la rete NAT di VirtualBox è spesso 192.168.56.0/24). Vedrai subito il tuo host-only adapter e le altre VM.

**Situazione: La rete è lenta o instabile, e alcuni host non vengono rilevati.**

```bash
sudo arp-scan -I eth0 10.10.10.0/24 --retry=5
```

**Spiegazione offensiva:**
L'opzione `--retry` dice al tool di riprovare più volte se un host non risponde subito. Aumentandolo (il default è 2) si diventa più accurati, ma lo scan impiega più tempo. È utile in reti Wi-Fi reali o congestionate dove i pacchetti si perdono facilmente.

**Situazione: Ottenere una lista pulita di soli IP da salvare in un file per nmap.**

```bash
sudo arp-scan -I eth0 --localnet --plain > scan.txt
cat scan.txt | awk '{print $1}' | sort -u > target_list.txt
```

**Contenuto del file target\_list.txt di esempio:**

```
192.168.1.1
192.168.1.105
```

**Spiegazione offensiva:**
Il primo comando salva l'output pulito (`--plain`) in un file. Il secondo comando (`awk '{print $1}'`) prende solo la prima colonna (gli IP) da quel file, li ordina e rimuove i duplicati (`sort -u`). Il file `target_list.txt` che ottieni è una lista perfetta e pulita da dare a `nmap -iL target_list.txt` per il passo successivo di enumerazione delle porte.

### 5. SCENARIO DI ATTACCO COMPLETO

**Contesto**: Hai una shell su una macchina vittima nella rete `172.16.100.0/24`. Devi mappare l'ambiente.

1. **Scoperta host**:

```bash
sudo arp-scan -I ens33 --localnet > scan_completo.txt
```

1. **Crea lista per il passo successivo**:

```bash
cat scan_completo.txt | grep '172.16.100' | awk '{print $1}' > vivi.txt
```

1. **Enumera i servizi sui target trovati**:

```bash
sudo nmap -sV -iL vivi.txt -oA enumerazione
```

**Risultato**: In meno di un minuto sei passato da "sono sulla rete 172.16.100.0/24" ad avere una mappa precisa di tutti gli host attivi e dei servizi che espongono. Ora puoi scegliere il bersaglio migliore (es. il server con porta 443 aperta).

### 6. CONSIDERAZIONI FINALI PER L'OPERATORE

* **Il punto di forza** di arp-scan è la sua affidabilità su reti locali. Se un host è collegato alla LAN e ha una scheda di rete attiva, molto probabilmente risponderà alle richieste ARP, anche se firewall severi bloccano tutto il resto.
* **Usalo sempre** come primo step di discovery in un ambiente interno. È più veloce e spesso più accurato di un ping sweep.
* **Il limite principale** è che funziona solo sul tuo segmento di rete locale (broadcast domain). Non può scoprire host in altre reti, per quello servono strumenti diversi.
* **Integralo nel flusso** subito dopo l'accesso iniziale. La sua output è l'input perfetto per la successiva fase di enumerazione con nmap.

### SEZIONE FORMATIVA HACKITA:

**Pronto a Portare le Tue Competenze Offensive al Livello Successivo?**

Saper muoverti rapidamente in una rete sconosciuta è una skill fondamentale per un Red Teamer. La teoria sui protocolli diventa potente quando applicata in scenari realistici.

**Hackita** offre formazione pratica e avanzata:

* **Corsi di Red Teaming** con scenari di movimento laterale e enumerazione di rete complessi
* **Mentorship 1:1** per affinare tattiche e strategie operative
* **Laboratori Accessibili 24/7** che replicano ambienti aziendali reali
* **Formazione Aziendale Su Misura**

Visita la pagina dei servizi di Hackita: [https://hackita.it/servizi/](https://hackita.it/servizi/)

**Supporta la Comunità della Sicurezza Italiana**

Credi in una formazione offensive etica e accessibile? Il tuo supporto ci aiuta a mantenere i laboratori, produrre nuovi contenuti e crescere la comunità.

Supporta il progetto con una donazione: [https://hackita.it/supporto/](https://hackita.it/supporto/)

**Note Legali**
**RICORDA:** Le tecniche descritte devono essere utilizzate esclusivamente in ambienti che possiedi o per i quali hai **autorizzazione scritta esplicita**. Il loro uso non autorizzato è illegale e non etico.

**Formati. Sperimenta. Previeni.**

**Hackita - Excellence in Offensive Security**

Riferimenti Esterni:
[https://datatracker.ietf.org/doc/html/rfc826](https://datatracker.ietf.org/doc/html/rfc826)

[https://www.kali.org/tools/arp-scan/](https://www.kali.org/tools/arp-scan/)
