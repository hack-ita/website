---
title: 'Tcpdump per Hacker Curiosi: Analizzare il Traffico di Rete da Terminale'
slug: tcpdump
description: >-
  Scopri come usare Tcpdump per analizzare il traffico di rete direttamente dal
  terminale. Una guida semplice e pratica pensata per hacker etici, curiosi e
  aspiranti professionisti della cybersecurity.
image: /tcpdump.webp
draft: false
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

# **Tcpdump per Hacker Curiosi: Analizzare il Traffico di Rete da Terminale**

### **Introduzione Tattica**

In un contesto di internal pentest su rete enterprise, ti trovi all’interno di un segmento dove convivono servizi moderni e protocolli legacy. Il traffico è intenso, i sistemi di monitoraggio sono attivi e non puoi basarti solo su scan attivi: devi osservare direttamente ciò che attraversa il wire. L’obiettivo è individuare credenziali in chiaro, token di sessione, metadati di autenticazione e pattern di comunicazione utili per escalation o movimento laterale. In questo scenario, tcpdump diventa lo strumento di osservazione a basso livello per validare cosa accade realmente sulla rete.

### **TL;DR Operativo (Flusso a Step)**

1. Identifica l'interfaccia di rete corretta (`tun0`, `eth0`) su cui transitare il traffico target.
2. Avvia una cattura minimale e filtrata per confermare reachability e servizi attivi.
3. Stringi il filtro sui servizi in plaintext (es. HTTP, FTP) per catturare credenziali e sessioni.
4. Salva il PCAP come evidenza incontrovertibile per il report e per analisi offline.
5. Analizza il traffico intercettato per individuare password riutilizzabili, token o indizi per privilege escalation.
6. Sfrutta le credenziali raccolte per tentare l'accesso ad altri sistemi (lateral movement).
7. Pulisci le tracce e comprendi come un defender avrebbe potuto rilevare la tua attività di sniffing.

### **Fase 1 – Ricognizione & Enumeration**

Fingerprinting della situazione di rete per individuare il punto di ascolto ottimale e il traffico sensibile.

**Comando: Identificazione Interfaccia**

```bash
sudo tcpdump -D
```

**Azione:** Determina se sei su VPN (`tun0`), LAN (`eth0`), o altro. Il traffico target deve transitare dall'interfaccia scelta.

**Comando: Sanity Check e Conferma Traffico**

```bash
sudo tcpdump -i tun0 -nn -c 10 host 10.10.10.10
```

**Azione:** Conferma che i pacchetti verso/da il target siano visibili. Niente pacchetti = interfaccia sbagliata o routing errato.

**Comando: Banner Grabbing Passivo e Service Detection**

```bash
sudo tcpdump -i tun0 -nn -s 0 -A 'tcp and host 10.10.10.10 and (port 80 or port 21)' | head -30
```

**Azione:** Cattura i banner e le prime risposte dei servizi in plaintext per identificare versioni e comportamenti senza inviare pacchetti attivi.

### **Fase 2 – Initial Exploitation**

Sfrutta misconfigurazioni di protocolli non cifrati per intercettare dati sensibili, il primo passo verso il compromissione di un endpoint.

**Comando: Cattura Credenziali HTTP Basic o POST**

```bash
sudo tcpdump -i eth0 -nn -s 0 -A 'tcp port 80 and host 192.168.1.50 and (((tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)))'
```

**Azione:** Filtra specificamente i pacchetti HTTP POST o GET per catturare form di login, parametri, token di sessione o file upload in chiaro.

**Comando: Intercettazione Sessioni FTP o Telnet**

```bash
sudo tcpdump -i eth0 -nn -s 0 -X 'tcp port 21 and host 192.168.1.50'
```

**Azione:** Cattura comandi FTP (USER, PASS) o interazioni Telnet. L'output in esadecimale (`-X`) aiuta a vedere i caratteri di controllo.

### **Fase 3 – Post-Compromise & Privilege Escalation**

Dopo aver ottenuto l'accesso iniziale, usa il sniffing per osservare il traffico interno al sistema compromesso o verso altri server, cercando segreti.

**Scenario: Sniffing del Traffico Locale (lo) per Indizi**

```bash
# Sulla macchina compromessa
sudo tcpdump -i lo -nn -s 0 -A 'port 3306 or port 5432' -c 20
```

**Azione:** Molte applicazioni comunicano con DB locali in plaintext sull'interfaccia di loopback. Intercetta query SQL che possono contenere credenziali di altri servizi.

**Scenario: Cattura di Chiavi SSH o Token in Transito (In Lab)**

```bash
# In un lab, se riesci a posizionarti tra due host che comunicano
sudo tcpdump -i eth0 -nn -s 0 -w ssh_handshake.pcap 'tcp port 22 and host 10.10.10.5'
```

**Azione:** Sebbene non decifrato, puoi analizzare timing, dimensioni e metadati della connessione. In scenari specifici (es. downgrade o misconfigurazioni), parti di handshake possono essere sfruttate.

**Comando: Ricerca di Pattern di Password e Secret**

```bash
tcpdump -nn -r captured.pcap -A | grep -i -E "pass=|pwd=|token=|secret=|key="
```

**Azione:** Analisi offline del PCAP per estrarre rapidamente stringhe sospette che possono portare a privilege escalation tramite password reuse.

### **Fase 4 – Lateral Movement & Pivoting**

Riutilizza le credenziali e gli indizi raccolti per muoverti lateralmente, utilizzando tcpdump per verificare la connettività verso nuovi segmenti di rete.

**Comando: Verifica Connessioni da un Pivot Point**

```bash
# Sul pivot (host compromesso)
sudo tcpdump -i any -nn 'host 172.16.5.20 and not arp' -c 5
```

**Azione:** Conferma che dal pivot sia raggiungibile un nuovo target nella rete interna (`172.16.5.20`), prima di lanciare attacchi diretti.

**Comando: Sniffing per Mappare Comunicazioni Orizzontali**

```bash
sudo tcpdump -i eth1 -nn 'net 172.16.5.0/24 and (port 445 or port 5985)' -w lateral_capture.pcap
```

**Azione:** Cattura il traffico SMB o WinRM verso una nuova subnet per identificare altri potenziali target per il movimento laterale.

### **Fase 5 – Detection & Hardening**

Comprendi come un Blue Team potrebbe rilevare la tua attività e quali contromisure concrete implementare.

**Indicatori di Compromissione (IoC) Reali:**

* Processo `tcpdump` o `libpcap` in esecuzione su host non autorizzati.
* Interfacce di rete impostate in modalità promiscua (visibile via `ip link` o tool come `promiscdetect`).
* Picchi anomali di traffico ARP su uno switch, possibili di ARP spoofing per MITM.
* Log di servizi (es. web server) che mostrano indirizzi IP sorgente improbabili (tipo gateway) per richieste sensibili.

**Hardening Concreto:**

* **Eliminare Plaintext:** Disabilitare definitivamente HTTP, FTP, Telnet, SNMP v2. Forzare TLS/SSH.
* **Segmentazione di Rete:** Implementare VLAN e firewall di micro-segmentazione per limitare la visibilità del traffico broadcast/unicast.
* **Controllo Privilegi:** Rimuovere i privilegi `sudo` per tcpdump e limitare le capability `CAP_NET_RAW` agli utenti strettamente necessari.
* **Monitoraggio Attivo:** Implementare regole IDS/IPS (Suricata/Snort) che alertano su tentativi di avvio di sniffer o su protocolli plaintext in reti considerate sicure.

### **Errori Comuni Che Vedo Negli Assessment Reali**

* **Sniffare sull'interfaccia sbagliata:** Perdersi `tun0` vs `eth0` e credere che il target non sia raggiungibile.
* **Filtri BPF troppo ampi o sbagliati:** Catturare GB di traffico inutile invece di stringere su `host` e `port`. Dimenticare le parentesi nelle espressioni complesse.
* **Non salvare il PCAP:** Perdere l'evidenza forense per il report o l'analisi successiva.
* **Interpretare male i "bad checksum":** Pensare a traffico corrotto invece di disabilitare `checksum offloading` con `ethtool -K eth0 tx off rx off` in lab.
* **Provare a decifrare TLS con tcpdump:** Non comprendere i limiti dello strumento; per ispezione TLS serve un proxy MITM configurato (mitmproxy).
* **Fare sniffing prolungato senza rotazione:** Riempire il disco del pivot point e causare denial of service.

### **Mini Tabella 80/20 Finale**

| Obiettivo                  | Azione                           | Comando                                                  |
| :------------------------- | :------------------------------- | :------------------------------------------------------- |
| **Identifica Interfaccia** | Lista interfacce disponibili     | `tcpdump -D`                                             |
| **Cattura Rapida**         | Conferma traffico verso target   | `tcpdump -i tun0 -nn -c 5 host 10.10.10.10`              |
| **Exploitation Creds**     | Intercetta login HTTP in chiaro  | `tcpdump -i eth0 -nn -A 'tcp port 80 and host X'`        |
| **Salva Evidenza**         | Cattura per report e replay      | `tcpdump -i any -s 0 -w proof.pcap 'port 21 and host X'` |
| **Analisi Post-Exploit**   | Cerca secret nel traffico locale | `tcpdump -i lo -nn -A 'port 3306' -c 50`                 |

## 🔗 Approfondisci e Metti in Pratica

Se vuoi applicare queste tecniche in scenari reali di **internal pentest, traffic sniffing e post-compromise analysis**, puoi esplorare:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)
👉 [https://hackita.it/supporta](https://hackita.it/supporto)

Per rafforzare la tua padronanza tecnica su tcpdump e BPF filtering:

* Tcpdump Manual Ufficiale: [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
* pcap-filter Reference (Sintassi BPF): [https://www.tcpdump.org/manpages/pcap-filter.7.html](https://www.tcpdump.org/manpages/pcap-filter.7.html)
* RFC 793 – TCP Protocol: [https://datatracker.ietf.org/doc/html/rfc793](https://datatracker.ietf.org/doc/html/rfc793)

La differenza tra semplice packet capture e offensive network intelligence sta nella precisione dei filtri, nella lettura corretta dei protocolli e nella capacità di trasformare traffico grezzo in vantaggio operativo reale.
