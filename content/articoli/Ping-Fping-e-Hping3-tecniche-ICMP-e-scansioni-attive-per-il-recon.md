---
title: 'Ping, Fping e Hping3: tecniche ICMP e scansioni attive per il recon'
description: >-
  Analizza il comportamento della rete con ping, fping e hping3. Tecniche di
  ricognizione ICMP, host discovery e test su firewall usati nei pentest.
image: /ping.webp
draft: true
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - icmp
  - ping
---

### 1. Ping, Fping e Hping3: tecniche ICMP e scansioni attive per il recon

**fping** è uno strumento di host discovery progettato per inviare richieste ICMP Echo a **molti target in parallelo**, invece che uno alla volta come `ping`. Lavora in modalità round-robin, risultando estremamente veloce su subnet medio-grandi.

**A cosa serve per un attaccante**: permette di passare rapidamente da “ho una subnet” a “so quali host sono vivi”, creando la base operativa per l’enumerazione successiva (porte, servizi, ruoli). È uno dei primi tool da usare dopo l’accesso iniziale in rete interna.

**Filosofia del tool**: velocità, semplicità e minimo overhead. fping non sostituisce nmap, ma **riduce lo scope** prima di usarlo.

***

### 2. SETUP E PRIMI PASSI

Installazione su Kali Linux:

sudo apt update && sudo apt install -y fping hping3

Verifica del funzionamento:

fping -v

**Nota operativa**:

* fping e ping funzionano senza privilegi root
* hping3 richiede root perché costruisce pacchetti raw

***

### 3. TECNICHE OFFENSIVE DETTAGLIATE

#### Ping sweep su una subnet (CIDR)

Situazione: devi scoprire rapidamente quali host sono attivi in una rete di laboratorio.

fping -a -g 10.10.20.0/24

Spiegazione offensiva:

* -g genera tutti gli IP del range
* -a mostra **solo** gli host che rispondono
* l’output “is alive” è immediatamente utilizzabile

Questo comando è il modo più rapido per ridurre una /24 da 254 IP a pochi target reali.

***

#### Creare una lista pulita di host vivi

Situazione: vuoi passare i target direttamente a nmap.

fping -a -g 10.10.20.0/24 > targets\_vivi.txt

Spiegazione offensiva:
Questo file diventa input diretto per nmap con -iL. È il flusso operativo standard in Red Team: discovery → lista → enumerazione.

***

#### Test singolo host (diagnostica rapida)

Situazione: vuoi confermare che un host specifico risponda.

fping -c 3 10.10.20.15

Spiegazione offensiva:

* -c 3 invia 3 echo request
* utile per verificare stabilità e latenza
* più rapido e leggibile di ping classico

***

#### Quando ICMP è filtrato: uso di hping3

Situazione: fping non mostra l’host come alive, ma sospetti filtraggio ICMP.

sudo hping3 -S -p 443 -c 1 10.10.20.15

Spiegazione offensiva:

* invia un TCP SYN su porta 443
* risposta SYN-ACK = host vivo + servizio esposto
* tecnica chirurgica, meno rumorosa di uno scan completo

***

#### Usare stdin / pipeline

Situazione: hai una lista grezza di IP proveniente da altri tool.

cat lista\_grezza.txt | fping -a -f -

Spiegazione offensiva:

* -f legge target da stdin
* permette di integrare fping in flussi automatizzati
* perfetto per filtrare host vivi in tempo reale

***

### 4. SCENARIO DI ATTACCO COMPLETO

**Contesto**: accesso iniziale a una workstation interna nella rete 192.168.1.0/24.

1. Discovery rapida:
   fping -a -g 192.168.1.0/24 > live\_hosts.txt
2. Verifica mirata su server sospetto:
   fping -c 3 192.168.1.10
3. Fallback se ICMP è bloccato:
   sudo hping3 -S -p 80 -c 1 192.168.1.10
4. Enumerazione avanzata:
   sudo nmap -sV -sC -iL live\_hosts.txt -oA scan\_reti

**Risultato**: mappa affidabile dei sistemi attivi e dei servizi critici. Da qui parte l’enumerazione SMB, SSH, HTTP, RDP.

***

### 5. CONSIDERAZIONI FINALI PER L’OPERATORE

* **Lezione chiave**: fping è il modo più veloce per definire il perimetro reale dell’attacco
* **Quando usarlo**: sempre prima di nmap in reti interne
* **Limiti**: ICMP può essere filtrato → serve fallback TCP
* **Confronto tool**:
  * fping → discovery massivo
  * ping → diagnostica singolo host
  * hping3 → test TCP mirati

***

### SEZIONE FORMATIVA HACKITA

**Pronto a Portare le Tue Competenze Offensive al Livello Successivo?**
La velocità nel muoverti in una rete sconosciuta è ciò che distingue un tester medio da un Red Teamer efficace.

Formazione avanzata e pratica:
[https://hackita.it/servizi/](https://hackita.it/servizi/)

**Supporta la Comunità della Sicurezza Italiana**
Il tuo supporto ci permette di mantenere laboratori, guide e formazione offensive di qualità.

[https://hackita.it/supporto/](https://hackita.it/supporto/)

***

### NOTE LEGALI

Le tecniche descritte devono essere utilizzate **esclusivamente** in ambienti autorizzati (lab, CTF, penetration test con permesso scritto).

**Formati. Sperimenta. Previeni.**
Hackita – Excellence in Offensive Security

***

### RIFERIMENTI ESTERNI

RFC 792 – ICMP: [https://www.rfc-editor.org/rfc/rfc792](https://www.rfc-editor.org/rfc/rfc792)
IANA ICMP Parameters: [https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
Documentazione fping: [https://fping.org/](https://fping.org/)
